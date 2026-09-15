#!/usr/bin/env python3
"""
SENTINEL — Log-based Anti-Pattern Analyser
==========================================
Reads gateway/logs/audit.jsonl and mines it into a catalogue of
FMware operational anti-patterns.

Anti-patterns detected
──────────────────────
AP-01  Timeout Cascade     — backend timeouts clustered in time (> N in window)
AP-02  Cost Blowup         — requests where estimated_cost_usd > threshold
AP-03  Risk Score Drift    — rolling mean risk score rising over time
AP-04  PII Leakage Attempt — PII detected in prompt that was NOT blocked
AP-05  Hopless Requests    — requests with no hop_timings (instrumentation gap)
AP-06  LLM Dominance       — llm_backend latency > 99% of total latency
AP-07  Redundant Hops      — a hop contributes 0 ms across many requests
AP-08  Output Flagging Spike — output_flagged rate > threshold in window

Usage
─────
  python research/analyze_logs.py [--log-file PATH] [--output PATH] [--window 300]

Default log file: gateway/logs/audit.jsonl
Default output:   research/results/antipattern_report_<timestamp>.md
"""

import json
import sys
import argparse
import statistics
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ── CLI ───────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SENTINEL log anti-pattern analyser")
    p.add_argument("--log-file", default="gateway/logs/audit.jsonl",
                   help="Path to audit JSONL log (default: gateway/logs/audit.jsonl)")
    p.add_argument("--output",   default=None,
                   help="Output markdown report path (default: research/results/antipattern_report_<ts>.md)")
    p.add_argument("--window",   type=int, default=300,
                   help="Analysis time window in seconds for sliding-window checks (default: 300)")
    p.add_argument("--cost-threshold", type=float, default=0.001,
                   help="Per-request cost USD threshold for AP-02 (default: 0.001)")
    p.add_argument("--timeout-cluster-n", type=int, default=3,
                   help="Min timeouts in window for AP-01 cascade (default: 3)")
    return p.parse_args()


# ── Log loader ────────────────────────────────────────────

def load_logs(path: str) -> list[dict]:
    records = []
    p = Path(path)
    if not p.exists():
        print(f"[warn] log file not found: {path}", file=sys.stderr)
        return records
    with p.open() as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[warn] skipping malformed line {line_no}: {e}", file=sys.stderr)
    return records


def parse_ts(record: dict) -> datetime | None:
    ts = record.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


# ── Anti-pattern detectors ────────────────────────────────

class AntiPatternReport:
    def __init__(self):
        self.findings: list[dict] = []

    def add(self, code: str, title: str, severity: str,
            count: int, description: str, examples: list[str]):
        self.findings.append({
            "code": code, "title": title, "severity": severity,
            "count": count, "description": description, "examples": examples,
        })


def detect_ap01_timeout_cascade(records: list[dict], window_s: int,
                                 cluster_n: int) -> dict:
    """AP-01: N or more backend timeouts within window_s seconds."""
    timeout_ts = []
    for r in records:
        for hop in r.get("hop_timings", []):
            if hop.get("name") == "llm_backend" and hop.get("status") == "error":
                ts = parse_ts(r)
                if ts:
                    timeout_ts.append(ts)

    # Also catch requests where total_latency_ms ≥ OLLAMA_TIMEOUT (180 s)
    for r in records:
        if r.get("total_latency_ms", r.get("total_latency_ms", 0)) >= 179_000:
            ts = parse_ts(r)
            if ts:
                timeout_ts.append(ts)

    timeout_ts.sort()
    cascade_windows = 0
    examples = []
    window = timedelta(seconds=window_s)

    for i, t in enumerate(timeout_ts):
        cluster = [x for x in timeout_ts[i:] if x - t <= window]
        if len(cluster) >= cluster_n:
            cascade_windows += 1
            examples.append(f"{t.isoformat()} — {len(cluster)} timeouts in {window_s}s window")

    return {
        "code": "AP-01", "title": "Timeout Cascade",
        "severity": "high" if cascade_windows > 0 else "none",
        "count": cascade_windows,
        "description": (
            f"LLM backend produced {len(timeout_ts)} timeout/error events total. "
            f"{cascade_windows} window(s) of ≥{cluster_n} timeouts within {window_s}s. "
            "A cascade blocks all users during the window and skews latency metrics."
        ),
        "examples": examples[:5],
    }


def detect_ap02_cost_blowup(records: list[dict], threshold_usd: float) -> dict:
    """AP-02: Requests whose estimated cost exceeds threshold."""
    expensive = []
    for r in records:
        cost = r.get("estimated_cost_usd", 0.0)
        if cost > threshold_usd:
            expensive.append((cost, r.get("request_id", "?"),
                              r.get("complexity_tier", "?"),
                              r.get("intent_class", "?")))

    expensive.sort(reverse=True)
    examples = [
        f"${c:.6f} · req={rid} · {ct}/{ic}"
        for c, rid, ct, ic in expensive[:5]
    ]
    return {
        "code": "AP-02", "title": "Cost Blowup",
        "severity": "medium" if expensive else "none",
        "count": len(expensive),
        "description": (
            f"{len(expensive)} request(s) exceed ${threshold_usd:.4f} estimated cost. "
            "On a cloud-hosted FM API these would dominate the invoice. "
            "Mitigation: route complex requests only; add token budget cap."
        ),
        "examples": examples,
    }


def detect_ap03_risk_drift(records: list[dict]) -> dict:
    """AP-03: Rolling mean risk score rising — potential adversarial campaign."""
    if len(records) < 20:
        return {"code": "AP-03", "title": "Risk Score Drift",
                "severity": "none", "count": 0,
                "description": "Insufficient data (< 20 records).", "examples": []}

    scores = [r.get("risk_score", 0.0) for r in records]
    half = len(scores) // 2
    first_mean  = statistics.mean(scores[:half])
    second_mean = statistics.mean(scores[half:])
    drift = second_mean - first_mean

    severity = "none"
    if drift > 0.15:
        severity = "high"
    elif drift > 0.05:
        severity = "medium"

    return {
        "code": "AP-03", "title": "Risk Score Drift",
        "severity": severity,
        "count": 1 if drift > 0.05 else 0,
        "description": (
            f"First-half mean risk: {first_mean:.3f}, second-half mean: {second_mean:.3f} "
            f"(drift = {drift:+.3f}). "
            "A rising trend may indicate an adversarial campaign or a new prompt pattern "
            "not yet captured by the injection scanner."
        ),
        "examples": [f"Δ risk = {drift:+.3f} over {len(records)} requests"],
    }


def detect_ap04_pii_allowed(records: list[dict]) -> dict:
    """AP-04: PII detected but request was allowed (detection-without-block gap)."""
    cases = []
    for r in records:
        if r.get("pii_detected") and r.get("policy_decision") == "allow":
            cases.append(
                f"req={r.get('request_id','?')} · role={r.get('role','?')} "
                f"· entities={r.get('pii_entities', [])}"
            )
    return {
        "code": "AP-04", "title": "PII Leakage Attempt (Allowed)",
        "severity": "high" if cases else "none",
        "count": len(cases),
        "description": (
            f"{len(cases)} request(s) contained PII that was detected but not blocked. "
            "This typically happens for admin role (policy allows admin PII) or when "
            "the risk score did not exceed the OPA threshold. Review OPA policy for "
            "whether admin-role PII should always require explicit consent."
        ),
        "examples": cases[:5],
    }


def detect_ap05_hopless(records: list[dict]) -> dict:
    """AP-05: Requests missing hop_timings (instrumentation gap)."""
    missing = [r.get("request_id", "?") for r in records
               if not r.get("hop_timings")]
    return {
        "code": "AP-05", "title": "Hopless Requests (Instrumentation Gap)",
        "severity": "medium" if missing else "none",
        "count": len(missing),
        "description": (
            f"{len(missing)} request(s) have no hop_timings in the audit log. "
            "These are likely from the pre-v2 gateway or from blocked requests "
            "that exited before the hop recorder was reached. Cannot attribute "
            "latency cost for these entries."
        ),
        "examples": missing[:5],
    }


def detect_ap06_llm_dominance(records: list[dict]) -> dict:
    """AP-06: llm_backend latency accounts for > 99% of total request time."""
    dominant = []
    for r in records:
        total = r.get("total_latency_ms", 0)
        if total <= 0:
            continue
        for hop in r.get("hop_timings", []):
            if hop.get("name") == "llm_backend":
                pct = hop["latency_ms"] / total * 100
                if pct > 99.0:
                    dominant.append((pct, r.get("request_id", "?"),
                                     hop["latency_ms"], total))
    dominant.sort(reverse=True)
    examples = [
        f"{pct:.1f}% · req={rid} · llm={llm}ms / total={tot}ms"
        for pct, rid, llm, tot in dominant[:5]
    ]
    return {
        "code": "AP-06", "title": "LLM Dominance (Backend Dominates Cost)",
        "severity": "info",
        "count": len(dominant),
        "description": (
            f"{len(dominant)} request(s) where llm_backend accounts for > 99% of "
            "end-to-end latency. This is the key operational finding: the control-plane "
            "pipeline overhead is negligible; the FM backend is the entire cost. "
            "This validates the research claim in positioning.md."
        ),
        "examples": examples,
    }


def detect_ap07_redundant_hops(records: list[dict]) -> dict:
    """AP-07: A hop that always completes in ≤ 1 ms (potential dead code or bypass)."""
    hop_latencies: dict[str, list[int]] = defaultdict(list)
    for r in records:
        for hop in r.get("hop_timings", []):
            hop_latencies[hop["name"]].append(hop["latency_ms"])

    redundant = []
    for name, lats in hop_latencies.items():
        if len(lats) >= 10 and statistics.mean(lats) <= 1.0:
            redundant.append(f"{name}: mean={statistics.mean(lats):.2f}ms over {len(lats)} samples")

    return {
        "code": "AP-07", "title": "Redundant Hops",
        "severity": "low" if redundant else "none",
        "count": len(redundant),
        "description": (
            "Hops with mean latency ≤ 1 ms across ≥ 10 samples may indicate "
            "short-circuit / bypass paths that are not performing real work."
        ),
        "examples": redundant,
    }


def detect_ap08_output_spike(records: list[dict], window_s: int) -> dict:
    """AP-08: Output flagging rate > 20% in any time window."""
    if not records:
        return {"code": "AP-08", "title": "Output Flagging Spike",
                "severity": "none", "count": 0,
                "description": "No records.", "examples": []}

    window = timedelta(seconds=window_s)
    flagged_ts = []
    for r in records:
        if r.get("output_flagged"):
            ts = parse_ts(r)
            if ts:
                flagged_ts.append(ts)

    all_ts = [parse_ts(r) for r in records if parse_ts(r)]
    all_ts.sort()

    spike_windows = 0
    examples = []
    for t in flagged_ts:
        window_records = [x for x in all_ts if t <= x <= t + window]
        window_flagged = [x for x in flagged_ts if t <= x <= t + window]
        if window_records and len(window_flagged) / len(window_records) > 0.2:
            spike_windows += 1
            examples.append(
                f"{t.isoformat()} — {len(window_flagged)}/{len(window_records)} flagged "
                f"({100*len(window_flagged)/len(window_records):.0f}%) in {window_s}s"
            )

    return {
        "code": "AP-08", "title": "Output Flagging Spike",
        "severity": "high" if spike_windows > 0 else "none",
        "count": spike_windows,
        "description": (
            f"{spike_windows} window(s) with output flagging rate > 20%. "
            "May indicate a model that has started reproducing training-data secrets, "
            "or a targeted extraction campaign via benign-looking prompts."
        ),
        "examples": examples[:5],
    }


# ── Summary statistics ────────────────────────────────────

def summarise(records: list[dict]) -> dict:
    if not records:
        return {}
    total = len(records)
    allowed   = sum(1 for r in records if r.get("policy_decision") == "allow")
    blocked   = sum(1 for r in records if r.get("policy_decision") == "block")
    pii       = sum(1 for r in records if r.get("pii_detected"))
    injection = sum(1 for r in records if r.get("injection_detected"))
    flagged   = sum(1 for r in records if r.get("output_flagged"))

    latencies = [r.get("total_latency_ms", 0) for r in records if r.get("total_latency_ms")]
    costs     = [r.get("estimated_cost_usd", 0.0) for r in records]

    hop_means: dict[str, float] = defaultdict(list)
    for r in records:
        for hop in r.get("hop_timings", []):
            hop_means[hop["name"]].append(hop["latency_ms"])
    hop_summary = {k: round(statistics.mean(v), 1) for k, v in hop_means.items() if v}

    tiers   = defaultdict(int)
    intents = defaultdict(int)
    for r in records:
        tiers[r.get("complexity_tier", "unknown")]   += 1
        intents[r.get("intent_class",  "unknown")]   += 1

    return {
        "total_requests":    total,
        "allowed":           allowed,
        "blocked":           blocked,
        "pii_detected":      pii,
        "injection_detected": injection,
        "output_flagged":    flagged,
        "latency_p50_ms":    sorted(latencies)[len(latencies)//2] if latencies else 0,
        "latency_p95_ms":    sorted(latencies)[int(len(latencies)*0.95)] if latencies else 0,
        "latency_max_ms":    max(latencies) if latencies else 0,
        "total_est_cost_usd": round(sum(costs), 6),
        "mean_cost_per_req": round(statistics.mean(costs), 8) if costs else 0,
        "hop_mean_latency_ms": hop_summary,
        "complexity_tiers":  dict(tiers),
        "intent_classes":    dict(intents),
    }


# ── Report renderer ───────────────────────────────────────

def render_markdown(records: list[dict], findings: list[dict], summary: dict,
                    args) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# SENTINEL — FMware Anti-Pattern Report",
        "",
        f"**Generated:** {ts}  ",
        f"**Log file:** `{args.log_file}`  ",
        f"**Records analysed:** {len(records)}  ",
        f"**Analysis window:** {args.window}s  ",
        "",
        "---",
        "",
        "## Summary Statistics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
    ]
    if summary:
        lines += [
            f"| Total requests | {summary['total_requests']} |",
            f"| Allowed | {summary['allowed']} |",
            f"| Blocked | {summary['blocked']} |",
            f"| PII detected | {summary['pii_detected']} |",
            f"| Injection detected | {summary['injection_detected']} |",
            f"| Output flagged | {summary['output_flagged']} |",
            f"| Latency p50 | {summary['latency_p50_ms']} ms |",
            f"| Latency p95 | {summary['latency_p95_ms']} ms |",
            f"| Latency max | {summary['latency_max_ms']} ms |",
            f"| Total est. cost | ${summary['total_est_cost_usd']:.6f} |",
            f"| Mean cost/req | ${summary['mean_cost_per_req']:.8f} |",
        ]

    if summary.get("hop_mean_latency_ms"):
        lines += ["", "### Per-Hop Mean Latency", "", "| Hop | Mean ms |", "|-----|---------|"]
        for hop, ms in summary["hop_mean_latency_ms"].items():
            lines.append(f"| {hop} | {ms} |")

    if summary.get("complexity_tiers"):
        lines += ["", "### Classifier Output Distribution", "",
                  "| Dimension | Value | Count |", "|-----------|-------|-------|"]
        for tier, cnt in summary["complexity_tiers"].items():
            lines.append(f"| complexity_tier | {tier} | {cnt} |")
        for intent, cnt in summary.get("intent_classes", {}).items():
            lines.append(f"| intent_class | {intent} | {cnt} |")

    lines += ["", "---", "", "## Anti-Pattern Catalogue", ""]

    active = [f for f in findings if f["severity"] != "none"]
    if not active:
        lines.append("No anti-patterns detected in this log sample. ✓")
    else:
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        active.sort(key=lambda x: severity_order.get(x["severity"], 9))
        for f in active:
            emoji = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(f["severity"], "")
            lines += [
                f"### {f['code']} — {f['title']}  {emoji}",
                "",
                f"**Severity:** {f['severity']}  |  **Occurrences:** {f['count']}",
                "",
                f"{f['description']}",
            ]
            if f["examples"]:
                lines += ["", "**Examples:**", "```"]
                lines += f["examples"]
                lines += ["```"]
            lines.append("")

    not_found = [f for f in findings if f["severity"] == "none"]
    if not_found:
        lines += ["", "### Anti-Patterns Not Present", ""]
        for f in not_found:
            lines.append(f"- **{f['code']} {f['title']}** — not detected")

    lines += [
        "", "---", "",
        "## Methodology",
        "",
        "Anti-patterns are detected by analysing the structured JSONL audit log",
        "emitted by the SENTINEL gateway. Each log record contains per-hop timing,",
        "risk scores, PII/injection findings, model routing decisions, and cost",
        "estimates. This script is the foundation for the **anti-pattern catalogue**",
        "described in positioning.md §Contribution trajectory item 4.",
        "",
        "Pattern definitions and thresholds are configurable via CLI flags.",
        "See `python research/analyze_logs.py --help` for options.",
    ]

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────

def main():
    args = parse_args()
    records = load_logs(args.log_file)

    if not records:
        print(f"[info] No records loaded from {args.log_file}. "
              "Run the gateway and send some requests first.", file=sys.stderr)

    summary  = summarise(records)
    findings = [
        detect_ap01_timeout_cascade(records, args.window, args.timeout_cluster_n),
        detect_ap02_cost_blowup(records, args.cost_threshold),
        detect_ap03_risk_drift(records),
        detect_ap04_pii_allowed(records),
        detect_ap05_hopless(records),
        detect_ap06_llm_dominance(records),
        detect_ap07_redundant_hops(records),
        detect_ap08_output_spike(records, args.window),
    ]

    report = render_markdown(records, findings, summary, args)

    if args.output:
        out_path = Path(args.output)
    else:
        ts_str   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = Path("research/results") / f"antipattern_report_{ts_str}.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"[ok] Report written to {out_path}")

    # Console summary
    active = [f for f in findings if f["severity"] not in ("none",)]
    if active:
        print(f"\n{len(active)} anti-pattern(s) detected:")
        for f in active:
            print(f"  {f['code']} [{f['severity'].upper()}] {f['title']} — {f['count']} occurrence(s)")
    else:
        print("\nNo anti-patterns detected. ✓")


if __name__ == "__main__":
    main()
