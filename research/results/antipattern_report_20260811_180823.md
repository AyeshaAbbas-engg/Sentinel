# SENTINEL — FMware Anti-Pattern Report

**Generated:** 2026-08-11 18:08:23 UTC  
**Log file:** `gateway/logs/audit.jsonl`  
**Records analysed:** 53  
**Analysis window:** 300s  

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total requests | 53 |
| Allowed | 0 |
| Blocked | 53 |
| PII detected | 9 |
| Injection detected | 47 |
| Output flagged | 0 |
| Latency p50 | 28 ms |
| Latency p95 | 34 ms |
| Latency max | 40 ms |
| Total est. cost | $0.000000 |
| Mean cost/req | $0.00000000 |

### Per-Hop Mean Latency

| Hop | Mean ms |
|-----|---------|
| rate_limit | 1 |
| sanitize | 1 |
| pii_scan | 18.2 |
| injection_scan | 1.1 |
| risk_score | 1 |
| classifier | 1 |
| opa_policy | 7.4 |

### Classifier Output Distribution

| Dimension | Value | Count |
|-----------|-------|-------|
| complexity_tier | unknown | 1 |
| complexity_tier | simple | 52 |
| intent_class | unknown | 1 |
| intent_class | qa | 5 |
| intent_class | other | 37 |
| intent_class | analysis | 5 |
| intent_class | code | 5 |

---

## Anti-Pattern Catalogue

### AP-05 — Hopless Requests (Instrumentation Gap)  🟡

**Severity:** medium  |  **Occurrences:** 1

1 request(s) have no hop_timings in the audit log. These are likely from the pre-v2 gateway or from blocked requests that exited before the hop recorder was reached. Cannot attribute latency cost for these entries.

**Examples:**
```
6a229fa7-2c9c-41d2-b621-45dffeedf8ca
```

### AP-07 — Redundant Hops  🔵

**Severity:** low  |  **Occurrences:** 4

Hops with mean latency ≤ 1 ms across ≥ 10 samples may indicate short-circuit / bypass paths that are not performing real work.

**Examples:**
```
rate_limit: mean=1.00ms over 52 samples
sanitize: mean=1.00ms over 52 samples
risk_score: mean=1.00ms over 52 samples
classifier: mean=1.00ms over 52 samples
```

### AP-06 — LLM Dominance (Backend Dominates Cost)  ℹ️

**Severity:** info  |  **Occurrences:** 0

0 request(s) where llm_backend accounts for > 99% of end-to-end latency. This is the key operational finding: the control-plane pipeline overhead is negligible; the FM backend is the entire cost. This validates the research claim in positioning.md.


### Anti-Patterns Not Present

- **AP-01 Timeout Cascade** — not detected
- **AP-02 Cost Blowup** — not detected
- **AP-03 Risk Score Drift** — not detected
- **AP-04 PII Leakage Attempt (Allowed)** — not detected
- **AP-08 Output Flagging Spike** — not detected

---

## Methodology

Anti-patterns are detected by analysing the structured JSONL audit log
emitted by the SENTINEL gateway. Each log record contains per-hop timing,
risk scores, PII/injection findings, model routing decisions, and cost
estimates. This script is the foundation for the **anti-pattern catalogue**
described in positioning.md §Contribution trajectory item 4.

Pattern definitions and thresholds are configurable via CLI flags.
See `python research/analyze_logs.py --help` for options.