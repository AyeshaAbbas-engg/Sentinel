# SENTINEL — Positioning & Research Framing

*Working brief for the FMware-operations research direction. Also the source
material for the MITACS Statement of Interest.*

---

## One-line positioning

> **SENTINEL is an operational control plane for FM-powered software: it runs a
> foundation-model inference pipeline as a monitored distributed system,
> instruments every hop for performance and cost, and mines its own execution
> logs into a catalogue of operational anti-patterns — a practical tool plus the
> best practices to operate it.**

## The problem it addresses

A demo that calls a foundation model is not yet a *system*. Turning FM-powered
software (**FMware**) into something production-ready requires the operational
scaffolding that ordinary services have long had: identity and access control,
externalized policy, end-to-end monitoring, cost and latency attribution, and
graceful failure handling. That gap — from *cool demo* to *production-ready,
trustworthy FMware* — is a **software-engineering** problem of analytics,
performance, monitoring, and operability.

## Why this aligns with the FMware-operations research agenda

The target research programme concerns **engineering tools and best practices for
operationalizing foundation models** — with specialization in software analytics,
software performance engineering, source-code analysis, software visualization,
and the monitoring and debugging of distributed systems. SENTINEL maps onto that
agenda point by point:

| Research axis | How SENTINEL instantiates it |
|---------------|------------------------------|
| **Operationalizing FM models** | A runnable pipeline that makes an FM app operable: auth, policy, routing, monitoring, fail-closed handling. |
| **Software performance engineering** | Per-request latency/cost measurement; the finding that the FM backend dominates end-to-end cost by 3–4 orders of magnitude; roadmap to per-hop cost breakdown and model-selection trade-offs. |
| **Monitoring & debugging of distributed systems** | A six-service stack with Prometheus/Grafana, a per-stage trace endpoint, and structured audit logs — the FM pipeline treated as a distributed system to be observed and debugged. |
| **Software analytics** | Privacy-preserving JSONL audit logs as a mineable substrate; roadmap to mine them into an operational anti-pattern catalogue. |
| **Software visualization** | Grafana dashboards today; per-hop latency/cost visualization for compound pipelines next. |

Security/governance is treated as **one observable dimension of operational
trustworthiness**, not the headline — consistent with an agenda centered on
operations, performance, and analytics rather than security per se.

## Current evidence (honest baseline)

The implemented system now supports the compound two-hop path, per-hop telemetry,
and log mining described below. Benchmark reports are generated artifacts, not
static claims: use the newest completed `research/results/benchmark_report_*.md`
and its paired raw JSON when reporting results.

Report all three outcomes together: governance accuracy (including false
negatives/positives), availability (timeouts and 5xx responses), and latency/cost
for completed requests. On CPU, the expected operational finding is that model
inference dominates the lightweight control-plane stages; the benchmark exists to
quantify that finding rather than assume it.

## Contribution trajectory (toward a preprint)

1. **Multi-model, two-hop pipeline** — ✅ implemented: intent/complexity classifier hop → model
   selection → generation hop; reproduces production cost/latency/quality
   trade-offs and turns one latency number into a per-hop breakdown.
2. **Per-hop governance & instrumentation** — ✅ implemented for classifier-aware policy and telemetry.
3. **Per-hop monitoring & visualization** — ✅ implemented: trace endpoint + Grafana panels
   showing where time and cost go across hops.
4. **Log-based analytics** — ✅ implemented: mine audit/telemetry into a catalogue of FMware
   operational anti-patterns (redundant hops, timeout cascades, cost blowups on
   low-value requests).
5. **Write-up** — a preprint: *"SENTINEL: An Operational Trustworthiness Layer for
   Compound FMware."*

## Reference framing (not competitors)

The work is positioned against the *research framing* of FMware operations, not a
feature matrix of guardrail products:

- Curated challenges in trustworthy FMware — FSE 2024, arXiv:2402.15943
- A Hitchhiker's Guide to production-ready trustworthy FMware — KDD 2025, arXiv:2505.10640
- From cool demos to production-ready FMware — TOSEM
- Towards AI-native software engineering / SE 3.0 — arXiv:2410.06107

No head-to-head accuracy claims are made against other tools; any such comparison
would require running the same dataset through each under identical conditions.
