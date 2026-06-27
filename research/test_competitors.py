#!/usr/bin/env python3
"""
Competitor Benchmark: Tests LLM Guard on the same dataset as SENTINEL.
This gives you a fair, reproducible comparison.

Install: pip install llm-guard
Run: python3 research/test_competitors.py
"""

import json
import time
from pathlib import Path

DATASET_PATH = Path(__file__).parent / "benchmark_dataset.json"
RESULTS_DIR = Path(__file__).parent / "results"


def test_llm_guard(dataset):
    """Test LLM Guard's injection scanner on same prompts."""
    try:
        from llm_guard.input_scanners import PromptInjection, BanTopics
        from llm_guard.input_scanners.prompt_injection import MatchType
    except ImportError:
        print("Install llm-guard: pip install llm-guard")
        return None

    scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
    results = {"attacks": [], "benign": []}

    print("\n[LLM Guard] Testing attacks...")
    for sample in dataset["attacks"]:
        start = time.time()
        sanitized, is_valid, risk = scanner.scan("", sample["prompt"])
        latency = int((time.time() - start) * 1000)
        detected = not is_valid  # is_valid=False means injection detected
        results["attacks"].append({
            "id": sample["id"],
            "category": sample["category"],
            "detected": detected,
            "correct": detected,  # attacks should be detected
            "risk": risk,
            "latency_ms": latency,
        })

    print("[LLM Guard] Testing benign...")
    for sample in dataset["benign"]:
        start = time.time()
        sanitized, is_valid, risk = scanner.scan("", sample["prompt"])
        latency = int((time.time() - start) * 1000)
        detected = not is_valid
        results["benign"].append({
            "id": sample["id"],
            "category": sample["category"],
            "detected": detected,
            "correct": not detected,  # benign should NOT be detected
            "risk": risk,
            "latency_ms": latency,
        })

    return results


def compute_metrics(results, tool_name):
    """Compute standard metrics for a tool's results."""
    attacks = results["attacks"]
    benign = results["benign"]

    tp = sum(1 for r in attacks if r["detected"])
    fn = sum(1 for r in attacks if not r["detected"])
    tn = sum(1 for r in benign if not r["detected"])
    fp = sum(1 for r in benign if r["detected"])

    detection_rate = tp / len(attacks) if attacks else 0
    fpr = fp / len(benign) if benign else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = detection_rate
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    latencies = [r["latency_ms"] for r in attacks + benign]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print(f"\n{'='*50}")
    print(f"  {tool_name} RESULTS")
    print(f"{'='*50}")
    print(f"  Detection Rate: {detection_rate*100:.1f}%")
    print(f"  False Positive Rate: {fpr*100:.1f}%")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  F1 Score: {f1:.4f}")
    print(f"  Avg Latency: {avg_latency:.0f}ms")

    # Per-category
    categories = {}
    for r in attacks:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0}
        categories[cat]["total"] += 1
        if r["detected"]:
            categories[cat]["detected"] += 1

    print(f"\n  Per-Category:")
    for cat, data in sorted(categories.items()):
        rate = data["detected"] / data["total"] * 100
        print(f"    {cat}: {rate:.0f}% ({data['detected']}/{data['total']})")

    # Missed attacks
    missed = [r for r in attacks if not r["detected"]]
    if missed:
        print(f"\n  Missed attacks ({len(missed)}):")
        for r in missed[:10]:
            print(f"    - {r['id']} ({r['category']})")

    # False positives
    fps = [r for r in benign if r["detected"]]
    if fps:
        print(f"\n  False positives ({len(fps)}):")
        for r in fps:
            print(f"    - {r['id']} ({r['category']})")

    return {
        "tool": tool_name,
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "avg_latency_ms": round(avg_latency, 1),
        "per_category": categories,
    }


def main():
    with open(DATASET_PATH) as f:
        dataset = json.load(f)

    print("=" * 50)
    print("  COMPETITOR BENCHMARK")
    print("  Same dataset, fair comparison")
    print("=" * 50)

    all_metrics = []

    # Test LLM Guard
    print("\n[*] Testing LLM Guard...")
    llm_guard_results = test_llm_guard(dataset)
    if llm_guard_results:
        metrics = compute_metrics(llm_guard_results, "LLM Guard")
        all_metrics.append(metrics)

    # Save comparison
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "competitor_results.json", "w") as f:
        json.dump(all_metrics, f, indent=2)

    print(f"\n[✓] Results saved to research/results/competitor_results.json")
    print("\nNow run: python3 research/run_benchmark.py")
    print("Then compare the two results side by side.")


if __name__ == "__main__":
    main()
