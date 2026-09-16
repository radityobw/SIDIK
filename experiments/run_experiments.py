"""Automated experiment runner for benchmark evaluation against test dataset and baselines."""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
import time
import tracemalloc
import statistics
from typing import Dict, Any, List

from sidik.secret_detector.detector import SecretDetector
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer
from experiments.baseline_runners import BaselineRegexSecretScanner, PipAuditBaselineScanner
from experiments.evaluate_metrics import compute_metrics

DATASET_DIR = os.path.join(BASE_DIR, "dataset")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def run_secret_experiment(reps: int = 5) -> Dict[str, Any]:
    """Runs comparative evaluation for secret detection (Proposed vs Baseline)."""
    print("Running Secret Detection Benchmark (Proposed vs Baseline)...", flush=True)
    gt_file = os.path.join(DATASET_DIR, "ground_truth", "secrets_ground_truth.json")
    with open(gt_file, "r", encoding="utf-8") as f:
        all_gt = json.load(f)

    test_gt = [item for item in all_gt if item.get("split") == "test"]

    proposed_detector = SecretDetector(enable_context=True, enable_entropy=True)
    baseline_detector = BaselineRegexSecretScanner()

    # Predictions collection
    proposed_preds = []
    baseline_preds = []

    for item in test_gt:
        file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
        if not os.path.exists(file_path):
            file_path = os.path.join(DATASET_DIR, item["file_path"].replace("dataset/", ""))

        # Proposed run
        p_findings = proposed_detector.scan_file(file_path)
        proposed_preds.append({
            "sample_id": item["sample_id"],
            "ground_truth": item["ground_truth"],
            "detected": len(p_findings) > 0,
            "category": item.get("category")
        })

        # Baseline run
        b_findings = baseline_detector.scan_file(file_path)
        baseline_preds.append({
            "sample_id": item["sample_id"],
            "ground_truth": item["ground_truth"],
            "detected": len(b_findings) > 0,
            "category": item.get("category")
        })

    # Benchmark resource consumption over N repetitions
    proposed_times = []
    proposed_mems = []
    baseline_times = []
    baseline_mems = []

    for _ in range(reps):
        # Proposed timing
        tracemalloc.start()
        t0 = time.perf_counter()
        for item in test_gt:
            file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
            proposed_detector.scan_file(file_path)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        proposed_times.append(t1 - t0)
        proposed_mems.append(peak / (1024 * 1024))

        # Baseline timing
        tracemalloc.start()
        t0 = time.perf_counter()
        for item in test_gt:
            file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
            baseline_detector.scan_file(file_path)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        baseline_times.append(t1 - t0)
        baseline_mems.append(peak / (1024 * 1024))

    prop_metrics = compute_metrics(proposed_preds)
    prop_metrics["performance"] = {
        "mean_time_seconds": round(statistics.mean(proposed_times), 4),
        "std_time_seconds": round(statistics.stdev(proposed_times) if reps > 1 else 0.0, 4),
        "mean_peak_memory_mb": round(statistics.mean(proposed_mems), 4),
        "std_peak_memory_mb": round(statistics.stdev(proposed_mems) if reps > 1 else 0.0, 4)
    }

    base_metrics = compute_metrics(baseline_preds)
    base_metrics["performance"] = {
        "mean_time_seconds": round(statistics.mean(baseline_times), 4),
        "std_time_seconds": round(statistics.stdev(baseline_times) if reps > 1 else 0.0, 4),
        "mean_peak_memory_mb": round(statistics.mean(baseline_mems), 4),
        "std_peak_memory_mb": round(statistics.stdev(baseline_mems) if reps > 1 else 0.0, 4)
    }

    print("Secret Detection Benchmark complete.", flush=True)
    return {
        "test_samples_count": len(test_gt),
        "proposed_secret_detector": prop_metrics,
        "baseline_regex_detector": base_metrics
    }


def run_dependency_experiment(reps: int = 5) -> Dict[str, Any]:
    """Runs comparative evaluation for dependency security analysis."""
    print("Running Dependency Security Benchmark...", flush=True)
    gt_file = os.path.join(DATASET_DIR, "ground_truth", "dependencies_ground_truth.json")
    with open(gt_file, "r", encoding="utf-8") as f:
        all_gt = json.load(f)

    test_gt = [item for item in all_gt if item.get("split") == "test"]
    proposed_analyzer = DependencyAnalyzer()

    proposed_preds = []
    pipaudit_preds = []

    for item in test_gt:
        file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
        if not os.path.exists(file_path):
            file_path = os.path.join(DATASET_DIR, item["file_path"].replace("dataset/", ""))

        # Proposed run
        p_findings = proposed_analyzer.scan_manifest_file(file_path)
        proposed_preds.append({
            "sample_id": item["sample_id"],
            "ground_truth": item["ground_truth"],
            "detected": len(p_findings) > 0,
            "manifest_type": item.get("manifest_type")
        })

        # Baseline Pip-Audit run (on requirements.txt cases, capped at 6 to avoid network latency)
        if item.get("manifest_type") == "requirements.txt" and len(pipaudit_preds) < 6:
            b_findings = PipAuditBaselineScanner.scan_requirements_file(file_path)
            pipaudit_preds.append({
                "sample_id": item["sample_id"],
                "ground_truth": item["ground_truth"],
                "detected": len(b_findings) > 0,
                "manifest_type": "requirements.txt"
            })

    # Benchmark performance
    proposed_times = []
    proposed_mems = []

    for _ in range(reps):
        tracemalloc.start()
        t0 = time.perf_counter()
        for item in test_gt:
            file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
            proposed_analyzer.scan_manifest_file(file_path)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        proposed_times.append(t1 - t0)
        proposed_mems.append(peak / (1024 * 1024))

    prop_metrics = compute_metrics(proposed_preds)
    prop_metrics["performance"] = {
        "mean_time_seconds": round(statistics.mean(proposed_times), 4),
        "std_time_seconds": round(statistics.stdev(proposed_times) if reps > 1 else 0.0, 4),
        "mean_peak_memory_mb": round(statistics.mean(proposed_mems), 4),
        "std_peak_memory_mb": round(statistics.stdev(proposed_mems) if reps > 1 else 0.0, 4)
    }

    pipaudit_metrics = compute_metrics(pipaudit_preds) if pipaudit_preds else {}

    print("Dependency Security Benchmark complete.", flush=True)
    return {
        "test_samples_count": len(test_gt),
        "proposed_dependency_analyzer": prop_metrics,
        "baseline_pip_audit": pipaudit_metrics
    }


def main():
    print("Executing RQ1, RQ2, RQ3, and RQ4 experiments across test ground truth...", flush=True)
    secret_results = run_secret_experiment(reps=5)
    dep_results = run_dependency_experiment(reps=5)

    full_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "secret_experiment": secret_results,
        "dependency_experiment": dep_results
    }

    output_path = os.path.join(RESULTS_DIR, "experiment_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2)

    print(f"Experiments successfully completed. Results written to: {output_path}", flush=True)


if __name__ == "__main__":
    main()
