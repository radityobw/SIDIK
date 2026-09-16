import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
from typing import Dict, Any
from sidik.secret_detector.detector import SecretDetector
from experiments.evaluate_metrics import compute_metrics

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def run_ablation_study() -> Dict[str, Any]:
    gt_file = os.path.join(DATASET_DIR, "ground_truth", "secrets_ground_truth.json")
    with open(gt_file, "r", encoding="utf-8") as f:
        all_gt = json.load(f)

    test_gt = [item for item in all_gt if item.get("split") == "test"]

    configurations = [
        {"name": "Config A (Pattern Only)", "context": False, "entropy": False},
        {"name": "Config B (Pattern + Context)", "context": True, "entropy": False},
        {"name": "Config C (Pattern + Entropy)", "context": False, "entropy": True},
        {"name": "Config D (Pattern + Context + Entropy)", "context": True, "entropy": True}
    ]

    ablation_results = {}

    for cfg in configurations:
        detector = SecretDetector(enable_context=cfg["context"], enable_entropy=cfg["entropy"])
        preds = []
        for item in test_gt:
            file_path = os.path.join(BASE_DIR, "dataset", item["file_path"].replace("dataset/", ""))
            if not os.path.exists(file_path):
                file_path = os.path.join(DATASET_DIR, item["file_path"].replace("dataset/", ""))

            findings = detector.scan_file(file_path)
            preds.append({
                "sample_id": item["sample_id"],
                "ground_truth": item["ground_truth"],
                "detected": len(findings) > 0
            })

        metrics = compute_metrics(preds)
        ablation_results[cfg["name"]] = {
            "config": {
                "pattern": True,
                "context": cfg["context"],
                "entropy": cfg["entropy"]
            },
            "metrics": metrics
        }

    output_path = os.path.join(RESULTS_DIR, "ablation_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)

    print(f"Ablation study completed. Results written to: {output_path}")
    return ablation_results


if __name__ == "__main__":
    run_ablation_study()
