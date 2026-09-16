"""Evaluation metric computations: Precision, Recall, F1, Accuracy, FPR, FNR, and MCC."""

import math
from typing import Dict, Any, List


def calculate_mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    """Calculates Matthews Correlation Coefficient (MCC).
    
    Formula:
        MCC = (TP*TN - FP*FN) / sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN))
    Returns value between -1.0 and +1.0. Returns 0.0 if denominator is zero.
    """
    numerator = (tp * tn) - (fp * fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def compute_metrics(predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes full suite of classification and error metrics from binary predictions.
    
    Each item in predictions must have:
        'ground_truth': bool
        'detected': bool
    """
    tp = sum(1 for p in predictions if p["ground_truth"] and p["detected"])
    fp = sum(1 for p in predictions if not p["ground_truth"] and p["detected"])
    tn = sum(1 for p in predictions if not p["ground_truth"] and not p["detected"])
    fn = sum(1 for p in predictions if p["ground_truth"] and not p["detected"])

    total = len(predictions)
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0
    mcc = calculate_mcc(tp, tn, fp, fn)

    return {
        "total_samples": total,
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn
        },
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "fnr": fnr,
        "mcc": mcc
    }
