"""Publication-quality chart and visualization generator for research paper."""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
import matplotlib.pyplot as plt
import numpy as np

FIGURES_DIR = os.path.join(BASE_DIR, "figures")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(FIGURES_DIR, exist_ok=True)

# Set clean aesthetic style
plt.rcParams.update({
    'font.sans-serif': 'DejaVu Sans',
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 13
})


def plot_detection_metrics_comparison(exp_data):
    """Figure 1: Comparison between Proposed and Baseline across Precision, Recall, F1, and MCC."""
    sec_prop = exp_data["secret_experiment"]["proposed_secret_detector"]
    sec_base = exp_data["secret_experiment"]["baseline_regex_detector"]

    metrics = ["Precision", "Recall", "F1-Score", "MCC"]
    prop_scores = [sec_prop["precision"], sec_prop["recall"], sec_prop["f1_score"], sec_prop["mcc"]]
    base_scores = [sec_base["precision"], sec_base["recall"], sec_base["f1_score"], sec_base["mcc"]]

    x = np.arange(len(metrics))
    width = 0.32

    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=300)
    rects1 = ax.bar(x - width/2, prop_scores, width, label='Proposed (Context + Entropy)', color='#1f77b4', edgecolor='black', linewidth=0.8)
    rects2 = ax.bar(x + width/2, base_scores, width, label='Baseline (Regex Only)', color='#ff7f0e', edgecolor='black', linewidth=0.8)

    ax.set_ylabel('Score (0.0 - 1.0)')
    ax.set_title('Secret Detection Performance: Proposed vs. Baseline')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.legend(loc='upper right', frameon=True)

    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.2f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight='bold')

    autolabel(rects1)
    autolabel(rects2)

    fig.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig1_detection_metrics_comparison.png")
    plt.savefig(out_path)
    plt.close()
    print(f"Saved: {out_path}")


def plot_ablation_study(abl_data):
    """Figure 2: Performance trajectory across Ablation Configurations A, B, C, D."""
    configs = ["Config A\n(Pattern Only)", "Config B\n(Pattern+Context)", "Config C\n(Pattern+Entropy)", "Config D\n(Full Proposed)"]
    keys = [
        "Config A (Pattern Only)",
        "Config B (Pattern + Context)",
        "Config C (Pattern + Entropy)",
        "Config D (Pattern + Context + Entropy)"
    ]

    precisions = [abl_data[k]["metrics"]["precision"] for k in keys]
    recalls = [abl_data[k]["metrics"]["recall"] for k in keys]
    f1_scores = [abl_data[k]["metrics"]["f1_score"] for k in keys]
    mccs = [abl_data[k]["metrics"]["mcc"] for k in keys]
    fps = [abl_data[k]["metrics"]["confusion_matrix"]["FP"] for k in keys]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2), dpi=300)

    # Subplot 1: Metrics
    x = np.arange(len(configs))
    ax1.plot(x, precisions, marker='o', linewidth=2, label='Precision', color='#2ca02c')
    ax1.plot(x, recalls, marker='s', linewidth=2, label='Recall', color='#1f77b4')
    ax1.plot(x, f1_scores, marker='^', linewidth=2, label='F1-Score', color='#d62728')
    ax1.plot(x, mccs, marker='D', linewidth=2, label='MCC', color='#9467bd')
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=8)
    ax1.set_ylabel('Score')
    ax1.set_ylim(0.4, 1.05)
    ax1.set_title('Ablation Study: Detection Effectiveness')
    ax1.grid(True, linestyle='--', alpha=0.5)
    ax1.legend(loc='lower right')

    # Subplot 2: False Positive Reduction
    bars = ax2.bar(configs, fps, color=['#d62728', '#ff7f0e', '#bcbd22', '#2ca02c'], edgecolor='black', width=0.5)
    ax2.set_ylabel('False Positive Count (Alerts)')
    ax2.set_title('False Positive Suppression across Configurations')
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    for bar in bars:
        h = bar.get_height()
        ax2.annotate(f'{int(h)}', xy=(bar.get_x() + bar.get_width()/2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')

    fig.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig2_ablation_study.png")
    plt.savefig(out_path)
    plt.close()
    print(f"Saved: {out_path}")


def plot_confusion_matrices(exp_data):
    """Figure 3: Confusion Matrix visualization for Secret and Dependency scanners."""
    sec_cm = exp_data["secret_experiment"]["proposed_secret_detector"]["confusion_matrix"]
    dep_cm = exp_data["dependency_experiment"]["proposed_dependency_analyzer"]["confusion_matrix"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 3.8), dpi=300)

    for ax, cm, title in [(ax1, sec_cm, "Secret Detector (N=100)"), (ax2, dep_cm, "Dependency Analyzer (N=60)")]:
        matrix = np.array([[cm["TP"], cm["FN"]], [cm["FP"], cm["TN"]]])
        im = ax.imshow(matrix, cmap='Blues', interpolation='nearest')
        ax.set_title(title, pad=10)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred Positive', 'Pred Negative'])
        ax.set_yticklabels(['Actual Positive', 'Actual Negative'])

        for i in range(2):
            for j in range(2):
                val = matrix[i, j]
                color = "white" if val > matrix.max() / 2 else "black"
                ax.text(j, i, f"{val}", ha="center", va="center", color=color, fontsize=12, fontweight='bold')

    fig.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig3_confusion_matrices.png")
    plt.savefig(out_path)
    plt.close()
    print(f"Saved: {out_path}")


def plot_performance_overhead(exp_data):
    """Figure 4: Resource consumption (Scan Time & Peak Memory) across proposed scanners."""
    sec_perf = exp_data["secret_experiment"]["proposed_secret_detector"]["performance"]
    dep_perf = exp_data["dependency_experiment"]["proposed_dependency_analyzer"]["performance"]

    modules = ["Secret Detector\n(100 Files)", "Dependency Analyzer\n(60 Manifests)"]
    times_ms = [sec_perf["mean_time_seconds"] * 1000, dep_perf["mean_time_seconds"] * 1000]
    mems_mb = [sec_perf["mean_peak_memory_mb"], dep_perf["mean_peak_memory_mb"]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.5), dpi=300)

    # Execution Time
    b1 = ax1.bar(modules, times_ms, color='#3498db', edgecolor='black', width=0.45)
    ax1.set_ylabel('Scan Time (milliseconds)')
    ax1.set_title('Average Execution Time (N=5 runs)')
    ax1.grid(axis='y', linestyle='--', alpha=0.5)
    for b in b1:
        ax1.annotate(f"{b.get_height():.1f} ms", xy=(b.get_x() + b.get_width()/2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=8)

    # Peak Memory
    b2 = ax2.bar(modules, mems_mb, color='#e67e22', edgecolor='black', width=0.45)
    ax2.set_ylabel('Peak Memory (MB)')
    ax2.set_title('Peak Memory Allocation')
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    for b in b2:
        ax2.annotate(f"{b.get_height():.2f} MB", xy=(b.get_x() + b.get_width()/2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=8)

    fig.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig4_performance_overhead.png")
    plt.savefig(out_path)
    plt.close()
    print(f"Saved: {out_path}")


def main():
    exp_file = os.path.join(RESULTS_DIR, "experiment_results.json")
    abl_file = os.path.join(RESULTS_DIR, "ablation_results.json")

    if not os.path.exists(exp_file):
        print(f"Error: {exp_file} not found. Run run_experiments.py first.")
        return

    with open(exp_file, "r", encoding="utf-8") as f:
        exp_data = json.load(f)

    plot_detection_metrics_comparison(exp_data)
    plot_confusion_matrices(exp_data)
    plot_performance_overhead(exp_data)

    if os.path.exists(abl_file):
        with open(abl_file, "r", encoding="utf-8") as f:
            abl_data = json.load(f)
        plot_ablation_study(abl_data)

    print("All scientific visualization figures generated successfully in figures/")


if __name__ == "__main__":
    main()
