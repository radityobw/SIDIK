"""Publication-quality chart and GUI dark-theme visualization generator for SIDIK research."""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

FIGURES_DIR = os.path.join(BASE_DIR, "figures")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(FIGURES_DIR, exist_ok=True)

# Set clean aesthetic style for paper figures
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
    ax.set_title('Secret Detection Performance: Proposed vs. Baseline (N=100)')
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

    x = np.arange(len(configs))
    ax1.plot(x, precisions, marker='o', linewidth=2, label='Precision', color='#2ca02c')
    ax1.plot(x, recalls, marker='s', linewidth=2, label='Recall', color='#1f77b4')
    ax1.plot(x, f1_scores, marker='^', linewidth=2, label='F1-Score', color='#d62728')
    ax1.plot(x, mccs, marker='D', linewidth=2, label='MCC', color='#9467bd')
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=8)
    ax1.set_ylabel('Score')
    ax1.set_ylim(0.4, 1.05)
    ax1.set_title('Ablation Study: Detection Effectiveness (N=100)')
    ax1.grid(True, linestyle='--', alpha=0.5)
    ax1.legend(loc='lower right')

    bars = ax2.bar(configs, fps, color=['#d62728', '#2ca02c', '#ff7f0e', '#2ca02c'], edgecolor='black', width=0.5)
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


def plot_confusion_matrices(exp_data, sca_data=None):
    """Figure 3: Confusion Matrix visualization for Secret (N=100) and Dependency v2 (N=200) scanners."""
    sec_cm = exp_data["secret_experiment"]["proposed_secret_detector"]["confusion_matrix"]
    if sca_data and len(sca_data) > 0:
        s0 = sca_data[0]
        dep_cm = {"TP": s0["tp"], "FP": s0["fp"], "TN": s0["tn"], "FN": s0["fn"]}
        dep_title = "Dependency Analyzer v2 (N=200)"
    else:
        dep_cm = exp_data["dependency_experiment"]["proposed_dependency_analyzer"]["confusion_matrix"]
        dep_title = "Dependency Analyzer (N=60)"

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 3.8), dpi=300)

    for ax, cm, title in [(ax1, sec_cm, "Secret Detector (N=100)"), (ax2, dep_cm, dep_title)]:
        matrix = np.array([[cm["TP"], cm["FN"]], [cm["FP"], cm["TN"]]])
        ax.imshow(matrix, cmap='Blues', interpolation='nearest')
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

    b1 = ax1.bar(modules, times_ms, color='#3498db', edgecolor='black', width=0.45)
    ax1.set_ylabel('Scan Time (milliseconds)')
    ax1.set_title('Average Execution Time (N=5 runs)')
    ax1.grid(axis='y', linestyle='--', alpha=0.5)
    for b in b1:
        ax1.annotate(f"{b.get_height():.1f} ms", xy=(b.get_x() + b.get_width()/2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=8)

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


def plot_comparative_industry_tools():
    """Figure 5: Secret and SCA Benchmark against Industry Tools."""
    sec_file = os.path.join(RESULTS_DIR, "secret_comparative_benchmark.json")
    sca_file = os.path.join(RESULTS_DIR, "sca_comparative_benchmark.json")
    if not os.path.isfile(sec_file) or not os.path.isfile(sca_file):
        return

    sec_data = json.load(open(sec_file, encoding="utf-8"))
    sca_data = json.load(open(sca_file, encoding="utf-8"))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 4.0), dpi=300)

    tools_sec = [d["tool"].replace(" (v8.30.1)", "").replace(" (v1.9.4)", "").replace(" (Usulan)", "") for d in sec_data]
    fprs = [d["fpr"] * 100 for d in sec_data]
    times = [d["total_time_seconds"] for d in sec_data]

    x = np.arange(len(tools_sec))
    width = 0.38

    b1 = ax1.bar(x - width/2, fprs, width, label='False Positive Rate (%)', color='#e74c3c', edgecolor='black', linewidth=0.8)
    b2 = ax1.bar(x + width/2, times, width, label='Scan Time (s)', color='#3498db', edgecolor='black', linewidth=0.8)

    ax1.set_ylabel('Percentage / Seconds')
    ax1.set_title('Secret Detection: FPR vs. Scan Time (N=25 Repos)')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools_sec, fontsize=8)
    ax1.grid(axis='y', linestyle='--', alpha=0.5)
    ax1.legend(loc='upper left', frameon=True)

    for b in b1:
        h = b.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(b.get_x() + b.get_width()/2, h),
                     xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7, fontweight='bold')
    for b in b2:
        h = b.get_height()
        ax1.annotate(f"{h:.1f}s", xy=(b.get_x() + b.get_width()/2, h),
                     xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7, fontweight='bold')

    tools_sca = [d["tool"].split(" (")[0] for d in sca_data]
    f1s = [d["f1_score"] * 100 for d in sca_data]
    sca_times = [d["scan_time_seconds"] for d in sca_data]

    x2 = np.arange(len(tools_sca))
    b3 = ax2.bar(x2 - width/2, f1s, width, label='F1-Score (%)', color='#2ecc71', edgecolor='black', linewidth=0.8)
    b4 = ax2.bar(x2 + width/2, sca_times, width, label='Scan Time (s)', color='#9b59b6', edgecolor='black', linewidth=0.8)

    ax2.set_ylabel('Percentage / Seconds')
    ax2.set_title('SCA Benchmark: F1-Score vs. Latency (N=200)')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(tools_sca, fontsize=8)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    ax2.legend(loc='upper right', frameon=True)

    for b in b3:
        h = b.get_height()
        ax2.annotate(f"{h:.1f}%", xy=(b.get_x() + b.get_width()/2, h),
                     xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7, fontweight='bold')
    for b in b4:
        h = b.get_height()
        ax2.annotate(f"{h:.1f}s", xy=(b.get_x() + b.get_width()/2, h),
                     xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7, fontweight='bold')

    fig.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig5_comparative_industry_tools.png")
    plt.savefig(out_path)
    plt.close()
    print(f"Saved: {out_path}")


def generate_gui_dark_benchmark_figures(exp_data, abl_data, sec_comp, sca_comp):
    """Generates dark-themed high-resolution figures for Tab 2 ('Benchmark Riset (Paper)') in the GUI."""
    bg = "#13181f"
    bg2 = "#1c2230"
    fg = "#e6edf3"
    fg2 = "#8b949e"
    grid_c = "#30363d"
    c_blue = "#3b82f6"
    c_orange = "#f97316"
    c_green = "#22c55e"
    c_red = "#ef4444"
    c_purple = "#a855f7"
    c_cyan = "#06b6d4"

    def style_ax(ax, title, ylabel=""):
        ax.set_facecolor(bg2)
        ax.set_title(title, color=fg, fontsize=11.5, pad=10, fontweight="bold")
        if ylabel:
            ax.set_ylabel(ylabel, color=fg2, fontsize=9.5)
        ax.tick_params(colors=fg2, labelsize=9)
        for sp in ax.spines.values():
            sp.set_color(grid_c)
        ax.set_axisbelow(True)
        ax.yaxis.grid(True, color=grid_c, linewidth=0.6, linestyle="--", alpha=0.7)

    def label_bars(ax, bars, fmt="{:.2f}", suffix="", fontsize=8.5):
        ymax = ax.get_ylim()[1]
        for bar in bars:
            h = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + ymax * 0.018,
                fmt.format(h) + suffix,
                ha="center", va="bottom",
                color=fg, fontsize=fontsize, fontweight="bold"
            )

    sec_prop = exp_data["secret_experiment"]["proposed_secret_detector"]
    sec_base = exp_data["secret_experiment"]["baseline_regex_detector"]

    # ── 1. GUI RQ1: Controlled Secret Benchmark (N=100) + 25 Real GitHub Repos ──
    fig1, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.6), dpi=160, facecolor=bg)
    style_ax(ax1, "RQ1 (A): Uji Terkontrol Secret (N=100 Berkas)", "Skor (0.0 - 1.0)")
    m_labels = ["Precision", "Recall", "F1-Score", "MCC"]
    x1 = np.arange(len(m_labels))
    w = 0.34
    b1 = ax1.bar(x1 - w/2, [sec_prop["precision"], sec_prop["recall"], sec_prop["f1_score"], sec_prop["mcc"]],
                 w, color=c_blue, edgecolor=grid_c, label="SIDIK (Regex + Konteks + Entropi) [0 FP]")
    b2 = ax1.bar(x1 + w/2, [sec_base["precision"], sec_base["recall"], sec_base["f1_score"], sec_base["mcc"]],
                 w, color=c_orange, edgecolor=grid_c, label="Baseline Regex Biasa [10 FP]")
    ax1.set_ylim(0, 1.22)
    ax1.set_xticks(x1)
    ax1.set_xticklabels(m_labels, color=fg)
    label_bars(ax1, b1)
    label_bars(ax1, b2)
    ax1.legend(loc="lower right", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    style_ax(ax2, "RQ1 (B): 25 Repo GitHub Nyata (1.193 Berkas, 109 Kandidat)", "Jumlah FP / Waktu (detik)")
    tools_r = ["SIDIK\n(Usulan)", "Gitleaks\n(v8.30.1)", "Bandit\n(v1.9.4)"]
    fps_r = [14, 0, 98]
    times_r = [3.19, 10.41, 25.26]
    x2 = np.arange(len(tools_r))
    b3 = ax2.bar(x2 - w/2, fps_r, w, color=c_red, edgecolor=grid_c, label="Alarm Palsu / False Positive (Kasus)")
    b4 = ax2.bar(x2 + w/2, times_r, w, color=c_cyan, edgecolor=grid_c, label="Waktu Pemindaian Total (Detik)")
    ax2.set_ylim(0, 118)
    ax2.set_xticks(x2)
    ax2.set_xticklabels(tools_r, color=fg)
    label_bars(ax2, b3, fmt="{:.0f}", suffix=" FP")
    label_bars(ax2, b4, fmt="{:.2f}", suffix="s")
    ax2.legend(loc="upper left", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)
    ax2.text(0.02, 0.78, "SIDIK memangkas 85.7% alarm palsu Bandit\ndan 3.3x lebih cepat dibanding Gitleaks",
             transform=ax2.transAxes, fontsize=8.5, color=fg2,
             bbox=dict(boxstyle="round,pad=0.4", facecolor=bg, edgecolor=grid_c))

    fig1.tight_layout(pad=1.6)
    p_rq1 = os.path.join(FIGURES_DIR, "gui_rq1_secret.png")
    fig1.savefig(p_rq1, dpi=160, facecolor=bg)
    plt.close(fig1)

    # ── 2. GUI RQ2: Multi-Manifest SCA v2 (N=200) vs Trivy & pip-audit ──
    fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.6), dpi=160, facecolor=bg)
    style_ax(ax1, "RQ2 (A): Akurasi SCA Multi-Manifes v2 (200 Paket, 39 Berkas)", "Persentase (%)")
    sca_tools = ["SIDIK\n(5 Format Luring)", "Trivy v0.76.1\n(Lockfile Saja)", "pip-audit v2.10.1\n(req.txt Saja)"]
    rec_vals = [100.0, 35.0, 0.0]
    f1_vals = [100.0, 51.85, 0.0]
    x_sca = np.arange(len(sca_tools))
    bs1 = ax1.bar(x_sca - w/2, rec_vals, w, color=c_green, edgecolor=grid_c, label="Recall Paket Rentan (%)")
    bs2 = ax1.bar(x_sca + w/2, f1_vals, w, color=c_blue, edgecolor=grid_c, label="Skor F1 (%)")
    ax1.set_ylim(0, 122)
    ax1.set_xticks(x_sca)
    ax1.set_xticklabels(sca_tools, color=fg)
    label_bars(ax1, bs1, fmt="{:.1f}", suffix="%")
    label_bars(ax1, bs2, fmt="{:.1f}", suffix="%")
    ax1.legend(loc="upper right", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    style_ax(ax2, "RQ2 (B): Cakupan Format Manifes & Waktu Eksekusi SCA", "Jumlah Format / Waktu (detik)")
    fmt_counts = [5, 2, 1]
    sca_times = [0.33, 132.00, 0.15]
    bs3 = ax2.bar(x_sca - w/2, fmt_counts, w, color=c_purple, edgecolor=grid_c, label="Format Manifes Didukung (Maks 5)")
    bs4 = ax2.bar(x_sca + w/2, sca_times, w, color=c_orange, edgecolor=grid_c, label="Waktu Pemindaian (Detik)")
    ax2.set_ylim(0, 155)
    ax2.set_xticks(x_sca)
    ax2.set_xticklabels(sca_tools, color=fg)
    label_bars(ax2, bs3, fmt="{:.0f}", suffix="/5 fmt")
    label_bars(ax2, bs4, fmt="{:.2f}", suffix="s")
    ax2.legend(loc="upper left", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)
    ax2.text(0.02, 0.74, "5 Format SIDIK:\n- requirements.txt   - Pipfile\n- pyproject.toml     - poetry.lock\n- setup.py (rentang >=, ~=, ==)",
             transform=ax2.transAxes, fontsize=8.5, color=fg2,
             bbox=dict(boxstyle="round,pad=0.4", facecolor=bg, edgecolor=grid_c))

    fig2.tight_layout(pad=1.6)
    p_rq2 = os.path.join(FIGURES_DIR, "gui_rq2_sca.png")
    fig2.savefig(p_rq2, dpi=160, facecolor=bg)
    plt.close(fig2)

    # ── 3. GUI RQ3: Ablation Study (Configs A-D) & Confusion Matrices (N=100 & N=200) ──
    fig3, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.6), dpi=160, facecolor=bg)
    style_ax(ax1, "RQ3 (A): Studi Ablasi 4 Konfigurasi pada N=100 Berkas", "Skor Metrik (0.0 - 1.0)")
    cfg_labels = ["Konfig A\n(Regex Saja)", "Konfig B\n(+Konteks)", "Konfig C\n(+Entropi)", "Konfig D\n(SIDIK Penuh)"]
    cfg_keys = [
        "Config A (Pattern Only)",
        "Config B (Pattern + Context)",
        "Config C (Pattern + Entropy)",
        "Config D (Pattern + Context + Entropy)"
    ]
    precs = [abl_data[k]["metrics"]["precision"] for k in cfg_keys]
    f1s = [abl_data[k]["metrics"]["f1_score"] for k in cfg_keys]
    mccs = [abl_data[k]["metrics"]["mcc"] for k in cfg_keys]
    xc = np.arange(len(cfg_labels))
    ax1.plot(xc, precs, marker="o", linewidth=2.4, color=c_green, label="Precision")
    ax1.plot(xc, f1s, marker="^", linewidth=2.4, color=c_blue, label="F1-Score")
    ax1.plot(xc, mccs, marker="D", linewidth=2.4, color=c_purple, label="MCC")
    for idx_pt in range(len(xc)):
        fp_cnt = abl_data[cfg_keys[idx_pt]]["metrics"]["confusion_matrix"]["FP"]
        ax1.annotate(f"F1: {f1s[idx_pt]:.2f}\n({fp_cnt} FP)", (xc[idx_pt], f1s[idx_pt]),
                     textcoords="offset points", xytext=(0, 10), ha="center",
                     color=fg, fontsize=8.5, fontweight="bold")
    ax1.set_xticks(xc)
    ax1.set_xticklabels(cfg_labels, color=fg)
    ax1.set_ylim(0.60, 1.12)
    ax1.legend(loc="lower right", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    style_ax(ax2, "RQ3 (B): Ringkasan Klasifikasi Benar vs Keliru (TP / TN / FP / FN)", "Jumlah Sampel Uji")
    cm_cats = ["TP\n(Rentan Terdeteksi)", "TN\n(Aman Diabaikan)", "FP\n(Alarm Palsu)", "FN\n(Terlewat)"]
    sec_cm_vals = [45, 50, 0, 5]
    sca_cm_vals = [100, 100, 0, 0]
    xm = np.arange(len(cm_cats))
    bm1 = ax2.bar(xm - w/2, sec_cm_vals, w, color=c_blue, edgecolor=grid_c, label="Deteksi Secret (N=100 Berkas)")
    bm2 = ax2.bar(xm + w/2, sca_cm_vals, w, color=c_green, edgecolor=grid_c, label="Analisis Dependensi SCA v2 (N=200 Paket)")
    ax2.set_ylim(0, 122)
    ax2.set_xticks(xm)
    ax2.set_xticklabels(cm_cats, color=fg)
    label_bars(ax2, bm1, fmt="{:.0f}")
    label_bars(ax2, bm2, fmt="{:.0f}")
    ax2.legend(loc="upper right", fontsize=8.5, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    fig3.tight_layout(pad=1.6)
    p_rq3 = os.path.join(FIGURES_DIR, "gui_rq3_ablation_cm.png")
    fig3.savefig(p_rq3, dpi=160, facecolor=bg)
    plt.close(fig3)

    # ── 4. GUI RQ4: Runtime & Honest Memory Profile ──
    fig4, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.6), dpi=160, facecolor=bg)
    style_ax(ax1, "RQ4 (A): Perbandingan Waktu Eksekusi pada 25 Repo & SCA v2", "Waktu Eksekusi (Detik - Skala Log)")
    t_labels = ["SIDIK\n(25 Repo)", "Gitleaks\n(25 Repo)", "Bandit\n(25 Repo)", "SIDIK\n(SCA 39 File)", "Trivy\n(SCA 39 File)"]
    t_vals = [3.19, 10.41, 25.26, 0.33, 132.00]
    t_cols = [c_blue, c_cyan, c_orange, c_green, c_red]
    bt = ax1.bar(t_labels, t_vals, color=t_cols, edgecolor=grid_c, width=0.5)
    ax1.set_yscale("log")
    ax1.set_ylim(0.1, 350)
    for bar, val in zip(bt, t_vals):
        ax1.text(bar.get_x() + bar.get_width()/2, val * 1.18, f"{val:.2f}s",
                 ha="center", va="bottom", color=fg, fontsize=8.5, fontweight="bold")

    style_ax(ax2, "RQ4 (B): Profil Jujur Konsumsi Memori RAM SIDIK", "Konsumsi Memori (MB - Skala Log)")
    mem_labels = ["Scan Secret\n(N=100 File)", "Scan per Repo\n(Rata-rata)", "Scan SCA v2\n(39 Manifes)", "Scan Gabungan\n(25 Repo Penuh)", "Muat DB OSV\n(1x Saat Awal)"]
    mem_vals = [0.21, 0.39, 1.14, 1.58, 116.47]
    mem_cols = [c_blue, c_green, c_cyan, c_purple, c_orange]
    bm = ax2.bar(mem_labels, mem_vals, color=mem_cols, edgecolor=grid_c, width=0.5)
    ax2.set_yscale("log")
    ax2.set_ylim(0.08, 350)
    for bar, val in zip(bm, mem_vals):
        ax2.text(bar.get_x() + bar.get_width()/2, val * 1.18, f"{val:.2f} MB",
                 ha="center", va="bottom", color=fg, fontsize=8.5, fontweight="bold")
    ax2.text(0.02, 0.78, "Catatan Transparansi:\n- RAM pemindaian aktif sangat ringan (0.15 - 1.58 MB)\n- Muat indeks 29.208 advisori OSV di awal: ~116.47 MB",
             transform=ax2.transAxes, fontsize=8.2, color=fg2,
             bbox=dict(boxstyle="round,pad=0.4", facecolor=bg, edgecolor=grid_c))

    fig4.tight_layout(pad=1.6)
    p_rq4 = os.path.join(FIGURES_DIR, "gui_rq4_perf.png")
    fig4.savefig(p_rq4, dpi=160, facecolor=bg)
    plt.close(fig4)

    # ── 5. MASTER BUNDLE (4-in-1 Integrated Overview) ──
    fig_all = plt.figure(figsize=(15.5, 9.2), dpi=160, facecolor=bg)
    fig_all.suptitle(
        "SIDIK - Master Research Benchmark Bundle (RQ1 - RQ4: N=100 Secret, N=200 SCA v2, & 25 Repo GitHub Nyata)",
        color=fg, fontsize=13, fontweight="bold", y=0.975
    )
    gs = gridspec.GridSpec(2, 2, figure=fig_all, hspace=0.36, wspace=0.24, left=0.06, right=0.97, top=0.91, bottom=0.07)

    # Panel 1 (RQ1: 25 Real Repos & Controlled N=100)
    ax_p1 = fig_all.add_subplot(gs[0, 0])
    style_ax(ax_p1, "RQ1: Deteksi Secret (Uji N=100 & 25 Repo GitHub Nyata)", "Jumlah FP / Waktu (s)")
    p1_labels = ["SIDIK\n(N=100)", "Regex\n(N=100)", "SIDIK\n(25 Repo)", "Gitleaks\n(25 Repo)", "Bandit\n(25 Repo)"]
    p1_fp = [0, 10, 14, 0, 98]
    p1_time = [0.03, 0.02, 3.19, 10.41, 25.26]
    xp1 = np.arange(len(p1_labels))
    bp1a = ax_p1.bar(xp1 - w/2, p1_fp, w, color=c_red, edgecolor=grid_c, label="Alarm Palsu (FP)")
    bp1b = ax_p1.bar(xp1 + w/2, p1_time, w, color=c_blue, edgecolor=grid_c, label="Waktu Scan (detik)")
    ax_p1.set_ylim(0, 118)
    ax_p1.set_xticks(xp1)
    ax_p1.set_xticklabels(p1_labels, color=fg, fontsize=8.5)
    label_bars(ax_p1, bp1a, fmt="{:.0f}", suffix=" FP", fontsize=8)
    label_bars(ax_p1, bp1b, fmt="{:.2f}", suffix="s", fontsize=8)
    ax_p1.legend(loc="upper left", fontsize=8, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    # Panel 2 (RQ2: SCA v2 N=200 vs Trivy & pip-audit)
    ax_p2 = fig_all.add_subplot(gs[0, 1])
    style_ax(ax_p2, "RQ2: Analisis Dependensi SCA v2 (200 Paket di 39 Manifes)", "Recall (%) / Waktu (s)")
    bp2a = ax_p2.bar(x_sca - w/2, rec_vals, w, color=c_green, edgecolor=grid_c, label="Recall Kerentanan (%)")
    bp2b = ax_p2.bar(x_sca + w/2, sca_times, w, color=c_orange, edgecolor=grid_c, label="Waktu Scan (detik)")
    ax_p2.set_ylim(0, 155)
    ax_p2.set_xticks(x_sca)
    ax_p2.set_xticklabels(sca_tools, color=fg, fontsize=8.5)
    label_bars(ax_p2, bp2a, fmt="{:.0f}", suffix="%", fontsize=8)
    label_bars(ax_p2, bp2b, fmt="{:.2f}", suffix="s", fontsize=8)
    ax_p2.legend(loc="upper left", fontsize=8, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    # Panel 3 (RQ3: Ablation Study A-D)
    ax_p3 = fig_all.add_subplot(gs[1, 0])
    style_ax(ax_p3, "RQ3: Studi Ablasi Komponen (Konfigurasi A - D)", "Skor (0.0 - 1.0)")
    ax_p3.plot(xc, precs, marker="o", linewidth=2.2, color=c_green, label="Precision")
    ax_p3.plot(xc, f1s, marker="^", linewidth=2.2, color=c_blue, label="F1-Score")
    ax_p3.plot(xc, mccs, marker="D", linewidth=2.2, color=c_purple, label="MCC")
    for idx_pt in range(len(xc)):
        fp_cnt = abl_data[cfg_keys[idx_pt]]["metrics"]["confusion_matrix"]["FP"]
        ax_p3.annotate(f"F1 {f1s[idx_pt]:.2f} ({fp_cnt} FP)", (xc[idx_pt], f1s[idx_pt]),
                       textcoords="offset points", xytext=(0, 8), ha="center",
                       color=fg, fontsize=8, fontweight="bold")
    ax_p3.set_xticks(xc)
    ax_p3.set_xticklabels(cfg_labels, color=fg, fontsize=8.5)
    ax_p3.set_ylim(0.60, 1.12)
    ax_p3.legend(loc="lower right", fontsize=8, facecolor=bg, labelcolor=fg, edgecolor=grid_c)

    # Panel 4 (RQ4: Honest Memory & Latency Profile)
    ax_p4 = fig_all.add_subplot(gs[1, 1])
    style_ax(ax_p4, "RQ4: Profil Konsumsi Memori RAM & Kecepatan Eksekusi", "MB / Detik (Skala Log)")
    p4_labels = ["RAM Scan\n(Per Repo)", "RAM Scan\n(25 Repo)", "Muat DB OSV\n(1x Awal)", "Waktu SIDIK\n(25 Repo)", "Waktu SIDIK\n(SCA 39 File)"]
    p4_vals = [0.39, 1.58, 116.47, 3.19, 0.33]
    p4_cols = [c_green, c_cyan, c_orange, c_blue, c_purple]
    bp4 = ax_p4.bar(p4_labels, p4_vals, color=p4_cols, edgecolor=grid_c, width=0.48)
    ax_p4.set_yscale("log")
    ax_p4.set_ylim(0.08, 350)
    p4_units = ["MB", "MB", "MB", "s", "s"]
    for bar, val, unit in zip(bp4, p4_vals, p4_units):
        ax_p4.text(bar.get_x() + bar.get_width()/2, val * 1.18, f"{val:.2f} {unit}",
                   ha="center", va="bottom", color=fg, fontsize=8, fontweight="bold")

    p_bundle = os.path.join(FIGURES_DIR, "fig_benchmark_bundle.png")
    fig_all.savefig(p_bundle, dpi=160, facecolor=bg)
    plt.close(fig_all)
    print(f"Saved GUI dark benchmark figures: {p_rq1}, {p_rq2}, {p_rq3}, {p_rq4}, {p_bundle}")


def main():
    exp_file = os.path.join(RESULTS_DIR, "experiment_results.json")
    abl_file = os.path.join(RESULTS_DIR, "ablation_results.json")
    sec_file = os.path.join(RESULTS_DIR, "secret_comparative_benchmark.json")
    sca_file = os.path.join(RESULTS_DIR, "sca_comparative_benchmark.json")

    exp_data = json.load(open(exp_file, "r", encoding="utf-8")) if os.path.exists(exp_file) else None
    abl_data = json.load(open(abl_file, "r", encoding="utf-8")) if os.path.exists(abl_file) else None
    sec_comp = json.load(open(sec_file, "r", encoding="utf-8")) if os.path.exists(sec_file) else None
    sca_comp = json.load(open(sca_file, "r", encoding="utf-8")) if os.path.exists(sca_file) else None

    if exp_data:
        plot_detection_metrics_comparison(exp_data)
        plot_confusion_matrices(exp_data, sca_comp)
        plot_performance_overhead(exp_data)

    if abl_data:
        plot_ablation_study(abl_data)

    plot_comparative_industry_tools()

    if exp_data and abl_data:
        generate_gui_dark_benchmark_figures(exp_data, abl_data, sec_comp, sca_comp)

    print("All scientific visualization figures generated successfully in figures/")


if __name__ == "__main__":
    main()
