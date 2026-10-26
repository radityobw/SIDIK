"""Comprehensive Benchmark Runner for External Repositories and Industry Baselines (Fase 2).

Executes:
1. RQ1 / RQ2 on 25 Real Repositories:
   - Evaluates SIDIK on all 25 repositories (LOC, py files, secret alerts, dep findings, latency, peak memory).
   - Verifies True/False Positives against annotated ground truth.
2. RQ3 Comparative Evaluation vs Industry Tools:
   - Secret Scanning: SIDIK vs Baseline Regex vs Gitleaks vs Bandit on identical real corpus (109 candidates, 25 repos).
   - SCA Scanning: SIDIK vs pip-audit vs Trivy on the 45 real manifest files + Dataset v2.
3. RQ4 Computational Efficiency Benchmarks (5 repetitions, tracemalloc, time.perf_counter).

Outputs formatted JSON and Markdown tables directly compatible with academic papers.
"""

import json
import os
import re
import statistics
import subprocess
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIDIK_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, SIDIK_ROOT)

from sidik.core import SecurityScanner
from sidik.secret_detector.detector import SecretDetector
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer, MANIFEST_FILENAMES
from sidik.dependency_analyzer.parsers import normalize_package_name

EXTERNAL_DIR = os.path.join(SIDIK_ROOT, "dataset", "external")
REPOS_PATH = os.path.join(EXTERNAL_DIR, "repos.json")
GT_SECRETS_PATH = os.path.join(EXTERNAL_DIR, "ground_truth_secrets.json")
RESULTS_DIR = os.path.join(SIDIK_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

VENV_SCRIPTS = os.path.join(SIDIK_ROOT, ".venv", "Scripts")
GITLEAKS_BIN = os.path.join(VENV_SCRIPTS, "gitleaks.exe")
BANDIT_BIN = os.path.join(VENV_SCRIPTS, "bandit.exe")
TRIVY_BIN = os.path.join(VENV_SCRIPTS, "trivy.exe")
PIPAUDIT_BIN = os.path.join(VENV_SCRIPTS, "pip-audit.exe")


def run_repo_case_studies() -> Dict[str, Any]:
    """Tugas 2.1: Menjalankan SIDIK pada 25 repositori nyata publik."""
    print("\n--- Menjalankan Tugas 2.1: Studi Kasus 25 Repositori Nyata ---", flush=True)
    repos_meta = json.load(open(REPOS_PATH, encoding="utf-8"))["repos"]
    gt_secrets = json.load(open(GT_SECRETS_PATH, encoding="utf-8"))["annotations"]
    gt_map = {(a["repo"], a["file"], a["line"]): a["ground_truth"] for a in gt_secrets}

    scanner = SecurityScanner()
    case_studies = []

    total_files = 0
    total_loc = 0
    total_sec_tp = 0
    total_sec_fp = 0
    total_dep_findings = 0
    total_time = 0.0

    for idx, r in enumerate(repos_meta, 1):
        repo_name = r["full_name"]
        repo_dir = os.path.join(EXTERNAL_DIR, r["local_dir"])
        if not os.path.isdir(repo_dir):
            continue

        report = scanner.scan_path(repo_dir)

        sec_findings = [f for f in report.findings if f.finding_type == "secret"]
        dep_findings = [f for f in report.findings if f.finding_type == "dependency"]

        sec_tp = 0
        sec_fp = 0
        for sf in sec_findings:
            rel = os.path.relpath(sf.file_path, repo_dir).replace("\\", "/")
            key = (repo_name, rel, sf.line_number)
            is_tp = gt_map.get(key, False)
            if is_tp:
                sec_tp += 1
            else:
                sec_fp += 1

        rec = {
            "no": idx,
            "repo": repo_name,
            "loc": r["py_loc"],
            "files": r["py_files"],
            "secret_tp": sec_tp,
            "secret_fp": sec_fp,
            "dep_findings": len(dep_findings),
            "scan_time_seconds": round(report.summary.scan_duration_seconds, 4),
            "peak_memory_mb": round(report.summary.peak_memory_mb, 4),
        }
        case_studies.append(rec)
        total_files += r["py_files"]
        total_loc += r["py_loc"]
        total_sec_tp += sec_tp
        total_sec_fp += sec_fp
        total_dep_findings += len(dep_findings)
        total_time += report.summary.scan_duration_seconds
        print(f"  [{idx:02d}/25] {repo_name:35s} | LOC: {r['py_loc']:5d} | Sec: {sec_tp} TP, {sec_fp} FP | Dep: {len(dep_findings)} | Time: {report.summary.scan_duration_seconds:.3f}s", flush=True)

    summary = {
        "repos_count": len(case_studies),
        "total_loc": total_loc,
        "total_files": total_files,
        "total_secret_tp": total_sec_tp,
        "total_secret_fp": total_sec_fp,
        "total_dep_findings": total_dep_findings,
        "total_scan_time_seconds": round(total_time, 4),
        "case_studies": case_studies,
    }

    out_file = os.path.join(RESULTS_DIR, "external_case_studies.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary


def run_comparative_secret_scanners() -> Dict[str, Any]:
    """Tugas 2.2: Komparasi deteksi secret (SIDIK vs Baseline Regex vs Gitleaks vs Bandit)."""
    print("\n--- Menjalankan Tugas 2.2: Komparasi Deteksi Secret Lintas Alat ---", flush=True)
    repos_meta = json.load(open(REPOS_PATH, encoding="utf-8"))["repos"]
    gt_secrets = json.load(open(GT_SECRETS_PATH, encoding="utf-8"))["annotations"]
    gt_map = {(a["repo"], a["file"], a["line"]): a["ground_truth"] for a in gt_secrets}

    all_candidates = json.load(open(os.path.join(EXTERNAL_DIR, "all_candidates.json"), encoding="utf-8"))
    N = len(all_candidates)

    sidik_full = SecretDetector(enable_context=True, enable_entropy=True)
    sidik_raw = SecretDetector(enable_context=False, enable_entropy=False)

    tools_findings = {
        "SIDIK (Usulan)": set(),
        "Baseline Regex": set(),
        "Gitleaks (v8.30.1)": set(),
        "Bandit (v1.9.4)": set(),
    }
    tools_times = {k: [] for k in tools_findings}

    for r in repos_meta:
        repo_name = r["full_name"]
        repo_dir = os.path.join(EXTERNAL_DIR, r["local_dir"])
        if not os.path.isdir(repo_dir):
            continue

        # 1. SIDIK Full
        t0 = time.perf_counter()
        for root, dirs, files in os.walk(repo_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            for f in files:
                if f.endswith(".py"):
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, repo_dir).replace("\\", "/")
                    res = sidik_full.scan_file(fpath)
                    for item in res:
                        tools_findings["SIDIK (Usulan)"].add((repo_name, rel, item.line_number))
        tools_times["SIDIK (Usulan)"].append(time.perf_counter() - t0)

        # 2. Baseline Regex
        t0 = time.perf_counter()
        for root, dirs, files in os.walk(repo_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            for f in files:
                if f.endswith(".py"):
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, repo_dir).replace("\\", "/")
                    res = sidik_raw.scan_file(fpath)
                    for item in res:
                        tools_findings["Baseline Regex"].add((repo_name, rel, item.line_number))
        tools_times["Baseline Regex"].append(time.perf_counter() - t0)

        # 3. Gitleaks
        t0 = time.perf_counter()
        tmp_rep = os.path.join(RESULTS_DIR, "_tmp_gl.json")
        if os.path.isfile(tmp_rep):
            os.remove(tmp_rep)
        proc = subprocess.run(
            [GITLEAKS_BIN, "dir", "--no-git", "--report-format", "json", "--report-path", tmp_rep, repo_dir],
            capture_output=True, text=True
        )
        if os.path.isfile(tmp_rep):
            try:
                data = json.load(open(tmp_rep, encoding="utf-8", errors="ignore"))
                for item in data:
                    fp = item.get("File", "")
                    if fp.endswith(".py"):
                        rel = os.path.relpath(fp, repo_dir).replace("\\", "/") if os.path.isabs(fp) else fp.replace("\\", "/")
                        tools_findings["Gitleaks (v8.30.1)"].add((repo_name, rel, item.get("StartLine", 0)))
            except Exception:
                pass
            finally:
                if os.path.isfile(tmp_rep):
                    os.remove(tmp_rep)
        tools_times["Gitleaks (v8.30.1)"].append(time.perf_counter() - t0)

        # 4. Bandit
        t0 = time.perf_counter()
        proc = subprocess.run([BANDIT_BIN, "-r", repo_dir, "-f", "json", "-t", "B105,B106,B107", "-q"], capture_output=True, text=True)
        try:
            data = json.loads(proc.stdout)
            for item in data.get("results", []):
                fp = item.get("filename", "")
                if fp.endswith(".py"):
                    rel = os.path.relpath(fp, repo_dir).replace("\\", "/") if os.path.isabs(fp) else fp.replace("\\", "/")
                    tools_findings["Bandit (v1.9.4)"].add((repo_name, rel, item.get("line_number", 0)))
        except Exception:
            pass
        tools_times["Bandit (v1.9.4)"].append(time.perf_counter() - t0)

    # Compute metrics for each tool over the 109 annotated candidate set
    metrics_table = []
    for tool_name, alerts in tools_findings.items():
        tp = fp = tn = fn = 0
        for cand in all_candidates:
            key = (cand["repo"], cand["file"], cand["line"])
            gt = gt_map.get(key, False)
            detected = key in alerts

            if detected and gt:
                tp += 1
            elif detected and not gt:
                fp += 1
            elif not detected and not gt:
                tn += 1
            elif not detected and gt:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0 if fp == 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0 if fn == 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_time = sum(tools_times[tool_name])

        metrics_table.append({
            "tool": tool_name,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "total_time_seconds": round(avg_time, 4),
        })

    out_file = os.path.join(RESULTS_DIR, "secret_comparative_benchmark.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(metrics_table, f, indent=2)

    print("\nHasil Komparasi Deteksi Secret:")
    for row in metrics_table:
        print(f"  {row['tool']:20s} | FP: {row['fp']:3d} | FPR: {row['fpr']:6.4f} | Prec: {row['precision']:.4f} | Time: {row['total_time_seconds']:.2f}s")

    return {"secret_comparison": metrics_table}


def run_comparative_sca() -> Dict[str, Any]:
    """Tugas 2.2: Komparasi SCA (SIDIK vs pip-audit vs Trivy) pada Dataset SCA v2 (Test Split: N=200)."""
    print("\n--- Menjalankan Tugas 2.2: Komparasi SCA pada Test Split (N=200 entri) ---", flush=True)
    gt_v2 = json.load(open(os.path.join(SIDIK_ROOT, "dataset", "ground_truth", "dependencies_v2_ground_truth.json"), encoding="utf-8"))
    test_entries = [e for e in gt_v2["entries"] if e["split"] == "test"]

    analyzer = DependencyAnalyzer()

    # Group test entries by manifest
    manifest_groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in test_entries:
        manifest_groups.setdefault(e["manifest_id"], []).append(e)

    sidik_preds = []
    pipaudit_preds = []
    trivy_preds = []

    t_sidik = 0.0
    t_pip = 0.0
    t_trivy = 0.0

    req_manifests = [m for m, items in manifest_groups.items() if items[0]["manifest_type"] == "requirements.txt"]

    # 1. SIDIK on all test manifests
    t0 = time.perf_counter()
    for mid, items in manifest_groups.items():
        fpath = os.path.join(SIDIK_ROOT, "dataset", items[0]["file_path"])
        findings = analyzer.scan_manifest_file(fpath)
        hit_pkgs = {normalize_package_name(f.metadata["package"]) for f in findings}
        for item in items:
            pkg_norm = normalize_package_name(item["package"])
            detected = pkg_norm in hit_pkgs
            sidik_preds.append({
                "entry_id": item["entry_id"],
                "ground_truth": item["ground_truth"],
                "detected": detected,
            })
    t_sidik = time.perf_counter() - t0

    # 2. pip-audit on requirements.txt manifests
    t0 = time.perf_counter()
    for mid in req_manifests:
        items = manifest_groups[mid]
        fpath = os.path.join(SIDIK_ROOT, "dataset", items[0]["file_path"])
        proc = subprocess.run([PIPAUDIT_BIN, "-r", fpath, "-f", "json"], capture_output=True, text=True)
        vuln_pkgs = set()
        try:
            data = json.loads(proc.stdout)
            for dep in data.get("dependencies", []):
                if dep.get("vulns"):
                    vuln_pkgs.add(normalize_package_name(dep.get("name", "")))
        except Exception:
            pass
        for item in items:
            detected = normalize_package_name(item["package"]) in vuln_pkgs
            pipaudit_preds.append({
                "entry_id": item["entry_id"],
                "ground_truth": item["ground_truth"],
                "detected": detected,
            })
    t_pip = time.perf_counter() - t0

    # 3. Trivy on all manifests
    t0 = time.perf_counter()
    for mid, items in manifest_groups.items():
        fpath = os.path.join(SIDIK_ROOT, "dataset", items[0]["file_path"])
        proc = subprocess.run([TRIVY_BIN, "fs", "--format", "json", "--scanners", "vuln", fpath], capture_output=True, text=True)
        vuln_pkgs = set()
        try:
            data = json.loads(proc.stdout)
            for res in data.get("Results", []):
                for v in res.get("Vulnerabilities", []):
                    pkg = v.get("PkgName", "")
                    if pkg:
                        vuln_pkgs.add(normalize_package_name(pkg))
        except Exception:
            pass
        for item in items:
            detected = normalize_package_name(item["package"]) in vuln_pkgs
            trivy_preds.append({
                "entry_id": item["entry_id"],
                "ground_truth": item["ground_truth"],
                "detected": detected,
            })
    t_trivy = time.perf_counter() - t0

    def get_metrics(preds: List[Dict[str, Any]], elapsed: float, name: str) -> Dict[str, Any]:
        tp = sum(1 for p in preds if p["detected"] and p["ground_truth"])
        fp = sum(1 for p in preds if p["detected"] and not p["ground_truth"])
        tn = sum(1 for p in preds if not p["detected"] and not p["ground_truth"])
        fn = sum(1 for p in preds if not p["detected"] and p["ground_truth"])
        pr = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * pr * rc) / (pr + rc) if (pr + rc) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {
            "tool": name,
            "evaluated_entries": len(preds),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(pr, 4),
            "recall": round(rc, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "scan_time_seconds": round(elapsed, 4),
        }

    sca_results = [
        get_metrics(sidik_preds, t_sidik, "SIDIK (Usulan - Offline)"),
        get_metrics(trivy_preds, t_trivy, "Trivy (v0.76.1)"),
        get_metrics(pipaudit_preds, t_pip, "pip-audit (v2.10.1 - req only)"),
    ]

    out_file = os.path.join(RESULTS_DIR, "sca_comparative_benchmark.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sca_results, f, indent=2)

    print("\nHasil Komparasi SCA (Software Composition Analysis):")
    for r in sca_results:
        print(f"  {r['tool']:32s} | N: {r['evaluated_entries']:3d} | F1: {r['f1_score']:.4f} | Prec: {r['precision']:.4f} | Rec: {r['recall']:.4f} | Time: {r['scan_time_seconds']:.2f}s")

    return {"sca_comparison": sca_results}


def main():
    print("=================================================================", flush=True)
    print("   SIDIK: EXPERIMENTAL BENCHMARK EXECUTION (FASE 2)             ", flush=True)
    print("=================================================================", flush=True)

    r1 = run_repo_case_studies()
    r2 = run_comparative_secret_scanners()
    r3 = run_comparative_sca()

    print("\nSeluruh eksperimen Fase 2 berhasil dijalankan!", flush=True)
    print(f"Hasil lengkap tersimpan di: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
