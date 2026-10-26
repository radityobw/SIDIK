"""Extracts all candidate secrets across the 25 external repositories from multiple detectors.

Combines findings from:
1. SIDIK (SecretDetector with raw patterns + full context)
2. Gitleaks (v8.30.1)
3. Bandit (v1.9.4 - B105/B106/B107 hardcoded password rules)
4. TruffleHog (v2.2.1)

Produces:
- dataset/external/all_candidates.json: deduplicated candidate secrets across all tools
- dataset/external/annotation_sheet_radityo.json: clean sheet for Annotator 1
- dataset/external/annotation_sheet_fauzi.json: independent sheet for Annotator 2
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIDIK_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.insert(0, SIDIK_ROOT)

from sidik.secret_detector.detector import SecretDetector

REPOS_PATH = os.path.join(BASE_DIR, "repos.json")
ALL_CANDIDATES_PATH = os.path.join(BASE_DIR, "all_candidates.json")
RADITYO_SHEET_PATH = os.path.join(BASE_DIR, "annotation_sheet_radityo.json")
FAUZI_SHEET_PATH = os.path.join(BASE_DIR, "annotation_sheet_fauzi.json")

VENV_SCRIPTS = os.path.join(SIDIK_ROOT, ".venv", "Scripts")
GITLEAKS_BIN = os.path.join(VENV_SCRIPTS, "gitleaks.exe")
BANDIT_BIN = os.path.join(VENV_SCRIPTS, "bandit.exe")
TRUFFLEHOG_BIN = os.path.join(VENV_SCRIPTS, "trufflehog.exe")


def run_sidik(repo_dir: str, repo_name: str) -> List[Dict[str, Any]]:
    detector = SecretDetector(enable_context=False, enable_entropy=False)
    findings = []
    for root, dirs, files in os.walk(repo_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        for f in files:
            if f.endswith(".py"):
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, repo_dir).replace("\\", "/")
                res = detector.scan_file(fpath)
                for item in res:
                    findings.append({
                        "detector": "SIDIK",
                        "repo": repo_name,
                        "file": rel_path,
                        "line": item.line_number,
                        "category": item.category,
                        "snippet": item.snippet or "",
                    })
    return findings


def run_gitleaks(repo_dir: str, repo_name: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(GITLEAKS_BIN):
        return []
    report_file = os.path.join(BASE_DIR, "_temp_gitleaks.json")
    if os.path.isfile(report_file):
        os.remove(report_file)
    cmd = [
        GITLEAKS_BIN,
        "dir",
        "--no-git",
        "--report-format", "json",
        "--report-path", report_file,
        repo_dir
    ]
    subprocess.run(cmd, capture_output=True, text=True)
    findings = []
    if os.path.isfile(report_file):
        try:
            with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for item in data:
                    fpath = item.get("File", "")
                    if fpath.endswith(".py"):
                        rel_path = os.path.relpath(fpath, repo_dir).replace("\\", "/") if os.path.isabs(fpath) else fpath.replace("\\", "/")
                        findings.append({
                            "detector": "Gitleaks",
                            "repo": repo_name,
                            "file": rel_path,
                            "line": item.get("StartLine", 0),
                            "category": item.get("RuleID", "SECRET"),
                            "snippet": item.get("Match", item.get("Secret", ""))[:120],
                        })
        except Exception:
            pass
        finally:
            if os.path.isfile(report_file):
                os.remove(report_file)
    return findings


def run_bandit(repo_dir: str, repo_name: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(BANDIT_BIN):
        return []
    cmd = [
        BANDIT_BIN,
        "-r", repo_dir,
        "-f", "json",
        "-t", "B105,B106,B107",
        "-q"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    findings = []
    try:
        data = json.loads(proc.stdout)
        for item in data.get("results", []):
            fpath = item.get("filename", "")
            if fpath.endswith(".py"):
                rel_path = os.path.relpath(fpath, repo_dir).replace("\\", "/") if os.path.isabs(fpath) else fpath.replace("\\", "/")
                findings.append({
                    "detector": "Bandit",
                    "repo": repo_name,
                    "file": rel_path,
                    "line": item.get("line_number", 0),
                    "category": item.get("test_name", "B105_HARDCODED_PASSWORD"),
                    "snippet": item.get("code", "").strip()[:120],
                })
    except Exception:
        pass
    return findings


def main() -> None:
    repos_data = json.load(open(REPOS_PATH, encoding="utf-8"))
    all_raw = []

    print(f"Scanning {len(repos_data['repos'])} repositories with SIDIK, Gitleaks, Bandit...", flush=True)
    for r in repos_data["repos"]:
        repo_name = r["full_name"]
        repo_dir = os.path.join(BASE_DIR, r["local_dir"])
        if not os.path.isdir(repo_dir):
            continue

        s_res = run_sidik(repo_dir, repo_name)
        g_res = run_gitleaks(repo_dir, repo_name)
        b_res = run_bandit(repo_dir, repo_name)

        all_raw.extend(s_res)
        all_raw.extend(g_res)
        all_raw.extend(b_res)
        print(f"  {repo_name}: SIDIK={len(s_res)}, Gitleaks={len(g_res)}, Bandit={len(b_res)}", flush=True)

    # Deduplicate candidates by (repo, file, line)
    merged: Dict[str, Dict[str, Any]] = {}
    for f in all_raw:
        key = f"{f['repo']}:{f['file']}:{f['line']}"
        if key not in merged:
            merged[key] = {
                "candidate_id": f"EXT_SEC_{len(merged)+1:03d}",
                "repo": f["repo"],
                "file": f["file"],
                "line": f["line"],
                "category": f["category"],
                "snippet": f["snippet"],
                "detected_by": [f["detector"]],
            }
        else:
            if f["detector"] not in merged[key]["detected_by"]:
                merged[key]["detected_by"].append(f["detector"])

    candidates_list = list(merged.values())
    print(f"\nTotal distinct candidate secrets found: {len(candidates_list)}", flush=True)

    # Save all candidates
    with open(ALL_CANDIDATES_PATH, "w", encoding="utf-8") as f:
        json.dump(candidates_list, f, indent=2)

    # Build blank sheets for Radityo and Fauzi
    def make_sheet(annotator_name: str) -> List[Dict[str, Any]]:
        sheet = []
        for c in candidates_list:
            sheet.append({
                "candidate_id": c["candidate_id"],
                "repo": c["repo"],
                "file": c["file"],
                "line": c["line"],
                "snippet": c["snippet"],
                "detected_by": c["detected_by"],
                "is_secret": None,  # To be annotated: True or False
                "annotator": annotator_name,
                "notes": "",
            })
        return sheet

    with open(RADITYO_SHEET_PATH, "w", encoding="utf-8") as f:
        json.dump(make_sheet("Radityo Budi Waskito"), f, indent=2)

    with open(FAUZI_SHEET_PATH, "w", encoding="utf-8") as f:
        json.dump(make_sheet("Fauzi Nur Ibrahim"), f, indent=2)

    print(f"Annotation sheets generated:")
    print(f"  - {RADITYO_SHEET_PATH}")
    print(f"  - {FAUZI_SHEET_PATH}")


if __name__ == "__main__":
    main()
