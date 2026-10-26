"""Selects and pins external Python repositories for real-world evaluation (plan A1.2).

Selection protocol (deterministic given SEED and GitHub state at run time):
  1. Query the GitHub search API per creation year (diversity across project age).
  2. Keep non-fork, non-archived repositories with a permissive SPDX license,
     100-5000 stars, and a push within the last 24 months.
  3. Shuffle with SEED, shallow-clone sequentially, count non-blank Python lines (LOC).
  4. Accept repositories with 1,000 <= LOC <= 20,000 until TARGET_REPOS are accepted.
  5. Record URL, license, stars, default branch, and the pinned commit hash.

Repository contents are NOT committed (dataset/external/_repos is git-ignored); only metadata is kept.
"""

import json
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List

SEED = 42
TARGET_REPOS = 25
MIN_LOC, MAX_LOC = 1000, 20000
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}
YEARS = range(2018, 2026)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPOS_DIR = os.path.join(BASE_DIR, "_repos")
OUT_PATH = os.path.join(BASE_DIR, "repos.json")


def gh_get(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "sidik-research", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read())


def search_candidates() -> List[Dict[str, Any]]:
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 730 * 86400))
    found: Dict[str, Dict[str, Any]] = {}
    for year in YEARS:
        query = (f"language:python stars:100..5000 size:300..6000 fork:false archived:false "
                 f"created:{year}-01-01..{year}-12-31 pushed:>{cutoff}")
        url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode(
            {"q": query, "sort": "updated", "order": "desc", "per_page": 40})
        try:
            items = gh_get(url).get("items", [])
        except OSError as exc:
            print(f"search failed for {year}: {exc}", file=sys.stderr)
            continue
        for item in items:
            spdx = (item.get("license") or {}).get("spdx_id")
            if spdx in PERMISSIVE:
                found[item["full_name"]] = {
                    "full_name": item["full_name"], "html_url": item["html_url"], "license": spdx,
                    "stars": item["stargazers_count"], "created_at": item["created_at"],
                    "pushed_at": item["pushed_at"], "default_branch": item["default_branch"],
                    "clone_url": item["clone_url"],
                }
        time.sleep(2)  # stay far below the unauthenticated search rate limit
    return sorted(found.values(), key=lambda r: r["full_name"])


def count_loc(root: str) -> Dict[str, int]:
    files = loc = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            if name.endswith(".py"):
                files += 1
                try:
                    with open(os.path.join(dirpath, name), "r", encoding="utf-8", errors="ignore") as f:
                        loc += sum(1 for line in f if line.strip())
                except OSError:
                    continue
    return {"py_files": files, "py_loc": loc}


def _rmtree(path: str) -> None:
    def onerror(func: Any, p: str, _exc: Any) -> None:
        os.chmod(p, 0o700)
        func(p)
    shutil.rmtree(path, onerror=onerror)


def main() -> None:
    os.makedirs(REPOS_DIR, exist_ok=True)
    candidates = search_candidates()
    print(f"{len(candidates)} permissive candidates", flush=True)
    random.Random(SEED).shuffle(candidates)

    accepted: List[Dict[str, Any]] = []
    for cand in candidates:
        if len(accepted) >= TARGET_REPOS:
            break
        dest = os.path.join(REPOS_DIR, cand["full_name"].replace("/", "__"))
        if os.path.isdir(dest):
            _rmtree(dest)
        proc = subprocess.run(
            ["git", "-c", "core.longpaths=true", "clone", "--depth", "1", "--quiet", cand["clone_url"], dest],
            capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(f"  skip {cand['full_name']}: clone failed", flush=True)
            continue
        stats = count_loc(dest)
        if not (MIN_LOC <= stats["py_loc"] <= MAX_LOC):
            print(f"  skip {cand['full_name']}: {stats['py_loc']} LOC", flush=True)
            _rmtree(dest)
            continue
        commit = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        rec = dict(cand)
        rec.update(stats)
        rec["commit"] = commit
        rec["local_dir"] = os.path.relpath(dest, BASE_DIR).replace("\\", "/")
        accepted.append(rec)
        print(f"  ACCEPT {cand['full_name']}: {stats['py_loc']} LOC @ {commit[:10]}", flush=True)

    accepted.sort(key=lambda r: r["full_name"])
    payload = {
        "metadata": {
            "selected_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seed": SEED, "target_repos": TARGET_REPOS, "loc_range": [MIN_LOC, MAX_LOC],
            "candidate_count": len(candidates), "accepted": len(accepted),
            "total_py_loc": sum(r["py_loc"] for r in accepted),
            "total_py_files": sum(r["py_files"] for r in accepted),
            "licenses": sorted(PERMISSIVE),
        },
        "repos": accepted,
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
    print(json.dumps(payload["metadata"], indent=2))


if __name__ == "__main__":
    main()
