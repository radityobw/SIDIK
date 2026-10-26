"""Builds the SCA ground-truth dataset v2 from real PyPI releases.

Design (see implementation plan, A1.3):
  * Packages are sampled from the public top-PyPI-packages list, independent of SIDIK's database.
  * Versions are sampled from each package's real release history (no pre-releases or yanked files).
  * The label of every (package, version) entry comes from an external oracle: the
    ``vulnerabilities`` field of PyPI's per-version JSON API (the same source used by pip-audit).
  * One manifest holds several dependencies and cycles through the five supported formats.
  * Packages never cross splits (dev / val / test), preventing leakage.

Usage:
    python dataset/build_dependency_dataset_v2.py --fetch    # network; resumable via cache
    python dataset/build_dependency_dataset_v2.py --build    # offline from cache
    python dataset/build_dependency_dataset_v2.py            # both
"""

import argparse
import json
import os
import random
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

SEED = 42
N_PACKAGES = 8000
VERSIONS_PER_PACKAGE = 2
WORKERS = 12
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
SPLIT_SIZES = {"test": 100, "val": 40, "dev": 40}  # per class (positive and negative)
FORMATS = ["requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "setup.py"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "dependencies_v2")
CACHE_PATH = os.path.join(OUT_DIR, "_cache.json")
GT_PATH = os.path.join(BASE_DIR, "ground_truth", "dependencies_v2_ground_truth.json")

_lock = threading.Lock()


def http_json(url: str, retries: int = 4) -> Optional[Dict[str, Any]]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sidik-research-dataset/1.0"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            time.sleep(2 ** attempt)
        except (OSError, TimeoutError, ValueError):
            time.sleep(2 ** attempt)
    return None


def load_cache() -> Dict[str, Any]:
    if os.path.isfile(CACHE_PATH):
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"top_last_update": None, "packages": {}, "versions": {}}


def save_cache(cache: Dict[str, Any]) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, separators=(",", ":"))
    for attempt in range(5):
        try:
            os.replace(tmp, CACHE_PATH)
            return
        except PermissionError:
            time.sleep(0.5 * (attempt + 1))
    with open(CACHE_PATH, "w", encoding="utf-8") as f:  # transient lock fallback
        json.dump(cache, f, separators=(",", ":"))


def release_versions(pkg_json: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for ver, files in (pkg_json.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease or v.is_postrelease:
            continue
        out.append(ver)
    return sorted(out, key=Version)


def fetch(cache: Dict[str, Any]) -> None:
    top = http_json(TOP_URL)
    if not top:
        sys.exit("Cannot download top-pypi-packages list")
    cache["top_last_update"] = top.get("last_update")
    names = [row["project"] for row in top["rows"]]
    rng = random.Random(SEED)
    rng.shuffle(names)
    names = names[:N_PACKAGES]

    def get_package(name: str) -> None:
        if name in cache["packages"]:
            return
        data = http_json(f"https://pypi.org/pypi/{name}/json")
        versions = release_versions(data) if data else []
        with _lock:
            cache["packages"][name] = versions

    print(f"[1/2] Release lists for {len(names)} packages", flush=True)
    with ThreadPoolExecutor(WORKERS) as pool:
        for i, _ in enumerate(pool.map(get_package, names), 1):
            if i % 200 == 0:
                print(f"  {i}/{len(names)}", flush=True)
                with _lock:
                    save_cache(cache)
    save_cache(cache)

    picks: List[Tuple[str, str]] = []
    for name in names:
        versions = cache["packages"].get(name) or []
        if not versions:
            continue
        r = random.Random(f"{SEED}-{name}")
        for ver in r.sample(versions, min(VERSIONS_PER_PACKAGE, len(versions))):
            picks.append((name, ver))

    def get_version(item: Tuple[str, str]) -> None:
        name, ver = item
        key = f"{name}=={ver}"
        if key in cache["versions"]:
            return
        data = http_json(f"https://pypi.org/pypi/{name}/{ver}/json")
        if data is None:
            return
        vulns = [
            {"id": v.get("id"), "aliases": v.get("aliases", []), "withdrawn": bool(v.get("withdrawn"))}
            for v in data.get("vulnerabilities", []) or []
        ]
        with _lock:
            cache["versions"][key] = vulns

    print(f"[2/2] Oracle labels for {len(picks)} (package, version) pairs", flush=True)
    with ThreadPoolExecutor(WORKERS) as pool:
        for i, _ in enumerate(pool.map(get_version, picks), 1):
            if i % 300 == 0:
                print(f"  {i}/{len(picks)}", flush=True)
                with _lock:
                    save_cache(cache)
    cache["oracle_fetched_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_cache(cache)


def manifest_content(fmt: str, manifest_id: str, deps: List[Tuple[str, str]]) -> str:
    if fmt == "requirements.txt":
        return "# Generated for SIDIK benchmark v2\n" + "".join(f"{p}=={v}\n" for p, v in deps)
    if fmt == "pyproject.toml":
        body = ",\n".join(f'    "{p}=={v}"' for p, v in deps)
        return f'[project]\nname = "app-{manifest_id}"\nversion = "0.1.0"\ndependencies = [\n{body}\n]\n'
    if fmt == "Pipfile":
        lines = "".join(f'{p} = "=={v}"\n' for p, v in deps)
        return f'[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n\n[packages]\n{lines}'
    if fmt == "poetry.lock":
        return "".join(
            f'[[package]]\nname = "{p}"\nversion = "{v}"\ndescription = ""\noptional = false\npython-versions = "*"\n\n'
            for p, v in deps
        )
    body = ",\n".join(f'        "{p}=={v}"' for p, v in deps)
    return f'from setuptools import setup\n\nsetup(\n    name="app-{manifest_id}",\n    version="0.1.0",\n    install_requires=[\n{body}\n    ],\n)\n'


def build(cache: Dict[str, Any]) -> None:
    entries: List[Dict[str, Any]] = []
    for key, vulns in cache["versions"].items():
        name, ver = key.split("==", 1)
        active = [v for v in vulns if not v["withdrawn"]]
        entries.append({
            "package": name, "version": ver, "ground_truth": bool(active),
            "oracle_ids": sorted({str(v["id"]) for v in active}),
        })
    entries.sort(key=lambda e: (e["package"], Version(e["version"])))
    rng = random.Random(SEED)

    pos_by_pkg: Dict[str, List[Dict[str, Any]]] = {}
    neg_by_pkg: Dict[str, List[Dict[str, Any]]] = {}
    for e in entries:
        (pos_by_pkg if e["ground_truth"] else neg_by_pkg).setdefault(e["package"], []).append(e)

    pos_pkgs = sorted(pos_by_pkg)
    rng.shuffle(pos_pkgs)
    need_pos = sum(SPLIT_SIZES.values())
    if len(pos_pkgs) < need_pos:
        sys.exit(f"Not enough vulnerable packages: {len(pos_pkgs)} < {need_pos}. Increase N_PACKAGES.")

    selected: Dict[str, List[Dict[str, Any]]] = {s: [] for s in SPLIT_SIZES}
    pkg_split: Dict[str, str] = {}
    cursor = 0
    for split, n in [("test", SPLIT_SIZES["test"]), ("val", SPLIT_SIZES["val"]), ("dev", SPLIT_SIZES["dev"])]:
        for pkg in pos_pkgs[cursor:cursor + n]:
            e = dict(rng.choice(pos_by_pkg[pkg]))
            e["hard_negative"] = False
            selected[split].append(e)
            pkg_split[pkg] = split
        cursor += n

    other_neg_pkgs = sorted(p for p in neg_by_pkg if p not in pkg_split)
    rng.shuffle(other_neg_pkgs)
    other_iter = iter(other_neg_pkgs)
    for split, n in SPLIT_SIZES.items():
        # Hard negatives: a safe version of a package that also has vulnerable releases.
        hard = [p for p in pkg_split if pkg_split[p] == split and p in neg_by_pkg]
        rng.shuffle(hard)
        for pkg in hard[: n // 2]:
            e = dict(rng.choice(neg_by_pkg[pkg]))
            e["hard_negative"] = True
            selected[split].append(e)
        while sum(1 for e in selected[split] if not e["ground_truth"]) < n:
            pkg = next(other_iter)
            e = dict(rng.choice(neg_by_pkg[pkg]))
            e["hard_negative"] = False
            selected[split].append(e)
            pkg_split[pkg] = split

    if os.path.isdir(OUT_DIR):
        for child in os.listdir(OUT_DIR):
            path = os.path.join(OUT_DIR, child)
            if os.path.isdir(path):
                shutil.rmtree(path)

    final: List[Dict[str, Any]] = []
    fmt_idx = 0
    for split in ("dev", "val", "test"):
        items = selected[split]
        rng.shuffle(items)
        i = 0
        manifest_no = 0
        while i < len(items):
            size = rng.randint(4, 6)
            chunk = items[i:i + size]
            i += size
            manifest_no += 1
            fmt = FORMATS[fmt_idx % len(FORMATS)]
            fmt_idx += 1
            manifest_id = f"dep2_{split}_{manifest_no:03d}"
            folder = os.path.join(OUT_DIR, split, manifest_id)
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, fmt), "w", encoding="utf-8") as f:
                f.write(manifest_content(fmt, manifest_id, [(e["package"], e["version"]) for e in chunk]))
            for e in chunk:
                final.append({
                    "entry_id": f"{manifest_id}:{e['package']}=={e['version']}",
                    "manifest_id": manifest_id,
                    "split": split,
                    "manifest_type": fmt,
                    "file_path": f"dependencies_v2/{split}/{manifest_id}/{fmt}",
                    "package": e["package"],
                    "version": e["version"],
                    "ground_truth": e["ground_truth"],
                    "hard_negative": e["hard_negative"],
                    "oracle_ids": e["oracle_ids"],
                })

    per_split = {
        s: {
            "positives": sum(1 for e in final if e["split"] == s and e["ground_truth"]),
            "negatives": sum(1 for e in final if e["split"] == s and not e["ground_truth"]),
            "manifests": len({e["manifest_id"] for e in final if e["split"] == s}),
        }
        for s in SPLIT_SIZES
    }
    payload = {
        "metadata": {
            "description": "SCA benchmark v2: real PyPI package versions labelled by PyPI per-version vulnerabilities",
            "unit_of_evaluation": "dependency entry (package, pinned version)",
            "oracle": "PyPI JSON API /pypi/<name>/<version>/json field 'vulnerabilities'",
            "oracle_fetched_utc": cache.get("oracle_fetched_utc"),
            "top_packages_list": TOP_URL,
            "top_packages_last_update": cache.get("top_last_update"),
            "seed": SEED,
            "sampled_packages": N_PACKAGES,
            "versions_per_package": VERSIONS_PER_PACKAGE,
            "formats": FORMATS,
            "per_split": per_split,
            "total_entries": len(final),
            "total_manifests": len({e["manifest_id"] for e in final}),
        },
        "entries": final,
    }
    os.makedirs(os.path.dirname(GT_PATH), exist_ok=True)
    with open(GT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
    print(json.dumps(payload["metadata"], indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    do_fetch = args.fetch or not args.build
    do_build = args.build or not args.fetch
    cache = load_cache()
    if do_fetch:
        fetch(cache)
    if do_build:
        build(cache)


if __name__ == "__main__":
    main()
