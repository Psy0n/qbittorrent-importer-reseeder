import argparse
import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from tqdm import tqdm


# ----------------------------
# Minimal bencode decoder/encoder (for .torrent parsing + infohash)
# ----------------------------
class BencodeError(Exception):
    pass


def bdecode(data: bytes, idx: int = 0) -> Tuple[Any, int]:
    if idx >= len(data):
        raise BencodeError("Unexpected end of data")

    c = data[idx:idx + 1]

    if c == b"i":  # int
        end = data.index(b"e", idx)
        num = int(data[idx + 1:end])
        return num, end + 1

    if c == b"l":  # list
        idx += 1
        out = []
        while data[idx:idx + 1] != b"e":
            item, idx = bdecode(data, idx)
            out.append(item)
        return out, idx + 1

    if c == b"d":  # dict
        idx += 1
        out = {}
        while data[idx:idx + 1] != b"e":
            key, idx = bdecode(data, idx)
            if not isinstance(key, (bytes, bytearray)):
                raise BencodeError("Dict key must be bytes")
            val, idx = bdecode(data, idx)
            out[bytes(key)] = val
        return out, idx + 1

    # bytes: <len>:<payload>
    if b"0" <= c <= b"9":
        colon = data.index(b":", idx)
        length = int(data[idx:colon])
        start = colon + 1
        end = start + length
        if end > len(data):
            raise BencodeError("String length out of bounds")
        return data[start:end], end

    raise BencodeError(f"Invalid bencode prefix at {idx}: {c!r}")


def bencode(x: Any) -> bytes:
    if isinstance(x, bool):
        x = int(x)

    if isinstance(x, int):
        return b"i" + str(x).encode("ascii") + b"e"

    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
        return str(len(b)).encode("ascii") + b":" + b

    if isinstance(x, str):
        b = x.encode("utf-8")
        return str(len(b)).encode("ascii") + b":" + b

    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"

    if isinstance(x, dict):
        bkeys = []
        for k in x.keys():
            if isinstance(k, bytes):
                bkeys.append(k)
            elif isinstance(k, str):
                bkeys.append(k.encode("utf-8"))
            else:
                raise BencodeError("Dict key must be bytes/str")

        items = []
        for k in sorted(bkeys):
            v = x.get(k, x.get(k.decode("utf-8", "ignore"), None))
            if v is None and k in x:
                v = x[k]
            items.append(bencode(k))
            items.append(bencode(v))
        return b"d" + b"".join(items) + b"e"

    raise BencodeError(f"Unsupported type for bencode: {type(x)}")


# ----------------------------
# Torrent parsing
# ----------------------------
def parse_torrent(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    obj, _ = bdecode(raw, 0)
    if not isinstance(obj, dict) or b"info" not in obj:
        raise BencodeError("Not a valid .torrent (missing info dict)")

    info = obj[b"info"]
    if not isinstance(info, dict):
        raise BencodeError("Invalid info dict")

    infohash = hashlib.sha1(bencode(info)).hexdigest()

    name = info.get(b"name", b"")
    if isinstance(name, (bytes, bytearray)):
        name_str = bytes(name).decode("utf-8", "replace")
    else:
        name_str = str(name)

    files = []
    if b"files" in info:  # multi-file
        for f in info[b"files"]:
            length = int(f[b"length"])
            parts = [p.decode("utf-8", "replace") for p in f[b"path"]]
            rel = "/".join(parts)
            files.append({"rel": rel, "length": length})
        mode = "multi"
    else:  # single file
        length = int(info[b"length"])
        files.append({"rel": name_str, "length": length})
        mode = "single"

    return {"path": str(path), "name": name_str, "mode": mode, "files": files, "infohash": infohash}


# ----------------------------
# Host matching helpers
# ----------------------------
def score_candidate(base_dir: Path, torrent_files: List[Dict[str, Any]]) -> Tuple[int, int]:
    matched = 0
    total = len(torrent_files)
    for tf in torrent_files:
        rel_parts = tf["rel"].split("/")
        p = base_dir.joinpath(*rel_parts)
        try:
            if p.is_file() and p.stat().st_size == tf["length"]:
                matched += 1
        except OSError:
            pass
    return matched, total


def _base_dir_from_match(file_path: Path, torrent_rel: str) -> Path:
    rel_parts = torrent_rel.split("/")
    base = file_path
    for _ in rel_parts:
        base = base.parent
    return base


def _to_qb_path(scan_root: Path, qb_root: str, host_dir: Path) -> str:
    rel = os.path.relpath(str(host_dir), str(scan_root)).replace("\\", "/")
    if rel == ".":
        return qb_root
    return qb_root.rstrip("/") + "/" + rel


def build_media_index(media_roots: List[Dict[str, str]]) -> Dict[Tuple[str, int], List[Tuple[Dict[str, str], Path]]]:
    """
    Index: (lowercase_filename, size_bytes) -> [(media_root_dict, full_path), ...]
    Streaming via os.walk to avoid big memory spikes.
    """
    index: Dict[Tuple[str, int], List[Tuple[Dict[str, str], Path]]] = {}

    for mr in media_roots:
        root = Path(mr["scan_path"])
        if not root.exists():
            print(f"[WARN] media root not found: {root}")
            continue

        print(f"\nIndexing: {mr['name']} -> {root}")
        scanned = 0

        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                key = (fn.lower(), size)
                index.setdefault(key, []).append((mr, p))
                scanned += 1

        print(f"  Indexed files: {scanned:,}")

    return index


def find_match_for_torrent_indexed(
    t: Dict[str, Any],
    file_index: Dict[Tuple[str, int], List[Tuple[Dict[str, str], Path]]],
    threshold: float,
) -> Optional[Dict[str, Any]]:
    name = t["name"]
    mode = t["mode"]
    files = t["files"]

    # ---- Single-file torrents (common for TV episodes) ----
    if mode == "single":
        tf = files[0]
        key = (Path(tf["rel"]).name.lower(), tf["length"])
        candidates = file_index.get(key, [])
        if not candidates:
            return None

        def cand_sort_key(item: Tuple[Dict[str, str], Path]) -> Tuple[int, int]:
            mr, p = item
            is_tv = 1 if mr["name"] in ("Series", "Animated") else 0
            depth = len(p.parts)
            return (is_tv, depth)

        mr, p = sorted(candidates, key=cand_sort_key, reverse=True)[0]
        scan_root = Path(mr["scan_path"])
        qb_root = mr["qb_root"]
        qb_category = mr.get("category") or mr["name"]

        save_dir_host = p.parent
        qb_savepath = _to_qb_path(scan_root, qb_root, save_dir_host)

        rel_to_root = Path(os.path.relpath(str(p), str(scan_root)))
        show = rel_to_root.parts[0] if rel_to_root.parts else name
        group_key = f"{mr['name']}::{show}" if mr["name"] in ("Series", "Animated") else f"{mr['name']}::{name}"

        return {
            "media_root": mr["name"],
            "qb_category": qb_category,
            "scan_root": str(scan_root),
            "scan_base_dir": str(save_dir_host),
            "qb_savepath": qb_savepath,
            "content_layout": "NoSubfolder",
            "match_ratio": 1.0,
            "group_key": group_key,
            "torrent_name": name,
        }

    # ---- Multi-file torrents (season packs etc.) ----
    sample_files = files[: min(25, len(files))]
    votes: Dict[Tuple[str, str, str], int] = {}
    mr_lookup: Dict[Tuple[str, str], Dict[str, str]] = {}

    # Build mr lookup from index contents
    for arr in file_index.values():
        for mr, _p in arr:
            mr_lookup[(mr["name"], mr["scan_path"])] = mr

    for tf in sample_files:
        key = (Path(tf["rel"]).name.lower(), tf["length"])
        for mr, p in file_index.get(key, []):
            base_dir = _base_dir_from_match(p, tf["rel"])
            k = (mr["name"], mr["scan_path"], str(base_dir))
            votes[k] = votes.get(k, 0) + 1

    if not votes:
        return None

    best: Optional[Dict[str, Any]] = None

    for (mr_name, mr_scan_path, base_dir_str), _vote in sorted(votes.items(), key=lambda x: x[1], reverse=True)[:15]:
        mr = mr_lookup.get((mr_name, mr_scan_path))
        if not mr:
            continue

        base_dir = Path(base_dir_str)
        scan_root = Path(mr["scan_path"])
        qb_root = mr["qb_root"]
        qb_category = mr.get("category") or mr["name"]

        matched_count, total = score_candidate(base_dir, files)
        ratio = matched_count / total if total else 0.0
        if ratio < threshold:
            continue

        if base_dir.name == name:
            content_layout = "Original"
            save_dir_host = base_dir.parent
        else:
            content_layout = "NoSubfolder"
            save_dir_host = base_dir

        qb_savepath = _to_qb_path(scan_root, qb_root, save_dir_host)

        rel_to_root = Path(os.path.relpath(str(save_dir_host), str(scan_root)))
        show = rel_to_root.parts[0] if rel_to_root.parts else name
        group_key = f"{mr['name']}::{show}" if mr["name"] in ("Series", "Animated") else f"{mr['name']}::{name}"

        cand = {
            "media_root": mr["name"],
            "qb_category": qb_category,
            "scan_root": str(scan_root),
            "scan_base_dir": str(base_dir),
            "qb_savepath": qb_savepath,
            "content_layout": content_layout,
            "match_ratio": ratio,
            "group_key": group_key,
            "torrent_name": name,
        }
        if best is None or cand["match_ratio"] > best["match_ratio"]:
            best = cand

    return best


# ----------------------------
# Staging torrents (copy .torrent files to NAS share)
# ----------------------------
def stage_torrent_file(torrent_file: Path, torrent_root: Path, stage_root: Path, infohash: str) -> Path:
    rel = torrent_file.relative_to(torrent_root)
    dest = stage_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        try:
            if dest.stat().st_size == torrent_file.stat().st_size:
                return dest
        except OSError:
            pass
        suffix = infohash[:8]
        dest = dest.with_name(f"{dest.stem}__{suffix}{dest.suffix}")

    shutil.copy2(torrent_file, dest)
    return dest


# ----------------------------
# qBittorrent Web API client
# ----------------------------
class QBClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "qb-import-helper/1.0",
            "Referer": self.base_url,
            "Origin": self.base_url,
        })

    def login(self) -> None:
        r = self.s.post(
            f"{self.base_url}/api/v2/auth/login",
            data={"username": self.username, "password": self.password},
            timeout=15,
        )
        body = (r.text or "").strip()
        if r.status_code != 200 or body.lower() != "ok.":
            raise RuntimeError(f"Login failed: HTTP {r.status_code} body={body!r}")

    def torrents_info(self, hashes: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {}
        if hashes:
            params["hashes"] = hashes
        r = self.s.get(f"{self.base_url}/api/v2/torrents/info", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def existing_hashes(self) -> set:
        items = self.torrents_info()
        return {i.get("hash", "").lower() for i in items if i.get("hash")}

    def categories(self) -> dict:
        r = self.s.get(f"{self.base_url}/api/v2/torrents/categories", timeout=30)
        r.raise_for_status()
        return r.json()

    def ensure_category(self, category: str, save_path: str = "") -> None:
        cats = self.categories()
        if category in cats:
            return
        r = self.s.post(
            f"{self.base_url}/api/v2/torrents/createCategory",
            data={"category": category, "savePath": save_path},
            timeout=30,
        )
        if r.status_code not in (200, 409):
            raise RuntimeError(f"CreateCategory failed: HTTP {r.status_code} body={r.text[:200]!r}")

    def set_category(self, hashes: List[str], category: str) -> None:
        # hashes are pipe-delimited per Web API
        payload = {"hashes": "|".join(hashes), "category": category}
        r = self.s.post(f"{self.base_url}/api/v2/torrents/setCategory", data=payload, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"setCategory failed: HTTP {r.status_code} body={r.text[:200]!r}")

    def add_torrent(
        self,
        torrent_file: Path,
        savepath: str,
        category: Optional[str] = None,
        paused: bool = True,
        skip_checking: bool = False,
        auto_tmm: bool = False,
        content_layout: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> None:
        with torrent_file.open("rb") as f:
            files = {"torrents": (torrent_file.name, f, "application/x-bittorrent")}
            data = {
                "savepath": savepath,
                "paused": "true" if paused else "false",
                "skip_checking": "true" if skip_checking else "false",
                "autoTMM": "true" if auto_tmm else "false",
            }
            if content_layout:
                data["contentLayout"] = content_layout
            if tags:
                data["tags"] = tags
            if category:
                data["category"] = category

            r = self.s.post(f"{self.base_url}/api/v2/torrents/add", data=data, files=files, timeout=60)
            if r.status_code != 200:
                raise RuntimeError(f"Add failed: HTTP {r.status_code} body={r.text[:200]!r}")


# ----------------------------
# Category fixer
# ----------------------------
def normalize_slash(p: str) -> str:
    return (p or "").replace("\\", "/").rstrip("/")


def build_qb_root_to_category(media_roots: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """
    Returns list of (qb_root, category) sorted by qb_root length desc for best prefix match.
    """
    pairs = []
    for mr in media_roots:
        qb_root = normalize_slash(mr["qb_root"])
        if not qb_root.startswith("/"):
            qb_root = "/" + qb_root
        category = mr.get("category") or mr["name"]
        pairs.append((qb_root, category))
    pairs.sort(key=lambda x: len(x[0]), reverse=True)
    return pairs


def infer_category_from_paths(torrent_info: Dict[str, Any], root_map: List[Tuple[str, str]]) -> Optional[str]:
    """
    Decide category from torrent's save_path (preferred) or content_path.
    """
    save_path = normalize_slash(torrent_info.get("save_path") or torrent_info.get("savePath") or "")
    content_path = normalize_slash(torrent_info.get("content_path") or torrent_info.get("contentPath") or "")

    for qb_root, cat in root_map:
        if save_path == qb_root or save_path.startswith(qb_root + "/"):
            return cat
        if content_path == qb_root or content_path.startswith(qb_root + "/"):
            return cat
    return None


def fix_uncategorized(qb: QBClient, media_roots: List[Dict[str, Any]], dry_run: bool) -> None:
    root_map = build_qb_root_to_category(media_roots)

    # ensure categories exist first
    needed = sorted({cat for _root, cat in root_map})
    for c in needed:
        qb.ensure_category(c)

    items = qb.torrents_info()
    to_fix: Dict[str, List[str]] = {}
    skipped_unknown = 0
    already_categorized = 0

    for it in items:
        current = (it.get("category") or "").strip()
        if current:
            already_categorized += 1
            continue  # only fix uncategorized

        target = infer_category_from_paths(it, root_map)
        h = (it.get("hash") or "").lower()
        if not h or not target:
            skipped_unknown += 1
            continue

        to_fix.setdefault(target, []).append(h)

    print("\nFix uncategorized summary")
    print(f"  Total torrents:         {len(items)}")
    print(f"  Already categorized:    {already_categorized}")
    print(f"  Uncategorized -> fix:   {sum(len(v) for v in to_fix.values())}")
    print(f"  Uncategorized skipped:  {skipped_unknown} (couldn't infer category from save_path/content_path)")

    if not to_fix:
        return

    for cat, hashes in to_fix.items():
        print(f"  - {cat}: {len(hashes)}")

    if dry_run:
        print("\nDry-run only: no changes applied.")
        return

    # Apply in batches to avoid huge POST bodies
    for cat, hashes in to_fix.items():
        for i in range(0, len(hashes), 100):
            batch = hashes[i:i + 100]
            qb.set_category(batch, cat)
            print(f"Set category '{cat}' for {len(batch)} torrents")


# ----------------------------
# Main
# ----------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Scan media folders, match existing files to .torrent files, import into qBittorrent, and optionally fix categories."
    )
    ap.add_argument("--config", required=True, help="Path to config.json")
    ap.add_argument("--threshold", type=float, default=0.95, help="Match ratio for multi-file torrents (default 0.95)")
    ap.add_argument("--dry-run", action="store_true", help="Only report / no changes")
    ap.add_argument("--yes", action="store_true", help="Import without prompting (yes to all)")
    ap.add_argument("--tags", default="imported", help="Tags to apply to imported torrents (default: imported)")
    ap.add_argument("--stage", action="store_true", help="In --dry-run mode, also stage matched torrents to torrent_stage_dir")
    ap.add_argument("--no-stage", action="store_true", help="Disable staging even if torrent_stage_dir is set")
    ap.add_argument("--fix-uncategorized", action="store_true", help="Fix existing uncategorized torrents by inferring category from save_path")

    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    qb_cfg = cfg["qb"]
    torrent_dir = Path(cfg["torrent_dir"])
    stage_dir_value = cfg.get("torrent_stage_dir")
    stage_root = Path(stage_dir_value) if stage_dir_value else None
    media_roots = cfg["media_roots"]

    qb = QBClient(qb_cfg["url"], qb_cfg["username"], qb_cfg["password"])
    qb.login()

    # Maintenance mode: fix categories and exit
    if args.fix_uncategorized:
        fix_uncategorized(qb, media_roots, dry_run=args.dry_run)
        return

    stage_enabled = (
        stage_root is not None
        and not args.no_stage
        and (not args.dry_run or args.stage)
    )

    torrent_files = sorted(torrent_dir.rglob("*.torrent"))
    if not torrent_files:
        print(f"No .torrent files found under: {torrent_dir}")
        return

    file_index = build_media_index(media_roots)
    existing = qb.existing_hashes()

    print(f"\nFound {len(torrent_files)} .torrent files. Matching against indexed media…")

    matched: List[Tuple[Path, Dict[str, Any], Dict[str, Any]]] = []
    skipped_existing = 0
    unmatched = 0

    for tf in tqdm(torrent_files, unit="torrent", desc="Parse+match"):
        try:
            t = parse_torrent(tf)
        except Exception as e:
            print(f"[PARSE FAIL] {tf}: {e}")
            continue

        ih = t["infohash"].lower()
        if ih in existing:
            skipped_existing += 1
            continue

        m = find_match_for_torrent_indexed(t, file_index, threshold=args.threshold)
        if not m:
            unmatched += 1
            continue

        matched.append((tf, t, m))

    print("\nSummary")
    print(f"  Matched:         {len(matched)}")
    print(f"  Unmatched:       {unmatched}")
    print(f"  Already in qB:   {skipped_existing}")

    if not matched:
        return

    if args.dry_run:
        print("\nDry-run matches (first 50):")
        for tf, t, m in matched[:50]:
            print(
                f"- {tf.name} -> {m['media_root']} | category={m['qb_category']} | "
                f"savepath={m['qb_savepath']} | layout={m['content_layout']} | ratio={m['match_ratio']:.2f} | group={m['group_key']}"
            )

        if stage_enabled and stage_root is not None:
            print(f"\nStaging matched .torrent files into: {stage_root}")
            staged = 0
            for tf, t, _m in tqdm(matched, desc="Stage torrents", unit="torrent"):
                try:
                    stage_torrent_file(tf, torrent_dir, stage_root, t["infohash"])
                    staged += 1
                except Exception as e:
                    print(f"[STAGE FAIL] {tf}: {e}")
            print(f"Staged: {staged}/{len(matched)}")

        return

    # Ensure categories exist
    needed_categories = sorted({m["qb_category"] for _tf, _t, m in matched})
    for c in needed_categories:
        qb.ensure_category(c)

    group_decisions: Dict[str, bool] = {}
    global_yes_all = args.yes

    imported_ok = 0
    imported_fail = 0

    for tf, t, m in matched:
        ih = t["infohash"].lower()
        if ih in existing:
            continue

        tf_to_use = tf
        if stage_enabled and stage_root is not None:
            try:
                tf_to_use = stage_torrent_file(tf, torrent_dir, stage_root, t["infohash"])
            except Exception as e:
                print(f"[STAGE FAIL] {tf}: {e}")
                tf_to_use = tf

        line = (
            f"IMPORT {tf.name} -> category={m['qb_category']} "
            f"savepath={m['qb_savepath']} layout={m['content_layout']} ({m['match_ratio']:.2f})"
        )

        if not global_yes_all:
            gkey = m.get("group_key")
            if gkey and gkey in group_decisions:
                if not group_decisions[gkey]:
                    continue
                print(line)
            else:
                prompt = f"{line}\nApprove ALL imports for group '{gkey}'? [y/n/a] (a = yes to ALL): "
                ans = input(prompt).strip().lower()
                if ans == "a":
                    global_yes_all = True
                    print(line)
                elif ans == "y":
                    if gkey:
                        group_decisions[gkey] = True
                    print(line)
                else:
                    if gkey:
                        group_decisions[gkey] = False
                    continue
        else:
            print(line)

        try:
            qb.add_torrent(
                torrent_file=tf_to_use,
                savepath=m["qb_savepath"],
                category=m["qb_category"],
                paused=True,
                skip_checking=False,
                auto_tmm=False,
                content_layout=m["content_layout"],
                tags=args.tags,
            )
            existing.add(ih)
            imported_ok += 1
        except Exception as e:
            imported_fail += 1
            print(f"[IMPORT FAIL] {tf_to_use}: {e}")

    print("\nDone.")
    print(f"  Imported OK:     {imported_ok}")
    print(f"  Imported issues: {imported_fail}")
    print("Imported torrents are paused; start them in qBittorrent when ready (they should hash-check first).")


if __name__ == "__main__":
    main()
