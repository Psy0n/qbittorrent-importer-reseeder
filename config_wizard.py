import json
import os
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None and default != "":
        full = f"{text} [{default}]: "
    else:
        full = f"{text}: "
    val = input(full).strip()
    return val if val else (default or "")


def prompt_required(text: str, default: Optional[str] = None) -> str:
    while True:
        val = prompt(text, default)
        if val.strip():
            return val.strip()
        print("  -> This value is required.")


def yesno(text: str, default_yes: bool = True) -> bool:
    d = "y" if default_yes else "n"
    ans = prompt(f"{text} (y/n)", d).strip().lower()
    return ans in ("y", "yes")


def normalize_qb_root(qb_root: str) -> str:
    qb_root = qb_root.strip()
    if not qb_root.startswith("/"):
        qb_root = "/" + qb_root
    if qb_root != "/" and qb_root.endswith("/"):
        qb_root = qb_root.rstrip("/")
    return qb_root


def load_existing_config(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_config(path: Path, cfg: Dict[str, Any]) -> None:
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"\nSaved config to: {path.resolve()}")


# ----------------------------
# Validation helpers
# ----------------------------
def validate_dir_read(path_str: str) -> Tuple[bool, str]:
    """
    Validate directory exists and is readable (listable).
    Works for local and UNC paths on Windows.
    """
    try:
        p = Path(path_str)
        if not p.exists():
            return False, "Path does not exist."
        if not p.is_dir():
            return False, "Path exists but is not a directory."
        try:
            next(p.iterdir(), None)
        except PermissionError:
            return False, "No permission to read directory."
        except OSError as e:
            return False, f"OS error while reading directory: {e}"
        return True, "OK"
    except Exception as e:
        return False, f"Invalid path: {e}"


def validate_dir_write(path_str: str) -> Tuple[bool, str]:
    """
    Validate directory is writable by creating and deleting a temp file.
    ALWAYS attempts write (as requested).
    """
    try:
        p = Path(path_str)
        if not p.exists():
            return False, "Path does not exist."
        if not p.is_dir():
            return False, "Path exists but is not a directory."

        test_file = p / f".qb_config_wizard_write_test_{os.getpid()}.tmp"
        try:
            test_file.write_text("test", encoding="utf-8")
            _ = test_file.read_text(encoding="utf-8")
        except PermissionError:
            return False, "No permission to write in directory."
        except OSError as e:
            return False, f"OS error while writing: {e}"
        finally:
            try:
                if test_file.exists():
                    test_file.unlink()
            except Exception:
                return False, "Wrote test file but could not delete it (permissions/locks)."

        return True, "OK"
    except Exception as e:
        return False, f"Invalid path: {e}"


def validate_qb_login(base_url: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Validate qBittorrent API login. Expects 'Ok.' on success, 'Fails.' on failure.
    """
    base_url = base_url.rstrip("/")
    s = requests.Session()
    s.headers.update({"User-Agent": "qb-config-wizard/1.0", "Referer": base_url, "Origin": base_url})
    try:
        r = s.post(
            f"{base_url}/api/v2/auth/login",
            data={"username": username, "password": password},
            timeout=15,
        )
        body = (r.text or "").strip()
        if r.status_code != 200:
            return False, f"HTTP {r.status_code} {body!r}"
        if body.lower() != "ok.":
            return False, f"Login rejected: {body!r} (check username/password and Web UI settings)"

        v = s.get(f"{base_url}/api/v2/app/version", timeout=15)
        if v.status_code == 200:
            return True, f"Login OK (qB version: {v.text.strip()})"
        return True, "Login OK (version check failed, but auth works)"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {e}"


def wizard() -> None:
    print("=== qBittorrent Import Config Wizard ===\n")
    print("Tip: You can paste Windows UNC paths like: \\\\Ds620\\ds620\\Series")
    print("Tip: Press Enter on a blank 'Media root name' prompt to finish.\n")

    out_path_str = prompt("Config file to write", "config.json")
    out_path = Path(out_path_str)

    existing = load_existing_config(out_path)
    if existing:
        print(f"\nFound an existing config at {out_path}. We'll update/overwrite fields.\n")

    # --- qBittorrent connection ---
    qb_url = prompt_required(
        "qBittorrent URL (Web UI base)",
        existing.get("qb", {}).get("url") if existing else "http://192.168.0.231:8080",
    )
    qb_user = prompt_required(
        "qBittorrent username",
        existing.get("qb", {}).get("username") if existing else "admin",
    )

    print("\nPassword will not be displayed while typing.")
    qb_pass = getpass("qBittorrent password: ").strip()
    if not qb_pass and existing and "qb" in existing and existing["qb"].get("password"):
        qb_pass = existing["qb"]["password"]
        print("  -> Keeping existing password from config.")

    # --- torrent locations ---
    print("\n--- Torrent locations ---")
    torrent_dir_default = existing.get("torrent_dir") if existing else ""
    torrent_dir = prompt_required("Source folder containing .torrent files", torrent_dir_default)

    stage_default = existing.get("torrent_stage_dir") if existing else ""
    torrent_stage_dir = prompt("Destination folder to COPY torrents into (optional; Enter to skip)", stage_default)

    # --- media roots ---
    print("\n--- Media roots ---")
    media_roots: List[Dict[str, str]] = []
    if existing and isinstance(existing.get("media_roots"), list) and existing["media_roots"]:
        if yesno("Load existing media roots from config and edit?", True):
            for mr in existing["media_roots"]:
                if isinstance(mr, dict):
                    media_roots.append(dict(mr))

    def add_media_root() -> bool:
        name = prompt("Media root name (blank to finish)", "")
        if not name:
            return False

        scan_path = prompt_required(f"  Scan path for '{name}'", "")
        qb_root = normalize_qb_root(prompt_required(f"  qB root for '{name}' (e.g. /{name})", f"/{name}"))
        category = prompt(f"  Category for '{name}' (Enter = same as name)", name) or name

        media_roots.append(
            {
                "name": name,
                "scan_path": scan_path,
                "qb_root": qb_root,
                "category": category,
            }
        )
        return True

    if media_roots:
        print("\nCurrent media roots loaded:")
        for i, mr in enumerate(media_roots, 1):
            print(
                f"  {i}. {mr.get('name')} | scan_path={mr.get('scan_path')} | "
                f"qb_root={mr.get('qb_root')} | category={mr.get('category')}"
            )
        choice = prompt("\nDo you want to (k)eep, (c)lear and re-enter, or (a)dd more?", "a").lower()
        if choice.startswith("c"):
            media_roots = []
        if choice.startswith("a"):
            while add_media_root():
                pass
    else:
        while add_media_root():
            pass

    if not media_roots:
        print("\nERROR: You must add at least one media root.")
        return

    # ----------------------------
    # Validation phase
    # ----------------------------
    print("\n=== Validation ===")

    print("\n[1/3] Testing qBittorrent login...")
    ok, msg = validate_qb_login(qb_url, qb_user, qb_pass)
    print(f"  Result: {'OK' if ok else 'FAIL'} - {msg}")
    if not ok and not yesno("Continue anyway?", False):
        print("Aborting. Fix qB URL/credentials and run wizard again.")
        return

    paths_to_test = [("torrent_dir", torrent_dir)]
    if torrent_stage_dir.strip():
        paths_to_test.append(("torrent_stage_dir", torrent_stage_dir))
    for mr in media_roots:
        paths_to_test.append((f"media_root:{mr['name']}", mr["scan_path"]))

    print("\n[2/3] Testing folder READ access...")
    read_all_ok = True
    for label, p in paths_to_test:
        okp, msgp = validate_dir_read(p)
        print(f"  {label}: {'OK' if okp else 'FAIL'} - {p} - {msgp}")
        if not okp:
            read_all_ok = False
    if not read_all_ok and not yesno("Some paths failed READ validation. Continue anyway?", False):
        print("Aborting. Fix paths and run wizard again.")
        return

    print("\n[3/3] Testing folder WRITE access (always)...")
    write_all_ok = True
    for label, p in paths_to_test:
        okw, msgw = validate_dir_write(p)
        print(f"  {label}: {'OK' if okw else 'FAIL'} - {p} - {msgw}")
        if not okw:
            write_all_ok = False

    # NOTE: torrent_dir is often read-only (share). Because you asked for ALWAYS write testing,
    # this may fail. You can still choose to save and continue.
    if not write_all_ok and not yesno("Some paths failed WRITE validation. Save config anyway?", False):
        print("Aborting. Fix permissions/paths and run wizard again.")
        return

    cfg = {
        "qb": {"url": qb_url, "username": qb_user, "password": qb_pass},
        "torrent_dir": torrent_dir,
        **({"torrent_stage_dir": torrent_stage_dir} if torrent_stage_dir.strip() else {}),
        "media_roots": media_roots,
    }

    save_config(out_path, cfg)

    print("\nDone.")
    print("Suggested next commands:")
    print("  python qb_import.py --config config.json --dry-run")
    print("  python qb_import.py --config config.json")
    print("  python qb_import.py --config config.json --fix-uncategorized --dry-run")


if __name__ == "__main__":
    wizard()
