#!/usr/bin/env python3
"""file-cleaner: find duplicate and corrupt files, then remove duplicates safely.

  python file_cleaner.py scan <folder> [--report report.json] [--protect PATH ...]
  python file_cleaner.py delete --report report.json            (dry run, changes nothing)
  python file_cleaner.py delete --report report.json --apply    (moves duplicates to quarantine)
  python file_cleaner.py delete --report report.json --apply --hard   (deletes for good)

The scan is read-only. Delete only touches exact duplicates, checks each one byte for byte
against the copy it keeps right before acting, and always keeps at least one copy.
Pure Python standard library. MIT licence.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.0.0"
CHUNK = 1 << 20
PARTIAL = 64 * 1024

EMPTY_OK = {".gitkeep", ".keep", "__init__.py", ".nojekyll", "py.typed", ".npmignore"}
TEXT_EXT = {".md", ".json", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".css",
            ".txt", ".py", ".sql", ".yml", ".yaml", ".csv", ".svg", ".ps1", ".sh"}
CHECK_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mov", ".m4a",
             ".zip", ".docx", ".xlsx", ".pptx"} | TEXT_EXT
# Folders inside these names are tagged and never offered for deletion.
SKIP_PARTS = {".git": "git-internal"}


# ---------------------------------------------------------------- helpers
def norm(p):
    return os.path.normcase(os.path.abspath(p))


def is_under(path, prefixes):
    np = norm(path)
    for pre in prefixes:
        if np == pre or np.startswith(pre.rstrip(os.sep) + os.sep):
            return True
    return False


def tag(path, protect):
    if is_under(path, protect):
        return "protected"
    parts = norm(path).split(os.sep)
    for name, label in SKIP_PARTS.items():
        if name in parts[:-1]:
            return label
    return "normal"


def sha256(path, limit=None):
    d = hashlib.sha256()
    with open(path, "rb") as f:
        if limit:
            d.update(f.read(limit))
        else:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                d.update(chunk)
    return d.hexdigest()


def same_bytes(a, b):
    """True only if both files exist, have the same size and the same content."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(CHUNK), fb.read(CHUNK)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# ---------------------------------------------------------------- corruption check
def sniff(path, ext, size):
    """Return a reason string if the file looks damaged, else None."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
            if size > 4096:
                f.seek(-2048, 2)
                tail = f.read()
            else:
                tail = head
    except OSError as e:
        return f"cannot read ({e.__class__.__name__})"
    if not head.strip(b"\0") and not tail.strip(b"\0"):
        return "only zero bytes (content lost, often sync damage)"
    if ext == ".pdf":
        if b"%PDF" not in head[:1024]:
            return "PDF header missing"
        if b"%%EOF" not in tail:
            return "PDF end missing (file cut short)"
    elif ext == ".png" and not head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG header wrong"
    elif ext in (".jpg", ".jpeg"):
        if not head.startswith(b"\xff\xd8"):
            return "JPG header wrong"
        if b"\xff\xd9" not in tail:
            return "JPG end missing (file cut short)"
    elif ext == ".gif" and head[:4] != b"GIF8":
        return "GIF header wrong"
    elif ext == ".webp" and not (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "WEBP header wrong"
    elif ext in (".mp4", ".mov", ".m4a") and head[4:8] not in (b"ftyp", b"moov", b"mdat", b"wide", b"free"):
        return "video header wrong"
    elif ext in (".zip", ".docx", ".xlsx", ".pptx"):
        try:
            with zipfile.ZipFile(path) as z:
                z.namelist()
        except Exception as e:  # noqa: BLE001 - any failure means the archive will not open
            return f"zip/Office file will not open ({e.__class__.__name__})"
    elif ext in TEXT_EXT and b"\0\0\0\0" in head + tail and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text file padded with zero bytes (often sync damage)"
    return None


# ---------------------------------------------------------------- scan
def walk(top, errors, skip):
    out = []
    stack = [top]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError as e:
            errors.append([d, str(e)])
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if not is_under(e.path, skip):
                            stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        out.append((e.path, e.stat(follow_symlinks=False).st_size))
                except OSError as ex:
                    errors.append([e.path, str(ex)])
    return out


def scan(folder, protect=(), workers=8, skip=(), quiet=False):
    root = os.path.abspath(folder)
    if not os.path.isdir(root):
        raise SystemExit(f"Not a folder: {folder}")
    protect_n = [norm(p) for p in protect]
    skip_n = [norm(p) for p in skip]
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    t0 = time.time()
    errors = []
    files = walk(root, errors, skip_n)
    total = sum(s for _, s in files)
    say(f"Listed {len(files)} files ({human(total)}) in {time.time() - t0:.0f}s")

    empty = [p for p, s in files if s == 0 and os.path.basename(p).lower() not in EMPTY_OK]
    todo = [(p, s) for p, s in files if s > 0 and os.path.splitext(p)[1].lower() in CHECK_EXT]
    corrupt, lock = [], threading.Lock()

    def check(item):
        p, s = item
        reason = sniff(p, os.path.splitext(p)[1].lower(), s)
        if reason:
            with lock:
                corrupt.append({"path": p, "size": s, "reason": reason, "tag": tag(p, protect_n)})

    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(check, todo, chunksize=64))
    say(f"Health check: {len(corrupt)} suspect files")

    by_size = defaultdict(list)
    for p, s in files:
        if s > 0:
            by_size[s].append(p)
    cands = [(s, ps) for s, ps in by_size.items() if len(ps) > 1]

    def safe_hash(p, limit=None):
        try:
            return sha256(p, limit)
        except OSError as e:
            with lock:
                errors.append([p, str(e)])
            return None

    groups = []
    with ThreadPoolExecutor(workers) as ex:
        for s, ps in cands:
            part = defaultdict(list)
            for p, d in zip(ps, ex.map(lambda p: safe_hash(p, PARTIAL), ps)):
                if d:
                    part[d].append(p)
            for pdigest, same in part.items():
                if len(same) < 2:
                    continue
                if s <= PARTIAL:  # the partial hash already covered the whole file
                    full = {pdigest: same}
                else:
                    full = defaultdict(list)
                    for p, d in zip(same, ex.map(safe_hash, same)):
                        if d:
                            full[d].append(p)
                for digest, dup in full.items():
                    if len(dup) > 1:
                        dup = sorted(dup)
                        groups.append({"size": s, "sha256": digest, "waste": s * (len(dup) - 1),
                                       "paths": dup, "tags": sorted({tag(p, protect_n) for p in dup})})
    groups.sort(key=lambda g: -g["waste"])
    say(f"Duplicates: {len(groups)} groups, {human(sum(g['waste'] for g in groups))} could be freed")
    corrupt.sort(key=lambda c: c["path"])
    return {
        "tool": "file-cleaner", "version": VERSION, "root": root,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "seconds": round(time.time() - t0, 1),
        "protect": [os.path.abspath(p) for p in protect],
        "files": len(files), "bytes": total,
        "dup_groups": groups, "corrupt": corrupt, "empty": sorted(empty), "errors": errors,
    }


def summary_text(r, limit=30):
    waste = sum(g["waste"] for g in r["dup_groups"])
    lines = [
        f"file-cleaner report for {r['root']}",
        f"Created {r['created']} in {r['seconds']}s",
        "",
        f"Files checked     : {r['files']} ({human(r['bytes'])})",
        f"Duplicate groups  : {len(r['dup_groups'])} (about {human(waste)} could be freed)",
        f"Suspect files     : {len(r['corrupt'])} (damaged or cut short, see below)",
        f"Empty files       : {len(r['empty'])}",
        f"Could not read    : {len(r['errors'])}",
        "",
        f"Biggest duplicate groups (top {limit}):",
    ]
    for g in r["dup_groups"][:limit]:
        lines.append(f"  {human(g['size'])} x {len(g['paths'])} copies" + ("  [has protected copy]" if "protected" in g["tags"] else ""))
        for p in g["paths"]:
            lines.append(f"      {p}")
    lines += ["", "Suspect files (never deleted by this tool, check them by hand):"]
    for c in r["corrupt"][: limit * 4]:
        lines.append(f"  {c['reason']:<50}  {c['path']}")
    if len(r["corrupt"]) > limit * 4:
        lines.append(f"  ... and {len(r['corrupt']) - limit * 4} more in the JSON report")
    lines += ["", "Next step: python file_cleaner.py delete --report <report.json>   (dry run first)"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- delete
def pick_keeper(paths, protect_n, rule):
    """Choose the copy to keep. A protected copy always wins, because it is never deleted."""
    existing = [p for p in paths if os.path.isfile(p)]
    if not existing:
        return None
    if rule == "newest":
        key = lambda p: (-os.path.getmtime(p), len(p), p)  # noqa: E731
    elif rule == "oldest":
        key = lambda p: (os.path.getmtime(p), len(p), p)  # noqa: E731
    else:  # shortest path, then alphabetical
        key = lambda p: (len(p), p)  # noqa: E731
    prot = [p for p in existing if tag(p, protect_n) != "normal"]
    return sorted(prot or existing, key=key)[0]


def delete(report_path, apply=False, hard=False, quarantine=None, protect=(), keep="shortest", quiet=False):
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    with open(report_path, encoding="utf-8") as f:
        r = json.load(f)
    if r.get("tool") != "file-cleaner":
        raise SystemExit("This file is not a file-cleaner report.")
    root = r["root"]
    protect_n = [norm(p) for p in list(r.get("protect", [])) + list(protect)]
    if quarantine is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        quarantine = os.path.join(os.path.dirname(os.path.abspath(report_path)), f"file-cleaner-quarantine-{stamp}")
    quarantine = os.path.abspath(quarantine)
    if apply and not hard and is_under(quarantine, [norm(root)]):
        raise SystemExit("The quarantine folder must be outside the scanned folder. Use --quarantine to pick one.")

    mode = "DRY RUN (nothing changes)" if not apply else ("HARD DELETE" if hard else f"MOVE TO QUARANTINE {quarantine}")
    say(f"Mode: {mode}")
    log, freed = [], 0
    counts = defaultdict(int)
    for g in r["dup_groups"]:
        keeper = pick_keeper(g["paths"], protect_n, keep)
        if keeper is None:
            for p in g["paths"]:
                log.append({"path": p, "action": "skipped", "why": "no copy left on disk"})
            counts["skipped"] += len(g["paths"])
            continue
        for p in g["paths"]:
            if p == keeper:
                continue
            why = None
            if tag(p, protect_n) != "normal":
                why = "protected"
            elif not os.path.isfile(p):
                why = "already gone"
            elif not os.path.isfile(keeper):
                why = "kept copy disappeared"
            else:
                try:
                    if os.path.samefile(p, keeper):
                        why = "same file (hard link)"
                except OSError:
                    why = "cannot stat"
            # Final byte-for-byte check, right before acting.
            if why is None and not same_bytes(p, keeper):
                why = "content changed since the scan"
            if why:
                log.append({"path": p, "keep": keeper, "action": "skipped", "why": why})
                counts["skipped"] += 1
                continue
            size = os.path.getsize(p)
            if not apply:
                log.append({"path": p, "keep": keeper, "action": "would remove", "size": size})
                counts["would remove"] += 1
                freed += size
                say(f"  would remove {p}\n        keeps {keeper}")
                continue
            try:
                if hard:
                    os.remove(p)
                    action = "deleted"
                else:
                    rel = os.path.relpath(p, root)
                    if rel.startswith(".."):
                        rel = os.path.splitdrive(os.path.abspath(p))[1].lstrip("\\/")
                    dst = os.path.join(quarantine, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    if os.path.exists(dst):
                        base, ext = os.path.splitext(dst)
                        n = 2
                        while os.path.exists(f"{base} ({n}){ext}"):
                            n += 1
                        dst = f"{base} ({n}){ext}"
                    shutil.move(p, dst)
                    action = "moved"
                log.append({"path": p, "keep": keeper, "action": action, "size": size,
                            **({"to": dst} if action == "moved" else {})})
                counts[action] += 1
                freed += size
            except OSError as e:
                log.append({"path": p, "keep": keeper, "action": "failed", "why": str(e)})
                counts["failed"] += 1
        # Safety net: the keeper must still be there.
        if apply and not os.path.isfile(keeper):
            log.append({"path": keeper, "action": "ERROR", "why": "kept copy missing after run"})
            counts["ERROR"] += 1

    log_path = None
    if apply:
        if not hard:
            os.makedirs(quarantine, exist_ok=True)
        log_dir = quarantine if not hard else os.path.dirname(os.path.abspath(report_path))
        log_path = os.path.join(log_dir, f"file-cleaner-log-{time.strftime('%Y%m%d-%H%M%S')}.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump({"report": os.path.abspath(report_path), "mode": mode, "log": log}, f, indent=1, ensure_ascii=False)
    say("")
    say("Result: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + f" | space: {human(freed)}")
    if log_path:
        say(f"Log: {log_path}")
    if not apply:
        say("Nothing was changed. Add --apply to move these files to a quarantine folder.")
    return {"counts": dict(counts), "freed": freed, "log": log, "log_path": log_path, "quarantine": None if hard else quarantine}


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog="file_cleaner.py", description="Find duplicate and corrupt files, then remove duplicates safely.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="read-only scan; writes a JSON report and a text summary")
    s.add_argument("folder")
    s.add_argument("--report", default="file-cleaner-report.json", help="report file (default: file-cleaner-report.json)")
    s.add_argument("--summary", help="text summary file (default: report name with .txt)")
    s.add_argument("--protect", action="append", default=[], metavar="PATH",
                   help="folder that is scanned but never offered for deletion (repeatable)")
    s.add_argument("--skip", action="append", default=[], metavar="PATH", help="folder not scanned at all (repeatable)")
    s.add_argument("--workers", type=int, default=8, help="threads for reading files (default 8)")

    d = sub.add_parser("delete", help="remove exact duplicates listed in a report (dry run unless --apply)")
    d.add_argument("--report", required=True)
    d.add_argument("--apply", action="store_true", help="actually move (or delete) files; without it nothing changes")
    d.add_argument("--hard", action="store_true", help="delete for good instead of moving to quarantine (needs --apply)")
    d.add_argument("--quarantine", metavar="DIR", help="where removed copies go (default: next to the report)")
    d.add_argument("--protect", action="append", default=[], metavar="PATH", help="extra folder never touched (repeatable)")
    d.add_argument("--keep", choices=["shortest", "oldest", "newest"], default="shortest",
                   help="which copy to keep: shortest path (default), oldest or newest")

    a = ap.parse_args(argv)
    if a.cmd == "scan":
        r = scan(a.folder, protect=a.protect, workers=max(1, a.workers), skip=a.skip)
        if is_under(a.report, [norm(r["root"])]):
            print("Note: the report is saved inside the scanned folder.")
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=1, ensure_ascii=False)
        summ = a.summary or os.path.splitext(a.report)[0] + ".txt"
        with open(summ, "w", encoding="utf-8") as f:
            f.write(summary_text(r))
        print(f"Report : {os.path.abspath(a.report)}")
        print(f"Summary: {os.path.abspath(summ)}")
        return 0
    if a.hard and not a.apply:
        ap.error("--hard needs --apply")
    res = delete(a.report, apply=a.apply, hard=a.hard, quarantine=a.quarantine, protect=a.protect, keep=a.keep)
    return 1 if res["counts"].get("ERROR") or res["counts"].get("failed") else 0


if __name__ == "__main__":
    sys.exit(main())
