#!/usr/bin/env python3
"""file-cleaner: find duplicate and corrupt files, then remove duplicates safely.

  python file_cleaner.py scan <folder> [--report report.json] [--protect PATH ...]
  python file_cleaner.py delete --report report.json            (dry run, changes nothing)
  python file_cleaner.py delete --report report.json --apply    (moves duplicates to quarantine)
  python file_cleaner.py delete --report report.json --apply --hard   (deletes for good)
  python file_cleaner.py restore --from <quarantine folder>     (dry run; add --apply to put files back)

The scan is read-only. Delete only touches exact duplicates, checks each one byte for byte
against the copy it keeps right before acting, and always keeps at least one copy.
Pure Python standard library. MIT licence.
"""
import argparse
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.1.0"
CHUNK = 1 << 20
PARTIAL = 64 * 1024

EMPTY_OK = {".gitkeep", ".keep", "__init__.py", ".nojekyll", "py.typed", ".npmignore"}
TEXT_EXT = {".md", ".json", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".css",
            ".txt", ".py", ".sql", ".yml", ".yaml", ".csv", ".svg", ".ps1", ".sh"}
CHECK_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mov", ".m4a",
             ".zip", ".docx", ".xlsx", ".pptx"} | TEXT_EXT
LOG_NAME = "file-cleaner-log.jsonl"  # also marks a folder as a quarantine
# Never read, never kept as "the" copy, never removed. A copy in a bin or a cache is not a safe copy.
OFF_LIMITS = re.compile(
    r"^(\.git|\.svn|\.hg|node_modules|site-packages|__pycache__|\.?venv|\$recycle\.bin|"
    r"system volume information|\.trash.*|lost\+found|found\.\d{3}|file-cleaner-quarantine.*|"
    r".+\.(app|framework|bundle|photoslibrary|lrdata|lrlibrary|musiclibrary|tvlibrary|imovielibrary|fcpbundle))$")
LINK_TAGS = (0xA000000C, 0xA0000003)  # Windows: symbolic link, junction or mount point
ONLINE_ONLY = 0x1000 | 0x40000 | 0x400000  # Windows: content is in the cloud, reading it would download it


# ---------------------------------------------------------------- helpers
def norm(p):
    return os.path.normcase(os.path.abspath(p))


def real(p):
    """Like norm, with links, junctions and Windows short names resolved."""
    return os.path.normcase(os.path.realpath(p))


def is_under(path, prefixes):
    np = norm(path)
    for pre in prefixes:
        if np == pre or np.startswith(pre.rstrip(os.sep) + os.sep):
            return True
    return False


def is_link(st):
    """True for symbolic links and for Windows junctions (which Python does not call links)."""
    return stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) in LINK_TAGS


def is_online_only(st):
    return bool(getattr(st, "st_file_attributes", 0) & ONLINE_ONLY)


def show(p):
    """A file name that is safe to print: control and direction characters become escapes."""
    return "".join(c if c.isprintable() else ascii(c)[1:-1] for c in str(p))


def system_dirs():
    if os.name == "nt":
        names = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "APPDATA", "LOCALAPPDATA")
        out = [os.environ[n] for n in names if os.environ.get(n)]
    else:
        out = ["/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64", "/opt", "/boot", "/System", "/Library",
               "/Applications", os.path.expanduser("~/Library")]
    return [real(p) for p in out if os.path.isdir(p)]


class Guard:
    """Says what may happen to a path: off-limits, protected, project or normal."""

    ORDER = ("off-limits", "protected", "project", "normal")  # the strictest label wins

    def __init__(self, root, protect=()):
        self.root = real(root)
        self.protect = [norm(p) for p in protect] + [real(p) for p in protect]
        self.ids = set()  # the protected folders by identity, so letter case or a link cannot hide one
        for p in protect:
            try:
                st = os.stat(p)
                if st.st_ino:
                    self.ids.add((st.st_dev, st.st_ino))
            except OSError:
                pass
        self.system = system_dirs()
        self.temp = [real(tempfile.gettempdir())]
        self.cache = {}

    def inside(self, path):
        """The folder really is in the scanned folder (no link leads out of it)."""
        return is_under(real(os.path.dirname(os.path.abspath(path))), [self.root])

    def _is_protected(self, p):
        if is_under(p, self.protect):
            return True
        if not self.ids:
            return False
        try:
            st = os.stat(p)
        except OSError:
            return False
        return (st.st_dev, st.st_ino) in self.ids

    def _folder(self, d):
        if d not in self.cache:
            if OFF_LIMITS.match(os.path.basename(d).lower()) or os.path.lexists(os.path.join(d, LOG_NAME)):
                label = "off-limits"
            elif self._is_protected(d):
                label = "protected"
            elif os.path.lexists(os.path.join(d, ".git")):
                label = "project"
            else:
                label = "normal"
            up = os.path.dirname(d)
            if up != d:
                label = min(label, self._folder(up), key=self.ORDER.index)
            self.cache[d] = label
        return self.cache[d]

    def place(self, path):
        folder = real(os.path.dirname(os.path.abspath(path)))
        if is_under(folder, self.system) and not is_under(folder, self.temp):
            return "off-limits"
        label = self._folder(folder)
        if label != "off-limits" and self._is_protected(path):
            return "protected"
        return label


def why_not(path, guard):
    """Reason this path cannot be trusted as a plain, readable file of the scanned folder, else None."""
    try:
        st = os.lstat(path)
    except OSError:
        return "already gone"
    if is_link(st):
        return "is a link now"
    if not stat.S_ISREG(st.st_mode):
        return "not a plain file"
    if is_online_only(st):
        return "online-only (not on this disk)"
    if not guard.inside(path):
        return "leads outside the scanned folder"
    if guard.place(path) == "off-limits":
        return "in a system, program, bin or quarantine folder"
    return None


def fingerprint(path):
    st = os.lstat(path)
    return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)


def move_file(src, dst):
    """Move without overwriting. Across disks: copy, check every byte, then remove the original."""
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "target already exists", dst)
    try:
        os.rename(src, dst)
        return
    except OSError as e:
        if e.errno != errno.EXDEV and getattr(e, "winerror", None) != 17:
            raise
    try:
        shutil.copy2(src, dst)
        if not same_bytes(src, dst):
            raise OSError("the copy does not match the original")
        os.remove(src)
    except OSError:
        if os.path.lexists(src) and os.path.lexists(dst):
            os.remove(dst)  # only our own new copy: the original is still in place
        raise


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
            if not head.strip(b"\0") and not tail.strip(b"\0"):
                return "starts and ends with zero bytes (content lost, often sync damage)"
            if ext in (".jpg", ".jpeg"):
                if not head.startswith(b"\xff\xd8"):
                    return "JPG header wrong"
                end_marker = b"\xff\xd9"
                if end_marker in tail or end_marker in head:
                    return None
                # Motion photos can have video data after the JPEG end marker.
                f.seek(len(head))
                previous = head[-1:]
                for chunk in iter(lambda: f.read(CHUNK), b""):
                    if end_marker in previous + chunk:
                        return None
                    previous = chunk[-1:]
                return "JPG end missing (file cut short)"
    except OSError as e:
        return f"cannot read ({e.__class__.__name__})"
    if ext == ".pdf":
        if b"%PDF" not in head[:1024]:
            return "PDF header missing"
        if b"%%EOF" not in tail:
            return "PDF end missing (file cut short)"
    elif ext == ".png" and not head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG header wrong"
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
def walk(top, errors, skip, notes):
    out = []
    stack = [top]
    while stack:
        d = stack.pop()
        if d != top and os.path.lexists(os.path.join(d, LOG_NAME)):  # an earlier quarantine
            notes["off_limits"] += 1
            continue
        try:
            it = os.scandir(d)
        except OSError as e:
            errors.append([d, str(e)])
            continue
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    if is_link(st):
                        notes["links"] += 1
                    elif stat.S_ISDIR(st.st_mode):
                        if OFF_LIMITS.match(e.name.lower()):
                            notes["off_limits"] += 1
                        elif not is_under(e.path, skip):
                            stack.append(e.path)
                    elif stat.S_ISREG(st.st_mode):
                        if is_online_only(st):
                            notes["online_only"] += 1
                        else:
                            out.append((e.path, st.st_size))
                except OSError as ex:
                    errors.append([e.path, str(ex)])
    return out


def make_group(size, digest, paths, guard):
    """One group per content. Hard links to the same data count once: removing one frees nothing."""
    first, places, removable = {}, {}, 0
    for p in sorted(paths):
        try:
            st = os.lstat(p)
        except OSError:
            continue
        place = guard.place(p)
        key = (st.st_dev, st.st_ino) if st.st_nlink > 1 and st.st_ino else p
        if place == "off-limits" or key in first:
            continue
        first[key] = p
        places[p] = place
        removable += place == "normal" and st.st_nlink <= 1
    if len(first) < 2:
        return None
    one_must_stay = removable == len(first)
    return {"size": size, "sha256": digest, "waste": size * (removable - one_must_stay),
            "paths": sorted(first.values()), "tags": sorted(set(places.values()))}


def scan(folder, protect=(), workers=8, skip=(), quiet=False):
    root = os.path.abspath(folder)
    if not os.path.isdir(root):
        raise SystemExit(f"Not a folder: {folder}")
    guard = Guard(root, protect)
    skip_n = [norm(p) for p in skip]
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    t0 = time.time()
    errors = []
    label = guard.place(os.path.join(root, "x"))
    if label != "normal":
        say(f"Note: this folder is {label}, so nothing in it will be offered for removal.")
    notes = {"links": 0, "online_only": 0, "off_limits": 0}
    files = walk(root, errors, skip_n, notes)
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
                corrupt.append({"path": p, "size": s, "reason": reason, "tag": guard.place(p)})

    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(check, todo, chunksize=64))
    say(f"Health check: {len(corrupt)} suspect files")

    # A damaged file is never offered for removal, so it takes no part in the duplicate search.
    damaged = {c["path"] for c in corrupt}
    by_size = defaultdict(list)
    for p, s in files:
        if s > 0 and p not in damaged:
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
                    group = make_group(s, digest, dup, guard)
                    if group:
                        groups.append(group)
    groups.sort(key=lambda g: -g["waste"])
    say(f"Duplicates: {len(groups)} groups, {human(sum(g['waste'] for g in groups))} could be freed")
    corrupt.sort(key=lambda c: c["path"])
    return {
        "tool": "file-cleaner", "version": VERSION, "root": root,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "seconds": round(time.time() - t0, 1),
        "protect": [os.path.abspath(p) for p in protect],
        "files": len(files), "bytes": total, "not_read": notes,
        "dup_groups": groups, "corrupt": corrupt, "empty": sorted(empty), "errors": errors,
    }


def summary_text(r, limit=30):
    waste = sum(g["waste"] for g in r["dup_groups"])
    lines = [
        f"file-cleaner report for {show(r['root'])}",
        f"Created {r['created']} in {r['seconds']}s",
        "",
        f"Files checked     : {r['files']} ({human(r['bytes'])})",
        f"Duplicate groups  : {len(r['dup_groups'])} (about {human(waste)} could be freed)",
        f"Suspect files     : {len(r['corrupt'])} (damaged or cut short, see below)",
        f"Empty files       : {len(r['empty'])}",
        f"Could not read    : {len(r['errors'])}",
        "Left alone        : {links} links, {online_only} online-only files, {off_limits} system, bin or code folders"
        .format(**r["not_read"]),
        "",
        f"Biggest duplicate groups (top {limit}):",
    ]
    for g in r["dup_groups"][:limit]:
        lines.append(f"  {human(g['size'])} x {len(g['paths'])} copies" + ("  [has protected copy]" if "protected" in g["tags"] else ""))
        for p in g["paths"]:
            lines.append(f"      {show(p)}")
    lines += ["", "Suspect files (never deleted by this tool, check them by hand):"]
    for c in r["corrupt"][: limit * 4]:
        lines.append(f"  {c['reason']:<50}  {show(c['path'])}")
    if len(r["corrupt"]) > limit * 4:
        lines.append(f"  ... and {len(r['corrupt']) - limit * 4} more in the JSON report")
    lines += ["", "Next step: python file_cleaner.py delete --report <report.json>   (dry run first)"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- delete
def pick_keeper(paths, guard, rule):
    """Choose the copy to keep. Protected wins, then a project copy, because those are never removed."""
    existing = [p for p in paths if why_not(p, guard) is None]
    if not existing:
        return None
    if rule == "newest":
        key = lambda p: (-os.path.getmtime(p), len(p), p)  # noqa: E731
    elif rule == "oldest":
        key = lambda p: (os.path.getmtime(p), len(p), p)  # noqa: E731
    else:  # shortest path, then alphabetical
        key = lambda p: (len(p), p)  # noqa: E731
    places = {p: guard.place(p) for p in existing}
    for wanted in ("protected", "project"):
        best = [p for p in existing if places[p] == wanted]
        if best:
            return sorted(best, key=key)[0]
    return sorted(existing, key=key)[0]


def reason_to_skip(p, keeper, guard, damaged):
    """Every check that must pass right before a copy is removed. Returns a reason, or None to go on."""
    if p in damaged or keeper in damaged:
        return "looks damaged, check it by hand"
    why = why_not(p, guard)
    if why:
        return why
    if why_not(keeper, guard):
        return "kept copy changed or disappeared"
    place = guard.place(p)
    if place == "protected":
        return "protected"
    if place == "project":
        return "inside a Git project"
    try:
        if os.path.samefile(p, keeper):
            return "same file (hard link)"
        if os.lstat(p).st_nlink > 1:
            return "has hard links (removing it may free nothing)"
        before = fingerprint(p), fingerprint(keeper)
        if not same_bytes(p, keeper):
            return "content changed since the scan"
        if (fingerprint(p), fingerprint(keeper)) != before:
            return "changed while it was being checked"
    except OSError:
        return "cannot read"
    return None


def delete(report_path, apply=False, hard=False, quarantine=None, protect=(), keep="shortest", quiet=False):
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    with open(report_path, encoding="utf-8") as f:
        r = json.load(f)
    if not isinstance(r, dict) or r.get("tool") != "file-cleaner":
        raise SystemExit("This file is not a file-cleaner report.")
    root = r["root"]
    if not os.path.isdir(root):
        raise SystemExit(f"The scanned folder is not there any more: {show(root)}")
    guard = Guard(root, list(r.get("protect", [])) + list(protect))
    damaged = {c["path"] for c in r.get("corrupt", [])}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    here = os.path.dirname(os.path.abspath(report_path))
    quarantine = os.path.abspath(quarantine or os.path.join(here, f"file-cleaner-quarantine-{stamp}"))
    if apply and not hard and is_under(real(quarantine), [guard.root]):
        raise SystemExit("The quarantine folder must be outside the scanned folder. Use --quarantine to pick one.")

    mode = "DRY RUN (nothing changes)" if not apply else ("HARD DELETE" if hard else f"MOVE TO QUARANTINE {show(quarantine)}")
    say(f"Mode: {mode}")
    log, freed = [], 0
    counts, reasons = defaultdict(int), defaultdict(int)
    log_path, log_file = None, None
    if apply:
        # The log is written line by line as the run goes, so a crash cannot lose it.
        if not hard:
            os.makedirs(quarantine, exist_ok=True)
        log_path = os.path.join(here, f"file-cleaner-deleted-{stamp}.jsonl") if hard else os.path.join(quarantine, LOG_NAME)
        log_file = open(log_path, "a", encoding="utf-8")

    def write(entry, keep_it=True):
        if keep_it:
            log.append(entry)
        if log_file:
            log_file.write(json.dumps(entry) + "\n")
            log_file.flush()

    try:
        write({"run": stamp, "root": root, "report": os.path.abspath(report_path),
               "mode": "hard" if hard else "quarantine"}, keep_it=False)
        for g in r["dup_groups"]:
            keeper = pick_keeper(g["paths"], guard, keep)
            if keeper is None:
                for p in g["paths"]:
                    write({"path": p, "action": "skipped", "why": "no copy left to keep"})
                counts["skipped"] += len(g["paths"])
                reasons["no copy left to keep"] += len(g["paths"])
                continue
            for p in g["paths"]:
                if p == keeper:
                    continue
                why = reason_to_skip(p, keeper, guard, damaged)
                if why:
                    write({"path": p, "keep": keeper, "action": "skipped", "why": why})
                    counts["skipped"] += 1
                    reasons[why] += 1
                    continue
                size = os.path.getsize(p)
                if not apply:
                    write({"path": p, "keep": keeper, "action": "would remove", "size": size})
                    counts["would remove"] += 1
                    freed += size
                    say(f"  would remove {show(p)}\n        keeps {show(keeper)}")
                    continue
                try:
                    if hard:
                        write({"path": p, "keep": keeper, "action": "deleting", "size": size}, keep_it=False)
                        os.remove(p)
                        entry = {"path": p, "keep": keeper, "action": "deleted", "size": size}
                    else:
                        dst = os.path.join(quarantine, os.path.relpath(os.path.realpath(p), os.path.realpath(root)))
                        base, ext = os.path.splitext(dst)
                        n = 2
                        while os.path.lexists(dst):
                            dst, n = f"{base} ({n}){ext}", n + 1
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        write({"path": p, "keep": keeper, "action": "moving", "to": dst, "size": size}, keep_it=False)
                        move_file(p, dst)
                        entry = {"path": p, "keep": keeper, "action": "moved", "to": dst, "size": size}
                    write(entry)
                    counts[entry["action"]] += 1
                    freed += size
                except OSError as e:
                    write({"path": p, "keep": keeper, "action": "failed", "why": str(e)})
                    counts["failed"] += 1
            # Safety net: the keeper must still be there.
            if apply and not os.path.isfile(keeper):
                write({"path": keeper, "action": "ERROR", "why": "kept copy missing after run"})
                counts["ERROR"] += 1
    finally:
        if log_file:
            log_file.close()

    say("")
    say("Result: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing to do") + f" | space: {human(freed)}")
    for why, n in sorted(reasons.items()):
        say(f"  skipped {n}: {why}")
    if log_path:
        say(f"Log: {show(log_path)}")
    if apply and not hard and counts.get("moved"):
        say(f'Undo: python file_cleaner.py restore --from "{show(quarantine)}" --apply')
    if not apply:
        say("Nothing was changed. Add --apply to move these files to a quarantine folder.")
    return {"counts": dict(counts), "freed": freed, "log": log, "log_path": log_path, "quarantine": None if hard else quarantine}


# ---------------------------------------------------------------- restore
def restore(folder, apply=False, quiet=False):
    """Put quarantined files back where they were. Never overwrites, never writes outside the scanned folder."""
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    log_path = folder if os.path.isfile(folder) else os.path.join(folder, LOG_NAME)
    if not os.path.isfile(log_path):
        raise SystemExit(f"No {LOG_NAME} found in {show(folder)}. Is this a file-cleaner quarantine folder?")
    home = real(os.path.dirname(os.path.abspath(log_path)))
    moves, root = {}, None
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue  # a line cut short by a crash
            if not isinstance(e, dict):
                continue
            if "run" in e:
                root = e.get("root")
            elif root and e.get("action") in ("moving", "moved") and e.get("to") and e.get("path"):
                moves[e["to"]] = (e["path"], root)
    say("Mode: " + ("RESTORE" if apply else "DRY RUN (nothing changes)"))
    counts, reasons = defaultdict(int), defaultdict(int)
    for to, (path, top) in moves.items():
        why = None
        if not os.path.lexists(to):
            why = "not in the quarantine folder (already restored or never moved)"
        elif not is_under(real(os.path.dirname(os.path.abspath(to))), [home]) or is_link(os.lstat(to)) or not os.path.isfile(to):
            why = "the log points outside the quarantine folder"
        elif not is_under(real(os.path.dirname(os.path.abspath(path))), [real(top)]):
            why = "the original place is outside the scanned folder"
        elif os.path.lexists(path):
            why = "a file is already there"
        if why:
            counts["skipped"] += 1
            reasons[why] += 1
            continue
        if not apply:
            counts["would restore"] += 1
            say(f"  would restore {show(path)}")
            continue
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            move_file(to, path)
            counts["restored"] += 1
        except OSError as e:
            counts["failed"] += 1
            say(f"  failed {show(path)}: {e}")
    say("Result: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing to do"))
    for why, n in sorted(reasons.items()):
        say(f"  skipped {n}: {why}")
    return {"counts": dict(counts)}


def check_output(path, kind):
    """Refuse to write over a file this tool did not make."""
    if not os.path.lexists(path):
        return
    try:
        with open(path, "rb") as f:
            head = f.read(200)
    except OSError:
        head = b""
    mark = b'"tool": "file-cleaner"' if kind == "report" else b"file-cleaner report for"
    if mark not in head:
        raise SystemExit(f"{show(path)} exists and is not a file-cleaner {kind}. Nothing was written. Pick another name.")


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

    u = sub.add_parser("restore", help="put quarantined files back (dry run unless --apply)")
    u.add_argument("--from", dest="source", required=True, metavar="DIR", help="the quarantine folder")
    u.add_argument("--apply", action="store_true", help="actually move the files back")

    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # a file name the console cannot print must not stop a run
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    if a.cmd == "restore":
        return 1 if restore(a.source, apply=a.apply)["counts"].get("failed") else 0
    for p in a.protect + getattr(a, "skip", []):
        if not os.path.lexists(p):
            ap.error(f"this path does not exist, check the spelling: {p}")
    if a.cmd == "scan":
        summ = a.summary or os.path.splitext(a.report)[0] + ".txt"
        if norm(summ) == norm(a.report):
            ap.error("the report and the summary need different names")
        check_output(a.report, "report")
        check_output(summ, "summary")
        r = scan(a.folder, protect=a.protect, workers=max(1, a.workers), skip=a.skip)
        if is_under(a.report, [norm(r["root"])]):
            print("Note: the report is saved inside the scanned folder.")
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=1)
        with open(summ, "w", encoding="utf-8", errors="backslashreplace") as f:
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
