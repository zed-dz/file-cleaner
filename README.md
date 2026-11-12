# file-cleaner

Find duplicate files and damaged files in a folder, then remove the duplicates safely.

- **Duplicates** are found by content, not by name. Two files count as copies only if every byte matches.
- **Damaged files** are files that look normal but will not open: files filled with zero bytes after a bad sync, PDFs and JPGs cut short, Office and ZIP files that cannot be read, wrong file headers.
- The scan only reads. Removing duplicates is a separate step, a dry run by default, and moves files to a quarantine folder instead of deleting them.

## Who it is for

Anyone with a drive full of copies from years of downloads, backups and cloud sync, who wants space back without the risk of losing the only copy of something.

## Requirements

- Python 3.8 or newer. Nothing else: it uses only the Python standard library.
- Works on Windows, macOS and Linux.

## Download

[Download the ZIP](https://github.com/zed-dz/file-cleaner/archive/refs/heads/main.zip) and unzip it.

## How to use

### 1. Scan (read-only)

```
python file_cleaner.py scan "D:\Photos"
```

This writes two files in the current folder:

- `file-cleaner-report.json`: the full result, used by the delete step.
- `file-cleaner-report.txt`: a readable summary with the biggest duplicate groups and every damaged file.

Options:

```
python file_cleaner.py scan "D:\Photos" --report photos.json
python file_cleaner.py scan "D:\Photos" --protect "D:\Photos\Originals"
python file_cleaner.py scan "D:\Photos" --skip "D:\Photos\cache"
```

- `--protect PATH` scans a folder but never removes anything from it. A protected copy is always the one kept. Repeat it for several folders.
- `--skip PATH` does not scan a folder at all.
- `--workers N` sets how many files are read at the same time (default 8).

Files inside `.git` folders are never offered for removal.

### 2. Dry run (still changes nothing)

```
python file_cleaner.py delete --report file-cleaner-report.json
```

It lists every copy it would remove and the copy it would keep.

### 3. Remove duplicates

```
python file_cleaner.py delete --report file-cleaner-report.json --apply
```

Each removed copy is moved to a quarantine folder next to the report (`file-cleaner-quarantine-<date>`), keeping its folder structure. A JSON log of every move is saved in the same folder.

Options:

- `--quarantine DIR` picks the quarantine folder. It must be outside the scanned folder.
- `--keep shortest|oldest|newest` picks which copy to keep (default: the shortest path).
- `--protect PATH` adds more folders that are never touched.
- `--hard` deletes for good instead of moving to quarantine. Only works together with `--apply`.

## Safety notes

- **The scan never changes a file.** It writes only the report and the summary.
- **Delete is a dry run** unless you add `--apply`.
- **Never the last copy.** In every group one copy is kept, and the tool checks it still exists after the run.
- **Checked again right before acting.** Each copy is compared byte for byte with the kept copy just before it is moved. If a file changed since the scan, or the kept copy is gone, it is skipped.
- **Damaged files are only reported, never removed.** Check them by hand: a file full of zero bytes has lost its content, and the only fix is an older backup or the cloud copy.
- Hard links to the same file are skipped.
- Empty files are listed in the report but not removed.

## How to undo

Quarantined files are still on disk. To restore them, move them back from the quarantine folder. The folder keeps the original structure relative to the scanned folder, and the log file lists each file's original path. When you are sure, delete the quarantine folder.

Files removed with `--hard` cannot be restored by this tool.

## How it works

1. Files are grouped by exact size. A file with a unique size cannot have a copy, so it is never hashed.
2. Files that share a size get a quick SHA-256 hash of their first 64 KB.
3. Files that still match get a full SHA-256 hash. Same hash means same content.
4. Each checked file type (PDF, JPG, PNG, GIF, WEBP, MP4/MOV, ZIP, DOCX, XLSX, PPTX and common text files) is checked at its start and its end.

## Tests

```
python -m unittest discover -s tests -v
```

## Licence

MIT. See [LICENSE](LICENSE).

---

Made by Amine Hammou. Custom tools: https://aminehammou.vercel.app/tools.html
