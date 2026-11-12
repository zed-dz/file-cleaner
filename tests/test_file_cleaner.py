"""Run: python -m unittest discover -s tests -v"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "file_cleaner.py")
sys.path.insert(0, os.path.dirname(HERE))
import file_cleaner as fc  # noqa: E402


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class FileCleanerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fc-test-")
        self.data = os.path.join(self.tmp, "data")
        big = os.urandom(200_000)  # larger than the partial-hash window
        small = b"hello duplicate world\n" * 10
        write(os.path.join(self.data, "photos", "trip.bin"), big)
        write(os.path.join(self.data, "backup", "trip.bin"), big)
        write(os.path.join(self.data, "backup", "old", "trip copy.bin"), big)
        write(os.path.join(self.data, "notes.txt"), small)
        write(os.path.join(self.data, "docs", "notes (1).txt"), small)
        write(os.path.join(self.data, "keep", "notes.txt"), small)  # will be protected
        write(os.path.join(self.data, "unique.txt"), b"only one of me")
        write(os.path.join(self.data, "broken.pdf"), b"\0" * 8192)  # zero-filled
        write(os.path.join(self.data, "cut.jpg"), b"\xff\xd8\xff\xe0" + os.urandom(5000))  # no end marker
        write(os.path.join(self.data, "good.jpg"), b"\xff\xd8\xff\xe0" + b"x" * 500 + b"\xff\xd9")
        self.report = os.path.join(self.tmp, "report.json")
        self.quar = os.path.join(self.tmp, "quarantine")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        p = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p.stdout

    def scan(self, *extra):
        self.run_cli("scan", self.data, "--report", self.report, *extra)
        with open(self.report, encoding="utf-8") as f:
            return json.load(f)

    def test_scan_finds_duplicates_and_corrupt_files(self):
        r = self.scan()
        sizes = sorted(len(g["paths"]) for g in r["dup_groups"])
        self.assertEqual(sizes, [3, 3])
        reasons = {os.path.basename(c["path"]): c["reason"] for c in r["corrupt"]}
        self.assertIn("broken.pdf", reasons)
        self.assertIn("zero bytes", reasons["broken.pdf"])
        self.assertIn("cut.jpg", reasons)
        self.assertIn("cut short", reasons["cut.jpg"])
        self.assertNotIn("good.jpg", reasons)
        self.assertTrue(os.path.isfile(os.path.splitext(self.report)[0] + ".txt"))

    def test_dry_run_changes_nothing(self):
        self.scan()
        before = sorted(os.path.join(d, f) for d, _, fs in os.walk(self.data) for f in fs)
        out = self.run_cli("delete", "--report", self.report)
        after = sorted(os.path.join(d, f) for d, _, fs in os.walk(self.data) for f in fs)
        self.assertEqual(before, after)
        self.assertIn("would remove 4", out)

    def test_delete_keeps_one_copy_and_quarantines_the_rest(self):
        self.scan("--protect", os.path.join(self.data, "keep"))
        # Change one duplicate after the scan: the re-check must refuse to remove it.
        changed = os.path.join(self.data, "docs", "notes (1).txt")
        write(changed, b"edited after the scan")
        self.run_cli("delete", "--report", self.report, "--apply", "--quarantine", self.quar)

        trips = [p for p in ("photos/trip.bin", "backup/trip.bin", "backup/old/trip copy.bin")
                 if os.path.isfile(os.path.join(self.data, p))]
        self.assertEqual(len(trips), 1, trips)
        # Protected copy is the keeper; the other unchanged copy went to quarantine.
        self.assertTrue(os.path.isfile(os.path.join(self.data, "keep", "notes.txt")))
        self.assertFalse(os.path.isfile(os.path.join(self.data, "notes.txt")))
        self.assertTrue(os.path.isfile(os.path.join(self.quar, "notes.txt")))
        self.assertTrue(os.path.isfile(changed), "file edited after the scan must not be removed")
        # Corrupt and unique files are never touched by delete.
        for name in ("broken.pdf", "cut.jpg", "unique.txt"):
            self.assertTrue(os.path.isfile(os.path.join(self.data, name)), name)
        moved = [f for _, _, fs in os.walk(self.quar) for f in fs if not f.startswith("file-cleaner-log")]
        self.assertEqual(len(moved), 3, moved)

    def test_hard_delete_never_removes_last_copy(self):
        self.scan()
        # Remove two of three copies by hand; the last one must survive --hard.
        os.remove(os.path.join(self.data, "photos", "trip.bin"))
        os.remove(os.path.join(self.data, "backup", "trip.bin"))
        res = fc.delete(self.report, apply=True, hard=True, quiet=True)
        self.assertTrue(os.path.isfile(os.path.join(self.data, "backup", "old", "trip copy.bin")))
        self.assertEqual(res["counts"].get("ERROR", 0), 0)


if __name__ == "__main__":
    unittest.main()
