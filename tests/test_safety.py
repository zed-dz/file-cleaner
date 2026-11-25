"""Tests that try to make file-cleaner lose a file. Run: python -m unittest discover -s tests -v"""
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "file_cleaner.py")
sys.path.insert(0, os.path.dirname(HERE))
import file_cleaner as fc  # noqa: E402


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def snapshot(folder):
    """Every path with its content, size, time and mode: proof that nothing changed."""
    out = {}
    for d, dirs, files in os.walk(folder):
        for n in dirs + files:
            p = os.path.join(d, n)
            st = os.lstat(p)
            body = None
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    body = hashlib.sha256(f.read()).hexdigest()
            out[os.path.relpath(p, folder)] = (body, st.st_size, st.st_mtime_ns if body else None, st.st_mode)
    return out


def make_dir_link(link, target):
    """A folder link: a junction on Windows (needs no rights), a symbolic link elsewhere."""
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(target, link)
    else:
        os.symlink(target, link, target_is_directory=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fc-safe-")
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.data)
        self.report = os.path.join(self.tmp, "report.json")
        self.quar = os.path.join(self.tmp, "held")
        self.body = os.urandom(150_000)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.data, *parts)

    def put(self, *parts, body=None):
        return write(self.p(*parts), self.body if body is None else body)

    def scan(self, **kw):
        r = fc.scan(self.data, quiet=True, **kw)
        with open(self.report, "w", encoding="utf-8") as f:
            json.dump(r, f)
        return r

    def delete(self, **kw):
        kw.setdefault("apply", True)
        if not kw.get("hard"):
            kw.setdefault("quarantine", self.quar)
        return fc.delete(self.report, quiet=True, **kw)

    def whys(self, res):
        return {os.path.relpath(e["path"], self.data).replace(os.sep, "/"): e.get("why") for e in res["log"]
                if e["action"] == "skipped"}


class DryRun(Base):
    def test_scan_and_dry_run_change_nothing(self):
        for n in ("a.bin", "x/b.bin", "x/y/c.bin"):
            self.put(*n.split("/"))
        self.put("cut.jpg", body=b"\xff\xd8\xff" + b"z" * 9000)
        before = snapshot(self.data)
        self.scan()
        res = self.delete(apply=False)
        self.assertEqual(res["counts"], {"would remove": 2})
        self.assertEqual(snapshot(self.data), before)
        self.assertFalse(os.path.exists(self.quar))
        self.assertEqual(sorted(os.listdir(self.tmp)), ["data", "report.json"])

    def test_dry_run_never_calls_a_function_that_changes_files(self):
        self.put("a.bin")
        self.put("b.bin")
        self.scan()
        boom = mock.Mock(side_effect=AssertionError("a dry run tried to change the disk"))
        with mock.patch.multiple(os, remove=boom, unlink=boom, rename=boom, replace=boom, makedirs=boom, mkdir=boom), \
                mock.patch.multiple(shutil, move=boom, copy2=boom, rmtree=boom):
            self.delete(apply=False)

    def test_hard_without_apply_is_refused(self):
        self.put("a.bin")
        self.scan()
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            fc.main(["delete", "--report", self.report, "--hard"])


class ReCheck(Base):
    def test_same_size_edit_after_scan_is_kept(self):
        a, b = self.put("a.bin"), self.put("sub", "b.bin")
        self.scan()
        changed = bytes([self.body[0] ^ 1]) + self.body[1:]
        write(b, changed)
        res = self.delete(hard=True)
        self.assertEqual(self.whys(res), {"sub/b.bin": "content changed since the scan"})
        self.assertTrue(os.path.isfile(a) and os.path.isfile(b))

    def test_edit_during_the_check_is_kept(self):
        self.put("a.bin")
        b = self.put("sub", "b.bin")
        self.scan()
        real_same = fc.same_bytes

        def slow(x, y):
            ok = real_same(x, y)
            write(b, self.body + b"new")  # somebody saves the file right after it was compared
            return ok
        with mock.patch.object(fc, "same_bytes", slow):
            res = self.delete(hard=True)
        self.assertEqual(self.whys(res), {"sub/b.bin": "changed while it was being checked"})
        self.assertTrue(os.path.isfile(b))

    def test_one_copy_always_survives_every_rule(self):
        for rule in ("shortest", "oldest", "newest"):
            with self.subTest(rule=rule):
                for n in ("a.bin", "s/b.bin", "s/t/c.bin"):
                    self.put(*n.split("/"))
                self.scan()
                self.delete(hard=True, keep=rule)
                left = [f for _, _, fs in os.walk(self.data) for f in fs]
                self.assertEqual(len(left), 1)

    def test_keeper_swapped_for_other_content(self):
        a, b = self.put("a.bin"), self.put("sub", "b.bin")
        self.scan()
        write(a, b"gone")
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(b))

    def test_damaged_twins_are_never_removed(self):
        cut = b"\xff\xd8\xff" + b"z" * 9000
        a, b = self.put("a.jpg", body=cut), self.put("sub", "a.jpg", body=cut)
        zero_a, zero_b = self.put("1.pdf", body=b"\0" * 9000), self.put("2.pdf", body=b"\0" * 9000)
        r = self.scan()
        self.assertEqual(r["dup_groups"], [])
        self.delete(hard=True)
        for p in (a, b, zero_a, zero_b):
            self.assertTrue(os.path.isfile(p))

    def test_old_report_that_lists_damaged_twins(self):
        cut = b"\xff\xd8\xff" + b"z" * 9000
        a, b = self.put("a.jpg", body=cut), self.put("sub", "a.jpg", body=cut)
        r = self.scan()
        r["dup_groups"] = [{"size": len(cut), "sha256": "x", "waste": 1, "paths": [a, b], "tags": ["normal"]}]
        with open(self.report, "w", encoding="utf-8") as f:
            json.dump(r, f)
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(a) and os.path.isfile(b))


class Links(Base):
    def test_hard_links_are_not_duplicates_and_stay(self):
        a = self.put("a.bin")
        os.link(a, self.p("b.bin"))
        r = self.scan()
        self.assertEqual(r["dup_groups"], [])
        c = self.put("sub", "c.bin")  # a true copy of the hard-linked pair
        r = self.scan()
        self.assertEqual(r["dup_groups"][0]["waste"], len(self.body))
        self.delete(hard=True)
        self.assertTrue(os.path.samefile(a, self.p("b.bin")))
        self.assertFalse(os.path.exists(c))

    def test_hard_linked_after_the_scan(self):
        a, b = self.put("a.bin"), self.put("sub", "b.bin")
        self.scan()
        os.link(b, os.path.join(self.tmp, "elsewhere.bin"))
        res = self.delete(hard=True)
        self.assertEqual(self.whys(res), {"sub/b.bin": "has hard links (removing it may free nothing)"})
        self.assertTrue(os.path.isfile(a) and os.path.isfile(b))

    def test_folder_link_is_not_followed(self):
        outside = os.path.join(self.tmp, "outside")
        write(os.path.join(outside, "only.bin"), self.body)
        self.put("only.bin")
        make_dir_link(self.p("link"), outside)
        make_dir_link(self.p("loop"), self.data)
        r = self.scan()
        self.assertEqual((r["files"], r["dup_groups"], r["not_read"]["links"]), (1, [], 2))
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(os.path.join(outside, "only.bin")))

    def test_folder_swapped_for_a_link_after_the_scan(self):
        self.put("a.bin")
        self.put("sub", "b.bin")
        self.scan()
        outside = os.path.join(self.tmp, "outside")
        os.rename(self.p("sub"), outside)
        make_dir_link(self.p("sub"), outside)
        res = self.delete(hard=True)
        self.assertEqual(self.whys(res), {"sub/b.bin": "leads outside the scanned folder"})
        self.assertTrue(os.path.isfile(os.path.join(outside, "b.bin")))

    def test_file_swapped_for_a_symlink(self):
        a, b = self.put("a.bin"), self.put("sub", "b.bin")
        self.scan()
        os.remove(a)
        try:
            os.symlink(b, a)
        except OSError:
            self.skipTest("no right to make symbolic links here")
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(b) and os.path.islink(a))

    def test_protect_through_a_folder_link(self):
        self.put("a.bin")
        b = self.put("sub", "deeper", "b.bin")
        make_dir_link(os.path.join(self.tmp, "alias"), self.p("sub"))
        self.scan(protect=[os.path.join(self.tmp, "alias")])
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(b))
        self.assertFalse(os.path.isfile(self.p("a.bin")))  # the protected copy is the one kept


class Places(Base):
    def test_bin_and_quarantine_copies_are_never_the_kept_copy(self):
        for bad in ("$RECYCLE.BIN", ".Trash-1000", "file-cleaner-quarantine-20260101-000000", "node_modules"):
            with self.subTest(folder=bad):
                self.put(bad, "a.bin")
                mine = self.put("my", "long", "folder", "name", "a.bin")
                r = self.scan()
                self.assertEqual(r["dup_groups"], [])
                self.delete(hard=True)
                self.assertTrue(os.path.isfile(mine))

    def test_renamed_quarantine_is_still_recognised(self):
        self.put("held", "a.bin")
        write(self.p("held", fc.LOG_NAME), b"{}\n")
        mine = self.put("my", "folder", "a.bin")
        self.assertEqual(self.scan()["dup_groups"], [])
        self.assertTrue(os.path.isfile(mine))

    def test_git_projects_stay_whole(self):
        self.put("proj1", ".git", "HEAD", body=b"x")
        self.put("proj2", ".git", body=b"gitdir: elsewhere")  # a worktree has a .git file
        one, two = self.put("proj1", "src", "a.bin"), self.put("proj2", "a.bin")
        loose = self.put("a.bin")
        self.scan()
        self.delete(hard=True)
        self.assertTrue(os.path.isfile(one) and os.path.isfile(two))
        self.assertFalse(os.path.isfile(loose))  # the project copy is the one kept

    def test_system_folder(self):
        guard = fc.Guard(self.data)
        guard.temp = []
        guard.system = [fc.real(self.data)]
        self.assertEqual(guard.place(self.put("a.bin")), "off-limits")
        sysdirs = fc.system_dirs()
        self.assertTrue(sysdirs)
        self.assertEqual(fc.Guard(self.data).place(os.path.join(sysdirs[0], "x.dll")), "off-limits")

    def test_report_that_points_outside_the_scanned_folder(self):
        out = write(os.path.join(self.tmp, "outside", "a.bin"), self.body)
        mine = self.put("a.bin")
        r = self.scan()
        r["dup_groups"] = [{"size": 1, "sha256": "x", "waste": 1, "tags": [],
                            "paths": [mine, out, os.path.join(self.data, "..", "outside", "a.bin")]}]
        with open(self.report, "w", encoding="utf-8") as f:
            json.dump(r, f)
        res = self.delete(hard=True)
        self.assertEqual(set(res["counts"]), {"skipped"})
        self.assertTrue(os.path.isfile(out) and os.path.isfile(mine))

    def test_online_only_files_are_not_read(self):
        a = self.put("a.bin")

        class Fake:
            st_file_attributes = 0x400000
        self.assertTrue(fc.is_online_only(Fake))
        self.assertFalse(fc.is_online_only(os.lstat(a)))
        with mock.patch.object(fc, "is_online_only", lambda st: True):
            r = fc.scan(self.data, quiet=True)
        self.assertEqual((r["files"], r["not_read"]["online_only"]), (0, 1))

    def test_quarantine_inside_the_scanned_folder_is_refused(self):
        self.put("a.bin")
        self.put("b.bin")
        self.scan()
        with self.assertRaises(SystemExit):
            self.delete(quarantine=self.p("held"))
        make_dir_link(os.path.join(self.tmp, "sneaky"), self.data)
        with self.assertRaises(SystemExit):
            self.delete(quarantine=os.path.join(self.tmp, "sneaky", "held"))
        self.assertEqual(sorted(os.listdir(self.data)), ["a.bin", "b.bin"])


class Restore(Base):
    def fill(self):
        for n in ("a.bin", "s/a.bin", "s/t/a.bin", "s/t/\u0635\u0648\u0631\u0629.bin"):
            self.put(*n.split("/"))
        self.before = snapshot(self.data)
        self.scan()

    def test_round_trip_is_exact(self):
        self.fill()
        self.assertEqual(self.delete()["counts"], {"moved": 3})
        self.assertEqual(len([f for _, _, fs in os.walk(self.data) for f in fs]), 1)
        shutil.rmtree(self.p("s"))  # even the empty folders are gone
        self.assertEqual(fc.restore(self.quar, quiet=True)["counts"], {"would restore": 3})
        self.assertFalse(os.path.exists(self.p("s")))  # the restore dry run changed nothing
        self.assertEqual(fc.restore(self.quar, apply=True, quiet=True)["counts"], {"restored": 3})
        self.assertEqual({k: v[:3] for k, v in snapshot(self.data).items() if v[0]},
                         {k: v[:3] for k, v in self.before.items() if v[0]})
        self.assertEqual(fc.restore(self.quar, apply=True, quiet=True)["counts"], {"skipped": 3})

    def test_never_overwrites(self):
        self.fill()
        self.delete()
        newer = self.put("s", "a.bin", body=b"a newer file took the name")
        fc.restore(self.quar, apply=True, quiet=True)
        with open(newer, "rb") as f:
            self.assertEqual(f.read(), b"a newer file took the name")
        self.assertTrue(os.path.isfile(os.path.join(self.quar, "s", "a.bin")))

    def test_two_runs_into_one_quarantine(self):
        self.fill()
        self.delete()
        self.put("s", "a.bin")  # the same name comes back and is removed again
        self.scan()
        self.delete()
        self.assertTrue(os.path.isfile(os.path.join(self.quar, "s", "a (2).bin")))
        self.assertEqual(fc.restore(self.quar, apply=True, quiet=True)["counts"], {"restored": 3, "skipped": 1})

    def test_across_disks(self):
        self.fill()
        with mock.patch.object(os, "rename", side_effect=OSError(fc.errno.EXDEV, "other disk")):
            self.assertEqual(self.delete()["counts"], {"moved": 3})
            fc.restore(self.quar, apply=True, quiet=True)
        self.assertEqual({k: v[0] for k, v in snapshot(self.data).items()}, {k: v[0] for k, v in self.before.items()})

    def test_across_disks_bad_copy_keeps_the_original(self):
        self.fill()

        def bad_copy(src, dst):
            with open(dst, "wb") as f:
                f.write(b"half")
        with mock.patch.object(os, "rename", side_effect=OSError(fc.errno.EXDEV, "other disk")), \
                mock.patch.object(shutil, "copy2", bad_copy):
            self.assertEqual(self.delete()["counts"], {"failed": 3})
        self.assertEqual(snapshot(self.data), self.before)

    def test_crash_in_the_middle_can_be_undone(self):
        self.fill()
        calls, real_move = [], fc.move_file

        def crash(src, dst):
            real_move(src, dst)
            calls.append(src)
            if len(calls) == 2:
                raise KeyboardInterrupt
        with mock.patch.object(fc, "move_file", crash), self.assertRaises(KeyboardInterrupt):
            self.delete()
        with open(os.path.join(self.quar, fc.LOG_NAME), "a", encoding="utf-8") as f:
            f.write('{"path": "cut sh')  # a line cut short
        self.assertEqual(fc.restore(self.quar, apply=True, quiet=True)["counts"], {"restored": 2})
        self.assertEqual({k: v[0] for k, v in snapshot(self.data).items()}, {k: v[0] for k, v in self.before.items()})

    def test_tampered_log_cannot_write_elsewhere(self):
        self.fill()
        self.delete()
        target = os.path.join(self.tmp, "victim", "evil.bin")
        os.makedirs(os.path.dirname(target))
        secret = write(os.path.join(self.tmp, "secret.bin"), b"s")
        with open(os.path.join(self.quar, fc.LOG_NAME), "a", encoding="utf-8") as f:
            f.write(json.dumps({"action": "moved", "to": os.path.join(self.quar, "s", "a.bin"), "path": target}) + "\n")
            f.write(json.dumps({"action": "moved", "to": secret, "path": self.p("stolen.bin")}) + "\n")
        res = fc.restore(self.quar, apply=True, quiet=True)
        self.assertEqual(res["counts"], {"restored": 2, "skipped": 2})
        self.assertFalse(os.path.exists(target) or os.path.exists(self.p("stolen.bin")))
        self.assertTrue(os.path.isfile(secret))


class Output(Base):
    def test_report_never_overwrites_your_file(self):
        mine = write(os.path.join(self.tmp, "mine.json"), b"{}")
        notes = write(os.path.join(self.tmp, "r.txt"), b"my notes")
        for rep in (mine, os.path.join(self.tmp, "r.json")):
            with self.assertRaises(SystemExit):
                fc.main(["scan", self.data, "--report", rep])
        with open(mine, "rb") as a, open(notes, "rb") as b:
            self.assertEqual((a.read(), b.read()), (b"{}", b"my notes"))

    def test_misspelled_protect_is_an_error(self):
        for cmd in (["scan", self.data, "--report", self.report], ["delete", "--report", self.report]):
            with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
                fc.main(cmd + ["--protect", self.p("nope")])

    def test_names_the_console_cannot_print(self):
        self.put("a.bin")
        self.put("s", "\u0635\u0648\u0631\u0629 \u202e.bin")
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        for args in (["scan", self.data, "--report", self.report], ["delete", "--report", self.report],
                     ["delete", "--report", self.report, "--apply", "--quarantine", self.quar],
                     ["restore", "--from", self.quar, "--apply"]):
            p = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True, env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn("\u202e", p.stdout)
        self.assertEqual(len([f for _, _, fs in os.walk(self.data) for f in fs]), 2)

    def test_control_characters_are_escaped(self):
        self.assertEqual(fc.show("a\x1b[2Jb\u202ec"), "a\\x1b[2Jb\\u202ec")

    def test_cli_prints_the_undo_command(self):
        self.put("a.bin")
        self.put("b.bin")
        self.scan()
        out = io.StringIO()
        with redirect_stdout(out):
            fc.delete(self.report, apply=True, quarantine=self.quar)
        self.assertIn("restore --from", out.getvalue())


if __name__ == "__main__":
    unittest.main()
