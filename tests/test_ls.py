#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

import contextlib
import io
import locale
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from rdflib import XSD, Literal

from pyaff4.cli import ls

FIXTURES = Path(__file__).resolve().parent.parent / "reference_images"
LOGICAL_DREAM = FIXTURES / "AFF4-L" / "deprecated" / "dream.aff4"
PHYSICAL = FIXTURES / "AFF4Std" / "Base-Linear.aff4"

VOLUME = "aff4://3a5b3e4c-1f6e-4a39-9d0c-6b1d1c2f0a11"

# A folder tree as some other AFF4-L tools write it: folders linked by aff4:child, paths in
# aff4:originalPathName.
FOLDER_TREE_TURTLE = f"""
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<{VOLUME}/1> a aff4:Folder ;
    aff4:originalPathName "/" ; aff4:fileName "" ; aff4:fileMode "16877"^^xsd:long ;
    aff4:child <{VOLUME}/2>, <{VOLUME}/3>, <{VOLUME}/4> .
<{VOLUME}/2> a aff4:Folder ;
    aff4:originalPathName "/Users" ; aff4:fileName "Users" ;
    aff4:fileMode "16877"^^xsd:long ; aff4:size "128"^^xsd:long ;
    aff4:lastWritten "2026-09-25T02:06:56.5Z"^^xsd:dateTime ;
    aff4:child <{VOLUME}/5>, <{VOLUME}/6> .
<{VOLUME}/3> a aff4:FileImage, aff4:Image ;
    aff4:originalPathName "/etc" ; aff4:fileName "etc" ;
    aff4:fileMode "41453"^^xsd:long ; aff4:size "11"^^xsd:long ;
    aff4:lastWritten "2026-09-20T23:49:45Z"^^xsd:dateTime ;
    aff4:symlinkTarget "private/etc" .
<{VOLUME}/4> a aff4:FileImage, aff4:Image ;
    aff4:originalPathName "/.hidden" ; aff4:fileName ".hidden" ;
    aff4:fileMode "33188"^^xsd:long ; aff4:size "0"^^xsd:long ;
    aff4:lastWritten "2026-09-20T23:49:45Z"^^xsd:dateTime .
<{VOLUME}/5> a aff4:FileImage, aff4:Image ;
    aff4:originalPathName "/Users/b.txt" ; aff4:fileName "b.txt" ;
    aff4:fileMode "33188"^^xsd:long ; aff4:size "13498"^^xsd:long ;
    aff4:lastWritten "2026-09-25T12:06:56+10:00"^^xsd:dateTime .
<{VOLUME}/6> a aff4:Folder ;
    aff4:originalPathName "/Users/a dir" ; aff4:fileName "a dir" ;
    aff4:fileMode "16877"^^xsd:long ; aff4:size "64"^^xsd:long ;
    aff4:lastWritten "2026-09-25T02:06:56Z"^^xsd:dateTime .
"""


def write_folder_tree_container(dest):
    with zipfile.ZipFile(dest, "w") as out:
        out.comment = VOLUME.encode()
        out.writestr("version.txt", "major=1\nminor=1\ntool=ExampleImager 1.0\n")
        out.writestr("container.description", VOLUME)
        out.writestr("information.turtle", FOLDER_TREE_TURTLE)


class TerminalStringIO(io.StringIO):
    def isatty(self):
        return True


def reread_time_zone():
    # macOS libc rereads TZ on every conversion, and some macOS Python builds lack tzset.
    if hasattr(time, "tzset"):
        time.tzset()


@contextlib.contextmanager
def time_zone(tz):
    try:
        with mock.patch.dict(os.environ, {"TZ": tz}):
            reread_time_zone()
            yield
    finally:
        reread_time_zone()


def run_ls_full(*argv, lc_all="C", tz="UTC", terminal_columns=None):
    """Run `aff4 ls` in the given locale and time zone; terminal_columns makes stdout a
    terminal that wide."""
    env = {"LC_ALL": lc_all}
    stdout, stderr = io.StringIO(), io.StringIO()
    if terminal_columns is not None:
        env["COLUMNS"] = str(terminal_columns)
        stdout = TerminalStringIO()
    previous = locale.setlocale(locale.LC_COLLATE)
    try:
        with (
            time_zone(tz),
            mock.patch.dict(os.environ, env),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = ls.main([str(a) for a in argv])
    finally:
        locale.setlocale(locale.LC_COLLATE, previous)
    return status, stdout.getvalue().split("\n")[:-1], stderr.getvalue()


def run_ls(*argv, **kwargs):
    """Exit status and stdout lines; stderr may carry unrelated GC ResourceWarnings."""
    status, lines, _ = run_ls_full(*argv, **kwargs)
    return status, lines


def available_locale(*names):
    previous = locale.setlocale(locale.LC_COLLATE)
    try:
        for name in names:
            try:
                locale.setlocale(locale.LC_COLLATE, name)
                return name
            except locale.Error:
                pass
        return None
    finally:
        locale.setlocale(locale.LC_COLLATE, previous)


ENGLISH_UTF8 = available_locale("en_AU.UTF-8", "en_US.UTF-8", "en_GB.UTF-8")


class FolderTreeLsTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.image = os.path.join(self.tmpdir, "folder-tree.aff4")
        write_folder_tree_container(self.image)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def testRootListsNamesSortedIncludingDotfiles(self):
        self.assertEqual((0, [".hidden", "Users", "etc"]), run_ls(self.image, "/"))

    @unittest.skipIf(ENGLISH_UTF8 is None, "no English UTF-8 locale installed")
    def testNamesSortByLocaleCollation(self):
        status, lines = run_ls(self.image, "/", lc_all=ENGLISH_UTF8)
        self.assertEqual(0, status)
        self.assertLess(lines.index("etc"), lines.index("Users"))

    def testTerminalGetsColumns(self):
        self.assertEqual((0, [".hidden Users   etc"]), run_ls(self.image, terminal_columns=80))

    def testTerminalTooNarrowGetsOneColumn(self):
        self.assertEqual((0, [".hidden", "Users", "etc"]), run_ls(self.image, terminal_columns=5))

    def testPathDefaultsToRoot(self):
        self.assertEqual(run_ls(self.image, "/"), run_ls(self.image))

    def testLongFormatAlignsColumns(self):
        expected = [
            "drwxr-xr-x    64 2026-09-25 02:06:56 a dir",
            "-rw-r--r-- 13498 2026-09-25 02:06:56 b.txt",
        ]
        self.assertEqual((0, expected), run_ls("-l", self.image, "/Users"))

    def testLongFormatShowsLocalTime(self):
        expected = [
            "drwxr-xr-x    64 2026-09-25 12:06:56 a dir",
            "-rw-r--r-- 13498 2026-09-25 12:06:56 b.txt",
        ]
        self.assertEqual((0, expected), run_ls("-l", self.image, "/Users", tz="Australia/Sydney"))

    def testTrailingSlashAndDotSegmentsAreNormalised(self):
        self.assertEqual(run_ls(self.image, "/Users"), run_ls(self.image, "/Users/"))
        self.assertEqual(run_ls(self.image, "/Users"), run_ls(self.image, "/etc/../Users"))

    def testEmptyFolderListsNothing(self):
        self.assertEqual((0, []), run_ls(self.image, "/Users/a dir"))

    def testFileOperandPrintsPathAsGiven(self):
        self.assertEqual((0, ["/Users/b.txt"]), run_ls(self.image, "/Users/b.txt"))

    def testSymlinkIsShownNotFollowed(self):
        expected = ["lrwxr-xr-x 11 2026-09-20 23:49:45 /etc -> private/etc"]
        self.assertEqual((0, expected), run_ls("-l", self.image, "/etc"))

    def testMissingPathReportsErrorAndExits1(self):
        status, lines, err = run_ls_full(self.image, "/nope")
        self.assertEqual((1, []), (status, lines))
        self.assertIn("aff4 ls: /nope: No such file or directory\n", err)


class ColumnsTest(unittest.TestCase):
    def testEmpty(self):
        self.assertEqual([], ls.columns([], 80))

    def testCellIsLongestUtf8ByteLengthPlusOneAndPaddingUsesDisplayWidth(self):
        # Measured from /bin/ls -G on macOS: 24 bytes, 16 columns wide, so 9 spaces of padding.
        self.assertEqual(
            ["文件文件文件文件" + " " * 9 + "a" + " " * 24 + "b"],
            ls.columns(["文件文件文件文件", "a", "b"], 200),
        )

    def testControlAndFormatCharactersShowAsQuestionMarks(self):
        self.assertEqual(
            ["new?line z?j      nb\u00a0sp"],
            ls.columns(["new\nline", "z\u200dj", "nb\u00a0sp"], 80),
        )

    def testDisplayWidth(self):
        self.assertEqual(1, ls.display_width("e\u0301"))
        self.assertEqual(2, ls.display_width("\U0001f600"))
        self.assertEqual(4, ls.display_width("한글"))
        self.assertEqual(2, ls.display_width("l\u2028s"))


class FormatTimeTest(unittest.TestCase):
    def format_in_sydney(self, lexical):
        with time_zone("Australia/Sydney"):
            return ls.format_time(Literal(lexical, datatype=XSD.dateTime))

    def testFollowsDaylightSaving(self):
        self.assertEqual("2026-01-15 11:00:00", self.format_in_sydney("2026-01-15T00:00:00Z"))
        self.assertEqual("2026-07-15 10:00:00", self.format_in_sydney("2026-07-15T00:00:00Z"))

    def testTimeWithoutZoneIsShownAsRecorded(self):
        self.assertEqual("2026-01-15 00:00:00", self.format_in_sydney("2026-01-15T00:00:00"))

    def testMissingTime(self):
        self.assertEqual("?", ls.format_time(None))


class PathTreeLsTest(unittest.TestCase):
    """pyaff4-written containers have no folders; ls derives them from file paths."""

    def testFoldersAreImpliedByFilePaths(self):
        self.assertEqual((0, ["test_images"]), run_ls(LOGICAL_DREAM, "/"))
        self.assertEqual((0, ["AFF4-L"]), run_ls(LOGICAL_DREAM, "/test_images"))

    def testLongFormatMarksUnknownFields(self):
        self.assertEqual((0, ["d????????? ? ? test_images"]), run_ls("-l", LOGICAL_DREAM, "/"))
        expected = ["-????????? 8688 2018-09-17 03:42:20 dream.txt"]
        self.assertEqual((0, expected), run_ls("-l", LOGICAL_DREAM, "/test_images/AFF4-L"))

    def testNormalise(self):
        self.assertEqual("/test_images/dream.txt", ls.normalise("./test_images/dream.txt"))
        self.assertEqual("/c:/Users/x.txt", ls.normalise("c:\\Users\\x.txt"))
        self.assertEqual("/server/share/x", ls.normalise("\\\\server\\share\\x"))
        self.assertEqual("/", ls.normalise(""))


class LsErrorsTest(unittest.TestCase):
    def testMissingImage(self):
        status, lines, err = run_ls_full("/no/such/image.aff4")
        self.assertEqual((1, []), (status, lines))
        self.assertIn("aff4 ls: /no/such/image.aff4: No such file or directory\n", err)

    def testPhysicalImageIsRejected(self):
        status, lines, err = run_ls_full(PHYSICAL)
        self.assertEqual((1, []), (status, lines))
        self.assertIn("not an AFF4 logical image", err)


class LsSubcommandTest(unittest.TestCase):
    def testAff4CliDispatchesLs(self):
        r = subprocess.run(
            [sys.executable, "-m", "pyaff4.cli", "ls", str(LOGICAL_DREAM), "/"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual((0, "test_images\n"), (r.returncode, r.stdout))


if __name__ == "__main__":
    unittest.main()
