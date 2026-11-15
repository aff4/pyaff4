#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""The `pyhdtcli` command: listing, querying with ? wildcards, and its errors."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from pyhdt2_cython.build import from_triples
from pyhdt2_cython.cli import main

TRIPLES = [
    ("http://a/s1", "http://a/p1", "http://a/o1"),
    ("http://a/s1", "http://a/p2", '"hello"@en'),
    ("http://a/s2", "http://a/p1", "http://a/o2"),
]


def run(*argv: str) -> tuple[int, list[str], str]:
    """(exit status, stdout lines, stderr) of pyhdtcli with argv."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            status = main(argv)
        except SystemExit as e:
            status = e.code if isinstance(e.code, int) else 1
    return status, out.getvalue().splitlines(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "graph.hdt"
        self.path.write_bytes(from_triples(TRIPLES))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_list_prints_every_triple_and_times_to_stderr(self) -> None:
        status, lines, err = run("-l", str(self.path))
        self.assertEqual(status, 0)
        self.assertEqual(sorted(lines), sorted(" ".join(t) for t in TRIPLES))
        self.assertIn("Load took", err)

    def test_query_treats_question_mark_as_any(self) -> None:
        status, lines, err = run("-q", "?", "http://a/p1", "?", str(self.path))
        self.assertEqual(status, 0)
        self.assertEqual(
            lines, ["http://a/s1 http://a/p1 http://a/o1", "http://a/s2 http://a/p1 http://a/o2"]
        )
        self.assertIn("Query took", err)

    def test_query_with_no_match_prints_nothing(self) -> None:
        status, lines, _ = run("-q", "http://a/s9", "?", "?", str(self.path))
        self.assertEqual((status, lines), (0, []))

    def test_missing_file_fails_with_a_message(self) -> None:
        status, lines, err = run("-l", str(self.path.with_name("absent.hdt")))
        self.assertEqual((status, lines), (1, []))
        self.assertIn("cannot load", err)

    def test_unreadable_hdt_fails_with_a_message(self) -> None:
        self.path.write_bytes(b"not an hdt")
        status, _, err = run("-l", str(self.path))
        self.assertEqual(status, 1)
        self.assertIn("cannot load", err)

    def test_an_action_is_required(self) -> None:
        status, _, err = run(str(self.path))
        self.assertEqual(status, 2)
        self.assertIn("one of the arguments -l/--list -q/--query is required", err)


if __name__ == "__main__":
    unittest.main()
