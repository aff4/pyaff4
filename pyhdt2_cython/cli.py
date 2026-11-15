#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""`pyhdtcli`: list or query the triples of an HDT file.

    pyhdtcli -l graph.hdt
    pyhdtcli -q S P O graph.hdt      # each of S, P, O is a term, or ? for any

Triples go to stdout, one per line as `subject predicate object`; load and query times go to
stderr.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from pyhdt2_cython import PyHdt

WILDCARD = "?"


def _load(path: Path) -> PyHdt:
    start = time.perf_counter()
    hdt = PyHdt(path.read_bytes())
    print(f"Load took {time.perf_counter() - start:.3f}s", file=sys.stderr)
    return hdt


def _term(arg: str) -> str | None:
    return None if arg == WILDCARD else arg


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pyhdtcli", description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("-l", "--list", action="store_true", help="print every triple")
    action.add_argument(
        "-q", "--query", nargs=3, metavar=("S", "P", "O"), help=f"terms, or {WILDCARD} for any"
    )
    parser.add_argument("filename", type=Path)
    args = parser.parse_args(argv)
    try:
        hdt = _load(args.filename)
    except (OSError, ValueError) as e:
        parser.exit(1, f"pyhdtcli: cannot load {args.filename}: {e}\n")
    start = time.perf_counter()
    if args.list:
        triples = hdt.triples()
    else:
        triples = hdt.triples_with_pattern(*(_term(a) for a in args.query))
    for t in triples:
        print(t.subject, t.predicate, t.object)
    if args.query:
        print(f"Query took {time.perf_counter() - start:.3f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
