#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Time HDT creation (`pyhdt2_cython.build.from_triples`) on a generated graph.

    python benchmarks/bench_build.py [--triples 1000000] [--repeat 3] [--plain] [--out r.json]

The graph is shaped like AFF4 metadata: IRI subjects, a few dozen predicates, objects that are
other subjects (so the shared section is populated), typed and language-tagged literals and
blank nodes. The output's BLAKE2b digest is printed with the timings (the clock and Software
property are frozen), so runs of two engines can be checked for identical bytes. Set
PYHDT2_CYTHON_INTERPRETED=1 to time the uncompiled kernels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from pyhdt2_cython import build

XSD = "http://www.w3.org/2001/XMLSchema#"


def generate(n: int, seed: int = 7) -> list[tuple[str, str, str]]:
    rng = random.Random(seed)
    n_subjects = max(1, n // 8)
    subjects = [f"aff4://{rng.getrandbits(64):016x}/item/{i}" for i in range(n_subjects)]
    predicates = [f"http://aff4.org/Schema#p{i}" for i in range(40)]
    datatypes = [f"{XSD}long", f"{XSD}dateTime", f"{XSD}hexBinary", f"{XSD}string"]
    triples = []
    for i in range(n):
        s = subjects[rng.randrange(n_subjects)]
        p = predicates[rng.randrange(len(predicates))]
        kind = rng.randrange(10)
        if kind < 4:
            o = subjects[rng.randrange(n_subjects)]
        elif kind < 8:
            o = f'"{rng.randrange(1 << 40)}"^^<{datatypes[kind % 4]}>'
        elif kind == 8:
            o = f'"name {i % 5000}"@en'
        else:
            o = f"_:b{i % 1000}"
        triples.append((s, p, o))
    return triples


def main() -> None:
    parser = argparse.ArgumentParser(description="Time HDT creation on a generated graph.")
    parser.add_argument("--triples", type=int, default=1_000_000)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--plain", action="store_true", help="dictionaryFour, not Psfc")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    triples = generate(args.triples)
    times = []
    data = b""
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    with (
        mock.patch.object(build, "_utc_now", return_value=issued),
        mock.patch.object(build, "_software", return_value="pyaff4/bench"),
    ):
        for _ in range(args.repeat):
            start = time.perf_counter()
            data = build.from_triples(triples, psfc=not args.plain)
            times.append(time.perf_counter() - start)
    result = {
        "triples": args.triples,
        "psfc": not args.plain,
        "best_s": min(times),
        "times_s": times,
        "hdt_bytes": len(data),
        "digest": hashlib.blake2b(data, digest_size=16).hexdigest(),
    }
    print(json.dumps(result, indent=2))
    if args.out is not None:
        args.out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
