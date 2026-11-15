#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Time pyhdt2_cython at three layers on one HDT file, each layer in its own process.

    python benchmarks/bench_api.py --hdt bench.hdt --queries queries.json [--out results.json]

Layers:
  - engine: `pyhdt2_cython.hdt.Hdt`, which yields plain tuples;
  - api:    `PyHdt.triples_with_pattern` plus `.subject/.predicate/.object` on each triple;
  - rdflib: `rdflib.Graph(HdtStore(bytes)).triples(pattern)`, the path pyaff4 uses. Its term
    caches are cleared before every timed run, so these numbers are cold-cache.

`queries.json` holds {"ask": [[s, p, o], ...], "subjects": [...], "predicates": [...]}. Every
result is digested.

    python benchmarks/bench_api.py --dictionary --hdt bench.hdt [--out results.json]

times pyhdt2_cython's front-coded sections directly: `Pfc.extract`, `Pfc.locate` for present
and absent strings, and `Pfc.affix` (each sampled string less its last two bytes, ending with
its last byte) on the HDT's shared and objects sections, a generated mix of IRIs, long
literals, multi-byte UTF-8 and language tags, and zero-padded synthetic URIs. Set
PYHDT2_CYTHON_INTERPRETED=1 to time the uncompiled kernels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path

LAYERS = ["engine", "api", "rdflib"]


def digest(triples: Iterable[tuple]) -> tuple[int, str]:
    h = hashlib.blake2b(digest_size=16)
    n = 0
    for s, p, o in triples:
        h.update(f"{s}\t{p}\t{o}\n".encode())
        n += 1
    return n, h.hexdigest()


def is_iri(term: str) -> bool:
    return not term.startswith(('"', "_:"))


def make_query(layer: str, data: bytes) -> Callable:
    """Return pattern(s, p, o) -> iterable of 3-tuples for this layer."""
    if layer == "engine":
        from pyhdt2_cython.hdt import Hdt

        hdt = Hdt(data)
        return hdt.triples_with_pattern
    if layer == "api":
        from pyhdt2_cython import PyHdt

        hdt = PyHdt(data)

        def pattern(s, p, o):
            return ((t.subject, t.predicate, t.object) for t in hdt.triples_with_pattern(s, p, o))

        return pattern
    import rdflib

    from rdflib_hdt_ng.hdt_store import HdtStore

    graph = rdflib.Graph(HdtStore(data))

    def term(x):
        return None if x is None else rdflib.URIRef(x)

    def pattern(s, p, o):
        return graph.triples((term(s), term(p), term(o)))

    return pattern


def clear_term_caches() -> None:
    """Empty rdflib_hdt_ng's term caches, so every timed rdflib run starts cold."""
    from rdflib_hdt_ng import terms

    for cached in (terms.resource, terms.predicate, terms.node_or_literal):
        cached.cache_clear()


def timed(fn: Callable[[], object]) -> float:
    t = time.perf_counter()
    fn()
    return time.perf_counter() - t


def consume(it: Iterable) -> int:
    n = 0
    for _ in it:
        n += 1
    return n


def measure(layer: str, hdt_path: Path, queries: dict) -> dict:
    data = hdt_path.read_bytes()
    load = min(timed(lambda: make_query(layer, data)) for _ in range(3))
    query = make_query(layer, data)
    # IRIs only, so the rdflib layer can pass every term as a URIRef and all layers run the
    # same patterns.
    ask = [t for t in queries["ask"] if all(is_iri(x) for x in t)]
    subjects = [s for s in queries["subjects"] if is_iri(s)]
    objects = list(dict.fromkeys(o for _, _, o in ask))[:500]
    po = [(p, o) for _, p, o in ask[:2000]]
    workloads = {
        "scan": [(None, None, None)],
        "ask": [tuple(t) for t in ask],
        "s??": [(s, None, None) for s in subjects],
        "?p?": [(None, p, None) for p in queries["predicates"]],
        "??o": [(None, None, o) for o in objects],
        "?po": [(None, p, o) for p, o in po],
    }
    res = {"layer": layer, "load_s": load}

    def run_all(patterns: list[tuple]) -> int:
        if layer == "rdflib":
            clear_term_caches()
        return sum(consume(query(*q)) for q in patterns)

    for name, patterns in workloads.items():
        # Best of N: timings on a shared machine vary by up to 2x between single runs.
        reps = (1 if layer == "rdflib" else 3) if name == "scan" else 5
        best = min(timed(lambda p=patterns: run_all(p)) for _ in range(reps))
        n, d = digest(t for q in patterns for t in query(*q))
        res[name] = {"s": best, "queries": len(patterns), "triples": n, "digest": d}
    return res


def drive(args: argparse.Namespace) -> int:
    results = []
    for layer in LAYERS:
        cmd = [sys.executable, __file__, "--hdt", str(args.hdt), "--queries", str(args.queries)]
        cmd += ["--one", layer]
        print(f"== {layer}", flush=True)
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return 1
        results.append(json.loads(proc.stdout))
    print_table(results)
    if args.out:
        args.out.write_text(json.dumps(results, indent=1))
    return 0


def print_table(results: list[dict]) -> None:
    cols = [r["layer"] for r in results]
    print(f"{'':28}" + "".join(f"{c:>22}" for c in cols))
    print(f"{'load (s)':28}" + "".join(f"{r['load_s']:>22.3f}" for r in results))
    for name, unit, scale in (
        ("scan", "s", 1),
        ("ask", "µs/query", 1e6),
        ("s??", "µs/query", 1e6),
        ("?p?", "ns/triple", 1e9),
        ("??o", "ns/triple", 1e9),
        ("?po", "µs/query", 1e6),
    ):
        cells = []
        for r in results:
            w = r[name]
            per = w["triples"] if unit == "ns/triple" else w["queries"]
            cells.append(f"{w['s'] / max(per, 1) * scale:>22.2f}")
        print(f"{name + ' (' + unit + ')':28}" + "".join(cells))


def mixed_terms(n: int, seed: int) -> list[bytes]:
    """IRIs with varied tails, long literals, multi-byte UTF-8 and language tags."""
    rng = random.Random(seed)
    hosts = [
        "http://dbpedia.org/resource/",
        "http://ja.dbpedia.org/resource/",
        "http://www.wikidata.org/entity/Q",
        "https://example.org/people/",
        "urn:uuid:",
    ]
    words = ["Zürich", "São_Paulo", "東京", "Москва", "Ελλάδα", "café", "naïve", "Łódź", "😀"]
    words += ["plain", "River", "Mount_Everest", "Ångström", "data", "set", "x"]
    langs = ["en", "de", "fr", "ja", "ru", "el", "pt-BR"]
    terms: set[str] = set()
    while len(terms) < n:
        kind = rng.randrange(4)
        text = "_".join(rng.choices(words, k=rng.randint(1, 4)))
        if kind == 0:
            terms.add(rng.choice(hosts) + text + str(rng.randrange(10 ** rng.randint(1, 7))))
        elif kind == 1:
            terms.add(f'"{text.replace("_", " ")}"@{rng.choice(langs)}')
        elif kind == 2:
            long_text = " ".join(rng.choices(words, k=rng.randint(15, 60)))
            terms.add(f'"{long_text}"')
        else:
            terms.add(f'"{rng.randrange(10**12)}"^^<http://www.w3.org/2001/XMLSchema#long>')
    return sorted(t.encode() for t in terms)


def absent_probes(strings: list[bytes], rng: random.Random) -> list[bytes]:
    """A proper prefix, an extension, or a changed last byte of each string."""
    probes = []
    for s in strings:
        kind = rng.randrange(3)
        if kind == 0:
            probes.append(s[: rng.randrange(len(s))])
        elif kind == 1:
            probes.append(s + b"!")
        else:
            probes.append(s[:-1] + bytes([(s[-1] + 1) % 256]))
    return probes


def time_calls(fn: Callable, args: list) -> tuple[float, str]:
    """Best-of-5 ns per call of fn over args, and a digest of the results."""
    best = float("inf")
    for _ in range(5):
        t = time.perf_counter()
        for a in args:
            fn(a)
        best = min(best, time.perf_counter() - t)
    h = hashlib.blake2b(digest_size=8)
    for a in args:
        h.update(f"{fn(a)}\n".encode())
    return best / len(args) * 1e9, h.hexdigest()


def measure_dictionary(hdt_path: Path) -> list[dict]:
    from pyhdt2_cython import _kernels as K
    from pyhdt2_cython.build import _pack_sorted, _pfc_section
    from pyhdt2_cython.hdt import Hdt, PfcSection, _Reader

    def section(terms: list[bytes]):
        packed = _pack_sorted(terms)
        return PfcSection(_Reader(_pfc_section(packed, packed.order)[0]), False)

    hdt = Hdt(hdt_path.read_bytes())
    sections = {
        "hdt shared": hdt.shared,
        "hdt objects": hdt.objects,
        "mixed text": section(mixed_terms(50_000, seed=1)),
        "zero-padded": section([f"http://example.org/r/{i:010d}".encode() for i in range(200_000)]),
    }
    samples = 2_000 if K.__file__.endswith(".py") else 20_000
    rng = random.Random(7)
    rows = []
    for name, sec in sections.items():
        pfc = sec.pfc
        ids = [rng.randint(1, sec.num_strings) for _ in range(samples)]
        present = [pfc.extract(i).encode() for i in ids]
        absent = [p for p in absent_probes(present, rng) if pfc.locate(p) == 0]
        row: dict = {"section": name, "strings": sec.num_strings, "absent probes": len(absent)}
        for op, fn, args in (
            ("extract", pfc.extract, ids),
            ("locate hit", pfc.locate, present),
            ("locate miss", pfc.locate, absent),
            ("affix", lambda a, pfc=pfc: pfc.affix(*a), [(t[:-2], t[-1:]) for t in present]),
        ):
            row[op], row[op + " digest"] = time_calls(fn, args)
        rows.append(row)
    return rows


def print_dictionary(rows: list[dict]) -> None:
    ops = ("extract", "locate hit", "locate miss", "affix")
    print(f"{'ns/call':16}" + "".join(f"{op:>14}" for op in ops))
    for row in rows:
        print(f"{row['section']:16}" + "".join(f"{row[op]:>14.0f}" for op in ops))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hdt", type=Path, required=True)
    parser.add_argument("--queries", type=Path)
    parser.add_argument("--dictionary", action="store_true", help="time front-coded sections")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--one", choices=LAYERS, help="run one layer's measurement as JSON")
    args = parser.parse_args()
    if args.dictionary:
        rows = measure_dictionary(args.hdt)
        print_dictionary(rows)
        if args.out:
            args.out.write_text(json.dumps(rows, indent=1))
        return 0
    if args.queries is None:
        parser.error("--queries is required unless --dictionary is given")
    if args.one:
        queries = json.loads(args.queries.read_text())
        print(json.dumps(measure(args.one, args.hdt, queries)))
        return 0
    return drive(args)


if __name__ == "__main__":
    sys.exit(main())
