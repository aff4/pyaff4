# pyaff4

AFF4 (forensic container format) library for Python 3.12+, distribution `pyaff4` 2.x. Wheels carry
three packages: `pyaff4`, `pyhdt2_cython` (an HDT engine; hot loops in `_kernels.py`, compiled by
Cython in pure-Python mode) and `rdflib_hdt_ng` (an rdflib Store over HDT).

## Commands

- Environment: `env -u UV_INDEX_URL -u UV_DEFAULT_INDEX uv sync` (see "uv and the package index").
- Tests: `uv run --no-sync python -m unittest discover -s tests -t .` (`-t .` is required:
  tests import each other as `tests.…`). Needs the `reference_images` submodule:
  `git submodule update --init`.
- Interpreted kernels: prefix with `PYHDT2_CYTHON_INTERPRETED=1`. Use this after editing
  `pyhdt2_cython/_kernels.py` until the kernels are rebuilt, or you test the old build.
- Rebuild kernels: `env -u UV_INDEX_URL -u UV_DEFAULT_INDEX uv sync --reinstall-package pyaff4`.
- Kernel lint: `uv run --no-sync python cicd/lint_kernels.py` (reads the generated `_kernels.c`).
- Lint, as CI runs it: `ruff check` and `ruff format --check` on `pyhdt2_cython rdflib_hdt_ng
  tests/test_pyhdt2_cython tests/test_rdflib_hdt_ng cicd benchmarks setup.py`. The rest of
  `pyaff4/` and `tests/` predates ruff; don't add findings to files you touch.
- Release build (Linux only): `bash cicd/release_build.sh` (`just release-build`).

## uv and the package index

A machine-wide `uv.toml` or the `UV_INDEX_URL`/`UV_DEFAULT_INDEX` environment variables can point
uv at an index other than PyPI. `pyproject.toml` names pypi.org as the default index, which beats a
machine-wide `uv.toml` but not the environment variables. Run uv with
`env -u UV_INDEX_URL -u UV_DEFAULT_INDEX`, or `uv lock` can rewrite `uv.lock` to that index. Every
`registry` in `uv.lock` must be `https://pypi.org/simple`.

## Layout

- `pyaff4/`: library; CLI in `pyaff4/cli/` (`aff4` entry point; `aff4 ls` in `pyaff4/cli/ls.py`).
- `tests/`: all tests (an importable package; `tests.HDT_FIXTURES`, `tests.HDT_GRAPHS`).
  `tests/hdt_fixtures/` holds the HDT fixtures, `build-golden/` the builder's byte-for-byte goldens
  (README there says how to regenerate them).
- `cicd/`: wheel cross-builds with zig; `cicd/cross/` holds third-party build inputs (see its
  README).
- `.github/workflows/`: `ci.yml` (PRs and pushes to main), `release.yml` (`v*` tags; publishes to
  PyPI by trusted publishing).

## Working agreements

- The user runs anything that talks to github.com or pypi.org (pushes, `gh`, lookups, `uv lock`,
  rebuilds that download). Hand them the exact command.
- Commit only when asked; commits are signed. One logical change per commit.

## What changed from 0.x (things to unlearn)

| 0.x | Now |
|---|---|
| Python 2/3 (`future`, `past`, `builtins` imports) | Python 3.12+ only; no compatibility imports |
| `setup.py` + `requirements.txt`, `aff4.py` script at the root | `pyproject.toml` + `uv.lock`; `aff4` entry point |
| Tests beside the code (`pyaff4/*_test.py`) | Tests in `tests/`, run with `-t .` |
| `rdfvalue.XSDString`, `XSDInteger`, `XSDDateTime`, … | `rdflib.Literal(value, datatype=XSD.…)` |
| `rdfvalue.URN("aff4://…")` | `rdfvalue.ARN("aff4://…")` (a `URIRef`); `URN()` takes no arguments, use `URN.FromFileName(path)` |
| Lexicon constants are strings, wrapped in `rdfvalue.URN(...)` | Lexicon constants are `URIRef`s; pass them directly |
| `hashes.newImmutableHash(hex, type)` | `Literal(hex, datatype=type)` |
| `pyaff4.utils` (`SmartUnicode`, `SmartStr`, …) | Removed; use `str()` / `bytes` |
| `createURN` returns a hash-based container unless `zip_based=True` | Returns a logical container; `hashbased=True` for hash-based |
| `compression_method=` / `allow_large_zipsegments=` (#36) | `createURN(zipstream_compression_method=…, always_write_zipstreams=…)`, set per container |
| Metadata only in `information.turtle` | `information.hdt` is written too, and readers prefer it |
| Zip64 field in local headers only when needed | Always reserved: every member is 20 bytes larger; size assertions in tests reflect this |
| GCS backend (`aff4_cloud.py`), `aes_keywrap.py` | Removed; key wrapping uses `cryptography`'s `aes_key_wrap` |
| `fastchunking` (Rabin-Karp), optional `snappy` | `fastcdc`; `python-snappy` is required |
