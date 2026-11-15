# HDT build goldens

The expected output of `pyhdt2_cython.build.from_triples` for the graphs in `golden_cases()` in
`tests/test_pyhdt2_cython/test_build.py`, each written with a plain (`-plain`) and a
suffix-coded objects dictionary (`-psfc`). `test_output_matches_the_goldens` checks the builder
reproduces them byte for byte.

They were written by the set-based builder that the streamed intersection reorganiser replaced,
so that the new builder could be shown to produce the same files. That builder is no longer in
this repository.

The builder writes a timestamp and a `Software` string into each file; the goldens fix them as
`GoldenTests.setUp` does. If the output format changes deliberately, regenerate them by piping
this to `uv run python -` from the repository root:

```python
from datetime import UTC, datetime
from unittest import mock

from pyhdt2_cython import build
from tests import HDT_FIXTURES
from tests.test_pyhdt2_cython.test_build import golden_cases

issued = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
with (
    mock.patch.object(build, "_utc_now", return_value=issued),
    mock.patch.object(build, "_software", return_value="pyaff4/golden"),
):
    for name, triples in golden_cases().items():
        for psfc in (True, False):
            golden = HDT_FIXTURES / "build-golden" / f"{name}-{'psfc' if psfc else 'plain'}.hdt"
            golden.write_bytes(build.from_triples(triples, psfc=psfc))
```
