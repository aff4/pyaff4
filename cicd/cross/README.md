# Third-party build inputs

`cicd/cross_build.py` uses these files to cross-compile the HDT kernels for Windows. They are
build inputs, not part of the `pyaff4` package.

| File | Source | Licence |
|---|---|---|
| `pyconfig-windows.h` | CPython v3.12.15 `PC/pyconfig.h`, unmodified | PSF License Version 2, in `LICENSE-CPython.txt` |
| `python3.def` | `src/python3.def` from PyO3's [python3-dll-a](https://github.com/PyO3/python3-dll-a) crate, version 0.2.14, unmodified | MIT, in `LICENSE-python3-dll-a.txt` |

`pyconfig-windows.h` is pinned by `PYCONFIG_WINDOWS_SHA256` in `cross_build.py`. To check it
against CPython:

```sh
curl -fsSL https://raw.githubusercontent.com/python/cpython/v3.12.15/PC/pyconfig.h | shasum -a 256
```

`LICENSE-CPython.txt` is CPython's `LICENSE` file, which states the PSF License and the history of
Python's earlier licences.
