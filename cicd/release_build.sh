#!/usr/bin/env bash
# Release build for pyaff4: cross-build the HDT kernels for six targets with zig, package and audit
# the wheels and sdist, then install and test this host's wheel on each supported Python.
# Runs on a Linux host, in CI or locally (the install tests load this host's linux-<arch> wheel).
# Needs only `uv` on PATH; binaries are inspected with pure-Python parsers.
#
# Outputs: dist/ (wheels + sdist, ready to publish) and build/release-artifacts/ (logs).
set -euo pipefail
# Unbuffered Python output, so the log shows progress live instead of when each step exits.
export PYTHONUNBUFFERED=1

CICD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$CICD/.." && pwd)"
ART="$PKG/build/release-artifacts"
mkdir -p "$ART"
exec > >(tee "$ART/release-build-$(uname -m).log") 2>&1

# Pinned build toolchain.
TOOLS=(numpy==2.5.3 crc32c==2.9.post0 cython==3.3.0 setuptools==84.0.0 ziglang==0.16.0
  abi3audit==0.0.26 auditwheel==6.8.2 macholib==1.16.4)
TEST_PYTHONS=(3.12 3.13 3.14)

step() { echo "== $(date -u +%H:%M:%S) $*"; }

# Without the submodule the tests that read reference images skip rather than fail.
if [[ ! -f "$PKG/reference_images/AFF4Std/Base-Linear.aff4" ]]; then
  echo "reference_images is empty: run git submodule update --init" >&2
  exit 1
fi

step "host: $(uname -srm)"
uv python install -q "${TEST_PYTHONS[@]}"
VENV="$PKG/build/tools-venv"
uv venv -q --clear --python 3.12 "$VENV"
uv pip install -q --python "$VENV/bin/python" "${TOOLS[@]}"
PY="$VENV/bin/python"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$PKG/pyproject.toml")"
echo "pyaff4 $VERSION"

step "cross-build (zig, 6 targets)"
"$PY" "$CICD/cross_build.py"
"$PY" "$CICD/lint_kernels.py"

step "wheels and sdist"
"$PY" "$CICD/build_wheels.py"
rm -f "$PKG"/dist/*.tar.gz
uv build -q --sdist --out-dir "$PKG/dist" "$PKG"
ls -l "$PKG/dist"

step "audits"
"$PY" -m abi3audit --strict --summary "$PKG"/dist/*abi3*.whl
for whl in "$PKG"/dist/*manylinux*.whl; do
  "$PY" -m auditwheel show "$whl"
done
"$PY" "$CICD/wheel_select.py"

step "sdist builds a wheel"
SDIST_OUT="$PKG/build/sdist-wheel"
rm -rf "$SDIST_OUT"
uv build -q --wheel --out-dir "$SDIST_OUT" "$PKG"/dist/*.tar.gz
ls "$SDIST_OUT"

# The tools venv has the HDT engine's dependencies only, so this runs the HDT engine's tests. The
# sdist build above left pyaff4.egg-info in $PKG, which supplies the version for the Software
# property.
step "HDT engine unit tests, interpreted kernels (source tree)"
(cd "$PKG" && PYTHONPATH="$PKG" PYHDT2_CYTHON_INTERPRETED=1 \
  "$PY" -W error -m unittest discover -s tests/test_pyhdt2_cython -t .)

NATIVE_SO="$PKG/build/cross/linux-$(uname -m)/pyhdt2_cython/_kernels.abi3.so"
# Install this host's wheel by path, with its dependencies from the index. Requesting pyaff4 by name
# would let uv pick the py312-none-any wheel, or the same version from the index.
HOST_WHL=("$PKG"/dist/pyaff4-"$VERSION"-cp312-abi3-manylinux*_"$(uname -m)".whl)
if [[ ${#HOST_WHL[@]} -ne 1 || ! -f ${HOST_WHL[0]} ]]; then
  echo "expected one manylinux $(uname -m) wheel in dist/, found: ${HOST_WHL[*]}" >&2
  exit 1
fi
for ver in "${TEST_PYTHONS[@]}"; do
  step "install test: Python $ver"
  TV="/tmp/pyaff4-install-$ver"
  uv venv -q --clear --python "$ver" "$TV"
  uv pip install -q --python "$TV/bin/python" "${HOST_WHL[0]}"
  "$TV/bin/python" - "$NATIVE_SO" <<'PY'
import hashlib
import sys
from pathlib import Path

import pyhdt2_cython._kernels as k

built = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
installed = hashlib.sha256(Path(k.__file__).read_bytes()).hexdigest()
print(f"kernels {Path(k.__file__).name}")
if installed != built:
    sys.exit("installed kernels are not the ones built by this run")
PY
  # The tests import each other as `tests.…`, so they need their parent directory on sys.path. In
  # $PKG that directory also holds the uncompiled packages, so run a copy beside the image
  # directories instead, and imports resolve to the installed wheel.
  TT="/tmp/pyaff4-tests-$ver"
  rm -rf "$TT"
  mkdir -p "$TT"
  cp -R "$PKG/tests" "$TT/tests"
  ln -s "$PKG/test_images" "$TT/test_images"
  ln -s "$PKG/reference_images" "$TT/reference_images"
  # pyaff4 supports Python <= 3.13; on 3.14, urllib's pathname2url("/c") returns "///c", so its file
  # URNs come out as file://///c and testLRU fails. The HDT engine and store tests still run.
  if [[ $ver != 3.14 ]]; then
    (cd "$TT" && "$TV/bin/python" -W ignore -m unittest discover -s tests -t .)
  else
    for suite in test_pyhdt2_cython test_rdflib_hdt_ng; do
      (cd "$TT" && "$TV/bin/python" -W ignore -m unittest discover -s "tests/$suite" -t .)
    done
  fi
done

cp "$PKG"/dist/* "$ART/"
step "release build passed"
