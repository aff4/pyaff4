default:
    @just --list

# Install pyaff4 (editable, compiling the HDT kernels) and its dependencies from uv.lock
sync:
    uv sync

# Build the pyaff4 sdist and a wheel for this host (all six platforms: cicd/release_build.sh)
build:
    uv build --out-dir dist/

# Cross-build, audit and install-test every release wheel (Linux hosts only)
release-build:
    bash cicd/release_build.sh

# Run all tests with compiled HDT kernels, then the HDT engine's tests interpreted
test:
    uv run --no-sync python -m unittest discover -s tests -t .
    PYHDT2_CYTHON_INTERPRETED=1 uv run --no-sync python -m unittest discover -s tests/test_pyhdt2_cython -t .

clean:
    rm -rf dist/

# Show the current pyproject version of pyaff4.
version:
    @uv version

# Bump pyaff4's pyproject version. Pass a kind (patch|minor|major|alpha|beta|rc)
# or an explicit version. Defaults to patch. Updates uv.lock automatically.
#   just bump              # 2.0.0a13 -> 2.0.0a14 (uv treats trailing alpha as patch-eligible)
#   just bump alpha        # 2.0.0a13 -> 2.0.0a14
#   just bump 2.0.0        # explicit promotion to release
bump KIND="patch":
    uv version {{ if KIND =~ '^[0-9]' { "" } else { "--bump" } }} {{ KIND }}
