"""Backwards-compatibility shim for legacy versioneer-style callers.

Pre-2.0 pyaff4 shipped a versioneer-generated `_version.py` that
exposed `raw_versions()` / `get_versions()` returning a dict of
git-derived version metadata. The uv_build migration removed
versioneer; the version is now sourced from pyproject.toml via
`importlib.metadata`. This module preserves the legacy function
shape so downstream consumers (e.g. mac-apt's LogLibraryVersions
hook calling `pyaff4._version.raw_versions()['version']`) continue
to work without code changes.
"""

from __future__ import annotations

from importlib.metadata import version

__version__: str = version("pyaff4")


def raw_versions() -> dict[str, object]:
    """Return version metadata under legacy keys.

    The original versioneer dict carried git-derived fields (full SHA,
    dirty flag, pep440 string). Releases now ship from clean git tags
    with pyproject.toml as the single source of truth, so only the
    `version` key carries meaningful information; the others are
    populated with the same value (for `pep440`-indexing callers) or
    benign defaults.
    """
    return {
        "version": __version__,
        "pep440": __version__,
        "version-pep440": __version__,
        "full-revisionid": "",
        "dirty": False,
        "error": None,
    }


def get_versions() -> dict[str, object]:
    """Versioneer-compatible alias for `raw_versions`."""
    return raw_versions()
