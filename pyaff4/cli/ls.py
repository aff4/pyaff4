#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""The `aff4 ls` subcommand: list a folder of an AFF4 logical image, modelled on ls(1)."""

import argparse
import functools
import locale
import os
import posixpath
import shutil
import stat
import sys
import unicodedata
from datetime import datetime

from rdflib import Literal

from pyaff4 import container, lexicon, rdfvalue

PROG = "aff4 ls"


class Entry:
    def __init__(self, path, urn, is_dir, name=None):
        self.path = path
        self.name = name if name is not None else posixpath.basename(path)
        self.urn = urn
        self.is_dir = is_dir


def normalise(path):
    """Map a stored or requested path onto an absolute POSIX path.

    Backslashes become slashes, so pyaff4's "./dir/file" and "c:\\dir\\file"
    become "/dir/file" and "/c:/dir/file".
    """
    path = path.replace("\\", "/")
    return posixpath.normpath("/" + path.lstrip("/"))


def first(volume, urn, predicate):
    return next(iter(volume.resolver.QuerySubjectPredicate(volume.urn, urn, predicate)), None)


class FolderTree:
    """Containers that link aff4:Folder objects with aff4:child, as other AFF4-L tools do."""

    def __init__(self, volume):
        self.volume = volume

    def entry(self, urn):
        types = list(
            self.volume.resolver.QuerySubjectPredicate(self.volume.urn, urn, lexicon.AFF4_TYPE)
        )
        path = str(first(self.volume, urn, self.volume.lexicon.pathName))
        name = first(self.volume, urn, lexicon.standard11.fileName)
        return Entry(
            path, urn, lexicon.standard11.FolderImage in types, None if name is None else str(name)
        )

    def lookup(self, path):
        subjects = self.volume.resolver.QueryPredicateObject(
            self.volume.urn, self.volume.lexicon.pathName, Literal(path)
        )
        urn = next(iter(subjects), None)
        if urn is None:
            return None
        return self.entry(urn)

    def children(self, entry):
        urns = self.volume.resolver.QuerySubjectPredicate(
            self.volume.urn, entry.urn, lexicon.standard11.child
        )
        return [self.entry(urn) for urn in urns]


class PathTree:
    """Containers that only record a path per file (e.g. pyaff4); folders are implied."""

    def __init__(self, volume):
        self.files = {}
        self.dirs = {"/": set()}
        for image in volume.images():
            path = normalise(image.name())
            self.files[path] = image.urn
            self.add_parents(path)

    def add_parents(self, path):
        while path != "/":
            parent, name = posixpath.split(path)
            self.dirs.setdefault(parent, set()).add(name)
            path = parent

    def lookup(self, path):
        if path in self.dirs:
            return Entry(path, self.files.get(path), True)
        if path in self.files:
            return Entry(path, self.files[path], False)
        return None

    def children(self, entry):
        return [self.lookup(posixpath.join(entry.path, name)) for name in self.dirs[entry.path]]


def open_tree(volume):
    has_child_links = volume.resolver.QueryPredicateObject(
        volume.urn, lexicon.standard11.child, None
    )
    if next(iter(has_child_links), None) is not None:
        return FolderTree(volume)
    return PathTree(volume)


def format_time(value):
    if value is None:
        return "?"
    when = value.toPython()
    if not isinstance(when, datetime):
        try:
            when = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
    if when.tzinfo is not None:
        when = when.astimezone()
    return when.strftime("%Y-%m-%d %H:%M:%S")


def long_row(volume, entry, name):
    if entry.urn is None:
        return ("d?????????", "?", "?", name)
    mode = first(volume, entry.urn, lexicon.standard11.fileMode)
    if mode is not None:
        mode = stat.filemode(int(mode))
    else:
        mode = ("d" if entry.is_dir else "-") + "?????????"
    size = first(volume, entry.urn, lexicon.standard11.streamSize)
    mtime = first(volume, entry.urn, lexicon.standard11.lastWritten)
    target = first(volume, entry.urn, lexicon.standard11.symlinkTarget)
    if target is not None:
        name = f"{name} -> {target}"
    return (mode, "?" if size is None else str(size), format_time(mtime), name)


def print_long(rows, to_tty):
    size_width = max((len(r[1]) for r in rows), default=0)
    time_width = max((len(r[2]) for r in rows), default=0)
    for mode, size, mtime, name in rows:
        name = tty_safe(name) if to_tty else name
        print(f"{mode} {size.rjust(size_width)} {mtime.ljust(time_width)} {name}")


def collate(a, b):
    """Order names as ls(1) does, by the locale's collation (strcoll), then by code point."""
    return locale.strcoll(a, b) or (a > b) - (a < b)


def tty_safe(name):
    """Show control and format characters as '?', as macOS ls does on a terminal."""
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf") else c for c in name)


def display_width(text):
    """Terminal columns for text: wide and fullwidth characters take two, combining marks and
    line/paragraph separators none."""
    width = 0
    for c in text:
        if unicodedata.category(c) in ("Mn", "Me", "Zl", "Zp"):
            continue
        width += 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
    return width


def columns(names, width):
    """Lay names out down then across, in rows at most width wide, as macOS `ls -G` does on a
    terminal: each cell is one wider than the longest name's UTF-8 byte length.
    """
    if not names:
        return []
    cell = max(len(name.encode("utf-8", "surrogatepass")) for name in names) + 1
    shown = [tty_safe(name) for name in names]
    if width < 2 * cell:
        return shown
    rows = -(-len(names) // (width // cell))
    lines = []
    for row in range(rows):
        cells = shown[row::rows]
        padded = [name + " " * (cell - display_width(name)) for name in cells[:-1]]
        lines.append("".join(padded) + cells[-1])
    return lines


def print_listing(volume, listing, long_format):
    to_tty = sys.stdout.isatty()
    if long_format:
        print_long([long_row(volume, e, name) for e, name in listing], to_tty)
        return
    names = [name for _, name in listing]
    if to_tty:
        names = columns(names, shutil.get_terminal_size().columns)
    for name in names:
        print(name)


def list_path(volume, path, long_format):
    """Print the listing for path; returns the ls(1) exit status."""
    tree = open_tree(volume)
    entry = tree.lookup(normalise(path))
    if entry is None:
        print(f"{PROG}: {path}: No such file or directory", file=sys.stderr)
        return 1
    if entry.is_dir:
        key = functools.cmp_to_key(collate)
        listing = sorted(((e, e.name) for e in tree.children(entry)), key=lambda p: key(p[1]))
    else:
        listing = [(entry, path)]
    print_listing(volume, listing, long_format)
    return 0


def run(image, path, long_format):
    if not os.path.exists(image):
        print(f"{PROG}: {image}: No such file or directory", file=sys.stderr)
        return 1
    with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(image)) as volume:
        if not isinstance(volume, container.LogicalImageContainer):
            print(f"{PROG}: {image}: not an AFF4 logical image", file=sys.stderr)
            return 1
        return list_path(volume, path, long_format)


def main(argv):
    parser = argparse.ArgumentParser(
        prog=PROG, description="List a folder in an AFF4 logical image, like ls(1)."
    )
    parser.add_argument(
        "-l",
        action="store_true",
        dest="long_format",
        help="long format: mode, size, last written (local time) and name",
    )
    parser.add_argument("image", help="the AFF4 container")
    parser.add_argument(
        "path", nargs="?", default="/", help="the folder or file to list (default: /)"
    )
    args = parser.parse_args(argv)
    try:
        locale.setlocale(locale.LC_COLLATE, "")
    except locale.Error:
        # An unknown locale in the environment: ls(1) falls back to the C locale too.
        locale.setlocale(locale.LC_COLLATE, "C")
    try:
        return run(args.image, args.path, args.long_format)
    except BrokenPipeError:
        # The reader went away (e.g. `| head`); silence the flush at interpreter exit.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1
