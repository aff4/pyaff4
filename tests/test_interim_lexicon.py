#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from pyaff4 import container, lexicon, rdfvalue

LOGICAL_DREAM = (
    Path(__file__).resolve().parent.parent / "reference_images" / "AFF4-L" / "deprecated" / "dream.aff4"
)
DREAM_PATH = "./test_images/AFF4-L/dream.txt"


def copy_dream(dest, tool, path_predicate):
    """Copy dream.aff4 to dest, rewriting the version.txt tool and the path predicate."""
    with zipfile.ZipFile(LOGICAL_DREAM) as src, zipfile.ZipFile(dest, "w") as out:
        out.comment = src.comment
        for info in src.infolist():
            data = src.read(info)
            if info.filename == "version.txt":
                data = f"major=1\nminor=1\ntool={tool}\n".encode()
            elif info.filename == "information.turtle":
                data = data.replace(b"aff4:originalFileName", path_predicate.encode("utf-8"))
            out.writestr(info, data)


class InterimAff4lLexiconTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def open(self, tool, path_predicate):
        name = os.path.join(self.tmpdir, "copy.aff4")
        copy_dream(name, tool, path_predicate)
        return container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(name))

    def testPyaff4ToolUsesStandard11(self):
        with self.open("pyaff4", "aff4:originalFileName") as volume:
            self.assertIs(volume.lexicon, lexicon.standard11)
            self.assertEqual([DREAM_PATH], [i.name() for i in volume.images()])

    def testOtherToolsUseInterimLexicon(self):
        for tool in ("ExampleImager 1.0", "Evimetry 3.0.0", ""):
            with self.subTest(tool=tool), self.open(tool, "aff4:originalPathName") as volume:
                self.assertIs(volume.lexicon, lexicon.interimAff4l)
                self.assertEqual([DREAM_PATH], [i.name() for i in volume.images()])

    def testInterimLexiconOpensAndReadsByPath(self):
        with self.open("ExampleImager 1.0", "aff4:originalPathName") as volume:
            image = next(volume.images())
            opened = volume.open(image.urn)
            self.assertEqual(DREAM_PATH, opened.name())
            with volume.resolver.AFF4FactoryOpen(image.urn) as stream:
                self.assertEqual(8688, len(stream.Read(10000)))

    def testCliExtractAllUsesInterimLexicon(self):
        from pyaff4.cli import commands

        dest = os.path.join(self.tmpdir, "out")
        name = os.path.join(self.tmpdir, "copy.aff4")
        copy_dream(name, "ExampleImager 1.0", "aff4:originalPathName")
        with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(name)) as volume:
            commands.extractAllFromVolume(name, volume, dest)
        extracted = os.path.join(dest, DREAM_PATH)
        self.assertEqual(8688, os.path.getsize(extracted))


if __name__ == "__main__":
    unittest.main()
