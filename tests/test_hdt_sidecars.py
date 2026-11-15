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
from unittest import mock

from pyaff4 import container, data_store, rdfvalue
from pyaff4.rdfvalue import ARN
from rdflib_hdt_ng import hdt_store

try:
    from pyhdt2_cython.build import write_opidx_sidecar
    from pyhdt2_cython.hdt import Hdt
except ImportError:
    Hdt = None

HDT_IMAGE = (
    Path(__file__).resolve().parent.parent / "test_images" / "AFF4Std1a" / "Base-Linear.aff4"
)
IMAGE_STREAM = ARN("aff4://c215ba20-5648-4209-a793-1f918c723610")


def opidx_sidecar_for(image):
    """Build a real .opidx sidecar for the information.hdt in image."""
    with zipfile.ZipFile(image) as z:
        hdt = Hdt(z.read("information.hdt"))
    return write_opidx_sidecar(*hdt.op_index_arrays())


def open_and_read(image):
    """Open image and read the bytes at a known offset of its disk image stream."""
    with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(str(image))) as volume:
        with volume.resolver.AFF4FactoryOpen(IMAGE_STREAM) as stream:
            stream.SeekRead(0x163)
            return stream.Read(17)


@unittest.skipIf(Hdt is None, "pyhdt2_cython is needed to write the sidecars")
class HdtSidecarTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.image = os.path.join(self.tmpdir, "with-sidecars.aff4")
        shutil.copy(HDT_IMAGE, self.image)
        self.opidx = opidx_sidecar_for(HDT_IMAGE)
        with zipfile.ZipFile(self.image, "a") as z:
            z.writestr("information.hdt.opidx", self.opidx)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def testSidecarIsPassedToTheStore(self):
        with mock.patch.object(data_store.hdt_store, "HdtStore", wraps=hdt_store.HdtStore) as store:
            open_and_read(self.image)
        _, kwargs = store.call_args
        self.assertEqual(self.opidx, kwargs["opidx_bytes"])

    def testContainerWithoutSidecarPassesNone(self):
        with mock.patch.object(data_store.hdt_store, "HdtStore", wraps=hdt_store.HdtStore) as store:
            open_and_read(HDT_IMAGE)
        _, kwargs = store.call_args
        self.assertIsNone(kwargs["opidx_bytes"])

    def testImageReadsTheSameWithSidecars(self):
        self.assertEqual(b"Invalid partition", open_and_read(self.image))
        self.assertEqual(open_and_read(HDT_IMAGE), open_and_read(self.image))


if __name__ == "__main__":
    unittest.main()
