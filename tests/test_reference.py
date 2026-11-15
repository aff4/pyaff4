# Copyright 2018 Schatz Forensic Pty Ltd. All rights reserved.
# Copyright © 2026 Apple Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
import tempfile

from rdflib import Literal

from pyaff4 import data_store
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import aff4_map
from pyaff4 import container
from pyaff4.container import Container
from pyaff4 import zip
from pyaff4 import version

import unittest
import os


"""
Creates an container with virtual file called "pdf1" which is backed by a byte range in another image.
The byte range is the file called "2015-Schatz-Extending AFF4 for Scalable Acquisition Live Analysis.pdf", found
in the AFF4 Canonical Reference Image "AFF4Std/Base-Linear.aff4"
"""

stdLinear = os.path.join(
    os.environ.get(
        "REFERENCE_IMAGES",
        os.path.join(os.path.dirname(__file__), "..", "reference_images")),
    "AFF4Std", "Base-Linear.aff4")

class ReferenceTest(unittest.TestCase):
    fileName = tempfile.gettempdir() + u"/reference.aff4"

    def setUp(self):
        with data_store.MemoryDataStore() as resolver:
            # Use the AFF4 Standard Lexicon
            self.lexicon = lexicon.standard

            with zip.ZipFile.NewZipFile(resolver, version.aff4v10, rdfvalue.URN.FromFileName(stdLinear)) as src_zip:
                with container.ZipMemberContainer(resolver, None, src_zip) as src_member_container:
                    # there is generally only one Image in a container. Get the underlying Map
                    imageURN = next(resolver.QueryPredicateObject(src_member_container.urn, lexicon.AFF4_TYPE, self.lexicon.Image))
                    datastreams = list(resolver.QuerySubjectPredicate(src_member_container.urn, imageURN, self.lexicon.dataStream))
                    imageMapURN = datastreams[0]

                    # get a reference to the actual bytestream that is the forensic image
                    with resolver.AFF4FactoryOpen(imageMapURN) as mapStream:

                        # now that we have a reference to the forensic image, we start building up a new container
                        # to store our new artefacts in

                        # create a second resolver so we dont pollute our metadata with that of the first container
                        with data_store.MemoryDataStore() as resolver2:

                            # create our new container
                            destFileURN = rdfvalue.URN.FromFileName(self.fileName)
                            with zip.ZipFile.NewZipFile(resolver2, version.aff4v10, destFileURN, appendmode="truncate") as dest_zip:
                                with container.ZipMemberContainer(resolver2, None, dest_zip, version=version.aff4v10) as dest_member_container:
                                    self.volume_urn = dest_member_container.urn

                                    # create a "version.txt" file so readers can tell it is an AFF4 Standard v1.0 container
                                    version_urn = self.volume_urn.Append("version.txt")
                                    with dest_member_container.CreateMember(version_urn) as versionFile:
                                        versionFile.Write("major=1\nminor=0\ntool=pyaff4\n".encode("utf-8"))

                                    # create a map to represent the byte range we are interested in
                                    self.image_urn = self.volume_urn.Append("pdf1")
                                    with aff4_map.AFF4Map.NewAFF4Map(
                                            resolver2, dest_member_container, self.image_urn, self.volume_urn) as imageURN:
                                        # add the segment that refers to the file in the destination address space
                                        # the locations were determined by opening in a forensic tool
                                        partitionOffset = 0x10000
                                        fileOffset = 0xfc3000
                                        diskOffset = partitionOffset + fileOffset
                                        fileSize = 629087
                                        imageURN.AddRange(0, diskOffset, fileSize, mapStream.urn)



    def testReadMapOfImage(self):
        fileSize = 629087

        # take the lexicon from our new container
        (arn, ver, lex) = Container.identify(self.fileName)

        # setup a resolver
        resolver = data_store.MemoryDataStore(lex)

        # open the two containers within the same resolver (needed so the transitive links work)
        with zip.ZipFile.NewZipFile(resolver, ver, rdfvalue.URN.FromFileName(stdLinear)) as targetZip:
            with container.ZipMemberContainer(resolver, None, targetZip) as targetMC:
                with zip.ZipFile.NewZipFile(resolver, ver, rdfvalue.URN.FromFileName(self.fileName)) as sourceZip:
                    with container.ZipMemberContainer(resolver, None, sourceZip) as sourceMC:

                        # open the virtual file and read
                        image_urn = sourceMC.urn.Append("pdf1")
                        with resolver.AFF4FactoryOpen(image_urn) as image:
                            # check the size is right
                            self.assertEqual(629087, image.Size())

                            # read the header of the virtual file
                            image.SeekRead(0, 0)
                            self.assertEqual(b"%PDF", image.Read(4))

                            # read the whole virtual file and compare with a known hash of it
                            image.SeekRead(0, 0)
                            buf = image.Read(629087)
                            hash = hashes.new(lexicon.HASH_SHA1)
                            hash.update(buf)
                            self.assertEqual("5A2FEE16139C7B017B7F1961D842D355A860C7AC".lower(), hash.hexdigest())



if __name__ == '__main__':
    unittest.main()