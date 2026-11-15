#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from builtins import next
from builtins import str
from builtins import object

import argparse
import sys, os, errno, shutil, uuid, io
import time
import logging

import requests

from pyaff4 import container, version
from pyaff4 import lexicon, logical, escaping
from pyaff4 import rdfvalue, hashes
from pyaff4 import block_hasher, data_store, linear_hasher, zip
from pyaff4 import aff4_map

#logging.basicConfig(level=logging.DEBUG)

VERBOSE = False
TERSE = False

class SlackAPIMetadata(object):
    def __init__(self, arn, api_url, length, birthTime):
        self.api_url = api_url
        self.arn = arn
        self.length = length
        self.birthTime = birthTime

    def store(self, resolver):
        resolver.Set(volume.urn, self.arn, rdfvalue.URN(lexicon.AFF4_STREAM_SIZE), rdfvalue.XSDInteger(self.length))
        resolver.Set(volume.urn, self.arn, rdfvalue.URN("http://aff4.org/2024/Schema#apiUrl"), rdfvalue.XSDString(self.api_url))
        resolver.Set(volume.urn, self.arn, rdfvalue.URN(lexicon.standard11.birthTime), rdfvalue.XSDDateTime(self.birthTime))

def addStreamToVolume(resolver, volume, stream, stream_meta):
    stream_arn = stream_meta.arn
    length = stream_meta.length

    hasher = linear_hasher.StreamHasher(stream, [lexicon.HASH_SHA1, lexicon.HASH_MD5])

    if length > volume.maxSegmentResidentSize:
        volume.writeCompressedBlockStream(stream_arn, None, hasher)
        volume.resolver.Add(volume.urn, stream_arn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.AFF4_IMAGE_TYPE))
    else:
        volume.writeZipStream(stream_arn, None, hasher)
        volume.resolver.Add(volume.urn, stream_arn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.AFF4_ZIP_SEGMENT_IMAGE_TYPE))

    volume.resolver.Add(volume.urn, stream_arn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN("http://aff4.org/2024/Schema#APIStreamImage"))
    volume.resolver.Add(volume.urn, stream_arn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))

    stream_meta.store(resolver)
    for h in hasher.hashes:
        hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
        resolver.Add(volume.urn, stream_arn, rdfvalue.URN(lexicon.standard.hash), hh)
    stream.close()

container_name = "/tmp/testcontainer.aff4"

urls = ["https://slashdot.org", "https://cnn.com"]

with data_store.MemoryDataStore() as resolver:
    container_arn = rdfvalue.URN.FromFileName(container_name)

    with container.Container.createURN(resolver, container_arn, encryption=False) as volume:
        print("Creating AFF4Container: file://%s <%s>" % (container_name, volume.urn))
        for url in urls:
            response = requests.get(url)

            # this is a file like object containing the JSON or remote content - could be the JSON stream from the slack API
            stream = io.BytesIO(response.content)
            stream_arn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
            stream_meta = SlackAPIMetadata(stream_arn, url, len(response.content), "2020-09-05T05:25:26.125Z")

            addStreamToVolume(resolver, volume, stream, stream_meta)

