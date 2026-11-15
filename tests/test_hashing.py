# Copyright 2016,2017 Schatz Forensic Pty Ltd. All rights reserved.
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
import os
import unittest
import logging

from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import plugins
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import hashes
from pyaff4 import block_hasher
from pyaff4 import linear_hasher
from pyaff4.rdfvalue import ARN

LOGGER = logging.getLogger("pyaff4")

referenceImagesPath = os.path.join(os.path.dirname(__file__), u"..",
                                   u"reference_images")
stdLinear = os.path.join(referenceImagesPath, u"AFF4Std", u"Base-Linear.aff4")
preStdLinear = os.path.join(referenceImagesPath, u"AFF4PreStd/Base-Linear.af4")
preStdAllocated = os.path.join(referenceImagesPath, u"AFF4PreStd",
                               u"Base-Allocated.af4")
stdLinear = os.path.join(referenceImagesPath, u"AFF4Std", u"Base-Linear.aff4")
stdAllocated = os.path.join(referenceImagesPath, u"AFF4Std",
                            u"Base-Allocated.aff4")
stdLinearAllHashes = os.path.join(referenceImagesPath,
                                  u"AFF4Std", u"Base-Linear-AllHashes.aff4")
stdLinearReadError = os.path.join(referenceImagesPath,
                                  u"AFF4Std", u"Base-Linear-ReadError.aff4")
stripedLinearA = os.path.join(referenceImagesPath,
                              u"AFF4Std", u"Striped", u"Base-Linear_1.aff4")
stripedLinearB = os.path.join(referenceImagesPath,
                              u"AFF4Std", u"Striped", u"Base-Linear_2.aff4")

def conditional_on_images(f):
    if not os.access(preStdLinear, os.R_OK):
        LOGGER.info("Test images not cloned into repository. Tests disabled."
                    "To enable them run `git submodule update --init`")

        def _decorator():
            print (f.__name__ + ' has been disabled')

        return _decorator
    return f



class RecordingListener(block_hasher.ValidationListener):
    """Records validation results instead of printing or raising."""

    def __init__(self):
        super().__init__()
        self.valid = {}
        self.invalid = []

    def onValidBlockHash(self, a):
        pass

    def onInvalidBlockHash(self, a, b, imageStreamURI, offset):
        self.invalid.append(("BlockHash", str(imageStreamURI), offset))

    def onValidHash(self, typ, hash, imageStreamURI):
        self.valid[(typ, str(imageStreamURI))] = str(hash)

    def onInvalidHash(self, typ, a, b, streamURI):
        self.invalid.append((typ, str(streamURI)))


# The aff4:imageStreamIndexHash and aff4:imageStreamHash stored on each ImageStream of the
# reference images that carry them, keyed by image path under reference_images.
STREAM_HASHES = {
    "AFF4Std/Base-Allocated.aff4": {
        "aff4://fce3df71-dce8-4a17-af67-36bed58f25c9": (
            "3d1b5407754358482885453b0bb6970a7f9d4fed0bf0a9c99df7b11a47b6e4ce"
            "f057bf562e10acff9928d6b724493a6cc05ef1ab381886f20ec85500785e1c10",
            "9fc93f63036b72ebbfe389661698f3f6307addcb7d7f9fee03c32b46cdf37ea2"
            "ae036bc90f62eee677a3b7bb2cbeda2617ed07e4ff53aecc02e9821803ee59f3",
        ),
    },
    "AFF4Std/Base-Linear-AllHashes.aff4": {
        "aff4://e53a108a-bb2e-41f4-ab2e-28fe4ef578c1": (
            "c663bc90d996d2c9699e00dc1ea2c55b3724f1eaca2b92119bb7c764aad222ee"
            "d321cb00ee67899c027f6837a3bd8f789a96adb6e9df51629b3cac0b6f9f0722",
            "f333238ff3e2c817628e81e3e40020da7ca6e4ecd2e3476fbba63aa246274584"
            "87337725b01075ed2aefaac69d74fd789b2e18fc255fd1c4316e6ca159ce54c6",
        ),
    },
    "AFF4Std/Base-Linear-ReadError.aff4": {
        "aff4://4b4396f1-0b68-4be0-af0f-5bf4667fe27b": (
            "128421bcf362e02817efe1d92f65e0e7fd836f8439f9e40eff7a357145f92192"
            "95336fa1412bb5ec3a62ae41f60816a02af2c686725f3a4aa2a975ff683f38e7",
            "3a0574abf41c8b4cd394a12195e3ca38c419718636b0f9fb6e7c3a0a067ba860"
            "4b403908a407aab212949f12e21ff4acdbc1de3301e357a7f80c3fe0609e9a24",
        ),
    },
    "AFF4Std/Base-Linear.aff4": {
        "aff4://c215ba20-5648-4209-a793-1f918c723610": (
            "c663bc90d996d2c9699e00dc1ea2c55b3724f1eaca2b92119bb7c764aad222ee"
            "d321cb00ee67899c027f6837a3bd8f789a96adb6e9df51629b3cac0b6f9f0722",
            "7c909ad458a90ca083cf2d10848fb3aaee7d9ac008605f85aef1ac2db8249973"
            "ac7b6716f3250edb80219ff628d6fb4873c33c59de0a3e6c7657e234e7ba0db3",
        ),
    },
    "AFF4Std/Striped/Base-Linear_1.aff4": {
        "aff4://a04a9189-5e92-4024-a577-37d6cfa72594": (
            "2364325d0822af6bbd5221813ac04d957f39c652de4a8151ebd8bea4b571f1a5"
            "f2dde0ba7a2dc274a936705b2e08dc9d6d957cf24ba7e7304cdd5e8aa19a8127",
            "574e12d53b6a609ad7340cbd7359243fe058876381cd82d6357da19052ed8900"
            "7aa6e2e63587ef8605c9de41691cd12689257e513af8c30a6777f6840c6d76b7",
        ),
    },
    "AFF4Std/Striped/Base-Linear_2.aff4": {
        "aff4://3bf0bd14-1ef9-4185-8b0a-2c7d511b4d30": (
            "09a5148b36ac629eb48af0f60263a7dcb81e186908b50544561954acd32810f9"
            "4a19554d5f906363079a03e4186ee9fe73860fbd0e87a2e55a31dc1dafd79e07",
            "30dfba8269539ee364361d17b4518c32cd367079aa99ff7ee96918ec027ecbce"
            "ff1334f1f2ed2f1046ef433c6ceaf644b7dd55401e7dda46ad1393be73ee24a8",
        ),
    },
    "Errata/Base-ExabyteSparse.aff4": {
        "aff4://7f7384be-4d97-4de5-97ee-8aa5e33b6eca": (
            "66da73aeb20aa17ad0ffbe6e8e7599e060abcc5432d2921367fcfe01df7fe882"
            "c0dbb0f022cd641a60c4cebbf62dadc0b69eb19178565351a8cb55812853b371",
            "37cd05833d2c6ba62dbb69afe80141f114f334f476c3183a4916f526db299314"
            "6bfb85f411c585fab90816a0c5d7d18948b19e87274e640006c75f1a6d3bdaaf",
        ),
    },
}


class ImageStreamHashTests(unittest.TestCase):
    """Every reference image that stores aff4:imageStreamIndexHash and aff4:imageStreamHash
    has each of them checked, and each matches."""

    def validate(self, *images):
        listener = RecordingListener()
        urns = [rdfvalue.URN.FromFileName(os.path.join(referenceImagesPath, i)) for i in images]
        validator = block_hasher.Validator(listener)
        if len(urns) == 1:
            validator.validateContainer(urns[0])
        else:
            validator.validateContainerMultiPart(*urns)
        return listener

    def expected(self, *images):
        out = {}
        for image in images:
            for stream, (index_hash, stream_hash) in STREAM_HASHES[image].items():
                out[("ImageStreamIndexHash", stream)] = index_hash
                out[("ImageStreamHash", stream)] = stream_hash
        return out

    @staticmethod
    def stream_hash_results(listener):
        return {k: v for k, v in listener.valid.items()
                if k[0] in ("ImageStreamIndexHash", "ImageStreamHash")}

    def test_single_part_images(self):
        for image in ("AFF4Std/Base-Linear.aff4", "AFF4Std/Base-Linear-AllHashes.aff4",
                      "AFF4Std/Base-Linear-ReadError.aff4", "AFF4Std/Base-Allocated.aff4",
                      "Errata/Base-ExabyteSparse.aff4"):
            with self.subTest(image=image):
                listener = self.validate(image)
                self.assertEqual([], listener.invalid)
                self.assertEqual(self.expected(image), self.stream_hash_results(listener))

    def test_striped_image_in_either_part_order(self):
        parts = ("AFF4Std/Striped/Base-Linear_1.aff4", "AFF4Std/Striped/Base-Linear_2.aff4")
        for order in (parts, parts[::-1]):
            with self.subTest(order=order):
                listener = self.validate(*order)
                self.assertEqual([], listener.invalid)
                self.assertEqual(self.expected(*parts), self.stream_hash_results(listener))


class ValidatorTest(unittest.TestCase):
    preStdLinearURN = rdfvalue.URN.FromFileName(preStdLinear)
    preStdAllocatedURN = rdfvalue.URN.FromFileName(preStdAllocated)
    stdLinearURN = rdfvalue.URN.FromFileName(stdLinear)
    stdAllocatedURN = rdfvalue.URN.FromFileName(stdAllocated)
    stdLinearAllHashesURN = rdfvalue.URN.FromFileName(stdLinearAllHashes)
    stdLinearReadErrorURN = rdfvalue.URN.FromFileName(stdLinearReadError)
    stripedLinearAURN = rdfvalue.URN.FromFileName(stripedLinearA)
    stripedLinearBURN = rdfvalue.URN.FromFileName(stripedLinearB)

    #@conditional_on_images
    def testBlockHashPreStdLinearImage(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.preStdLinearURN)

    #@conditional_on_images
    def testLinearHashPreStdLinearImage(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.preStdLinearURN,
            ARN("aff4://085066db-6315-4369-a87e-bdc7bc777d45"),
            lexicon.HASH_SHA1)
        print(dir(hash))
        print(hash.value)
        self.assertEqual(hash.value, "5d5f183ae7355b8dc8938b67aab77c0215c29ab4")

    #@conditional_on_images
    def testLinearHashPreStdPartialAllocatedImage(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.preStdAllocatedURN,
            ARN("aff4://48a85e17-1041-4bcc-8b2b-7fb2cd4f815b"), lexicon.HASH_SHA1)
        print(dir(hash))
        print(hash.value)
        self.assertEqual(hash.value, "a9f21b04a0a77613a5a34ecdd3af269464984035")

    #@conditional_on_images
    def testBlockHashPreStdPartialAllocatedImage(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.preStdAllocatedURN)

    #@conditional_on_images
    def testBlockHashStdLinearImage(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.stdLinearURN)

    #@conditional_on_images
    def testBlockHashStdLinearReadError(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.stdLinearReadErrorURN)

    #@conditional_on_images
    def testHashStdLinearImage(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.stdLinearURN,
            ARN("aff4://fcbfdce7-4488-4677-abf6-08bc931e195b"), lexicon.HASH_SHA1)
        print(dir(hash))
        print(hash.value)
        self.assertEqual(hash.value, "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d")

    #@conditional_on_images
    def testHashStdLinearReadError(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.stdLinearReadErrorURN,
            ARN("aff4://b282d5f4-333a-4f6a-b96f-0e5138bb18c8"), lexicon.HASH_SHA1)
        print(dir(hash))
        print(hash.value)
        self.assertEqual(hash.value, "67e245a640e2784ead30c1ff1a3f8d237b58310f")

    #@conditional_on_images
    def testHashStdPartialAllocatedImage(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.stdAllocatedURN,
            ARN("aff4://e9cd53d3-b682-4f12-8045-86ba50a0239c"), lexicon.HASH_SHA1)
        self.assertEqual(hash.value, "e8650e89b262cf0b4b73c025312488d5a6317a26")

    #@conditional_on_images
    def testBlockHashStdLinearStriped(self):
        validator = block_hasher.Validator()
        validator.validateContainerMultiPart(self.stripedLinearBURN,
                                             self.stripedLinearAURN)

    #@conditional_on_images
    def testHashStdLinearStriped(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hashMulti(
            self.stripedLinearBURN, self.stripedLinearAURN,
            ARN("aff4://2dd04819-73c8-40e3-a32b-fdddb0317eac"), lexicon.HASH_SHA1)
        self.assertEqual(hash.value, "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d")

    #@conditional_on_images
    def testBlockHashStdContainerPartialAllocated(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.stdAllocatedURN)

    #@conditional_on_images
    def testBlockHashStdLinearAllHashesImage(self):
        validator = block_hasher.Validator()
        validator.validateContainer(self.stdLinearAllHashesURN)

    #@conditional_on_images
    def testHashStdLinearAllHashesImage(self):
        validator = linear_hasher.LinearHasher()
        hash = validator.hash(
            self.stdLinearAllHashesURN,
            ARN("aff4://2a497fe5-0221-4156-8b4d-176bebf7163f"),
            lexicon.HASH_SHA1)

        print(dir(hash))
        print(hash.value)
        self.assertEqual(hash.value, "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d")

if __name__ == '__main__':
    unittest.main()
