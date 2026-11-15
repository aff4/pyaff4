#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import crc32c

from pyhdt2_cython.hdt import Hdt


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "reference_images"

PHYSICAL = FIXTURES / "AFF4Std" / "Base-Linear.aff4"
PHYSICAL_HASHES = FIXTURES / "AFF4Std" / "Base-Linear-AllHashes.aff4"
PHYSICAL_STRIPED = FIXTURES / "AFF4Std" / "Striped" / "Base-Linear_1.aff4"
LOGICAL_DREAM = FIXTURES / "AFF4-L" / "deprecated" / "dream.aff4"
LOGICAL_UNICODE = FIXTURES / "AFF4-L" / "deprecated" / "unicode.aff4"


def run_cli(*args, cwd=None, timeout=120):
    return subprocess.run(
        [sys.executable, "-m", "pyaff4.cli", *args],
        cwd=cwd if cwd is None else str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def needs(*paths):
    missing = [str(p) for p in paths if not Path(p).exists()]
    return unittest.skipUnless(not missing, f"fixture(s) missing: {missing}")


class CliSmokeTest(unittest.TestCase):
    def test_help_exits_zero(self):
        r = run_cli("--help")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        for flag in (
            "--list", "--meta", "--verify", "--extract", "--extract-all",
            "--create-logical", "--append", "--terse",
        ):
            self.assertIn(flag, r.stdout)

    def test_no_args_fails(self):
        r = run_cli()
        self.assertNotEqual(r.returncode, 0)


class CliReadSideTest(unittest.TestCase):
    @needs(PHYSICAL)
    def test_list_physical(self):
        r = run_cli("-l", str(PHYSICAL))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("AFF4Container:", r.stdout)
        self.assertIn(str(PHYSICAL), r.stdout)
        # Base-Linear.aff4 is a fixed fixture; assert on the unique values its
        # metadata carries so a regression in metadata lookup or RDFObject
        # value extraction can't slip through (just asserting on labels would
        # still pass against the previous "section header but no values" bug).
        self.assertIn("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb (DiskImage)", r.stdout)
        self.assertIn("Size: 268435456 (bytes)", r.stdout)
        self.assertIn("Sectors: 524288", r.stdout)
        self.assertIn(
            "BlockMapHash: c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c"
            "364b3d6c56793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2",
            r.stdout,
        )
        self.assertIn("Case Description: Canonical Image Generation Test Case", r.stdout)
        self.assertIn("Case Name: Canonical Image Generation", r.stdout)
        self.assertIn("Examiner: Administrator", r.stdout)

    @needs(LOGICAL_DREAM)
    def test_list_logical(self):
        r = run_cli("-l", str(LOGICAL_DREAM))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("AFF4Container:", r.stdout)
        self.assertIn("aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83", r.stdout)
        self.assertIn("dream.txt", r.stdout)

    @needs(LOGICAL_UNICODE)
    def test_list_unicode_container(self):
        r = run_cli("-l", str(LOGICAL_UNICODE))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("aff4://daee60a5-6dc5-4b15-9c3f-a56f6b6e0438", r.stdout)
        # The fixture is a logical container holding seven named FileImage
        # members. Assert each one is listed so that an LogicalImageContainer
        # iteration regression (or a printLogicalImageInfo formatting change)
        # can't slip through.
        for name in (
            "./test_images/AFF4Std/Base-Allocated.aff4",
            "./test_images/AFF4Std/Base-Linear-AllHashes.aff4",
            "./test_images/AFF4Std/Base-Linear-ReadError.aff4",
            "./test_images/AFF4Std/Base-Linear.aff4",
            "./test_images/AFF4Std/README.txt",
            "./test_images/AFF4Std/Striped/Base-Linear_1.aff4",
            "./test_images/AFF4Std/Striped/Base-Linear_2.aff4",
        ):
            self.assertIn(name, r.stdout)

    @needs(PHYSICAL_STRIPED)
    def test_list_striped(self):
        r = run_cli("-l", str(PHYSICAL_STRIPED))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad", r.stdout)
        # Striped image fixture is an immutable physical container; pin its
        # disk-metadata fingerprints rather than just section labels.
        self.assertIn("aff4://951b3e29-6549-4266-8e81-3f88ddba61ae (DiskImage)", r.stdout)
        self.assertIn("Size: 268435456 (bytes)", r.stdout)
        self.assertIn("Sectors: 524288", r.stdout)
        self.assertIn(
            "BlockMapHash: 1bc643e0680978381ef519e6cc9d3f13ad1266257f29735cbff7f405"
            "3910acae1cc1b26ae93a28c269addca5736e4d4ca3a59987f130244f2331823848f80ce0",
            r.stdout,
        )

    @needs(PHYSICAL)
    def test_meta_physical(self):
        r = run_cli("-m", str(PHYSICAL))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        # Meta dumps the turtle: assert prefixes, the fixture's CaseDetails
        # block, the ImageStream block with its specific hashes, and the
        # Map subject — collectively a fingerprint of the fixture metadata.
        self.assertIn("@prefix aff4:", r.stdout)
        self.assertIn("@prefix xsd:", r.stdout)
        self.assertIn("aff4:CaseDetails", r.stdout)
        self.assertIn('aff4:caseDescription  "Canonical Image Generation Test Case"', r.stdout)
        self.assertIn('aff4:caseName         "Canonical Image Generation"', r.stdout)
        self.assertIn('aff4:examiner         "Administrator"', r.stdout)
        self.assertIn("aff4:ImageStream", r.stdout)
        self.assertIn("aff4://c215ba20-5648-4209-a793-1f918c723610", r.stdout)
        self.assertIn('"d5825dc1152a42958c8219ff11ed01a3"^^aff4:MD5', r.stdout)
        self.assertIn('"fbac22cca549310bc5df03b7560afcf490995fbb"^^aff4:SHA1', r.stdout)

    @needs(LOGICAL_DREAM)
    def test_meta_logical(self):
        r = run_cli("-m", str(LOGICAL_DREAM))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        # Pin specific facts of the dream.aff4 turtle: the AFF4 schema prefix,
        # the file image subject's full URN, the FileImage type, and the
        # fixture's stable MD5/SHA1 hashes plus declared size and source path.
        self.assertIn("@prefix aff4: <http://aff4.org/Schema#>", r.stdout)
        self.assertIn("@prefix xsd: <http://www.w3.org/2001/XMLSchema#>", r.stdout)
        self.assertIn(
            "<aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83//test_images/AFF4-L/dream.txt>",
            r.stdout,
        )
        self.assertIn("aff4:FileImage", r.stdout)
        self.assertIn('"75d83773f8d431a3ca91bfb8859e486d"^^aff4:MD5', r.stdout)
        self.assertIn('"9ae1b46bead70c322eef7ac8bc36a8ea2055595c"^^aff4:SHA1', r.stdout)
        self.assertIn("aff4:size 8688", r.stdout)
        self.assertIn('aff4:originalFileName "./test_images/AFF4-L/dream.txt"', r.stdout)

    @needs(PHYSICAL_HASHES)
    def test_verify_allhashes(self):
        r = run_cli("-v", str(PHYSICAL_HASHES))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("Verifying AFF4 File", r.stdout)
        # Pin each hash value the validator emits for this fixture so any
        # arithmetic regression in block_hasher (or in the underlying hash
        # primitives) is caught, not just the presence of "succeeded".
        map_urn = "aff4://2a497fe5-0221-4156-8b4d-176bebf7163f"
        self.assertIn(map_urn, r.stdout)
        for label, value in [
            ("mapIdxHash",
             "0e1f10b723fba3a4e40daae0aefb2557024f6639c701e2649faf6dcd23e7b3d3"
             "d304f19ab2a8b4d8d89b4349afedb8485de77bb70c4812acbe47c858ef183aad"),
            ("mapPointHash",
             "2add12a4a27e3167f5c03b0ee364dc6762d705b64963981b3dc5081d16ee1c70"
             "d7898b8f4eeb14d70a511755ae86e31321cd598db02e659af030c56fbf924b22"),
            ("mapPathHash",
             "ce1b4e71d96f17817a7f0f4077851aee8ccc4b624a1043c45b76b7fa567d1257"
             "8c6ea491cd3cce50b20cbb0136db809e56ba43fa3c963c26aac31074e3310f1a"),
            ("mapHash",
             "90359e6a413d0a81b3af01c7d536ab84825368c5beba44c7ecfe478b0c17c3d4"
             "8011aeb583e78ca90427c1f0a17ece976312de1c23e62275730c537a341657b9"),
            ("BlockMapHash",
             "72e3d91ddf6e73ede978af4f1e0fe3813cdfb50e2909b338005f5919c3d4a271"
             "e659c68483e0d8630f940b9f1cf1549e0a9da411f4bae394e6ae4db496527026"),
        ]:
            self.assertIn(f"{label} succeeded. Hash = {value}", r.stdout)
        self.assertNotIn("Hash failure", r.stdout)

    @needs(LOGICAL_DREAM)
    def test_terse_shortens_output(self):
        # `-t` strips the volume-URN prefix from member URNs. The effect is
        # only visible for logical containers (where members live under the
        # volume URN); for physical containers the image URN is independent
        # so trimVolume is a no-op. Use the logical fixture and assert the
        # specific transformation, not just "shorter".
        long_run = run_cli("-l", str(LOGICAL_DREAM))
        terse_run = run_cli("-t", "-l", str(LOGICAL_DREAM))
        self.assertEqual(long_run.returncode, 0, msg=long_run.stderr)
        self.assertEqual(terse_run.returncode, 0, msg=terse_run.stderr)

        full_member_urn = "aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83//test_images/AFF4-L/dream.txt"
        trimmed_form = "<//test_images/AFF4-L/dream.txt>"
        self.assertIn(f"<{full_member_urn}>", long_run.stdout)
        self.assertNotIn(f"<{full_member_urn}>", terse_run.stdout)
        self.assertIn(trimmed_form, terse_run.stdout)


class CliRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="aff4cli-it-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @needs(LOGICAL_DREAM)
    def test_extract_all(self):
        out = self.tmpdir / "extracted"
        out.mkdir()
        r = run_cli("-X", "-f", str(out), str(LOGICAL_DREAM))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        extracted = list(out.rglob("dream.txt"))
        self.assertEqual(len(extracted), 1, msg=f"expected one dream.txt under {out}")
        self.assertGreater(extracted[0].stat().st_size, 0)

    def test_create_list_extract_roundtrip(self):
        src = self.tmpdir / "hello.txt"
        payload = b"hello aff4 integration test\n"
        src.write_bytes(payload)
        container = self.tmpdir / "out.aff4"

        create = run_cli("-c", str(container), str(src))
        self.assertEqual(create.returncode, 0, msg=create.stderr)
        self.assertTrue(container.exists())

        listing = run_cli("-l", str(container))
        self.assertEqual(listing.returncode, 0, msg=listing.stderr)
        self.assertIn("hello.txt", listing.stdout)

        outdir = self.tmpdir / "extracted"
        outdir.mkdir()
        extract = run_cli("-X", "-f", str(outdir), str(container))
        self.assertEqual(extract.returncode, 0, msg=extract.stderr)
        extracted = list(outdir.rglob("hello.txt"))
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0].read_bytes(), payload)

    def test_append_logical(self):
        a = self.tmpdir / "a.txt"
        a.write_bytes(b"first\n")
        b = self.tmpdir / "b.txt"
        b.write_bytes(b"second\n")
        container = self.tmpdir / "out.aff4"

        self.assertEqual(run_cli("-c", str(container), str(a)).returncode, 0)
        self.assertEqual(run_cli("-c", "-a", str(container), str(b)).returncode, 0)

        r = run_cli("-l", str(container))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("a.txt", r.stdout)
        self.assertIn("b.txt", r.stdout)

    def test_verify_fresh_container_succeeds(self):
        src = self.tmpdir / "hello.txt"
        src.write_bytes(b"hello aff4\n")
        container = self.tmpdir / "out.aff4"

        self.assertEqual(run_cli("-c", str(container), str(src)).returncode, 0)
        r = run_cli("-v", str(container))
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("Verified", r.stdout)
        self.assertNotIn("Hash failure", r.stdout)

    @needs(LOGICAL_DREAM)
    def test_extract_all_default_folder_is_cwd(self):
        # Regression test for `default=[os.getcwd()]` fix in main(): with no -f
        # flag, extraction must land in the current working directory rather
        # than crashing on args.folder[0] returning the first character of cwd.
        cwd = self.tmpdir / "cwd"
        cwd.mkdir()
        r = run_cli("-X", str(LOGICAL_DREAM), cwd=cwd)
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        extracted = list(cwd.rglob("dream.txt"))
        self.assertEqual(len(extracted), 1, msg=f"dream.txt not extracted under {cwd}")


class CliErrorPathTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="aff4cli-it-err-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_missing_input_fails(self):
        r = run_cli("-l", str(self.tmpdir / "does-not-exist.aff4"))
        self.assertNotEqual(r.returncode, 0)

    def test_non_aff4_input_fails(self):
        bad = self.tmpdir / "not-an-aff4.aff4"
        bad.write_bytes(b"this is not a zip file at all")
        r = run_cli("-l", str(bad))
        self.assertNotEqual(r.returncode, 0)

    def test_verify_detects_tampered_hash(self):
        # Build a clean container, then mutate one hex character of a stored
        # hash literal in its metadata (information.turtle and information.hdt).
        # The verify path should both report `Hash failure` on stdout AND exit
        # non-zero (the latter is the regression test for the verify exit-code
        # wiring).
        good, bad = self._clean_container()
        data = Path(good).read_bytes()
        hdt = zipfile.ZipFile(good).read("information.hdt")
        at = data.index(hdt)
        before, after = data[:at], data[at + len(hdt):]
        forged = self._flip_hash(before) + self._forge_hdt_hash(hdt) + after
        Path(bad).write_bytes(forged)

        r = run_cli("-v", str(bad))
        self.assertNotEqual(r.returncode, 0,
                            msg=f"verify should fail on tampered hash; stdout={r.stdout!r}")
        self.assertIn("Hash failure", r.stdout)

    def test_verify_fails_on_a_corrupt_hdt(self):
        # A byte changed in information.hdt without its section CRC being fixed
        # up is caught when the HDT is read.
        good, bad = self._clean_container()
        data = Path(good).read_bytes()
        hdt = zipfile.ZipFile(good).read("information.hdt")
        at = data.index(hdt)
        Path(bad).write_bytes(data[:at] + self._flip_hash(hdt) + data[at + len(hdt):])

        r = run_cli("-v", str(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("CRC-32C mismatch", r.stderr)

    def _clean_container(self):
        src = self.tmpdir / "hello.txt"
        src.write_bytes(b"tamper test payload\n")
        good = self.tmpdir / "good.aff4"
        self.assertEqual(run_cli("-c", str(good), str(src)).returncode, 0)
        return good, self.tmpdir / "bad.aff4"

    @staticmethod
    def _flip_hash(data):
        """data with one hex char flipped in every hash literal.

        Patches at the byte level rather than rebuilding the zip via
        ``zipfile.writestr``: the AFF4 reader is sensitive to extra fields
        and compression metadata and will refuse a re-packed container,
        whereas an in-place byte flip leaves the zip structure intact.
        Same-length hex-for-hex substitution preserves member offsets, so
        the central directory still points at valid members. The mutated
        byte invalidates the zip CRC for that member, but pyaff4 doesn't
        verify zip CRCs during read, only the AFF4-level hash — which is
        exactly what we want to fail.
        """
        def flip(match):
            good = match.group(1)
            return b'"' + (b"1" if good[:1] != b"1" else b"0") + good[1:] + b'"'

        flipped, count = re.subn(rb'"([0-9a-f]{32,})"', flip, data)
        if count == 0:
            raise RuntimeError("no hex hash literal found in container bytes")
        return flipped

    @classmethod
    def _forge_hdt_hash(cls, hdt):
        """information.hdt with its hash literals flipped as _flip_hash does, and the objects
        section's CRC-32C recomputed so the HDT still reads."""
        packed = bytes(Hdt(hdt).objects.packed)
        at = hdt.index(packed)
        forged = cls._flip_hash(packed)
        crc = crc32c.crc32c(forged).to_bytes(4, "little")
        return hdt[:at] + forged + crc + hdt[at + len(packed) + 4:]

if __name__ == "__main__":
    unittest.main()
