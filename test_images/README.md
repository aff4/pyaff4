# pyaff4 test images

Test inputs specific to pyaff4. The AFF4 Canonical Reference Images are in the
`reference_images` submodule (https://github.com/aff4/ReferenceImages); run
`git submodule update --init` to fetch them.

- `AFF4Std1a/Base-Linear.aff4`: the AFF4Std Base-Linear image with its metadata
  also stored as `information.hdt` (HDT metadata tests).
- `AFF4-L/streamless-image.aff4`: a logical image with no data streams.
- `AFF4-L/paper-hash_based_disk_imaging_using_aff4.pdf` and its `.frag.1` and
  `.frag.2` pieces: deduplication inputs.
- `keys/certificate.pem` and `keys/key.pem`: a test-only X.509 certificate and
  private key for certificate-wrapped keybags.
