# AFF4 -The Advanced Forensics File Format

The Advanced Forensics File Format 4 (AFF4) is an open source format used for
the storage of digital evidence and data.

It was originally designed and published in [1] and has since been standardised
as the AFF4 Standard v1.0, which is available at
https://github.com/aff4/Standard.

The focus of this implementation is:
1. Standards compliance with AFF4 Standard v1.0 (for physical images)
2. Ongoing development of the AFF4-L Standard v1.0 (for logical images)

Canonical images for the v1.0 physical image specification are provided in the
AFF4 Reference Images github project at https://github.com/aff4/ReferenceImages

## What is currently supported.

1. Reading, writing & appending to ZipFile style volumes.
2. Reading striped ZipFile volumes.
2. Reading & writing AFF4 ImageStreams using the deflate or snappy compressor.
3. Reading RDF metadata using Turtle and HDT (see below).
4. Verification of linear and block hashed images.
5. Reading & writing logical images.
6. Reading & writing deduplicated logical images.
7. Encrypted AFF4 logical volumes.

## RDF metadata and HDT

AFF4 metadata is RDF. Containers always store it as Turtle and optionally as
[Header Dictionary Triples](https://www.rdfhdt.org/) (`information.hdt`), a compressed, queryable binary form which supports fast
opening of large containers. 

- Nothing is unpacked: the dictionary, bitmaps and packed sequences of the HDT strucure are read in
  place. An optional `.opidx` sidecar (as the Java tools write, and as a
  container may hold as `information.hdt.opidx`) saves building the object
  index.
- Wheels are `cp312-abi3` for Linux (manylinux2014, x86_64 and aarch64),
  macOS 11+ (x86_64 and arm64) and Windows (x86_64 and arm64). Other platforms
  get the `py312-none-any` wheel, which runs the HDT kernels interpreted and is
  about 100× slower on HDT queries.

pyaff4 bundles two packages for HDT:

- `rdflib_hdt_ng`: a read-only `rdflib.Store` over HDT bytes, and
  `graph_to_hdt` to write an rdflib graph as HDT.
- `pyhdt2_cython`: the HDT reader and writer behind it, in Python and NumPy
  with the hot loops compiled by Cython.

### UTF-8 extended HDT format
HDT v1 relies on NULL terminators for determining the end of strings (and hence length), which fails for valid UTF-8 strings containing the Unicode NUL code point.

This implementation reads and writes HDT serializations which include the full range of UTF-8, by defining a new DictionarySection type. pyaff4 writes every dictionary section in this type, and reads it alongside the standard type 2. hdt-cpp 1.3.3 and hdt-java 2.1.2 cannot read type 8, so they cannot read the HDT files pyaff4 writes.
With reference section 4 of "HDT Binary Format" (2015) [1], the newly defined PlainFrontCodingUtf8 = 8 dictionary section reuses the design of the existing PlainFrontCoding DictionarySection, instead employing a length-prepended string encoding, per the following structure:

```
<Buffer of Blocks>
 <VByte size of following string in bytes>
 <First String of Block>
 <VByte count of Common prefix characters> <VByte size of following string in bytes> <Suffix String>
 … as many times as necessary to fit "BlockSize" strings.
<CRC32 of Buffer of Blocks>
```

The included test file "hdtv1-failing-utf8.hdt" contains two triples constructed from such strings which demonstrate the limitation,
while the test file "hdt-ng-utf8.hdt" demonstrates the proposed new UTF-8 capable variant of format.

Literal text is stored raw, as hdt-java and hdt-cpp store it: the characters between a literal's quotes are stored as they are, without N-Triples escapes, and a reader finds the end of the text at the last `"`.

## Porting from v0.x

pyaff4 2.x needs Python 3.12 or later. While 2.x is in pre-release, install it
with `pip install --pre pyaff4`; without `--pre`, pip installs 0.x. The
command-line tool is the `aff4` entry point. Code written against 0.x needs
these changes:

| 0.x | 2.x |
|---|---|
| `rdfvalue.XSDString`, `XSDInteger`, `XSDDateTime`, … | `rdflib.Literal(value, datatype=XSD.…)` |
| `rdfvalue.URN("aff4://…")` | `rdfvalue.ARN("aff4://…")`, an `rdflib.URIRef`. `URN()` takes no arguments; use `URN.FromFileName(path)` for files |
| Lexicon constants are strings, wrapped in `rdfvalue.URN(...)` | Lexicon constants are `URIRef`s; pass them directly |
| `hashes.newImmutableHash(hexdigest, hash_type)` | `rdflib.Literal(hexdigest, datatype=hash_type)` |
| `pyaff4.utils` (`SmartUnicode`, `SmartStr`, …) | Removed; use `str()` and `bytes` |
| `Container.createURN` returns a hash-based container unless `zip_based=True` | It returns a logical container; pass `hashbased=True` for a hash-based one |
| `createURN(compression_method=…)` and `writeLogicalStream(…, allow_large_zipsegments=True)` | `createURN(zipstream_compression_method=…, always_write_zipstreams=True)`, set once per container |
| Metadata in `information.turtle` only | Containers also hold `information.hdt` and its `.opidx` index, which readers prefer; encrypted containers keep Turtle only |
| The local header of a zip member has a Zip64 field only when needed | It always has one, so each member is 20 bytes larger than 0.x wrote it |
| Google Cloud Storage backend (`aff4_cloud`), `aes_keywrap` module | Removed; key wrapping uses `cryptography`'s `aes_key_wrap` |
| `fastchunking` for hash-based containers; `snappy` optional | `fastcdc`; `python-snappy` is a required dependency |

## Development

`uv sync` installs pyaff4 editable and compiles the HDT kernels. The tests also
read the AFF4 reference images from the `reference_images` submodule: clone with
`--recurse-submodules`, or run `git submodule update --init`.

```bash
just test             # all tests, then the HDT engine's tests with interpreted kernels
just build            # sdist and a wheel for this host
just release-build    # cross-build, audit and install-test every release wheel (Linux)
python cicd/lint_kernels.py   # no CPython API calls in the compiled hot loops
```

## References

[1] "Extending the advanced forensic format to accommodate multiple data
sources, logical evidence, arbitrary information and forensic workflow" M.I.
Cohen, Simson Garfinkel and Bradley Schatz, digital investigation 6 (2009)
S57-S68.
