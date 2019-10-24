# AFF4 -The Advanced Forensics File Format

The Advanced Forensics File Format 4 (AFF4) is an open source format used for
the storage of digital evidence and data.

It was originally designed and published in [1] and has since been standardised
as the AFF4 Standard v1.0, which is available at
https://github.com/aff4/Standard. This project is a work in progress
implementation, providing two library implementations, C/C++ and Python.

## What is currently supported.

The focus of this implementation is reading physical images conforming with the
AFF4 Standard v1.0, and for the ongoing development of an AFF4 based logical
image standard.

Canonical images for the v1.0 physical image specification are provided in the
AFF4 Reference Images github project at https://github.com/aff4/ReferenceImages

1. Reading, writing & appending to ZipFile style volumes.
2. Reading striped ZipFile volumes.
2. Reading & writing AFF4 ImageStreams using the deflate or snappy compressor.
3. Reading RDF metadata using Turtle (and to some degree YAML).
4. Verification of linear and block hashed images.
5. Reading & writing logical images (*new*) .
6. Reading & writing deduplicated logical images (*new*).
7. Encrypted AFF4 logical volumes (*new*).

## What is not yet supported:

The write support in the libraries is currently broken and being worked on.
Other aspects of the AFF4 that have not yet been implemented in this codebase
include:

1. Persistent data store (resolver).
2. HTTP backed streams.
3. Support for signed statements or Bill of Materials.
4. Directory based volumes.

## Notice

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google and Schatz Forensic.

## References

[1] "Extending the advanced forensic format to accommodate multiple data
sources, logical evidence, arbitrary information and forensic workflow" M.I.
Cohen, Simson Garfinkel and Bradley Schatz, digital investigation 6 (2009)
S57-S68.
