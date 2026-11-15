# Fixture sources

| File | Notes |
|---|---|
| `synthetic.ttl` | Hand-written source of the two `synthetic*.hdt` files. Each block exercises one kind of term or structure; every dictionary section holds more than 16 entries. |
| `synthetic.hdt` | `synthetic.ttl` converted by hdt-cpp 1.3.3: `rdf2hdt -f turtle -B "http://example.org/" synthetic.ttl synthetic.hdt` |
| `synthetic-java.hdt` | `synthetic.ttl` converted by hdt-java 2.1.2 with Jena 3.13.1: `RDF2HDT -rdftype turtle -base "http://example.org/" synthetic.ttl synthetic-java.hdt` |
| `datatype-variants.hdt` | Typed literals, including the AFF4 hash datatypes. |
| `java-hdtv1.hdt` | Written by hdt-java. |
| `hdtv1-failing-utf8.hdt` | Two triples whose strings contain U+0000, in a NUL-terminated section (type 2): the UTF-8 NUL byte problem. |
| `hdt-ng-utf8.hdt` | The same strings in a length-prefixed section (type 8, PlainFrontCodingUtf8). |
| `hdt-ng-utf8-deprecated.hdt` | The same strings in the earlier length-prefixed, NUL-terminated section (type 7). |
| `opidx-golden.opidx` | Written by a Java HDT writer. The layout is described at `write_opidx_sidecar` in `pyhdt2_cython/build.py`. |
| `build-golden/` | Written by pyaff4. See `build-golden/README.md`. |

## Literal text is stored raw

hdt-cpp and hdt-java store the text between a literal's quotes as it is: a backslash, quote,
newline or tab is stored as itself, not escaped. pyaff4 reads and writes literals the same way.
pyaff4 writes every dictionary section as type 8, so terms may also contain U+0000, which a
NUL-terminated (type 2) section cannot hold.

## How the third-party conversions differ from the Turtle

- hdt-java stores `"v"^^xsd:string` as `"v"` and lowercases language tags, as Jena does. hdt-cpp
  keeps both as written.

## Lookups that miss on these files

`tests/test_rdflib_hdt_ng/test_hdtstore.py` (`ThirdPartyWriterTests`) pins the first two
and skips the third:

- rdflib rewrites some typed lexical forms when it builds a `Literal` (`"1.0E0"^^xsd:double`
  becomes `"1.0"`, `"…09.131Z"^^xsd:dateTime` becomes `"…09.131000+00:00"`), so a lookup with the
  rdflib term does not match the stored string. Both files.
- Lookups lowercase language tags, so `"colour"@en-GB` does not match hdt-cpp's stored
  `"colour"@en-GB`. `synthetic.hdt` only.
- Lookups write `"v"^^xsd:string` as `"v"`, so they do not match hdt-cpp's stored
  `"v"^^<…#string>`. `synthetic.hdt` only.

## Rebuilding the hdt-java fixture

hdt-java 2.1.2 needs Jena 3.13.1 (not 5.x or 6.x) and its runtime dependencies on the class path:
hdt-api, hdt-java-core and hdt-java-cli 2.1.2; jcommander 1.82; jena-core, jena-arq, jena-base,
jena-iri and jena-shaded-guava 3.13.1; commons-compress 1.18, commons-lang3 3.9, commons-io 2.6,
commons-math3 3.6.1, commons-codec 1.10, commons-collections4 4.1, commons-csv 1.5; libthrift
0.12.0; jackson-core, -databind and -annotations 2.9; jsonld-java 0.12.1; httpclient 4.5.2,
httpcore 4.4.4; collection 0.7; slf4j-api 1.7. The main class is `org.rdfhdt.hdt.tools.RDF2HDT`.
