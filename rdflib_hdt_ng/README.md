# RDF & HDT examples

# CLI

The `pyhdtcli` command lists or queries an HDT file: `pyhdtcli -l graph.hdt`
prints every triple, and `pyhdtcli -q S P O graph.hdt` those matching a
pattern, with `?` for any term.

## Code examples
```python
import rdflib
from rdflib import Literal, URIRef
from rdflib_hdt_ng import HdtStore

with open("graph.hdt", "rb") as f:
    g = rdflib.Graph(HdtStore(f.read()))
for s, p, o in g.triples(
    (None, URIRef("http://example.org/vocab#label"), Literal("Alpha", lang="en"))
):
    print(s)
```

```python
from pyhdt2_cython import PyHdt

hdt = PyHdt.from_triples([("http://ex.org/s", "http://ex.org/p", '"hello"@en')])
for t in hdt.triples_with_pattern(None, "http://ex.org/p", None):
    print(t.subject, t.predicate, t.object)
hdt.write("graph.hdt")
```

