from pathlib import Path

HDT_FIXTURES = Path(__file__).resolve().parent / "hdt_fixtures"
# The well-formed graphs that query and term tests check against a full scan.
HDT_GRAPHS = tuple(
    HDT_FIXTURES / name
    for name in (
        "datatype-variants.hdt",
        "hdt-ng-utf8-deprecated.hdt",
        "hdt-ng-utf8.hdt",
        "synthetic.hdt",
        "synthetic-java.hdt",
    )
)
