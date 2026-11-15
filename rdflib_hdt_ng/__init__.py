#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""rdflib Store backend over HDT (Header Dictionary Triples)."""

from .hdt_store import HdtStore
from .rdflib_bridge import graph_to_hdt, graph_to_hdt_bytes

__all__ = ["HdtStore", "graph_to_hdt", "graph_to_hdt_bytes"]
