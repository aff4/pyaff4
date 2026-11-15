class RDFObject:
    def __init__(self, URN, resolver, lexicon):
        self.resolver = resolver
        self.urn = URN
        self.lexicon = lexicon

    def __getattr__(self, item):
        from pyaff4.lexicon import any as any_graph
        values = self.resolver.Get(any_graph, self.urn, self.lexicon.of(item))
        return next(iter(values), None)