class RDFObject(object):
    def __init__(self, URN, resolver, lexicon):
        self.resolver = resolver
        self.urn = URN
        self.lexicon = lexicon

    def __getattr__(self, item):
        #print self.resolver.DumpToTurtle()
        val = self.resolver.Get(self.urn, self.lexicon.of(item))
        return val