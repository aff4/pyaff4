
def toDirectivesAndTripes(text):
    directives = []
    triples = []

    in_directives = True
    for line in text.splitlines():
        if in_directives:
            if line.startswith("@"):
                directives.append(line)
                continue
            elif line == "":
                in_directives = False
        else:
            triples.append(line)

    return (u"\r\n".join(directives), u"\r\n".join(triples))



def difference(a, b):
    aset = set(a.split(u"\r\n"))
    bset = set(b.split(u"\r\n"))
    return aset.difference(bset)