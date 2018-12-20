"""Some utility functions."""
from __future__ import unicode_literals
__author__ = "Michael Cohen <scudette@gmail.com>"

import six
from future import types

def SmartStr(string, encoding="utf8"):
    """Forces the string to be an encoded byte string."""
    if six.PY3:
        if isinstance(string, str):
            return string.encode(encoding, "ignore")

        elif isinstance(string, bytes):
            return string

        elif hasattr(string, "__bytes__"):
            return string.__bytes__()

        return str(string).encode(encoding)

    if six.PY2:
        if type(string) is str:
            return string

        elif type(string) is unicode:
            return string.encode(encoding)

        elif hasattr(string, "__bytes__"):
            return string.__bytes__()

        return unicode(string).encode(encoding)


def SmartUnicode(string, encoding="utf8"):
    """Forces the string into a unicode object."""
    if six.PY3:
        if isinstance(string, bytes):
            return string.decode(encoding)

        # Call the object's __str__ method which should return an unicode
        # object.
        return str(string)

    elif six.PY2:
        if isinstance(string, str):
            return string.decode(encoding)

        return unicode(string)


def AssertStr(string):
    if six.PY3:
        if type(string) is not bytes:
            raise RuntimeError("String must be bytes.")

    elif six.PY2:
        if type(string) not in (str, types.newstr):
            raise RuntimeError("String must be bytes.")


def AssertUnicode(string):
    if six.PY3:
        if type(string) is not str:
            raise RuntimeError("String must be unicode.")

    elif six.PY2:
        if type(string) not in (unicode, types.newstr):
            raise RuntimeError("String must be unicode.")

# TODO. This is so ugly. Need to go through and fix all calls to Get to make
# sure they are expecting an array or generator in response
def asList(a, b):
    a_islist = isinstance(a, list)
    b_islist = isinstance(b, list)

    if a == None:
        if b_islist:
            return b
        else:
            return [b]
    elif b == None:
        if a_islist:
            return a
        else:
            return [a]
    else:
        if a_islist and b_islist:
            a.extend(b)
            return a
        elif b_islist:
            b.append(a)
            return b
        elif a_islist:
            a.append(b)
            return a
        else:
            return [a,b]
