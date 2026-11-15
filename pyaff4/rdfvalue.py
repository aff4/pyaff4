# Copyright 2014 Google Inc. All rights reserved.
# Copyright © 2026 Apple Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

import urllib.parse
import urllib.request, urllib.parse, urllib.error

import os
import posixpath

import rdflib
from rdflib import URIRef


from typing import (
    Any,
)

# pylint: disable=protected-access

def parse_components(value: URIRef):
    components = urllib.parse.urlparse(value)

    # dont normalise path for http URI's
    if components.scheme and not components.scheme == "http":
        normalized_path = posixpath.normpath(components.path)
        if normalized_path == ".":
            normalized_path = ""

        components = components._replace(path=normalized_path)
    if not components.scheme:
        # For file:// URNs, we need to parse them from a filename.
        components = components._replace(
            netloc="",
            path=urllib.request.pathname2url(value),
            scheme="file")

    return components

class ARN(URIRef):
    def __eq__(self, other: Any) -> bool:
        """
        We might be comparing an ARN in code, with a URIRef that has been parsed from turtle
        Make sure they are equal
        """

        if type(self) is type(other):
            return str(self) == str(other)
        elif type(other) is URIRef:
            return str(self) == str(other)
        else:
            return False

    def __hash__(self):
        return super().__hash__()

    def Append(self, component, quote=True):
        (components, original_filename) = Parse(self.toPython())
        if quote:
            component = urllib.parse.quote(component)

        if components.scheme.startswith("http"):
            new_path = posixpath.normpath(posixpath.join(
                "/", components.path, component))
            components = components._replace(path=new_path)
            return URIRef(urllib.parse.urlunparse(components))
        elif components.scheme == "aff4":
            if components.path != u"":
                new_path = posixpath.normpath(posixpath.join(
                    "/", components.path, component))
            else:
                new_path = posixpath.normpath(component)
                new_path = "/" + new_path

            components = components._replace(path=new_path)

            # we dont rely on the basic urllib as our IRI scheme is not a regular URL scheme
            return ARN(u"%s://%s%s" % (components.scheme, components.hostname, components.path))
        elif components.scheme == "file" or components.scheme == "zip" :
            new_path = posixpath.normpath(posixpath.join(
                "/", components.path, component))
            components = components._replace(path=new_path)
            return FileRef(u"%s://%s" % (components.scheme, components.path))
        else:
            raise Exception("Not implemented")

    def RelativePath(self, urn):
        urn_value = urn.toPython()
        self_value = self.toPython()
        if urn_value.startswith(self_value):
            return urn_value[len(self_value):]

class FileRef(URIRef):
    def ToFilename(self):
        # For file: urls we exactly reverse the conversion applied in
        # FromFileName.
        value = self.toPython()
        if value.startswith("file:"):
            res = urllib.request.url2pathname(value[5:])
            if res.startswith("///"):
                res = res[2:]
            return res

        (components, original_filename) = Parse(value)
        if components.scheme == "file":
            return components.path

def Parse(value):
    components = urllib.parse.urlparse(value)
    original_filename = None
    # dont normalise path for http URI's
    if components.scheme and not components.scheme == "http":
        normalized_path = posixpath.normpath(components.path)
        if normalized_path == ".":
            normalized_path = ""

        components = components._replace(path=normalized_path)
    if not components.scheme:
        # For file:// URNs, we need to parse them from a filename.
        components = components._replace(
            netloc="",
            path=urllib.request.pathname2url(value),
            scheme="file")
        original_filename = value

    return (components, original_filename)


class URN():
    """Represent a URN.

    According to RFC1738 URLs must be encoded in ASCII. Therefore the
    internal representation of a URN is bytes. When creating the URN
    from other forms (e.g. filenames, we assume UTF8 encoding if the
    filename is a unicode string.
    """

    @classmethod
    def FromFileName(cls, filename):
        """Parse the URN from filename.

        Filename may be a unicode string, in which case it will be
        UTF8 encoded into the URN. URNs are always ASCII.
        """
        if filename[0] in ["/", "\\"]:
            # absolute path reference
            pass
        elif filename[1] == ":" and filename[2] in ["/", "\\"]:
            # windows path beginning with a drive letter
            pass
        else:
            # some kind of relative path
            filename = os.getcwd() + "/" + filename

        #result = cls("file://%s" % urllib.request.pathname2url(filename))
        #result.original_filename = filename
        #return result
        return FileRef("file://%s" % urllib.request.pathname2url(filename))

    @classmethod
    def NewURNFromFilename(cls, filename):
        return cls.FromFileName(filename)

    def ToFilename(self):
        # For file: urls we exactly reverse the conversion applied in
        # FromFileName.
        if self.value.startswith("file:"):
            res = urllib.request.url2pathname(self.value[5:])
            if res.startswith("///"):
                res = res[2:]
            return res

        (components, original_filename) = self.Parse()
        if components.scheme == "file":
            return components.path


def AssertURN(urn):
    if not isinstance(urn, URIRef):
        raise TypeError("Expecting a URIRef.")

# Custom RDF datatypes. See https://skeptric.com/rdflib-add-types/ for a good introduction.
# The following coerces our hashes to a string as the value
AFF4_HASH_TYPES = [ "http://aff4.org/Schema#SHA512",
    "http://aff4.org/Schema#SHA256",
    "http://aff4.org/Schema#SHA1",
    "http://aff4.org/Schema#MD5",
    "http://aff4.org/Schema#Blake2b",
    "http://aff4.org/Schema#blockMapHashSHA512",
    "http://afflib.org/2009/aff4#SHA512",
    "http://afflib.org/2009/aff4#SHA256",
    "http://afflib.org/2009/aff4#SHA1",
    "http://afflib.org/2009/aff4#MD5",
    "http://afflib.org/2009/aff4#blockMapHashSHA512" ]

for hash in AFF4_HASH_TYPES:
    rdflib.term.bind(datatype=rdflib.URIRef(hash),
                     pythontype=str,
                     datatype_specific=True)
