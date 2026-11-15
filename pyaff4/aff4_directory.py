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

"""This module implements the Directory AFF4 Volume."""
import logging
import os

from rdflib import Literal, URIRef

from pyaff4 import aff4
from pyaff4 import aff4_file
from pyaff4 import aff4_utils
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import escaping

LOGGER = logging.getLogger("pyaff4")


class AFF4Directory(aff4.AFF4Volume):

    root_path = ""

    @classmethod
    def NewAFF4Directory(cls, resolver, version, root_urn, appendmode=None):
        result = AFF4Directory(resolver, None, None)
        result.version = version
        result.root_path = root_urn.ToFilename()
        result.mode = appendmode

        if appendmode == "truncate":
            aff4_utils.RemoveDirectory(result.root_path)

        if not (os.path.isdir(result.root_path) or
                os.path.isfile(result.root_path)):
            if appendmode in ("truncate", "append"):
                aff4_utils.MkDir(result.root_path)
            elif appendmode is None:
                # Read-only open of an existing directory volume; the path
                # must already exist.
                raise RuntimeError("AFF4Directory storage does not exist: %s"
                                   % result.root_path)
            else:
                raise RuntimeError("Unknown mode: %s" % appendmode)

        resolver.Set(lexicon.transient_graph, result.urn, lexicon.AFF4_TYPE,
                     URIRef(lexicon.AFF4_DIRECTORY_TYPE))

        resolver.Set(lexicon.transient_graph, result.urn, lexicon.AFF4_STORED,
                     URIRef(root_urn))

        result.LoadFromURN()
        result.properties.writable = appendmode in ("truncate", "append")

        return resolver.CachePut(result)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.children = set()
        self.mode = None

    def Close(self):
        pass

    def ContainsSegment(self, child_arn):
        localpath = escaping.member_name_for_file_iri(str(child_arn))
        if os.path.exists(localpath):
            return True
        return False

    def CreateMember(self, child_urn):
        # Check that child is a relative path in our URN.
        relative_path = self.urn.RelativePath(child_urn)
        if relative_path is None or relative_path == str(child_urn):
            raise IOError("Child URN is not within container URN.")

        # Use this filename. Note that since filesystems can not typically
        # represent files and directories as the same path component we can not
        # allow slashes in the filename. Otherwise we will fail to create
        # e.g. stream/0000000 and stream/0000000/index.
        filename = escaping.member_name_for_urn(
            child_urn, self.version, self.urn)
        absolute_path = self.root_path + os.sep + filename

        # Persist the member's type so it survives turtle round-trip;
        # AFF4_FILE_NAME is just a session-only filesystem binding.
        self.resolver.Set(self.urn, child_urn, lexicon.AFF4_TYPE,
                          URIRef(lexicon.AFF4_FILE_TYPE))
        self.resolver.Set(self.urn, child_urn, URIRef(lexicon.AFF4_DIRECTORY_CHILD_FILENAME),
                          Literal(filename))
        self.resolver.Set(lexicon.transient_graph,
            child_urn, lexicon.AFF4_FILE_NAME,
            Literal(absolute_path))

        # Construct the FileBackedObject directly with appendmode="truncate"
        # rather than going through AFF4FactoryOpen — the directory volume
        # always wants to write fresh files, and AFF4FactoryOpen has no way
        # to thread an appendmode kwarg through to the handler.
        result = aff4_file.FileBackedObject(
            self.resolver, child_urn, self, appendmode="truncate")
        result.LoadFromURN()
        self.resolver.ObjectCache.Put(result, True)
        result.Prepare()

        self.MarkDirty()
        self.children.add(child_urn)

        return result

    def LoadFromURN(self):
        self.storage = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        if not self.storage:
            LOGGER.error("Unable to find storage for AFF4Directory %s",
                         self.urn)
            raise IOError("NOT_FOUND")

        # The actual filename for the root directory.
        if not isinstance(self.storage, rdfvalue.FileRef):
            self.storage = rdfvalue.FileRef(str(self.storage))
        self.root_path = self.storage.ToFilename()

        try:
            # Read container.description directly from the filesystem; it
            # holds the canonical aff4:// URN of the container which we
            # adopt in place of our placeholder UUID.
            container_desc_path = os.path.join(
                self.root_path, lexicon.AFF4_CONTAINER_DESCRIPTION)
            if os.path.exists(container_desc_path):
                with open(container_desc_path, "rb") as f:
                    urn_string = f.read(1000).decode("utf-8").strip()

                if urn_string and str(self.urn) != urn_string:
                    self.resolver.DeleteSubject(self.urn)
                    self.urn = rdfvalue.ARN(urn_string)

                self.resolver.Set(lexicon.transient_graph, self.urn, lexicon.AFF4_TYPE,
                                  URIRef(lexicon.AFF4_DIRECTORY_TYPE))
                self.resolver.Set(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED,
                                  URIRef(self.storage))
                LOGGER.info("AFF4Directory volume found: %s", self.urn)

            # Try to load the RDF metadata file from the storage.
            turtle_path = os.path.join(
                self.root_path, lexicon.AFF4_CONTAINER_INFO_TURTLE)
            if os.path.exists(turtle_path):
                with open(turtle_path, "rb") as turtle_stream:
                    turtle_text = turtle_stream.read().decode("utf-8")
                self.resolver.store.parse(data=turtle_text, format="turtle")

                # Find all the contained objects and adjust their filenames
                # so they map to the actual filesystem paths under the
                # current root_path.
                for subject in self.resolver.SelectSubjectsByPrefix(
                        lexicon.any, str(self.urn)):
                    child_filename = next(self.resolver.Get(
                        lexicon.any, subject, URIRef(lexicon.AFF4_DIRECTORY_CHILD_FILENAME)),
                        None)
                    if child_filename:
                        self.resolver.Set(lexicon.transient_graph,
                            subject, lexicon.AFF4_FILE_NAME,
                            Literal("%s%s%s" % (
                                self.root_path, os.sep, child_filename)))

        except IOError:
            pass


    def Flush(self):
        if self.IsDirty():
            # Flush all children before us. This ensures that metadata is fully
            # generated for each child.
            for child_urn in list(self.children):
                obj = self.resolver.CacheGet(child_urn)
                if obj:
                    obj.Flush()

            # Mark the container with its URN
            with self.CreateMember(
                    self.urn.Append(
                        lexicon.AFF4_CONTAINER_DESCRIPTION)) as desc:
                desc.Truncate()
                desc.Write(str(self.urn).encode("utf-8"))
                desc.Flush() # Flush explicitly since we already flushed above.

            # Dump the resolver into the directory.
            with self.CreateMember(
                    self.urn.Append(
                        lexicon.AFF4_CONTAINER_INFO_TURTLE)) as turtle_stream:
                # Overwrite the old turtle file with the newer data.
                turtle_stream.Truncate()
                turtle_text = self.resolver._DumpToTurtle(self.urn)
                if isinstance(turtle_text, str):
                    turtle_text = turtle_text.encode("utf-8")
                turtle_stream.Write(turtle_text)
                turtle_stream.Flush()

        return super().Flush()


registry.AFF4_TYPE_MAP[lexicon.AFF4_DIRECTORY_TYPE] = AFF4Directory
