# This script demonstrates how to extract AFF4 streams from a volume.
from pyaff4 import data_store
from pyaff4 import aff4_image
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip

import re
import sys

# Convert a filename to URN. AFF4 uses URNs to refer to everything.
volume_path_urn = rdfvalue.URN.NewURNFromFilename(sys.argv[1])

# We need to make a resolver to hold all the RDF metadata
resolver = data_store.MemoryDataStore()

# Open the AFF4 volume from a ZipFile.
with zip.ZipFile.NewZipFile(resolver, volume_path_urn) as volume:
    volume_urn = volume.urn

    # This will dump out the resolver.
    resolver.Dump()

    # Find all subjects with a type of Image. Alternatively if you
    # know the subject URN in advance just open it. Replace the
    # AFF4_IMAGE_TYPE with AFF4_MAP_TYPE for maps.
    for subject in resolver.QueryPredicateObject(
            lexicon.AFF4_TYPE, lexicon.AFF4_IMAGE_TYPE):

        # This should be able to open the URN.
        with resolver.AFF4FactoryOpen(subject) as in_fd:

            # Escape the subject to make something like a valid filename.
            filename = re.sub("[^a-z0-9A-Z-]",
                              lambda m: "%%%02x" % ord(m[0]),
                              str(subject))
            print ("Dumping %s to file %s" % (subject, filename))

            with open(filename, "wb") as out_fd:

                # Just copy the output to the file.
                while 1:
                    data = in_fd.read(1024 * 1024)
                    if not data:
                        break
                    out_fd.write(data)
