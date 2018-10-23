import argparse
import sys, os, errno, shutil, uuid

from pyaff4 import container
from pyaff4 import lexicon, logical, escaping
from pyaff4 import rdfvalue, hashes, utils
from pyaff4 import block_hasher, data_store, linear_hasher

# here's the beginnings of a command line app for manipulating AFF4 images
# more of a PoC code example for now.
# author bradley@evimetry.com

VERBOSE = False
TERSE = False

def meta(file):
    volume = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file))
    resolver = volume.resolver

    metadataURN = volume.urn.Append("information.turtle")
    try:
        with resolver.AFF4FactoryOpen(metadataURN) as fd:
            txt = fd.ReadAll()
            print(utils.SmartUnicode(txt))
    except:
        pass


def list(file):
    volume = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file))

    if issubclass(volume.__class__, container.PhysicalImageContainer):
        printDiskImageInfo(file, volume)
    elif issubclass(volume.__class__, container.LogicalImageContainer):
        printLogicalImageInfo(file, volume)

def printLogicalImageInfo(file, volume):
    printVolumeInfo(file, volume)
    printCaseInfo(volume)

    for image in volume.images():
        print ("\t%s <%s>" % (image.name(), trimVolume(volume.urn, image.urn)))


def printVolumeInfo(file, volume):
    volumeURN = volume.urn

    print("AFF4Container: file://%s <%s>" % (file, str(volumeURN)))

def printCaseInfo(volume):
    caseDetails = volume.getMetadata("CaseDetails")
    if caseDetails == None:
        return
    print ("\tCase Description: %s" % caseDetails.caseDescription)
    print ("\tCase Name: %s" % caseDetails.caseName)
    print ("\tExaminer: %s" % caseDetails.examiner)

def printDiskImageInfo(file, volume):
    printVolumeInfo(file, volume)
    printCaseInfo(volume)

    image = volume.getMetadata("DiskImage")
    print ("\t%s (DiskImage)" % image.urn)
    print ("\t\tSize: %s (bytes)" % image.size)
    print ("\t\tSize: %s (bytes)" % image.size)
    print ("\t\tSectors: %s" % image.sectorCount)
    print ("\t\tBlockMapHash: %s" % image.hash)

    # the following property is to test that unknown properties are handled OK
    print ("\t\tUnknownproperty: %s" % image.foobar)

    computerInfo = volume.getMetadata("ComputeResource")
    if computerInfo != None:
        print ("\tAcquisition computer details")
        print ("\t\tSystem board vendor: %s" % computerInfo.systemboardVendor)
        print ("\t\tSystem board serial: %s" % computerInfo.systemboardSerial)
        print ("\t\tUnknownproperty: %s" % computerInfo.foobar)


class VerificationListener(object):
    def __init__(self):
        self.results = []

    def onValidBlockHash(self, a):
        pass

    def onInvalidBlockHash(self, a, b, imageStreamURI, offset):
        self.results.append("Invalid block hash comarison for stream %s at offset %d" % (imageStreamURI, offset))

    def onValidHash(self, typ, hash, imageStreamURI):
        self.results.append("Validation of %s %s succeeded. Hash = %s" % (imageStreamURI, typ, hash))

    def onInvalidHash(self, typ, a, b, streamURI):
        self.results.append("Invalid %s comarison for stream %s" % (typ, streamURI))

class LinearVerificationListener(object):
    def __init__(self):
        self.results = []

    def onValidHash(self, typ, hash, imageStreamURI):
        print ("\t\t%s Verified (%s)" % (typ, hash))

    def onInvalidHash(self, typ, hasha, hashb, streamURI):
        print ("\t\t%s Hash failure stored = %s calculated = %s)" % (typ, hasha, hashb))



def trimVolume(volume, image):
    global TERSE
    if TERSE:
        volstring = utils.SmartUnicode(volume)
        imagestring = utils.SmartUnicode(image)
        if imagestring.startswith(volstring):
            imagestring = imagestring[len(volstring):]
        return imagestring
    else:
        return image


def verify(file):
    volume = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file))
    printVolumeInfo(file, volume)
    printCaseInfo(volume)
    resolver = volume.resolver

    if type(volume) == container.PhysicalImageContainer:
        image = volume.image
        listener = VerificationListener()
        validator = block_hasher.Validator(listener)
        print("Verifying AFF4 File: %s" % file)
        validator.validateContainer(rdfvalue.URN.FromFileName(file))
        for result in listener.results:
            print("\t%s" % result)
    elif type(volume) == container.LogicalImageContainer:
        #print ("\tLogical Images:")
        hasher = linear_hasher.LinearHasher2(resolver, LinearVerificationListener())
        for image in volume.images():
            print ("\t%s <%s>" % (image.name(), trimVolume(volume.urn, image.urn)))
            hasher.hash(image)



def addPathNames(container_name, pathnames, recursive):
    with data_store.MemoryDataStore() as resolver:
        container_urn = rdfvalue.URN.FromFileName(container_name)
        urn = None
        with container.Container.createURN(resolver, container_urn) as volume:
            print("Creating AFF4Container: file://%s <%s>" % (container_name, volume.urn))
            for pathname in pathnames:
                pathname = utils.SmartUnicode(pathname)
                print ("\tAdding: %s" % pathname)
                fsmeta = logical.FSMetadata.create(pathname)
                if os.path.isdir(pathname):
                    image_urn = None
                    if volume.isAFF4Collision(pathname):
                        image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
                    else:
                        image_urn = volume.urn.Append(escaping.arnPathFragment_from_path(pathname), quote=False)

                    fsmeta.urn = image_urn
                    fsmeta.store(resolver)
                    resolver.Set(image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(pathname))
                    resolver.Add(image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FolderImage))
                    resolver.Add(image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
                    if recursive:
                        for child in os.listdir(pathname):
                            pathnames.append(os.path.join(pathname, child))
                else:
                    with open(pathname, "rb") as src:
                        hasher = linear_hasher.StreamHasher(src, [lexicon.HASH_SHA1, lexicon.HASH_MD5])
                        urn = volume.writeLogical(pathname, hasher, fsmeta.length)
                        fsmeta.urn = urn
                        fsmeta.store(resolver)
                        for h in hasher.hashes:
                            hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                            resolver.Add(urn, rdfvalue.URN(lexicon.standard.hash), hh)
        return urn

def extract(container_name, imageURNs, destFolder):
    with data_store.MemoryDataStore() as resolver:
        container_urn = rdfvalue.URN.FromFileName(container_name)
        urn = None

        with container.Container.openURNtoContainer(container_urn) as volume:
            printVolumeInfo(file, volume)
            resolver = volume.resolver
            for imageUrn in imageURNs:
                imageUrn = utils.SmartUnicode(imageUrn)

                pathName = next(resolver.QuerySubjectPredicate(imageUrn, volume.lexicon.pathName))

                with resolver.AFF4FactoryOpen(imageUrn) as srcStream:
                    if destFolder != "-":
                        destFile = os.path.join(destFolder, escaping.arnPathFragment_from_path(pathName.value))
                        if not os.path.exists(os.path.dirname(destFile)):
                            try:
                                os.makedirs(os.path.dirname(destFile))
                            except OSError as exc:  # Guard against race condition
                                if exc.errno != errno.EEXIST:
                                    raise
                        with open(destFile, "w") as destStream:
                            shutil.copyfileobj(srcStream, destStream)
                            print ("\tExtracted %s to %s" % (pathName.value, destFile))
                    else:
                        shutil.copyfileobj(srcStream, sys.stdout)


def main(argv):
    parser = argparse.ArgumentParser(description='AFF4 command line utility.')
    parser.add_argument('-v', "--verify", action="store_true",
                        help='verify the objects in the container')
    parser.add_argument("--verbose", action="store_true",
                        help='enable verbose output')
    parser.add_argument('-t', "--terse", action="store_true",
                        help='enable terse output')
    parser.add_argument('-l', "--list", action="store_true",
                        help='list the objects in the container')
    parser.add_argument('-m', "--meta", action="store_true",
                        help='dump the AFF4 metadata found in the container')
    parser.add_argument('-f', "--folder", default=os.getcwd(),
                        help='the destination folder for extraction of logical images')
    parser.add_argument('-r', "--recursive", action="store_true",
                        help='add files and folders recursively')
    parser.add_argument('-c', "--create-logical", action="store_true",
                        help='create an AFF4 logical container containing srcFiles')
    parser.add_argument('-x', "--extract", action="store_true",
                        help='extract objects from the container')
    parser.add_argument('aff4container', help='the pathname of the AFF4 container')
    parser.add_argument('srcFiles', nargs="*", help='source files and folders to add as logical image')


    args = parser.parse_args()
    global TERSE
    global VERBOSE
    VERBOSE = args.verbose
    TERSE = args.terse

    if args.create_logical == True:
        dest = args.aff4container
        addPathNames(dest, args.srcFiles, args.recursive)
    elif  args.meta == True:
        dest = args.aff4container
        meta(dest)
    elif  args.list == True:
        dest = args.aff4container
        list(dest)
    elif  args.verify == True:
        dest = args.aff4container
        verify(dest)
    elif args.extract == True:
        dest = args.aff4container
        extract(dest, args.srcFiles, args.folder)


if __name__ == "__main__":
    main(sys.argv)
