import pyaff4
from pyaff4 import container
import argparse
import sys
from pyaff4 import rdfvalue
from pyaff4 import block_hasher

def info(file):
    volume = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file))
    image = volume.image
    volumeURN = volume.urn

    print("AFF4 File: %s" % file)
    print("\tVolume ID: %s" % str(volumeURN))

    caseDetails = volume.getMetadata("CaseDetails")
    print ("\tCase Description: %s" % caseDetails.caseDescription)
    print ("\tCase Name: %s" % caseDetails.caseName)
    print ("\tExaminer: %s" % caseDetails.examiner)

    image = volume.getMetadata("Image")
    print ("\tSize: %s (bytes)" % image.size)
    print ("\tSectors: %s" % image.sectorCount)
    print ("\tBlockMapHash: %s" % image.hash)
    print ("\tUnknownproperty: %s" % image.foobar)

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

def verify(file):
    volume = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file))
    image = volume.image
    listener = VerificationListener()
    validator = block_hasher.Validator(listener)
    print("Verifying AFF4 File: %s" % file)
    validator.validateContainer(rdfvalue.URN.FromFileName(file))
    for result in listener.results:
        print("\t%s" % result)

def main(args):
    if args[1] == "info":
        info(args[2])
    elif args[1] == "verify":
        verify(args[2])

if __name__ == "__main__":
    main(sys.argv)
