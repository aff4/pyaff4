from rdflib import Literal, XSD
from pyaff4 import rdfvalue

import unittest

class URNTest(unittest.TestCase):

    # def testXSDInt(self):
    #     i1 = Literal("100", datatype=XSD.integer)
    #     self.assertLess(99, i1)
    #     self.assertEqual(100, i1)
    #     self.assertGreater(101, 100)
    #     self.assertGreater(101, i1)
    #     self.assertTrue(99 < i1)
    #     self.assertTrue(101 > i1)
    #     self.assertTrue(100 == i1)

    def testURN(self):
        url = "http://www.google.com/path/to/element#hash_data"
        self.assertEqual(rdfvalue.ARN(url).toPython(), url)
        # dont overload the constructor of URN to support a non-URN as an input
        # self.assertEqual(rdfvalue.URN("//etc/passwd"),
        #                  "file://etc/passwd")

    def testTrailingSlashURN(self):
        url = "http://code.google.com/p/snappy/"
        test = rdfvalue.ARN(url)
        self.assertEqual(test.toPython(),
                          "http://code.google.com/p/snappy/")

    def testAppend(self):
        test = rdfvalue.ARN("http://www.google.com")
        aff4volume = rdfvalue.ARN("aff4://volumeguid/image/0000")

        self.assertEqual(aff4volume.Append("index").toPython(),
                          "aff4://volumeguid/image/0000/index")

        self.assertEqual(test.Append("foobar").toPython(),
                          "http://www.google.com/foobar")

        self.assertEqual(test.Append("/foobar").toPython(),
                          "http://www.google.com/foobar")

        self.assertEqual(test.Append("..").toPython(),
                          "http://www.google.com/")

        self.assertEqual(test.Append("../../../..").toPython(),
                          "http://www.google.com/")

        self.assertEqual(test.Append("aa/bb/../..").toPython(),
                          "http://www.google.com/")

        self.assertEqual(test.Append("aa//../c").toPython(),
                          "http://www.google.com/c")

        self.assertEqual(
            test.Append("aa///////////.///./c").toPython(),
            "http://www.google.com/aa/c")


if __name__ == '__main__':
    unittest.main()
