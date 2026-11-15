import unittest

from pyaff4 import container
from pyaff4.rdfvalue import ARN
from tests import test_hashing

class ContainerTest(unittest.TestCase):

    @test_hashing.conditional_on_images
    def testOpen(self):
        fd = container.Container.open(test_hashing.stdLinear)
        self.assertEqual(fd.urn,
                        ARN("aff4://fcbfdce7-4488-4677-abf6-08bc931e195b"))


if __name__ == '__main__':
    unittest.main()
