# -*- coding: utf-8 -*-
#

import unittest
from pyaff4.escaping import arnPathFragment_from_path, member_name_for_urn
from pyaff4 import rdfvalue

"""
Tests escaping rules
"""
class EscapingTest(unittest.TestCase):

    def setUp(self):
        pass


    # NTFS Allowed filename characters  see https://en.wikipedia.org/wiki/NTFS
    # In Win32 namespace: any UTF-16 code unit (case-insensitive) except /\:*"?<>| as well as NUL[5]
    # In POSIX namespace: any UTF-16 code unit (case-sensitive) except / as well as NUL

    def testEscapeUnicode(self):
        self.assertEqual(u"ネコ.txt", arnPathFragment_from_path(u"ネコ.txt"))
        self.assertEqual(u"ネコ.txt", arnPathFragment_from_path(u"/ネコ.txt"))
        self.assertEqual(u"ネコ.txt", arnPathFragment_from_path(u"\ネコ.txt"))
        self.assertEqual(u"a/b/c/ネコ.txt", arnPathFragment_from_path(u"\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"c:/a/b/c/ネコ.txt", arnPathFragment_from_path(u"c:\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"storage/a/b/c/ネコ.txt", arnPathFragment_from_path(u"\\\\storage\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"c:", arnPathFragment_from_path(u"c:"))
        self.assertEqual(u"c:/", arnPathFragment_from_path(u"c:\\"))
        self.assertEqual(u"c:/foo", arnPathFragment_from_path(u"c:\\foo"))
        self.assertEqual(u"bar/c$", arnPathFragment_from_path(u"\\\\bar\\c$"))
        self.assertEqual(u"bar/c$/foo.txt", arnPathFragment_from_path(u"\\\\bar\\c$\\foo.txt"))
        self.assertEqual(u"bar/c$/foo/ネコ.txt", arnPathFragment_from_path(u"\\\\bar\\c$\\foo\\ネコ.txt"))
        self.assertEqual(u"foo/bar", arnPathFragment_from_path(u"/foo/bar"))
        self.assertEqual(u"some%20file", arnPathFragment_from_path(u"/some file"))
        self.assertEqual(u"some%20file", arnPathFragment_from_path(u"./some file"))
        self.assertEqual(u"some%20file", arnPathFragment_from_path(u"../some file"))

    def testARNtoZipSegment(self):
        self.assertEqual(u"c:/foo", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/c:/foo",
                                                        base_urn=rdfvalue.URN(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"bar/c$", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$",
                                                        base_urn=rdfvalue.URN(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"bar/c$/foo.txt", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo.txt",
                                                        base_urn=rdfvalue.URN(
                                                            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"foo/bar",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/foo/bar",
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"foo/some file",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/foo/some%20file",
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"foo/some  file",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/foo/some%20%20file",
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"bar/c$/foo/ネコ.txt",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo/ネコ.txt",
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))

if __name__ == '__main__':
    unittest.main()