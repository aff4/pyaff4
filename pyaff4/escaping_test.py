# -*- coding: utf-8 -*-
#

import unittest
from pyaff4.escaping import arnPathFragment_from_path, member_name_for_urn, urn_from_member_name
from pyaff4 import rdfvalue, container

"""
Tests escaping rules
"""
class EscapingTest(unittest.TestCase):

    def setUp(self):
        pass


    # NTFS Allowed filename characters  see https://en.wikipedia.org/wiki/NTFS
    # In Win32 namespace: any UTF-16 code unit (case-insensitive) except /\:*"?<>| as well as NUL[5]
    # In POSIX namespace: any UTF-16 code unit (case-sensitive) except / as well as NUL

    def testPathToARNPathFragment(self):
        self.assertEqual(u"/my_filename_with_forbidden_chars_like?_and_#", arnPathFragment_from_path(u"my_filename_with_forbidden_chars_like?_and_#"))
        self.assertEqual(u"/ネコ.txt", arnPathFragment_from_path(u"ネコ.txt"))
        self.assertEqual(u"/ネコ.txt", arnPathFragment_from_path(u"/ネコ.txt"))
        self.assertEqual(u"/ネコ.txt", arnPathFragment_from_path(u"\ネコ.txt"))
        self.assertEqual(u"/a/b/c/ネコ.txt", arnPathFragment_from_path(u"\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"/c:/a/b/c/ネコ.txt", arnPathFragment_from_path(u"c:\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"storage/a/b/c/ネコ.txt", arnPathFragment_from_path(u"\\\\storage\\a\\b\\c\\ネコ.txt"))
        self.assertEqual(u"/c:", arnPathFragment_from_path(u"c:"))
        self.assertEqual(u"/c:/", arnPathFragment_from_path(u"c:\\"))
        self.assertEqual(u"/c:/foo", arnPathFragment_from_path(u"c:\\foo"))
        self.assertEqual(u"bar/c$", arnPathFragment_from_path(u"\\\\bar\\c$"))
        self.assertEqual(u"bar/c$/foo.txt", arnPathFragment_from_path(u"\\\\bar\\c$\\foo.txt"))
        self.assertEqual(u"bar/c$/foo/ネコ.txt", arnPathFragment_from_path(u"\\\\bar\\c$\\foo\\ネコ.txt"))
        self.assertEqual(u"/foo/bar", arnPathFragment_from_path(u"/foo/bar"))
        self.assertEqual(u"/some%20file", arnPathFragment_from_path(u"/some file"))
        self.assertEqual(u"/some%20file", arnPathFragment_from_path(u"./some file"))
        self.assertEqual(u"/some%20file", arnPathFragment_from_path(u"../some file"))

        # examples from https://blogs.msdn.microsoft.com/ie/2006/12/06/file-uris-in-windows/
        self.assertEqual(u"laptop/My%20Documents/FileSchemeURIs.doc", arnPathFragment_from_path(u"\\\\laptop\\My Documents\\FileSchemeURIs.doc"))
        self.assertEqual(u"/C:/Documents%20and%20Settings/davris/FileSchemeURIs.doc", arnPathFragment_from_path(u"C:\\Documents and Settings\\davris\\FileSchemeURIs.doc"))
        self.assertEqual(u"/D:/Program%20Files/Viewer/startup.htm", arnPathFragment_from_path(u"D:\\Program Files\\Viewer\\startup.htm"))
        self.assertEqual(u"/C:/Program%20Files/Music/Web%20Sys/main.html?REQUEST=RADIO", arnPathFragment_from_path(u"C:\\Program Files\\Music\Web Sys\\main.html?REQUEST=RADIO"))
        self.assertEqual(u"applib/products/a-b/abc_9/4148.920a/media/start.swf", arnPathFragment_from_path(u"\\\\applib\\products/a-b/abc_9/4148.920a/media/start.swf"))
        self.assertEqual(u"/C:/exampleㄓ.txt", arnPathFragment_from_path(u"C:\exampleㄓ.txt"))

        # microsoft device paths
        self.assertEqual(u"./Windows/foo.txt", arnPathFragment_from_path(u"\\\\.\\Windows\\foo.txt"))

        # MacOS seen
        self.assertEqual(u"/", u"/")
        #self.assertEqual(u"/private/var/tmp/bootstrap/share/man/man1/%5b.1", arnPathFragment_from_path(u"/private/var/tmp/bootstrap/share/man/man1/[.1"))

    def testARNtoZipSegment(self):
        version = container.Version(1, 1, "pyaff4")
        self.assertEqual(u"/c:/foo", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//c:/foo",
                                                         version,
                                                         base_urn=rdfvalue.URN(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"bar/c$", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$",
                                                        version,
                                                        base_urn=rdfvalue.URN(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"bar/c$/foo.txt", member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo.txt",
                                                        version,
                                                        base_urn=rdfvalue.URN(
                                                            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                                        use_unicode=True))
        self.assertEqual(u"/foo/bar",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/bar",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/foo/some file",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/some%20file",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/foo/some  file",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/some%20%20file",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"bar/c$/foo/ネコ.txt",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo/ネコ.txt",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))

        # examples from https://blogs.msdn.microsoft.com/ie/2006/12/06/file-uris-in-windows/
        self.assertEqual(u"laptop/My Documents/FileSchemeURIs.doc",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/laptop/My%20Documents/FileSchemeURIs.doc",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/C:/Documents and Settings/davris/FileSchemeURIs.doc",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/Documents and Settings/davris/FileSchemeURIs.doc",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/D:/Program Files/Viewer/startup.htm",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//D:/Program Files/Viewer/startup.htm",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/C:/Program Files/Music/Web Sys/main.html?REQUEST=RADIO",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/Program Files/Music/Web%20Sys/main.html?REQUEST=RADIO",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"applib/products/a-b/abc_9/4148.920a/media/start.swf",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/applib/products/a-b/abc_9/4148.920a/media/start.swf",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))
        self.assertEqual(u"/C:/exampleㄓ.txt",
                         member_name_for_urn(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/exampleㄓ.txt",
                                             version,
                                             base_urn=rdfvalue.URN(
                                                 u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18"),
                                             use_unicode=True))

    def testZipSegmenttoARN(self):
        version = container.Version(1, 1, "pyaff4")
        base_urn = rdfvalue.URN(
            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18")
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//c:/foo",
                         urn_from_member_name(u"/c:/foo", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//c:/foo",
                         urn_from_member_name(u"/c:/foo", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$",
                         urn_from_member_name(u"bar/c$", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo.txt",
                         urn_from_member_name(u"bar/c$/foo.txt", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/bar",
                        urn_from_member_name(u"/foo/bar", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/some%20file",
                         urn_from_member_name(u"/foo/some file", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//foo/some%20%20file",
                         urn_from_member_name(u"/foo/some  file", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/bar/c$/foo/ネコ.txt",
                         urn_from_member_name(u"bar/c$/foo/ネコ.txt", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/laptop/My%20Documents/FileSchemeURIs.doc",
                         urn_from_member_name(u"laptop/My Documents/FileSchemeURIs.doc", base_urn, version))
        self.assertEqual(
            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/Documents%20and%20Settings/davris/FileSchemeURIs.doc",
            urn_from_member_name(u"/C:/Documents and Settings/davris/FileSchemeURIs.doc", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//D:/Program%20Files/Viewer/startup.htm",
                         urn_from_member_name(u"/D:/Program Files/Viewer/startup.htm", base_urn, version))
        self.assertEqual(
            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/Program%20Files/Music/Web%20Sys/main.html?REQUEST=RADIO",
            urn_from_member_name(u"/C:/Program Files/Music/Web Sys/main.html?REQUEST=RADIO", base_urn, version))
        self.assertEqual(
            u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18/applib/products/a-b/abc_9/4148.920a/media/start.swf",
            urn_from_member_name(u"applib/products/a-b/abc_9/4148.920a/media/start.swf", base_urn, version))
        self.assertEqual(u"aff4://e6bae91b-0be3-4770-8a36-14d231833e18//C:/exampleㄓ.txt",
                         urn_from_member_name(u"/C:/exampleㄓ.txt", base_urn, version))

if __name__ == '__main__':
    unittest.main()