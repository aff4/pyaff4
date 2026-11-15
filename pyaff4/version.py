#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

class Version:
    def __init__(self, major, minor, tool):
        self.major = major
        self.minor = minor
        self.tool = tool

    @staticmethod
    def create(dic):
        return Version(int(dic["major"]),int(dic["minor"]),dic["tool"])

    def is10(self):
        if self.major == 1 and self.minor == 0:
            return True
        return False

    def is11(self):
        if self.major == 1 and self.minor == 1:
            return True
        return False

    def isLessThanOrEqual(self, major, minor):
        if self.major < major:
            return True
        if self.major == major:
            if self.minor <= minor:
                return True
        return False

    def isGreaterThanOrEqual(self, major, minor):
        if self.major > major:
            return True
        if self.major == major:
            if self.minor >= minor:
                return True
        return False

    def equals(self, major, minor):
        return self.major == major and self.minor == minor

    def __str__(self):
        return u"major=%d\nminor=%d\ntool=%s\n" % (self.major, self.minor, self.tool)

def parseProperties(propertiesText):
    res = {}
    for line in propertiesText.split("\n"):
        try:
            (prop, value) = line.split("=")
            res[prop] = value
        except ValueError:
            pass
    return res

basic_zip = Version(0, 0, "pyaff4")
aff4v10 = Version(1, 0, "pyaff4")
aff4v11 = Version(1, 1, "pyaff4")