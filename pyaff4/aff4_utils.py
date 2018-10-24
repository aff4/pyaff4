from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import chr
import os
import re
import shutil
import string
import urllib.parse

from pyaff4 import rdfvalue
from pyaff4 import utils


def MkDir(path):
    try:
        os.mkdir(path)
    except OSError as e:
        if "File exists" in e.strerror:
            return

        raise

def RemoveDirectory(path):
    try:
        shutil.rmtree(path)
    except OSError:
        pass

def EnsureDirectoryExists(path):
    dirname = os.path.dirname(path)
    try:
        os.makedirs(dirname)
    except OSError:
        pass
