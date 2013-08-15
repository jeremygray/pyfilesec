"""Test suite for pyFileSec:

This file allows py.test without args to discover and run the tests.
The actual tests are in class Tests in the same file as the code.

TestsWithAnotherOpenSSL runs tests using a different openssl binary.
"""

from os.path import exists
from pyfilesec import *


class TestsWithAnotherOpenSSL(Tests):
    def setup_class(self):
        global pytest
        import pytest

        global OPENSSL
        OPENSSL = '/opt/local/bin/openssl'
        # this path can easily be non-existent!

        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)
