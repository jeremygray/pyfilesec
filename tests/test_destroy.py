#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Test suite for pytest, covering secure file removal (destroy).

Part of the pyFileSec library. Copyright (c) 2013, Jeremy R. Gray
"""


import pytest
import pyfilesec
from   pyfilesec import *


class TestDestroy(object):
    def setup_class(self):
        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)

    def teardown_class(self):
        os.chdir(self.start_dir)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_destroy(self):
        # see if it takes at least 50x longer to destroy() than unlink a file
        # if so, DESTROY_EXE is doing something, hopefully its a secure delete

        if sys.platform == 'win32' and not DESTROY_EXE:
            pytest.skip()

        tw_path = 'tmp_test_destroy no unicode'
        tw_reps = 3
        destroy_times = []
        for i in range(tw_reps):
            with open(tw_path, 'wb') as fd:
                fd.write(b'\0')
            result = SecFile(tw_path).destroy().result
            assert result['disposition'] == destroy_code[pfs_DESTROYED]
            # assert links == 1  # separate test
            destroy_times.append(result['seconds'])
        unlink_times = []
        for i in range(tw_reps):
            with open(tw_path, 'wb') as fd:
                fd.write(b'\0')
            t0 = get_time()
            os.unlink(tw_path)
            unlink_times.append(get_time() - t0)
        avg_destroy = sum(destroy_times) / tw_reps
        avg_unlink = sum(unlink_times) / tw_reps

        assert min(destroy_times) > 10 * max(unlink_times)
        assert avg_destroy > 50 * avg_unlink

    def test_destroy_links(self):
        # Test detection of multiple links to a file when destroy()ing it:

        tw_path = 'tmp_test_destroy no unicode'
        with open(tw_path, 'wb') as fd:
            fd.write(b'\0')
        assert isfile(tw_path)  # need a file or can't test
        if not user_can_link:
            result = SecFile(tw_path).destroy().result
            assert result['orig_links'] == -1
            pytest.skip()  # need admin priv for fsutil
        numlinks = 2
        for i in range(numlinks):
            new = tw_path + 'hardlink' + str(i)
            if sys.platform in ['win32']:
                sys_call(['fsutil', 'hardlink', 'create', new, tw_path])
            else:
                os.link(tw_path, new)

        sf = SecFile(tw_path)
        orig_links = sf.hardlinks
        sf.destroy()
        assert sf.result['orig_links'] == numlinks + 1  # +1 for itself
        assert sf.result['orig_links'] == orig_links
