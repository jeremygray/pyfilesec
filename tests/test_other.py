#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Test suite for pytest, covering noncrypto classes and functions.

Part of the pyFileSec library. Copyright (c) 2013, Jeremy R. Gray
"""


import pytest
import pyfilesec
from   pyfilesec import *
from   pyfilesec import _abspath, _uniq_file, _parse_args

def _known_values(folder='.'):
    """Return tmp files with known keys, data, signature for testing.
    This is a WEAK key, 1024 bits, for testing ONLY.
    """
    bits = '1024'
    pub, priv, pphr = GenRSA().demo_rsa_keys(folder)

    kwnSig0p9p8 = (  # openssl 0.9.8r
        "dNF9IudjTjZ9sxO5P07Kal9FkY7hCRJCyn7IbebJtcEoVOpuU5Gs9pSngPnDvFE"
        "2BILvwRFCGq30Ehnhm8USZ1zc5m2nw6S97LFPNFepnB6h+575OHfHX6Eaothpcz"
        "BK+91UMVId13iTu9d1HaGgHriK6BcasSuN0iTfvbvnGc4=")
    kwnSig1p0 = (   # openssl 1.0.1e or 1.0.0-fips
        "eWv7oIGw9hnWgSmicFxakPOsxGMeEh8Dxf/HlqP0aSX+qJ8+whMeJ3Ol7AgjsrN"
        "mfk//J4mywjLeBp5ny5BBd15mDeaOLn1ETmkiXePhomQiGAaynfyQfEOw/F6/Ux"
        "03rlYerys2Cktgpya8ezxbOwJcOCnHKydnf1xkGDdFywc=")
    return (_abspath(pub), _abspath(priv), _abspath(pphr),
            bits, (kwnSig0p9p8, kwnSig1p0))

class TestBasics(object):
    """Test suite for noncrypto.

    pytest.skip:
    - unicode in paths fail on win32
    - permissions fail on win32
    - hardlinks (fsutil) need admin priv on win32; test links reported = -1
    """
    def setup_class(self):
        global codec
        codec = PFSCodecRegistry(default_codec)

        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)

    def teardown_class(self):
        os.chdir(self.start_dir)
        shutil.rmtree(self.tmp, ignore_errors=True)

    '''
    def test_SecStr_printable_pwd(self):
        # ensure a non-interned string because has '#'
        s = '#ca6e89'
        ss = SecStr(s)
        assert id(s) == ss._id == id(ss._val) == id(ss.str)
        assert s in ss.str
        with pytest.raises(RuntimeError):
            val = "%s" % ss
        ss.zero()
        assert ss.str == ss._val == b'\0' * len(s)

        # SecStr should not be iterable:
        with pytest.raises(TypeError):
            assert ss[0] == b'\0'

        with pytest.raises(TypeError):
            ss += 'more string stuff'

        # del or clear should zero the *original* string:
        s_orig = '#ca6e89'
        ss = SecStr(s_orig)
        del(ss)
        assert s_orig == b'\0' * len(s_orig)

        # null string should pass
        for s in ['', ()]:
            SecStr(s)

        # interned string or non-string should raise:
        # sometimes u'#ca6e89' works, sometimes not
        for s in ['ca6e89', 123]:
            with pytest.raises(ValueError):
                ss = SecStr(s)

        # a printable_pwd should be a SecStr:
        pwd = printable_pwd(256, '#')
        assert pwd.str.startswith('#')
        assert len(pwd.str) == 256 // 4 + 1
        pwd.zero()
        assert pwd.zeroed
        assert pwd.__repr__()
        assert pwd._id == None
        assert pwd._val == pwd.str == b'\0' * (256 // 4 + 1)
    '''

    @pytest.mark.notravis
    def test_import_pyperclip(self):
        import _pyperclip

    def test_import_getpass_which(self):
        os.chdir(self.start_dir)
        import _getpass
        import which
        os.chdir(self.tmp)

    def test_SecFileBase(self):
        test_file = 'tf'
        with open(test_file, write_mode) as fd:
            fd.write('a')
        sf = SecFile(test_file)  # inherits from _SecFileBase
        sf.openssl = OPENSSL
        sf._openssl_version = None
        sf.openssl_version

        # no file:
        sf._file = None
        with pytest.raises(ValueError):
            sf.size
        sf.basename
        sf.read(1)
        with pytest.raises(ValueError):
            assert sf.metadata == {}
        with pytest.raises(ValueError):
            assert sf.metadataf == '{}'
        with pytest.raises(ValueError):
            sf._require_file()
        assert sf.load_metadata() == NO_META_DATA

        sf.hardlinks
        save_val = pyfilesec.user_can_link
        pyfilesec.user_can_link = False
        assert sf.hardlinks == -1
        pyfilesec.user_can_link = save_val

        sf.is_in_dropbox
        sf._get_git_info(None)
        sf._get_git_info('.', git='notgit')
        sf._get_svn_info(None)
        sf._get_hg_info(None)

        # regular file:
        sf._file = test_file
        sf.read()
        sf.read(1)
        sf.basename
        with pytest.raises(AttributeError):
            sf.set_file(1)
        with pytest.raises(NotImplementedError):
            sf.set_file_time(0)
        sf.snippet
        with pytest.raises(FileNotEncryptedError):
            sf._require_enc_file()
        sf.metadata

        # non-writeable dir:
        no_write = 'non_writeable_test'
        os.makedirs(no_write)
        f = os.path.join(no_write, 'tmp_no_write')
        with open(f, write_mode) as fd:
            fd.write('x')
        sf = SecFile(f)
        assert sf.is_in_writeable_dir
        # TO-DO: change write-permission on win32
        if sys.platform != 'win32':
            os.chmod(no_write, stat.S_IREAD)
            assert sf.is_in_writeable_dir == False
            os.chmod(no_write, stat.S_IRWXU)
        shutil.rmtree(no_write)

        # bad file name
        sf._file = test_file + 'xyz'
        with pytest.raises(OSError):
            sf._require_file()
        sf.set_file(test_file)

        # encrypted file:
        pub = _known_values()[0]
        sf.encrypt(pub, keep=True)
        sf.read()
        assert sf.metadata != {}
        assert sf.metadataf != '{}'
        sf.snippet

        # .pem file (warns)
        sf.set_file(pub)
        sf.set_file(test_file)

        sf.is_tracked
        sf._get_git_info(sf.file)
        sf._get_git_info(sf.file)
        sf._get_git_info(sf.file)

    def test_misc_helper(self):
        good_path = OPENSSL
        with pytest.raises(RuntimeError):
            set_openssl('junk.glop')
        # TO-DO write a win32 version of this, eg .bat file
        if sys.platform != 'win32':
            with pytest.raises(RuntimeError):
                p = os.path.join(split(__file__)[0], 'openssl_version_97')
                set_openssl(p)
        set_openssl(good_path)
        if sys.platform in ['win32']:
            # exercise more code by forcing a reconstructon of the .bat files:
            if OPENSSL.endswith('.bat'):
                if bat_identifier in open(OPENSSL, 'rb').read():
                    os.unlink(OPENSSL)
            if DESTROY_EXE.endswith('.bat'):
                if bat_identifier in open(DESTROY_EXE, 'rb').read():
                    os.unlink(DESTROY_EXE)

        command_alias()
        set_openssl()
        set_destroy()
        sys.argv = [sys.executable, lib_path, '--verbose']
        args = _parse_args()
        logging = set_logging(True)
        logging.debug('test message')

        get_dropbox_path()

    def test_stdin_pipeout(self):
        # passwords are typically sent to openssl via stdin
        msg = 'echo'
        cmd = ('grep', 'findstr')[sys.platform == 'win32']
        echo = sys_call([cmd, msg], stdin=msg)
        assert echo == msg

    def test_unicode_path(self):
        stuff = b'\0'
        for filename in ['normal', ' ¡pathol☢gical filename!  ']:
            u = _uniq_file(filename)
            assert u == filename

            # test basic file read-write:
            with open(filename, 'wb') as fd:
                fd.write(stuff)
            with open(filename, 'rb') as fd:
                b = fd.read()
            # test whether archive works:
            #t = make_archive(filename)

            if sys.platform in ['win32']:
                continue
                # otherwise get annoying tmp files

            # test whether encrypt can handle it:
            pub, priv, pphr = _known_values()[:3]
            sf = SecFile(filename)
            sf.encrypt(pub)  # tarfile fails here, bad filename
            assert isfile(sf.file)

            sf.decrypt(priv, pphr)
            assert stuff == open(sf.file, 'rb').read()
        if sys.platform in ['win32']:
            pytest.skip()

    def test_bit_count(self):
        # bit count using a known pub key
        pub, __, __, bits, __ = _known_values()
        assert int(bits) == get_key_length(pub)

    def test_padding(self):
        known_size = 128
        orig = b'a' * known_size
        tmp1 = 'padtest.txt'
        tmp2 = 'padtest2.txt'
        with open(tmp1, 'wb') as fd:
            fd.write(orig)
        with open(tmp2, 'wb') as fd:
            fd.write(orig * 125)

        sf1 = SecFile(tmp1, codec=codec)
        sf2 = SecFile(tmp2, codec=codec)
        sf1._ok_to_pad(12)

        # less that PAD_MIN:
        with pytest.raises(PaddingError):
            sf1.pad(2)

        # bad pad, file would be longer than size
        with pytest.raises(PaddingError):
            sf1.pad(known_size)

        # bad unpad (non-padded file):
        with pytest.raises(PaddingError):
            sf1.unpad()
        with pytest.raises(PaddingError):
            sf1.pad(-1)  # strict should fail

        # padding should obscure file sizes (thats the whole point):
        _test_size = known_size * 300
        sf1.pad(_test_size)
        sf2.pad(_test_size)
        assert sf1.size == sf2.size == _test_size

        sf1.unpad()
        sf1.pad()
        sf1.pad(-1)  # same as unpad
        sf1.pad(0)
        assert orig == open(tmp1, 'rb').read()

        # tmp1 is unpadded at this point:
        sf1.pad(0)  # not strict should do nothing quietly

        #global PAD_BYTE
        pyfilesec.PAD_BYTE = b'\1'
        sf1.pad(2 * known_size)
        file_contents = open(tmp1, 'rb').read()
        assert file_contents[-1] == pyfilesec.PAD_BYTE  # actual byte should not matter

        pyfilesec.PAD_BYTE = b'\0'
        with pytest.raises(PaddingError):
            sf1.pad(-1)  # should be a byte mismatch at this point

        # pad a null file should work:
        with open(tmp2, 'wb') as fd:
            fd.write('')
        assert getsize(tmp2) == 0
        sf = SecFile(tmp2).pad()
        assert sf.size == DEFAULT_PAD_SIZE

        # non-int, negative, or too-large value for pad-len in the file:
        with open(tmp2, 'wb') as fd:
            bad_pad_bytes = PAD_STR + "abc0000000"
            stuff = 'a' * 128  + bad_pad_bytes + PAD_BYTE + PFS_PAD + PAD_BYTE
            fd.write(stuff)
        assert SecFile(tmp2)._pad_len() == 0
        with open(tmp2, 'wb') as fd:
            bad_pad_bytes = PAD_STR + "-100000000"
            stuff = 'a' * 128  + bad_pad_bytes + PAD_BYTE + PFS_PAD + PAD_BYTE
            fd.write(stuff)
        assert SecFile(tmp2)._pad_len() == 0
        with open(tmp2, 'wb') as fd:
            bad_pad_bytes = PAD_STR + "1000000000"
            stuff = 'a' * 128  + bad_pad_bytes + PAD_BYTE + PFS_PAD + PAD_BYTE
            fd.write(stuff)
        assert SecFile(tmp2)._pad_len() == 0

    def test_logging(self):
        sys.argv = [__file__, '--pad', 'no file', '--verbose']
        args = _parse_args()
        log_test = set_logging()
        log_test.debug('trigger coverage of debug log')

    def test_no_metadata(self):
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext unicode.txt'
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = _known_values()[:4]

        # Should not be able to suppress meta-data file, just the info:
        for some_meta in [False, {}, {'old meta': 'stuff'}, True]:
            sf = SecFile(datafile)
            sf.encrypt(pub1, meta=some_meta, keep=True)
            if not some_meta:
                assert sf.result['meta'] == NO_META_DATA
            else:
                assert sf.result['meta'] != NO_META_DATA

        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        sf = SecFile(datafile)
        with pytest.raises(AttributeError):
            sf.encrypt(pub1, meta='junk', keep=True)

    def test_max_size_limit(self):
        # avoid large files at encrypt() or pad(), others ok
        # manually tested: works with an actual large file as well
        MAX_restore = pyfilesec.MAX_FILE_SIZE
        pyfilesec.MAX_FILE_SIZE = 2 ** 8  # fake, to test if hit the limit
        over_max = 'maxsize_plus1.txt'
        with open(over_max, write_mode) as fd:
            fd.write(b'a' * (pyfilesec.MAX_FILE_SIZE + 1))  # ensure too large

        # test whether invoking encrypt/decrypt checks file size appropriately:
        pub, priv, pphr = _known_values()[:3]

        # no error to set a large file--might be an encrypted file:
        sf = SecFile(over_max)
        # yes error if try to encrypt it:
        with pytest.raises(ValueError):
            sf.encrypt(pub)

        # yes ValueError if try to pad it: (PaddingError if just under max)
        pyfilesec.MAX_FILE_SIZE += 2
        sf = SecFile(over_max)
        with pytest.raises(ValueError):
            sf.pad(pyfilesec.MAX_FILE_SIZE + 1)

        # a file that goes over max size duing encryption should still decrypt:
        at_max = 'maxsize.txt'
        msg = b'a' * (pyfilesec.MAX_FILE_SIZE)
        with open(at_max, write_mode) as fd:
            fd.write(msg)
        sf = SecFile(at_max)
        sf.encrypt(pub)
        assert sf.size > pyfilesec.MAX_FILE_SIZE
        sf.decrypt(priv, pphr=pphr)
        assert open(sf.file, read_mode).read() == msg

        pyfilesec.MAX_FILE_SIZE = MAX_restore

    def test_compressability(self):
        # idea: check that encrypted is not compressable, cleartext is
        datafile = 'test_size'
        with open(datafile, write_mode) as fd:
            fd.write(b'1')
        size_orig = getsize(datafile)
        assert size_orig == 1

        pad2len = 16384
        sf = SecFile(datafile)
        sf.pad(pad2len)  # should be very compressable, mostly padding
        assert pad2len == sf.size

        # add some compression
        arc = SecFileArchive(files=[datafile])
        size_tgz = getsize(arc.name)
        assert 150 < size_tgz < 200 < pad2len // 8  # pass if much smaller
        sf.encrypt(_known_values()[0])
        assert pad2len * 1.02 < sf.size  # pass if not smaller
        assert sf.size < pad2len * 1.20  # pass if than than 20% bigger

    def test_permissions(self):
        if sys.platform == 'win32':
            pytest.skip()
            # need different tests

        assert PERMISSIONS == 0o600
        assert UMASK == 0o077

        filename = 'umask_test no unicode'
        pub, priv, pphr = _known_values()[:3]
        umask_restore = os.umask(0o002)  # need permissive to test
        with open(filename, write_mode) as fd:
            fd.write(b'\0')
        assert permissions_str(filename) == '0o664'  # permissive to test
        sf = SecFile(filename)
        sf.encrypt(pub)
        assert int(sf.permissions) == PERMISSIONS
        assert not isfile(filename)
        sf.decrypt(priv, pphr)
        assert int(sf.permissions) == PERMISSIONS  # restricted
        os.umask(umask_restore)

    def test_rename(self):
        with open('abc', 'wb') as fd:
            fd.write('abc')
        s = SecFile('abc')
        s.rename('bca')
        assert isfile('bca')

        with pytest.raises(IOError):
            secure_rename('missing file name', 'abc')

        # try to trigger OSError as handled within secure rename, but its
        # triggered only if tmp is on another disk partition
        tmp = NamedTemporaryFile()
        tmp.write('x')
        secure_rename(tmp.name, 'abc')

    def test_dropbox_stuff(self):
        # assume that is_in_dropbox returns actual Dropbox folder, or False
        # test whether decrypt() will refuse to proceed inside it

        # use real Dropbox path if this test machine has it, otherwise fake it
        real_dropbox_path = get_dropbox_path()  # sets dropbox_path global
        #global dropbox_path
        orig_path = pyfilesec.dropbox_path

        # set up a path and a file
        if real_dropbox_path == False:
            fake_dropbox_path = _abspath('.')
            pyfilesec.dropbox_path = fake_dropbox_path  # set global var
            assert get_dropbox_path() == fake_dropbox_path
        test_path = os.path.join(pyfilesec.dropbox_path, 'test.txt')
        with open(test_path, 'wb') as fd:
            fd.write('test db file contents')
        assert isfile(test_path)

        # raise FileStatusError if try to decrypt in Dropbox folder
        pub, priv, pphr = _known_values()[:3]
        sf = SecFile(test_path)
        sf.encrypt(pub, keep=True)
        assert sf.is_in_dropbox  # whether real or fake
        with pytest.raises(FileStatusError):
            sf.decrypt(priv, pphr)
        os.unlink(test_path)
        #os.unlink(sf.file)
        sf.destroy()  # get coverage

        # partial test of get_dropbox_path()
        pyfilesec.dropbox_path = None
        if real_dropbox_path and sys.platform != 'win32':
            host_db = os.path.expanduser('~/.dropbox/host.db')
            # temporarily moves your actual dropbox locator file
            # seems safe enough: gets auto-rebuilt by Dropbox if file is lost
            if exists(host_db):
                try:
                    os.rename(host_db, host_db + '.orig')
                    get_dropbox_path()
                    assert sf.is_in_dropbox == False  # bc no dropbox now
                finally:
                    os.rename(host_db + '.orig', host_db)
                assert pyfilesec.dropbox_path == False

        pyfilesec.dropbox_path = orig_path


class TestCodecReg(object):
    def setup_class(self):
        global codec
        codec = PFSCodecRegistry(default_codec)

        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)

    def teardown_class(self):
        os.chdir(self.start_dir)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_codec_registry(self):
        # Test basic set-up:
        test_codec = PFSCodecRegistry()
        assert len(list(test_codec.keys())) == 0
        test_codec = PFSCodecRegistry(default_codec)
        assert len(list(test_codec.keys())) == 2
        current = list(codec.keys())
        assert (current[0].startswith('_encrypt_') or
                current[0].startswith('_decrypt_'))
        assert (current[1].startswith('_encrypt_') or
                current[1].startswith('_decrypt_'))
        test_codec.unregister(current)
        assert len(list(test_codec.keys())) == 0
        test_codec.unregister(current)  # should log.warn but not raise

        test_codec.register(default_codec)
        assert len(list(test_codec.keys())) == 2
        with pytest.raises(ValueError):
            test_codec.register(default_codec)  # already regd

        bad = default_codec.copy()
        bad['_encrypt_rsa_aes256cbc'] = 'something not callable'
        with pytest.raises(ValueError):
            test_codec.register(bad)

        # too short / bad keys:
        bad1 = {'_en': pyfilesec._encrypt_rsa_aes256cbc}
        bad2 = {'_foo': pyfilesec._decrypt_rsa_aes256cbc}
        with pytest.raises(ValueError):  # too short
            test_codec.register(bad1)
        with pytest.raises(ValueError):  # not _enc or _dec
            test_codec.register(bad2)

        # unicode not convertable to ascii:
        bad_key = u'_encrypt_☢☢☢_aes256cbc'
        with pytest.raises(UnicodeEncodeError):
            str(bad_key)
        bad = {bad_key: pyfilesec._encrypt_rsa_aes256cbc}
        with pytest.raises(ValueError):
            test_codec.register(bad)

        # unicode convertable to ascii:
        test_codec2 = PFSCodecRegistry()
        ok = {u'_decrypt_rsa_aes256cbc': pyfilesec._decrypt_rsa_aes256cbc}
        str(list(ok.keys())[0])
        test_codec2.register(ok)

        with pytest.raises(CodecRegistryError):
            test_codec2.get_function('this key is so not in the codec')

    def test_add_new_codec(self):
        import codecs
        global _encrypt_rot13
        global _decrypt_rot13

        def _encrypt_rot13(dataFile, *args, **kwargs):
            stuff = open(dataFile, 'rb').read()
            with open(dataFile, 'wb') as fd:
                fd.write(codecs.encode(stuff, 'rot_13'))
            return dataFile
        _decrypt_rot13 = _encrypt_rot13  # == fun fact

        rot13 = {'_encrypt_rot13': _encrypt_rot13,
                 '_decrypt_rot13': _decrypt_rot13}
        codec.register(rot13)
        assert '_encrypt_rot13' in list(codec.keys())
        assert '_decrypt_rot13' in list(codec.keys())

        clearText = 'clearText.txt'
        secret = 'la la la, sssssh!'
        with open(clearText, 'wb') as fd:
            fd.write(secret)
        _decrypt_rot13(_encrypt_rot13(clearText))
        extracted = open(clearText, 'rb').read()
        assert extracted == secret
        # not working yet, due to encrypt() expect a pubkey, etc:
        # decrypt(encrypt(clearText, encMethod='_encrypt_rot13'))

        # test whether can register just a _dec but not _enc function:
        codec.unregister(rot13)
        dec_rot13 = {'_decrypt_rot13': _decrypt_rot13}
        codec.register(dec_rot13)
        enc_rot13 = {'_encrypt_rot13': _encrypt_rot13}
        codec.register(enc_rot13)  # OK because dec is already there
        codec.unregister(rot13)
        with pytest.raises(ValueError):
            codec.register(enc_rot13)  # fails because dec is no longer there

    def test_default_codec_fxn_errors(self):
        # testing error conditions rather than enc dec per se
        # the ususal suspects:
        pub, priv, pphr = _known_values()[:3]
        tmp = 'test_default_enc_dec'
        with open(tmp, 'wb') as fd:
            fd.write('asd')
        sf = SecFile(tmp, pub=pub, priv=priv, pphr=pphr)
        sf.encrypt(keep=True)
        enc, pwd, meta = SecFileArchive(sf.file).unpack()

        # ----------
        DECRYPT = codec_registry.get_function('_decrypt_rsa_aes256cbc')
        assert DECRYPT
        assert DECRYPT(enc, pwd, priv, sf.rsakeys.pphr, openssl=OPENSSL)

        # test no openssl
        with pytest.raises(RuntimeError):
            DECRYPT(enc, pwd, priv, sf.rsakeys.pphr, openssl=None)
        with pytest.raises(RuntimeError):
            DECRYPT(enc, pwd, priv, sf.rsakeys.pphr, openssl=OPENSSL + 'xyz')

        # bad pwd (use pub to test)
        with pytest.raises(DecryptError):
            DECRYPT(enc, pub, priv, sf.rsakeys.pphr, openssl=OPENSSL)

        # TO-DO: various other decrypt failure conditions... harder to induce

        # ----------
        ENCRYPT = codec_registry.get_function('_encrypt_rsa_aes256cbc')
        assert ENCRYPT
        assert ENCRYPT(tmp, pub, openssl=OPENSSL)

        # test no openssl
        with pytest.raises(RuntimeError):
            ENCRYPT(tmp, pub, openssl=None)
        with pytest.raises(RuntimeError):
            ENCRYPT(tmp, pub, openssl=OPENSSL + 'xyz')
