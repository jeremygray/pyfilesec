#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Test suite for pytest.

Part of the pyFileSec library. Copyright (c) 2013, Jeremy R. Gray
"""


import argparse
import copy
import os
from   os.path import abspath, isfile, getsize, isdir, exists, split
import pytest
import shutil
import sys

import pyfilesec
from   pyfilesec import *
from   pyfilesec import _abspath, _uniq_file, _parse_args

# referenced in tests: pyfilesec._encrypt_rsa_aes256cbc
#                      pyfilesec._decrypt_rsa_aes256cbc


class Tests(object):
    """Test suite for py.test

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

    def _known_values(self, folder=''):
        """Return tmp files with known keys, data, signature for testing.
        This is a WEAK key, 1024 bits, for testing ONLY.
        """
        bits = '1024'
        pub, priv, pphr = DEMO_RSA_KEYS()

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

    def _known_values_no_pphr(self, folder=''):
        bits = '1024'
        pub = os.path.join(folder, 'pubKnown_no_pphr')
        pubkey = """-----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3jHEfUzcy4B8N/Neiee3XYGiy
            SNsNU9jB/tUwEOS3gSOs4IQGGkL7bwvqfby+UwFTHx3F2UfIANQ5qtq6xY88JaV7
            kgpx84K96CneT9x8zSr71ZPmKeQJWDLq0V15jo3ABUj8gvPMiytWA0IhhiaCrZrI
            bCjd/2UTJlSVnAxuBwIDAQAB
            -----END PUBLIC KEY-----
            """.replace('    ', '')
        if not isfile(pub):
            with open(pub, 'wb') as fd:
                fd.write(pubkey)
        priv = os.path.join(folder, 'privKnown_no_pphr')
        privkey = """-----BEGIN RSA PRIVATE KEY-----
            MIICWwIBAAKBgQC3jHEfUzcy4B8N/Neiee3XYGiySNsNU9jB/tUwEOS3gSOs4IQG
            GkL7bwvqfby+UwFTHx3F2UfIANQ5qtq6xY88JaV7kgpx84K96CneT9x8zSr71ZPm
            KeQJWDLq0V15jo3ABUj8gvPMiytWA0IhhiaCrZrIbCjd/2UTJlSVnAxuBwIDAQAB
            AoGAOq1cEI6Sy+HYK6mT6e4eucapUa120bjnR4VG8/nClGNlW0PfEPBeT3D9lzYh
            G5r/hmohI3nFt8uEDPdwu1qi4iWp+WRUBJKYhw31g5xLMuKoQ7ICYc4iJSggigZc
            5EGPA/QyfIBxzNSK6wSAi1H1Y9iF6FK4912RwnNl/1eTM4ECQQDnDl+dZA/tGSHi
            mJ9ZGDviq7GDmGls3SBS0GGCNC3Woj3DfZv8PL2eTs4l9JMR7F+6/DwxMlikqzgE
            wP/I2g7HAkEAy10eATfgJ3azRL6rT+HMAamf8pNY222uO27mbmsi5snmfJx7+I5B
            eJOQdiS15ymVCZgS1tZJQT91SLI70BxmwQJAfCywXDDLklvgZxwo/0PT41TsmNGP
            Tw9j8L3Guaf7Po+A7BAUhbHLIkot5h4T8Bz9scsfOj1ZgF34RC3JCZOPPwJAExY3
            Rbf/0tRiOPaIT6QKqLFJ8NOBiH6/1pYvDHgDu5OBjXqGbCq13GJFMcF6TSrq8Q6T
            3hQYpgYVtO/9iyfPQQJAJbZ3Xw7q8i0vNp/3XsG2S90j9lZ9c6OKwdtRavjWWVm5
            kIZMrRBdjmx7EWpoJ52OVCO+21FtLzUz+I3O4yJDtg==
            -----END RSA PRIVATE KEY-----
            """.replace('    ', '')
        if not isfile(priv):
            with open(priv, 'wb') as fd:
                fd.write(privkey)
        kwnSig0p9p8 = (  # openssl 0.9.8r
            "")
        kwnSig1p0 = (   # openssl 1.0.1e or 1.0.0-fips
            "")

        return (_abspath(pub), _abspath(priv), bits,
                (kwnSig0p9p8, kwnSig1p0))

    def test_constants_imports(self):
        import pyfilesec.constants
        os.chdir(self.start_dir)
        import which
        os.chdir(self.tmp)

    @pytest.mark.notravis
    def test_imports(self):
        os.chdir(self.start_dir)
        import _pyperclip
        import _getpass
        os.chdir(self.tmp)

    def test_secfile_base(self):
        test_file = 'tf'
        with open(test_file, 'wb') as fd:
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
        sf.hardlinks
        sf.is_in_dropbox
        sf._get_git_info(None)
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
        # TO-DO

        # bad file name
        sf._file = test_file + 'xyz'
        with pytest.raises(OSError):
            sf._require_file()
        sf.set_file(test_file)

        # encrypted file:
        pub = self._known_values()[0]
        sf.encrypt(pub, keep=True)
        sf.read()
        assert sf.metadata != {}
        assert sf.metadataf != '{}'

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
        #with pytest.raises(RuntimeError):
        #    p = os.path.join(os.path.split(__file__)[0], 'openssl_version_97')
        #    set_openssl(p)
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
        logging, log_t0 = set_logging(True)
        logging.debug('test message')

        get_dropbox_path()

    def test_SecFile_basics(self):
        with pytest.raises(SecFileFormatError):
            SecFile('.dot_file')
        test_file = 'tf'
        with open(test_file, 'wb') as fd:
            fd.write('a')
        sf = SecFile(test_file)
        str(sf)

        # encrypt-encrypted warning:
        pub, priv, pphr = self._known_values()[:3]
        sf.encrypt(pub)
        sf.encrypt(pub, note='a' * (METADATA_NOTE_MAX_LEN + 1))  # logging.warn

        # decrypt missing passphrase when one is required
        with pytest.raises(PrivateKeyError):
            sf.decrypt()
        with pytest.raises(PassphraseError):
            sf.decrypt(priv=priv)

        # decrypt unencrypted priv key (no passphrase)
        pub_no, priv_no = self._known_values_no_pphr()[:2]
        sf.encrypt(pub_no)
        sf.decrypt(priv_no)

        # fake version control
        os.mkdir('.svn')
        sf.decrypt(priv=priv, pphr=pphr)
        #shutil.rmtree('.svn')  # not yet

        # rotate unencrypted file:
        with open(test_file, 'wb') as fd:
            fd.write('a')
        sf = SecFile(test_file)
        with pytest.raises(FileNotEncryptedError):
            sf.rotate(pub=pub, priv=priv, pphr=pphr)

        # sign with priv no pphr
        sf.sign(priv=priv_no)

        # verify without a sig
        with pytest.raises(AttributeError):
            sf.verify(pub=pub_no)

        # destroy coverage -- dropbox and version control
        assert isdir('.svn')
        sf.destroy()
        shutil.rmtree('.svn')

    def test_RsaKeys(self):
        # placeholder for more tests
        pub, priv, pphr, bits = self._known_values()[:4]

        # test individual keys:
        with pytest.raises(PublicKeyError):
            RsaKeys(pub=priv)
        with pytest.raises(PassphraseError):
            RsaKeys(pub, priv).test()
        with open('bad_pub', 'wb') as fd:
            fd.write('PUBLIC KEY')
        with pytest.raises(PublicKeyError):
            RsaKeys('bad_pub')
        with pytest.raises(PublicKeyError):
            RsaKeys(pub=1)
        RsaKeys()
        with pytest.raises(PrivateKeyError):
            RsaKeys(priv='')
        with pytest.raises(PrivateKeyError):
            RsaKeys(priv=pub)
        with pytest.raises(PrivateKeyError):
            RsaKeys(pphr=1)
        with pytest.raises(PrivateKeyError):
            RsaKeys(priv='')

        # test integrity of the set of keys:
        rk = RsaKeys(pub, priv, pphr).test()

        # same again, no passphrase:
        pub_no, priv_no, bits_no = self._known_values_no_pphr()[:3]
        rk_no = RsaKeys(pub_no, priv_no).test()

        # test get_key_length function
        klen = get_key_length(pub)
        cmdGETMOD = [OPENSSL, 'rsa', '-modulus', '-in',
                     pub, '-pubin', '-noout']
        modulus = sys_call(cmdGETMOD).replace('Modulus=', '')
        assert hexdigits_re.match(modulus)

    def test_SecFileArchive(self):
        # test getting a name
        SecFileArchive(files=None)
        # default get a name from one of the files in paths:
        with open('abc' + AES_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, 'wb') as fd:
            fd.write('abc')
        SecFileArchive(files=['abc' + RSA_EXT, 'abc' + AES_EXT])
        with pytest.raises(AttributeError):
            SecFileArchive(files='abc')
        sf = SecFileArchive()
        with pytest.raises(AttributeError):
            sf.unpack()

        # get_dec_method
        sf = SecFile('abc' + AES_EXT)
        pub = self._known_values_no_pphr()[0]
        sf.encrypt(pub, keep=True, meta=False)
        sfa = SecFileArchive(sf.file)
        sfa.unpack()
        sfa.get_dec_method(codec_registry)

        sfa = SecFileArchive().pack(pub)
        with open('ttt', 'wb') as fd:
            fd.write('ttt')
        with pytest.raises(SecFileArchiveFormatError):
            s = SecFileArchive('ttt')
            s.name = 'ttt'
            s.unpack()

        '''
        # test fall-through decryption method:
        with open('abc' + AES_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + META_EXT, 'wb') as fd:
            fd.write(str(NO_META_DATA))
        #assert exists(datafile)
        sf = SecFileArchive(paths=['abc' + AES_EXT,
                                    'abc' + RSA_EXT, 'abc' + META_EXT])
        dec_method = sf.get_dec_method('unknown')
        assert dec_method in list(default_codec.keys())

        # test missing enc-method in meta-data
        md = 'md'
        with open(md, 'wb') as fd:
            fd.write(log_metadata(NO_META_DATA))
        dec_method = _get_dec_method(md, 'unknown')
        assert dec_method == '_decrypt_rsa_aes256cbc'

        # test malformed cipher_text archive:
        archname = _uniq_file(os.path.splitext(datafile)[0] + ENC_EXT)
        bad_arch = make_archive(datafile, archname)  # datafile extension bad
        with pytest.raises(SecFileArchiveFormatError):
            decrypt(bad_arch, priv1, pphr1)
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

    def test_main(self):
        # similar to test_command_line (those do not count toward coverage)

        sys.argv = [__file__, '--help']
        with pytest.raises(SystemExit):
            args = _parse_args()

        sys.argv = [__file__, 'genrsa', '-a']
        with pytest.raises(SystemExit):
            main(_parse_args())

        tmp = 'tmp'
        with open(tmp, 'wb') as fd:
            fd.write('a')

        sys.argv = [__file__, '--pad', '-z', '0', tmp]
        main(_parse_args())

        pub, priv, pphr = self._known_values()[:3]
        sys.argv = [__file__, '--encrypt', '--keep', '--pub', pub,
                    '-z', '0', tmp]
        main(_parse_args())

        sys.argv = [__file__, '--decrypt', '--keep',
                    '--priv', priv, '--pphr', pphr, tmp + ENC_EXT]
        main(_parse_args())

        sys.argv = [__file__, '--rotate', '--pub', pub, '-z', '0',
                    '--priv', priv, '--pphr', pphr, tmp + ENC_EXT]
        out = main(_parse_args())

        sys.argv = [__file__, '--sign', tmp,
                    '--priv', priv, '--pphr', pphr, '--out', 'sig.cmdline']
        outs = main(_parse_args())
        contents = open(outs['out'], 'rb').read()
        if openssl_version < 'OpenSSL 1.0':
            assert "mrKDFi4NrfJVTm+RLB+dHuSHNImUl9" in outs['sig']
            assert "mrKDFi4NrfJVTm+RLB+dHuSHNImUl9" in contents
        else:
            assert 'An3qI8bOdvuKt9g7a+fdFoEdh79Iip' in outs['sig']
            assert "An3qI8bOdvuKt9g7a+fdFoEdh79Iip" in contents

        sys.argv = [__file__, '--verify', tmp,
                    '--sig', outs['out'], '--pub', pub]
        outv = main(_parse_args())
        assert outv['verified'] == True

        sys.argv = [__file__, '--pad', tmp + tmp]
        with pytest.raises(ArgumentError):  # no such file, bad name
            main(_parse_args())

        sys.argv = [__file__, '--pad', '-z', '-24', tmp]  # bad size
        with pytest.raises(ValueError):
            main(_parse_args())

        # misc coverage
        sys.argv = [__file__, tmp, '--unpad']
        main(_parse_args())
        sys.argv = [__file__, tmp, '--hardlinks']
        main(_parse_args())
        sys.argv = [__file__, tmp, '--tracked']
        main(_parse_args())
        sys.argv = [__file__, tmp, '--permissions']
        main(_parse_args())
        sys.argv = [__file__, tmp, '--dropbox']
        main(_parse_args())

        # destroy last
        sys.argv = [__file__, '--destroy', tmp]
        main(_parse_args())

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
            pub, priv, pphr = self._known_values()[:3]
            sf = SecFile(filename)
            sf.encrypt(pub)  # tarfile fails here, bad filename
            assert isfile(sf.file)

            sf.decrypt(priv, pphr)
            assert stuff == open(sf.file, 'rb').read()
        if sys.platform in ['win32']:
            pytest.skip()

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

    def test_bit_count(self):
        # bit count using a known pub key
        pub, __, __, bits, __ = self._known_values()
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

    def test_signatures(self):
        # sign a known file with a known key. can we get known signature?
        __, kwnPriv, kwnPphr, datum, kwnSigs = self._known_values()
        kwnData = 'knwSig'
        with open(kwnData, 'wb+') as fd:
            fd.write(datum)
        sf = SecFile(kwnData).sign(priv=kwnPriv, pphr=kwnPphr)
        sig1 = sf.result['sig']

        if openssl_version < 'OpenSSL 1.':
            assert sig1 == kwnSigs[0]
        else:
            assert sig1 == kwnSigs[1]

        # test result[`out`] contains filename, with sig in that file
        outfile = 'sig.out'
        sf.sign(priv=kwnPriv, pphr=kwnPphr, out=outfile)
        assert sf.result['out'] == outfile
        assert open(outfile, 'rb').read() in kwnSigs

    def test_max_size_limit(self):
        # manual test: works with an actual 1G (MAX_FILE_SIZE) file as well
        MAX_restore = pyfilesec.MAX_FILE_SIZE
        pyfilesec.MAX_FILE_SIZE = 2 ** 8  # fake, to test if hit the limit
        tmpmax = 'maxsize.txt'
        with open(tmpmax, 'w+b') as fd:
            fd.write(b'a' * (pyfilesec.MAX_FILE_SIZE + 1))  # ensure too large

        with pytest.raises(FileStatusError):
            sf = SecFile(tmpmax)
        pyfilesec.MAX_FILE_SIZE += 2
        sf = SecFile(tmpmax)
        with pytest.raises(ValueError):
            sf.pad(pyfilesec.MAX_FILE_SIZE + 1)
        pyfilesec.MAX_FILE_SIZE = getsize(tmpmax) - 2
        with pytest.raises(ValueError):
            hmac_sha256('key', tmpmax)

        pyfilesec.MAX_FILE_SIZE = MAX_restore

    @pytest.mark.slow
    def test_big_file(self):
        # by default, tests a file just over the LRG_FILE_WARN limit (17M)
        # uncomment to create encrypt & decrypt a 8G file, takes a while

        bs = 4096  # block size
        zeros = b'\0' * bs
        test_counts = [1 + LRG_FILE_WARN // bs]  # hit size warning
        #test_counts.append(MAX_FILE_SIZE // bs)  # 8G file test
        #test_counts.append(1)  # test the test
        for count in test_counts:
            size = bs * count  # bytes
            # make a big ol' file:
            try:
                orig = 'bigfile.zeros'
                enc = 'bigfile' + ENC_EXT
                with open(orig, 'wb') as fd:
                    for i in range(count):
                        fd.write(zeros)
                # not much faster at least for LRG_FILE_WARN:
                #    sys_call(['dd', 'if=/dev/zero', 'of=%s' % orig,
                #          'bs=%d' % bs, 'count=%d' % count])
                pub, priv, pphr = self._known_values()[:3]
                sf = SecFile(orig)
                sf.encrypt(pub)
                bigfile_size = sf.size
            finally:
                os.remove(sf.file)
            assert bigfile_size > size

    @pytest.mark.slow
    def test_GenRSA(self):
        # set sys.argv to test arg usage; similar in test_main()

        gen = GenRSA()
        gen.check_entropy()

        # test dialog
        sys.argv = [__file__, 'genrsa', '--passfile']
        args = _parse_args()
        pub, priv, pp = genrsa(interactive=False)
        GenRSA().dialog(interactive=False, args=args)
        sys.argv = [__file__, 'genrsa', '--clipboard']
        args = _parse_args()
        GenRSA().dialog(interactive=False, args=args)

        # induce some badness to increase test cov: pub==priv, existing priv:
        sys.argv = [__file__, 'genrsa', '--pub', priv, '--priv', priv]
        args = _parse_args()
        pu, pr, pp = gen.dialog(interactive=False)
        gen._cleanup('test cleanup', pu, pr, pp)
        gen._cleanup('test cleanup', pu, pr, 'passphrase')

        # the test is that we won't overwrite existing priv
        # priv comes from _uniq(pub) to preserve matched sets of key files
        '''
        priv = _uniq_file(pub)
        with open(priv, 'wb') as fd:
            fd.write('a')
        assert isfile(priv)  # or can't test
        sys.argv = [__file__, 'genrsa', '--priv', priv]
        args = _parse_args()
        pu, pr, pp = gen.dialog(interactive=False)
        assert (pu, pr) == (None, None)
        '''

    def test_logging(self):
        sys.argv = [__file__, '--pad', 'no file', '--verbose']
        args = _parse_args()
        log_test, log_test_t0 = set_logging()
        log_test.debug('trigger coverage of debug log')

    def test_default_codec_fxn_errors(self):
        # testing error conditions rather than enc dec per se
        # the ususal suspects:
        pub, priv, pphr = self._known_values()[:3]
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
        # TO-DO: various other failure conditions... harder to induce
        # bad pwd (use pub to test)
        with pytest.raises(PrivateKeyError):
            DECRYPT(enc, pub, priv, sf.rsakeys.pphr, openssl=OPENSSL)

        # ----------
        ENCRYPT = codec_registry.get_function('_encrypt_rsa_aes256cbc')
        assert ENCRYPT
        assert ENCRYPT(tmp, pub, openssl=OPENSSL)

        # test no openssl
        with pytest.raises(RuntimeError):
            ENCRYPT(tmp, pub, openssl=None)
        with pytest.raises(RuntimeError):
            ENCRYPT(tmp, pub, openssl=OPENSSL + 'xyz')

    def test_encrypt_decrypt(self):
        # test with null-length file, and some secret content
        secret = 'secret snippet %s' % printable_pwd(128, '#').str
        for secretText in ['', secret]:
            datafile = 'cleartext no unicode.txt'
            with open(datafile, 'wb') as fd:
                fd.write(secretText)
            assert getsize(datafile) in [0, len(secret)]

            testBits = 2048  # fine to test with 1024 and 4096
            pubTmp1 = 'pubkey1 no unicode.pem'
            prvTmp1 = 'prvkey1 no unicode.pem'
            pphr1 = printable_pwd(180)
            pub1, priv1 = GenRSA().generate(pubTmp1, prvTmp1, pphr1.str, testBits)

            pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
            prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
            pphr2_spaces = printable_pwd(180)
            pphr2_w_spaces = copy.copy('  ' + pphr2_spaces.str + '   ')
            pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2,
                                            pphr2_w_spaces, testBits)

            # test decrypt with GOOD passphrase, trailing whitespace:
            sf = SecFile(datafile).encrypt(pub2)  # not keep=True
            sf.decrypt(priv2, pphr=pphr2_w_spaces)
            recoveredText = open(sf.file).read()
            # file contents match:
            assert recoveredText == secretText
            # file name match: can FAIL due to utf-8 encoding issues
            assert os.path.split(sf.file)[-1] == datafile

            # send some bad parameters:
            with pytest.raises(ValueError):
                SecFile(datafile).encrypt(pub2, enc_method='abc')
            with pytest.raises(PublicKeyError):
                SecFile(datafile).encrypt(pub=None)
            with pytest.raises(OSError):
                SecFile(datafile + ' oops').encrypt(pub2)
            with pytest.raises(ValueError):
                SecFile().encrypt(pub2)
            with pytest.raises(ValueError):
                SecFile(datafile).encrypt(pub2, keep=17)

            # test decrypt with GOOD passphrase as STRING:
            assert exists(datafile)
            sf = SecFile(datafile).encrypt(pub1)
            sf.decrypt(priv1, pphr1.str)
            recoveredText = open(sf.file).read()
            # file contents match:
            assert recoveredText == secretText
            # file name match: can FAIL due to utf-8 encoding issues
            assert os.path.split(sf.file)[-1] == datafile

            # test decrypt with GOOD passphrase in a FILE:
            sf = SecFile(datafile).encrypt(pub1, keep=True)
            pphr1_file = prvTmp1 + '.pphr'
            with open(pphr1_file, 'wb') as fd:
                fd.write(pphr1.str)
            sf.decrypt(priv1, pphr1_file)
            recoveredText = open(sf.file).read()
            # file contents match:
            assert recoveredText == secretText

            # a BAD or MISSING passphrase should fail:
            sf = SecFile(datafile).encrypt(pub1, keep=True)
            with pytest.raises(PrivateKeyError):
                sf.decrypt(priv1, pphr2_w_spaces)
            with pytest.raises(PrivateKeyError):
                sf.decrypt(priv1)

            # a correct-format but wrong priv key should fail:
            sf = SecFile(datafile).encrypt(pub1, keep=True)
            pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr1.str, testBits)
            with pytest.raises(PrivateKeyError):
                sf.decrypt(priv2, pphr1.str)

            # should refuse-to-encrypt if pub key is too short:
            with pytest.raises(PublicKeyTooShortError):
                pub256, __ = GenRSA().generate('pub256.pem',
                                               'priv256.pem', bits=256)
            #global RSA_MODULUS_MIN
            rsa_mod_orig = pyfilesec.RSA_MODULUS_MIN
            pyfilesec.RSA_MODULUS_MIN = 4096
            try:
                sf = SecFile(datafile)
                with pytest.raises(PublicKeyTooShortError):
                    sf.encrypt(pub2)
            finally:
                pyfilesec.RSA_MODULUS_MIN = rsa_mod_orig

    def test_rotate(self):
        # Set-up:
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'file to rotate.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pwd = printable_pwd(180)
        pphr2 = '  ' + pwd.str + '   '  # spaces in pphr
        #print pwd, pphr2
        pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr2, 1024)

        # Rotate encryption including padding change:
        sf = SecFile(datafile).encrypt(pub1, date=False, keep=True)
        first_enc_size = sf.size
        sf.rotate(pub=pub2, priv=priv1, pphr=pphr1, pad=8192)
        second_enc_size = sf.size
        sf.rotate(pub=pub1, priv=priv2, pphr=pphr2, pad=16384, hmac_key='key')
        assert first_enc_size < second_enc_size < sf.size

        md = sf.metadata  # save metadata now for testing below

        sf.decrypt(priv1, pphr=pphr1)
        assert not open(sf.file).read() == secretText  # dec but still padded
        sf.pad(0)
        assert open(sf.file).read() == secretText

        # Meta-data from key rotation:
        dates = list(md.keys())
        hashes = [md[d]['hash of cipher_text'] for d in dates]
        assert len(hashes) == len(set(hashes)) == 3
        assert ('meta-data %s' % DATE_UNKNOWN) in dates

        # Should be only one hmac-sha256 present; hashing tested in test_hmac:
        hmacs = [md[d]['hash of cipher_text'] for d in dates
                 if 'hmac (enc-then-mac)' in list(md[d].keys())]
        assert len(hmacs) == 1

    def test_no_metadata(self):
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext unicode.txt'
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

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

    def test_misc_crypto(self):
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext unicode.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

        # Using keep=True should not remove orig file:
        sf = SecFile(datafile).encrypt(pub1, keep=True)
        assert isfile(datafile)
        data_aes, pwd_rsa, meta = SecFileArchive(sf.file).unpack()

        # Check size of RSA-pub encrypted password for AES256:
        assert getsize(pwd_rsa) == int(testBits) // 8

        # Non-existent decMethod should fail:
        with pytest.raises(CodecRegistryError):
            SecFile(sf.file).decrypt(priv1, pphr1,
                          dec_method='_decrypt_what_the_what')
        # Good decMethod should work:
        SecFile(sf.file).decrypt(priv1, pphr1,
                          dec_method='_decrypt_rsa_aes256cbc')

    def test_compressability(self):
        # idea: check that encrypted is not compressable, cleartext is
        datafile = 'test_size'
        with open(datafile, 'wb') as fd:
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
        sf.encrypt(self._known_values()[0])
        assert pad2len * 1.02 < sf.size  # pass if not smaller
        assert sf.size < pad2len * 1.20  # pass if than than 20% bigger

    def test_permissions(self):
        if sys.platform == 'win32':
            pytest.skip()
            # need different tests

        assert PERMISSIONS == 0o600
        assert UMASK == 0o077

        filename = 'umask_test no unicode'
        pub, priv, pphr = self._known_values()[:3]
        umask_restore = os.umask(0o002)  # need permissive to test
        with open(filename, 'wb') as fd:
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

    def test_hmac(self):
        # verify pfs hmac implementation against a widely used example:
        key = 'key'
        value = "The quick brown fox jumps over the lazy dog"
        hm = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
        tmp = 'hmac_test no unicode'
        with open(tmp, 'wb+') as fd:
            fd.write(value)
        hmac_openssl = hmac_sha256(key, tmp)
        # openssl 1.0.x returns this:
        # 'HMAC-SHA256(filename)= f7bc83f430538424b13298e6aa6fb143e97479db...'
        assert hmac_openssl.endswith(hm)
        assert hmac_openssl.split(')= ')[-1] == hm

        # bad key, file:
        # test of hmac file MAX_SIZE is in test_max_size_limit
        assert hmac_sha256(None, tmp) is None

    def test_command_line(self):
        # send encrypt and decrypt commands via command line

        datafile = 'cleartext no unicode.txt'
        secretText = 'secret snippet %.6f' % get_time()
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1 = self._known_values()[:3]
        pathToSelf = lib_path
        datafile = _abspath(datafile)

        # Encrypt:
        cmdLineCmd = [sys.executable, pathToSelf, datafile, '--encrypt',
                      '--pub', pub1, '--keep', '--openssl=' + OPENSSL]
        oute = sys_call(cmdLineCmd)
        assert 'cipher_text' in oute
        enc = eval(oute)
        assert isfile(enc['cipher_text'])

        # Decrypt:
        cmdLineCmd = [sys.executable, pathToSelf,
                      enc['cipher_text'], '--decrypt', '--keep',
                      '--priv', priv1, '--pphr', pphr1, '--openssl=' + OPENSSL]
        outd = sys_call(cmdLineCmd)
        assert 'clear_text' in outd
        dec = eval(outd)
        assert isfile(dec['clear_text'])
        recoveredText = open(dec['clear_text']).read()
        assert recoveredText == secretText  # need both enc and dec to work

        # Rotate:
        assert (isfile(enc['cipher_text']) and
            enc['cipher_text'].endswith(ENC_EXT))  # need --keep in d
        cmdLineRotate = [sys.executable, pathToSelf,
                         enc['cipher_text'], '--rotate',
                        '--pub', pub1, '--priv', priv1, '--pphr', pphr1,
                        '-z', str(getsize(enc['cipher_text']) * 2)]
        outr = sys_call(cmdLineRotate)  # dict as a string
        assert 'rotate' in outr and 'good' in outr
        rot = eval(outr)
        assert isfile(rot['file'])

        # Sign and Verify (target = the file from rot):
        cmdLineSign = [sys.executable, pathToSelf, rot['file'], '--sign',
                      '--priv', priv1, '--pphr', pphr1, '--out', 'sig.out']
        outs = sys_call(cmdLineSign)
        assert 'sig' in outs
        sig = eval(outs)
        cmdLineVerify = [sys.executable, pathToSelf, rot['file'], '--verify',
                      '--pub', pub1, '--sig', sig['out']]
        outv = sys_call(cmdLineVerify)
        assert 'verified' in outv
        out = eval(outv)
        assert out['verified']  # need both sign and verify to work

        # Pad, unpad:
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        orig_size = getsize(datafile)
        cmdLinePad = [sys.executable, pathToSelf, datafile, '--pad']
        outp = sys_call(cmdLinePad)
        assert "'method': 'pad'" in outp
        assert "'size': %d" % DEFAULT_PAD_SIZE in outp
        out = eval(outp)
        assert getsize(datafile) == DEFAULT_PAD_SIZE

        # more coverage
        cmdLineUnpad = [sys.executable, pathToSelf, datafile, '--pad',
                        '-z', '0']
        outunp = sys_call(cmdLineUnpad)
        assert 'padding' in outunp
        out = eval(outunp)
        assert out['padding'] == None

        cmdLineUnpad = [sys.executable, pathToSelf, datafile, '--pad',
                        '-z', '0', '--verbose']
        outv = sys_call(cmdLineUnpad)
        assert outv.startswith('0.000')
        assert lib_name in outv
        assert len(outv) > 1000
        assert len(outv.splitlines()) > 50

        # Destroy:
        cmdLineDestroy = [sys.executable, pathToSelf, datafile, '--destroy']
        outx = sys_call(cmdLineDestroy)
        if 'disposition' in outx:
            out = eval(outx)
        assert out['disposition'] == destroy_code[pfs_DESTROYED]

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

    @pytest.mark.slow
    def test_8192_bit_keys(self):
        # mostly just to show that it can be done
        pub = 'pub_8192.pem'
        pub_stuff = """-----BEGIN PUBLIC KEY-----
            MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA1NVm8RI/fo58LNmjNoDA
            sdRZ1L507zBfGufo1cI/0eLfWTOtbHE+hoqCdac2RW/TVd/eTo1/wUqpbnkg1Y6m
            icvaEEfCivhBgQNrJLvXLrqkg1J9ApI6ha4kDpgsFkYITy+GdNNQcbuLJ88eA1nn
            oy1JiSBOtuXOP2OQnMI/zssPL0RogofqGIIGtOxeQia5eGS3d7fQkbZEN5dqBLJZ
            FqGDtMqCcMmZFnfGTfKUEtf3LH1dTvelHx/ypvRp5ir92c4qz9JA21ftbuTfJIkw
            9S672WsoghCuFZpdxRn/r0q5wanWPVPb7GiTSbTfcjrZR5Ma5DPm14wCMAo6gAtD
            1CWbFI+x5bHCj8XcW8evqzBn/NtW6Rug3T6tPfuv9O/W5kCq1vUtmktv6Ew+9onN
            CAkTHJKktOIK2ydTHTUeAzEhIzMsvrOSeIpyqkRZK4z5bsbYTcKKxZwq8T9IuiNs
            d5PqfU1NHBCXkEjAMA2aAyB9AEXPC4ENm6fXu5rbioUvzS95oUlnVTFPoc1lDPNx
            MUh8Xm2Qjc01fcIZmEz8IIWLu/refGS2Q2s0hDh1C4mD6bXMh3TVVSI7q2eM8Ftd
            0cBWzj0ufsk0/Vs6zE8xfRdXKSCNHA5qDRh4ZRrufZnw0r2yacCNFB1wdKsVvpOH
            jaGQb590kPewKQ/7aG3WrNLd2/dJfQiXAA7hcKCzbiZf5nwdEu/BaQcZUYBySADK
            PpTVBKaZaCvWKtZKi+0UmMMjgk3uAmkvnlKJt45i5qDcr+i9IziWX/qV9LuX5U/8
            LlqgiA/CGawTlnpOaZWx6hh5/l6d0chJ0ULTGhiEPIeiWMMKE9/zE9D/e6t9PJQ/
            XdaxpIM/2rI8Mx7a3dK4zjqzPkYoP301NcBub9Vq6pQMn/89K8fikGP7LKncI/lf
            n6U9uXKW487u5/WULe1atDQUkCIx1P9UEqQxl8MhUX+KorV8nQFaazGa7tY39YRW
            eBMucPZjC9hywCF1O9+OJW5pGU/WCR/KGKoZfOsGY5GT85HeXdCkYqpemPuLgC9+
            YU2xd5sMPotFHrK5PNMzqpf7xryUiwc0FDgM278Sp9TJ+WO2lp6rTJJfFehINjV5
            1mG4Oddf3k9RJWk5CEuEPhV2kP3JH6EslnkjS4M1l2w3pLc/5XkMYyL9kUlRXW7I
            bqbPXrds/GuVR42vixA8x4Rzb8dIbZauIFvuueWYyETLCGK6jyXhgzRSgFX26aCs
            J/u3eHHpac+xuiZFhXqcSdYocoRyioOQ9X7zqMZxQcfvrxSgl8PVhfh7hzHR9ZPi
            lGzMDEaUjv0ZbkWJa1rohoOtggwMXeKH2mh//0Jp7vYZzfgC/0iIHAQH1MPEodVl
            4wIDAQAB
            -----END PUBLIC KEY-----
            """.replace('    ', '')
        with open(pub, 'wb') as fd:
            fd.write(pub_stuff)
        assert open(pub, 'rb').read() == pub_stuff
        priv = 'priv_8192.pem'
        priv_stuff = """-----BEGIN RSA PRIVATE KEY-----
            Proc-Type: 4,ENCRYPTED
            DEK-Info: AES-256-CBC,ABD70159132455FBDC8E798415A4DE36

            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
            -----END RSA PRIVATE KEY-----
            """.replace('    ', '')
        with open(priv, 'wb') as fd:
            fd.write(priv_stuff)
        assert open(priv, 'rb').read() == priv_stuff
        pphr = 'pphr_8192'
        pphr_stuff = '149acf1a8c196eeb5cdba121567e670b'
        with open(pphr, 'wb') as fd:
            fd.write(pphr_stuff)
        assert open(pphr, 'rb').read() == pphr_stuff

        secretText = 'secret.txt'
        datafile = secretText  # does double duty as file name and contents
        with open(datafile, 'wb') as fd:
            fd.write(secretText)

        sf = SecFile(datafile)
        sf.encrypt(pub).decrypt(priv, pphr=pphr)
        recoveredText = open(sf.file).read()
        assert recoveredText == secretText

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
        pub, priv, pphr = self._known_values()[:3]
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


@pytest.mark.notravis
@pytest.mark.slow
class TestAgain(Tests):
    """Same again using another version of OpenSSL
    """
    def setup_class(self):
        set_openssl('/opt/local/bin/openssl')
        global codec
        codec = PFSCodecRegistry(default_codec)

        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)
