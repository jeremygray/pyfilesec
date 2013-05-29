#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""PyFileSec: Tests, written for py.test
"""

# Copyright (c) Jeremy R. Gray, 2013
# Released under the GPLv3 licence with the additional exemption that
# compiling, linking, and/or using OpenSSL is allowed.

import os
import sys
from os.path import isfile, abspath
import stat
import shutil
import time
from tempfile import NamedTemporaryFile
from pyfilesec import pyfilesec as pfs
from pyfilesec.pyfilesec import *  #OSWCodecRegistry, wipe, _unpad_strict


class Tests(object):
    """Test suite for py.test
    """
    def setup_class(self):
        global pytest
        import pytest

        tmp = '.__öpensslwrap test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)

    def teardown_class(self):
        try:
            shutil.rmtree(self.tmp, ignore_errors=False)
            # CentOS + py2.6 says Tests has no attr self.tmp
        except:
            myhome = '/home/jgray/.__öpensslwrap test__'
            shutil.rmtree(myhome, ignore_errors=False)

    def _knownValues(self):
        """Return tmp files with known keys, data, signature for testing.
        This is a WEAK key, 1024 bits, for testing ONLY.
        """
        bits = '1024'
        pub = 'pubKnown'
        pubkey = """-----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9wLTHLDHvr+g8WAZT77al/dNm
            uFqFFNcgKGs1JDyN8gkqD6TR+ARa1Q4hJSaW8RUdif6eufrGR3DEhJMlXKh10QXQ
            z8EUJHtxIrAgRQSUZz73ebeY4kV21jFyEEAyZnpAsXZMssC5BBtctaUYL9GR3bFN
            yN8lJmBnyTkWmZ+OIwIDAQAB
            -----END PUBLIC KEY-----
            """.replace('    ', '')
        if not os.path.isfile(pub):
            with open(pub, 'w+b') as fd:
                fd.write(pubkey)

        priv = 'privKnown'
        privkey = """-----BEGIN RSA PRIVATE KEY-----
            Proc-Type: 4,ENCRYPTED
            DEK-Info: DES-EDE3-CBC,CAE91148C704A765

            F2UT1W+Xkeux69BbesjG+xIsNtEMs3Nc6i72nrj1OZ7WKBb0keDE3Rin0sdkXzy0
            asbiIAA4fccew0/Wn7rq1v2mOdxgZTGheIDKP7kcPW//jF/XBIrbs0zH3bB9Wztp
            IOfb5YPV/BlPtec/Eniaj5xcWK/UGzebT/ela4f8OjiurIDJxW02XOwN4T6mA55m
            rNxorDmdvt0CmGSZlG8b9nB9XdFSCnBnD1s1l0MwZYHgiBFZ4R8A6mPJPpUFeZcX
            S1l3ty87hU0DcJr0tCwjGV6Ghh7B17+LBWa4Vj4Z+q5yHdYeKj29IIFLvzbvj5Hs
            aMwpFKhiofNVJvTrsZep7ZbGJleTP3wxhlcbK5WY+tL34dHsxGhP0h2VrVESIQN2
            HJj/QfCP8p65Jii1YGlp7SqzQXEt+aoOzbIAPrr0fAtZjWIOsB6imAbloP0kLi96
            9nsB9PKARxZagbe9d4ewLs6Uu0cprw63LUb1r10dx5J22XE84zYTInN1qXeHz1U5
            eSCD6L17f9Ff31Lo4oRITJv4ksZvJRyIRBCubjgaOT5utXo722Df7LsqIzYNC3Ow
            RQRhwISo/AMWvHPRwNnt6ZanzZMc0dUQl36d7Di+lJCTxNRJkPG80UzyULGmnSjT
            v0bA3mUT7/yZUjdXZ1V4zFvkRRXh2wsPkX8UVvvcA+qhbYpE5ChHj7km/ZrS+66x
            L+LTRq7fsv8V21phcofbxZaQfKIO4FeeGnE+v14H2bDKkf7rop4PhDV0E4obCFT3
            THSOgTQAWEWjOU/IwlgOwRz5pM6xV0RmAa7b5uovheI=
            -----END RSA PRIVATE KEY-----
            """.replace('    ', '')
        if not isfile(priv):
            with open(priv, 'w+b') as fd:
                fd.write(privkey)

        pphr = 'pphrKnown'
        p = "337876469593251699797157678785713755296571899138117259"
        if not os.path.isfile(pphr):
            with open(pphr, 'w+b') as fd:
                fd.write(p)

        kwnSig0p9p8 = (  # openssl 0.9.8r
            "dNF9IudjTjZ9sxO5P07Kal9FkY7hCRJCyn7IbebJtcEoVOpuU5Gs9pSngPnDvFE" +
            "2BILvwRFCGq30Ehnhm8USZ1zc5m2nw6S97LFPNFepnB6h+575OHfHX6Eaothpcz" +
            "BK+91UMVId13iTu9d1HaGgHriK6BcasSuN0iTfvbvnGc4=")
        kwnSig1p0 = (   # openssl 1.0.1e or 1.0.0-fips
            "eWv7oIGw9hnWgSmicFxakPOsxGMeEh8Dxf/HlqP0aSX+qJ8+whMeJ3Ol7AgjsrN" +
            "mfk//J4mywjLeBp5ny5BBd15mDeaOLn1ETmkiXePhomQiGAaynfyQfEOw/F6/Ux" +
            "03rlYerys2Cktgpya8ezxbOwJcOCnHKydnf1xkGDdFywc=")
        return (abspath(pub), abspath(priv), abspath(pphr),
                bits, (kwnSig0p9p8, kwnSig1p0))

    def test_codec_registry(self):
        # Test basic set-up:
        test_codec = OSWCodecRegistry()
        assert len(test_codec.keys()) == 0
        test_codec = OSWCodecRegistry(default_codec)
        assert len(test_codec.keys()) == 2
        current = codec.keys()
        assert (current[0].startswith('_encrypt_') or
                current[0].startswith('_decrypt_'))
        assert (current[1].startswith('_encrypt_') or
                current[1].startswith('_decrypt_'))
        test_codec.unregister(current)
        assert len(test_codec.keys()) == 0
        test_codec.register(default_codec)
        assert len(test_codec.keys()) == 2

    def test_bit_count(self):
        # bit count using a known pub key
        logging.debug('test bit_count')
        os.chdir(mkdtemp())
        pub, __, __, bits, __ = self._knownValues()
        assert int(bits) == numBits(pub)

    def test_padding(self):
        known_size = 128
        orig = 'a' * known_size
        tmp1 = 'padtest.txt'
        tmp2 = 'padtest2.txt'
        with open(tmp1, 'w+b') as fd:
            fd.write(orig)
        with open(tmp2, 'w+b') as fd:
            fd.write(orig * 125)

        # bad pad, file would be longer than size
        with pytest.raises(PaddingError):
            pad(tmp1, size=known_size, test=True)

        # bad unpad (non-padded file):
        with pytest.raises(PaddingError):
            _unpad_strict(tmp1)

        # padding should obscure file sizes (thats the whole point):
        _test_size = known_size * 300
        pad(tmp1, size=_test_size)
        pad(tmp2, size=_test_size)
        tmp1_size = getsize(tmp1)
        tmp2_size = getsize(tmp2)
        assert tmp1_size == tmp2_size == _test_size

        # unpad `test` mode should not change file size:
        new = _unpad_strict(tmp1, test=True)
        assert tmp1_size == getsize(tmp1) == new

        _unpad_strict(tmp1)
        pad(tmp1)
        pad(tmp1, -1)  # same as unpad strict
        assert orig == open(tmp1, 'rb').read()

        # tmp is unpadded at this point:
        with pytest.raises(PaddingError):
            pad(tmp1, -1)  # strict should fail
        pad(tmp1, 0)  # not strict should do nothing quietly

        global PAD_BYTE
        PAD_BYTE = b'\1'
        pad(tmp1, 2 * known_size)
        file_contents = open(tmp1, 'rb').read()
        assert file_contents[-1] == PAD_BYTE  # the actual byte is irrelevant
        pad(tmp1, -1, test=True)
        PAD_BYTE = b'\0'
        with pytest.raises(PaddingError):
            pad(tmp1, -1)  # should be a byte mismatch

    def test_signatures(self):
        # sign a known file with a known key. can we get known signature?
        __, kwnPriv, kwnPphr, datum, kwnSigs = self._knownValues()
        with NamedTemporaryFile() as kwnData:
            kwnData.write(datum)
            kwnData.seek(0)
            sig1 = sign(kwnData.name, kwnPriv, pphr=kwnPphr)
            assert sig1 in kwnSigs

    def test_max_size_limit(self):
        global MAX_SIZE
        good_max_file_size = bool(MAX_SIZE <= 2 ** 30)
        MAX_SIZE = 2 ** 8
        tmpmax = 'maxsize.txt'
        with open(tmpmax, 'w+b') as fd:
            fd.write('abcd' * MAX_SIZE)  # ensure larger than MAX_SIZE
        with pytest.raises(ValueError):
            pad(tmpmax)
        with pytest.raises(ValueError):  # fake pubkey, just use tmpmax again
            encrypt(tmpmax, tmpmax)
        MAX_SIZE = 2 ** 30

    def test_encrypt_decrypt_etc(self):
        # Lots of tests here (just to avoid re-generating keys a lot)
        secretText = 'secret snippet %.6f' % time.time()
        datafile = 'cleartext unic\xcc\x88de.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)

        testBits = 2048  # fine to test with 1024 and 4096
        pubTmp1 = 'pubkey1 unic\xcc\x88de.pem'
        prvTmp1 = 'prvkey1 unic\xcc\x88de.pem'
        pphr1 = 'passphrs1 unic\xcc\x88de.txt'
        with open(pphr1, 'wb') as fd:
            fd.write(_printablePwd(180))
        pub1, priv1 = genRsa(pubTmp1, prvTmp1, pphr1, testBits)

        pubTmp2 = 'pubkey2 unic\xcc\x88de.pem'
        prvTmp2 = 'prvkey2 unic\xcc\x88de.pem'
        pphr2 = 'passphrs2 unic\xcc\x88de.txt'
        with open(pphr2, 'wb') as fd:
            fd.write(_printablePwd(180))

        # test decrypt with GOOD passphrase:
        dataEnc = encrypt(datafile, pub1)
        dataEncDec = decrypt(dataEnc, priv1, pphr=pphr1)
        recoveredText = open(dataEncDec).read()
        # file contents match:
        assert recoveredText == secretText
        # file name match: can FAIL due to utf-8 encoding issues
        assert os.path.split(dataEncDec)[-1] == datafile

        # a BAD passphrase should fail:
        with pytest.raises(PrivateKeyError):
            decrypt(dataEnc, priv1, pphr=pphr2)

        # nesting of decrypt(encrypt()) should work:
        dataDecNested = decrypt(encrypt(datafile, pub1), priv1, pphr=pphr1)
        recoveredText = open(dataDecNested).read()
        assert recoveredText == secretText

        # a correct-format but wrong priv key should fail:
        pub2, priv2 = genRsa(pubTmp2, prvTmp2, pphr1, testBits)
        with pytest.raises(DecryptError):
            dataEncDec = decrypt(dataEnc, priv2, pphr1)

        # should refuse-to-encrypt if pub key is too short:
        pub256, __ = genRsa('pub256.pem', 'priv256.pem', bits=256)
        assert numBits(pub256) == 256  # oops failed to get a short key to use
        with pytest.raises(PublicKeyTooShortError):
            dataEnc = encrypt(datafile, pub256)

        # test verifySig:
        sig2 = sign(datafile, priv1, pphr=pphr1)
        assert verify(datafile, pub1, sig2)
        assert not verify(pub1, pub2, sig2)
        assert not verify(datafile, pub2, sig2)

        # Rotate encryption including padding change:
        first_enc = encrypt(datafile, pub1, date=False)
        second_enc = rotate(first_enc, priv1, pub2, pphr=pphr1, newPad=8192)
        third_enc = rotate(second_enc, priv2, pub1, pphr=pphr1, newPad=16384,
                           hmac_key='key')
        # padding affects .enc file size, values vary a little from run to run
        assert getsize(first_enc) < getsize(second_enc) < getsize(third_enc)

        dec_rot3 = decrypt(third_enc, priv1, pphr=pphr1)
        assert not open(dec_rot3).read() == secretText  # dec but still padded
        pad(dec_rot3, 0)
        assert open(dec_rot3).read() == secretText

        # Meta-data from key rotation:
        md = loadMetaData(dec_rot3 + META_EXT)
        logMetaData(md)  # for debug
        dates = md.keys()
        hashes = [md[d]['sha256 of encrypted file'] for d in dates]
        assert len(hashes) == len(set(hashes)) == 3
        assert (u'meta-data %s' % NO_DATE) in dates

        # Should be only one hmac-sha256 present; hashing tested in test_hmac:
        hmacs = [md[d]['hmac-sha256 of encrypted file'] for d in dates
                 if 'hmac-sha256 of encrypted file' in md[d].keys()]
        assert len(hmacs) == 1

        # Should be able to suppress meta-data file:
        new_enc = encrypt(datafile, pub1, meta=False, keep=True)
        dataFileEnc, pwdFileRsa, metaFile = _unbundle(new_enc)
        assert metaFile == None
        assert dataFileEnc and pwdFileRsa

        # test keep=True:
        assert isfile(datafile)

        # Check size of RSA-pub encrypted password for AES256:
        assert os.path.getsize(pwdFileRsa) == testBits // 8

        # Non-existent decMethod should fail:
        with pytest.raises(ValueError):
            dataDec = decrypt(new_enc, priv1, pphr1,
                          decMethod='_decrypt_what_the_what')
        # Good decMethod should work:
        dataDec = decrypt(new_enc, priv1, pphr1,
                          decMethod='_decrypt_rsa_aes256cbc')

    def X_test_enc_size(self):
        pytest.skip()
        # idea: check that encrypted data can't be compressed
        datafile = 'test_size'
        with open(datafile, 'wb') as fd:
            fd.write('1')
        assert _zip_size(datafile) < 200  # 117 bytes
        global PAD_BYTE
        PAD_BYTE = b'\1'
        pad(datafile, 16384)
        PAD_BYTE = b'\0'
        assert os.stat(datafile)[stat.ST_SIZE] == 16384
        assert _zip_size(datafile) < 400  # fails, not small when compresses

        pub = self._knownValues()[0]
        dataEnc = encrypt(datafile, pub, keep=True)
        assert _zip_size(datafile) < _zip_size(dataEnc)

    def test_umask(self):
        assert PERMISSIONS == 0o600
        assert UMASK == 0o777 - PERMISSIONS

        filename = 'umask_test'
        pub, priv, pphr, __, __ = self._knownValues()
        umask_restore = os.umask(0o000)
        with open(filename, 'wb') as fd:
            fd.write('\0')
        assert _get_permissions(filename) == 0o666  # lack execute
        enc = encrypt(filename, pub)
        assert _get_permissions(enc) == PERMISSIONS
        assert not os.path.isfile(filename)
        dec = decrypt(enc, priv, pphr)
        assert _get_permissions(dec) == PERMISSIONS
        os.umask(umask_restore)

    def test_hmac(self):
        # widely used example = useful for validation
        key = 'key'
        bigkey = key * _hmac_blocksize
        value = "The quick brown fox jumps over the lazy dog"
        hm = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
        hb = '69d6cdc2fef262d48a4b012df5327e9b1679b6e3c95b05c940a18374b059a5e7'

        with NamedTemporaryFile() as fd:
            fd.write(value)
            fd.seek(0)
            hmac_python = hmac_sha256(key, fd.name)
            fd.seek(0)
            hmac_python_bigkey = hmac_sha256(bigkey, fd.name)
            fd.seek(0)
            cmdDgst = [OPENSSL, 'dgst', '-sha256', '-hmac', key, fd.name]
            hmac_openssl = _sysCall(cmdDgst)
        # avoid '==' to test because openssl 1.0.x returns this:
        # 'HMAC-SHA256(filename)= f7bc83f430538424b13298e6aa6fb143e97479db...'
        assert hmac_openssl.endswith(hm)
        assert hmac_python == hm
        assert hmac_python_bigkey == hb

    def test_command_line(self):
        # send encrypt and decrypt commands via command line

        datafile = 'cleartext unicöde.txt'
        secretText = 'secret snippet %.6f' % time.time()
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, __, __ = self._knownValues()
        pathToSelf = abspath(__file__)
        datafile = abspath(datafile)

        # Encrypt:
        cmdLineCmd = [sys.executable, pathToSelf, 'encrypt', datafile,
                      pub1, '--openssl=' + OPENSSL]
        dataEnc = _sysCall(cmdLineCmd).strip()
        assert os.path.isfile(dataEnc)

        # Decrypt:
        cmdLineCmd = [sys.executable, pathToSelf, 'decrypt', dataEnc,
                      priv1, pphr1, '--openssl=' + OPENSSL]
        dataEncDec_cmdline = _sysCall(cmdLineCmd).strip()
        assert os.path.isfile(dataEncDec_cmdline)

        # Both enc and dec need to succeed to recover the original text:
        recoveredText = open(dataEncDec_cmdline).read()
        assert recoveredText == secretText

    def test_wipe(self):
        # see if it takes at least 50x longer to wipe() than unlink a file
        # if so, WIPE_TOOL is doing something, hopefully its a secure delete

        if sys.platform == 'win32' and not have_sdelete:
            pytest.skip()

        tw_path = 'tmp_test_wipe'
        tw_reps = 3
        wipe_times = []
        for i in xrange(tw_reps):
            with open(tw_path, 'wb') as fd:
                fd.write(b'\0')
            code, links, t1 = wipe(tw_path)
            assert code == osw_WIPED
            assert links == 1
            wipe_times.append(t1)
        unlink_times = []
        for i in xrange(tw_reps):
            with open(tw_path, 'wb') as fd:
                fd.write(b'\0')
            t0 = time.time()
            os.unlink(tw_path)
            unlink_times.append(time.time() - t0)
        avg_wipe = sum(wipe_times) / tw_reps
        avg_unlink = sum(unlink_times) / tw_reps

        assert min(wipe_times) > 10 * max(unlink_times)
        assert avg_wipe > 50 * avg_unlink  # 1000x mac, mostly 200x CentOS VM

    def test_wipe_links(self):
        # Test whether can detect multiple links to a file when wipe()ing it:
        if sys.platform in ['win32', 'cygwin']:
            # from http://www.gossamer-threads.com/lists/python/dev/517504
            def _CreateHardLink(src, dst):
                import ctypes
                if not ctypes.windll.kernel32.CreateHardLinkA(dst, src, 0):
                    #pytest.skip()  # os.link not available on Windows
                    raise OSError  # could not make os.link on win32
            if not hasattr(os, 'link'):
                os.link = _CreateHardLink

        tw_path = 'tmp_test_wipe'
        with open(tw_path, 'wb') as fd:
            fd.write(b'\0')
        assert isfile(tw_path)  # need a file or can't test
        numlinks = 2
        for i in xrange(numlinks):
            os.link(tw_path, tw_path + 'hardlink' + str(i))

        hardlinks = os.stat(tw_path)[stat.ST_NLINK]
        code, links, __ = wipe(tw_path)
        assert links == numlinks + 1
        assert links == hardlinks

