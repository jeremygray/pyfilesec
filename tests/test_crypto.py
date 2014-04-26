#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Test suite for pytest, covering crypto classes and functions.

Part of the pyFileSec library. Copyright (c) 2013, Jeremy R. Gray
"""


import pytest
import pyfilesec
from   pyfilesec import *
from   pyfilesec import _abspath, _uniq_file, _parse_args

# referenced in tests: pyfilesec._encrypt_rsa_aes256cbc
#                      pyfilesec._decrypt_rsa_aes256cbc


class TestsCrypto(object):
    """Test suite for py.test
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

    def test_RsaKeys(self):
        pub, priv, pphr, bits = _known_values()[:4]

        # test individual keys:
        with pytest.raises(PublicKeyError):
            RsaKeys(pub=priv)
        with pytest.raises(PassphraseError):
            RsaKeys(pub, priv).test()
        with open('bad_pub', write_mode) as fd:
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
        rk.sniff(priv)

        # same again, no passphrase:
        pub_no, priv_no, bits_no = _known_values_no_pphr()[:3]
        rk_no = RsaKeys(pub_no, priv_no).test()

        # mismatched pub priv:
        with pytest.raises(PublicKeyError):
            rk = RsaKeys(pub, priv_no).test()

        # make short keys, test if pub_bits < RSA_MODULUS_MIN
        #sys_call([OPENSSL, 'genrsa', '-out', priv, str(RSA_MODULUS_MIN)])
        #sys_call([OPENSSL, 'rsa', '-in', priv, '-pubout', '-out', pub])
        #rk = RsaKeys(pub, priv).test()

        # test get_key_length function
        klen = get_key_length(pub)
        cmdMOD = [OPENSSL, 'rsa', '-modulus', '-in', pub, '-pubin', '-noout']
        modulus = sys_call(cmdMOD).replace('Modulus=', '')
        assert hexdigits_re.match(modulus)

        # test sniff
        assert RsaKeys().sniff(None) == (None, None)
        assert RsaKeys().sniff('') == ('(no file)', None)
        with open('testsniff', write_mode) as fd:
            fd.write('no key here')
        assert RsaKeys().sniff('testsniff') == (None, None)

    def test_SecFile_basics(self):
        with pytest.raises(SecFileFormatError):
            SecFile('.dot_file')
        test_file = 'tf'
        with open(test_file, write_mode) as fd:
            fd.write('a')
        sf = SecFile(test_file)
        str(sf)
        repr(sf)

        # encrypt-encrypted warning:
        pub, priv, pphr = _known_values()[:3]
        sf.encrypt(pub)
        sf.encrypt(pub, note='a' * (METADATA_NOTE_MAX_LEN + 1))  # logging.warn

        # decrypt missing passphrase when one is required
        with pytest.raises(PrivateKeyError):
            sf.decrypt()
        with pytest.raises(PassphraseError):
            sf.decrypt(priv=priv)

        # decrypt unencrypted priv key (no passphrase)
        pub_no, priv_no = _known_values_no_pphr()[:2]
        sf.encrypt(pub_no)
        sf.decrypt(priv_no)

        # fake version control
        os.mkdir('.svn')
        sf.decrypt(priv=priv, pphr=pphr)
        #shutil.rmtree('.svn')  # not yet

        # rotate unencrypted file:
        with open(test_file, write_mode) as fd:
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

    def test_encrypt_decrypt(self):
        # test with null-length file, and some secret content
        secret = 'secret snippet %s' % printable_pwd(128, '#')
        for secretText in ['', secret]:
            datafile = 'cleartext no unicode.txt'
            with open(datafile, write_mode) as fd:
                fd.write(secretText)
            assert getsize(datafile) in [0, len(secret)]

            testBits = 2048  # fine to test with 1024 and 4096
            pubTmp1 = 'pubkey1 no unicode.pem'
            prvTmp1 = 'prvkey1 no unicode.pem'
            pphr1 = printable_pwd(180)
            pub1, priv1 = GenRSA().generate(pubTmp1, prvTmp1, pphr1, testBits)

            pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
            prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
            pphr2_spaces = printable_pwd(180)
            pphr2_w_spaces = copy.copy('  ' + pphr2_spaces + '   ')
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
            sf.decrypt(priv1, pphr1)
            recoveredText = open(sf.file).read()
            # file contents match:
            assert recoveredText == secretText
            # file name match: can FAIL due to utf-8 encoding issues
            assert os.path.split(sf.file)[-1] == datafile

            # test decrypt with GOOD passphrase in a FILE:
            sf = SecFile(datafile).encrypt(pub1, keep=True)
            pphr1_file = prvTmp1 + '.pphr'
            with open(pphr1_file, write_mode) as fd:
                fd.write(pphr1)
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
            pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr1, testBits)
            with pytest.raises(DecryptError):
                sf.decrypt(priv2, pphr1)

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

            # arrange for a bad session key, should fail to decrypt:
            pub, priv, pphr = GenRSA().demo_rsa_keys()
            sf = SecFile(datafile).encrypt(pub, keep=True)
            sfa = SecFileArchive(arc=sf.file)
            sfa.unpack()
            sf2 = SecFile(datafile).encrypt(pub, keep=True)
            sfa2 = SecFileArchive(arc=sf2.file)
            sfa2.unpack()
            sfa2.pack(files=[sfa2.meta, sfa2.data_aes, sfa.pwd_rsa])
            sf.set_file(sfa2.name)
            with pytest.raises(DecryptError):
                sf.decrypt(priv=priv, pphr=pphr)

    def test_SecFileArchive(self):
        # test getting a name
        SecFileArchive(files=None)
        # default get a name from one of the files in paths:
        with open('abc' + AES_EXT, write_mode) as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, write_mode) as fd:
            fd.write('abc')
        SecFileArchive(files=['abc' + RSA_EXT, 'abc' + AES_EXT])
        with pytest.raises(AttributeError):
            SecFileArchive(files='abc')
        sf = SecFileArchive()
        with pytest.raises(AttributeError):
            sf.unpack()

        # get_dec_method
        sf = SecFile('abc' + AES_EXT)
        pub = _known_values_no_pphr()[0]
        sf.encrypt(pub, keep=True, meta=False)
        sfa = SecFileArchive(sf.file)
        sfa.unpack()
        sfa.get_dec_method(codec_registry)

        sfa = SecFileArchive().pack(pub)
        with open('ttt', write_mode) as fd:
            fd.write('ttt')
        with pytest.raises(SecFileArchiveFormatError):
            s = SecFileArchive('ttt')
            s.name = 'ttt'
            s.unpack()

        # construct an archive with a bad file name:
        sfa = SecFileArchive()
        sfa.name = 'sfa_name' + ENC_EXT
        aes = 'aes' + AES_EXT
        pwd = '..pwd' + RSA_EXT  # bad initial char
        md = 'md' + META_EXT
        bad = md + 'BAD'
        files = [aes, md, pwd, bad]
        for f in files:
            with open(f, write_mode) as fd:
                fd.write('x')
        files = [aes, md, bad]
        sfa._make_tar(files, keep=True)
        sfa.unpack()

        bad_files = [aes, md, pwd]
        sfa = SecFileArchive()
        sfa.name = 'sfa_name2' + ENC_EXT
        sfa._make_tar(bad_files, keep=True)
        with pytest.raises(SecFileFormatError):
            sfa.unpack()  # triggers _check

        # bad decrypt method from archive:
        c = PFSCodecRegistry()
        pub = GenRSA().demo_rsa_keys()[0]
        sf = SecFile('ttt').encrypt(pub)
        sfa = SecFileArchive(arc=sf.file)
        with pytest.raises(CodecRegistryError):
            sfa.get_dec_method(c)

        '''
        # test fall-through decryption method:
        with open('abc' + AES_EXT, write_mode) as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, write_mode) as fd:
            fd.write('abc')
        with open('abc' + META_EXT, write_mode) as fd:
            fd.write(str(NO_META_DATA))
        #assert exists(datafile)
        sf = SecFileArchive(paths=['abc' + AES_EXT,
                                    'abc' + RSA_EXT, 'abc' + META_EXT])
        dec_method = sf.get_dec_method('unknown')
        assert dec_method in list(default_codec.keys())

        # test missing enc-method in meta-data
        md = 'md'
        with open(md, write_mode) as fd:
            fd.write(log_metadata(NO_META_DATA))
        dec_method = _get_dec_method(md, 'unknown')
        assert dec_method == '_decrypt_rsa_aes256cbc'

        # test malformed cipher_text archive:
        archname = _uniq_file(os.path.splitext(datafile)[0] + ENC_EXT)
        bad_arch = make_archive(datafile, archname)  # datafile extension bad
        with pytest.raises(SecFileArchiveFormatError):
            decrypt(bad_arch, priv1, pphr1)
        '''

    def test_main(self):
        # similar to test_command_line (those do not count toward coverage)

        sys.argv = [__file__, '--help']
        with pytest.raises(SystemExit):
            args = _parse_args()

        sys.argv = [__file__, 'genrsa', '-a']
        with pytest.raises(SystemExit):
            main(_parse_args())

        tmp = 'tmp'
        with open(tmp, write_mode) as fd:
            fd.write('a')

        sys.argv = [__file__, '--pad', '-z', '0', tmp]
        main(_parse_args())

        pub, priv, pphr = _known_values()[:3]
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
        contents = open(outs['out'], read_mode).read()
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

    def test_signatures(self):
        # sign a known file with a known key. can we get known signature?
        __, kwnPriv, kwnPphr, datum, kwnSigs = _known_values()
        kwnData = 'knwSig'
        with open(kwnData, write_mode) as fd:
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
        assert open(outfile, read_mode).read() in kwnSigs

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
                with open(orig, write_mode) as fd:
                    for i in range(count):
                        fd.write(zeros)
                # not much faster at least for LRG_FILE_WARN:
                #    sys_call(['dd', 'if=/dev/zero', 'of=%s' % orig,
                #          'bs=%d' % bs, 'count=%d' % count])
                pub, priv, pphr = _known_values()[:3]
                sf = SecFile(orig)
                sf.encrypt(pub)
                bigfile_size = sf.size
            finally:
                os.remove(sf.file)
            assert bigfile_size > size

    @pytest.mark.slow
    def test_GenRSA(self):
        GenRSA().check_entropy()

        # test dialog as pyfilesec.genrsa()
        pub, priv, pp = genrsa(interactive=False)
        assert exists(pub)
        assert exists(priv)
        assert len(pp) >= 16

        sys.argv = [__file__, 'genrsa', '--clipboard']
        args = _parse_args()
        assert args.clipboard
        # travis-ci builds on linux, needs xclip, else import will fail
        try:
            import _pyperclip
            GenRSA().dialog(interactive=False, args=args)
        except (RuntimeError, ImportError):
            with pytest.raises(RuntimeError):
                GenRSA().dialog(interactive=False, args=args)

        sys.argv = [__file__, 'genrsa', '--passfile']
        args = _parse_args()
        assert args.passfile
        GenRSA().dialog(interactive=False, args=args)

        # test pub priv name collision
        sys.argv = [__file__, 'genrsa', '--pub', 'pub', '--priv', 'pub']
        args = _parse_args()
        assert args.pub == args.priv
        GenRSA().dialog(interactive=False, args=args)

        # test detect existing priv?
        with open('priv.pem', write_mode) as fd:
            fd.write('x')
        assert exists('priv.pem')
        sys.argv = [__file__, 'genrsa', '--pub', 'pub', '--priv', 'priv.pem']
        args = _parse_args()
        GenRSA().dialog(interactive=False, args=args)

        # test cleanup
        pub, priv, pphr = GenRSA().demo_rsa_keys()
        GenRSA()._cleanup('test cleanup', pub, priv, pphr)
        assert not exists(pub)
        assert not exists(priv)
        assert not exists(pphr)
        GenRSA()._cleanup('test cleanup', '', '', '')
        assert GenRSA()._cleanup('test cleanup', 'x', 'x', 'x') == (None, ) * 3

    def test_rotate(self):
        # Set-up:
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'file to rotate.txt'
        with open(datafile, write_mode) as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = _known_values()[:4]

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pwd = printable_pwd(180)
        pphr2 = '  ' + pwd + '   '  # spaces in pphr
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

    def test_misc_crypto(self):
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext unicode.txt'
        with open(datafile, write_mode) as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = _known_values()[:4]

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
        with open(pub, write_mode) as fd:
            fd.write(pub_stuff)
        assert open(pub, read_mode).read() == pub_stuff
        priv = 'priv_8192.pem'
        priv_stuff = """-----BEGIN RSA PRIVATE KEY-----
            Proc-Type: 4,ENCRYPTED
            DEK-Info: AES-256-CBC,ABD70159132455FBDC8E798415A4DE36

            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
            -----END RSA PRIVATE KEY-----
            """.replace('    ', '')
        with open(priv, write_mode) as fd:
            fd.write(priv_stuff)
        assert open(priv, read_mode).read() == priv_stuff
        pphr = 'pphr_8192'
        pphr_stuff = '149acf1a8c196eeb5cdba121567e670b'
        with open(pphr, write_mode) as fd:
            fd.write(pphr_stuff)
        assert open(pphr, read_mode).read() == pphr_stuff

        secretText = 'secret.txt'
        datafile = secretText  # does double duty as file name and contents
        with open(datafile, write_mode) as fd:
            fd.write(secretText)

        sf = SecFile(datafile)
        sf.encrypt(pub).decrypt(priv, pphr=pphr)
        recoveredText = open(sf.file).read()
        assert recoveredText == secretText

    def test_hmac(self):
        # verify pfs hmac implementation against a widely used example:
        key = 'key'
        value = "The quick brown fox jumps over the lazy dog"
        hm = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
        tmp = 'hmac_test no unicode'
        with open(tmp, write_mode) as fd:
            fd.write(value)
        hmac_openssl = hmac_sha256(key, tmp)
        # openssl 1.0.x returns this:
        # 'HMAC-SHA256(filename)= f7bc83f430538424b13298e6aa6fb143e97479db...'
        assert hmac_openssl.endswith(hm)
        assert hmac_openssl.split(')= ')[-1] == hm

        # bad key, file:
        # test of hmac file MAX_SIZE is in test_max_size_limit
        assert hmac_sha256(None, tmp) is None

    @pytest.mark.commandline
    def test_command_line(self):
        # send encrypt and decrypt commands via command line

        datafile = 'cleartext no unicode.txt'
        secretText = 'secret snippet %.6f' % get_time()
        with open(datafile, write_mode) as fd:
            fd.write(secretText)
        pub1, priv1, pphr1 = _known_values()[:3]
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
        with open(datafile, write_mode) as fd:
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
        # see if there's lots of output, with some plausible detail:
        assert outv.startswith('0.0')
        assert lib_name in outv
        assert len(outv) > 800
        assert len(outv.splitlines()) > 40

        # Destroy:
        cmdLineDestroy = [sys.executable, pathToSelf, datafile, '--destroy']
        outx = sys_call(cmdLineDestroy)
        if 'disposition' in outx:
            out = eval(outx)
        assert out['disposition'] == destroy_code[pfs_DESTROYED]


@pytest.mark.slow
@pytest.mark.notravis
class xxxTestCryptoUsingAnotherOpenSSL(TestsCrypto):
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


def _known_values_no_pphr(folder='.'):
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
        with open(pub, write_mode) as fd:
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
        with open(priv, write_mode) as fd:
            fd.write(privkey)
    kwnSig0p9p8 = (  # openssl 0.9.8r
        "")
    kwnSig1p0 = (   # openssl 1.0.1e or 1.0.0-fips
        "")

    return (_abspath(pub), _abspath(priv), bits, (kwnSig0p9p8, kwnSig1p0))
