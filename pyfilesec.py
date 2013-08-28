#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pyFileSec: File-oriented privacy & integrity management tools
"""

 # Copyright (c) Jeremy R. Gray, 2013
 # Released under the GPLv3 licence with the additional exemptions that
 # 1) compiling, linking, and/or using OpenSSL are allowed, and
 # 2) the copyright, licence terms, and following disclaimer be included in any
 #    and all derivative work.

 # DISCLAIMER: THIS SOFTWARE IS PROVIDED ``AS IS'', WITHOUT REPRESENTATION FROM
 # THE COPYRIGHT HOLDER OR CONTRIBUTORS AS TO ITS FITNESS FOR ANY PURPOSE, AND
 # WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 # LIMITATION THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 # PARTICULAR PURPOSE. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 # BE LIABLE FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 # CONSEQUENTIAL DAMAGES OF ANY NATURE, WITH RESPECT TO ANY CLAIM HOWEVER
 # CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 # LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING OUT OF OR IN
 # CONNECTION WITH THE USE OF THE SOFTWARE, EVEN IF THE COPYRIGHT HOLDER OR
 # CONTRIBUTORS HAVE BEEN OR ARE HEREAFTER ADVISED OF THE POSSIBILITY OF SUCH
 # DAMAGES.


__version__ = '0.2.01alpha (branch = SecFile class)'
__author__ = 'Jeremy R. Gray'
__contact__ = 'jrgray@gmail.com'


import sys
if sys.version < '2.6':
    raise RuntimeError('Requires python 2.6 or higher')

import argparse
from base64 import b64encode, b64decode
import copy
from functools import partial  # for buffered hash digest
import getpass  # for RSA key-gen
import hashlib
import json
import os
from os.path import abspath, isfile, getsize, isdir, dirname, exists, split
import random
import re
import shutil
import stat
import subprocess
import tarfile
from tempfile import mkdtemp, NamedTemporaryFile
import time

# other imports:
# GenRSA will import _pyperclip if use --clipboard option

# CONSTANTS and INITS ------------ (with code folding) --------------------
if True:
    # python 3 compatibility kludge:
    input23 = (input, raw_input)[sys.version < '3.']

    lib_name = 'pyFileSec'
    lib_path = abspath(__file__)
    if isfile(lib_path.strip('co')):
        lib_path = lib_path.strip('co')
    lib_dir = os.path.split(lib_path)[0]

    RSA_PADDING = '-oaep'  # actual arg for openssl rsautl in encrypt, decrypt

    ENC_EXT = '.enc'  # extension for for tgz of AES, PWD.RSA, META
    AES_EXT = '.aes256'   # extension for AES encrypted data file
    RSA_EXT = '.pwdrsa'   # extension for RSA-encrypted AES-pwd (ciphertext)
    META_EXT = '.meta'    # extension for meta-data

    # RSA key
    RSA_MODULUS_MIN = 1024  # threshold to avoid PublicKeyTooShortError
    RSA_MODULUS_WARN = 2048  # threshold to avoid warning about short key

    # warn that operations will take a while, check disk space, ...
    LRG_FILE_WARN = 2 ** 24  # 17M; used in tests but not implemented elsewhere
    MAX_FILE_SIZE = 2 ** 33  # 8G; larger likely fine unless pad w/ > 8G pad

    # file-length padding:
    PFS_PAD = lib_name + '_padded'  # label = 'file is padded'
    PAD_STR = 'pad='    # label means 'pad length = \d\d\d\d\d\d\d\d\d\d bytes'
    PAD_BYTE = b'\0'    # actual byte to use; value unimportant
    assert not PAD_BYTE in PFS_PAD
    assert len(PAD_BYTE) == 1
    PAD_LEN = len(PAD_STR + PFS_PAD) + 10 + 2  # len of info about padding
        # 10 = # digits in max file size, also works for 4G files
        # 2 = # extra bytes, one at end, one between PAD_STR and PFS_PAD labels
    PAD_MIN = 128  # minimum length in bytes post-padding
    DEFAULT_PAD_SIZE = 16384  # default resulting file size

    # used if user suppresses the date; will sort before a numerical date:
    DATE_UNKNOWN = '(date-time unknown)'
    NO_META_DATA = {'meta-data %s' % DATE_UNKNOWN: {'meta-data': False}}

    whitespace_re = re.compile('\s')
    hexdigits_re = re.compile('^[\dA-F]+$|^[\da-f]+$')

    # destroy() return codes:
    destroy_code = {1: 'secure deleted', 0: 'unlinked', -1: 'unknown'}
    pfs_DESTROYED = 1
    pfs_UNLINKED = 0
    pfs_UNKNOWN = -1

    # decrypted file status:
    PERMISSIONS = 0o600  # for decrypted file, no execute, no group, no other
    UMASK = 0o077  # need u+x permission for diretories
    old_umask = None  # set as global in set_umask, unset_umask

    # string to help be sure a .bat file belongs to pfs (win32, set_openssl):
    bat_identifier = '-- pyFileSec .bat file --'

    # Initialize values: ------------------
    dropbox_path = None


# EXCEPTION CLASSES -------------- (with code folding) --------------------
if True:
    class PyFileSecError(Exception):
        """Base exception for pyFileSec errors."""

    class PublicKeyTooShortError(PyFileSecError):
        '''Error to indicate that a public key is not long enough.'''

    class EncryptError(PyFileSecError):
        '''Error to indicate that encryption failed, or refused to start.'''

    class DecryptError(PyFileSecError):
        '''Error to indicate that decryption failed, or refused to start.'''

    class PublicKeyError(PyFileSecError):
        '''Error to indicate that public key failed.'''

    class PrivateKeyError(PyFileSecError):
        '''Error to indicate that loading a private key failed.'''

    class SecFileArchiveFormatError(PyFileSecError):
        '''Error to indicate bad format or file name inside archive file.'''

    class PaddingError(PyFileSecError):
        '''Error to indicate bad file padding.'''

    class CodecRegistryError(PyFileSecError):
        '''Error to indicate codec registry problem, e.g., not registered.'''

    class DestroyError(PyFileSecError):
        '''Error to indicate secure delete problem, e.g., destroy failed.'''

    class ArgumentError(PyFileSecError):
        '''Error to indicate an argument problem, e.g., no file specified.'''

    class FileNotEncryptedError(PyFileSecError):
        '''Error to indicate that an encrypted file is required (not provided).'''

    class FileStatusError(PyFileSecError):
        '''Error to indicate that a required status check failed.'''


class PyFileSecClass(object):
    pass


class PFSCodecRegistry(PyFileSecClass):
    """Class to explicitly manage the encrypt & decrypt functions.

    Motivation:

    1) Want extensible structure so that other encryption tools can drop in,
       while retaining the file-bundling and meta-data generation.

    2) Want the method used for encryption to be documentable in meta-data,
       esp. useful if there are several alternative methods available.

    3) Retain the ability to access all decryption methods, even if the
       related encryption method is no longer supported.

    Currently works for the default functions. To register a new function, the
    idea is to be able to do::

        codec = PFSCodecRegistry()
        new = {'_encrypt_xyz': _encrypt_xyz,
               '_decrypt_xyz': _decrypt_xyz}
        codec.register(new)

    and then `encrypt(method='_encrypt_xyz')` will work. Keys ('_encrypt_xyz')
    must be ascii-compatible (not unicode).

    But its not this simple yet: a) will need to update file extensions AES_EXT
    and so on for files generated (currently are constants). b) `rotate()` will
    need a newEncMethod param. c) will need a way to give arguments to the
    new_enc() and new_dec() methods, should be possible with `*args **kwargs`.
    """

    def __init__(self, defaults={}):
        self.name = 'PFSCodecRegistry'
        self._functions = {}
        self.register(defaults)

    def keys(self):
        return list(self._functions.keys())

    def register(self, new_functions):
        """Validate and add a codec to the registry.

        Typically one adds {_enc:e, _dec:d}. However, _dec:d only is accepted
        to support "read only" use of a codec, but _enc only is not.
        """
        for key in list(new_functions.keys()):
            try:
                key = str(key)  # not unicode
            except:
                fatal('keys restricted to str (not unicode)')
            fxn = new_functions[key]
            if not len(key) > 3 or key[:4] not in ['_enc', '_dec']:
                msg = ': failed to register "%s": need _enc/_dec...' % key
                fatal(self.name + msg)
            if not key in globals() or not hasattr(fxn, '__call__'):
                msg = ': failed to register "%s", not callable' % key
                fatal(self.name + msg)
            if key in list(self.keys()):
                fatal(self.name + ': function "%s" already registered' % key)
            self._functions.update({key: fxn})
            fxn_info = '%s(): fxn id=%d' % (key, id(fxn))
            logging.info(self.name + ': registered %s' % fxn_info)

        # allow _dec without _enc, but not vice-verse:
        for key in list(new_functions.keys()):
            if key.startswith('_dec'):
                continue
            assert key.startswith('_enc')
            dec_twin = key.replace('_enc', '_dec', 1)
            if not dec_twin in list(self._functions.keys()):
                fatal('method "%s" bad codec: _enc without a _dec' % key)
            # ideally also check dec(enc(secret.txt, pub), priv, pphr)
            # but this won't easily just work for rot13, gpg, etc

    def unregister(self, function_list):
        """Remove codec pairs from the registry based on keys.
        """
        target_list = []
        prefix_swap = {'_enc': '_dec', '_dec': '_enc'}
        for key in function_list:
            target_list.append(key)
            lead = key[:4]
            target_list.append(key.replace(lead, prefix_swap[lead], 1))
        for key in list(set(target_list)):
            if key in list(self._functions.keys()):
                del self._functions[key]
                logging.info('removed %s from registry' % key)
            else:
                msg = 'failed to remove %s from registry, not found' % key
                logging.warning(msg)

    def get_function(self, fxn_name):
        """Return a validated function from {method_name: fxn} dict.
        """
        if self.is_registered(fxn_name):
            return self._functions[fxn_name]
        raise CodecRegistryError('function %s not in registry' % fxn_name)

    def is_registered(self, fxn_name):
        """Returns True if `fxn_name` is registered; validated at registration.
        """
        return fxn_name in self._functions


class SecFile(PyFileSecClass):
    """Class for working with a file as a more-secure object.
    """
    def __init__(self, infile=None, pub=None, pad=None, priv=None, pphr=None,
                 codec=None, openssl=None):
        """:Parameters:
            ``infile`` : the target file to work on
            ``pub`` : public key, .pem format
            ``pad`` : padding, if any, to be applied to the file (before encryption)
            ``priv`` : private key, .pem format
            ``pphr`` : passphrase, as a file name or the passphrase itself
            ``codec`` : the pyFileSec codec to use
            ``openssl`` : path to the version of OpenSSL to use
        """
        '''API guide:
            self.file can be set explicitly or implicitly by user
                explicitly = at init, or through set_file; no other way (property).
                implicitly = change name due to a change of state
                    such as destroy --> None; encrypt --> .enc
                good: sf = SecFile(filename).encrypt(pub)
                      sf = SecFile().set_file(filename).decrypt(priv, pphr)
                       r = SecFile(filename).destroy().result
            methods that return self must also populate a self.result dict:
                method : name (encrypt, decrypt, rotate, ...)
                status: started, good, bad
                * seconds, orig_links, disposition, old_file, [inum]
                * meta : actual metadata dict (enc, dec, rot)
                * sig : actual sig
                * sig_out : name of file containing sig
                * verified : bool
                ...
                query .results right after a call; not guaranteed accurate beyond that
            properties cannot rely on self.result values, can be stale
            require_X methods must only use the default / already set file
            some methods call others (decrypt can call destroy), nested .results need work
        '''
        self.set_file(infile)
        self._require_keys(pub=pub, priv=priv, pphr=pphr)
        if not codec:
            codec = codec_registry  # default codec
        self.codec = copy.deepcopy(codec)
        self._openssl = openssl

        # passing infile AND value(s) at init can trigger some methods
        # the order of code below was chosen to enable implicit rotation but
        # you might lose metadata that way; use rotate()
        # here need to ensure that there is a file before calling anything
        if self.is_encrypted and priv:
            self.decrypt(priv, pphr)
        if self.is_not_encrypted:  # not elif
            pad and self.pad(pad)
            pub and self.encrypt(pub)
        # reset() should never auto-triggering because infile=None

    def __str__(self):
        return '<pyfilesec.SecFile object, file=%s>' % repr(self.file)

    def _get_openssl(self):
        if not self._openssl:
            self._openssl = OPENSSL  # use global var, pre-set
            logging.info('openssl set to %s' % self._openssl)
            self._openssl_version = None
        return self._openssl

    def _set_openssl(self, openssl):
        set_openssl(openssl)
        self._openssl_version = None  # force update if/when needed

    openssl = property(_get_openssl, _set_openssl, None, 'path to openssl')

    @property
    def openssl_version(self):
        if not self._openssl_version:
            self._openssl_version = sys_call([self.openssl, 'version'])
        return self._openssl_version

    @property
    def size(self):
        self._require_file()
        if self.file is None:
            return None
        else:
            return getsize(self.file)

    def reset(self):
        """Reinitialize, preserve RSA keys, openssl, and codec
        """
        name = 'reset'
        logging.info(name + ' start')
        # params here will not trigger because infile=None:
        self.__init__(infile=None, pub=self.pub, priv=self.priv, pphr=self.pphr,
                 codec=self.codec, openssl=self._openssl)

    def set_file(self, infile):
        """Set the filename, and change the file's permissions on disk.

        File permissions are set to conservative value on disk (Mac, Linux).
        """
        # self.file is always a path, not a file object
        if infile is None:
            self._file = None
            logging.info('set_file: received filename: None')
            return
        if not isinstance(infile, basestring):
            fatal('set_file: infile expected as a string', AttributeError)
        self._file = _abspath(infile)
        if exists(self._file):
            self.permissions = 0o600  # changes permissions on disk
        else:
            raise OSError('no such file %s' % self._file)
        return self  # probably not needed / useful

    @property
    def file(self):
        """The current file path/name (string, not a file object).
        """
        return self._file

    def _require_file(self, status=None):
        """Return the filename, raise error if missing, no file, or too large.
        """
        logging.debug('_require_file: current %s' % self.file)
        if self.file is None:
            fatal('file name required, missing', ValueError)
        if not isfile(self.file):
            fatal('%s not found' % self.file, OSError)
        if status is not None and not status:
            fatal('_require_file: bad status', FileStatusError)
        # use getsize because self.size calls _require_file() --> recursion
        if getsize(self._file) > MAX_FILE_SIZE:
            fatal("file too large (max size %d bytes)" % MAX_FILE_SIZE, FileStatusError)
        return self.file

    def _require_enc_file(self, status=None):
        """Returns a SecFileArchive, or fails
        """
        self._require_file(status)
        if self.is_not_encrypted:
            fatal('Require an encrypted file.', FileNotEncryptedError)
        return SecFileArchive(self.file)

    def _require_keys(self, pub=None, priv=None, pphr=None):
        """Accept new value, use existing if no new, or fail.

        priv: string or file --> file if priv is encrypted, otherwise string
        pphr: string or file --> string
        """
        def _get_pub(pub=None):
            """Get pub from self or from param, set as needed
            """
            # TO DO: screen for small RSA modulus
            if isinstance(pub, basestring):
                if exists(pub) and 'PUBLIC KEY' in open(pub, 'rb').read():
                    self.pub = _abspath(pub)
                else:
                    fatal('bad public key %s' % pub, PublicKeyError)
                try:
                    key_len = get_key_length(self.pub)
                except ValueError:
                    fatal('bad public key %s' % pub, PublicKeyError)
                if key_len < RSA_MODULUS_MIN:
                    fatal('short public key %s' % pub, PublicKeyTooShortError)
                if key_len < RSA_MODULUS_WARN:
                    logging.warning('short public key %s' % pub)
            if not hasattr(self, 'pub'):
                self.pub = None
            return self.pub

        def _get_priv(priv=None):
            """Get pub from self or from param, set as needed
            """
            # TO DO: screen for small RSA modulus
            if isinstance(priv, basestring):
                if exists(priv) and 'PRIVATE KEY' in open(priv, 'rb').read():
                    # got a file
                    self.priv = _abspath(priv)
                elif 'PRIVATE KEY' in priv:
                    # got actual key
                    self.priv = priv
                else:
                    logging.error('bad pub key %s' % priv)
            if not hasattr(self, 'priv'):
                self.priv = None
            return self.priv

        def _get_pphr(pphr=None):
            """Get pphr from self, param, set as needed

            Load from file if give a file
            """
            # TO DO: screen for weak passphrase
            if isinstance(pphr, basestring):
                if exists(pphr):
                    self.pphr = open(pphr, 'rb').read()
                else:
                    self.pphr = pphr
            if not hasattr(self, 'pphr'):
                self.pphr = None
            return self.pphr

        _get_pub(pub)  # get, or set-then-get
        _get_priv(priv)
        _get_pphr(pphr)

    def pad(self, size=DEFAULT_PAD_SIZE):
        """Append null bytes to ``filename`` until it has length ``size``.

        The size is changed but `the fact that it was changed` is only obscured if
        the padded file is encrypted. ``pad`` only changes the effective length,
        and the padding is easy to see (unless the padding is encrypted).

        Files shorter than `size` will be padded out to `size` (see details below).
        The minimum resulting file size is 128 bytes. Files that are already padded
        will first have any padding removed, and then be padded out to the new
        target size.

        Padded files include a few bytes for padding-descriptor tags, not just null
        bytes. Thus files that are close to ``size`` already would not have their
        sizes obscured AND also be marked as being padded (in the last ~36 bytes),
        raising a ``PaddingError``. To avoid this, you can check using the
        convenience function ``_ok_to_pad()`` before calling ``pad()``.

        Internal padding format:

            ``file + n bytes + padding descriptors + final byte``

        The padding descriptors consist of ``10-digits + one byte + PFS_PAD``,
        where ``byte`` is b'\0' (the null byte). The process does not depend on the
        value of the byte. The 10 digits gives the length of the padding as an
        integer, in bytes. ``n`` is selected to make the new file size equal the
        requested ``size``.

        To make unpadding easier and more robust (and enable human inspection),
        the end bytes provide the number of padding bytes that were added, plus an
        identifier. 10 digits is not hard-coded as 10, but as the length of
        ``str(max_file_size)``, where the ``max_file_size`` constant is 8G by
        default. This means that any changes to the max file size constant can thus
        cause pad / unpad failures across versions.

        Special ``size`` values:

           0 : unpad = remove any existing padding, no error if not present

           -1 : strict unpad = remove padding if present, raise ``PaddingError``
           if not present
        """
        name = 'pad'
        self.result = {'method': name, 'status': 'started'}

        filename = self._require_file()
        logging.debug(name + 'start')
        size = int(size)
        if 0 < size < PAD_MIN:
            logging.info(name + ': requested size increased to %i bytes' % PAD_MIN)
            size = PAD_MIN
        if size > MAX_FILE_SIZE:
            fatal(name + ': size must be <= %d (maximum file size)' % MAX_FILE_SIZE)
        # handle special size values (0, -1) => unpad
        pad_count = self._pad_len()
        if size < 1:
            if pad_count or size == -1:
                self.unpad()  # or fail appropriately
            return self

        if pad_count:
            self.unpad()
        needed = self._ok_to_pad(size)
        if needed == 0:
            msg = name + ': file length not obscured (length >= requested size)'
            fatal(msg, PaddingError)
        pad_bytes = PAD_STR + "%010d" % (needed + PAD_LEN)

        # append bytes to pad the file:
        with open(filename, 'a+b') as fd:
            chunk = 1024  # cap memory usage
            chunkbytes = PAD_BYTE * chunk
            for i in range(needed // chunk):
                fd.write(chunkbytes)
            extrabytes = PAD_BYTE * (needed % chunk)
            fd.write(extrabytes + pad_bytes + PAD_BYTE + PFS_PAD + PAD_BYTE)
            logging.info(name + ': append bytes to get to %d bytes' % size)

        self.result.update({'padding': needed + PAD_LEN, 'status': 'good'})
        return self

    def _ok_to_pad(self, size):
        """Return 0 if ``size`` is not adequate to obscure the file length.
        Else return the (non-zero) size.
        """
        filename = self._require_file()
        pad_count = self._pad_len()
        size = max(size, PAD_MIN)
        return max(0, size - (getsize(filename) - pad_count) - PAD_LEN)

    def _pad_len(self):
        """Returns ``pad_count`` (in bytes) if the file contains PFS padding.

        Returns 0 if bad or missing padding.
        """
        name = 'pad_len'
        filename = self._require_file()
        logging.debug(name + ': start, file="%s"' % filename)
        filelen = getsize(filename)
        if filelen < PAD_LEN:
            return 0
        with open(filename, 'rb') as fd:
            # read end bytes and then split
            fd.seek(filelen - PAD_LEN)
            pad_stuff = fd.read()
            last_byte = pad_stuff[-1]  # expect all padding to be this byte
            if last_byte != PAD_BYTE:
                return 0
            try:
                pad_tag_count, pad_marker = pad_stuff.split(PAD_BYTE)[-3:-1]
                pad_count = int(pad_tag_count.split(PAD_STR)[-1])
                assert pad_marker == PFS_PAD
            except:
                return 0
        if pad_count > filelen or pad_count > MAX_FILE_SIZE or pad_count < 0:
            return 0
        return pad_count

    def unpad(self):
        """Removes PFS padding from the file. raise ``PaddingError`` if no pad.

        Truncates the file to remove padding; does not `destroy` the padding.
        """
        name = 'unpad'
        self.result = {'method': name, 'status': 'started'}
        filename = self._require_file()
        logging.debug(name + ': start, file="%s"' % filename)
        filelen = getsize(filename)
        pad_count = self._pad_len()
        if not pad_count:
            msg = name + ": file not padded, can't unpad"
            fatal(msg, PaddingError)
        with open(filename, 'r+b') as fd:
            new_length = filelen - pad_count
            logging.info(name + ': found padding in file %s' % filename)
            # try to overwrite padding info, unknown effectiveness
            overwrite = min(PAD_LEN, filelen - new_length)
            if overwrite > 0:
                for i in range(7):
                    fd.seek(filelen - overwrite)
                    fd.write(printable_pwd(overwrite * 4))
            # trim the padding length info
            fd.truncate(new_length)
        logging.info(name + ': truncated the file to remove padding')
        self.result.update({'padding': None, 'status': 'good'})

        return self

    def encrypt(self, pub=None, meta=True, date=True, keep=False,
                enc_method='_encrypt_rsa_aes256cbc', hmac_key=None):
        """Encrypt a file using AES-256, encrypt the password with RSA pub-key.

        The idea is that you can have and share a public key, which anyone can
        use to encrypt things that only you can decrypt. Generating good keys and
        managing them is non-trivial (see `genRsaKeys()` and documentation).

        By default, the original plaintext is secure-deleted after encryption
        (default ``keep=False``). This is time-consuming, but important.

        Files larger than 8G before encryption will raise an error.

        To mask small file sizes, ``pad()`` them to a desired minimum
        size before calling ``encrypt()``.

        :Parameters:

            ``pub``:
                The public key to use, specified as the path to a ``.pem`` file.
                The minimum recommended key length is 2048 bits; 1024 is allowed
                but strongly discouraged as it is not medium-term secure.
            ``meta``:
                If ``True`` or a dict, include the meta-data (plaintext) in the
                archive. If given a dict, the dict will be updated with new
                meta-data. This allows all meta-data to be retained from the
                initial encryption through multiple rotations of the encryption.
                If ``False``, will indicate that the meta-data were suppressed.

                See ``load_metadata()`` and ``log_metadata()``.
            ``date``:
                ``True`` : save the date in the clear-text meta-data.
                ``False`` : suppress the date (if the date itself is sensitive)
                File time-stamps are NOT obscured, even if ``date=False``.
            ``keep``:
                ``False`` = remove original (unencrypted) file
                ``True``  = leave original file
            ``enc_method``:
                name of the function / method to use (currently only one option)
            ``hmac_key``:
                optional key to use for a message authentication (HMAC-SHA256,
                post-encryption); if a key is provided, the HMAC will be generated
                and stored with the meta-data. (This is encrypt-then-MAC.)
                For stronger integrity assurance, use ``sign()``.
        """
        set_umask()
        name = 'encrypt'
        self.result = {'method': name, 'status': 'started'}
        self._require_file()  # enc file ok, allow but warn about it
        self._require_keys(pub=pub)
        if not self.pub:
            fatal(name + ': requires a public key', EncryptError)
        logging.debug(name + 'start')
        if self.is_encrypted:
            logging.warning(name + ": file is already encrypted; encrypting again")
        if not self.codec.is_registered(enc_method):
            fatal(name + ": requested encMethod '%s' not registered" % enc_method)
        if not type(meta) in [bool, dict]:
            fatal(name + ': meta must be True, False, or dict', AttributeError)

        # Handle file size constraints:
        size = getsize(self.file)
        if size > MAX_FILE_SIZE:
            fatal(name + ": file too large (max size %d bytes)" % MAX_FILE_SIZE)

        # Refuse to proceed without a pub key of sufficient bits:
        bits = get_key_length(pub)
        logging.info(name + ': pubkey length %d' % bits)
        if bits < 1024:
            fatal("public key < 1024 bits; too short!", PublicKeyTooShortError)
        if bits < 2048:
            logging.error(name + ': public key < 2048 bits, no real security')
        if not keep in [True, False]:
            fatal(name + ": bad value for 'keep' parameter")

        # Do the encryption, using a registered `encMethod`:
        ENCRYPT_FXN = self.codec.get_function(enc_method)
        set_umask()  # redundant
        data_enc, pwd_rsa = ENCRYPT_FXN(self.file, pub, openssl=self.openssl)
        ok_encrypt = (isfile(data_enc) and
                        os.stat(data_enc)[stat.ST_SIZE] and
                        isfile(pwd_rsa) and
                        os.stat(pwd_rsa)[stat.ST_SIZE] >= PAD_MIN)
        logging.info(name + 'ok_encrypt %s' % ok_encrypt)

        # Get and save meta-data (including HMAC):
        metafile = os.path.split(self.file)[1] + META_EXT
        # meta is True, False, or a meta-data dict to update with this session
        if not meta:  # False or {}
            meta = NO_META_DATA
        else:  # True or exising md
            if meta is True:
                meta = {}
            md = self._make_metadata(self.file, data_enc, pub,
                                     enc_method, date, hmac_key)
            meta.update(md)
        with open(metafile, 'wb') as fd:
            json.dump(meta, fd)

        # Bundle the files: (cipher text, rsa pwd, meta-data) --> data.enc
        files = [data_enc, pwd_rsa, metafile]
        arch_enc = SecFileArchive(self.file, files, keep=False)

        if not keep:
            # secure-delete unencrypted original, unless encrypt failed:
            ok_to_destroy = (ok_encrypt and isfile(arch_enc.name) and
                             bool(os.stat(arch_enc.name)[stat.ST_SIZE]))
            logging.info(name + ': ok_to_destroy %s' % ok_to_destroy)

            if ok_to_destroy:
                # destroy using another SecFile obj to preserve self.result
                demolish = SecFile(self.file).destroy().result
                if demolish['disposition'] != destroy_code[pfs_DESTROYED]:
                    fatal('destroy orig. failed within encrypt', EncryptError)
                self.set_file(arch_enc.name)  # don't lose status during set_file
                logging.info(name +
                    ': post-encrypt destroyed orig. file complete')
            else:
                logging.error(name +
                    ': retaining original file, encryption did not succeed')

        unset_umask()
        self.set_file(arch_enc.name)
        self.result.update({'archive': self.file, 'meta': meta})
        return self

    def _make_metadata(self, datafile, data_enc, pub, enc_method, date=True, hmac=None):
        """Return info about an encryption context, as a {date-now: {info}} dict.

        If `date` is True, date-now is numerical date of the form
        year-month-day-localtime,
        If `date` is False, date-now is '(date-time suppressed)'. The date values
        are also keys to the meta-data dict, and their format is chosen so that
        they will sort to be in chronological order, even if the original
        encryption date was suppressed (it comes first). Only do `date=False` for
        the first initial encryption, not for rotation.
        """

        md = {'clear-text-file': abspath(datafile),
            'sha256 of encrypted file': '%s' % sha256_(data_enc)}
        if hmac:
            hmac_val = hmac_sha256(hmac, data_enc)
            md.update({'hmac-sha256 of encrypted file': hmac_val})
        md.update({'sha256 of public key': sha256_(pub),
            'encryption method': lib_name + '.' + enc_method,
            'sha256 of lib %s' % lib_name: sha256_(lib_path),
            'rsa padding': RSA_PADDING,
            'max_file_size_limit': MAX_FILE_SIZE})
        if date:
            now = time.strftime("%Y_%m_%d_%H%M", time.localtime())
            m = int(get_time() / 60)
            s = (get_time() - m * 60)
            now += ('.%6.3f' % s).replace(' ', '0')  # zeros for clarity & sorting
                # only want ms precision for testing, which can easily
                # generate two files within ms of each other
        else:
            now = DATE_UNKNOWN
        md.update({'encrypted year-month-day-localtime-Hm.s.ms': now,
            'openssl version': openssl_version,
            'platform': sys.platform,
            'python version': '%d.%d.%d' % sys.version_info[:3]})

        return {'meta-data %s' % now: md}

    def decrypt(self, priv=None, pphr='', keep_meta=False, keep_enc=False,
                dec_method=None):
        """Decrypt a file that was encoded using ``encrypt()``.

        To get the data back, need two files: ``data.enc`` and ``privkey.pem``.
        If the private key has a passphrase, you'll need to provide that too.
        `pphr` can be the passphrase itself (a string), or a file name. These
        must match the public key used for encryption.

        Works on a copy of ``data.enc``, tries to decrypt it, and will clean-up only those files.
        The original ``data.enc`` is not used (except to make a copy).

        Tries to detect whether the decrypted file would end up inside a Dropbox
        folder; if so, refuse to proceed.

        :Parameters:

            `priv` :
                path to the private key that is paired with the ``pub`` key used at
                encryption; in ``.pem`` format
            `pphr` :
                passphrase for the private key (as a string, or filename)
            `keep_meta` :
                if False, unlink the meta file after decrypt
            `keep_enc` :
                if False, unlink the encrypted file after decryption
            `dec_method` : (not implemented yet, only one choice)
                name of a decryption method that has been registered in
                the current ``codec`` (see ``PFSCodecRegistry``)
        """
        set_umask()
        name = 'decrypt'
        self.result = {'method': name, 'status': 'started'}
        arch_enc = self._require_enc_file(self.is_not_in_dropbox)
        self._require_keys(priv=priv, pphr=pphr)
        if not self.priv:
            fatal(name + ': requires a private key', DecryptError)
        logging.debug(name + 'start')

        if self.is_tracked:
            logging.warning(name + ': file exposed to version control')
        if not self.pphr and 'ENCRYPTED' in open(priv, 'r').read().upper():
            fatal(name + ': missing passphrase (for encrypted privkey)', DecryptError)

        # Extract files from the archive (dataFileEnc) into the same directory,
        # avoid name collisions, decrypt:
        try:
            # Unpack from archive into the dest_dir = same dir as the .enc file:
            dest_dir = os.path.split(arch_enc.name)[0]
            logging.info(name + ': decrypting into %s' % dest_dir)

            data_aes, pwd_file, meta_file = arch_enc.unpack()
            if not all([data_aes, pwd_file, meta_file]):
                logging.warn(name + ': did not find 3 files in archive %s' % arch_enc.name)
            tmp_dir = os.path.split(data_aes)[0]

            # Get a valid decrypt method, from meta-data or argument:
            clear_text = None  # file name; set in case _get_dec_method raise()es
            if not dec_method:
                dec_method = arch_enc.get_dec_method(self.codec)  # from .meta, or default
                #fatal(name + ': Could not get a valid decryption method', DecryptError)

            # Decrypt (into same new tmp dir):
            DECRYPT_FXN = self.codec.get_function(dec_method)
            set_umask()  # redundant
            data_dec = DECRYPT_FXN(data_aes, pwd_file, self.priv, self.pphr,
                                   openssl=self.openssl)

            # Rename decrypted and meta files (mv to dest_dir):
            _new_path = os.path.join(dest_dir, os.path.basename(data_dec))
            clear_text = _uniq_file(_new_path)
            try:
                os.rename(data_dec, clear_text)
            except OSError:
                # if /tmp is on another partition
                shutil.copy(data_dec, clear_text)
                demolish = SecFile(data_dec).destroy().result
                if demolish['disposition'] != destroy_code[pfs_DESTROYED]:
                    msg = name + ': destroy tmp clear txt failed: %s' % data_dec
                    fatal(msg, DestroyError)
            perm_str = permissions_str(clear_text)
            logging.info('decrypted, permissions ' + perm_str + ': ' + clear_text)
            if meta_file and keep_meta:
                newMeta = _uniq_file(clear_text + META_EXT)
                try:
                    os.rename(meta_file, newMeta)
                except OSError:
                    # if /tmp is on another partition can't rename it
                    shutil.copy(meta_file, newMeta)
                    demolish = SecFile(meta_file).destroy().result
                    if demolish['disposition'] != destroy_code[pfs_DESTROYED]:
                        msg = name + ': destroy tmp meta-data failed: %s' % meta_file
                        fatal(msg, DestroyError)
                perm_str = permissions_str(newMeta)
                logging.info('meta-data, permissions ' + perm_str + ': ' + newMeta)
        finally:
            try:
                # clean-up, nothing clear-text inside
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except:
                pass
            try:
                # redundant (umask on mac, linux) or no effect (win):
                os.chmod(clear_text, PERMISSIONS)
                os.chmod(newMeta, PERMISSIONS)
            except:
                pass

        unset_umask()
        if not keep_enc:
            os.unlink(arch_enc.name)
        self.set_file(clear_text)  # set file
        self.result = {'method': name, 'status': 'started'}  # destroy overwrites
        self.result.update({'clear_text': clear_text, 'status': 'good'})
        if meta_file and keep_meta:
            self.result.update({'meta': newMeta})
            self.meta = newMeta

        return self

    def rotate(self, pub=None, priv=None, pphr=None,
               hmac_key=None, pad=None, keep_meta=True):
        """Swap old encryption (priv) for new (pub), i.e., decrypt-then-re-encrypt.

        Returns the path to the "same" underlying file (i.e., same contents, new
        encryption). New meta-data are added alongside the original meta-data. If
        `new_pad` is given, the padding will be updated to the new value prior to
        re-encryption.

        Conceptually there are three separate steps: rotate, confirm that the
        rotation worked, and destroy the old (insecure) file. ``rotate()` will
        only do the first step (rotation).

        ``rotate()`` will preserve meta-data across encryption sessions, if
        available, adding to it rather than saving just the last one. (keep_meta=False
        will suppress all meta_data; typically rotation events are not sensitive.)
        Handling the meta-data is the principle motivation for having a rotate
        method; otherwise sf.decrypt(old).encrypt(new) would suffice.
        """
        set_umask()
        name = 'rotate'
        logging.debug(name + ': start (decrypt old, [pad new,] encrypt new)')
        self.result = {'method': name, 'status': 'started'}
        self._require_enc_file(self.is_not_in_dropbox)
        self._require_keys(pub=pub, priv=priv, pphr=pphr)

        file_dec = None
        try:
            # do _require_enc_file() in decrypt, bad if do it twice
            self.decrypt(priv, pphr=pphr, keep_meta=True)
            # decrypt can raise FileNotEncryptedError if not .enc file

            # encrypt() will destroy intermediate clear_text, but might be
            # an exception before getting to encrypt(), so wrap in try except

            logging.debug('rotate self.meta = %s' % self.meta)
            if isfile(self.meta):
                try:
                    md = self.load_metadata()
                    logging.debug(name + ': read metadata from file')
                except:
                    logging.error(name + ': failed to read metadata file; using None')
                    md = self.NO_META_DATA
            else:
                logging.debug(name + ': self.meta no such file')
                md = self.NO_META_DATA
            if pad > 0:  # can be -1
                self.pad(pad)
            file_dec = self.file  # track file names so can destroy if needed

            self.encrypt(pub=pub, date=True, meta=md,
                     keep=False, hmac_key=hmac_key)
        except FileNotEncryptedError:
            logging.error(name + ': not given an encrypted file')
            raise FileNotEncryptedError
        finally:
            # if exception, make sure we destroy any clear-text
            if file_dec and isfile(file_dec):
                self.destroy(file_dec)
            if hasattr(self, 'meta') and isfile(self.meta):
                os.unlink(self.meta)  # not sensitive

        unset_umask()
        self.result = {'method': name, 'status': 'started'}
        self.result.update({'file': self.file,
                       'status': 'good',
                       'old': os.path.split(priv)[1],
                       'new': os.path.split(pub)[1]})
        return self

    def load_metadata(self):
        """Read meta-data file, return it as a dict.
        """
        if self.meta:
            return json.load(open(self.meta, 'rb'))

    def log_metadata(self, md, log=True):
        """Log and return meta-data dict in human-friendly form.
        """
        md_fmt = json.dumps(md, indent=2, sort_keys=True, separators=(',', ': '))
        if log:
            logging.info(md_fmt)
        return md_fmt

    def sign(self, priv=None, pphr=None, out=None):
        """Sign a given file with a private key, via `openssl dgst`.

        Get a digest of the file, sign the digest, return base64-encoded signature
        or save it in file ``out``.
        """
        name = 'sign'
        logging.debug(name + ': start')
        self._require_file()
        self._require_keys(priv=priv, pphr=pphr)
        sig_out = self.file + '.sig'

        cmd_SIGN = [self.openssl, 'dgst', '-sign', priv, '-out', sig_out]
        if self.pphr:
            cmd_SIGN += ['-passin', 'stdin']
        cmd_SIGN += ['-keyform', 'PEM', self.file]
        if self.pphr:
            sys_call(cmd_SIGN, stdin=self.pphr)
        else:
            sys_call(cmd_SIGN)
        sig = open(sig_out, 'rb').read()

        self.result = {'sig': b64encode(sig),
                       'file': self.file}
        if out:
            out = _uniq_file(out)
            with open(out, 'wb') as fd:
                fd.write(self.result['sig'])
            self.result.update({'out': out})
        return self

    def verify(self, pub=None, sig=None):
        """Verify signature of ``filename`` using pubkey ``pub``.

        ``sig`` should be a base64-encoded signature, or a path to a signature file.
        """
        name = 'verify'
        logging.debug(name + ': start')
        self._require_file()
        self._require_keys(pub=pub)
        if not sig:
            fatal('signature required for verify(), as string or filename')

        cmd_VERIFY = [self.openssl, 'dgst', '-verify', pub, '-keyform', 'PEM']
        if isfile(sig):
            sig = open(sig, 'rb').read()
        with NamedTemporaryFile(delete=False) as sig_file:
            sig_file.write(b64decode(sig))
        cmd_VERIFY += ['-signature', sig_file.name, self.file]
        result = sys_call(cmd_VERIFY)
        os.unlink(sig_file.name)  # b/c delete=False

        self.result = {'verified': result in ['Verification OK', 'Verified OK'],
                       'file' : self.file}
        return self.result['verified']

    def destroy(self):
        """Try to secure-delete a file; returns (status, link count, time taken).

        Calls an OS-specific secure-delete utility, defaulting to::

            Mac:     srm -f -z --medium  filename
            Linux:   shred -f -u -n 7 filename
            Windows: sdelete.exe -q -p 7 filename

        To secure-delete a file, use this syntax:

            SecFile('a.enc').destroy().result

        If these are not available, ``destroy()`` will warn and fall through to trying
        to merely overwrite the data with 0's (with unknown effectiveness). Do
        not rely on this default behavior.

        Ideally avoid the need to destroy files as much as possible. Keep
        sensitive data in RAM. File systems that are journaled, have RAID, are
        mirrored, or other back-up are much trickier to secure-delete.

        ``destroy()`` may fail to remove all traces of a file if multiple hard-links
        exist for the file. For this reason, the original link count is returned.
        In the case of multiple hardlinks, Linux (shred) and Windows (sdelete)
        do appear to destroy the data (the inode), whereas Mac (srm) does not.

        If ``destroy()`` succeeds, the SecFile object is ``reset()``. The .result
        attribute contains the details. If ``destroy()`` fails, ``.result` is not reset.
        """

        #If a NamedTemporaryFile object is given instead of a filename, destroy()
        #will try to secure-delete the contents and close the file. Other open
        #file-objects will raise a DestroyError, because the file is not removed.

        name = 'destroy'
        logging.debug(name + ': start')
        self.result = None
        target_file = self._require_file()
        #got_file_object = hasattr(filename, 'close')
        #if got_file_object:
        #    filename, file_object = filename.name, filename
        #    file_object.seek(0)

        if self.is_in_dropbox:
            logging.error(name + ': in dropbox; no secure delete of remote files')
        if self.is_tracked:
            logging.warning(name + ': file exposed to version control')
        destroy_t0 = get_time()

        # Try to detect & inform about hardlinks:
        orig_links = self.hardlinks
        inum = os.stat(target_file)[stat.ST_INO]
        if orig_links > 1:
            if sys.platform != 'win32':
                mount_path = abspath(target_file)
                while not os.path.ismount(mount_path):
                    mount_path = os.path.dirname(mount_path)
                msg = name + """: '%s' (inode %d) has other hardlinks:
                    `find %s -xdev -inum %d`""".replace('    ', '')
                vals = (target_file, inum, mount_path, inum)
                logging.warning(msg % vals)
            else:
                mount_path = '(unknown)'

        cmd_Destroy = (destroy_TOOL,) + destroy_OPTS + (target_file,)
        good_sys_call = False
        try:
            __, err = sys_call(cmd_Destroy, stderr=True)
            good_sys_call = not err
            # mac srm will warn about multiple links via stderr -> disp unknown
        except OSError as e:
            good_sys_call = False
            logging.warning(name + ': %s' % e)
            logging.warning(name + ': %s' % ' '.join(cmd_Destroy))
        finally:
            #if got_file_object: only for NamedTemporaryFiles
            #    try:
            #        file_object.close()
            #        file_object.unlink()
            #        del(file_object.name)
            #    except:
            #        pass  # gives an OSError but has done something
            pass

        if not isfile(target_file):
            # there's no longer a file
            if good_sys_call:
                disposition = pfs_DESTROYED
            else:
                disposition = pfs_UNKNOWN
        else:
            disposition = pfs_UNKNOWN
            # there is a file still, or something
            logging.error(name + ': falling through to trying 1 pass of zeros')
            with open(target_file, 'wb') as fd:
                fd.write(chr(0) * getsize(target_file))
            shutil.rmtree(target_file, ignore_errors=True)

        duration = round(get_time() - destroy_t0, 4)
        self.reset()  # clear everything, including self.result
        disp_exp = destroy_code[disposition]
        if orig_links > 1:
            disp_exp += ', other hardlinks exist (see inum)'
        if err:
            disp_exp += '; ' + err
        vals = [disp_exp, orig_links, duration, target_file]
        keys = ['disposition', 'orig_links', 'seconds', 'target_file']
        if orig_links > 1 or disposition == pfs_UNKNOWN:
            vals.extend([inum, mount_path])
            keys.extend(['inum', 'mount_path'])
        self.result = dict(zip(keys, vals))
        if isfile(target_file):  # yikes, file still remains
            msg = name + ': %s remains after destroy(), %d bytes' % (target_file, getsize(target_file))
            fatal(msg, DestroyError)

        return self

    def _get_permissions(self):
        name = '_get_permissions'
        self._require_file()
        if sys.platform in ['win32']:
            perm = -1  #  'win32-not-implemented'
        else:
            perm = int(oct(os.stat(self.file)[stat.ST_MODE])[-3:], 8)
        logging.debug(name + ': %s %d base10' % (self.file, perm))
        if args:
            self.result = permissions_str(self.file)
        return perm

    def _set_permissions(self, mode):
        name = '_set_permissions'
        self._require_file()
        if sys.platform not in ['win32']:
            os.chmod(self.file, mode)
        else:
            pass
            # import win32security  # looks interesting
            # info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | \
            #           DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
            # info = 1,3,7 works as admin, 15 not enough priv; SACL = 8
            # win32security.GetFileSecurity(filename, info)
            # win32security.SetFileSecurity
        logging.info(name + ': %s %s' % (self.file, permissions_str(self.file)))

    permissions = property(_get_permissions, _set_permissions, None,
        "mac/nix:  Returns POSIX ugo permissions\nwin32  :  not implemented, returns -1")

    @property
    def hardlinks(self):
        if not self.file:
            return 0
        filename = self._require_file()
        if sys.platform == 'win32':
            if user_can_link:
                cmd = ('fsutil', 'hardlink', 'list', filename)
                links = sys_call(cmd)
                count = len([f for f in links.splitlines() if f.strip()])
            else:
                logging.warning('need to be an admin to use fsutil.exe (hardlink)')
                count = -1
        else:
            count = os.stat(filename)[stat.ST_NLINK]
        return count

    @property
    def is_in_dropbox(self):
        """True if the file is within a Dropbox folder; False if no file.
        """
        if not self.file:
            return False
        db_path = get_dropbox_path()
        if not db_path:
            inside = False
        else:
            inside = (self.file.startswith(db_path + os.sep) or
                  self.file == db_path)
        not_or_blank = (' not', '')[inside]
        logging.info('%s is%s inside Dropbox' % (self.file, not_or_blank))

        return inside

    @property
    def is_not_in_dropbox(self):
        return self.file and not self.is_in_dropbox

    @property
    def is_encrypted(self):
        # TO-DO: detect format regardless of file name
        # maybe just need the check the type == SecFileArchive
        return self.file and self.file.endswith(ENC_EXT)

    @property
    def is_not_encrypted(self):
        return self.file and not self.is_encrypted

    @property
    def is_tracked(self):
        """Try to detect if this file is under version control (svn, git, hg).

        Returns a boolean.
        Only approximate: the directory might be versioned, but not this file;
        or versioned with git but git is not call-able.
        """
        self._require_file()
        logging.debug('trying to detect version control (svn, git, hg)')

        return any([self._get_svn_info(self.file),
                    self._get_git_info(self.file),
                    self._get_hg_info(self.file)])

    def _get_git_info(self, path):
        """Report whether a directory or file is in a git repo (version control).

        Can test any generic filename, not just current file::

            >>> from pyfilesec import SecFile
            >>> SecFile().get_git_info(path)

        Files can be in the repo directory but not actually tracked by git.
        Assumes path is not versioned by git if git is not call-able.
        """
        if not path or not exists(path):
            return False
        try:
            sys_call(['git'])
        except OSError:
            # no git, not call-able
            return False
        cmd = ['git', 'ls-files', abspath(path)]
        reported = sys_call(cmd)
        is_tracked = bool(reported)

        logging.debug('path %s tracked in git repo: %s' % (path, is_tracked))
        return is_tracked

    def _get_svn_info(self, path):
        """Tries to discover if a file is under svn (version control).
        """
        if not isdir(path):
            path = dirname(path)
        has_svn_dir = isdir(os.path.join(path, '.svn'))
        logging.debug('path %s tracked in svn repo: %s' % (path, has_svn_dir))
        return has_svn_dir

    def _get_hg_info(self, path):
        """Tries to discover if a file is under mercurial (version control).

        `detailed=True` not tested recently (similar code worked before).
        """
        if not isdir(path):
            path = dirname(path)
        has_hg_dir = isdir(os.path.join(path, '.hg'))
        logging.debug('path %s tracked in hg repo: %s' % (path, has_hg_dir))
        return has_hg_dir

    # short-cuts for interactive use:
    enc = encrypt
    dec = decrypt
    rot = rotate


class SecFileArchive(PyFileSecClass):
    """Class for working with an archive file (= *.enc).

    Provide a name to create an empty archive, or infer a name from paths.

    Currently an archive is a .tar.gz file.
    """
    def __init__(self, name='', paths=None, keep=True):
        """
        """
        # init must not create any temp files if paths=None
        if paths and isinstance(paths, basestring):
            paths = tuple(paths)
        if name and isfile(name) and name.endswith(ENC_EXT):
            # given a name, and it is a valid archive file
            self.name = name
        elif name:
            # got a name, but its not (yet) a valid archive file
            self.name = name + ENC_EXT
        elif paths:
            # no name, infer a name from paths, prefer .meta file as a base
            for p in paths:
                path, ext = os.path.splitext(p)
                if not ext in [AES_EXT, RSA_EXT]:
                    self.name = path + ENC_EXT
                    break
            else:
                path, ext = os.path.splitext(paths[0])
                self.name = path + ENC_EXT
        else:
            self.name = _uniq_file('secFileArchive' + ENC_EXT)
        logging.debug('SecFileArchive.__init__ %s' % self.name)
        if paths:
            self.pack(paths, keep=keep)

    def pack(self, paths, keep=True):
        """Make a tgz file from a list of paths, set permissions.

        Directories ok currently (might change and only allow a file).

        Eventually might take an arg to decide whether to use tar or zip.
        Just a tarfile wrapper with extension, permissions, unlink options.
        unlink is whether to unlink the original files after making an archive, not
        a secure-delete option.
        """

        set_umask()
        if isinstance(paths, str):
            paths = [paths]
        self.name = _uniq_file(self.name)
        tar_fd = tarfile.open(self.name, "w:gz")
        for p in [os.path.split(f)[1] for f in paths]:
            tar_fd.add(p, recursive=True)  # True by default, get whole directory
            if not keep:
                try:
                    shutil.rmtree(p)  # might be a directory
                except OSError:
                    os.unlink(p)
        tar_fd.close()

        unset_umask()
        return self.name

    def _check(self):
        data_enc = self.name
        # Check for bad paths:
        if not data_enc or not isfile(data_enc):
            fatal("could not find <file>%s '%s'" % (ENC_EXT, str(data_enc)))
        if not tarfile.is_tarfile(data_enc):
            fatal(name + ': %s not expected format (.tgz)' % data_enc,
                   SecFileArchiveFormatError)

        # Check for bad internal paths:
        #    can't "with open(tarfile...) as tar" in python 2.6.6
        tar = tarfile.open(data_enc, "r:gz")
        badNames = [f for f in tar.getmembers()
                    if f.name[0] in ['.', os.sep] or f.name[1:3] == ':\\']
        tar.close()
        if badNames:
            fatal(name + ': bad/dubious internal file names' % os.sep,
                   SecFileArchiveFormatError)
        return True

    def unpack(self):
        """Extract files from archive into a tmp dir, return paths to files.

        :Parameters:
            ``keep`` :
                ``False`` will unlink the data_enc file after unpacking, but
                only if there were no errors during unpacking
        """
        set_umask()
        name = 'unpack'
        logging.debug(name + ': start')
        self._check()
        logging.debug(name + ': _check OK')
        data_enc = self.name

        # Extract:
        tmp_dir = mkdtemp()
        tar = tarfile.open(data_enc, "r:gz")
        tar.extractall(path=tmp_dir)  # already screened for bad names
        tar.close()

        fileList = os.listdir(tmp_dir)
        self.data_aes, self.pwd_rsa, self.meta = None, None, None
        for fname in fileList:
            if fname.endswith(AES_EXT):
                self.data_aes = os.path.join(tmp_dir, fname)
            elif fname.endswith(RSA_EXT):
                self.pwd_rsa = os.path.join(tmp_dir, fname)
            elif fname.endswith(META_EXT):
                self.meta = os.path.join(tmp_dir, fname)
            else:
                fatal(name + ': unexpected file in archive', SecFileArchiveFormatError)

        unset_umask()

        return self.data_aes, self.pwd_rsa, self.meta

    def get_dec_method(self, codec):
        """Return a valid decryption method from meta-data or default.

        Cross-validate requested dec_method against meta-data, warn if mismatch.
        """
        enc_method = 'unknown'
        meta_file = self.meta

        if meta_file:
            md = self.load_metadata()
            dates = list(md.keys())  # dates of meta-data events
            most_recent = sorted(dates)[-1]
            if not 'encryption method' in list(md[most_recent].keys()):
                enc_method = 'unknown'
                _dec_from_enc = enc_method
            else:
                enc_method = md[most_recent]['encryption method'].split('.')[1]
                _dec_from_enc = enc_method.replace('_encrypt', '_decrypt')

            try:
                dec_method = str(_dec_from_enc)  # avoid unicode issue
            except:
                dec_method = _dec_from_enc
            logging.info('implicitly want "' + dec_method + '" (meta-data)')
        if not meta_file or enc_method == 'unknown':
            # can't infer, no meta-data
            if not dec_method or enc_method == 'unknown':
                # ... and nothing explicit either, so go with default:
                logging.info('falling through to default decryption')
                available = [f for f in list(default_codec.keys())
                             if f.startswith('_decrypt_')]
                dec_method = available[0]

        if not codec.is_registered(dec_method):
            fatal("_get_dec_method: dec fxn '%s' not registered" % dec_method,
                   CodecRegistryError)
        logging.info('_get_dec_method: dec fxn set to: ' + str(dec_method))

        return dec_method

    def load_metadata(self):
        """Read meta-data file, return it as a dict.
        """
        return json.load(open(self.meta, 'rb'))

    def log_metadata(self, md, log=True):
        """Log and return meta-data dict in human-friendly form.
        """
        md_fmt = json.dumps(md, indent=2, sort_keys=True, separators=(',', ': '))
        if log:
            logging.info(md_fmt)
        return md_fmt


class GenRSA(PyFileSecClass):
    def __init__(self):
        pass

    def check_entropy(self):
        """Basic query for some indication that entropy is available.
        """
        if sys.platform == 'darwin':
            # SecurityServer daemon is supposed to ensure entropy is available:
            ps = sys_call(['ps', '-e'])
            securityd = sys_call(['which', 'securityd'])  # full path
            if securityd in ps:
                e = securityd + ' running   (= good)'
            else:
                e = ''
            rdrand = sys_call(['sysctl', 'hw.optional.rdrand'])
            e += '\n           rdrand: ' + rdrand
            if rdrand == 'hw.optional.rdrand: 1':
                e += ' (= good)'
        elif sys.platform.startswith('linux'):
            avail = sys_call(['cat', '/proc/sys/kernel/random/entropy_avail'])
            e = 'entropy_avail: ' + avail
            if int(avail) < 50:
                e += ' (= not so much...)'
        else:
            e = '(unknown)'
        return e

    def generate(self, pub='pub.pem', priv='priv.pem', pphr=None, bits=4096):
        """Generate new RSA pub and priv keys, return paths to files.

        pphr should be a string containing the actual passphrase (if desired).
        """
        set_umask()
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-aes256', '-passout', 'stdin']
        sys_call(cmdGEN + [str(bits)], stdin=pphr)

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv,
                     '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'stdin']
        sys_call(cmdEXTpub, stdin=pphr)

        unset_umask()
        return _abspath(pub), _abspath(priv)

    def dialog(self, interactive=True, out=None):
        """Command line dialog to generate an RSA key pair, PEM format.

        Launch from the command line::

            % python pyfilesec.py genrsa

        or same thing, but save the passphrase into a file named 'pphr' [or save onto the clipboard]::

            % python pyfilesec.py genrsa --out pphr [--clipboard]

        or within a python interpreter shell::

            >>> import pyfilesec as pfs
            >>> pfs.genrsa()

        The passphrase will not be printed if it was entered manually. If it is
        auto-generated, it will either be printed or saved to a file (if option
        ``--out`` is used). This is the only copy of the passphrase.

        Choose from 2048, 4096, or 8192 bits; 1024 is not secure for medium-term
        storage, and 16384 bits is not needed (nor is 8192). A passphrase is
        required, or one will be auto generated and printed to the console (this is
        the only copy, don't lose it). Ideally, generate a strong passphrase using
        a password manager (e.g., KeePassX), save there, paste it into the dialog.

        You may only ever need to do this once. You may also want to generate keys
        for testing purposes, and then generate keys for actual use.
        """
        # `interactive=False` is for automated test coverage
        def _cleanup(msg):
            print(msg)
            try:
                destroy(priv)
            except:
                pass
            try:
                os.unlink(pub)
            except:
                pass

        #if not args:  # run interactively within python interpreter shell

        # constant:
        AUTO_PPHR_BITS = 128
        RSA_BITS_DEFAULT = 4096

        # use args for filenames if given explicitly:
        pub = (args and args.pub) or abspath(_uniq_file('pub_RSA.pem'))  # ensure unique
        priv = (args and args.priv) or pub.replace('pub_RSA', 'priv_RSA')  # matched pair
        if not args or args and args.passfile:
            pphr_out = pub.replace('pub_RSA', 'pphr_RSA')  # matched name
            pphr_out = os.path.splitext(pphr_out)[0] + '.txt'
        else:
            pphr_out = None

        if args and args.clipboard:
            import _pyperclip
        pub = abspath(pub)
        priv = abspath(priv)
        if pub == priv:
            priv += '_priv.pem'

        msg = '\n%s: RSA key-pair generation dialog\n' % lib_name
        print(msg)
        if os.path.exists(priv) or args and args.passfile and os.path.exists(pphr_out):
            print('  > output file(s)already exist <\n'
                   '  > Clean up files and try again. Exiting. <')
            return None, None, None

        print('Will try to create files:')
        pub_msg = '  pub  = %s' % pub
        print(pub_msg)
        priv_msg = '  priv = %s' % priv
        print(priv_msg)
        if not args:
            pphr_msg = '  pphr = %s' % pphr_out
            print(pphr_msg)
        if args and args.passfile:
            pphrout_msg = '  pphr = %s' % pphr_out
            print(pphrout_msg)
        if args and interactive:
            print('\nEnter a passphrase for the private key (16 or more chars)\n'
                  '  or press <return> to auto-generate a passphrase')
            pphr = getpass.getpass('Passphrase: ')
        else:
            pphr = ''
        if pphr:
            pphr2 = getpass.getpass('same again: ')
            if pphr != pphr2:
                print('  > Passphrase mismatch. Exiting. <')
                return None, None, None
            pphr_auto = False
        else:
            if args:
                print('(auto-generating a passphrase)')
            pphr = printable_pwd(AUTO_PPHR_BITS)
            pphr_auto = True
        print('')
        if pphr and len(pphr) < 16:
            print('  > passphrase too short, exiting <')
            return None, None
        bits = RSA_BITS_DEFAULT
        if interactive:
            b = input23('Enter the desired RSA key length (2048, 4096, 8192): [%d] ' % RSA_BITS_DEFAULT)
            if b in ['2048', '4096', '8192']:
                bits = int(b)
        bits_msg = '  using %i' % bits
        if bits > 4096:
            bits_msg += '; this will take a minute!'
        print(bits_msg)
        ent_msg = '  entropy: ' + self.check_entropy()
        print(ent_msg)

        nap = (2, 5)[bool(interactive)]  # 5 sec sleep in interactive mode
        print('\nMove the mouse around for %ds (to help generate entropy)' % nap)
        sys.stdout.flush()
        try:
            time.sleep(nap)
        except KeyboardInterrupt:
            _cleanup(' >> cancelled, exiting <<')
            return None, None, None

        msg = '\nGenerating RSA keys (using %s)\n' % openssl_version
        print(msg)
        try:
            self.generate(pub, priv, pphr, bits)
        except KeyboardInterrupt:
            _cleanup('\n  >> cancelled, exiting <<')
            return None, None, None
        except:
            _cleanup('\n  > exception in generate(), exiting <')
            return None, None, None

        pub_msg = 'public key:  ' + pub
        print(pub_msg)
        priv_msg = 'private key: ' + priv
        print(priv_msg)
        if pphr_auto:
            if not args or args and args.passfile:
                pphr_msg = 'passphrase:  %s' % pphr_out
                try:
                    set_umask()
                    with open(pphr_out, 'wb') as fd:
                        fd.write(pphr)
                    unset_umask()
                except:
                    _cleanup()
                if not isfile(pphr_out) or not getsize(pphr_out) == AUTO_PPHR_BITS // 4:
                    _cleanup(' >> failed to save passphrase file, exiting <<')
                    return None, None
            elif args and args.clipboard:
                _pyperclip.copy(pphr)
                pphr_msg = ('passphrase:  saved to clipboard only... paste it somewhere safe!!\n' +
                            '      (It is exactly %d characters long, no end-of-line char)' % (AUTO_PPHR_BITS // 4))
            else:
                pphr_msg = 'passphrase:  ' + pphr
        else:
            pphr_msg = 'passphrase:  (entered by hand)'
        print(pphr_msg)
        warn_msg = (' >> Keep the private key private! <<\n'
               '  >> Do not lose the passphrase! <<')
        print(warn_msg)

        if not interactive:
            return pub, priv, pphr_out


def _abspath(filename):
    """Returns the absolute path (norm-pathed), Capitalize first char (win32)
    """
    f = os.path.abspath(filename)  # implicitly does normpath too
    return f[0].capitalize() + f[1:]


def command_alias():
    """Print aliases that can be used for command-line usage.
    """
    aliases = ('bash:  alias pfs="python %s"\n' % lib_path +
               '*csh:  alias pfs "python %s"\n' % lib_path +
               'DOS :  doskey pfs=python %s $*' % lib_path)
    print(aliases)


def _decrypt_rsa_aes256cbc(data_enc, pwd_rsa, priv, pphr=None, openssl=None):
    """Decrypt a file that was encoded by _encrypt_rsa_aes256cbc()

    If present, pphr must be the actual passphrase, not a filename.
    Path to openssl must always be given explicitly.
    pwd_rsa is the AES password that has been encrypted with an RSA pub key.

    This function is intended to be free of global vars (but needs functions).
    """
    name = '_decrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)
    if not openssl or not isfile(openssl):
        fatal(name + ': require path to openssl executable', RuntimeError)

    # set the name for decrypted file:
    data_dec = os.path.splitext(abspath(data_enc))[0]

    # set up the command to retrieve password from pwdFileRsa
    cmdRSA = [openssl, 'rsautl', '-in', pwd_rsa, '-inkey', priv]
    if pphr:
        assert not isfile(pphr)
        cmdRSA += ['-passin', 'stdin']
    cmdRSA += [RSA_PADDING, '-decrypt']

    # set up the command to decrypt the data using pwd:
    cmdAES = [openssl, 'enc', '-d', '-aes-256-cbc', '-a',
              '-in', data_enc, '-out', data_dec, '-pass', 'stdin']

    # decrypt pwd (digital envelope "session" key) to RAM using private key
    # then use pwd to decrypt the ciphertext file (data_enc):
    try:
        pwd, se_RSA = sys_call(cmdRSA, stdin=pphr, stderr=True)
        ___, se_AES = sys_call(cmdAES, stdin=pwd, stderr=True)
    except KeyboardInterrupt:
        if isfile(data_dec):
            destroy(data_dec)
        fatal('%s: Could not decrypt' % name, KeyboardInterrupt)
    except:
        if isfile(data_dec):
            destroy(data_dec)
        fatal('%s: Could not decrypt (exception in RSA or AES step)' % name,
               DecryptError)
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try

    if sys.platform == 'win32':
        glop = "Loading 'screen' into random state - done"  # why in se??
        se_RSA = se_RSA.replace(glop, '')
    if se_RSA.strip():
        if 'unable to load Private Key' in se_RSA:
            fatal('%s: unable to load Private Key' % name, PrivateKeyError)
        elif 'RSA operation error' in se_RSA:
            fatal("%s: can't use Priv Key; wrong key?" % name, DecryptError)
        else:
            fatal('%s: Bad decrypt (RSA) %s' % (name, se_RSA), DecryptError)
    if se_AES:
        if 'bad decrypt' in se_AES:
            fatal('%s: openssl bad decrypt (AES step)' % name, DecryptError)
        else:
            fatal('%s: Bad decrypt (AES) %s' % (name, se_AES), DecryptError)

    return _abspath(data_dec)


def _encrypt_rsa_aes256cbc(datafile, pub, openssl=None):
    """Encrypt a datafile using openssl to do rsa pub-key + aes256cbc.

    Path to openssl must always be given explicitly.

    This function is intended to be free of global vars (but needs functions).
    """
    name = '_encrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)
    if not openssl or not isfile(openssl):
        fatal(name + ': require path to openssl executable', RuntimeError)

    # Define file paths:
    data_enc = _uniq_file(abspath(datafile + AES_EXT))
    pwd_rsa = data_enc + RSA_EXT  # path to RSA-encrypted session key

    # Generate a password (digital envelope "session" key):
    # want printable because its sent to openssl via stdin
    pwd = printable_pwd(nbits=256)
    assert not whitespace_re.search(pwd)
    assert len(pwd) == 64  # hex characters

    # Define command to RSA-PUBKEY-encrypt the pwd, save ciphertext to file:
    cmd_RSA = [openssl, 'rsautl',
          '-out', pwd_rsa,
          '-inkey', pub,
          '-keyform', 'PEM',
          '-pubin',
          RSA_PADDING, '-encrypt']

    # Define command to AES-256-CBC encrypt datafile using the password:
    cmd_AES = [openssl, 'enc', '-aes-256-cbc',
              '-a', '-salt',
              '-in', datafile,
              '-out', data_enc,
              '-pass', 'stdin']

    try:
        # encrypt the password:
        sys_call(cmd_RSA, stdin=pwd)
        # encrypt the file, using password; takes a long time for large file:
        sys_call(cmd_AES, stdin=pwd)
        # better to return immediately, del(pwd); using stdin blocks return
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try

    return _abspath(data_enc), _abspath(pwd_rsa)


def fatal(msg, err=ValueError):
    """log then raise err(msg).
    """
    logging.error(msg)
    raise err(msg)


def genrsa():
    """Launch RSA key-generation dialog.
    """
    GenRSA().dialog()


def get_dropbox_path():
    """Return the path to the Dropbox folder, or False if not found.

    First time called will set a global var (used on subsequent calls).
    """
    global dropbox_path
    if dropbox_path is None:
        if sys.platform != 'win32':
            host_db = os.path.expanduser('~/.dropbox/host.db')
        else:
            host_db = os.path.join(os.environ['APPDATA'], 'Dropbox', 'host.db')
        if not exists(host_db):
            logging.info('did not find a Dropbox folder')
            dropbox_path = False
        else:
            db_path_b64 = open(host_db, 'rb').readlines()[1]  # second line
            db_path = b64decode(db_path_b64.strip())
            dropbox_path = _abspath(db_path)
            logging.info('found Dropbox folder %s' % dropbox_path)

    return dropbox_path


def get_key_length(pubkey):
    """Return the number of bits in a RSA public key.
    """
    name = 'get_key_length'
    cmdGETMOD = [OPENSSL, 'rsa', '-modulus', '-in', pubkey, '-pubin', '-noout']
    modulus = sys_call(cmdGETMOD).replace('Modulus=', '')
    if not modulus:
        fatal(name + ': no RSA modulus in pub "%s" (bad .pem file?)' % pubkey)
    if not hexdigits_re.match(modulus):
        fatal(name + ': expected hex digits in pubkey RSA modulus')
    return len(modulus) * 4


def hmac_sha256(key, filename):
    """Return a hash-based message authentication code (HMAC), using SHA256.

    The key is a string value.
    """
    if not key:
        return None
    if getsize(filename) > MAX_FILE_SIZE:
        fatal('hmac_sha256: file too large (> max file size)')
    cmd_HMAC = [OPENSSL, 'dgst', '-sha256', '-hmac', key, filename]
    hmac_openssl = sys_call(cmd_HMAC)

    return hmac_openssl


def printable_pwd(nbits=256):
    """Return a string of hex digits with n random bits, zero-padded.
    """
    pwd = hex(random.SystemRandom().getrandbits(nbits))
    return pwd.strip('L').replace('0x', '', 1).zfill(nbits // 4)


def permissions_str(filename):
    if sys.platform in ['win32']:
        return 'win32-not-implemented'
    else:
        perm = int(oct(os.stat(filename)[stat.ST_MODE])[-3:], 8)
        return '0o' + oct(perm)[1:]


def set_umask(new_umask=UMASK):
    # decorator to (set-umask, do-fxn, unset-umask) worked but ate the doc-strs
    global _old_umask
    _old_umask = os.umask(new_umask)
    return _old_umask


def set_destroy():
    """Find, set, and report info about secure file removal tool to be used.
    """
    if sys.platform in ['darwin']:
        destroy_TOOL = sys_call(['which', 'srm'])
        destroy_OPTS = ('-f', '-z', '--medium')  # 7 US DoD compliant passes
    elif sys.platform.startswith('linux'):
        destroy_TOOL = sys_call(['which', 'shred'])
        destroy_OPTS = ('-f', '-u', '-n', '7')
    elif sys.platform in ['win32']:
        app_lib_dir = os.path.join(os.environ['APPDATA'], split(lib_dir)[-1])
        default = os.path.join(app_lib_dir, '_sdelete.bat')
        if not isfile(default):
            guess = sys_call(['where', '/r', 'C:\\', 'sdelete.exe'])
            if not guess.strip().endswith('sdelete.exe'):
                fatal('Failed to find sdelete.exe. Please install ' +
                       'under C:\\, run it manually to accept the terms.')
            bat_template = """@echo off
                REM  """ + bat_identifier + """ for using sdelete.exe

                START "" /b /wait XSDELETEX %*""".replace('    ', '')
            bat = bat_template.replace('XSDELETEX', guess)
            with open(default, 'wb') as fd:
                fd.write(bat)
        destroy_TOOL = default
        sd_version = sys_call([destroy_TOOL]).splitlines()[0]
        logging.info('Found ' + sd_version)
        destroy_OPTS = ('-q', '-p', '7')
    if not isfile(destroy_TOOL):
        raise NotImplementedError("Can't find a secure file-removal tool")

    logging.info('set destroy init: use %s %s' % (destroy_TOOL, ' '.join(destroy_OPTS)))

    return destroy_TOOL, destroy_OPTS


def set_logging():
    class _log2stdout(object):
        """Print all logging messages, regardless of log level.
        """
        @staticmethod
        def debug(msg):
            m = msgfmt % (get_time() - logging_t0, msg)
            print(m)
        # flatten log levels:
        error = warning = exp = data = info = debug

    class _no_logging(object):
        @staticmethod
        def debug(msg):
            pass
        error = warning = exp = data = info = debug

    logging_t0 = get_time()
    verbose = args and bool(args.verbose or args.filename == 'debug')
    if not verbose:
        logging = _no_logging()
    else:
        msgfmt = "%.4f  " + lib_name + ": %s"
        logging = _log2stdout()

    return logging, logging_t0
    return logging, logging_t0


def set_openssl(path=None):
    """Find, check, set, and report info about the OpenSSL binary to be used.
    """
    if path:  # command-line arg or parameter
        OPENSSL = path
        logging.info('Requested openssl executable: ' + OPENSSL)
    elif sys.platform not in ['win32']:
        OPENSSL = sys_call(['which', 'openssl'])
        if OPENSSL not in ['/usr/bin/openssl']:
            msg = 'unexpected location for openssl binary: %s' % OPENSSL
            logging.warning(msg)
    else:
        # use a bat file for openssl.cfg; create .bat if not found or broken
        bat_name = '_openssl.bat'
        sys_app_data = os.environ['APPDATA']
        if not isdir(sys_app_data):
            os.mkdir(sys_app_data)
        app_lib_dir = os.path.join(sys_app_data, split(lib_dir)[-1])
        if not isdir(app_lib_dir):
            os.mkdir(app_lib_dir)
        OPENSSL = os.path.join(app_lib_dir, bat_name)
        if not exists(OPENSSL):
            logging.info('no working %s file; trying to recreate' % bat_name)
            openssl_expr = 'XX-OPENSSL_PATH-XX'
            bat_template = """@echo off
                REM  """ + bat_identifier + """ for using openssl.exe

                set PATH=""" + openssl_expr + """;%PATH%
                set OPENSSL_CONF=""" + openssl_expr + """\\openssl.cfg
                START "" /b /wait openssl.exe %*""".replace('    ', '')
            default = 'C:\\OpenSSL-Win32\\bin'
            bat = bat_template.replace(openssl_expr, default)
            with open(OPENSSL, 'wb') as fd:
                fd.write(bat)
            test = sys_call([OPENSSL, 'version'])
            if not test.startswith('OpenSSL'):
                # locate and cache result, takes 5-6 seconds:
                cmd = ['where', '/r', 'C:\\', 'openssl.exe']
                where_out = sys_call(cmd)
                if not where_out.strip().endswith('openssl.exe'):
                    fatal('Failed to find OpenSSL.exe.\n' +
                           'Please install under C:\ and try again.')
                guess = where_out.splitlines()[0]  # take first match
                guess_path = guess.replace(os.sep + 'openssl.exe', '')
                where_bat = bat_template.replace(openssl_expr, guess_path)
                with open(OPENSSL, 'wb') as fd:
                    fd.write(where_bat)
        logging.info('will use .bat file for OpenSSL: %s' % OPENSSL)

    if not isfile(OPENSSL):
        msg = 'Could not find openssl executable, tried: %s' % OPENSSL
        fatal(msg, RuntimeError)

    openssl_version = sys_call([OPENSSL, 'version'])
    if openssl_version.split()[1] < '0.9.8':
        fatal('OpenSSL too old (%s)' % openssl_version, RuntimeError)
    logging.info('OpenSSL binary  = %s' % OPENSSL)
    logging.info('OpenSSL version = %s' % openssl_version)

    return OPENSSL, openssl_version


def sha256_(filename):
    """Return sha256 hex-digest of a file, buffered for large files.
    """
    # from stackoverflow:
    dgst = hashlib.sha256()
    with open(filename, mode='rb') as fd:
        for buf in iter(partial(fd.read, 2048), b''):  # null byte sentinel
            dgst.update(buf)
    return dgst.hexdigest()


def sys_call(cmdList, stderr=False, stdin='', ignore_error=False):
    """Run a system command via subprocess, return stdout [, stderr].

    stdin is optional string to pipe in. Will always log a non-empty stderr.
    (stderr is sent to logging.INFO if ignore_error=True).
    """
    msg = ('', ' (ignore_error=True)')[ignore_error]
    log = (logging.error, logging.info)[ignore_error]
    logging.debug('sys_call%s: %s' % (msg, (' '.join(cmdList))))

    proc = subprocess.Popen(cmdList, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    so, se = proc.communicate(stdin)
    so, se = so.strip(), se.strip()
    if se:
        log('stderr%s: %s' % (msg, se))
    if stderr:
        return so.strip(), se
    else:
        return so


def _uniq_file(filename):
    """Avoid file name collisions by appending a count before extension.

    Special case: file.enc.enc --> file.enc_2 rather than file_2.enc
    """
    count = 0
    base, filext = os.path.splitext(filename)
    while isfile(filename) or os.path.isdir(filename):
        count += 1
        filename = base + '_' + str(count) + filext
    return filename


def unset_umask():
    global _old_umask
    if _old_umask is None:
        _old_umask = os.umask(UMASK)  # get current, and change
        os.umask(_old_umask)  # set it back
        return
    reverted_umask = os.umask(_old_umask)
    _old_umask = None
    return reverted_umask


class Tests(object):
    """Test suite for py.test

    pytest.skip:
    - unicode in paths fail on win32
    - permissions fail on win32
    - hardlinks (fsutil) need admin priv on win32
    """
    def setup_class(self):
        global pytest
        import pytest
        #global OPENSSL
        #OPENSSL = '/opt/local/bin/openssl'

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

    def _known_values(self):
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
        if not isfile(pub):
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
        if not isfile(pphr):
            with open(pphr, 'w+b') as fd:
                fd.write(p)

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

    def test_misc_helper_functions(self):
        command_alias()
        sf = SecFile(__file__)
        sf.is_tracked
        sf._get_git_info(sf.file)
        sf._get_git_info(sf.file)
        sf._get_git_info(sf.file)
        get_dropbox_path()

        SecFile().log_metadata(NO_META_DATA)

        good_path = OPENSSL
        with pytest.raises(RuntimeError):
            set_openssl('junk.glop')
        set_openssl(good_path)
        if sys.platform in ['win32']:
            # exercise more code by forcing a reconstructon of the .bat files:
            if OPENSSL.endswith('.bat'):
                if bat_identifier in open(OPENSSL, 'rb').read():
                    os.unlink(OPENSSL)
            if destroy_TOOL.endswith('.bat'):
                if bat_identifier in open(destroy_TOOL, 'rb').read():
                    os.unlink(destroy_TOOL)
        set_openssl()
        set_destroy()

    def test_SecFileArchive(self):
        # test getting a name
        SecFileArchive(paths=None)
        # default get a name from one of the files in paths:
        with open('abc' + AES_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, 'wb') as fd:
            fd.write('abc')
        SecFileArchive(paths=['abc' + RSA_EXT, 'abc' + AES_EXT])

        '''
        # test fall-through decryption method:
        with open('abc' + AES_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + RSA_EXT, 'wb') as fd:
            fd.write('abc')
        with open('abc' + META_EXT, 'wb') as fd:
            fd.write(str(NO_META_DATA))
        #assert exists(datafile)
        sf = SecFileArchive(paths=['abc' + AES_EXT, 'abc' + RSA_EXT, 'abc' + META_EXT])
        dec_method = sf.get_dec_method('unknown')
        assert dec_method in list(default_codec.keys())

        # test missing enc-method in meta-data
        md = 'md'
        with open(md, 'wb') as fd:
            fd.write(log_metadata(NO_META_DATA))
        dec_method = _get_dec_method(md, 'unknown')
        assert dec_method == '_decrypt_rsa_aes256cbc'

        # test malformed archive:
        archname = _uniq_file(os.path.splitext(datafile)[0] + ENC_EXT)
        bad_arch = make_archive(datafile, archname)  # datafile extension bad
        with pytest.raises(SecFileArchiveFormatError):
            decrypt(bad_arch, priv1, pphr1)
        '''

    def test_main(self):
        # similar to test_command_line; this counts towards coverage

        global args
        real_args = sys.argv

        # 'debug' can work but leaves debris behind causing other test fails
        # and gc info gets dumped to screen after py.test
        # avoid inf loop by disabling test_main in debug (for test in tests:)
        #sys.argv = [__file__, 'debug']
        #args = _parse_args()
        #_main()

        # genrsa --> interactive commandline
        sys.argv = [__file__, '--help']
        with pytest.raises(SystemExit):
            args = _parse_args()

        tmp = 'tmp'
        with open(tmp, 'wb') as fd:
            fd.write('a')

        sys.argv = [__file__, '--pad', '-z', '0', tmp]
        args = _parse_args()
        main()

        pub, priv, pphr = self._known_values()[:3]
        sys.argv = [__file__, '--encrypt', '--keep', '--pub', pub,
                    '-z', '0', tmp]
        args = _parse_args()
        main()

        sys.argv = [__file__, '--decrypt', '--keep',
                    '--priv', priv, '--pphr', pphr, tmp + ENC_EXT]
        args = _parse_args()
        main()

        sys.argv = [__file__, '--rotate', '--pub', pub, '-z', '0',
                    '--priv', priv, '--pphr', pphr, tmp + ENC_EXT]
        args = _parse_args()
        out = main()

        sys.argv = [__file__, '--sign',
                    '--priv', priv, '--pphr', pphr, out['file']]
        args = _parse_args()
        out = main()

        sys.argv = [__file__, '--verify',
                    '--sig', priv, '--pub', pub, out['file']]
        args = _parse_args()
        main()

        sys.argv = [__file__, '--pad', tmp + tmp, '--verbose']
        args = _parse_args()
        with pytest.raises(ArgumentError):  # no such file, bad name
            main()

        sys.argv = [__file__, '--pad', '-z', '-24', tmp]  # bad size
        args = _parse_args()
        with pytest.raises(ValueError):
            main()

        sys.argv = [__file__, '--destroy', tmp]
        args = _parse_args()
        main()

        sys.argv = real_args

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
        bad1 = {'_en': _encrypt_rsa_aes256cbc}
        bad2 = {'_foo': _decrypt_rsa_aes256cbc}
        with pytest.raises(ValueError):  # too short
            test_codec.register(bad1)
        with pytest.raises(ValueError):  # not _enc or _dec
            test_codec.register(bad2)

        # unicode not convertable to ascii:
        bad_key = u'_encrypt_☢☢☢_aes256cbc'
        with pytest.raises(UnicodeEncodeError):
            str(bad_key)
        bad = {bad_key: _encrypt_rsa_aes256cbc}
        with pytest.raises(ValueError):
            test_codec.register(bad)

        # unicode convertable to ascii:
        test_codec2 = PFSCodecRegistry()
        ok = {u'_decrypt_rsa_aes256cbc': _decrypt_rsa_aes256cbc}
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
        logging.debug('test bit_count')
        os.chdir(mkdtemp())
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

        global PAD_BYTE
        PAD_BYTE = b'\1'
        sf1.pad(2 * known_size)
        file_contents = open(tmp1, 'rb').read()
        assert file_contents[-1] == PAD_BYTE  # actual byte should not matter

        PAD_BYTE = b'\0'
        with pytest.raises(PaddingError):
            sf1.pad(-1)  # should be a byte mismatch at this point

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
        global MAX_FILE_SIZE
        MAX_restore = MAX_FILE_SIZE
        MAX_FILE_SIZE = 2 ** 8  # fake, to test if hit the limit
        tmpmax = 'maxsize.txt'
        with open(tmpmax, 'w+b') as fd:
            fd.write(b'a' * (MAX_FILE_SIZE + 1))  # ensure too large

        with pytest.raises(FileStatusError):
            sf = SecFile(tmpmax)
        MAX_FILE_SIZE = MAX_restore

    def test_big_file(self):
        pytest.skip()  # its slow
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

    def test_genRsaKeys(self):
        pytest.skip()  # its slow
        # set sys.argv to test arg usage; similar in test_main()
        global args
        real_args = sys.argv

        gen = GenRSA()

        # test genRsaKeys
        sys.argv = [__file__, 'genrsa', '--passfile']
        args = _parse_args()
        pub, priv, pp = gen.dialog(interactive=False)

        # induce some badness to increase test cov: pub==priv, existing priv:
        sys.argv = [__file__, 'genrsa', '--pub', priv, '--priv', priv]
        args = _parse_args()
        pu, pr, pp = gen.dialog(interactive=False)

        # the test is that we won't overwrite existing priv
        with open(priv, 'wb') as fd:
            fd.write('a')
        assert isfile(priv)  # or can't test
        sys.argv = [__file__, 'genrsa', '--priv', priv]
        args = _parse_args()
        pu, pr, pp = gen.dialog(interactive=False)
        assert (pu, pr) == (None, None)

        sys.argv = [__file__, '--pad', 'no file', '--verbose']
        args = _parse_args()
        log_test, log_test_t0 = set_logging()
        log_test.debug('trigger coverage of debug log')

        sys.argv = real_args

    def test_encrypt_decrypt(self):
        # Lots of tests here (just to avoid re-generating keys a lot)
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext no unicode.txt'
        with open(datafile, 'wb') as fd:
            fd.write(secretText)

        testBits = 2048  # fine to test with 1024 and 4096
        pubTmp1 = 'pubkey1 no unicode.pem'
        prvTmp1 = 'prvkey1 no unicode.pem'
        pphr1 = printable_pwd(180)
        pub1, priv1 = GenRSA().generate(pubTmp1, prvTmp1, pphr1, testBits)

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pphr2_w_spaces = '  ' + printable_pwd(180) + '   '  # spaces in pphr
        pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr2_w_spaces, testBits)

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
        with pytest.raises(EncryptError):
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
        with open(pphr1_file, 'wb') as fd:
            fd.write(pphr1)
        sf.decrypt(priv1, pphr1_file)
        recoveredText = open(sf.file).read()
        # file contents match:
        assert recoveredText == secretText

        # a BAD or MISSING passphrase should fail:
        sf = SecFile(datafile).encrypt(pub1, keep=True)
        with pytest.raises(PrivateKeyError):
            sf.decrypt(priv1, pphr2_w_spaces)
        with pytest.raises(DecryptError):
            sf.decrypt(priv1)

        # a correct-format but wrong priv key should fail:
        sf = SecFile(datafile).encrypt(pub1, keep=True)
        pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr1, testBits)
        with pytest.raises(DecryptError):
            sf.decrypt(priv2, pphr1)

        # should refuse-to-encrypt if pub key is too short:
        pub256, __ = GenRSA().generate('pub256.pem', 'priv256.pem', bits=256)
        assert get_key_length(pub256) == 256  # need a short key to use in test
        sf = SecFile(datafile).encrypt(pub1, keep=True)
        with pytest.raises(PublicKeyTooShortError):
            sf.encrypt(pub256)

    def test_rotate(self):
        # Set-up:
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext no unicode.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pphr2 = '  ' + printable_pwd(180) + '   '  # spaces in pphr
        pub2, priv2 = GenRSA().generate(pubTmp2, prvTmp2, pphr2, 1024)

        # Rotate encryption including padding change:
        sf = SecFile(datafile).encrypt(pub1, date=False)
        first_enc_size = sf.size
        sf.rotate(pub=pub2, priv=priv1, pphr=pphr1, pad=8192)
        second_enc_size = sf.size
        sf.rotate(pub=pub1, priv=priv2, pphr=pphr2, pad=16384, hmac_key='key')
        third_enc_size = sf.size
        # padding affects .enc file size, values vary a little from run to run
        assert first_enc_size < third_enc_size

        sf.decrypt(priv1, pphr=pphr1)
        assert not open(sf.file).read() == secretText  # dec but still padded
        sf.pad(0)
        assert open(sf.file).read() == secretText

        pytest.skip()
        ##################################################################

        # Meta-data from key rotation:
        sf = SecFile(datafile).encrypt(pub1)
        print sf.file
        md = sf.load_metadata()
        log_metadata(md)  # for debug
        dates = list(md.keys())
        hashes = [md[d]['sha256 of encrypted file'] for d in dates]
        assert len(hashes) == len(set(hashes)) == 3
        assert ('meta-data %s' % DATE_UNKNOWN) in dates

        # Should be only one hmac-sha256 present; hashing tested in test_hmac:
        hmacs = [md[d]['hmac-sha256 of encrypted file'] for d in dates
                 if 'hmac-sha256 of encrypted file' in list(md[d].keys())]
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
        print sf.file
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
        arc = SecFileArchive(paths=[datafile])
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
        print __file__, lib_path
        datafile = _abspath(datafile)

        # Encrypt:
        cmdLineCmd = [sys.executable, pathToSelf, datafile, '--encrypt',
                      '--pub', pub1, '--keep', '--openssl=' + OPENSSL]
        oute = sys_call(cmdLineCmd)
        assert 'archive' in oute
        enc = eval(oute)
        assert isfile(enc['archive'])

        # Decrypt:
        cmdLineCmd = [sys.executable, pathToSelf, enc['archive'], '--decrypt', '--keep',
                      '--priv', priv1, '--pphr', pphr1, '--openssl=' + OPENSSL]
        outd = sys_call(cmdLineCmd)
        assert 'clear_text' in outd
        dec = eval(outd)
        assert isfile(dec['clear_text'])
        recoveredText = open(dec['clear_text']).read()
        assert recoveredText == secretText  # need both enc and dec to work

        # Rotate:
        assert isfile(enc['archive']) and enc['archive'].endswith(ENC_EXT)  # need --keep in d
        cmdLineRotate = [sys.executable, pathToSelf, enc['archive'], '--rotate',
                      '--pub', pub1, '-z', str(getsize(enc['archive']) * 2),
                      '--priv', priv1, '--pphr', pphr1]
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
        assert 'padding' in outp
        out = eval(outp)
        assert getsize(datafile) == DEFAULT_PAD_SIZE
        assert out['padding'] == DEFAULT_PAD_SIZE - orig_size

        cmdLineUnpad = [sys.executable, pathToSelf, datafile, '--pad',
                        '-z', '0']
        outunp = sys_call(cmdLineUnpad)
        assert 'padding' in outunp
        out = eval(outunp)
        assert out['padding'] == None

        # Destroy:
        cmdLineDestroy = [sys.executable, pathToSelf, datafile, '--destroy']
        outx = sys_call(cmdLineDestroy)
        if 'disposition' in outx:
            out = eval(outx)
        assert out['disposition'] == destroy_code[pfs_DESTROYED]

    def test_destroy(self):
        # see if it takes at least 50x longer to destroy() than unlink a file
        # if so, destroy_TOOL is doing something, hopefully its a secure delete

        if sys.platform == 'win32' and not destroy_TOOL:
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

        global dropbox_path
        orig = dropbox_path

        '''
        # NamedTempFile is ok by design:
        with NamedTemporaryFile() as fd:
            dropbox_path = split(abspath(fd.name))[0]  # trigger Dropbox warn
            assert hasattr(fd, 'close')
            fd.write('a')
            destroy(fd, cmdList=('-f', '-s'))
        dropbox_path = orig  # restore real path
        '''

    def test_destroy_links(self):
        # Test detection of multiple links to a file when destroy()ing it:

        tw_path = 'tmp_test_destroy no unicode'
        with open(tw_path, 'wb') as fd:
            fd.write(b'\0')
        assert isfile(tw_path)  # need a file or can't test
        if not user_can_link:
            code, links, __ = destroy(tw_path)
            assert links == -1
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
        # assumes that is_in_dropbox works correctly (returns Dropbox folder)
        # this test assesses whether decrypt will refuse to proceed
        global dropbox_path
        orig_path = dropbox_path

        fake_dropbox_path = _abspath('.')
        dropbox_path = fake_dropbox_path  # set global var
        assert get_dropbox_path() == fake_dropbox_path  #  get_dropbox_path() returns dropbox_path

        test_path = os.path.join(dropbox_path, 'test.txt')
        with open(test_path, 'wb') as fd:
            fd.write('test db file contents')
        assert isfile(test_path)

        # raise if try to decrypt in Dropbox folder
        pub, priv, pphr = self._known_values()[:3]
        sf = SecFile(test_path)
        sf.encrypt(pub)
        assert sf.is_in_dropbox  # fake dropbox
        with pytest.raises(FileStatusError):
            sf.decrypt(priv, pphr)

        dropbox_path = None
        if sys.platform != 'win32':
            host_db = os.path.expanduser('~/.dropbox/host.db')
            # moves your actual dropbox locator; auto-rebuilt by DB if lost
            if exists(host_db):
                try:
                    os.rename(host_db, host_db + '.orig')
                    get_dropbox_path()
                    assert sf.is_in_dropbox == False  # bc no dropbox now
                finally:
                    os.rename(host_db + '.orig', host_db)
                assert dropbox_path == False

        dropbox_path = orig_path


def main():
    logging.info("%s with %s" % (lib_name, openssl_version))
    if args.filename == 'debug':
        """Run tests with verbose logging; check for memory leaks using gc.
            $ python pyfilesec.py debug --gc >& saved
        """
        global pytest
        import pytest

        dbg_dir = 'debug_' + lib_name
        shutil.rmtree(dbg_dir, ignore_errors=True)
        os.mkdir(dbg_dir)
        os.chdir(dbg_dir)  # intermediate files get left inside
        if args.gc:
            import gc
            gc.enable()
            gc.set_debug(gc.DEBUG_LEAK)

        ts = Tests()
        tests = [t for t in dir(ts) if t.startswith('test_')]
        for test in tests:
            try:
                eval('ts.' + test + '()')
            except:
                result = test + ' FAILED'
                print(result)
        logging.info("%.4fs for tests" % (get_time() - logging_t0))
    elif args.filename == 'genrsa':
        """Walk through key generation on command line.
        """
        GenRSA().dialog()
    elif not isfile(args.filename):
        raise ArgumentError('no such file (requires genrsa, debug, or a file)')
    else:
        """Call requested method with arguments, return result.

        Methods:    encrypt, decrypt, rotate, pad, sign, verify, destroy
        Properties: hardlinks, is_tracked, permissions, is_in_dropbox
        """
        fxn = None  # becomes the actual function
        kw = {}  # kwargs for fxn

        # "kw.update()" ==> required arg, use kw even though its position-able
        # "arg and kw.update(arg)" ==> optional args; watch out for value == 0

        sf = SecFile(args.filename)
        # mutually exclusive args.fxn:
        if args.encrypt:
            sf_fxn = sf.encrypt
            # convenience arg: pad the file prior to encryption
            if args.size >= -1:
                sf.pad(args.size)
            kw.update({'pub': args.pub})
            args.keep and kw.update({'keep': args.keep})
            meta = not args.nometa
            meta and kw.update({'meta': meta})
            args.hmac and kw.update({'hmac_key': args.hmac})
        elif args.decrypt:
            sf_fxn = sf.decrypt
            kw.update({'priv': args.priv})
            args.pphr and kw.update({'pphr': args.pphr})
            args.out and kw.update({'out': args.out})
            args.keep and kw.update({'keep_enc': args.keep})
        elif args.rotate:
            sf_fxn = sf.rotate
            kw.update({'priv': args.priv})
            args.pphr and kw.update({'pphr': args.pphr})
            kw.update({'pub': args.pub})
            args.keep and kw.update({'keep_meta': args.keep})
            args.hmac and kw.update({'hmac_new': args.hmac})
            if args.size >= -1:
                kw.update({'pad': args.size})
        elif args.pad:
            sf_fxn = sf.pad
            if args.size >= -1:
                kw.update({'size': args.size})
            elif args.size is not None:
                raise ValueError('bad argument for -z/--size to pad')
        elif args.sign:
            sf_fxn = sf.sign
            kw.update({'priv': args.priv})
            args.pphr and kw.update({'pphr': args.pphr})
            args.out and kw.update({'out': args.out})
        elif args.verify:
            sf_fxn = sf.verify
            kw.update({'pub': args.pub})
            kw.update({'sig': args.sig})
        elif args.destroy:
            sf_fxn = sf.destroy
        elif args.hardlinks:
            sf_fxn = sf.hardlinks
        elif args.versioned:
            sf_fxn = sf.is_tracked
        elif args.permissions:
            sf_fxn = sf._get_permissions
        elif args.dropbox:
            sf_fxn = sf._get_is_in_dropbox

        sf_fxn(**kw)  # make it happen
        return sf.result


def _parse_args():
    """Parse and return command line arguments.

    a file name is typically the first (required) argument
    passphrases for command-line usage must go through files;
        will get a logging.warning()
    currently not possible to register a new enc/dec method via command line
    """
    parser = argparse.ArgumentParser(
        description='File-oriented privacy & integrity management library.',
        epilog="See http://pythonhosted.org/pyFileSec/")
    parser.add_argument('filename', help='file (path), "genrsa", or "debug" (no quotes)')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--verbose', action='store_true', help='print logging info to stdout')
    parser.add_argument('--openssl', help='specify path of the openssl binary to use')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--encrypt', action='store_true', help='encrypt with RSA + AES256 (-u [-m][-n][-c][-z][-e][-k])')
    group.add_argument('--decrypt', action='store_true', help='use private key to decrypt (-v [-d][-r])')
    group.add_argument('--rotate', action='store_true', help='rotate the encryption (-v -U [-V][-r][-R][-z][-e][-c])')
    group.add_argument('--sign', action='store_true', help='sign file / make signature (-v [-r][-o])')
    group.add_argument('--verify', action='store_true', help='verify a signature using public key (-u -s)')
    group.add_argument('--pad', action='store_true', help='obscure file length by padding with bytes ([-z])')
    group.add_argument('--destroy', action='store_true', help='secure delete')
    group.add_argument('--hardlinks', action='store_true',help='return number of hardlinks to a file', default=False)
    group.add_argument('--tracked', action='store_true',help='return True if file is tracked using git, svn, or hg', default=False)
    group.add_argument('--permissions', action='store_true',help='return file permissions', default=False)
    group.add_argument('--dropbox', action='store_true',help='return True if a file is in Dropbox folder', default=False)

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('--clipboard', action='store_true', help='genrsa: passphrase placed on clipboard (only)', default=False)
    group2.add_argument('--passfile', action='store_true', help='genrsa: save passphrase to file, name matches keys', default=False)

    parser.add_argument('-o', '--out', help='sign: path name for the generated sig')
    parser.add_argument('-u', '--pub', help='path to public key (.pem file)')
    parser.add_argument('-v', '--priv', help='path to private key (.pem file)')
    parser.add_argument('-p', '--pphr', help='path to file containing passphrase for private key')
    parser.add_argument('-c', '--hmac', help='path to file containing hmac key')
    parser.add_argument('-s', '--sig', help='path to signature file (required input for --verify)')
    parser.add_argument('-z', '--size', type=int, help='bytes for --pad, min 128, default 16384; remove 0, -1')
    parser.add_argument('-N', '--nodate', action='store_true', help='do not include date in the meta-data (clear-text)')
    parser.add_argument('-M', '--nometa', action='store_true', help='suppress saving meta-data with encrypted file', default=False)
    parser.add_argument('-k', '--keep', action='store_true', help='do not --destroy plain-text file after --encrypt')
    parser.add_argument('-g', '--gc', action='store_true', help='debug: use gc.DEBUG_LEAK (garbage collection)', default=False)

    return parser.parse_args()


# Basic set-up (order matters) ------------------------------------------------

if sys.platform == 'win32':
    get_time = time.clock
    from win32com.shell import shell
    user_can_link = shell.IsUserAnAdmin()  # for fsutil hardlink
else:
    get_time = time.time
    user_can_link = True

if __name__ == "__main__":
    args = _parse_args()
else:
    args = None

logging, logging_t0 = set_logging()
path_wanted = args and args.openssl
OPENSSL, openssl_version = set_openssl(path_wanted)
destroy_TOOL, destroy_OPTS = set_destroy()

default_codec = {'_encrypt_rsa_aes256cbc': _encrypt_rsa_aes256cbc,
                 '_decrypt_rsa_aes256cbc': _decrypt_rsa_aes256cbc}
codec_registry = PFSCodecRegistry(default_codec)

if __name__ == '__main__':
    print(main())
