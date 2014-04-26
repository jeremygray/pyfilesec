#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pyFileSec: File-oriented privacy & integrity management tools
"""

 # Copyright (c) Jeremy R. Gray, 2013-2014
 # Released under the GPLv3 licence with the additional exemptions that
 # 1) compiling, linking, and/or using OpenSSL are allowed, and
 # 2) the copyright notice, licence terms, and following disclaimer be included
 #    in any and all derivative work.

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


__version__ = '0.2.14'
__author__ = 'Jeremy R. Gray <jrgray@gmail.com>'


import sys
if sys.version < '2.6':
    raise RuntimeError('Requires python 2.6 or higher')

PY3 = sys.version > '3'
if PY3:
    read_mode = 'r'  # 3.x file open does universal newlines by default
else:
    read_mode = 'rU'  # univeral newlines, for cross-platform transparency
write_mode = 'w'

import argparse
from   base64 import b64encode, b64decode
import copy
from   functools import partial  # for buffered hash digest
import hashlib
import json
import os
from   os.path import abspath, isfile, getsize, isdir, dirname, exists, split
import random
import re
import shutil
import stat
import subprocess
import tarfile
from   tempfile import mkdtemp, NamedTemporaryFile
import threading
import time

# higher directory has: which, _getpass, _pyperclip
sys.path.insert(0, dirname(abspath('__file__')))
from which import which, WhichError

lib_name = 'pyFileSec'
lib_path = abspath(__file__).rstrip('co')  # .py not .pyc, .pyo
lib_dir = dirname(lib_path)

if sys.platform == 'win32':
    from win32com.shell import shell  # pylint: disable=F0401
    user_can_link = shell.IsUserAnAdmin()  # for fsutil hardlink
    get_time = time.clock
else:
    user_can_link = True
    get_time = time.time

# Constants: --------------------
RSA_PADDING = '-oaep'  # actual arg for openssl rsautl in encrypt, decrypt

ENC_EXT = '.enc'     # extension for for tgz of AES, PWD.RSA, META
AES_EXT = '.aes256'  # extension for AES encrypted data file
RSA_EXT = '.pwdrsa'  # extension for RSA-encrypted AES-pwd (ciphertext)
META_EXT = '.meta'   # extension for meta-data

# RSA key
RSA_MODULUS_MIN = 1024  # threshold to avoid PublicKeyTooShortError
RSA_MODULUS_WRN = 2048  # threshold to avoid warning about short key

# RsaKeys require() codes:
NEED_PUBK = 1
NEED_PRIV = 2
NEED_PPHR = 4

# warn that operations will take a while, check disk space, ...
LRG_FILE_WARN = 2 ** 24  # 17M; used in tests but not implemented elsewhere
MAX_FILE_SIZE = 2 ** 33  # 8G; larger likely fine unless pad w/ > 8G pad

# file-length padding:
PFS_PAD = 'pyFileSec_padded'  # label = 'file is padded'
PAD_STR = 'pad='    # label means 'pad length = \d\d\d\d\d\d\d\d\d\d bytes'
PAD_BYTE = b'\0'    # actual byte to use; value unimportant
assert not str(PAD_BYTE) in PFS_PAD
assert len(PAD_BYTE) == 1
PAD_LEN = len(PAD_STR + PFS_PAD) + 10 + 2  # len of info about padding
    # 10 = # digits in max file size, also works for 4G files
    # 2 = # extra bytes, one at end, one between PAD_STR and PFS_PAD labels
PAD_MIN = 128  # minimum length in bytes post-padding
DEFAULT_PAD_SIZE = 16384  # default resulting file size

# used if user suppresses the date; will sort before a numerical date:
DATE_UNKNOWN = '(date-time suppressed)'
NO_META_DATA = {'meta-data %s' % DATE_UNKNOWN: {'meta-data': False}}
METADATA_NOTE_MAX_LEN = 120

whitespace_re = re.compile('\s')
hexdigits_re = re.compile('^[\dA-F]+$|^[\da-f]+$')

# destroy() return codes:
destroy_code = {1: 'secure deleted', 0: 'unlinked', -1: 'unknown'}
pfs_DESTROYED = 1
pfs_UNLINKED = 0
pfs_UNKNOWN = -1

# SecFile.file permissions:
PERMISSIONS = 0o600  # for all SecFiles: no execute, no group, no other
UMASK = 0o077  # need u+x permission for directories
old_umask = None  # set as global in set_umask, unset_umask

lib_path = os.path.abspath(__file__).strip('co')  # .py not .pyc, .pyo
lib_dir = os.path.split(lib_path)[0]

# for making .bat files for sdelete.exe and openssl.exe:
bat_identifier = '-- pyFileSec .bat file --'
sd_bat_template = """@echo off
                    REM  """ + bat_identifier + """ for using sdelete.exe

                    START "" /b /wait XSDELETEX %*""".replace('    ', '')
op_expr = 'XX-OPENSSL_PATH-XX'
op_default = 'C:\\OpenSSL-Win32\\bin'
op_bat_template = """@echo off
    REM  """ + bat_identifier + """ for using openssl.exe

    set PATH=""" + op_expr + """;%PATH%
    set OPENSSL_CONF=""" + op_expr + """\\openssl.cfg
    START "" /b /wait openssl.exe %*""".replace('    ', '')
if sys.platform == 'win32':
    appdata_lib_dir = os.path.join(os.environ['APPDATA'],
                                   os.path.split(lib_dir)[-1])
    if not os.path.isdir(appdata_lib_dir):
        os.mkdir(appdata_lib_dir)

    op_bat_name = os.path.join(appdata_lib_dir, '_openssl.bat')


# Initialize values: --------------------
dropbox_path = None


# Exception classes: --------------------
if True:
    # pylint: disable=C0111,C0321
    class PyFileSecError(Exception): pass  # Base exception for pyFileSec errors

    class EncryptError(PyFileSecError): pass  # failed, or refused to start

    class DecryptError(PyFileSecError): pass  # failed, or refused to start

    class PublicKeyError(PyFileSecError): pass

    class PublicKeyTooShortError(PyFileSecError): pass

    class PrivateKeyError(PyFileSecError): pass

    class PassphraseError(PyFileSecError): pass

    class SecFileFormatError(PyFileSecError): pass

    SecFileArchiveFormatError = SecFileFormatError

    class PaddingError(PyFileSecError): pass

    class CodecRegistryError(PyFileSecError): pass  # e.g., not registered

    class DestroyError(PyFileSecError): pass  # e.g., destroy failed

    class ArgumentError(PyFileSecError): pass  # e.g., no file specified

    class FileNotEncryptedError(PyFileSecError): pass

    class FileStatusError(PyFileSecError): pass


class PFSCodecRegistry(object):
    """Class to explicitly manage the encrypt and decrypt functions (= codec).

    A PFSCodecRegistry is used to return the actual encrypt and decrypt
    functions to use when a SecFile object calls its ``.encrypt()`` or
    ``.decrypt()`` methods. The functions are vetted to conform to a minimal
    expected format, and can optionally be required to pass an
    encrypt-then-decrypt self-test before being registered (and hence available
    to a SecFile to use).

    Typically, there is no need for anything other than the default registry
    that is set-up automatically. Each instance of a ``SecFile`` keeps its
    own copy of the registry. In part, having a registry is to help ensure
    longer-term API stability even in the event that a change in underlying
    cryptographic protocol is necessitated. It is also desirable to be able to
    support a "read only" mode, i.e., to access and use all decryption methods,
    while preventing encryption with that same codec.

    The checks are designed to protect against archival ambiguity and operator
    errors, and not against adversarial manipulation of the registry.

    To register a new function, the idea is to be able to do::

        codec = PFSCodecRegistry()
        new = {'_encrypt_xyz': _encrypt_xyz,
               '_decrypt_xyz': _decrypt_xyz}
        codec.register(new)
    """
    # However, its not this simple yet: a) will need to update file extensions
    # and so on for files generated (currently are constants).
    # b) `rotate()` will need a newEncMethod param.

    def __init__(self, defaults={}, test_keys=None):
        """The class is designed around the default functions, and is intended
        to be easily extensible. To register a new function, the
        idea is to be able to do::

            codec = PFSCodecRegistry()
            ...
            new = {'_encrypt_xyz': _encrypt_xyz,
                   '_decrypt_xyz': _decrypt_xyz}
            codec.register(new)

        and then `encrypt(method='_encrypt_xyz')` will work.

        If ``enc_kwargs`` and ``dec_kargs`` are given (as kwarg dicts), the
        codecwill be tested on a sample file. Registration will only succeed if
        the new decryption method can recover a snippet of text that was
        encrypted by the new encryption function.

        The codec keys (e.g., '_encrypt_xyz' in the above example) should match
        the function names (for clarity), and for this reason should be
        ascii-compatible (because names in python 2 cannot be unicode).
        """
        self.name = 'PFSCodecRegistry'
        self._functions = {}
        self.register(defaults, test_keys)

    def keys(self):
        return list(self._functions.keys())

    def register(self, new_functions, test_keys=None):
        """Validate and add a new codec functions to the registry.

        Typically one registers encrypt and decrypt functions in pairs. Its
        possible to register only a decrypt function, to support "read only"
        (decrypt) use of a codec.

        If ``test_keys`` is provided, an
        encrypt-decrypt self-test validation must passbefore registration can
        proceed. ``test_keys``  should be a tuple of (enc_kwargs, dec_kwargs)
        that will be passed to the respective functions being registered.
        """
        if test_keys:
            enc_kwargs, dec_kwargs = test_keys
            test_co = PFSCodecRegistry({})
            test_co._functions = new_functions  # splice in to bypass .register
            test_dir = mkdtemp()
            test_file = os.path.join(test_dir, 'codec_enc_dec.txt')
            test_datum = printable_pwd(64)
            with open(test_file, write_mode) as fd:
                fd.write(test_datum)
            try:
                sf = SecFile(test_file, codec=test_co)
                sf.encrypt(keep=True, **enc_kwargs)
                sf.decrypt(**dec_kwargs)
            finally:
                os.unlink(test_file)
                if sf.file:
                    recovered = open(sf.file, read_mode).read()
                os.unlink(sf.file)
            assert recovered == test_datum  # 'Codec reg: enc-dec failed'

        for key, fxn in list(new_functions.items()):
            try:
                key = str(key)  # not unicode
            except UnicodeEncodeError:
                fatal('keys restricted to str (not unicode)')
            if not len(key) > 3 or key[:4] not in ['_enc', '_dec']:
                msg = ': failed to register "%s": need _enc..., _dec...' % key
                fatal(self.name + msg)
            if not hasattr(fxn, '__call__'):
                msg = ': failed to register "%s", not callable' % key
                fatal(self.name + msg)
            if key in list(self.keys()):
                fatal(self.name + ': function "%s" already registered' % key)
            self._functions.update({key: fxn})
            fxn_info = '%s(): fxn hash=%d' % (key, hash(fxn))
            # could require functions be in external files, get a sha256 ...
            logging.info(self.name + ': registered %s' % fxn_info)

        # allow _dec without _enc, but not vice-verse:
        for key in list(new_functions.keys()):
            if key.startswith('_dec'):
                continue
            assert key.startswith('_enc')
            dec_twin = key.replace('_enc', '_dec', 1)
            if not dec_twin in list(self._functions.keys()):
                fatal('method "%s" bad codec: _enc without a _dec' % key)

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
                msg = 'not found in registry: %s' % key
                logging.warning(msg)

    def get_function(self, fxn_name):
        """Return a validated function based on its registry key ``fxn_name``.
        """
        if self.is_registered(fxn_name):
            return self._functions[fxn_name]
        fatal('function %s not in registry' % fxn_name, CodecRegistryError)

    def is_registered(self, fxn_name):
        """Returns True if `fxn_name` is registered; validated at registration.
        """
        return fxn_name in self._functions


class _SecFileBase(object):
    """Class providing helper methods and properties, but not core sec methods.
    """
    def __init__(self, pub=None, priv=None, pphr=None):
        self.rsakeys = RsaKeys(pub=pub, priv=priv, pphr=pphr)

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
        self._require_file(check_size=False)
        return getsize(self.file)

    def reset(self):
        """Reinitialize, preserve RSA keys, openssl, and codec
        """
        name = 'reset'
        logging.info(name + ' start')
        self.__init__(infile=None, pub=self.rsakeys.pub,
                      priv=self.rsakeys.priv, pphr=self.rsakeys.pphr,
                      codec=self.codec, openssl=self._openssl)

    def set_file(self, infile):
        """Set the filename, and change the file's permissions on disk.

        File permissions are set to conservative value on disk (Mac, Linux).
        Warn if infile looks like a public key (easy to get pos. arg wrong)
        """
        # self.file is always a path, not a file object
        if infile is None:
            self._file = None
            logging.info('set_file: received filename: None')
            return
        if not isinstance_basestring23(infile):
            fatal('set_file: infile expected as a string', AttributeError)
        f = os.path.split(infile)[1]
        if f and f[0] in ['.', os.sep]:
            fatal('set_file: infile name starts with bad character',
                  SecFileArchiveFormatError)
        self._file = _abspath(infile)
        if exists(self._file):
            self.permissions = PERMISSIONS  # changes permissions on disk
        else:
            raise OSError('no such file %s' % self._file)
        if (os.path.splitext(self._file)[1] == '.pem' or
            'PUBLIC KEY' in open(infile, read_mode).read()):
            logging.warning('infile looks like a public key')

    def set_file_time(self, new_time=None):
        """Obscure the time-stamp on the underlying file system.
        """
        fatal('file time-stamp removal not supported yet', NotImplementedError)

    @property
    def file(self):
        """The current file path/name (string, not a file object).
        """
        return self._file  # can be None

    @property
    def basename(self):
        if not self.file:
            return None
        return os.path.basename(self.file)

    def read(self, lines=0):
        """Return lines from self.file as a string; 0 means all lines.
        """
        if not self.file:
            return ''

        if int(lines) < 1:
            contents = open(self.file, read_mode).read()  # all
        else:
            if self.is_encrypted:
                contents = open(self.file, read_mode).read(lines * 60)
            else:
                _ = open(self.file, read_mode).readlines()[:lines]
                contents = ''.join(_)
        if self.is_encrypted:
            return b64encode(contents)
        return contents

    @property
    def snippet(self):
        """Up to 60 characters of the first line
        """
        return self.read(1).strip()[:60]

    def _require_file(self, status=None, check_size=True):
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
        if check_size and getsize(self._file) > MAX_FILE_SIZE:
            fatal("file too large (max size %d bytes)" % MAX_FILE_SIZE,
                  ValueError)
        return self.file

    def _require_enc_file(self, status=None, check_size=False):
        """Returns a SecFileArchive, or fails
        """
        self._require_file(status, check_size=check_size)
        if self.is_not_encrypted:
            fatal('Require an encrypted file.', FileNotEncryptedError)
        return SecFileArchive(self.file)

    @property
    def is_in_writeable_dir(self):
        # True if permissions allow writing to the file's current directory
        # don't call _require_*file
        # TO-DO: explore os.access using a try-except approach
        # that is safer than if test-then-read, see os.access docs
        # (still might want to be able to check writeability as a property)
        if not self._file:
            return False
        directory, filename = os.path.split(self._file)
        writeable = True
        try:
            tmp = printable_pwd(32)
            test_name = os.path.join(directory, tmp)
            open(test_name, write_mode)
        except IOError as e:
            if e.errno == os.errno.EACCES:
                writeable = False
        finally:
            try:
                os.unlink(test_name)
            except:
                pass
        return writeable

    def load_metadata(self):
        """Read meta-data file, return it as a dict.
        """
        if hasattr(self, 'meta') and self.meta:
            return json.load(open(self.meta, read_mode))
        return NO_META_DATA

    @property
    def metadataf(self):
        """Return formatted meta-data dict (human-friendly string).
        """
        return json.dumps(self.metadata, indent=2, sort_keys=True,
                          separators=(',', ': '))

    @property
    def metadata(self):
        try:
            self._require_enc_file()
        except FileNotEncryptedError:
            return {}
        sfa = SecFileArchive(arc=self.file)
        self.data_aes, self.pwd_rsa, self.meta = sfa.unpack()
        md = self.load_metadata()
        for f in [self.data_aes, self.pwd_rsa, self.meta]:
            os.unlink(f)
        self.data_aes, self.pwd_rsa, self.meta = (None,) * 3
        return md

    def _get_permissions(self):
        name = '_get_permissions'
        self._require_file(check_size=False)
        perm = -1  # 'win32-not-implemented'
        if not sys.platform in ['win32']:
            perm = int(oct(os.stat(self.file)[stat.ST_MODE])[-3:], 8)
        logging.debug(name + ': %s %s octal' % (self.file, oct(perm)))
        self.result = oct(perm)
        return perm

    def _set_permissions(self, mode):
        name = '_set_permissions'
        self._require_file(check_size=False)
        if sys.platform not in ['win32']:
            os.chmod(self.file, mode)
        else:
            pass
            # import win32security  # looks interesting
            # info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            #           DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
            # info = 1,3,7 works as admin, 15 not enough priv; SACL = 8
            # win32security.GetFileSecurity(filename, info)
            # win32security.SetFileSecurity
        logging.info(name +
                     ': %s %s' % (self.file, permissions_str(self.file)))

    permissions = property(_get_permissions, _set_permissions, None,
        "mac/nix:  Returns POSIX ugo permissions\n"
        "win32  :  not implemented, returns -1")

    @property
    def hardlinks(self):
        if not user_can_link:
            return -1
        if not self.file:
            return 0
        filename = self._require_file(check_size=False)
        if sys.platform == 'win32':
            links = sys_call(['fsutil', 'hardlink', 'list', filename])
            count = len([f for f in links.splitlines() if f.strip()])
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
        inside = db_path and ((self.file.startswith(db_path + os.sep) or
                  self.file == db_path))
        not_or_blank = (' not', '')[inside]
        logging.info('%s is%s inside Dropbox' % (self.file, not_or_blank))

        return inside

    @property
    def is_not_in_dropbox(self):
        return self.file and not self.is_in_dropbox

    @property
    def is_encrypted(self):
        # TO-DO: detect format regardless of file name
        encrypted = (self.file and
                     self.file.endswith(ENC_EXT) and
                     tarfile.is_tarfile(self.file))
        return encrypted

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
        self._require_file(check_size=False)
        logging.debug('trying to detect version control (svn, git, hg)')

        return any([self._get_svn_info(self.file),
                    self._get_git_info(self.file),
                    self._get_hg_info(self.file)])

    def _get_git_info(self, path, git='git'):
        """Report whether a directory or file is tracked in a git repo.

        Can test any generic filename, not just current file::

            >>> from pyfilesec import SecFile
            >>> SecFile()._get_git_info(path)

        Accurate if a file is the repo directory but not actually tracked.
        Assumes path is not versioned by git if git is not call-able.
        """
        if not path or not exists(path):
            return False
        try:
            sys_call([git])
        except OSError:
            # no git, not call-able
            return False
        cmd = [git, 'ls-files', abspath(path)]
        is_tracked = bool(sys_call(cmd, ignore_error=True))

        logging.debug('path %s tracked in git repo: %s' % (path, is_tracked))
        return is_tracked

    def _get_svn_info(self, path):
        """Tries to discover if a file is tracked under svn.
        """
        if not path or not exists(path):
            return False
        if not isdir(path):
            path = dirname(path)
        has_svn_dir = isdir(os.path.join(path, '.svn'))
        logging.debug('path %s tracked in svn repo: %s' % (path, has_svn_dir))
        return has_svn_dir

    def _get_hg_info(self, path):
        """Tries to discover if a file is tracked under mercurial.
        """
        if not path or not exists(path):
            return False
        if not isdir(path):
            path = dirname(path)
        has_hg_dir = isdir(os.path.join(path, '.hg'))
        logging.debug('path %s tracked in hg repo: %s' % (path, has_hg_dir))
        return has_hg_dir


class SecFile(_SecFileBase):
    """Class for working with a file as a more-secure object.

    A SecFile instance tracks a specific file, and regards it as being
    "the same" object despite differences to the underlying file on the disk
    file system (e.g., being encrypted).

    **Example**

    A SecFile object is created to track a file (here the file is named
    "The Larch.txt", which happens to have a space in it). Typically the file
    name is given at initialization, but it can be given later as well::

        >>> sf = SecFile('The Larch.txt')
        >>> sf.file
        '/Users/.../data/The Larch.txt'

    The file can be now encrypted using a public key (stored in the file named
    ``pub.pem``)::

        >>> sf.encrypt('pub.pem')
        >>> sf.file
        '/Users/.../data/The Larch.enc'

    The SecFile instance remains the same, but the underlying file has been
    renamed with extension ``.enc``. The original file has securely deleted.

    SecFile objects have various properties that can be queried (continuing on
    from the above example)::

        >>> sf.is_encrypted
        True
        >>> sf.basename
        'The Larch.enc'
        >>> sf.snippet
        '(encrypted)'

    Decryption is done in a similar way, using a private key (here, as read
    from a file named ``priv.pem``)::

        >>> sf.decrypt('priv.pem', 'pphr.txt')
        >>> sf.basename
        'The Larch.txt'

    Note that the original file's basename is restored; the full path is not.

    """
    def __init__(self, infile=None, pub=None, priv=None, pphr=None,
                 codec=None, openssl=None):
        """:Parameters:
            ``infile`` : the target file to work on
            ``pub`` : public key, .pem format
            ``priv`` : private key, .pem format
            ``pphr`` : passphrase, as a file name or the passphrase itself
            ``codec`` : the pyFileSec codec to use
            ``openssl`` : path to the version of OpenSSL to use
        """
        '''dev notes: ---------
            self.file can be set explicitly or implicitly by user
                explicitly = at init, or through set_file; no other way.
                implicitly = change name due to a change of state
                    such as destroy --> None; encrypt --> .enc
                good: sf = SecFile(filename).encrypt(pub)
                      sf = SecFile().set_file(filename).decrypt(priv, pphr)
                       r = SecFile(filename).destroy().result
            methods that return self must also populate a self.result dict:
                self.result must never contain anything sensitive:
                    pphr, file size unpadded
                method : name (encrypt, decrypt, rotate, ...)
                status: started, good, bad
                * seconds, orig_links, disposition, old_file, [inum]
                * meta : actual metadata dict (enc, dec, rot)
                * sig : actual sig
                * sig_out : name of file containing sig
                * verified : bool
                ...
                query .results right after a call; not guaranteed long-term
            properties cannot rely on self.result values, can be stale
            require_X methods must only use the default / already set file

            methods build up self.results. if a method needs to use self.method
            just use another SecFile() obj.method instead, preserves .result

            methods that create files must ensure a _uniq_name() is used. this
            also means that the actual file name created might not be the name
            passed to the method. for this reason the result['filename'] should
            either be checked after a method call (eg in .rename), or should be
            ensured to be unique before the call.

            the parameter `openssl` should probably be `engine` or `backend`, in order
            to support gpg or pycrypto usage. then .encrypt(pub) will call the
            corresponding lib
        '''

        # sets self.rsakeys:
        super(SecFile, self).__init__(pub=pub, priv=priv, pphr=pphr)
        self.set_file(infile)
        if not codec:
            codec = codec_registry  # default codec
        self.codec = copy.deepcopy(codec)
        self._openssl = openssl

    def __str__(self):
        txt = '<pyfilesec.SecFile object, file=%s, enc=%s>'
        return  txt % (repr(self.file), self.is_encrypted)

    def __repr__(self):
        return str(self)

    def pad(self, size=DEFAULT_PAD_SIZE):
        """Append null bytes to ``filename`` until it has length ``size``.

        The size is changed but `the fact that it was changed` is only obscured
        if the padded file is encrypted. ``pad`` only changes the effective
        length, and the padding is easy to see (unless the padding is
        encrypted).

        Files shorter than `size` will be padded out to `size` (see details
        below). The minimum resulting file size is 128 bytes. Files that are
        already padded will first have any padding removed, and then be padded
        out to the new target size.

        Padded files include a few bytes for padding-descriptor tags, not just
        null bytes. Thus files that are close to ``size`` already would not
        have their sizes obscured AND also be marked as being padded (in the
        last ~36 bytes), raising a ``PaddingError``. To avoid this, you can
        check using the convenience function ``_ok_to_pad()`` before calling
        ``pad()``.

        Internal padding format:

            ``file + n bytes + padding descriptors + final byte``

        The padding descriptors consist of ``10-digits + one byte + PFS_PAD``,
        where ``byte`` is b'\0' (the null byte). The process does not depend on
        the value of the byte. The 10 digits gives the length of the padding as
        an integer, in bytes. ``n`` is selected to make the new file size equal
        the requested ``size``.

        To make unpadding easier and more robust (and enable human inspection),
        the end bytes provide the number of padding bytes that were added, plus
        an identifier. 10 digits is not hard-coded as 10, but as the length of
        ``str(max_file_size)``, where the ``max_file_size`` constant is 8G by
        default. This means that any changes to the max file size constant can
        thus cause pad / unpad failures across versions.

        Special ``size`` values:

           0 : unpad = remove any existing padding, no error if not present

           -1 : strict unpad = remove padding if present, error if not present
        """
        name = 'pad'
        self.result = {'method': name, 'status': 'started'}

        filename = self._require_file()
        logging.debug(name + 'start')
        size = int(size)
        if 0 < size < PAD_MIN:
            logging.info(name +
                         ': requested size increased to %i bytes' % PAD_MIN)
            size = PAD_MIN
        if size > MAX_FILE_SIZE:
            fatal(name +
                  ': size must be <= %d (maximum file size)' % MAX_FILE_SIZE)
        # handle special size values (0, -1) => unpad
        pad_count = self._pad_len()
        if size < 1:
            if pad_count or size == -1:
                self.unpad()  # or fail appropriately
            return self

        if pad_count:
            SecFile(self.file).pad(0)
        needed = self._ok_to_pad(size)
        if needed == 0:
            msg = ': file length not obscured (length >= requested size)'
            fatal(name + msg, PaddingError)
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

        self.result.update({'size': self.size, 'status': 'good'})
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
        filename = self._require_file(check_size=False)
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
                enc_method='_encrypt_rsa_aes256cbc', hmac_key=None, note=None):
        """Encrypt a file using a public key.

        By default, the original plaintext is secure-deleted after encryption
        (default ``keep=False``). This is time-consuming, but important.

        The idea is that you can have and share a public key, which anyone can
        use to encrypt things that only you can decrypt. Generating good keys
        and managing them is non-trivial (see ``genrsa()`` and documentation).


        Files larger than 8G before encryption will raise an error.

        To mask small file sizes, ``pad()`` them to a desired minimum
        size before calling ``encrypt()``.

        :Parameters:

            ``pub``:
                The public key to use, specified as the path to a ``.pem``
                file. The minimum recommended key length is 2048 bits; 1024
                is allowed but strongly discouraged.
            ``meta``:
                If ``True`` or a dict, include the meta-data (plaintext) in the
                archive. If given a dict, the dict will be updated with new
                meta-data. This allows all meta-data to be retained from the
                initial encryption through multiple rotations of encryption.
                If ``False``, will indicate that the meta-data were suppressed.

                See ``load_metadata()`` and ``log_metadata()``.
            ``date``:
                ``True`` : save the date in the clear-text meta-data.
                ``False`` : suppress date from being saved in the meta-data.

                .. note:: File time-stamps on the underlying file-system are
                    NOT obscured, even if ``date=False``.

            ``keep``:
                ``False`` = remove original (unencrypted) file
                ``True``  = leave original file
            ``enc_method``:
                name of the function / method to use (currently only one
                option, the default)
            ``hmac_key``:
                optional key to use for a message authentication (HMAC-SHA256,
                post-encryption); if a key is provided, the HMAC will be
                generated and stored with the meta-data. (This is
                encrypt-then-MAC.) For stronger integrity assurance, use
                ``sign()``.
            ``note`` :
                allows a short, single-line string to be included in the
                meta-data. trimmed to ensure that its < 120 characters (mainly
                so that the text of a private key cannot become embedded
                in the meta-data, which are not encrypted).
        """
        set_umask()
        name = 'encrypt'
        self.result = {'method': name, 'status': 'started'}
        self._require_file(self.is_in_writeable_dir)  # enc file ok, warn
        self.rsakeys.update(pub=pub, req=NEED_PUBK)
        logging.debug(name + 'start')
        if self.is_encrypted:
            logging.warning(name + ": file is already encrypted")
        if not self.codec.is_registered(enc_method):
            fatal(name + ": requested '%s' not registered" % enc_method)
        if not type(meta) in [bool, dict]:
            fatal(name + ': meta must be True, False, or dict', AttributeError)
        if not keep in [True, False]:
            fatal(name + ": bad value for 'keep' parameter")
        # Do the encryption, using a registered `encMethod`:
        ENCRYPT_FXN = self.codec.get_function(enc_method)
        set_umask()  # redundant
        data_enc, pwd_rsa = ENCRYPT_FXN(self.file, self.rsakeys.pub,
                                        openssl=self.openssl)
        ok_encrypt = (isfile(data_enc) and
                        os.stat(data_enc)[stat.ST_SIZE] and
                        isfile(pwd_rsa) and
                        os.stat(pwd_rsa)[stat.ST_SIZE] >= PAD_MIN)
        logging.info(name + ': ok_encrypt %s' % ok_encrypt)

        # Get and save meta-data:
        if not meta:  # False or {}
            meta = NO_META_DATA
        else:
            if isinstance_basestring23(note):
                if len(note) > METADATA_NOTE_MAX_LEN:
                    logging.warning('trimming note to %d chars' %
                                     METADATA_NOTE_MAX_LEN)
                    n = METADATA_NOTE_MAX_LEN // 2 - 3
                    note = note[:n] + ' ... ' + note[-n:]
                note = note.replace('\n', ' ')
            if meta is True:
                meta = {}
            md = self._make_metadata(self.file, data_enc, self.rsakeys.pub,
                                     enc_method, date, hmac_key, note)
            meta.update(md)
        metafile = os.path.split(self.file)[1] + META_EXT
        with open(metafile, write_mode) as fd:
            json.dump(meta, fd)

        # Bundle the files: (cipher text, rsa pwd, meta-data) --> data.enc
        new_name = os.path.splitext(self.file)[0] + ENC_EXT
        arch_files = [data_enc, pwd_rsa, metafile]
        arch_enc = SecFileArchive(new_name, arch_files, keep=False)

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
                self.set_file(arch_enc.name)
                logging.info(name +
                    ': post-encrypt destroyed orig. file complete')
            else:
                logging.error(name +
                    ': retaining original file, encryption did not succeed')

        unset_umask()
        self.set_file(arch_enc.name)  # likely off in some situations
        self.result.update({'status': 'good', 'cipher_text': self.file,
                            'meta': meta})
        return self

    def _make_metadata(self, datafile, data_enc, pub, enc_method,
                       date=True, hmac=None, note=None):
        """Return info about an encryption context, as {date-now: {info}} dict.

        If ``date`` is True, date-now is the local time in numerical form.
        If ``date`` is False, date info is suppressed. The date values
        are also keys to the meta-data dict, and their format is chosen so that
        they will sort to be in chronological order, even if the original
        encryption date was suppressed (it comes first).
        """

        md = {'clear_text': abspath(datafile),
            'hash of cipher_text': '%s' % sha256_(data_enc)}
        if hmac:
            hmac_val = hmac_sha256(hmac, data_enc)
            md.update({'hmac (enc-then-mac)': hmac_val})
        md.update({'hash of public key': sha256_(pub),
            'encryption method': lib_name + '.' + enc_method,
            'hash of %s' % lib_name: sha256_(lib_path),
            'rsa padding': RSA_PADDING})
        if date:
            time_now = time.strftime("%Y_%m_%d_%H:%M", time.localtime())
            m = int(get_time() / 60)
            s = (get_time() - m * 60)
            time_now += ('.%6.3f' % s).replace(' ', '0')  # zeros for sorting
                # only want ms precision for testing, which can easily
                # generate two files within ms of each other
        else:
            time_now = DATE_UNKNOWN
        md.update({'encrypted at localtime Y_M_D_H:m.s.ms': time_now,
            'openssl': openssl_version,
            'platform': sys.platform,
            'python': '%d.%d.%d' % sys.version_info[:3]})
        if isinstance_basestring23(note):
            md.update({'note': note[:METADATA_NOTE_MAX_LEN]})

        return {'meta-data %s' % time_now: md}

    def decrypt(self, priv=None, pphr=None, keep_meta=False, keep_enc=False,
                dec_method=None):
        """Decrypt a file that was encoded using ``encrypt()``.

        To get the data back, need two files: ``data.enc`` and ``privkey.pem``.
        If the private key has a passphrase, you'll need to provide that too.
        `pphr` can be the passphrase itself (a string), or a file name. These
        must match the public key used for encryption.

        Works on a copy of ``data.enc``, tries to decrypt it.
        The original ``data.enc`` is removed (unless ``keep_enc=True``).

        Tries to detect whether the decrypted file would end up inside a
        Dropbox folder; if so, refuse to proceed.

        :Parameters:

            `priv` :
                path to the private key that is paired with the ``pub`` key
                used at encryption; in ``.pem`` format
            `pphr` :
                passphrase for the private key (as a string, or filename)
            `keep_meta` :
                if False, unlink the meta file after decrypt
            `keep_enc` :
                if False, unlink the encrypted file after decryption
            `dec_method` : (not implemented yet, only one choice).
                name of a decryption method that has been registered in
                the current ``codec`` (see ``PFSCodecRegistry``).
                ``None`` will try to use information in the file's meta-data,
                and will fall through to the default method.
        """
        set_umask()
        name = 'decrypt'
        self.result = {'method': name, 'status': 'started'}
        logging.debug(name + 'start')
        arch_enc = self._require_enc_file(self.is_not_in_dropbox &
                                          self.is_in_writeable_dir,
                                          check_size=False)
        self.rsakeys.update(priv=priv, pphr=pphr, req=NEED_PRIV)
        if self.is_tracked:
            logging.warning(name + ': file exposed to version control')

        # Extract files from the archive (self.file) and decrypt:
        try:
            # Unpack from archive into same dir as .enc:
            dest_dir = os.path.split(arch_enc.name)[0]
            logging.info(name + ': decrypting into %s' % dest_dir)

            data_aes, pwd_file, meta_file = arch_enc.unpack()
            tmp_dir = os.path.split(data_aes)[0]

            # Get a valid decrypt method, from meta-data or argument:
            clear_text = None  # file name; set in case something raise()es
            if not dec_method:
                dec_method = arch_enc.get_dec_method(self.codec)

            # Decrypt (into same new tmp dir):
            DECRYPT_FXN = self.codec.get_function(dec_method)
            set_umask()  # redundant
            data_dec = DECRYPT_FXN(data_aes, pwd_file, self.rsakeys.priv,
                                   self.rsakeys.pphr, openssl=self.openssl)

            # Rename decrypted and meta files:
            _new_path = os.path.join(dest_dir, os.path.basename(data_dec))
            result = secure_rename(data_dec, _new_path)  # (src, dest)
            clear_text = result['new_name']

            perm_str = permissions_str(clear_text)
            logging.info('decrypted, permissions ' +
                         perm_str + ': ' + clear_text)
            if meta_file and keep_meta:
                result = secure_rename(meta_file, clear_text + META_EXT)
                new_meta = result['new_name']
                perm_str = permissions_str(new_meta)
                logging.info('meta-data, permissions ' +
                             perm_str + ': ' + new_meta)
        finally:
            # clean-up; no protected clear-text inside (maybe meta-data)
            shutil.rmtree(tmp_dir, ignore_errors=True)

        unset_umask()
        if not keep_enc:
            os.unlink(arch_enc.name)
        self.set_file(clear_text)  # set file
        self.result = {'method': name, 'status': 'started'}
        self.result.update({'clear_text': clear_text, 'status': 'good'})
        if meta_file and keep_meta:
            self.result.update({'meta': new_meta})
            self.meta = new_meta

        return self

    def rotate(self, pub=None, priv=None, pphr=None, hmac_key=None, pad=None):
        """Swap old encryption for new: decrypt-then-re-encrypt.

        Conceptually there are three separate steps: decrypt with ``priv``
        (this is the "old" private key), re-encrypt (with the "new" public
        key), confirm that the rotation worked, and destroy the old (insecure)
        file. ``rotate()`` will only do the first two of these.

        If ``pad`` is given, the padding will be updated to the new length
        prior to re-encryption.

        New meta-data are added alongside the original meta-data.
        ``rotate()`` will preserve meta-data across encryption sessions, if
        available, adding to it rather than saving just the last one.
        (``keep_meta=False`` will suppress all meta_data; typically rotation
        events are not sensitive.) Handling the meta-data is the principle
        motivation for having a rotate method; otherwise
        ``sf.decrypt(old).encrypt(new)`` would suffice.

        :Parameters:

            `priv` :
                path to the old private key that is paired with the ``pub``
                key that was used for the existing encryption
            `pphr` :
                passphrase for the private key (as a string, or filename)
            `pub` :
                path to the new public key to be used for the new encryption.
            `hmac_key` :
                key (string) to use for an HMAC to be saved in the meta-data
        """
        set_umask()
        name = 'rotate'
        logging.debug(name + ': start (decrypt old, [pad new,] encrypt new)')
        self.result = {'method': name, 'status': 'started'}
        self._require_enc_file(self.is_not_in_dropbox &
                               self.is_in_writeable_dir)
        dec_rsakeys = RsaKeys(priv=(priv or self.rsakeys.priv),
                              pphr=(pphr or self.rsakeys.pphr))
        dec_rsakeys.require(NEED_PRIV)
        enc_rsakeys = RsaKeys(pub=(pub or self.rsakeys.pub))
        enc_rsakeys.require(NEED_PUBK)

        file_dec = None
        try:
            # encrypt() will destroy intermediate clear_text, but might be
            # an exception before getting to encrypt(), so wrap in try except

            sf = SecFile(self.file).decrypt(dec_rsakeys.priv, keep_meta=True,
                                            pphr=dec_rsakeys.pphr)
            self.meta = sf.meta
            self.set_file(sf.file)  # decrypted file name

            logging.debug('rotate self.meta = %s' % self.meta)
            md = self.load_metadata()  # get NO_META_DATA if missing
            pad = max(0, pad)  # disallow -1, don't want errors mid-rotate
            if pad == 0 or self._ok_to_pad(pad):
                SecFile(self.file).pad(pad)
            file_dec = self.file  # track file names so can destroy if needed

            sf = SecFile(self.file).encrypt(pub=enc_rsakeys.pub, date=True,
                     meta=md, keep=False, hmac_key=hmac_key)
            self.set_file(sf.file)  # newly encrypted file name
        finally:
            # generally rotate must not leave any decrypted stuff. exception:
            #   decrypt, destroy orig.enc, *then* get exception --> now what?
            # unlikely situation: require_keys(pub) before starting, if dec
            #   works then directory write permissions are ok
            file_dec and isfile(file_dec) and SecFile(file_dec).destroy()

        unset_umask()
        self.result.update({'file': self.file,
                       'status': 'good',
                       'old': os.path.split(priv)[1],
                       'new': os.path.split(pub)[1]})
        return self

    def sign(self, priv=None, pphr=None, out=None):
        """Sign a given file with a private key.

        Get a digest of the file, sign the digest, return base64-encoded
        signature (or save it in file ``out``).
        """
        name = 'sign'
        logging.debug(name + ': start')
        self._require_file(check_size=False)
        self.rsakeys.update(priv=priv, pphr=pphr, req=NEED_PRIV)
        sig_out = self.file + '.sig'

        cmd_SIGN = [self.openssl, 'dgst', '-sign',
                        self.rsakeys.priv, '-out', sig_out]
        if self.rsakeys.pphr:
            cmd_SIGN += ['-passin', 'stdin']
        cmd_SIGN += ['-keyform', 'PEM', self.file]
        if self.rsakeys.pphr:
            sys_call(cmd_SIGN, stdin=self.rsakeys.pphr)
        else:
            sys_call(cmd_SIGN)
        sig = open(sig_out, 'rb').read()

        self.result = {'sig': b64encode(sig),
                       'file': self.file}
        if out:
            out = _uniq_file(out)
            with open(out, write_mode) as fd:
                fd.write(self.result['sig'])
            self.result.update({'out': out})
        return self

    def verify(self, pub=None, sig=None):
        """Verify signature of ``filename`` using pubkey ``pub``.

        ``sig`` should be a base64-encoded signature, or a path to a sig file.
        """
        name = 'verify'
        logging.debug(name + ': start')
        self._require_file(check_size=False)
        self.rsakeys.update(pub=pub, req=NEED_PUBK)
        if not sig:
            fatal('signature required for verify(), as string or filename',
                  AttributeError)

        cmd_VERIFY = [self.openssl, 'dgst', '-verify',
                        self.rsakeys.pub, '-keyform', 'PEM']
        if isfile(sig):
            sig = open(sig, 'rb').read()
        with NamedTemporaryFile(delete=False) as sig_file:
            sig_file.write(b64decode(sig))
        cmd_VERIFY += ['-signature', sig_file.name, self.file]
        result = sys_call(cmd_VERIFY)
        os.unlink(sig_file.name)  # b/c delete=False
        verified = result in ['Verification OK', 'Verified OK']

        self.result = {'verified': verified, 'file': self.file}
        return self.result['verified']

    def destroy(self):
        """Try to secure-delete a file.

        Calls an OS-specific secure-delete utility, defaulting to::

            Mac:     srm -f -z --medium  filename
            Linux:   shred -f -u -n 7 filename
            Windows: sdelete.exe -q -p 7 filename

        To secure-delete a file, use this syntax:

            SecFile('a.enc').destroy().result

        Ideally avoid the need to destroy files as much as possible. Keep
        sensitive data in RAM. File systems that are journaled, have RAID, are
        mirrored, or other back-up are much trickier to secure-delete.

        ``destroy()`` may fail to remove all traces of a file if multiple
        hard-links exist for the file. For this reason, the original link count
        is returned. In the case of multiple hardlinks, Linux (shred) and
        Windows (sdelete) do appear to destroy the data (the inode), whereas
        Mac (srm) does not.

        If ``destroy()`` succeeds, the SecFile object is ``reset()``. The
        ``.result`` attribute contains the details. If ``destroy()`` fails,
        ``.result`` is not reset.
        """

        name = 'destroy'
        logging.debug(name + ': start')
        self.result = None
        target_file = self._require_file(check_size=False)

        if self.is_in_dropbox:
            logging.error(name + ": in dropbox; can't secure delete remotely")
        if self.is_tracked:
            logging.warning(name + ': file exposed to version control')
        destroy_t0 = get_time()

        # Try to detect & inform about hardlinks:
        orig_links = self.hardlinks
        if orig_links > 1:  # -1 is user can't link
            inum = os.stat(target_file)[stat.ST_INO]
            mount_path = '(unknown)'
            if sys.platform != 'win32':
                mount_path = abspath(target_file)
                while not os.path.ismount(mount_path):
                    mount_path = os.path.dirname(mount_path)
                msg = name + """: '%s' (inode %d) has other hardlinks:
                    `find %s -xdev -inum %d`""".replace('    ', '')
                vals = (target_file, inum, mount_path, inum)
                logging.warning(msg % vals)

        cmd_Destroy = (DESTROY_EXE,) + DESTROY_OPTS + (target_file,)
        good_sys_call = False
        __, err = sys_call(cmd_Destroy, stderr=True)
        good_sys_call = not err
        # mac srm will warn about multiple links via stderr -> disp unknown

        disposition = pfs_UNKNOWN
        if not isfile(target_file):
            if good_sys_call:
                disposition = pfs_DESTROYED
        else:
            # last-ditch effort
            logging.error(name + ': falling through to trying 1 pass of zeros')
            with open(target_file, write_mode) as fd:
                fd.write(chr(0) * getsize(target_file))
            shutil.rmtree(target_file)

        duration = round(get_time() - destroy_t0, 4)
        self.reset()  # clear everything, including self.result
        disp_exp = destroy_code[disposition]
        if err:
            disp_exp += '; ' + err
        vals = [disp_exp, orig_links, duration, target_file]
        keys = ['disposition', 'orig_links', 'seconds', 'target_file']
        if user_can_link:
            if orig_links > 1 or disposition == pfs_UNKNOWN:
                disp_exp += ', other hardlinks exist (see inum)'
                vals.extend([inum, mount_path])
                keys.extend(['inum', 'mount_path'])
        self.result = dict(list(zip(keys, vals)))

        return self

    def rename(self, new_name):
        """Change the name of the file on the file system.
        """
        self._require_file(check_size=False)
        result = secure_rename(self.file, new_name)
        if result['status'] == 'good':
            self.set_file(result['new_name'])  # can be changed to ensure uniq


class SecFileArchive(_SecFileBase):
    """Class for working with a cipher_text archive file (= \*.enc).

    Used transparently by SecFile as needed; typically there's no need to work
    directly with a SecFileArchive.

    - Provide a name to create an empty archive, or infer a name from paths in
        ``files``, or from archive ``arc`` name.

    - Providing files will also ``pack()`` them into the archive.

    - Providing an existing archive ``arc`` will also unpack it into a tmp
        directory and return full paths to the file names. (This can result in
        stray tmp files if they are not removed by the user, but everything
        sensitive is encrypted.)
    """
    def __init__(self, name='', files=None, arc=None, keep=True):
        """
        """
        super(SecFileArchive, self).__init__()

        # init must not create any temp files if paths=None
        if files and isinstance_basestring23(files):
            files = tuple(files)
        if name:
            # given a name, regardless of its file status
            self.name = name
        elif files:
            # no name, infer a name from paths, prefer .meta file as a base
            for p in files:
                path, ext = os.path.splitext(p)
                if not ext in [AES_EXT, RSA_EXT]:
                    self.name = path + ENC_EXT
                    break
            else:
                path, ext = os.path.splitext(files[0])
                self.name = path + ENC_EXT
        elif arc:
            self.name = arc
        else:
            self.name = _uniq_file('secFileArchive' + ENC_EXT)
        if not name.endswith(ENC_EXT):
            self.name = os.path.splitext(self.name)[0] + ENC_EXT
        logging.debug('SecFileArchive.__init__ %s' % self.name)
        if files:
            self.pack(files, keep=keep)
        elif arc:
            self.unpack()

    def pack(self, files, keep=True):
        """Make a tgz file from a list of paths, set permissions.

        Eventually might take an arg to decide whether to use tar or zip.
        Just a tarfile wrapper with extension, permissions, unlink options.
        unlink is whether to unlink the original files after making a
        cipher_text archive, not a secure-delete option.
        """

        if isinstance_basestring23(files):
            files = [files]
        if not all([exists(f) for f in files]):
            fatal('missing file; cannot add to archive', AttributeError)
        self.name = _uniq_file(self.name)
        self._make_tar(files, keep)

        return self.name

    def _make_tar(self, files, keep):
        """Require files not directories; store as name file (not path/file)
        """
        set_umask()
        tar_fd = tarfile.open(self.name, "w:gz")
        for fullp, fname in [(f, os.path.split(f)[1]) for f in files]:
            tar_fd.add(fullp, fname, recursive=False)  # True = whole directory
            if not keep:
                os.unlink(fullp)
        tar_fd.close()
        unset_umask()

    def _check(self):
        data_enc = self.name
        # Check for bad paths:
        if not data_enc or not isfile(data_enc):
            fatal("could not find '%s'" % str(data_enc), AttributeError)
        if not tarfile.is_tarfile(data_enc):
            fatal('%s not expected format (.tgz)' % data_enc,
                   SecFileArchiveFormatError)

        # Check for bad internal paths:
        #    can't "with open(tarfile...) as tar" in python 2.6.6
        tar = tarfile.open(data_enc, "r:gz")
        badNames = [f for f in tar.getmembers()
                    if f.name[0] in ['.', os.sep] or f.name[1:3] == ':\\']
        tar.close()
        if badNames:
            fatal('bad/dubious internal file names', SecFileArchiveFormatError)
        return True

    def unpack(self):
        """Extract files from cipher_text archive, return paths to files.

        Files are unpacked into a tmp directory; the process calling ``pack()``
        should take care to clean up those files appropriately. There is no
        sensitive information revealed by unpacking files.

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
                logging.error(name + ': unexpected file %s in archive' % fname)
                # seems better to allow unpack to proceed anyway, eg, to rotate
        if not all([self.data_aes, self.pwd_rsa, self.meta]):
            logging.error('did not find 3 files in archive %s' % self.name)
        unset_umask()

        return self.data_aes, self.pwd_rsa, self.meta

    def get_dec_method(self, codec):
        """Return a valid decryption method from meta-data or default.

        Cross-validate requested dec_method against meta-data.
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

            dec_method = str(_dec_from_enc)  # avoid unicode issue
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
            fatal("get_dec_method: dec fxn '%s' not registered" % dec_method,
                   CodecRegistryError)
        logging.info('get_dec_method: dec fxn set to: ' + str(dec_method))

        return dec_method


class RsaKeys(object):
    """Class to manage and test RSA key-pairs.
    """
    def __init__(self, pub=None, priv=None, pphr=None):
        self.update(pub=pub, priv=priv, pphr=pphr)

    def test(self):
        """Tests whether the key pair is suitable for use with pyFileSec.

        Keys should be tested in matched pairs. Includes an actual test of
        encrypt-then-decrypt using the keys with the default codec.
        """
        self.require(req=NEED_PUBK | NEED_PRIV)
        pubk, pub_bits = self.sniff(self.pub)

        # compare pub against pub as extracted from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', self.priv, '-pubout']
        if self.pphr:
            cmdEXTpub += ['-passin', 'stdin']
        test_pub = sys_call(cmdEXTpub, stdin=self.pphr)
        # user might have comment or extra stuff in self.pub, so use 'in'
        if test_pub not in open(self.pub, read_mode).read():
            fatal('public key not paired with private key', PublicKeyError)

        # .update() will detect and fail before we get here, so use assert:
        #if pub_bits < RSA_MODULUS_MIN:
        #    fatal('public key too short; no real security below 1024 bits',
        #          PublicKeyTooShortError)
        assert pub_bits >= RSA_MODULUS_MIN
        if pub_bits < RSA_MODULUS_WRN:
            logging.warning('short RSA key')

        # can the new keys be used to enc-dec in the codec?
        test_codec = PFSCodecRegistry(default_codec,
                        test_keys=(  # keys kwargs will trigger the auto-test
                            {'pub': self.pub},
                            {'priv': self.priv, 'pphr': self.pphr})
                        )
        return self

    def sniff(self, key):
        """Inspects the file ``key``, returns information.

        Example return values:

            ``('pub', 2048)`` = public key with length (RSA modulus) 2048 bits

            ``('priv', True)`` = encrypted private key (will require a
                passphrase to use)

            ``(None, None)`` = not a detectable key format
        """
        if not isinstance_basestring23(key):
            return None, None
        if not isfile(key):
            return '(no file)', None

        keytype = enc = None
        with open(key, read_mode) as fd:
            for line in iter(partial(fd.readline), b''):
                if '-----BEGIN' in line and 'PUBLIC KEY-----' in line:
                    keytype = 'pub'
                    modulus = get_key_length(key)
                    return keytype, modulus
                if '-----BEGIN' in line and 'PRIVATE KEY-----' in line:
                    keytype = 'priv'
                #if len(line) >= 64:
                #    enc = False
                #    return keytype, enc  # hit end of header info
                if 'ENCRYPTED' in line and keytype == 'priv':
                    return keytype, True
        return keytype, enc

    def require(self, req):
        """Raise error if key requirement(s) ``req`` are not met; assert-like.

        Used by SecFile methods: ``rsakeys.require(req=NEED_PUBK | NEED_PRIV)``
        reads as ``assert rsakeys.pub and rsakeys.priv`` or raise a tailored
        error, including a missing passphrase if the private key is encrypted.
        """
        if req & NEED_PUBK:
            if not self.pub:
                fatal('public key required, missing', PublicKeyError)
        if req & NEED_PRIV:
            if not self.priv:
                fatal('private key required, missing', PrivateKeyError)
        if req & NEED_PPHR:
            if not self.pphr:
                fatal('passphrase required, missing', PassphraseError)
        return self

    def update(self, pub=None, priv=None, pphr=None, req=0):
        """Accept new value, use existing val if no new one, or fail.
        """
        self._update_pub(pub)
        self._update_priv(priv)
        self._update_pphr(pphr)
        if self.priv_requires_pphr:
            req |= NEED_PPHR
        req and self.require(req)

    def _update_pub(self, pub=None):
        """Get pub from self or from param, set as needed
        """
        if isinstance_basestring23(pub):
            if exists(pub) and 'PUBLIC KEY' in open(pub, read_mode).read():
                self._pub = _abspath(pub)
            else:
                fatal('bad public key %s' % pub, PublicKeyError)
            try:
                key_len = get_key_length(self.pub)
            except ValueError:
                fatal('bad public key %s' % pub, PublicKeyError)
            if key_len < RSA_MODULUS_MIN:
                fatal('short public key %s' % pub, PublicKeyTooShortError)
            if key_len < RSA_MODULUS_WRN:
                logging.warning('short public key %s' % pub)
        elif pub is not None:
            fatal('bad public key; expected a string or None', PublicKeyError)

    def _update_priv(self, priv=None):
        """Get priv from self or from param, set as needed.

        Return bool to indicate whether priv in encrypted (= require pphr)
        """
        self.priv_requires_pphr = False
        if isinstance_basestring23(priv):
            if exists(priv):  # is_file
                contents = open(priv, read_mode).read()  # better to sniff...
                if 'PRIVATE KEY' in contents:
                    self._priv = _abspath(priv)
                else:
                    fatal('bad private key', PrivateKeyError)
                if 'ENCRYPTED' in contents:
                    self.priv_requires_pphr = True
            else:
                fatal('bad private key (no file %s)' % priv, PrivateKeyError)

    def _update_pphr(self, pphr=None):
        """Get pphr from self, param, set as needed

        Load from file if give a file
        """
        # don't screen for weak passphrase here, its too late
        if isinstance_basestring23(pphr):
            if exists(pphr):
                self._pphr = open(pphr, 'rb').read()
            else:
                self._pphr = pphr
        elif pphr is not None:
            fatal('bad passphrase; expected string or None', PrivateKeyError)

    @property
    def pub(self):
        if hasattr(self, '_pub'):
            return self._pub
        else:
            return None

    @property
    def priv(self):
        if hasattr(self, '_priv'):
            return self._priv
        else:
            return None

    @property
    def pphr(self):
        if hasattr(self, '_pphr'):
            return self._pphr
        else:
            return None


class GenRSA(object):
    """A class to generate RSA key-pairs
    """
    def __init__(self):
        pass

    def demo_rsa_keys(self, folder=''):
        pub = os.path.join(folder, 'pubkey_demo_only')
        pubkey = """   !!! DEMO public key do not use; for testing only!!!

            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9wLTHLDHvr+g8WAZT77al/dNm
            uFqFFNcgKGs1JDyN8gkqD6TR+ARa1Q4hJSaW8RUdif6eufrGR3DEhJMlXKh10QXQ
            z8EUJHtxIrAgRQSUZz73ebeY4kV21jFyEEAyZnpAsXZMssC5BBtctaUYL9GR3bFN
            yN8lJmBnyTkWmZ+OIwIDAQAB
            -----END PUBLIC KEY-----
            """.replace('    ', '')
        if not isfile(pub):
            with open(pub, write_mode) as fd:
                fd.write(pubkey)

        priv = os.path.join(folder, 'privkey_demo_only')
        privkey = """   !!! DEMO private key do not use; for testing only!!!

            -----BEGIN RSA PRIVATE KEY-----
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
            with open(priv, write_mode) as fd:
                fd.write(privkey)

        pphr = os.path.join(folder, 'pphr_demo_only')
        pp = "337876469593251699797157678785713755296571899138117259"
        if not isfile(pphr):
            with open(pphr, write_mode) as fd:
                fd.write(pp)
        return _abspath(pub), _abspath(priv), _abspath(pphr)

    def check_entropy(self):
        """Basic query for some indication that entropy is available.
        """
        e = '(unknown)'
        if sys.platform == 'darwin':
            # SecurityServer daemon is supposed to ensure entropy is available:
            ps = sys_call(['ps', '-e'])
            securityd = sys_call(['which', 'securityd'])  # full path
            e = 'securityd NOT running  (= bad)'
            if securityd in ps:
                e = securityd + ' running   (= good)'
            rdrand = sys_call(['sysctl', 'hw.optional.rdrand'])
            e += '\n           rdrand: ' + rdrand
            if rdrand == 'hw.optional.rdrand: 1':
                e += ' (= good)'
        elif sys.platform.startswith('linux'):
            avail = sys_call(['cat', '/proc/sys/kernel/random/entropy_avail'])
            e = 'entropy_avail: ' + avail
        return e

    def generate(self, pub='pub.pem', priv='priv.pem', pphr=None, bits=4096):
        """Generate new RSA pub and priv keys, return paths to files.

        ``pphr`` should be a string containing the actual passphrase.
        """
        if bits < RSA_MODULUS_MIN:
            fatal('Too short a key length requested',
                  PublicKeyTooShortError)

        set_umask()
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-aes256', '-passout', 'stdin']
        sys_call(cmdGEN + [str(bits)], stdin=pphr)

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv, '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'stdin']
        sys_call(cmdEXTpub, stdin=pphr)

        unset_umask()
        try:
            RsaKeys(pub=pub, priv=priv, pphr=pphr).test()
        except:
            self._cleanup('', priv, pub)
            fatal('new keys failed to validate; removing them', RuntimeError)
        return _abspath(pub), _abspath(priv)

    def _cleanup(self, msg, pub='', priv='', pphr=None):
        print(msg)
        try:
            SecFile(priv).destroy()
        except:
            try:
                os.unlink(priv)
            except:
                pass
        if pphr:
            try:
                SecFile(pphr).destroy()
            except:
                try:
                    os.unlink(pphr)
                except:
                    pass
        try:
            os.unlink(pub)
        except:
            pass
        return None, None, None

    def dialog(self, interactive=True, args=None):
        """Command line dialog to generate an RSA key pair, PEM format.

        To launch from the command line::

            % python pyfilesec.py genrsa

        The following will do the same thing, but save the passphrase into a
        file named 'pphr' [or save onto the clipboard]::

            % python pyfilesec.py genrsa [--passfile | --clipboard]

        And it can be done from a python interpreter shell::

            >>> import pyfilesec as pfs
            >>> pfs.genrsa()

        The passphrase will not be printed if it was entered manually. If it
        is auto-generated, it will be displayed or saved to a file if option
        ``--passfile`` is given, or saved to the clipboard if option
        ``--clipboard`` is given. This is the only copy of the passphrase; the
        key-pair is useless without it. Actually, its far worse than useless.
        Its dangerous: you could still encrypt something that you could
        not decrypt.

        Choose from 2048, 4096, or 8192 bits. 1024 is not secure medium-term,
        and 16384 bits is not needed (nor is 8192). A passphrase is required,
        or one will be auto generated. Ideally, generate a strong passphrase
        in a password manager (e.g., KeePassX), save there, paste it into the
        dialog.

        You may want to generate keys for testing purposes, and then generate
        different keys for actual use.
        """

        PPHR_BITS_DEFAULT = 128
        PPHR_OUT_SIZE = PPHR_BITS_DEFAULT // 4 + 1  # +1 for printable_pwd '#'
        RSA_BITS_DEFAULT = 4096
        if not args:
            # add default args to locals; simplifies the code below
            sys.argv = [lib_path, 'genrsa']
            args = _parse_args()

        # ensure uniq matched sets (pub, priv, pphr):
        pub = _abspath(_uniq_file(args.pub or 'pub_RSA.pem'))
        priv = _abspath(args.priv or pub.replace('pub_RSA', 'priv_RSA'))
        if args.passfile:
            pphr_out = pub.replace('pub_RSA', 'pphr_RSA')  # matched
            pphr_out = os.path.splitext(pphr_out)[0] + '.txt'
        else:
            pphr_out = None
        if pub == priv:
            priv = os.path.splitext(priv)[0] + '_priv.pem'

        msg = '\n%s: RSA key-generation dialog\n' % lib_name
        print(msg)
        if (os.path.exists(priv) or
                args.passfile and os.path.exists(pphr_out)):
            return self._cleanup('  > output file(s)already exist <\n'
                  '  > Clean up files and try again. Exiting. <')

        print('Will try to create files:')
        pub_msg = '  pub  = %s' % pub
        print(pub_msg)
        priv_msg = '  priv = %s' % priv
        print(priv_msg)
        if args.passfile:
            pphrout_msg = '  pphr = %s' % pphr_out
            print(pphrout_msg)
        print('\nEnter a passphrase for the private key (16 or more chars)'
              '\n  or press <return> to auto-generate a passphrase')
        pphr_auto = True
        bits = RSA_BITS_DEFAULT
        if interactive:  # pragma: no cover
            import _getpass
            # python 3 compatibility:
            input23 = (input, raw_input)[sys.version < '3.']
            try:
                pphr = _getpass.getpass('Passphrase: ')
            except ValueError:
                pass  # hit return, == want auto-generate
            else:
                if 0 < len(pphr) < 16:
                    return self._cleanup('\n  > Passphrase too short. <')
                elif len(pphr) > 0:
                    pphr_auto = False
                    pphr2 = _getpass.getpass('same again: ')
                    if pphr != pphr2:
                        return self._cleanup('  > Passphrases do not match. <')
            b = input23('\nKey length (2048, 4096, 8192): [%d] ' %
                        RSA_BITS_DEFAULT)
            if b:
                bits = int(b)

        if pphr_auto:
            print('(auto-generating a passphrase)')
            pphr = printable_pwd(PPHR_BITS_DEFAULT)
        bits_msg = '  using %i' % bits
        bit = max(bits, RSA_MODULUS_WRN)
        print(bits_msg)
        ent_msg = '  entropy: ' + self.check_entropy()
        print(ent_msg)

        nap = 5  # 5 sec pause to give entropy a chance
        msg = '\nMove the mouse for %ds (to help generate entropy)' % nap
        print(msg)
        sys.stdout.flush()
        try:
            time.sleep(nap)
        except:  # eg KeyboardInterrupt
            return self._cleanup(' > cancelled, exiting <', pub, priv, pphr)

        msg = '\nGenerating RSA keys (using %s)\n' % openssl_version
        print(msg)
        try:
            self.generate(pub, priv, pphr, bits)
        except:  # eg KeyboardInterrupt
            return self._cleanup('\n  > exception in generate(), exiting <',
                          pub, priv, pphr)

        pub_msg = 'public key:  ' + pub
        print(pub_msg)
        priv_msg = 'private key: ' + priv
        print(priv_msg)
        pphr_msg = 'passphrase:  (entered by hand)'
        if pphr_auto:
            if args.passfile:
                pphr_msg = 'passphrase:  %s' % pphr_out
                set_umask()
                with open(pphr_out, write_mode) as fd:
                    fd.write(pphr)
                unset_umask()
                if (not isfile(pphr_out) or
                        not getsize(pphr_out) == PPHR_OUT_SIZE):
                    return self._cleanup(' > failed to save passphrase file <',
                                  pub, priv, pphr_out)
            elif args.clipboard:
                try:
                    import _pyperclip
                except (ImportError, RuntimeError):
                    fatal("can't import clipboard: no display?", RuntimeError)
                _pyperclip.copy(pphr)
                pphr_msg = ('passphrase:  saved to clipboard only... '
                            'paste it somewhere safe!!\n'
                            '      (It is exactly %d characters long, '
                            'no end-of-line char)' % PPHR_OUT_SIZE)
            else:
                pphr_msg = 'passphrase:  ' + pphr
                pphr_out = pphr
        print(pphr_msg)
        warn_msg = (' > Keep the private key private! <\n'
            '  > Do not lose the passphrase! <')
        print(warn_msg)

        del(pphr)
        if not interactive:
            return pub, priv, pphr_out

# not implemented; revisit after port to python3:
'''
class _SecStr(object):
    """Class to help mitigate accidental disclosure of sensitive strings.

    A SecStr "hardens" the string: normal string representations are disabled.
    Fewer copies will be left in memory, and there is less chance of the value
    swapping out to disk (and so being preserved indefinitely). A SecStr does
    not truly secure the string in a strong sense, most notably because it does
    not prevent copies being made. It is almost unavoidable to make copies when
    doing anything useful with the string.

    If ``pwd`` is a ``SecStr`` instance, use ``.str`` to get the string value;
    ``str(pwd)`` raises a ValueError.

    ``pwd.zero()`` will replace the value of the string with 0's in memory to
    the extent possible. Interned strings (= one character, or alphanumeric)
    cannot be zeroed, and will raise a ValueError at initialization.

    Example usage::

        >>> password = 'abc$dfg%#'
        >>> pwd = SecStr(password)
        >>> print pwd.str
        abc$dfg%#
        >>> pwd.zero()
        <<class 'pyfilesec.SecStr'> instance, zeroed=True>
        >>> password
        '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'

    :Parameters:
        ``str_obj`` :
            the string object; cannot have a value that python will intern.
    """
    class PyStringObject(Structure):
        _fields_ = [
            ('ob_refcnt', c_size_t),
            ('ob_type', py_object),
            ('ob_size', c_size_t),
            ('ob_shash', c_long),
            ('ob_sstate', c_int)
            # ob_sval varies in size
            ]

    def __init__(self, str_obj):
        self.s_obj = self.PyStringObject.from_address(id(str_obj))
        if str_obj and self.s_obj.ob_sstate > 0:
            raise ValueError("interned string (or non-string)")
        if not str_obj:
            str_obj = ''
        self._val = str_obj
        # del(str_obj.__str__)  # fails, its read-only
        self._zeroed = False
        self._id = id(str_obj)

    @property
    def str(self):
        return self._val

    @property
    def zeroed(self):
        return self._zeroed

    def __len__(self):
        return len(self._val)

    def __str__(self):
        raise RuntimeError('cannot get value via str(), use .str')

    def __repr__(self):
        return '<%s instance, zeroed=%s>' % (str(self.__class__), self.zeroed)

    def __del__(self):
        if hasattr(self, 'zero'):
            self.zero()

    def _memset0(self):
        # from http://stackoverflow.com/questions/15581881/
        #           ctypes-in-python-crashes-with-memset
        # and http://stackoverflow.com/questions/728164/
        #           securely-erasing-password-in-memory-python
        # beware getting "a false sense of
        # security.... there would still be other copies of the password that
        # have been created in various string operations."

        # __init__ should prevent this, but don't want to seg-fault
        if self.s_obj.ob_sstate > 0:
            raise ValueError("cannot zero an interned string")
        self.s_obj.ob_shash = -1  # not hashed yet

        offset = sizeof(self.PyStringObject) + (0, -4)[py64bit]
            # 20 for 32-bit python
            # sizeof() == 40 on py64bit; unclear why sizeof() is not 36

        tare = ''.__sizeof__()  # not unicode
        num_bytes = self._val.__sizeof__() - tare
        memset(id(self._val) + offset, 0, num_bytes)

    def zero(self):
        """Try to overwrite the whole string in memory with '\\\\x00's.

        Supports anonymous usage: ``SecStr(str_obj).zero()``.
        """
        try:
            self._memset0()
        except ValueError:
            self._zeroed = False
            tmp = b'\0' * len(self)
            self._id = id(tmp)
            del self._val
            self._val = tmp  # new / different id
        else:
            self._zeroed = True
            self._id = None

        if not self._val:
            self._zeroed = True
        return self
'''


def _abspath(filename):
    """Returns the absolute path, capitalize drive letter (win32)
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
        fatal(name + ': require path to openssl executable',
              RuntimeError)

    # set the name for decrypted file:
    data_dec = os.path.splitext(abspath(data_enc))[0]

    # Define command to retrieve password from pwdFileRsa
    cmdRSA = [openssl, 'rsautl', '-in', pwd_rsa, '-inkey', priv]
    if pphr:
        assert not isfile(pphr)  # passphrase must not be in a file
        cmdRSA += ['-passin', 'stdin']
    cmdRSA += [RSA_PADDING, '-decrypt']

    # Define command to decrypt the data using pwd:
    cmdAES = [openssl, 'enc', '-d', '-aes-256-cbc',
                '-a',
                '-in', data_enc,
                '-out', data_dec,
                '-pass', 'stdin']

    # decrypt pwd (digital envelope "session" key) to RAM using private key
    # then use pwd to decrypt the ciphertext file (data_enc):
    try:
        pwd, se_RSA = sys_call(cmdRSA, stdin=pphr, stderr=True)
        __, se_AES = sys_call(cmdAES, stdin=pwd, stderr=True)
    except:
        if isfile(data_dec) and isfile(data_enc):
            SecFile(data_dec).destroy()
        fatal('%s: Could not decrypt (exception in RSA or AES step)' % name,
               DecryptError)
    finally:
        if 'pwd' in locals():
            del pwd

    # Log any error-ish conditions:
    if 'unable to load Private Key' in se_RSA:
        fatal('%s: unable to load Private Key' % name, PrivateKeyError)
    glop = "Loading 'screen' into random state - done"
    se_RSA = se_RSA.replace(glop, '').strip()
    if se_RSA:
        fatal('%s: Bad decrypt (RSA) %s (wrong key?)' % (name, se_RSA),
              DecryptError)
    if se_AES:
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

    # Define file paths (openssl will create the files):
    data_enc = _uniq_file(abspath(datafile + AES_EXT))
    pwd_rsa = data_enc + RSA_EXT  # path to RSA-encrypted session key

    # Generate a password (digital envelope "session" key):
    # want printable because its sent to openssl via stdin
    bits = 256
    pwd = printable_pwd(nbits=bits)  # has leading '#'
    assert not whitespace_re.search(pwd)
    assert len(pwd.replace('#', '')) == bits // 4

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
        sys_call(cmd_RSA, stdin=pwd)
        sys_call(cmd_AES, stdin=pwd)
        # better to return immediately + del(pwd) but using stdin blocks
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try; should happen right away anyway

    return _abspath(data_enc), _abspath(pwd_rsa)


def fatal(msg, err=ValueError):
    """log then raise err(msg).
    """
    logging.error(msg)
    raise err(msg)


def genrsa(interactive=True):
    """Launch RSA key-generation dialog.
    """
    return GenRSA().dialog(interactive)


def get_dropbox_path():
    """Return the path to the Dropbox folder, or False if not found.

    First time called will set a global var (used on subsequent calls).
    """
    global dropbox_path
    if dropbox_path is None:
        if sys.platform == 'win32':
            host_db = os.path.join(os.environ['APPDATA'], 'Dropbox', 'host.db')
        else:
            host_db = os.path.expanduser('~/.dropbox/host.db')
        if not exists(host_db):
            logging.info('did not find a Dropbox folder')
            dropbox_path = False
        else:
            db_path_b64 = open(host_db, read_mode).readlines()[1]  # second line
            db_path = b64decode(db_path_b64.strip())
            dropbox_path = _abspath(db_path)
            logging.info('found Dropbox folder %s' % dropbox_path)

    return dropbox_path


def get_key_length(pub):
    """Return the number of bits in a RSA public key.
    """
    name = 'get_key_length'
    cmdGETMOD = [OPENSSL, 'rsa', '-modulus', '-in', pub, '-pubin', '-noout']
    modulus = sys_call(cmdGETMOD).replace('Modulus=', '')
    if not modulus:
        fatal(name + ': no RSA modulus in pub "%s" (bad .pem file?)' % pub)
    return len(modulus) * 4


def hmac_sha256(key, filename):
    """Return a hash-based message authentication code (HMAC), using SHA256.

    The key is a string value.
    """
    if not key:
        return None
    #if getsize(filename) > MAX_FILE_SIZE:
    #    fatal('hmac_sha256: file too large (> max file size)')
    cmd_HMAC = [OPENSSL, 'dgst', '-sha256', '-hmac', key, filename]
    hmac_openssl = sys_call(cmd_HMAC)

    return hmac_openssl


def isinstance_basestring23(duck):
    # placeholder for 2to3
    #return isinstance(duck, basestring)
    try:
        duck + 'quack'
        duck.endswith('quack')
        return True
    except:
        return False


def printable_pwd(nbits=256, prefix='#'):
    """Return hex digits with n random bits, zero-padded.
    """
    # default prefix ensures that the returned str is not interned by python

    val = random.SystemRandom().getrandbits(nbits)
    len = nbits // 4
    pwd = prefix + hex(val).strip('L').replace('0x', '').zfill(len)

    return pwd


def permissions_str(filename):
    perm = 'win32-not-implemented'
    if not sys.platform in ['win32']:
        p = int(oct(os.stat(filename)[stat.ST_MODE])[-3:], 8)
        perm = '0o' + oct(p)[1:]
    return perm


def secure_rename(src, dest):
    """Securely move file ``src`` to ``dest``.

    Ensure unique name, secure delete if needed.
    """
    if exists(dest):
        dest = _uniq_file(dest)
    try:
        os.rename(src, dest)
    except OSError:  # pragma: no cover
        # e.g., if /tmp is on another disk partition can't just rename
        shutil.copy(src, dest)
        demolished = SecFile(src).destroy().result
        if demolished['disposition'] != destroy_code[pfs_DESTROYED]:
            msg = name + ': destroy tmp file failed: %s' % src
            fatal(msg, DestroyError)
    return {'method': 'secure_rename', 'status': 'good', 'new_name': dest}


def set_umask(new_umask=UMASK):
    # decorator to (set-umask, do-fxn, unset-umask) worked but ate the doc-strs
    global _old_umask
    _old_umask = os.umask(new_umask)
    return _old_umask


def set_destroy():
    """Find, set, and report info about secure file removal tool to be used.

    on win32, use a .bat file.
    """
    opts = {'darwin': ('-f', '-z', '--medium'),  # 7 passes
            'linux2': ('-f', '-u', '-n', '7'),
            'win32':  ('-q', '-p', '7')}
    DESTROY_OPTS = opts[sys.platform]
    global DESTROY_EXE
    try:  # darwin
        DESTROY_EXE = which('srm')
    except WhichError:
        try:  # linux
            DESTROY_EXE = which('shred')
        except WhichError:  # win32
            DESTROY_EXE = os.path.join(appdata_lib_dir, '_sdelete.bat')
            if not isfile(DESTROY_EXE):
                try:
                    guess = which('sdelete.exe')  # which is fast
                except WhichError:  # where is slow
                    guess = sys_call(['where', '/r', 'C:\\', 'sdelete.exe'])
                    if not guess.endswith('sdelete.exe'):
                        fatal('Failed to find sdelete.exe. Please install ' +
                            'under C:\\, run it manually to accept the terms.',
                            RuntimeError)
                # bat_template in constants.py
                bat = sd_bat_template.replace('XSDELETEX', _abspath(guess))
                with open(DESTROY_EXE, write_mode) as fd:
                    fd.write(bat)

    if not isfile(DESTROY_EXE):  # pragma: no cover
        fatal("Can't find a secure file-removal tool", RuntimeError)
    logging.info('set destroy init: use %s %s' % (DESTROY_EXE,
                                                  ' '.join(DESTROY_OPTS)))
    sd_version = sys_call([DESTROY_EXE, '--version']).splitlines()[0]
    logging.info('destroy version: ' + sd_version)

    return DESTROY_EXE, DESTROY_OPTS


def set_logging(verbose=False):
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
    if not verbose:
        logging = _no_logging()
    else:
        msgfmt = "%.4f  " + lib_name + ": %s"
        logging = _log2stdout()

    return logging


def set_openssl(path=None):
    """Find, check, set, and report info about the OpenSSL binary to be used.

    On win32, use a .bat file to set openssl environment variable.
    """
    if path:  # command-line arg or parameter
        OPENSSL = path
        logging.info('Requested openssl executable: ' + OPENSSL)
    elif sys.platform not in ['win32']:
        OPENSSL = which('openssl')
        if OPENSSL not in ['/usr/bin/openssl']:  # pragma: no cover
            msg = 'unexpected location for openssl binary: %s' % OPENSSL
            logging.warning(msg)
    else:
        # use a bat file to set OPENSSL_CONF; create .bat if not found
        OPENSSL = op_bat_name  # from constants
        if not exists(OPENSSL):
            logging.info('no working %s file; will recreate' % op_bat_name)
            bat = op_bat_template.replace(op_expr, op_default)
            with open(OPENSSL, write_mode) as fd:
                fd.write(bat)
            test = sys_call([OPENSSL, 'version'])
            if not test.startswith('OpenSSL'):
                # locate and cache result, takes 5-6 seconds:
                cmd = ['where', '/r', 'C:\\', 'openssl.exe']
                guess = sys_call(cmd).splitlines()[0]  # take first match
                if not guess.endswith('openssl.exe'):
                    fatal('Failed to find OpenSSL.exe.\n' +
                           'Please install under C:\ and try again.',
                           RuntimeError)
                guess_path = guess.replace(os.sep + 'openssl.exe', '')
                where_bat = op_bat_template.replace(op_expr, guess_path)
                with open(OPENSSL, write_mode) as fd:
                    fd.write(where_bat)
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
    with open(filename, 'rb') as fd:
        for buf in iter(partial(fd.read, 2048), b''):  # null byte sentinel
            dgst.update(buf)
    return dgst.hexdigest()


def sys_call(cmdList, stderr=False, stdin='', ignore_error=False):
    """Run a system command via subprocess, return stdout [, stderr].

    stdin is optional string to pipe in. Will always log a non-empty stderr.
    (stderr is sent to logging.INFO if ignore_error=True).
    """
    #sec_str=True will return stdout as a SecStr

    msg = ('', ' (ignore_error=True)')[ignore_error]
    log = (logging.error, logging.info)[ignore_error]
    logging.debug('sys_call%s: %s' % (msg, (' '.join(cmdList))))

    proc = subprocess.Popen(cmdList,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    _so, se = proc.communicate(stdin)

    so = _so.strip()
    se = se.strip()
    if se:
        log('stderr%s: %s' % (msg, se))
    if stderr:
        return so, se
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


def main(args):
    logging.info("%s with %s" % (lib_name, openssl_version))
    if args.filename == 'genrsa':  # pragma: no cover
        """Walk through key generation on command line.
        """
        GenRSA().dialog(interactive=(not args.autogen), args=args)
        sys.exit()
    elif not isfile(args.filename):
        raise ArgumentError('no such file (requires "genrsa" or a filename)')
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
            args.nometa and kw.update({'meta': False})
            args.nodate and kw.update({'date': False})
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
        elif args.unpad:
            sf_fxn = sf.pad
            kw.update({'size': 0})
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
            return sf.hardlinks
        elif args.tracked:
            return sf.is_tracked
        elif args.permissions:
            return sf.permissions
        elif args.dropbox:
            return sf.is_in_dropbox

        sf_fxn(**kw)  # make it happen
        return sf.result


def _parse_args():
    """Parse and return command line arguments.

    a file name is typically the first (required) argument
    passphrases for command-line usage must go through files;
        will get a logging.warning()
    currently not possible to register a new enc/dec method via command line
    """
    #  pylint: disable=C0301

    parser = argparse.ArgumentParser(
        description='File-oriented privacy & integrity management library.',
        epilog="See http://pythonhosted.org/pyFileSec/")
    parser.add_argument('filename', help='file path, or "genrsa" (no quotes)')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--verbose', action='store_true', help='print logging info to stdout', default=False)
    parser.add_argument('--openssl', help='path of the openssl binary to use')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--encrypt', action='store_true', help='encrypt with RSA + AES256 (-u [-m][-n][-c][-z][-e][-k])')
    group.add_argument('--decrypt', action='store_true', help='use private key to decrypt (-v [-d][-r])')
    group.add_argument('--rotate', action='store_true', help='rotate the encryption (-v -U [-V][-r][-R][-z][-e][-c])')
    group.add_argument('--sign', action='store_true', help='sign file / make signature (-v [-r][-o])')
    group.add_argument('--verify', action='store_true', help='verify a signature using public key (-u -s)')
    group.add_argument('--pad', action='store_true', help='obscure file length by padding with bytes ([-z])')
    group.add_argument('--unpad', action='store_true', help='remove padding')
    group.add_argument('--destroy', action='store_true', help='secure delete')
    group.add_argument('--hardlinks', action='store_true', help='return number of hardlinks to a file', default=False)
    group.add_argument('--tracked', action='store_true', help='return True if file is tracked using git, svn, or hg', default=False)
    group.add_argument('--permissions', action='store_true', help='return file permissions', default=False)
    group.add_argument('--dropbox', action='store_true', help='return True if a file is in Dropbox folder', default=False)

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('--clipboard', action='store_true', help='genrsa: passphrase placed on clipboard (only)', default=False)
    group2.add_argument('--passfile', action='store_true', help='genrsa: save passphrase to file, name matches keys', default=False)

    parser.add_argument('-o', '--out', help='sign: path name for the sig')
    parser.add_argument('-u', '--pub', help='path to public key (.pem file)')
    parser.add_argument('-v', '--priv', help='path to private key (.pem file)')
    parser.add_argument('-p', '--pphr', help='path to file with passphrase')
    parser.add_argument('-c', '--hmac', help='path to file with hmac key')
    parser.add_argument('-s', '--sig', help='path to signature file (required input for --verify)')
    parser.add_argument('-z', '--size', type=int, help='bytes for --pad, min 128, default 16384; unpad 0, -1')
    parser.add_argument('-a', '--autogen', action='store_true', help='non-interactive genrsa', default=False)
    parser.add_argument('-N', '--nodate', action='store_true', help='suppress date (meta-data are clear-text)', default=False)
    parser.add_argument('-M', '--nometa', action='store_true', help='suppress all meta-data', default=False)
    parser.add_argument('-k', '--keep', action='store_true', help='do not --destroy plain-text file after --encrypt')

    return parser.parse_args()


# Basic set-up (order matters) ------------------------------------------------

args = (__name__ == "__main__") and _parse_args()

logging = set_logging(args and args.verbose)
OPENSSL, openssl_version = set_openssl(args and args.openssl)
DESTROY_EXE, DESTROY_OPTS = set_destroy()

py64bit = bool(sys.maxsize == 2 ** 63 - 1)

# Register the default codec, runs auto-test
default_codec = {'_encrypt_rsa_aes256cbc': _encrypt_rsa_aes256cbc,
                 '_decrypt_rsa_aes256cbc': _decrypt_rsa_aes256cbc}
try:
    tmp = mkdtemp()
    u, v, p = GenRSA().demo_rsa_keys(tmp)
    codec_registry = PFSCodecRegistry(default_codec,
                        test_keys=({'pub': u}, {'priv': v, 'pphr': p}))
finally:
    shutil.rmtree(tmp, ignore_errors=False)

if __name__ == '__main__':  # pragma: no cover
    result = main(args)
    print(result)
