#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""PyFileSec: File privacy & integrity tools, e.g., for human-subjects research
"""

"""
# Copyright (c) Jeremy R. Gray, 2013
# Released under the GPLv3 licence with the additional exemptions that
# 1) compiling, linking, and/or using OpenSSL are allowed, and
# 2) this licence and copyright notice be included in all derivative works.

THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION FROM THE COPYRIGHT
HOLDER AS TO ITS FITNESS FOR ANY PURPOSE, AND WITHOUT WARRANTY BY THE COPYRIGHT
HOLDER OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
LIMITATION THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE. THE COPYRIGHT HOLDER SHALL NOT BE LIABLE FOR ANY DAMAGES,
INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, WITH RESPECT
TO ANY CLAIM ARISING OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
IF HE HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
"""

__version__ = '0.1.1'
__author__ = 'Jeremy R. Gray'
__contact__ = 'jrgray@gmail.com'

import sys
from platform import python_version
import os
from os.path import abspath, isfile, getsize
import stat
import shutil
import tarfile
import zipfile
import re
from random import SystemRandom
sysRand = SystemRandom()

import json
import time
from tempfile import mkdtemp, NamedTemporaryFile
import subprocess
import hashlib
from functools import partial  # for buffered hash digest
from base64 import b64encode, b64decode
import getpass  # for RSA key-gen


lib_name = 'PyFileSec'
lib_path = abspath(__file__)
usage = """%(name)s v%(version)s

  File privacy and integrity for psychology and human neuroscience research:
    encrypt, decrypt, sign, verify, rotate, generate passwords (RSA keys),
    secure delete, pad (to obscure file-size), & archive.
    Requires Python 2.6 or 2.7, and OpenSSL 0.9.8 or higher.

  Module example:
    >>> import %(name)s as pfs
    >>> pfs.encrypt('data.txt', 'pub.pem')
    /path/to/data.enc
    >>> pfs.decrypt('/path/to/data.enc', 'priv.pem')
    /path/to/data.txt

  Command-line example:
    $ alias pfs='%(lib_path)s'
    $ pfs encrypt data.txt pub.pem
    /path/to/data.enc
    $ pfs decrypt data.enc priv.pem
    /path/to/data.txt

  Options:
    --help | -h : display this message
    --version   : print version and exit
    --openssl=/path/to/openssl : openssl binary file to use for openssl calls

  Testing:
    $ py.test %(name)s.py
  """ % {'name': os.path.splitext(os.path.basename(__file__))[0],
         'lib_path': lib_path,
         'version': __version__}

if '--version' in sys.argv:
    print(__version__)
    sys.exit()
if (__name__ == "__main__" and len(sys.argv) == 1 or
    '-h' in sys.argv or '--help' in sys.argv):
    print(usage)
    sys.exit()
if python_version() < '2.6.6':
    raise RuntimeError('Requires python 2.6+')


class PublicKeyTooShortError(Exception):
    '''Error to indicate that a public key is not long enough.'''

class DecryptError(Exception):
    '''Error to signify that decryption failed.'''

class PrivateKeyError(Exception):
    '''Error to signify that loading a private key failed.'''

class InternalFormatError(Exception):
    '''Error to indicate bad file name inside .tgz file.'''

class PaddingError(Exception):
    '''Error to indicate bad padding.'''


class PFSCodecRegistry(object):
    """Class to explicitly manage the encrypt & decrypt functions.

    Motivation:

    1) Want extensible structure so that other encryption tools can drop in,
       while retaining the file-bundling and meta-data generation.

    2) Want the method used for encryption to be documentable in meta-data,
       esp. useful if there are several alternative methods available.

    Currently works for the default functions. To register a new function, the
    idea is to be able to do::

        codec = PFSCodecRegistry()
        new = {'_encrypt_xyz': _encrypt_xyz,
               '_decrypt_xyz': _decrypt_xyz}
        # checks for matching enc/dec pairs
        codec.register(new)

    and then `encrypt(method='_encrypt_xyz')` will work.

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
        """Validate and add codec pairs to the registry, in pairs.
        """
        for key in list(new_functions.keys()):
            fxn = new_functions[key]
            if not key in globals() or not hasattr(fxn, '__call__'):
                msg = ': failed to register "%s", not callable' % key
                _fatal(self.name + msg)
            if key in list(self.keys()):
                _fatal(self.name + ': function "%s" already registered' % key)
            if not len(key) > 3 or key[:4] not in ['_enc', '_dec']:
                msg = ': failed to register "%s": need _enc/_dec...' % key
                _fatal(self.name + msg)
            self._functions.update({key: fxn})
            fxn_info = '%s(): fxn id=%d' % (key, id(fxn))
            logging.info(self.name + ': registered %s' % fxn_info)
        for key in list(new_functions.keys()):
            # check for the other half of the pair, now that all are updated:
            lead = key[:4]
            prefix_swap = {'_enc': '_dec', '_dec': '_enc'}
            twin = key.replace(lead, prefix_swap[lead], 1)
            if not twin in list(self._functions.keys()):
                _fatal('method "%s" incomplete codec pair' % key)

    def unregister(self, function_list):
        """Remove codec pairs from the registry based on keys.
        """
        #raise NotImplementedError()
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
        return None

    def is_registered(self, fxn_name):
        """Returns True if `fxn_name` is registered; validated at registration.
        """
        return fxn_name in self._functions


def _setup_logging():
    # Logging:  stderr, or psychopy.logging if we're a PsychoPy module
    class _log2stderr(object):
        """Print all logging messages, regardless of log level.
        """
        @staticmethod
        def debug(msg):
            m = msgfmt % (time.time() - logging_t0, msg)
            print(m)

        # flatten log levels:
        error = warning = exp = data = info = debug

    class _no_logging(object):
        @staticmethod
        def debug(msg):
            pass
        error = warning = exp = data = info = debug

    loggingID = lib_name
    logging_t0 = time.time()
    log_sysCalls = True
    verbose = bool('--verbose' in sys.argv or '--test' in sys.argv or
                   '--debug' in sys.argv)
    if '--verbose' in sys.argv:
        del(sys.argv[sys.argv.index('--verbose')])
    if not verbose:
        logging = _no_logging()
    else:
        msgfmt = "%.4f  " + loggingID + ": %s"
        logging = _log2stderr()
        if __name__ != '__main__':
            try:
                from psychopy import logging
            except:
                pass
    return logging, loggingID, logging_t0, log_sysCalls


def _sysCall(cmdList, stderr=False, stdin=''):
    """Run a system command via subprocess, return stdout [, stderr].

    stdin is optional string to pipe in. Will always log a non-empty stderr.
    """
    if log_sysCalls:
        logging.debug('_sysCall: %s' % (' '.join(cmdList)))

    proc = subprocess.Popen(cmdList, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    so, se = proc.communicate(stdin)
    if se:
        logging.error(se.strip())
    if stderr:
        return so.strip(), se.strip()
    else:
        return so.strip()


def _get_openssl_info():
    """Find, check, and report info about the OpenSSL binary on this system.
    """
    for i, arg in enumerate(sys.argv):
        if arg.startswith('--openssl='):
            # spaces in path ok if parses as one argument
            OPENSSL = arg.replace('--openssl=', '')
            del(sys.argv[i])
            logging.info('Option requesting OpenSSL version: ' + OPENSSL)
            break
    else:
        if sys.platform not in ['win32']:
            OPENSSL = _sysCall(['which', 'openssl'])
            if OPENSSL not in ['/usr/bin/openssl']:
                msg = 'unexpected location for openssl binary: %s' % OPENSSL
                logging.warning(msg)
        else:
            guess = _sysCall(['where', '/r', 'C:\\', 'openssl'])  # vista+
            if not (isfile(guess) and guess.endswith('openssl.exe')):
                guess = 'C:/OpenSSL-Win32/bin/openssl.exe'
                if not isfile(guess):
                    cwd = os.path.split(os.path.abspath(__file__))[0]
                    guess = os.path.join(cwd, os.path.abspath('openssl.exe'))
            OPENSSL = guess
    if not isfile(OPENSSL):
        if sys.platform not in ['win32']:
            msg = 'Could not find openssl, tried: %s' % OPENSSL
        else:
            msg = 'Could not find openssl.exe\n' +\
              'Expecting C:\\OpenSSL-Win32\\bin\\openssl.exe, ' +\
              'or %s\\openssl.exe\n' % cwd +\
              'Try http://www.slproweb.com/products/Win32OpenSSL.html'
        _fatal(msg, RuntimeError)

    opensslVersion = _sysCall([OPENSSL, 'version'])
    if opensslVersion.lower() < 'openssl 0.9.8':
        _fatal('OpenSSL too old (%s)' % opensslVersion, RuntimeError)
    logging.info('OpenSSL binary  = %s' % OPENSSL)
    logging.info('OpenSSL version = %s' % opensslVersion)

    # use_rsautl = opensslVersion < 'OpenSSL 1.0'  # ideally use pkeyutl
    # but -decrypt with passphrase fails with pkeyutl, so always use rsautl:
    use_rsautl = True

    return OPENSSL, opensslVersion, use_rsautl


def _get_wipe_info():
    """Find and return into about secure file removal tools on this system.
    """
    if sys.platform in ['darwin']:
        WIPE_TOOL = _sysCall(['which', 'srm'])
        WIPE_OPTS = ('-f', '-z', '--medium')  # 7 US DoD compliant passes
    elif sys.platform.startswith('linux'):
        WIPE_TOOL = _sysCall(['which', 'shred'])
        WIPE_OPTS = ('-f', '-u', '-n', '7')
    elif sys.platform in ['win32', 'cygwin']:
        guess = _sysCall(['where', '/r', 'C:\\', 'sdelete.exe'])  # vista+
        WIPE_TOOL = guess
        WIPE_OPTS = ('-q', '-p', '7')
    else:
        WIPE_TOOL = None
        WIPE_OPTS = ()
    have_wipe_tool = WIPE_TOOL and isfile(WIPE_TOOL)
    return have_wipe_tool, WIPE_TOOL, WIPE_OPTS


def _fatal(msg, err=ValueError):
    """log then raise err(msg).
    """
    logging.error(msg)
    raise err(msg)


if True:  # CONSTANTS (with code folding) ------------
    RSA_PADDING = '-oaep'  # actual arg for openssl rsautl in encrypt, decrypt

    BNDL_EXT = '.enc'   # extension for for tgz of AES, PWD.RSA, META
    AES_EXT = '.aes256'  # extension for AES encrypted data file
    PWD_EXT = 'pwd'     # extension for file containing password
    RSA_EXT = '.rsa'    # extension for RSA-encrypted AES-password ciphertext
    META_EXT = '.meta'  # extension for meta-data

    # files larger than this size in bytes will not be encrypted:
    MAX_FILE_SIZE = 2 ** 30  # 1G

    # file-length padding:
    PFS_PAD = lib_name + '_padded'  # label = 'file is padded by opensslwrap'
    PAD_STR = 'pad='    # label means 'pad length = \d\d\d\d\d\d\d\d\d\d bytes'
    PAD_BYTE = b'\0'    # actual byte to use; value unimportant
    if PAD_BYTE in PFS_PAD:
        _fatal('padding byte must not be in the label %s' % PFS_PAD)
    if len(PAD_BYTE) != 1:
        _fatal('padding byte length must be 1')
    PAD_LEN = len(PAD_STR + PFS_PAD) + 10 + 2
    # 10 = # digits in max file size, also works for 4G files
    #  2 = # extra bytes, one at end, one between PAD_STR and PFS_PAD labels

    # used if user suppresses the date; will sort before a numerical date:
    NO_DATE = '(date-time suppressed)'

    # for python-based HMAC (from wikipedia):
    _hmac_trans_5C = "".join(chr(x ^ 0x5c) for x in range(256))
    _hmac_trans_36 = "".join(chr(x ^ 0x36) for x in range(256))
    _hmac_blocksize = hashlib.sha256().block_size

    hexdigits_re = re.compile('^[\dA-F]+$|^[\da-f]+$')

    # wipe return codes:
    pfs_WIPED = 1
    pfs_UNLINKED = 0
    pfs_UNKNOWN = -1

    # decrypted file status:
    PERMISSIONS = 0o600  # for decrypted file, no execute, no group, no other
    UMASK = 0o777 - PERMISSIONS


def _entropy():
    """Basic query for some indication that entropy is available.
    """
    if sys.platform == 'darwin':
        # SecurityServer daemon is supposed to ensure entropy is available:
        ps = _sysCall(['ps', '-e'])
        securityd = _sysCall(['which', 'securityd'])  # full path
        if securityd in ps:
            e = securityd + ' running'
        else:
            e = ''
    elif sys.platform.startswith('linux'):
        avail = _sysCall(['cat', '/proc/sys/kernel/random/entropy_avail'])
        e = 'entropy_avail: ' + avail
    else:
        e = '(unknown)'
    return e


def _sha256(filename, prepend='', raw=False):
    """Return sha256 hexdigest of a file, using a buffered digest.
    """
    # from stackoverflow:
    dgst = hashlib.sha256()
    dgst.update(prepend)
    with open(filename, mode='rb') as fd:
        for buf in iter(partial(fd.read, 2048), b''):  # null byte sentinel
            dgst.update(buf)
    if raw:
        return dgst.digest()
    else:
        return dgst.hexdigest()


def hmac_sha256(key, valueFile):
    """Return a hash-based message authentication code (HMAC), using SHA256.
    """
    # code from wikipedia, verified against openssl (see test_hmac)
    # openssl works fine but is 100x slower than pure python for small files

    if not key:
        return None
    if getsize(valueFile) > MAX_FILE_SIZE:
        _fatal('hmac_sha256: msg too large (> max file size)')
    if len(key) > _hmac_blocksize:
        key = hashlib.sha256(key).digest()
    key += chr(0) * (_hmac_blocksize - len(key))
    o_key_pad = key.translate(_hmac_trans_5C)  # see constants
    i_key_pad = key.translate(_hmac_trans_36)
    dgst = hashlib.sha256(o_key_pad + _sha256(valueFile, i_key_pad, True))

    return dgst.hexdigest()


def numBits(pubkey):
    """Return the number of bits in a RSA public key.
    """
    cmdGETMOD = [OPENSSL, 'rsa', '-modulus', '-in', pubkey, '-pubin', '-noout']
    modulus = _sysCall(cmdGETMOD).replace('Modulus=', '')
    if not modulus:
        _fatal('numBits: no RSA modulus in pub "%s" (bad .pem file?)' % pubkey)
    if not hexdigits_re.match(modulus):
        _fatal('numBits: expected hex digits in pubkey RSA modulus')
    return len(modulus) * 4


def _printablePwd(nbits=256):
    """Return a string of hex digits with n random bits, zero-padded.

    Uses random.SystemRandom().getrandbits().
    """
    pwd = hex(sysRand.getrandbits(nbits))
    return pwd.strip('L').replace('0x', '', 1).zfill(nbits // 4)


def archive(paths, name='', ext='.tgz', umask=0o0077, unlink=False):
    """Make a tgz file from a list of paths, set permissions. Directories ok.

    Eventually might take an arg to decide whether to use tar or zip.
    Just a tarfile wrapper with extension, permissions, unlink options.
    unlink is whether to unlink the original files after making an archive, not
    a secure-delete option.
    """
    if isinstance(paths, str):
        paths = [paths]
    if not name:
        name = os.path.splitext(paths[0])[0].strip(os.sep) + ext
    umask_restore = os.umask(umask)
    tar_fd = tarfile.open(name, "w:gz")
    os.chmod(tar_fd.name, 0o0777 - umask)  # redundant, hopefully
    for p in paths:
        tar_fd.add(p, recursive=True)  # True by default
        if unlink:
            try:
                shutil.rmtree(p)  # might be a directory
            except OSError:
                os.unlink(p)
    tar_fd.close()
    os.umask(umask_restore)

    return name


def _zip_size(paths, name=''):
    """Make a .zip file and return its size.
    """
    if isinstance(paths, str):
        paths = [paths]
    if not name:
        name = os.path.splitext(paths[0])[0] + '.zip'
    zip_fd = zipfile.ZipFile(name, "w")
    for p in paths:
        zip_fd.write(p)
    zip_fd.close()

    return os.stat(name)[stat.ST_SIZE]


def wipe(filename, cmdList=()):
    """Try to secure-delete a file; returns (status, link count, time taken).

    Calls an OS-specific secure-delete utility, defaulting to::

        Mac:     /usr/bin/srm   -f -z --medium  filename
        Linux:   /usr/bin/shred -f -u -n 7 filename
        Windows: sdelete.exe    -q -p 7 filename

    If these are not available, `wipe` will warn and fall through to trying
    to merely overwrite the data with 0's.

    As an alternative, a custom command sequence can be specified::

        cmdList = (command, option1, option2, ..., filename)

    Ideally avoid the need to wipe files. Keep all sensitive data in RAM.
    File systems that are journaled, have RAID, are mirrored, or other back-up
    are much trickier to secure-delete.

    `wipe` may fail to remove all traces of a file if multiple hard-links
    exist for the file. For this reason, the original link count is
    returned.

    The time required can help confirm whether it was a secure removal (slow)
    or an ordinary removal (unlinking is fast).

    If an open file-descriptor is given instead of a filename, wipe() will try
    to secure-delete the contents and close the file. This is intended to be
    useful when working with NamedTemporaryFiles, which vanish when closed.
    """

    got_file = hasattr(filename, 'file') and hasattr(filename, 'close')
    if got_file:
        filename, file_in = filename.name, filename
        file_in.seek(0)

    os.chmod(filename, 0o600)  # raises OSError if no file or cant change
    t0 = time.time()

    # Try to detect & inform about hardlinks:
    # srm will detect but not affect those links or the inode data
    # shred will blast the inode's data, but not unlink other links
    if sys.platform != 'win32':
        file_stat = os.stat(filename)
        orig_links = file_stat[stat.ST_NLINK]
        if orig_links > 1:
            mount_path = abspath(filename)
            while not os.path.ismount(mount_path):
                mount_path = os.path.dirname(mount_path)
            msg = """wipe: '%s' (inode %d) has other hardlinks:
                `find %s -xdev -inum %d`""".replace('    ', '')
            inode = file_stat[stat.ST_INO]
            vals = (filename, inode, mount_path, inode)
            logging.warning(msg % vals)
    else:
        links = _sysCall(['fsutil.exe', 'hardlink', 'list', abspath(filename)])
        orig_links = len(links)

    if not cmdList:
        cmdList = (WIPE_TOOL,) + WIPE_OPTS + (filename,)
    else:
        logging.info('wipe: %s' % ' '.join(cmdList))

    good_sys_call = False
    try:
        __, err = _sysCall(cmdList, stderr=True)
        good_sys_call = not err
    except OSError as e:
        good_sys_call = False
        logging.warning('wipe: %s' % e)
        logging.warning('wipe: %s' % ' '.join(cmdList))
    finally:
        if got_file:
            try:
                file_in.close()
                file_in.unlink()
                del(file_in.name)
            except:
                pass  # gives an OSError but has done something
        if not isfile(filename):
            if good_sys_call:
                return pfs_WIPED, orig_links, time.time() - t0
            return pfs_UNKNOWN, orig_links, time.time() - t0

    # file should have been overwritten and removed; if not...
    logging.warning('wipe: falling through to 1 pass of zeros')
    with open(filename, 'wb') as fd:
        fd.write(chr(0) * getsize(filename))
    shutil.rmtree(filename, ignore_errors=True)
    assert not isfile(filename)  # yikes, file remains

    return pfs_UNKNOWN, orig_links, time.time() - t0


def _get_permissions(filename):
    return int(oct(os.stat(filename)[stat.ST_MODE])[-3:], 8)


def _uniqFile(filename):
    """Avoid file name collisions by appending a count before extension.
    """
    count = 0
    base, filext = os.path.splitext(filename)
    while isfile(filename) or os.path.isdir(filename):
        count += 1
        filename = base + '(' + str(count) + ')' + filext
    return filename


def _getMetaData(datafile, dataEncFile, pubkey, encMethod,
                 date=True, hmac_key=None):
    """Return info about an encryption context, as a {date-now: {info}} dict.

    If `date` is True, date-now is numerical date of the form
    year-month-day-localtime,
    If `date` is False, date-now is '(date-time suppressed)'. The date values
    are also keys to the meta-data dict, and their format is chosen so that
    they will sort to be in chronological order, even if the original
    encryption date was suppressed (it comes first).
    """

    md = {'clear-text-file': abspath(datafile),
        'sha256 of encrypted file': '%s' % _sha256(dataEncFile)}
    if hmac_key:
        hmac = hmac_sha256(hmac_key, dataEncFile)
        md.update({'hmac-sha256 of encrypted file': hmac})
    md.update({'sha256 of public key': _sha256(pubkey),
        'encryption method': lib_name + '.' + encMethod,
        'sha256 of lib %s' % lib_name: _sha256(lib_path),
        'rsa padding': RSA_PADDING,
        'max_file_size_limit': MAX_FILE_SIZE})
    if date:
        now = time.strftime("%Y_%m_%d_%H%M", time.localtime())
        m = int(time.time() / 60)
        s = (time.time() - m * 60)
        now += ('.%6.3f' % s).replace(' ', '0')  # zeros for clarity & sorting
            # only want ms precision for testing, which can easily
            # generate two files within ms of each other
    else:
        now = NO_DATE
    md.update({'encrypted year-month-day-localtime-Hm.s.ms': now,
        'openssl version': opensslVersion,
        'platform': sys.platform,
        'python version': '%d.%d.%d' % sys.version_info[:3]})

    return {'meta-data %s' % now: md}


def loadMetaData(md_file):
    """Convenience function to read meta-data from a file, return it as a dict.
    """
    return json.load(open(md_file, 'r+b'))


def logMetaData(md, log=True):
    """Convenience function to log and return meta-data in human-friendly form.
    """
    md_fmt = json.dumps(md, indent=2, sort_keys=True, separators=(',', ': '))
    if log:
        logging.info(md_fmt)
    return md_fmt


def pad(filename, size=16384, test=False, strict=True):
    """Append or remove `byte` + tags until `filename` reaches `size`.

    Aim: Provide a way to mask file size. Files shorter than `size` will be
    padded out to `size`. The minimum resulting file size is 128 bytes.
    Passing `size` of 0 will remove any padding, if present, and -1 is the same
    as 0 except that it is strict: it will raise an error if there's no padding
    already.

    All files have ~36 bytes appended for two pad-descriptor tags. Thus files
    that are close to `size` already would not have their sizes obscured AND
    also be marked as being padded (in the last ~36 bytes). If it is ok to have
    file sizes exceeding `size` (and hence leak the size of the original file),
    use `strict=False`.

    Padding format: file + n bytes + pad=10-digits + byte + PFS_PAD + byte
    n is selected to make the new file size == `size`.

    `test` allows for testing whether the `size` is adequate to obscure
    the file size. This is similar to testing getsize(file) > size,
    except that `test` also takes into account the padding-size info that is
    stored as part of the padding (36 bytes, unless max file size is not the
    default of 1G). So its getsize(file) > size - 36. Testing succeeded
    if no PaddingError is raised.

    To make unpadding easier and more robust (= facilitate human inspection),
    the end bytes provide the number of padding bytes that were added, plus an
    identifier. 10 digits is not hard-coded as 10, but as the length of
    str(max_file_size), where max_file_size is 1G by default (2**30). Changes
    to the max file size can thus cause pad / unpad failures.

    Special size values:
       0 = remove any existing padding
      -1 = remove padding if its present, raise PaddingError if not present
    """
    name = 'pad: '
    size = int(size)
    if size > MAX_FILE_SIZE:
        _fatal('pad: size must be <= %d (maximum file size)' % MAX_FILE_SIZE)
    # handle special size values (0, -1) => unpad
    try:
        oldsize = _unpad_strict(filename, test=test)
        padded = True
    except PaddingError:
        padded = False  # wasn't padded with PAD_BYTE
        if size < 0:
            _fatal(name + 'file not padded, requested strict', PaddingError)
    if size < 1:
        if padded:
            return oldsize
        else:
            return getsize(filename)

    filesize = getsize(filename)
    size = max(size, 128)
    needed = max(0, size - filesize - PAD_LEN)
    if needed == 0:
        msg = name + 'file length not obscured (existing length >= reqd size)'
        if test or strict:
            _fatal(msg, PaddingError)
        logging.error(msg)
    elif test:
        logging.info(name + ' test complete, file size + padding < reqd size')
        return
    pad_bytes = PAD_STR + "%010d" % (needed + PAD_LEN)

    # append bytes to pad the file:
    with open(filename, 'a+b') as fd:
        chunk = 1024  # cap memory usage
        chunkbytes = PAD_BYTE * chunk
        for i in range(needed // chunk):
            fd.write(chunkbytes)
        extrabytes = PAD_BYTE * (needed % chunk)
        fd.write(extrabytes)
        fd.write(pad_bytes)
        fd.write(PAD_BYTE + PFS_PAD + PAD_BYTE)
        logging.info(name + 'append bytes to get to %d bytes' % size)

    return getsize(filename)


def _unpad_strict(filename, test=False):
    """Removes padding from the file. raise PaddingError if no or bad padding.

    `test=True` tests for good padding but does not actually truncate the file.
    This is provided because a given file may or may not be padded, and it may
    be desired to simply test whether it is padded, without actually doing any
    unpadding:

        try:
            _unpad_strict(filename, test=True)
            padded = True
        except PaddingError:
            padded = False

    Truncates the file to remove padding; does not wipe.
    """
    name = 'unpad: '
    logging.debug(name + 'start, file="%s"' % filename)
    filelen = getsize(filename)
    with open(filename, 'r+b') as fd:
        # read last 100 bytes and then split
        fd.seek(max(0, filelen - PAD_LEN))
        pad_stuff = fd.read()
        last_byte = pad_stuff[-1]  # expect all padding to be this byte
        if last_byte != PAD_BYTE:
            msg = 'unpad: file %s not padded by chr(%d)'
            _fatal(msg % (filename, ord(PAD_BYTE)), PaddingError)
        try:
            pad_tag_count, pad_marker = pad_stuff.split(PAD_BYTE)[-3:-1]
            pad_count = int(pad_tag_count.split(PAD_STR)[-1])
            assert pad_marker == PFS_PAD
        except:
            _fatal('unpad: file not padded? bad format', PaddingError)
        if pad_count > filelen or pad_count > MAX_FILE_SIZE or pad_count < 0:
            _fatal('unpad: bad pad count; file not padded?', PaddingError)

        new_length = (filelen - pad_count)
        logging.info(name + 'found padding in file %s' % filename)
        if test:
            logging.info(name + 'test only, file unchanged')
        else:
            # trim but not wipe() the padding length info
            os.ftruncate(fd.fileno(), new_length)
            logging.info(name + 'truncated the file to remove padding')

    return getsize(filename)


def encrypt(datafile, pubkeyPem, meta=True, date=True, keep=False,
            encMethod='_encrypt_rsa_aes256cbc', hmac_key=None):
    """Encrypt a file using openssl, AES-256, and an RSA public-key.

    Returns: full path to the encrypted file (= .tgz bundle of 3 files).

    The idea is that you can have and share a public key, which anyone can
    use to encrypt things that only you can decrypt. Generating good keys and
    managing them is non-trivial, and is entirely up to you. GPG can help.

    No attempt is made to verify key signatures automatically; you could do
    so manually using `verify()`.

    By default, the original plaintext is secure-deleted after encryption (see
    parameter `keep=False`).

    Files larger than 1G (2^30 bytes, before encryption) will raise a
    ValueError. To mask small file sizes, `pad()` them to a desired minimum
    size before calling `encrypt()`. To encrypt a directory, first tar or zip
    it to create a single file, which you can then `encrypt()`.

    :Parameters:
        `datafile`:
            The path (name) of the original plaintext file to be encrypted.
            NB: To encrypt a whole directory, first convert it to a single
            file (using zip or tar czf), then encrypt the .zip or .tar file.
        `pubkeyPem`:
            The public key to use, specified as the path to a .pem file. The
            minimum recommended key length is 2048 bits; 1024 is allowed but
            strongly discouraged as it is not secure.
        `meta`:
            If `True`, include meta-data as plaintext in the archive::
                original file name & sha256 of encrypted
                platform & date
                openssl version, padding
                pubkey info (to aid in key rotation)
        `date`:
            True mean save the date in the clear-text meta-data.
            Use False if the date is sensitive.
            File time-stamps are NOT obscured in any way.
        `keep`:
            None | False  = remove original (unencrypted) & all intermediate
                files (more secure)
            True  = leave original file, delete intermediate (encrypted) files
            'all' = leave all intermed files & orig (for testing purposes)
        `encMethod`:
            name of the function / method to use (currently only one option)
        `hmac_key`:
            key to use for HMAC-SHA256; if provided a HMAC will be generated
            and stored with the meta-data
    """
    name = 'encrypt: '
    logging.debug(name + 'start')
    if not codec.is_registered(encMethod):
        _fatal(name + "requested encMethod '%s' not registered" % encMethod)
    if not pubkeyPem or not isfile(pubkeyPem):
        _fatal(name + "no public-key.pem; file '%s' not found" % pubkeyPem)
    if not datafile or not isfile(datafile):
        _fatal(name + "no data; file '%s' not found" % datafile)

    # Handle file size constraints:
    size = getsize(datafile)
    if size > MAX_FILE_SIZE:
        _fatal(name + "file too large (max size %d bytes)" % MAX_FILE_SIZE)

    # Refuse to proceed without a pub key of sufficient bits:
    bitCount = numBits(pubkeyPem)
    logging.info(name + 'pubkey length %d' % bitCount)
    if bitCount < 1024:
        _fatal("public key < 1024 bits; too short!", PublicKeyTooShortError)
    if bitCount < 2048:
        logging.error(name + 'public key < 2048 bits, no real security')
    if not keep in [None, True, False]:
        _fatal(name + "bad value for 'keep' parameter")

    # Do the encryption, using a registered `encMethod`:
    ENCRYPT_FXN = codec.get_function(encMethod)
    dataFileEnc, pwdEncFile = ENCRYPT_FXN(datafile, pubkeyPem, OPENSSL)
    ok_encrypt = (isfile(dataFileEnc) and
                    os.stat(dataFileEnc)[stat.ST_SIZE] and
                    isfile(pwdEncFile) and
                    os.stat(pwdEncFile)[stat.ST_SIZE] >= 128)

    # Get and save meta-data (including HMAC):
    if meta:
        metaDataFile = os.path.split(datafile)[1] + META_EXT
        md = _getMetaData(datafile, dataFileEnc, pubkeyPem, encMethod,
                          date, hmac_key)
        if not isinstance(meta, dict):
            logging.warning(name + 'non-dict value for meta; using {}')
            meta = {}
        meta.update(md)
        with open(metaDataFile, 'w+b') as fd:
            json.dump(meta, fd)

    # Bundle the files: (cipher text, rsa pwd, meta-data) --> data.enc:
    bundleFilename = _uniqFile(os.path.splitext(datafile)[0] + BNDL_EXT)
    bundleFiles = [dataFileEnc, pwdEncFile]  # files to be bundled in .tgz
    if meta:
        bundleFiles.append(metaDataFile)

    # get file names no path info & bundle them together as a single file
    files = [os.path.split(f)[1] for f in bundleFiles]
    archive(files, bundleFilename, BNDL_EXT, 0o0177, unlink=True)

    if not keep:
        # secure-delete unencrypted original, unless encrypt did not succeed:
        ok_to_wipe = (ok_encrypt and
                      isfile(bundleFilename) and
                      os.stat(bundleFilename)[stat.ST_SIZE])
        if ok_to_wipe:
            wipe(datafile)
        else:
            logging.error(name + 'retaining original file, not wipe()d')

    return abspath(bundleFilename)


def _encrypt_rsa_aes256cbc(datafile, pubkeyPem, OPENSSL=''):
    """Encrypt a datafile using openssl to do rsa pub-key + aes256cbc.
    """
    name = '_encrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # Define file paths:
    pwdFileRsa = PWD_EXT + RSA_EXT
    dataFileEnc = abspath(datafile) + AES_EXT
    pwdFileRsaNew = _uniqFile(dataFileEnc + pwdFileRsa)

    # Define command to RSA-PUBKEY-encrypt the pwd, save ciphertext to file:
    if use_rsautl:
        cmd_RSA = [OPENSSL, 'rsautl',
              '-out', pwdFileRsa,
              '-inkey', pubkeyPem,
              #'-keyform', 'PEM',
              '-pubin',
              RSA_PADDING, '-encrypt']
    else:
        # openssl pkeyutl -encrypt -in message.txt -pubin -inkey
        #   pubkey-ID.pem -out ciphertext-ID.bin -pkeyopt rsa_padding_mode:oeap
        cmd_RSA = [OPENSSL, 'pkeyutl', '-encrypt',
              #'-in', stdin
              '-pubin',
              '-inkey', pubkeyPem,
              '-out', pwdFileRsa,
              '-keyform', 'PEM',
              '-pkeyopt', 'rsa_padding_mode:' + RSA_PADDING]

    # Define command to AES-256-CBC encrypt datafile using the password:
    cmd_AES = [OPENSSL, 'enc', '-aes-256-cbc',
              '-a', '-salt',
              '-in', datafile,
              '-out', dataFileEnc,
              '-pass', 'stdin']

    pwd = _printablePwd(nbits=256)
    try:
        so = _sysCall(cmd_RSA, stdin=pwd)  # stderr is logged in _sysCall
        so = _sysCall(cmd_AES, stdin=pwd)
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try
            # can fail if manual interrupt when queried for passphrase

    # Rename the pwd_ciphertext file to match the datafile:
    os.rename(pwdFileRsa, pwdFileRsaNew)

    return abspath(dataFileEnc), abspath(pwdFileRsaNew)


def _unbundle(dataEnc):
    """Extract files from bundle, return tmp_dir and files.
    """
    logging.debug('_unbundle: start')

    # Check for bad paths:
    if not dataEnc or not isfile(dataEnc):
        _fatal("could not find <file>%s file '%s'" % (BNDL_EXT, str(dataEnc)))
    if not tarfile.is_tarfile(dataEnc):
        _fatal('%s not expected format (.tgz)' % dataEnc, InternalFormatError)

    # Check for bad internal paths:
    #    can't "with open(tarfile...) as tar" in python 2.6.6
    tar = tarfile.open(dataEnc, "r:gz")
    badNames = [f for f in tar.getmembers()
                if f.name[0] in ['.', os.sep] or f.name[1:3] == ':\\']
    if badNames:
        _fatal('bad/dubious internal file names' % os.sep, InternalFormatError)

    # Extract:
    tmp_dir = mkdtemp()
    umask_restore = os.umask(UMASK)
    tar.extractall(path=tmp_dir)  # extract from .tgz file
    os.umask(umask_restore)
    tar.close()

    fileList = os.listdir(tmp_dir)
    dataFileEnc = pwdFileRsa = metaFile = None
    for fname in fileList:
        if fname.endswith(AES_EXT):
            dataFileEnc = os.path.join(tmp_dir, fname)
        elif fname.endswith(PWD_EXT + RSA_EXT):
            pwdFileRsa = os.path.join(tmp_dir, fname)
        elif fname.endswith(META_EXT):
            metaFile = os.path.join(tmp_dir, fname)

    return dataFileEnc, pwdFileRsa, metaFile


def _getValidDecMethod(metaFile, decMethod):
    """Return a valid decryption method, based on meta-data or default
    """
    if metaFile:
        md = loadMetaData(metaFile)
        dates = list(md.keys())  # dates of meta-data events
        most_recent = sorted(dates)[-1]
        encMethod = md[most_recent]['encryption method'].split('.')[1]
        _dec_from_enc = encMethod.replace('_encrypt', '_decrypt')

        if decMethod:
            if decMethod != _dec_from_enc:
                msg = 'requested decryption function (%s)' % decMethod +\
                      ' != encryption function (meta-data: %s)' % encMethod
                logging.warning(msg)
        else:
            decMethod = _dec_from_enc
            logging.info('implicitly want "' + decMethod + '" (meta-data)')
        if not decMethod in globals():
            _fatal("decryption function '%s' not available" % decMethod)
    else:
        # can't infer, no meta-data
        if not decMethod:
            # ... and nothing explicit either, so go with default:
            logging.info('falling through to default decryption')
            available = [f for f in list(default_codec.keys())
                         if f.startswith('_decrypt_')]
            decMethod = available[0]

    if not codec.is_registered(decMethod):
        _fatal("_getValidDecMethod: dec fxn '%s' not registered" % decMethod)
    logging.info('_getValidDecMethod: dec fxn set to: ' + str(decMethod))

    return decMethod


def decrypt(dataEnc, privkeyPem, pphr='', outFile='', decMethod=None):
    """Decrypt a file that was encoded using `encrypt()`.

    To get the data back, need two files: `data.enc` and `privkey.pem`.
    If the private key has a passphrase, you'll need to provide that too.

    Works on a copy of data.enc, tries to decrypt, clean-up only those files.
    The original is never touched beyond making a copy.
    """
    name = 'decrypt: '
    logging.debug(name + 'start')
    perm_str = '0o' + oct(PERMISSIONS)[1:]

    priv = abspath(privkeyPem)
    dataEnc = abspath(dataEnc)
    if pphr:
        pphr = abspath(pphr)
    elif 'ENCRYPTED' in open(privkeyPem, 'r').read().upper():
        _fatal(name + 'missing passphrase (encrypted privkey)', DecryptError)

    # Extract files from the bundle (dataFileEnc) into a tmp_dir:
    try:
        dataFileEnc, pwdFile, metaFile = _unbundle(dataEnc)
        orig_dir = os.path.split(dataEnc)[0]
        logging.info('decrypting into %s' % orig_dir)
        tmp_dir = os.path.split(dataFileEnc)[0]  # get dir from file path

        # Get a valid decrypt method:
        logging.info("meta-data file: " + str(metaFile))
        newClearTextFile = None  # in case _getValidDecMethod raise()es
        decMethod = _getValidDecMethod(metaFile, decMethod)
        if not decMethod:
            _fatal('Could not get a valid decryption method', DecryptError)

        # Decrypt:
        DECRYPT_FXN = codec.get_function(decMethod)
        dataFileDec = DECRYPT_FXN(dataFileEnc, pwdFile, priv, pphr, outFile,
                                  OPENSSL=OPENSSL)
        os.chmod(dataFileDec, PERMISSIONS)
        logging.info('decrypted, permissions ' + perm_str + ': ' + dataFileDec)

        # Move decrypted and meta files out of tmp_dir:
        _newLoc = os.path.join(orig_dir, dataFileDec.split(os.sep)[-1])
        newClearTextFile = _uniqFile(_newLoc)
        try:
            os.rename(dataFileDec, newClearTextFile)
        except OSError:
            # CentOS 6, py2.6: "OSError: [Errno 18] Invalid cross-device link"
            shutil.copy(dataFileDec, newClearTextFile)
            wipe(dataFileDec)
        if metaFile:
            newMeta = newClearTextFile + META_EXT
            try:
                os.rename(metaFile, newMeta)
            except OSError:
                shutil.copy(metaFile, newMeta)
                wipe(metaFile)
    finally:
        try:
            os.chmod(newClearTextFile, PERMISSIONS)  # typically already done
            os.chmod(newMeta, PERMISSIONS)  # typically not already done
        except:
            pass
        try:
            shutil.rmtree(tmp_dir, ignore_errors=False)
            # wipe(tmp_dir) not needed, only encrypted things left behind
        except:
            assert (not 'tmp_dir' in locals() or  # never created, ok
                not len(os.listdir(tmp_dir)))  # oops, supposed to be empty

    return abspath(newClearTextFile)


def _decrypt_rsa_aes256cbc(dataFileEnc, pwdFileRsa, privkeyPem,
                           pphr=None, outFile='', OPENSSL=''):
    """Decrypt a file that was encoded by _encrypt_rsa_aes256cbc()
    """
    name = '_decrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # set the name for decrypted file:
    if outFile:
        dataDecrypted = outFile
    else:
        dataDecrypted = os.path.splitext(abspath(dataFileEnc))[0]
    #else:
    #    dataDecrypted = abspath(dataFileEnc)

    # set up the command to retrieve password from pwdFileRsa
    if use_rsautl:
        cmdRSA = [OPENSSL, 'rsautl',
                  '-in', pwdFileRsa,
                  '-inkey', privkeyPem]
        if pphr:
            cmdRSA += ['-passin', 'file:' + pphr]
        cmdRSA += [RSA_PADDING, '-decrypt']
    else:
        # pkeyutl only decrypts for me if no passphrase
        # openssl pkeyutl -decrypt -in ciphertext-ID.bin -inkey privkey-ID.pem
        #   -out received-ID.txt -pkeyopt rsa_padding_mode:oeap
        #   -passin file:pphr.test
        cmdRSA = [OPENSSL, 'pkeyutl', '-decrypt',
                  '-in', pwdFileRsa,
                  '-inkey', privkeyPem,
                  #-out stdout
                  '-pkeyopt', 'rsa_padding_mode:' + RSA_PADDING,
                  ]
        if pphr:
            cmdRSA += ['-passin', 'file:' + pphr]

    # set up the command to decrypt the data using pwd:
    cmdAES = [OPENSSL, 'enc', '-d', '-aes-256-cbc', '-a',
              '-in', dataFileEnc,
              '-out', dataDecrypted,
              '-pass', 'stdin']

    # retrieve password (to RAM), then use to decrypt into dataDecrypted file:
    try:
        umask_restore = os.umask(UMASK)
        pwd, se_RSA = _sysCall(cmdRSA, stderr=True)  # want se, parse below
        __,  se_AES = _sysCall(cmdAES, stdin=pwd, stderr=True)
    except:
        try:
            wipe(dataDecrypted)
        except ex as reason:
            logging.error('failure during wipe: %s' % reason)
        _fatal('%s: Could not decrypt (exception in RSA or AES step)' % name,
               DecryptError)
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try
            # e.g., manual interrupt when queried for passphrase
        os.umask(umask_restore)

    if se_RSA:
        if 'unable to load Private Key' in se_RSA:
            _fatal('%s: unable to load Private Key' % name, PrivateKeyError)
        elif 'RSA operation error' in se_RSA:
            _fatal("%s: can't use Priv Key; wrong key?" % name, DecryptError)
        else:
            _fatal('%s: Could not decrypt (RSA step)' % name, DecryptError)
    if se_AES:
        if 'bad decrypt' in se_AES:
            _fatal('%s: openssl bad decrypt (AES step)' % name, DecryptError)
        else:
            _fatal('%s: Could not decrypt (AES step)' % name, DecryptError)

    return abspath(dataDecrypted)


def rotate(fileEnc, oldPriv, newPub, pphr=None,
           keep=None, hmac_key=None, newPad=None):
    """Swap old encryption for new (decrypt-then-re-encrypt).

    Returns the path to new encrypted file. A new meta-data entry is added
    alongside the existing one.

    newPad will update to a new padding size (prior to re-encryption).
    """
    logging.debug('rotate (beta): start')
    fileDec = decrypt(fileEnc, oldPriv, pphr=pphr)
    old_meta_file = fileDec + META_EXT

    # seem best to always store the date of the rotation
    md = loadMetaData(old_meta_file)
    if newPad > 0:
        pad(fileDec, newPad)
    newFileEnc = encrypt(fileDec, newPub, date=True, meta=md,
                         keep=None, hmac_key=hmac_key)
    if isfile(fileDec):
        wipe(fileDec)

    return newFileEnc


def sign(filename, priv, pphr=None):
    """Sign a given file with a private key, via `openssl dgst`.

    Get a digest of the file, sign the digest, return base64-encoded signature.
    """
    logging.debug('sign: start')
    _sig = filename + '.sig'
    if use_rsautl:
        cmd_SIGN = [OPENSSL, 'dgst', '-sign', priv, '-out', _sig]
        if pphr:
            cmd_SIGN += ['-passin', 'file:' + pphr]
        cmd_SIGN += ['-keyform', 'PEM', filename]
    else:
        # openssl dgst -sha256 -sign privpphr-ID.pem -out sign-ID.bin
        #   -passin file:pphr.test -pkeyopt digest:sha256 message.txt
        cmd_SIGN = [OPENSSL, 'dgst', '-sha256', '-sign', priv, '-out', _sig]
        if pphr:
            cmd_SIGN += ['-passin', 'file:' + pphr]
        cmd_SIGN += ['-pkeyopt', 'digest:sha256', filename]
    _sysCall(cmd_SIGN)
    sig = open(_sig, 'rb').read()

    return b64encode(sig)


def verify(filename, pub, sig):
    """Verify signature of filename using pubkey, to check file integrity.
    """
    logging.debug('verifySig: start')
    with NamedTemporaryFile() as sig_file:
        sig_file.write(b64decode(sig))
        sig_file.seek(0)
        if use_rsautl:
            cmd_VERIFY = [OPENSSL, 'dgst', '-verify', pub, '-keyform', 'PEM',
                         '-signature', sig_file.name, filename]
        else:
            # openssl dgst -sha256 -verify pubkey-ID.pem
            # -signature sign-ID.bin received-ID.txt
            cmd_VERIFY = [OPENSSL, 'dgst', '-sha256', '-verify', pub,
                         '-signature', sig_file.name, filename]
        result = _sysCall(cmd_VERIFY)

    return result in ['Verification OK', 'Verified OK']


def _genRsa(pub='pub.pem', priv='priv.pem', pphr=None, bits=2048):
    """For TESTS: generate new RSA pub and priv keys, return paths to files.

    pphr is expected to be a file here.
    """
    if use_rsautl:
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-des3', '-passout', 'file:' + pphr]
        _sysCall(cmdGEN + [str(bits)])

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv, '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'file:' + pphr]
        _sysCall(cmdEXTpub)
    else:
        # NOT TESTED
        # Generate key pairs with passphrases from file:
        #  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
        #       -pkeyopt rsa_keygen_pubexp:3 -out privkey-ID.pem
        #  openssl pkey -in privkey-ID.pem -des3 -out privpphr-ID.pem
        #       -passout file:pphr.test
        # Or just one command:
        # openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
        #       -pkeyopt rsa_keygen_pubexp:3 -out privpphr-ID.pem
        #       -des3 -pass file:pphr.test
        cmdGEN = [OPENSSL, 'genpkey', '-algorithm', 'RSA',
                  '-pkeyopt', 'rsa_keygen_bits:' + str(bits),
                  '-pkeyopt', 'rsa_keygen_pubexp:3',  # 3 OK if pad=OAEP
                  '-out', priv]
        _sysCall(cmdGEN)

        if pphr:
            cmdENC = [OPENSSL, 'pkey', '-in', priv, '-des3',  '-out',
                      priv + '.des3', '-passout', 'file:' + pphr]
            _sysCall(cmdENC)
        if pphr:
            assert 'ENCRYPTED' in open(priv + '.des3').read()

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'pkey', '-in', priv, '-out', pub, '-pubout']
        if pphr:
            cmdEXTpub += ['-passin', 'file:' + pphr]
        _sysCall(cmdEXTpub)

    return abspath(pub), abspath(priv)


def genRsaKeys(pub='pub.pem', priv='priv.pem', pphr=None, bits=2048):
    """Dialog to generate an RSA key pair, with optional passphrase.

    Bare bones. Works but not user-friendly. Needs lots of documentation.
    Will need the passphrase saved in a file to use it with decrypt, etc.
    """
    pub = _uniqFile(pub)
    priv = _uniqFile(priv)
    print('RSA key generation. 16 char minimum passphrase.')
    if not pphr:
        pphr = getpass.getpass('Passphrase: ')
        if pphr:
            pphr2 = getpass.getpass('same again: ')
            if pphr != pphr2:
                print('  > differ, exiting <')
                return
        else:
            print('  > no passphrase, proceeding anyway <')
    if pphr and len(pphr) < 16:
        print('  > too short; exiting <')
        return
    if python_version > '3.':
        b = eval(input('RSA key length (2048 or 4096): '))
    else:
        b = raw_input('RSA key length (2048 or 4096): ')
        if b in ['2048', '4096']:
            bits = b
    bits_msg = '  using %s' % bits
    print(bits_msg)
    ent_msg = 'entropy: ' + _entropy()
    print(ent_msg)

    try:
        umask_restore = os.umask(UMASK)
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-des3', '-passout', 'stdin']
        _sysCall(cmdGEN + [str(bits)], stdin=pphr)

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv, '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'stdin']
        _sysCall(cmdEXTpub, stdin=pphr)
    finally:
        os.umask(umask_restore)

    pub = abspath(pub)
    priv = abspath(priv)
    pub_msg = 'public key:  ' + pub
    print(pub_msg)
    priv_msg = 'private key: ' + priv
    print(priv_msg)
    print('Keep the private key private, and remember your passphrase!')
    return pub, priv


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
        if not os.path.isfile(priv):
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
        test_codec.register(default_codec)
        assert len(list(test_codec.keys())) == 2

    def test_bit_count(self):
        # bit count using a known pub key
        logging.debug('test bit_count')
        os.chdir(mkdtemp())
        pub, __, __, bits, __ = self._knownValues()
        assert int(bits) == numBits(pub)

    def test_padding(self):
        known_size = 128
        orig = b'a' * known_size
        tmp1 = 'padtest.txt'
        tmp2 = 'padtest2.txt'
        with open(tmp1, 'wb') as fd:
            fd.write(orig)
        with open(tmp2, 'wb') as fd:
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

        # tmp1 is unpadded at this point:
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
        global MAX_FILE_SIZE
        MAX_restore = MAX_FILE_SIZE
        good_max_file_size = bool(MAX_FILE_SIZE <= 2 ** 30)
        MAX_FILE_SIZE = 2 ** 8
        tmpmax = 'maxsize.txt'
        with open(tmpmax, 'w+b') as fd:
            fd.write('abcd' * MAX_FILE_SIZE)  # ensure too large
        with pytest.raises(ValueError):
            pad(tmpmax)
        with pytest.raises(ValueError):  # fake pubkey, just use tmpmax again
            encrypt(tmpmax, tmpmax)
        MAX_FILE_SIZE = MAX_restore

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
        pub1, priv1 = _genRsa(pubTmp1, prvTmp1, pphr1, testBits)

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
        pub2, priv2 = _genRsa(pubTmp2, prvTmp2, pphr1, testBits)
        with pytest.raises(DecryptError):
            dataEncDec = decrypt(dataEnc, priv2, pphr1)

        # should refuse-to-encrypt if pub key is too short:
        pub256, __ = _genRsa('pub256.pem', 'priv256.pem', bits=256)
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
        dates = list(md.keys())
        hashes = [md[d]['sha256 of encrypted file'] for d in dates]
        assert len(hashes) == len(set(hashes)) == 3
        assert ('meta-data %s' % NO_DATE) in dates

        # Should be only one hmac-sha256 present; hashing tested in test_hmac:
        hmacs = [md[d]['hmac-sha256 of encrypted file'] for d in dates
                 if 'hmac-sha256 of encrypted file' in list(md[d].keys())]
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
        for i in range(tw_reps):
            with open(tw_path, 'wb') as fd:
                fd.write(b'\0')
            code, links, t1 = wipe(tw_path)
            assert code == pfs_WIPED
            assert links == 1
            wipe_times.append(t1)
        unlink_times = []
        for i in range(tw_reps):
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
        for i in range(numlinks):
            os.link(tw_path, tw_path + 'hardlink' + str(i))

        hardlinks = os.stat(tw_path)[stat.ST_NLINK]
        code, links, __ = wipe(tw_path)
        assert links == numlinks + 1  # +1 for itself
        assert links == hardlinks

    def test_add_new_codec(self):
        import codecs
        global _decrypt_rot13
        global _encrypt_rot13

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

# Basic set-up (order matters) ------------------------------------------------
logging, loggingID, logging_t0, log_sysCalls = _setup_logging()
OPENSSL, opensslVersion, use_rsautl = _get_openssl_info()
have_wipe_tool, WIPE_TOOL, WIPE_OPTS = _get_wipe_info()

default_codec = {'_encrypt_rsa_aes256cbc': _encrypt_rsa_aes256cbc,
                 '_decrypt_rsa_aes256cbc': _decrypt_rsa_aes256cbc}
codec = PFSCodecRegistry(default_codec)

if __name__ == '__main__':
    logging.info("%s with %s" % (lib_name, opensslVersion))
    if '--debug' in sys.argv:
        global pytest
        import pytest

        t0 = time.time()
        ts = Tests()
        tests = [t for t in dir(ts) if t.startswith('test_')]
        for test in tests:
            try:
                eval('ts.' + test + '()')
            except:
                result = test + ' FAILED'
                print(result)
        logging.info("%.4fs for tests" % (time.time() - t0))
    else:
        """pass sys.args to encrypt or decrypt
        """
        logging.info(OPENSSL)
        if sys.argv[1] in ['enc', 'dec']:
            sys.argv[1] += 'rypt'
        if sys.argv[1] in ['encrypt', 'decrypt', 'pad', 'unpad']:
            cmd = sys.argv[1]
            if cmd == 'unpad':
                cmd = '_unpad_strict'
            del sys.argv[1]
            result = eval(cmd + '(*sys.argv[1:])')
            print(result)  # full path to file
        else:
            print(usage)
            sys.exit()
