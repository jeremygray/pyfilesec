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


__version__ = '0.1.5'
__author__ = 'Jeremy R. Gray'
__contact__ = 'jrgray@gmail.com'

import sys
from platform import python_version
import os
from os.path import abspath, isfile, getsize
import stat
import shutil
import tarfile
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


lib_name = 'pyFileSec'
lib_path = abspath(__file__)
usage = """%(name)s v%(version)s

  File privacy and integrity for psychology and human neuroscience research:
    encrypt, decrypt, sign, verify, rotate, generate passwords (RSA keys),
    secure delete, pad (to obscure file-size), & archive.
    Requires Python 2.6+, and OpenSSL 0.9.8 or higher.

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
    --openssl=/path/to/openssl : binary file to use for openssl calls
    --genrsa    : RSA key generation dialog

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
if python_version < '3.':
    input23 = raw_input
else:
    input23 = input

if sys.platform == 'win32':
    get_time = time.clock
    from win32com.shell import shell
    user_can_admin = shell.IsUserAnAdmin()
    user_can_link = user_can_admin  # for fsutil hardlink
else:
    get_time = time.time
    user_can_admin = False  # not known; not needed
    user_can_link = True


class PyFileSecError(Exception):
    """Base exception for pyFileSec errors."""

class PublicKeyTooShortError(PyFileSecError):
    '''Error to indicate that a public key is not long enough.'''

class DecryptError(PyFileSecError):
    '''Error to indicate that decryption failed.'''

class PrivateKeyError(PyFileSecError):
    '''Error to indicate that loading a private key failed.'''

class InternalFormatError(PyFileSecError):
    '''Error to indicate bad format or file name inside archive file.'''

class PaddingError(PyFileSecError):
    '''Error to indicate bad file padding.'''


class PFSCodecRegistry(object):
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

        # allow _dec without _enc, but not vice-verse:
        for key in list(new_functions.keys()):
            if key.startswith('_dec'):
                continue
            assert key.startswith('_enc')
            dec_twin = key.replace('_enc', '_dec', 1)
            if not dec_twin in list(self._functions.keys()):
                _fatal('method "%s" incomplete codec pair' % key)
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
        return None

    def is_registered(self, fxn_name):
        """Returns True if `fxn_name` is registered; validated at registration.
        """
        return fxn_name in self._functions


class SetUmask(object):
    """Decorator for functions that create files.
    """
    def __init__(self, fxn):
        self.fxn = fxn

    def __call__(self, *args, **kwargs):
        restore = os.umask(UMASK)
        val = self.fxn(*args, **kwargs)
        os.umask(restore)
        return val


def _setup_logging():
    # Logging:  stderr, or psychopy.logging if we're a PsychoPy module
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
    verbose = bool('--verbose' in sys.argv or '--debug' in sys.argv)
    if '--verbose' in sys.argv:
        del(sys.argv[sys.argv.index('--verbose')])
    if not verbose:
        logging = _no_logging()
    else:
        msgfmt = "%.4f  " + lib_name + ": %s"
        logging = _log2stdout()
        if __name__ != '__main__':
            try:
                from psychopy import logging
            except:
                pass
    return logging, logging_t0


def _sys_call(cmdList, stderr=False, stdin=''):
    """Run a system command via subprocess, return stdout [, stderr].

    stdin is optional string to pipe in. Will always log a non-empty stderr.
    """
    logging.debug('_sys_call: %s' % (' '.join(cmdList)))

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
    if sys.platform in ['win32']:
        # use a bat file for openssl.cfg; create .bat if not found or broken
        # might have to move to os.environ['HOME'] to ensure write permission
        libdir = os.path.split(os.path.abspath(__file__))[0]
        bat_name = '_openssl.bat'
        OPENSSL = os.path.join(libdir, bat_name)
        if not os.path.exists(OPENSSL):
            logging.info('no working %s file; trying to recreate' % bat_name)
            default = 'C:\\OpenSSL-Win32\\bin'
            openssl_expr = 'XX-OPENSSL_PATH-XX'
            bat = """@echo off
                set PATH=""" + openssl_expr + """;%PATH%
                set OPENSSL_CONF=""" + openssl_expr + """\\openssl.cfg
                START "" /b /wait openssl.exe %*"""
            default = bat.replace(openssl_expr, default).replace('    ', '')
            with open(OPENSSL, 'wb') as fd:
                fd.write(default)
            test = _sys_call([OPENSSL, 'version'])
            if not test.startswith('OpenSSL'):
                # locate and cache result, takes 5-6 seconds:
                cmd = ['where', '/r', 'C:\\', 'openssl.exe']
                where_out = _sys_call(cmd)
                if not where_out.strip().endswith('openssl.exe'):
                    _fatal('Failed to find OpenSSL.exe.\n' +
                           'Please install under C:\ and try again.')
                guess = where_out.splitlines()[0]  # take first match
                guess_path = guess.replace(os.sep + 'openssl.exe', '')
                where_bat = bat.replace(openssl_expr, guess_path)
                with open(OPENSSL, 'wb') as fd:
                    fd.write(where_bat)
        logging.info('will use .bat file for OpenSSL: %s' % OPENSSL)
    for i, arg in enumerate(sys.argv):
        if arg.startswith('--openssl='):
            # spaces in path ok if parses as one argument
            OPENSSL = arg.replace('--openssl=', '')
            del(sys.argv[i])
            logging.info('Option requesting OpenSSL version: ' + OPENSSL)
            break
    else:
        if sys.platform not in ['win32']:
            OPENSSL = _sys_call(['which', 'openssl'])
            if OPENSSL not in ['/usr/bin/openssl']:
                msg = 'unexpected location for openssl binary: %s' % OPENSSL
                logging.warning(msg)
        #else:
        #    OPENSSL = bat_file  # already set
    if not isfile(OPENSSL):
        msg = 'Could not find openssl, tried: %s' % OPENSSL
        _fatal(msg, RuntimeError)

    openssl_version = _sys_call([OPENSSL, 'version'])
    if openssl_version.lower() < 'openssl 0.9.8':
        _fatal('OpenSSL too old (%s)' % openssl_version, RuntimeError)
    logging.info('OpenSSL binary  = %s' % OPENSSL)
    logging.info('OpenSSL version = %s' % openssl_version)

    # use_rsautl = (openssl_version < 'OpenSSL 1.0')  # ideally use pkeyutl
    # but -decrypt with passphrase fails with pkeyutl, so always use rsautl:
    use_rsautl = True

    return OPENSSL, openssl_version, use_rsautl


def _get_destroy_info():
    """Find and return into about secure file removal tools on this system.
    """
    if sys.platform in ['darwin']:
        destroy_TOOL = _sys_call(['which', 'srm'])
        destroy_OPTS = ('-f', '-z', '--medium')  # 7 US DoD compliant passes
    elif sys.platform.startswith('linux'):
        destroy_TOOL = _sys_call(['which', 'shred'])
        destroy_OPTS = ('-f', '-u', '-n', '7')
    elif sys.platform in ['win32']:
        libdir = os.path.split(os.path.abspath(__file__))[0]
        default = os.path.join(libdir, '_sdelete.bat')
        if not isfile(default):
            guess = _sys_call(['where', '/r', 'C:\\', 'sdelete.exe'])
            if not guess.strip().endswith('sdelete.exe'):
                _fatal('Failed to find sdelete.exe. Please install ' +
                       'under C:\\, run it manually to accept the terms.')
            bat = """@echo off
                START "" /b /wait SDELETE %*""".replace('SDELETE', guess)
            with open(default, 'wb') as fd:
                fd.write(bat)
        destroy_TOOL = default
        sd_version = _sys_call([destroy_TOOL]).splitlines()[0]
        logging.info('Found ' + sd_version)
        destroy_OPTS = ('-q', '-p', '7')
    else:
        destroy_TOOL = ''
        destroy_OPTS = ()
    if not isfile(destroy_TOOL):
        destroy_TOOL = ''

    return destroy_TOOL, destroy_OPTS


def _fatal(msg, err=ValueError):
    """log then raise err(msg).
    """
    logging.error(msg)
    raise err(msg)


# CONSTANTS ------------ (with code folding) ------------
if True:
    RSA_PADDING = '-oaep'  # actual arg for openssl rsautl in encrypt, decrypt

    ARCHIVE_EXT = '.enc'  # extension for for tgz of AES, PWD.RSA, META
    AES_EXT = '.aes256'   # extension for AES encrypted data file
    RSA_EXT = '.pwdrsa'   # extension for RSA-encrypted AES-pwd (ciphertext)
    META_EXT = '.meta'    # extension for meta-data

    # warn that operations will take a while, check disk space, ...
    LRG_FILE_WARN = 2 ** 24  # 17M; used in tests but not implemented elsewhere
    MAX_FILE_SIZE = 2 ** 33  # 8G; larger maybe fine, untested, will affect pad

    # file-length padding:
    PFS_PAD = lib_name + '_padded'  # label = 'file is padded'
    PAD_STR = 'pad='    # label means 'pad length = \d\d\d\d\d\d\d\d\d\d bytes'
    PAD_BYTE = b'\0'    # actual byte to use; value unimportant
    assert not PAD_BYTE in PFS_PAD
    assert len(PAD_BYTE) == 1
    PAD_LEN = len(PAD_STR + PFS_PAD) + 10 + 2  # len of info about padding
    # 10 = # digits in max file size, also works for 4G files
    #  2 = # extra bytes, one at end, one between PAD_STR and PFS_PAD labels

    # value to use for missing meta-data:
    META_DATA_UNKNOWN = '(meta-data unknown)'

    # used if user suppresses the date; will sort before a numerical date:
    DATE_UNKNOWN = '(date-time unknown)'

    whitespace_re = re.compile('\s')
    hexdigits_re = re.compile('^[\dA-F]+$|^[\da-f]+$')

    # destroy() return codes:
    pfs_DESTROYED = 1
    pfs_UNLINKED = 0
    pfs_UNKNOWN = -1

    # decrypted file status:
    PERMISSIONS = 0o600  # for decrypted file, no execute, no group, no other
    UMASK = 0o077  # need u+x permission for diretories


def _entropy_check():
    """Basic query for some indication that entropy is available.
    """
    if sys.platform == 'darwin':
        # SecurityServer daemon is supposed to ensure entropy is available:
        ps = _sys_call(['ps', '-e'])
        securityd = _sys_call(['which', 'securityd'])  # full path
        if securityd in ps:
            e = securityd + ' running'
        else:
            e = ''
    elif sys.platform.startswith('linux'):
        avail = _sys_call(['cat', '/proc/sys/kernel/random/entropy_avail'])
        e = 'entropy_avail: ' + avail
    else:
        e = '(unknown)'
    return e


def _sha256(filename):
    """Return sha256 hex-digest of a file, buffered for large files.
    """
    # from stackoverflow:
    dgst = hashlib.sha256()
    with open(filename, mode='rb') as fd:
        for buf in iter(partial(fd.read, 2048), b''):  # null byte sentinel
            dgst.update(buf)
    return dgst.hexdigest()


def hmac_sha256(key, filename):
    """Return a hash-based message authentication code (HMAC), using SHA256.

    The key is a string value.
    """
    if not key:
        return None
    if getsize(filename) > MAX_FILE_SIZE:
        _fatal('hmac_sha256: msg too large (> max file size)')
    cmd_HMAC = [OPENSSL, 'dgst', '-sha256', '-hmac', key, filename]
    hmac_openssl = _sys_call(cmd_HMAC)

    return hmac_openssl


def get_key_length(pubkey):
    """Return the number of bits in a RSA public key.
    """
    name = 'get_key_length'
    cmdGETMOD = [OPENSSL, 'rsa', '-modulus', '-in', pubkey, '-pubin', '-noout']
    modulus = _sys_call(cmdGETMOD).replace('Modulus=', '')
    if not modulus:
        _fatal(name + ': no RSA modulus in pub "%s" (bad .pem file?)' % pubkey)
    if not hexdigits_re.match(modulus):
        _fatal(name + ': expected hex digits in pubkey RSA modulus')
    return len(modulus) * 4


def _printable_pwd(nbits=256):
    """Return a string of hex digits with n random bits, zero-padded.

    Uses random.SystemRandom().getrandbits().
    """
    pwd = hex(sysRand.getrandbits(nbits))
    return pwd.strip('L').replace('0x', '', 1).zfill(nbits // 4)


@SetUmask
def make_archive(paths, name='', keep=True):
    """Make a tgz file from a list of paths, set permissions. Directories ok.

    Eventually might take an arg to decide whether to use tar or zip.
    Just a tarfile wrapper with extension, permissions, unlink options.
    unlink is whether to unlink the original files after making an archive, not
    a secure-delete option.
    """
    if isinstance(paths, str):
        paths = [paths]
    if not name:
        name = os.path.splitext(paths[0])[0].strip(os.sep) + '.tgz'
    assert not isfile(name)
    tar_fd = tarfile.open(name, "w:gz")
    for p in paths:
        tar_fd.add(p, recursive=True)  # True by default, get whole directory
        if not keep:
            try:
                shutil.rmtree(p)  # might be a directory
            except OSError:
                os.unlink(p)
    tar_fd.close()
    os.chmod(name, PERMISSIONS)  # redundant, but not enough on win?

    return name


def destroy(filename, cmdList=()):
    """Try to secure-delete a file; returns (status, link count, time taken).

    Calls an OS-specific secure-delete utility, defaulting to::

        Mac:     /usr/bin/srm   -f -z --medium  filename
        Linux:   /usr/bin/shred -f -u -n 7 filename
        Windows: sdelete.exe    -q -p 7 filename

    If these are not available, `destroy` will warn and fall through to trying
    to merely overwrite the data with 0's (with unknown effectiveness)

    As an alternative, a custom command sequence can be specified::

        cmdList = (command, option1, option2, ..., filename)

    Ideally avoid the need to destroy files. Keep all sensitive data in RAM.
    File systems that are journaled, have RAID, are mirrored, or other back-up
    are much trickier to secure-delete.

    `destroy` may fail to remove all traces of a file if multiple hard-links
    exist for the file. For this reason, the original link count is returned.
    In the case of multiple hardlinks, Linux (shred) and Windows (sdelete)
    do appear to destroy the data, whereas Mac (srm) will not.

    The time required can help confirm whether it was a secure removal (slow)
    or an ordinary removal (unlinking is fast).

    If an open file-descriptor is given instead of a filename, destroy() will
    try to secure-delete the contents and close the file. This is intended to
    be useful when working with NamedTemporaryFiles, which vanish when closed.
    """

    name = 'destroy'
    got_file = hasattr(filename, 'file') and hasattr(filename, 'close')
    if got_file:
        filename, file_in = filename.name, filename
        file_in.seek(0)

    os.chmod(filename, 0o600)  # raises OSError if no file or cant change
    filename = abspath(filename)
    t0 = get_time()

    # Try to detect & inform about hardlinks:
    # srm will detect but not affect those links or the inode data
    # shred and fsutil will blast the inode's data, but not unlink other links
    orig_links = _get_hardlink_count(filename)
    if sys.platform != 'win32' and orig_links > 1:
        mount_path = abspath(filename)
        while not os.path.ismount(mount_path):
            mount_path = os.path.dirname(mount_path)
        msg = name + """: '%s' (inode %d) has other hardlinks:
            `find %s -xdev -inum %d`""".replace('    ', '')
        file_stat = os.stat(filename)
        inode = file_stat[stat.ST_INO]
        vals = (filename, inode, mount_path, inode)
        logging.warning(msg % vals)

    if not cmdList:
        cmdList = (destroy_TOOL,) + destroy_OPTS + (filename,)
    else:
        logging.info(name + ': %s' % ' '.join(cmdList))

    good_sys_call = False
    try:
        __, err = _sys_call(cmdList, stderr=True)
        good_sys_call = not err
    except OSError as e:
        good_sys_call = False
        logging.warning(name + ': %s' % e)
        logging.warning(name + ': %s' % ' '.join(cmdList))
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
                return pfs_DESTROYED, orig_links, get_time() - t0
            return pfs_UNKNOWN, orig_links, get_time() - t0

    # file should have been overwritten and removed; if not...
    logging.warning(name + ': falling through to 1 pass of zeros')
    with open(filename, 'wb') as fd:
        fd.write(chr(0) * getsize(filename))
    shutil.rmtree(filename, ignore_errors=True)
    assert not isfile(filename)  # yikes, file remains

    return pfs_UNKNOWN, orig_links, get_time() - t0


def _get_file_permissions(filename):
    return int(oct(os.stat(filename)[stat.ST_MODE])[-3:], 8)


def _set_file_permissions(filename, mode):
    pass
    # import win32security  # looks interesting
    # info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | \
    #           DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
    # info = 1,3,7 works as admin, 15 not enough priv; SACL = 8
    # win32security.GetFileSecurity(filename, info)
    # win32security.SetFileSecurity


def _get_hardlink_count(filename):
    if sys.platform == 'win32':
        if user_can_link:
            cmd = ('fsutil', 'hardlink', 'list', filename)
            links = _sys_call(cmd)
            count = len([f for f in links.splitlines() if f.strip()])
        else:
            logging.warning('need to be an admin to use fsutil.exe (hardlink)')
            count = -1
    else:
        count = os.stat(filename)[stat.ST_NLINK]
    return count


def _uniq_file(filename):
    """Avoid file name collisions by appending a count before extension.
    """
    count = 0
    base, filext = os.path.splitext(filename)
    while isfile(filename) or os.path.isdir(filename):
        count += 1
        filename = base + '(' + str(count) + ')' + filext
    return filename


def _get_no_metadata():
    """Return valid meta-data format, with no data
    """
    return {'meta-data %s' % DATE_UNKNOWN: META_DATA_UNKNOWN}


def _get_metadata(datafile, data_enc, pub, enc_method, date=True, hmac=None):
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
        'sha256 of encrypted file': '%s' % _sha256(data_enc)}
    if hmac:
        hmac_val = hmac_sha256(hmac, data_enc)
        md.update({'hmac-sha256 of encrypted file': hmac_val})
    md.update({'sha256 of public key': _sha256(pub),
        'encryption method': lib_name + '.' + enc_method,
        'sha256 of lib %s' % lib_name: _sha256(lib_path),
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


def load_metadata(md_file):
    """Convenience function to read meta-data from a file, return it as a dict.
    """
    return json.load(open(md_file, 'rb'))


def log_metadata(md, log=True):
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
    str(max_file_size), where max_file_size is 8G by default. Changes
    to the max file size can thus cause pad / unpad failures.

    Special size values:

       0 :  remove any existing padding
       -1 : remove padding if its present, raise PaddingError if not present
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

    Truncates the file to remove padding; does not `destroy` the padding.
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
            # try to overwrite padding info, unknown effectiveness
            overwrite = min(PAD_LEN, filelen - new_length)
            if overwrite > 0:
                for i in range(7):
                    fd.seek(filelen - overwrite)
                    fd.write(_printable_pwd(overwrite * 4))
            # trim the padding length info
            fd.truncate(new_length)
            logging.info(name + 'truncated the file to remove padding')

    return getsize(filename)


@SetUmask
def encrypt(datafile, pub, meta=True, date=True, keep=False,
            enc_method='_encrypt_rsa_aes256cbc', hmac_key=None):
    """Encrypt a file using AES-256, encrypt the password with RSA public-key.

    Returns: full path to the encrypted file (= .tgz bundle of 3 files).

    The idea is that you can have and share a public key, which anyone can
    use to encrypt things that only you can decrypt. Generating good keys and
    managing them is non-trivial (see `genRsaKeys()` and documentation).

    By default, the original plaintext is secure-deleted after encryption (see
    parameter `keep=False`).

    Files larger than 8G before encryption will raise a
    ValueError. To mask small file sizes, `pad()` them to a desired minimum
    size before calling `encrypt()`. To encrypt a directory, first tar or zip
    it to create a single file, which you can then `encrypt()`.

    :Parameters:

        `datafile`:
            The path (name) of the original plaintext file to be encrypted.
            NB: To encrypt a whole directory, first convert it to a single
            file (using `archive`), then encrypt the archive file.
        `pub`:
            The public key to use, specified as the path to a .pem file. The
            minimum recommended key length is 2048 bits; 1024 is allowed but
            strongly discouraged as it is not secure.
        `meta`:
            If `True` or a dict, include meta-data plaintext in the archive::

                original file name & sha256 of encrypted
                platform & date
                openssl version, padding
                pubkey info (to aid in key rotation)

                If given a dict, the dict will be updated with new meta-data.
                This allows all meta-data to be retained from the initial
                encryption and multiple rotations of the encryption.

            If `False`, explicitly indicate that the meta-data were suppressed.
        `date`:
            True mean save the date in the clear-text meta-data.
            Use False if the date is sensitive.
            File time-stamps are NOT obscured in any way.
        `keep`:
            False = remove original (unencrypted) file
            True  = leave original file
        `enc_method`:
            name of the function / method to use (currently only one option)
        `hmac_key`:
            optional key to use for HMAC-SHA256, post-encryption; if a key is
            provided, the HMAC will be generated and stored with the meta-data
            (encrypt-then-MAC).

    """
    name = 'encrypt: '
    logging.debug(name + 'start')
    if not codec.is_registered(enc_method):
        _fatal(name + "requested encMethod '%s' not registered" % enc_method)
    if not pub or not isfile(pub):
        _fatal(name + "no public-key.pem; file '%s' not found" % pub)
    if not datafile or not isfile(datafile):
        _fatal(name + "no data; file '%s' not found" % datafile)

    # Handle file size constraints:
    size = getsize(datafile)
    if size > MAX_FILE_SIZE:
        _fatal(name + "file too large (max size %d bytes)" % MAX_FILE_SIZE)

    # Refuse to proceed without a pub key of sufficient bits:
    bits = get_key_length(pub)
    logging.info(name + 'pubkey length %d' % bits)
    if bits < 1024:
        _fatal("public key < 1024 bits; too short!", PublicKeyTooShortError)
    if bits < 2048:
        logging.error(name + 'public key < 2048 bits, no real security')
    if not keep in [True, False]:
        _fatal(name + "bad value for 'keep' parameter")

    # Do the encryption, using a registered `encMethod`:
    ENCRYPT_FXN = codec.get_function(enc_method)
    data_enc, pwd_rsa = ENCRYPT_FXN(datafile, pub, OPENSSL)
    ok_encrypt = (isfile(data_enc) and
                    os.stat(data_enc)[stat.ST_SIZE] and
                    isfile(pwd_rsa) and
                    os.stat(pwd_rsa)[stat.ST_SIZE] >= 128)

    # Get and save meta-data (including HMAC):
    if not meta:
        md = _get_no_metadata()
    else:
        metadata = os.path.split(datafile)[1] + META_EXT
        md = _get_metadata(datafile, data_enc, pub, enc_method, date, hmac_key)
        if not isinstance(meta, dict):
            logging.warning(name + 'non-dict value for meta; using default')
            meta = _get_no_metadata()
        meta.update(md)
        with open(metadata, 'w+b') as fd:
            json.dump(meta, fd)

    # Bundle the files: (cipher text, rsa pwd, meta-data) --> data.enc:
    fullpath_files = [data_enc, pwd_rsa]
    if meta:
        fullpath_files.append(metadata)

    # get file names no path info & bundle them together as a single file
    files = [os.path.split(f)[1] for f in fullpath_files]
    archive = _uniq_file(os.path.splitext(datafile)[0] + ARCHIVE_EXT)
    make_archive(files, archive, keep=False)

    if not keep:
        # secure-delete unencrypted original, unless encrypt did not succeed:
        ok_to_destroy = (ok_encrypt and
                      isfile(archive) and
                      os.stat(archive)[stat.ST_SIZE])
        if ok_to_destroy:
            destroy(datafile)
            logging.info(name + 'destroy()ed original file')
        else:
            logging.error(name + 'retaining original file, not destroy()ed')

    return abspath(archive)


@SetUmask
def _encrypt_rsa_aes256cbc(datafile, pub, OPENSSL=''):
    """Encrypt a datafile using openssl to do rsa pub-key + aes256cbc.
    """
    name = '_encrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # Define file paths:
    data_enc = _uniq_file(abspath(datafile) + AES_EXT)
    pwd_rsa = _uniq_file(data_enc + RSA_EXT)

    # Define command to RSA-PUBKEY-encrypt the pwd, save ciphertext to file:
    if use_rsautl:
        cmd_RSA = [OPENSSL, 'rsautl',
              '-out', pwd_rsa,
              '-inkey', pub,
              '-keyform', 'PEM',
              '-pubin',
              RSA_PADDING, '-encrypt']
    else:
        raise NotImplementedError

    # Define command to AES-256-CBC encrypt datafile using the password:
    cmd_AES = [OPENSSL, 'enc', '-aes-256-cbc',
              '-a', '-salt',
              '-in', datafile,
              '-out', data_enc,
              '-pass', 'stdin']

    # Generate a password, ensure no whitespace (should never happen):
    pwd = _printable_pwd(nbits=256)
    assert not whitespace_re.search(pwd)
    try:
        # encrypt the password:
        _sys_call(cmd_RSA, stdin=pwd)
        # encrypt the file, using password; takes a long time for large file:
        _sys_call(cmd_AES, stdin=pwd)
        # better to return immediately, del(pwd); using stdin blocks return
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try

    return abspath(data_enc), abspath(pwd_rsa)


@SetUmask
def _unpack(data_enc):
    """Extract files from archive, return paths to files.
    """
    name = 'unpack'
    logging.debug(name + ': start')

    # Check for bad paths:
    if not data_enc or not isfile(data_enc):
        _fatal("could not find <file>%s '%s'" % (ARCHIVE_EXT, str(data_enc)))
    if not tarfile.is_tarfile(data_enc):
        _fatal(name + ': %s not expected format (.tgz)' % data_enc,
               InternalFormatError)

    # Check for bad internal paths:
    #    can't "with open(tarfile...) as tar" in python 2.6.6
    tar = tarfile.open(data_enc, "r:gz")
    badNames = [f for f in tar.getmembers()
                if f.name[0] in ['.', os.sep] or f.name[1:3] == ':\\']
    if badNames:
        _fatal(name + ': bad/dubious internal file names' % os.sep,
               InternalFormatError)

    # Extract:
    tmp_dir = mkdtemp()
    tar.extractall(path=tmp_dir)
    tar.close()

    fileList = os.listdir(tmp_dir)
    data_aes = pwdFileRsa = meta_file = None
    for fname in fileList:
        if fname.endswith(AES_EXT):
            data_aes = os.path.join(tmp_dir, fname)
        elif fname.endswith(RSA_EXT):
            pwdFileRsa = os.path.join(tmp_dir, fname)
        elif fname.endswith(META_EXT):
            meta_file = os.path.join(tmp_dir, fname)
        else:
            _fatal(name + ': unexpected file in archive',
                   InternalFormatError)

    return data_aes, pwdFileRsa, meta_file


def _get_dec_method(meta_file, dec_method):
    """Return a valid decryption method, based on meta-data or default
    """
    if meta_file:
        md = load_metadata(meta_file)
        dates = list(md.keys())  # dates of meta-data events
        most_recent = sorted(dates)[-1]
        enc_method = md[most_recent]['encryption method'].split('.')[1]
        _dec_from_enc = enc_method.replace('_encrypt', '_decrypt')

        if dec_method:
            if dec_method != _dec_from_enc:
                msg = 'requested decryption function (%s)' % dec_method +\
                      ' != encryption function (meta-data: %s)' % enc_method
                logging.warning(msg)
        else:
            dec_method = _dec_from_enc
            logging.info('implicitly want "' + dec_method + '" (meta-data)')
        if not dec_method in globals():
            _fatal("decryption function '%s' not available" % dec_method)
    else:
        # can't infer, no meta-data
        if not dec_method:
            # ... and nothing explicit either, so go with default:
            logging.info('falling through to default decryption')
            available = [f for f in list(default_codec.keys())
                         if f.startswith('_decrypt_')]
            dec_method = available[0]

    if not codec.is_registered(dec_method):
        _fatal("_get_dec_method: dec fxn '%s' not registered" % dec_method)
    logging.info('_get_dec_method: dec fxn set to: ' + str(dec_method))

    return dec_method


@SetUmask
def decrypt(data_enc, priv, pphr='', outFile='', dec_method=None):
    """Decrypt a file that was encoded using `encrypt()`.

    To get the data back, need two files: `data.enc` and `privkey.pem`.
    If the private key has a passphrase, you'll need to provide that too.
    `pphr` should be the passphrase itself (a string), not a file name.

    Works on a copy of data.enc, tries to decrypt, clean-up only those files.
    The original is never touched beyond making a copy.
    """
    name = 'decrypt: '
    logging.debug(name + 'start')

    priv = abspath(priv)
    data_enc = abspath(data_enc)
    if pphr and isfile(pphr):
        pphr = open(abspath(pphr), 'rb').read()
    elif 'ENCRYPTED' in open(priv, 'r').read().upper():
        _fatal(name + 'missing passphrase (encrypted privkey)', DecryptError)

    # Extract files from the archive (dataFileEnc) into the same directory,
    # avoid name collisions, decrypt:
    try:
        # Unpack from archive into the same dir as the .enc file:
        dest_dir = os.path.split(data_enc)[0]
        logging.info('decrypting into %s' % dest_dir)

        # Unpack the .enc file bundle:
        data_aes, pwd_file, meta_file = _unpack(data_enc)

        # Get a valid decrypt method, from meta-data or argument:
        logging.info("meta-data file: " + str(meta_file))
        clear_text = None  # in case _get_dec_method raise()es
        dec_method = _get_dec_method(meta_file, dec_method)
        if not dec_method:
            _fatal('Could not get a valid decryption method', DecryptError)

        # Decrypt:
        DECRYPT_FXN = codec.get_function(dec_method)
        data_dec = DECRYPT_FXN(data_aes, pwd_file, priv, pphr, outFile,
                                  OPENSSL=OPENSSL)
        os.chmod(data_dec, PERMISSIONS)  # hopefully redundant
        perm_str = '0o' + oct(PERMISSIONS)[1:]
        logging.info('decrypted, permissions ' + perm_str + ': ' + data_dec)

        # Rename decrypted and meta files:
        _new_path = os.path.join(dest_dir, data_dec.split(os.sep)[-1])
        clear_text = _uniq_file(_new_path)
        try:
            os.rename(data_dec, clear_text)
        except OSError:
            shutil.copy(data_dec, clear_text)
            destroy(data_dec)
        if meta_file:
            newMeta = _uniq_file(clear_text + META_EXT)
            try:
                os.rename(meta_file, newMeta)
            except OSError:
                shutil.copy(meta_file, newMeta)
                destroy(meta_file)
    finally:
        try:
            os.chmod(clear_text, PERMISSIONS)  # should be done
            os.chmod(newMeta, PERMISSIONS)  # typically not done yet
        except:
            pass

    return abspath(clear_text)


@SetUmask
def _decrypt_rsa_aes256cbc(data_enc, pwd_rsa, priv, pphr=None,
                           outFile='', OPENSSL=''):
    """Decrypt a file that was encoded by _encrypt_rsa_aes256cbc()
    """
    name = '_decrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # set the name for decrypted file:
    if outFile:
        data_dec = outFile
    else:
        data_dec = os.path.splitext(abspath(data_enc))[0]
    #else:
    #    data_dec = abspath(data_enc)

    # set up the command to retrieve password from pwdFileRsa
    if use_rsautl:
        cmdRSA = [OPENSSL, 'rsautl',
                  '-in', pwd_rsa,
                  '-inkey', priv]
        if pphr:
            if isfile(pphr):
                logging.warning(name + ': reading passphrase from file')
                pphr = open(pphr, 'rb').read()
            cmdRSA += ['-passin', 'stdin']
        cmdRSA += [RSA_PADDING, '-decrypt']
    else:
        raise NotImplementedError

    # set up the command to decrypt the data using pwd:
    cmdAES = [OPENSSL, 'enc', '-d', '-aes-256-cbc', '-a',
              '-in', data_enc,
              '-out', data_dec,
              '-pass', 'stdin']

    # retrieve password (to RAM), then use to decrypt the data file:
    try:
        if pphr and not isfile(pphr):
            pwd, se_RSA = _sys_call(cmdRSA, stdin=pphr, stderr=True)  # want se
        else:
            pwd, se_RSA = _sys_call(cmdRSA, stderr=True)  # want se, parse
        __, se_AES = _sys_call(cmdAES, stdin=pwd, stderr=True)
    except:
        if isfile(data_dec):
            destroy(data_dec)
        _fatal('%s: Could not decrypt (exception in RSA or AES step)' % name,
               DecryptError)
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try
            # e.g., manual interrupt when queried for passphrase

    se_RSA = se_RSA.replace("Loading 'screen' into random state - done", '')
    if se_RSA.strip():
        if 'unable to load Private Key' in se_RSA:
            _fatal('%s: unable to load Private Key' % name, PrivateKeyError)
        elif 'RSA operation error' in se_RSA:
            _fatal("%s: can't use Priv Key; wrong key?" % name, DecryptError)
        else:
            _fatal('%s: Bad decrypt (RSA) %s' % (name, se_RSA), DecryptError)
    if se_AES:
        if 'bad decrypt' in se_AES:
            _fatal('%s: openssl bad decrypt (AES step)' % name, DecryptError)
        else:
            _fatal('%s: Bad decrypt (AES) %s' % (name, se_AES), DecryptError)

    return abspath(data_dec)


@SetUmask
def rotate(data_enc, priv_old, pub_new, pphr_old=None,
           priv_new=None, pphr_new=None,
           hmac_new=None, pad_new=None):
    """Swap old encryption for new (decrypt-then-re-encrypt).

    Returns the path to the "same" underlying file (i.e., same contents, new
    encryption). New meta-data are added alongside the original meta-data. If
    `new_pad` is given, the padding will be updated to the new value prior to
    re-encryption.

    Conceptually there are three separate steps: rotate, verify the new file,
    and destroy the old file. By default, `rotate()` will only do rotation. To
    do the other two steps, `rotate()` requires an existence proof that the new
    encrypted file can be decrypted. If decrypting the new file succeeds (which
    requires `priv_new` and `pphr_new`), then original file will be destroyed.

    The dilemma is that it would be highly undesirable to re-encrypt the data
    with a new public key for which the private key is not available. But
    simply retaining the original encrypted file is also not ideal: Key
    rotation is typically done when the old keys are no longer considered
    secure. It is desirable to destroy the old encrypted file as soon as it is
    safe to do so. Hashes are used to determine whether the file contents match
    (ignoring possible differences in padding).

    `rotate()` will generally try to be permissive about its inputs, so that
    its easy to rotate the encryption to recover from some internal formatting
    errors.
    """
    name = 'rotate'
    logging.debug(name + ': start')
    file_dec = decrypt(data_enc, priv_old, pphr=pphr_old)
    try:
        old_meta = file_dec + META_EXT

        # Always store the date of the rotation
        if isfile(old_meta):
            try:
                md = load_metadata(old_meta)
                if not type(md) == dict:
                    raise InternalFormatError
            except:
                logging.error(name + ': failed to read metadata from file')
                md = _get_no_metadata()
        else:
            md = _get_no_metadata()
        if pad_new > 0:  # can be -1
            pad(file_dec, pad_new)
        # for verification, only hash after changing the padding
        hash_old = _sha256(file_dec)
        new_enc = encrypt(file_dec, pub_new, date=True, meta=md,
                             keep=False, hmac_key=hmac_new)
    finally:
        # Never want the intermediate clear-text; encrypt() will destroy
        # it but there might be an exception before getting to encrypt()
        if isfile(file_dec):
            destroy(file_dec)
        if isfile(old_meta):
            destroy(old_meta)

    # Check the rotation if given a key to do so; destroy data_enc if safe:
    if priv_new:
        # if a hash of decrypted file is good, delete original data_enc
        new_dec = decrypt(new_enc, priv_new, pphr=pphr_new)
        hash_new = _sha256(new_dec)
        destroy(new_dec)  # just wanted to get a hash
        new_meta = new_dec + META_EXT
        if isfile(new_meta):
            destroy(new_meta)
        if hash_new != hash_old:
            _fatal(name + ': failed to verify, retaining original')
        else:
            logging.info(name + ': verified, deleting original')
            destroy(data_enc)

    return new_enc


def sign(filename, priv, pphr=None):
    """Sign a given file with a private key, via `openssl dgst`.

    Get a digest of the file, sign the digest, return base64-encoded signature.
    """
    name = 'sign'
    logging.debug(name + ': start')
    sig_out = filename + '.sig'
    if use_rsautl:
        cmd_SIGN = [OPENSSL, 'dgst', '-sign', priv, '-out', sig_out]
        if pphr:
            if isfile(pphr):
                logging.warning(name + ': reading passphrase from file')
                pphr = open(pphr, 'rb').read()
            cmd_SIGN += ['-passin', 'stdin']
        cmd_SIGN += ['-keyform', 'PEM', filename]
    else:
        raise NotImplementedError
    if pphr:
        _sys_call(cmd_SIGN, stdin=pphr)
    else:
        _sys_call(cmd_SIGN)
    sig = open(sig_out, 'rb').read()

    return b64encode(sig)


def verify(filename, pub, sig):
    """Verify signature of filename using pubkey; expects a base64-encoded sig.
    """
    name = 'verify'
    logging.debug(name + ': start')
    with NamedTemporaryFile() as sig_file:
        sig_file.write(b64decode(sig))
        sig_file.seek(0)
        if use_rsautl:
            cmd_VERIFY = [OPENSSL, 'dgst', '-verify', pub, '-keyform',
                          'PEM', '-signature', sig_file.name, filename]
        else:
            raise NotImplementedError
        result = _sys_call(cmd_VERIFY)

    return result in ['Verification OK', 'Verified OK']


# likely to remove this code, and refactor tests to use _genRsa2 (no file):
@SetUmask
def _genRsa(pub='pub.pem', priv='priv.pem', pphr=None, bits=2048):
    """For TESTS: generate new RSA pub and priv keys, return paths to files.

    pphr is expected to be in a FILE here.
    """
    if use_rsautl:
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-aes256', '-passout', 'file:' + pphr]
        _sys_call(cmdGEN + [str(bits)])

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv,
                     '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'file:' + pphr]
        _sys_call(cmdEXTpub)
    else:
        raise NotImplementedError

    return abspath(pub), abspath(priv)


@SetUmask
def _genRsa2(pub='pub.pem', priv='priv.pem', pphr=None, bits=2048):
    """Generate new RSA pub and priv keys, return paths to files.

    pphr is expected to be in a string here.
    """
    if use_rsautl:
        # Generate priv key:
        cmdGEN = [OPENSSL, 'genrsa', '-out', priv]
        if pphr:
            cmdGEN += ['-aes256', '-passout', 'stdin']
        _sys_call(cmdGEN + [str(bits)], stdin=pphr)

        # Extract pub from priv:
        cmdEXTpub = [OPENSSL, 'rsa', '-in', priv,
                     '-pubout', '-out', pub]
        if pphr:
            cmdEXTpub += ['-passin', 'stdin']
        _sys_call(cmdEXTpub, stdin=pphr)
    else:
        raise NotImplementedError

    return abspath(pub), abspath(priv)


def genRsaKeys():
    """Dialog to generate an RSA key pair, PEM format.

    Limited to 2048, 4096, 8192 bits; 1024 is not secure for medium-term
    storage, and 16384 bits is impractical. Require or generate a passphrase.

    Needs lots of documentation. Ideally, generate a strong passphrase using a
    password manager (e.g., KeePassX), save there, paste it in here.
    """
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

    pub = abspath(_uniq_file('pub_RSA.pem'))  # ensure unique, abspath
    priv = pub.replace('pub_RSA', 'priv_RSA')  # ensure a matched pair
    if os.path.exists(priv):
        msg = ('RSA key generation.\n  %s already exists\n' % priv +
               '  > Clean up files and try again. Exiting. <')
        print(msg)
        return None, None

    print('RSA key generation. Will try to create two files:')
    pub_msg = '  %s   = %s' % (os.path.split(pub)[1], pub)
    print(pub_msg)
    priv_msg = '  %s  = %s' % (os.path.split(priv)[1], priv)
    print(priv_msg)
    print('To proceed, enter a passphrase (16+ chars, return to generate).')
    pphr = getpass.getpass('Passphrase: ')
    if pphr:
        pphr2 = getpass.getpass('same again: ')
        if pphr != pphr2:
            print('  > Passphrase mismatch. Exiting. <')
            return None, None
        pphr_auto = False
    else:
        pphr = _printable_pwd(128)  # or a word-based generator?
        pphr_auto = True
    if pphr and len(pphr) < 16:
        print('  > passphrase too short; exiting <')
        return None, None
    bits = 4096  # default
    b = input23('RSA key length (2048, 4096, 8192): ')
    if b in ['2048', '4096', '8192']:
        bits = b
    bits_msg = '  using %s' % bits
    if bits > 4096:
        bits_msg += '; this will take a minute!'
    print(bits_msg)
    ent_msg = '  entropy: ' + _entropy_check()
    print(ent_msg)
    print('  > move the mouse around for 5s (to help generate entropy)')
    time.sleep(5)
    msg = 'Generating RSA keys (using %s)\n' % openssl_version
    print(msg)

    try:
        _genRsa2(pub, priv, pphr, bits)
    except:
        # might get a KeyboardInterrupt
        _cleanup('\n  > Removing temp files. Exiting. <')
        raise

    pub_msg = 'public key:  ' + pub
    print(pub_msg)
    priv_msg = 'private key: ' + priv
    print(priv_msg)
    if pphr_auto:
        pphr_msg = 'passphrase:  ' + pphr
    else:
        pphr_msg = 'passphrase:  (entered by hand)'
    print(pphr_msg)
    warn_msg = (' >> Keep the private key private! <<\n' +
           '  >> Do not lose the passphrase! <<')
    print(warn_msg)

    return pub, priv


class Tests(object):
    """Test suite for py.test

    - unicode in paths fail on win32
    - permissions fail on win32
    - fsutil need admin priv on win32
    """
    def setup_class(self):
        global pytest
        import pytest

        self.start_dir = os.getcwd()
        tmp = '__pyfilesec test__'
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp)
        self.tmp = abspath(tmp)
        os.chdir(tmp)

    def teardown_class(self):
        try:
            shutil.rmtree(self.tmp, ignore_errors=False)
            # CentOS + py2.6 says Tests has no attr self.tmp
        except:
            myhome = '/home/jgray/__pyfilesec test__'
            shutil.rmtree(myhome, ignore_errors=True)
        finally:
            os.chdir(self.start_dir)

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

    def test_stdin_pipeout(self):
        # passwords are typically sent to openssl via stdin
        msg = 'echo'
        cmd = ('grep', 'findstr')[sys.platform == 'win32']
        echo = _sys_call([cmd, msg], stdin=msg)
        assert echo == msg

    def test_unicode_path_openssl(self):
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
            t = make_archive(filename)

            # test whether encrypt can handle it:
            pub, priv, pphr = self._known_values()[:3]
            enc = encrypt(filename, pub)  # tarfile fails here with bad filename
            assert isfile(enc)

            dec = decrypt(enc, priv, pphr)
            assert stuff == open(dec, 'rb').read()

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
        __, kwnPriv, kwnPphr, datum, kwnSigs = self._known_values()
        kwnData = 'knwSig'
        with open(kwnData, 'wb+') as fd:
            fd.write(datum)
        sig1 = sign(kwnData, kwnPriv, pphr=kwnPphr)
        assert sig1 in kwnSigs

    def test_max_size_limit(self):
        # manual test: works with an actual 1G (MAX_FILE_SIZE) file as well
        global MAX_FILE_SIZE
        MAX_restore = MAX_FILE_SIZE
        good_max_file_size = bool(MAX_FILE_SIZE <= 2 ** 30)
        MAX_FILE_SIZE = 2 ** 8
        tmpmax = 'maxsize.txt'
        with open(tmpmax, 'w+b') as fd:
            fd.write(b'a' * (MAX_FILE_SIZE + 1))  # ensure too large
        with pytest.raises(ValueError):
            pad(tmpmax)
        with pytest.raises(ValueError):  # fake pubkey, just use tmpmax again
            encrypt(tmpmax, tmpmax)
        MAX_FILE_SIZE = MAX_restore

    def test_big_file(self):
        # by default, tests a file just over the LRG_FILE_WARN limit (17M)
        # tweak to create encrypt & decrypt a 4G file, ~15G disk space, ~13min

        bs = 1024  # block size
        #count = MAX_FILE_SIZE // 2 // bs  # 4G total size
        count = 1 + LRG_FILE_WARN // bs  # to test that warnings are triggered
        #count = 1  # uncomment to test the test
        size = bs * count  # bytes

        # make a big ol' file:
        try:
            orig = 'bigfile.zeros'
            enc = 'bigfile' + ARCHIVE_EXT
            if sys.platform == 'win32':
                with open(orig, 'wb') as fd:
                    zeros = b'\0' * bs
                    for i in range(count):
                        fd.write(zeros)
            else:
                _sys_call(['dd', 'if=/dev/zero', 'of=%s' % orig,
                      'bs=%d' % bs, 'count=%d' % count])
            pub, priv, pphr = self._known_values()[:3]
            encrypt(orig, pub)
            bigfile_size = getsize(enc)
            decrypt(enc, priv, pphr)
            bigfile_zeros_size = getsize(orig)
        except:
            os.remove('%s' % orig)
            os.remove(enc)
            os.remove('%s%s' % (orig, META_EXT))
        assert bigfile_size > size
        assert bigfile_zeros_size == size

    def test_encrypt_decrypt(self):
        # Lots of tests here (just to avoid re-generating keys a lot)
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext no unicode.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)

        testBits = 2048  # fine to test with 1024 and 4096
        pubTmp1 = 'pubkey1 no unicode.pem'
        prvTmp1 = 'prvkey1 no unicode.pem'
        pphr1 = 'passphrs1 no unicode.txt'
        with open(pphr1, 'wb') as fd:
            fd.write(_printable_pwd(180))
        pub1, priv1 = _genRsa(pubTmp1, prvTmp1, pphr1, testBits)

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pphr2 = 'passphrs2 no unicode.txt   '
        with open(pphr2, 'wb') as fd:
            fd.write('  ' + _printable_pwd(180) + '   ')  # spaces in pphr
        pub2, priv2 = _genRsa(pubTmp2, prvTmp2, pphr2, testBits)

        # test decrypt with GOOD passphrase, trailing whitespace:
        dataEnc = encrypt(datafile, pub2)  # not keep=True
        dataEncDec = decrypt(dataEnc, priv2, pphr=pphr2)
        recoveredText = open(dataEncDec).read()
        # file contents match:
        assert recoveredText == secretText
        # file name match: can FAIL due to utf-8 encoding issues
        assert os.path.split(dataEncDec)[-1] == datafile

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
        assert get_key_length(pub256) == 256  # need a short key to use
        with pytest.raises(PublicKeyTooShortError):
            dataEnc = encrypt(datafile, pub256)

        # test verifySig:
        sig2 = sign(datafile, priv1, pphr=pphr1)
        assert verify(datafile, pub1, sig2)
        assert not verify(pub1, pub2, sig2)
        assert not verify(datafile, pub2, sig2)

    def test_rotate(self):
        # Set-up:
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext no unicode.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

        pubTmp2 = 'pubkey2 no unicode.pem   '  # trailing whitespace in
        prvTmp2 = 'prvkey2 no unicode.pem   '  # file names
        pphr2 = 'passphrs2 no unicode.txt   '
        with open(pphr2, 'wb') as fd:
            fd.write('  ' + _printable_pwd(180) + '   ')  # spaces in pphr
        pub2, priv2 = _genRsa(pubTmp2, prvTmp2, pphr2, 1024)

        # Rotate encryption including padding change:
        first_enc = encrypt(datafile, pub1, date=False)
        second_enc = rotate(first_enc, priv1, pub2, pphr_old=pphr1,
                            pad_new=8192)
        third_enc = rotate(second_enc, priv2, pub1, pphr_old=pphr2,
                           priv_new=priv1, pphr_new=pphr1,  # = destroy orig
                           pad_new=16384, hmac_new='key')
        # padding affects .enc file size, values vary a little from run to run
        assert getsize(first_enc) < getsize(third_enc)

        # verify original encrypted file is not deleted by default:
        assert isfile(first_enc)
        # verify that passing priv_new deletes original enc file:
        assert not isfile(second_enc)

        dec_rot3 = decrypt(third_enc, priv1, pphr=pphr1)
        assert not open(dec_rot3).read() == secretText  # dec but still padded
        pad(dec_rot3, 0)
        assert open(dec_rot3).read() == secretText

        # Meta-data from key rotation:
        md = load_metadata(dec_rot3 + META_EXT)
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
        pytest.skip()

    def test_misc(self):
        secretText = 'secret snippet %.6f' % get_time()
        datafile = 'cleartext unicode.txt'
        with open(datafile, 'w+b') as fd:
            fd.write(secretText)
        pub1, priv1, pphr1, testBits = self._known_values()[:4]

        # Should be able to suppress meta-data file:
        new_enc = encrypt(datafile, pub1, meta=False, keep=True)
        data_enc, pwdFileRsa, metaFile = _unpack(new_enc)
        assert metaFile == None
        assert data_enc and pwdFileRsa

        # test keep=True:
        assert isfile(datafile)

        # Check size of RSA-pub encrypted password for AES256:
        assert os.path.getsize(pwdFileRsa) == int(testBits) // 8

        # Non-existent decMethod should fail:
        with pytest.raises(ValueError):
            dataDec = decrypt(new_enc, priv1, pphr1,
                          dec_method='_decrypt_what_the_what')
        # Good decMethod should work:
        dataDec = decrypt(new_enc, priv1, pphr1,
                          dec_method='_decrypt_rsa_aes256cbc')

    def test_compressability(self):
        # idea: check that encrypted is not compressable, cleartext is
        datafile = 'test_size'
        with open(datafile, 'wb') as fd:
            fd.write(b'1')
        size_orig = getsize(datafile)
        assert size_orig == 1

        pad2len = 16384
        pad(datafile, pad2len)  # should be very compressable, mostly padding
        size_pad = getsize(datafile)
        assert size_pad == pad2len
        arc = make_archive(datafile)  # tgz compression
        size_arc = getsize(arc)
        assert 150 < size_arc < 200 < pad2len // 8
        pub = self._known_values()[0]
        enc = encrypt(datafile, pub)  # should not be compressable
        size_enc = getsize(enc)
        assert pad2len * 1.02 < size_enc < pad2len * 1.20  # 1.093

    def test_permissions(self):
        assert PERMISSIONS == 0o600
        assert UMASK == 0o077

        filename = 'umask_test no unicode'
        pub, priv, pphr = self._known_values()[:3]
        umask_restore = os.umask(0o000)  # need permissive to test
        with open(filename, 'wb') as fd:
            fd.write(b'\0')
        assert _get_file_permissions(filename) == 0o666  # permissive to test
        enc = encrypt(filename, pub)
        # os.chmod(enc, PERMISSIONS)  # even this fails win32 as admin
        assert _get_file_permissions(enc) == PERMISSIONS  # fails win32
        assert not os.path.isfile(filename)
        dec = decrypt(enc, priv, pphr)
        assert _get_file_permissions(dec) == PERMISSIONS  # restricted
        os.umask(umask_restore)

    def test_hmac(self):
        # verify openssl hmac usage against a widely used example:
        key = 'key'
        value = "The quick brown fox jumps over the lazy dog"
        hm = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
        hb = '69d6cdc2fef262d48a4b012df5327e9b1679b6e3c95b05c940a18374b059a5e7'
        tmp = 'hmac_test no unicode'
        with open(tmp, 'wb+') as fd:
            fd.write(value)
        hmac_openssl = hmac_sha256(key, tmp)
        # avoid '==' to test because openssl 1.0.x returns this:
        # 'HMAC-SHA256(filename)= f7bc83f430538424b13298e6aa6fb143e97479db...'
        assert hmac_openssl.endswith(hm)

    def test_command_line(self):
        # send encrypt and decrypt commands via command line

        datafile = 'cleartext no unicode.txt'
        secretText = 'secret snippet %.6f' % get_time()
        with open(datafile, 'wb') as fd:
            fd.write(secretText)
        pub1, priv1 = _genRsa(bits=1024)  # NO PASSPHRASE
        pathToSelf = abspath(__file__)
        datafile = abspath(datafile)

        # Encrypt:
        cmdLineCmd = [sys.executable, pathToSelf, 'encrypt', datafile,
                      pub1, '--openssl=' + OPENSSL]
        dataEnc = _sys_call(cmdLineCmd).strip()
        assert os.path.isfile(dataEnc)

        # Decrypt:
        cmdLineCmd = [sys.executable, pathToSelf, 'decrypt', dataEnc,
                      priv1, '--openssl=' + OPENSSL]
        dataEncDec_cmdline = _sys_call(cmdLineCmd).strip()
        assert os.path.isfile(dataEncDec_cmdline)

        # Both enc and dec need to succeed to recover the original text:
        recoveredText = open(dataEncDec_cmdline).read()
        assert recoveredText == secretText

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
            code, links, t1 = destroy(tw_path)
            assert code == pfs_DESTROYED
            # assert links == 1  # separate test
            destroy_times.append(t1)
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
            code, links, __ = destroy(tw_path)
            assert links == -1
            pytest.skip()  # need admin priv for fsutil
        numlinks = 2
        for i in range(numlinks):
            new = tw_path + 'hardlink' + str(i)
            if sys.platform in ['win32']:
                _sys_call(['fsutil', 'hardlink', 'create', new, tw_path])
            else:
                os.link(tw_path, new)

        hardlinks = _get_hardlink_count(tw_path)
        code, links, __ = destroy(tw_path)
        assert links == numlinks + 1  # +1 for itself
        assert links == hardlinks

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

    def test_8192_bit_keys(self):
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

        enc = encrypt(datafile, pub)
        dataDecNested = decrypt(enc, priv, pphr=pphr)
        recoveredText = open(dataDecNested).read()
        assert recoveredText == secretText


# Basic set-up (order matters) ------------------------------------------------
logging, logging_t0 = _setup_logging()
if not user_can_link:
    logging.warning('%s: No admin priv; cannot check hardlinks' % lib_name)
OPENSSL, openssl_version, use_rsautl = _get_openssl_info()
destroy_TOOL, destroy_OPTS = _get_destroy_info()

default_codec = {'_encrypt_rsa_aes256cbc': _encrypt_rsa_aes256cbc,
                 '_decrypt_rsa_aes256cbc': _decrypt_rsa_aes256cbc}
codec = PFSCodecRegistry(default_codec)

if __name__ == '__main__':
    logging.info("%s with %s" % (lib_name, openssl_version))
    if '--debug' in sys.argv:
        """Run tests with verbose logging.
            $ python pyfilesec.py --debug > results.txt
        """
        global pytest
        import pytest

        os.mkdir('debug_' + lib_name)
        os.chdir('debug_' + lib_name)  # intermediate files get left inside
        ts = Tests()
        tests = [t for t in dir(ts) if t.startswith('test_')]
        for test in tests:
            try:
                eval('ts.' + test + '()')
            except:
                result = test + ' FAILED'
                print(result)
        logging.info("%.4fs for tests" % (get_time() - logging_t0))
    elif '--genrsa' in sys.argv:
        """Walk through key generation.
        """
        genRsaKeys()
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
