"""Constants, initial values, and exception classes (execfile'd).

Part of the pyFileSec library, Copyright (c) 2013 Jeremy R. Gray.
"""

import re

# Constants: --------------------
RSA_PADDING = '-oaep'  # actual arg for openssl rsautl in encrypt, decrypt

ENC_EXT = '.enc'  # extension for for tgz of AES, PWD.RSA, META
AES_EXT = '.aes256'   # extension for AES encrypted data file
RSA_EXT = '.pwdrsa'   # extension for RSA-encrypted AES-pwd (ciphertext)
META_EXT = '.meta'    # extension for meta-data

# RSA key
RSA_MODULUS_MIN = 1024  # threshold to avoid PublicKeyTooShortError
RSA_MODULUS_WARN = 2048  # threshold to avoid warning about short key

# RsaKeys require()
NEED_PUB = 1
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

# string to help be sure a .bat file belongs to pfs (win32, set_openssl):
bat_identifier = '-- pyFileSec .bat file --'


# Initialize values: --------------------
dropbox_path = None


# Exception classes: --------------------

class PyFileSecError(Exception):
    """Base exception for pyFileSec errors."""

class EncryptError(PyFileSecError): pass  # failed, or refused to start

class DecryptError(PyFileSecError): pass  # failed, or refused to start

class PublicKeyError(PyFileSecError): pass

class PublicKeyTooShortError(PyFileSecError): pass

class PrivateKeyError(PyFileSecError): pass

class PassphraseError(PyFileSecError): pass

class SecFileArchiveFormatError(PyFileSecError): pass

SecFileFormatError = SecFileArchiveFormatError

class PaddingError(PyFileSecError): pass

class CodecRegistryError(PyFileSecError): pass # e.g., not registered

class DestroyError(PyFileSecError): pass  # e.g., destroy failed

class ArgumentError(PyFileSecError): pass  # e.g., no file specified

class FileNotEncryptedError(PyFileSecError): pass

class FileStatusError(PyFileSecError): pass
