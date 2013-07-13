===========
 pyFileSec
===========

pyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve an "industry standard"
level of privacy (AES256), capable of protecting confidential information from
inspection or accidental disclosure. Integrity assurance may be useful in
archival and provenance applications.

The motivation for developing pyFileSec is to better secure research data obtained
from human subjects, e.g., in combination with PsychoPy or the Open Science
Framework. The hope is that pyFileSec will be more widely useful. Command-line
usage will make it accessible from non-python programs, such as EPrime via the
``Shell()`` command.

Several excellent Python packages are available for encryption. However, file
security requires far more than just encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide secure file-
management with a low barrier to entry. These considerations motivate
many of the design choices.

The main functions provided include encryption: ``encrypt()``, ``decrypt()``,
``rotate()``; and verification: ``sign()``, ``verify()``. It is also easy to
obscure file length: ``pad()``, securely remove files from disk: ``destroy()``,
combine a set of files into a single archive file prior to encryption:
``archive()``, and display the meta-data associated with an encrypted file.
Large files (8G) and command-line / shell-script usage are also supported.

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography (RSA + AES256 --
an approach that is well-known and widely regarded). The aim is to provide an
easily extensible framework for adding other encryption backends (e.g.,
PyCrypto or GPG, should they be desired), without requiring changes to the API.

The integrated test-suite passes on **Mac OS X** (10.8) and **Linux** (CentOS 6.4,
Debian squeeze, and Ubuntu 12.04). Most tests pass on **Windows** 7 (except filenames
with unicode, and file permissions). Tested using 9 versions of OpenSSL,
including a compiled development release.
Python 3.x support looks easy (``2to3`` passes now).

Milestones:

- 0.2.0  Documentation, command-line support. Move to beta status.
- 0.3.0  Windows file-permissions, Python 3, and alternative encryption backend

Contributors
-------------
Jeremy R. Gray - package author (GPG key D934B0D7)

Thanks to
----------
Michael Stone - awesome code review

Sol Simpson - Windows compatibility
