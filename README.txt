==========
pyFileSec
==========

pyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve a "industry standard"
level of privacy, capable of protecting confidential information from casual
inspection or accidental disclosure in a research setting. In addition,
integrity assurance may be useful in archival and provenance applications. The
main motivation for developing pyFileSec is research with human subjects (e.g.,
in combination with PsychoPy or the Open Science Framework), but the hope is
that it will be more widely useful.

Several excellent Python packages are available for encryption. However, file
security requires far more than just encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide secure /file
management/ tools having a /low barrier to entry/. These considerations motivate
many of the design choices, e.g., using OpenSSL (often already installed)
rather than PyCrypto (requires compiling) or GPG (requires set-up).

The main functions provided include encryption: ``encrypt()``, ``decrypt()``,
``rotate()``; and verification: ``sign()``, ``verify()``. It is also easy to
obscure file length: ``pad()``, securely remove files from disk: ``wipe()``,
combine a set of files into a single archive file prior to encryption:
``archive()``, and display the meta-data associated with an encrypted file.
Large files and command-line / shell-script usage are also supported.

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography (RSA + AES256 --
an approach that is well-known and widely regarded). The aim is to provide an
easily extensible framework for adding other encryption backends (e.g.,
PyCrypto or GPG, should they be desired), without requiring changes to the API.

The integrated test-suite passes on Mac OS (10.8) and Linux (CentOS 6.4,
Debian squeeze, and Ubuntu 12.04), using 7 different versions of OpenSSL.
Python 3.x support looks easy (2to3 passes now). Windows support forthcoming.

Contributors
-------------
Jeremy R. Gray - package author

Thanks to
----------
Michael Stone - awesome code review
Sol Simpson - Windows compatibility