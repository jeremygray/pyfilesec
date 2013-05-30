==========
PyFileSec
==========

PyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve a "industry standard"
level of privacy, capable of protecting confidential information
about human research subjects from casual inspection or accidental disclosure.
In addition, integrity assurance may be useful in archival and provenance
applications.

Public-key encryption is used for security and flexibility, currently relying
on OpenSSL for all cryptography (RSA + AES256). The aim is to provide a
extensible framework for adding other encryption methods, while retaining the
API and meta-data.

The main contribution of PyFileSec is data management: 1) to make existing
file-oriented strong encryption tools more accessible to human subjects
research (``encrypt``, ``decrypt``, ``rotate``), and 2) to automatically
document the encryption procedures used (in meta-data). Other tools are
provided to obscure file length (``pad``), securely remove files from disk
(``wipe``), and combine a set of files into an archive file (``archive``).

The integrated test-suite passes on Mac OS (10.8.3) and Linux (CentOS 6.4 and
Ubuntu 12.04). Windows support to be added soon (will require user to install
OpenSSL and SDelete).

Contributors
-------------
Jeremy R. Gray - package author

Thanks to
----------
Michael Stone - awesome code review