===========
 pyFileSec
===========

pyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve an "industry standard"
level of strong privacy, capable of protecting confidential information from
inspection or accidental disclosure. Integrity assurance may be useful in
archival and provenance applications.

Overview
---------

The motivation for developing pyFileSec is to better secure research data obtained
from human subjects, e.g., in combination with PsychoPy (http://www.psychopy.org)
or the Open Science Framework (http://www.openscienceframework.org). The hope is
that pyFileSec will be more widely useful. For example, command-line options
make it accessible from non-python or non-open-source programs.

Several truly excellent Python packages are available for encryption. However, file
security requires more than just good encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide cross-platform, secure
file-management with a low barrier to entry and a stable API going forward. These
considerations motivate many of the design choices.

The main functions provided include encryption (``encrypt``, ``decrypt``,
``rotate``) and verification (``sign``, ``verify``). It is also easy to
obscure file length (``pad``, ``unpad``), securely remove files from disk (``destroy``)
and inspect meta-data.
Large files (tested up to 8G) and command-line usage are also supported.

By default, file permissions are set to conservative values (only Mac & linux
at this point). Unencrypted files are deleted securely after a successful encryption.
Multiple hardlinks, version control, and Dropbox folders are detected and reported.

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography. The aim is to provide
a robust and easily extensible framework for adding other encryption backends,
without requiring changes to the API.

Bug reports and code contributions are welcome; the project is on github and you
can contact me there (https://github.com/jeremygray/pyFileSec). For contacting me
privately, e.g., about security issues, please look for my gmail address at the
top of the main code. Help with Windows would be particularly welcome (see the
issues list).


Contributors
-------------
Jeremy R. Gray - package author (GPG key D934B0D7)

Thanks to
----------
Michael Stone - awesome code review

Sol Simpson - Windows compatibility


Milestones
-----------

- 0.3  class SecFile; Python 3 (2to3 mostly passes now)
- 0.4  An alternative encryption backend (possibly pycrypto and gpg support)
- 0.5  Windows file-permissions


See also
---------

- pyCrypto, M2Crypto, pyOpenSSL - excellent crypto packages, no or few sys-admin features
- pycogworks.crypto - similar audience as pyfilesec, no file encyrption
- Ephemeral - provides encrypted temporary files
