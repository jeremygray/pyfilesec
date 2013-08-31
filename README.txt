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
make it accessible from non-python or non-open-source programs, such as EPrime
via the ``Shell()`` command.

Several excellent Python packages are available for encryption. However, file
security requires more than just good encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide cross-platform, secure
file-management with a low barrier to entry and a stable API going forward. These
considerations motivate many of the design choices.

The main functions provided include encryption (``encrypt``, ``decrypt``,
``rotate``) and verification (``sign``, ``verify``). It is also easy to
obscure file length (``pad``, ``unpad``), securely remove files from disk (``destroy``).
Large files (8G) and command-line / shell-script usage are also supported.

By default, file permissions are set to conservative values (only Mac & linux
at this point). Clear-text files are deleted securely after a successful encryption. If the
file (inode) had other links to it, their presence is reported.
Decryption will not proceed inside a Dropbox folder (to help limit unintended
propagation of clear-text to other machines). Decryption into a folder that
appears to be under version control will proceed but and the version control will be noted
(for svn, git, and hg).

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography (RSA + AES256 --
an approach that is well-known). The aim is to provide an
easily extensible framework for adding other encryption backends (e.g.,
PyCrypto or GPG, should they be desired), without requiring changes to the API.

Bug reports and code contributions are welcome; the project is on github and you
can contact me there (https://github.com/jeremygray/pyFileSec). For contacting me
privately, e.g., about security issues, please look for my gmail address at the
top of the main code. Help with Windows would be great (see the issues list).


Contributors
-------------
Jeremy R. Gray - package author (GPG key D934B0D7)

Thanks to
----------
Michael Stone - awesome code review

Sol Simpson - Windows compatibility


Milestones
-----------

- 0.3  class SecFile; Tests; Python 3 (2to3 mostly passes now)
- 0.4  An alternative encryption backend (possibly pycrypto and gpg support)
- 0.5  Windows file-permissions
