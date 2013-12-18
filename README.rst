
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

Several truly excellent Python packages are available for encryption. However,
file security requires more than just good encryption, e.g., securely deleting
a file after encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide cross-platform,
secure file-management with a low barrier to entry and a stable API going
forward. These considerations motivate many of the design choices.

The main functions provided include encryption (``encrypt``, ``decrypt``,
``rotate``) and verification (``sign``, ``verify``). It is also easy to
obscure file length (``pad``, ``unpad``), securely remove files from disk
(``destroy``) and inspect meta-data (``.metadata``). Large files (tested up to 8G) and
command-line usage are also supported. By default, file permissions are set to
conservative values (only Mac & linux at this point). Unencrypted files are
deleted securely after a successful encryption. Multiple hardlinks, version
control, and Dropbox folders are detected and reported.

pyFileSec provides the class ``SecFile``, which is designed to be easy to use::

    >>> import pyfilesec as pfs
    >>> sf = pfs.SecFile('data.txt')
    >>> sf.encrypt(path_to_pubkey)

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography. The aim is to provide
a robust and easily extensible framework for adding other encryption backends,
without requiring changes to the API.

Bug reports and code contributions are welcome; the project is on github and you
can contact me there.  Help with Windows file permissions would be particularly
welcome (see the issues list). For contacting me privately, e.g., about security
issues, please look for my email address at the top of the main code.

Software that includes pyFileSec
---------------------------------
- PsychoPy (v1.79.00+)

Contributors
-------------
Jeremy R. Gray - package creator and maintainer (GPG key D934B0D7)

Michael Stone - awesome code review

Sol Simpson - Windows compatibility

Milestones
-----------

- 0.3  Python 3 (2to3 mostly passes now)
- 0.4  An alternative encryption backend (possibly pyCrypto and gpg support)
- 0.5  Windows file-permissions

Dev branch status
------------------

This status information concerns the master branch of the source code on
github. Pypi releases are made from time to time, based on stable points
in the development code.

.. image:: https://travis-ci.org/jeremygray/pyfilesec.png?branch=master
    :target: https://travis-ci.org/jeremygray/pyfilesec?branch=master

.. image:: https://coveralls.io/repos/jeremygray/pyfilesec/badge.png?branch=master
    :target: https://coveralls.io/r/jeremygray/pyfilesec?branch=master

See also
---------

- pyCrypto, M2Crypto, pyOpenSSL - broad crypto packages, few sys-admin features
- pycogworks.crypto - similar audience as pyfilesec, no file encryption
