===========
 pyFileSec
===========

pyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve an "industry standard"
level of privacy (AES256), capable of protecting confidential information from
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
security requires more than just encryption. The main and potentially
unique contribution of pyFileSec is that it aspires to provide secure file-
management with a low barrier to entry and a stable API going forward. These
considerations motivate many of the design choices.

The main functions provided include encryption (``encrypt``, ``decrypt``,
``rotate``) and verification (``sign``, ``verify``). It is also easy to
obscure file length (``pad``, ``unpad``), securely remove files from disk (``destroy``),
combine multiple files or directories into a single archive file prior to encryption
(``archive``), and display the meta-data associated with an encrypted file.
Large files (8G) and command-line / shell-script usage are also supported.

By default, file permissions are set to conservative values (only Mac & linux
at this point). Clear-text files are deleted securely after encryption. If the
file (inode) had other links to it, their presence is reported (as a count
which can be checked).
Decryption will not proceed inside a Dropbox folder (to help limit unintended
propagation of clear-text to other machines). Decryption into a folder that
appears to be under version control will proceed but be noted with a warning
(for svn, git, and hg).

Public-key (asymmetric) encryption is used for security and flexibility,
currently relying on calls to OpenSSL for all cryptography (RSA + AES256 --
an approach that is well-known and widely regarded). The aim is to provide an
easily extensible framework for adding other encryption backends (e.g.,
PyCrypto or GPG, should they be desired), without requiring changes to the API.

The integrated test-suite passes on **Mac OS X** (10.8) and **Linux** (CentOS
6.4, Debian squeeze, and Ubuntu 12.04). Most tests pass on **Windows** 7 (except
filenames with unicode, and file permissions). Tested using 9 versions of OpenSSL,
including a compiled development release.

Bug reports and code contributions are welcome; the project is on github and you
can contact me there (https://github.com/jeremygray/pyFileSec). For contacting me
privately, e.g., about security issues, please look for my gmail address at the
top of the main code. Help with Windows issues would be great (especially file permissions).


Getting started
----------------

Generally, you do not need administrative privildges to work with pyFileSec once
it is installed. The only exception is that, on Windows, you need to be an admin
to check whether files have other hard links to them.

Command line usage is likely to be easier with an alias. To find out what path
and syntax to use in an alias, start python interactively (type ``python`` at a
terminal or command prompt) and then:

    >>> import pyfilesec as pfs
    >>> pfs.command_alias()

This will print aliases for bash, csh/tcsh, and DOS. Copy and paste into your
shell as appropriate (or elsewhere, like a ~/.bash_profile).

A demos/ directory is in the same directory as pyfilesec.py, and has usage
examples for python scripting (example_1.py) and command-line / shell scripting
(example_2.sh). A guide (``readme.txt``) has basic instructions on how to
generate an RSA key-pair using pyFileSec; any valid .pem format key-pair will work.

Contributors
-------------
Jeremy R. Gray - package author (GPG key D934B0D7)

Thanks to
----------
Michael Stone - awesome code review

Sol Simpson - Windows compatibility


Milestones
-----------

- 0.2  Documentation
- 0.3  Python 3 (looks easy, ``2to3`` passes now)
- 0.4  An alternative encryption backend, possibly pycrypto and some gpg support
- 0.5  Windows file-permissions
