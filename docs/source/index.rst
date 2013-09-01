
:mod:`pyFileSec` File-oriented privacy and integrity management tools *(alpha)*

.. toctree::
   :maxdepth: 2

==================================================================

File-oriented security in python
---------------------------------

pyFileSec provides a class ``SecFile`` that is intended
to make it easier to protect computer files from casual
inspection or accidental disclosure. By design, privacy assurance, ease-of-use, and a
stable, cross-platform API are important security goals. Integrity
assurance is useful but not a top priority. The speed of code execution is
relatively unimportant. Truly sensitive information should be protected through
multiple means, including procedural, physical, and legal methods.

pyFileSec is less about encryption (which it does handily, as do many excellent
packages), and more about managing the immediate security issues that arise
when working with files. Anyone doing system administration tasks in a
research lab might find it useful, possibly including edvanced users and
developers of software presentation programs for human subjects research. Anyone
needing file management with compatible security goals could potentially benefit.

From a security perspective, the goal is to better protect files in the local
environment, and reduce the chances of their accidental disclosure. It is beyond
pyFileSec's scope to try to defend against all possible adversarial attacks.
pyFileSec is only concerned with file-oriented aspects of information security.

**Example use-case:** A research team might wish to collect data on illegal
drug-use (or other HIPAA-covered information). To keep the window of accidental
disclosure as small as possible, such sensitive information is best protected
as early as possible in the data stream -- ideally from within the data collection
program. It is also desirable to be able to encrypt it without needing to be able
to decrypt on the same computer, and without needing to store a password for
decryption where the password might be copied, disclosed, or exposed to
key-loggers (any of which could make encryption irrelevant). Being able to
secure-delete the original file(s) to avoid leaving sensitive information
on the disk is useful. And at times it can be desirable to obscure file sizes,
e.g., so that a larger file cannot indicate a more extensive history of drug use.

Despite excellent tools for encryption being widely available, security is hard
to achieve. Even good and trustworthy people can make mistakes that compromise
security. Tools to help manage file security can reduce the chances of mistakes
and help people be more confident and more productive.

pyFileSec is intended to be adequate for the purpose of securing data files
within a typical research lab. Even so, the
effective security will be higher if the data have low economic value (which is
typically the case in psychology and neuroscience labs). The effective security
will be much higher
if the lab has reasonable physical and network security, with only trained,
trusted people working there (also typically the case).

**Cautions:** Using encryption in a research context requires some consideration.
Perhaps the most important thing to keep in mind is that, depending on your
circumstances, the use of encryption (or particular forms of encryption) can conflict
with policies of your boss, institution, or even government. You are responsible for
knowing your situation, and for the consequences of your decisions about whether
and how to use encryption. In addition,  the encryption is definitely strong enough
to cause trouble. Consider an example: Although you can lock yourself out of your
own car or house, you could also hire someone with training and tools to break in
on your behalf. With encryption, however, it would likely be prohibitively expensive
to hire someone to "break in on your behalf"; hopefully that is not possible,
even for a well-funded adversary. So it is possible to lose data by trying to secure it.

**Development status:** As of version 0.2.0, the development status is still **alpha**,
meaning that major API changes and bugs are likely. The development emphasis is
currently on refactoring the code from a function-based organization (0.2.0)
to a class-based organization (milestone 0.3 release). class SecFile will be the
core class provided by the package. Documentation is a work in progress. A few
extensions are planned, e.g., an alternative encryption backend and zip. File
permissions on Windows needs work. Python 3 is completely untested.

Comments and code contributions are welcome. Feedback can be posted on github
(see issues at https://github.com/jeremygray/pyfilesec/). Contact by
private email is preferred for anything sensitive, such as security concerns.


Principles and Approach
------------------------

Using public-key encryption allows a non-secret "password" (the public key) to
be distributed and used for encryption, with no need for the non-shared private key
to be involved in the encryption process. This logically separates encryption from
decryption, which in turn allows their physical separation. This separability
gives considerable flexibility (and security).
The idea is that anyone anywhere can encrypt information that only a trusted process
(i.e., with access to the private key) can decrypt. For example, multiple testing-room
computers could have the public key, and use it to encrypt the data from each subject
so that it can be transferred to a main computer for de-identification, analysis, and
archiving. The private key (for decryption) does not need to be shared beyond the
main trusted computer. Keep it as private as possible.

pyFileSec does not, of itself, implement cryptographic code; by design it relies
on external implementations. In particular, cryptographic operations use
OpenSSL (see openssl.org), using its implementation of RSA and AES. These ciphers
are industry standards and can be very secure when used correctly. The effective
weak link is almost certainly not cryptographic but rather in how the encryption
key(s) are handled, which depends mostly on  you (the user), including what happens
during key generation, storage, and backup. If your keys are bad or compromised,
the encryption strength is basically irrelevant. The strength of the lock on your
front door is irrelevant if you make a habit of leaving the key under the doormat.

Some considerations:

- A test-suite is included as part of the library.
- OpenSSL is not distributed as part of the library (see Installation).
- By design, the computer used for encryption can be different from the computer used
  for decryption; it can be a different device, operating system, and version of OpenSSL.
  The only known incompatability that that signatures (obtained from ``sign()``)
  can fail to ``verify()`` if the version of OpenSSL used is too different (i.e.,
  if one is pre version 1.0 and the other is 1.0 or higher).
- You should both encrypt and decrypt only on machines that are physically secure,
  with access limited to trusted people. Although encryption can be done anywhere,
  using a public key, if someone used a different public key to encrypt data
  intended for you, you would not be able to access "your" data.
- Ideally, do not move your private key from the machine on which it was
  generated; certainly never ever email it. Its typically fine to share the public
  key, certainly within a small group of trusted people, such as a research lab.
  The more widely it is distributed, the sooner it should be retired (and the
  encryption rotated on files encrypted with that key).
- Some good advice from GnuPG: "If your system allows for encrypted swap partitions,
  please make use of that feature."

Design goals:

- Rely exclusively on standard, widely available and supported tools and algorithms.
  OpenSSL and the basic approach (RSA + AES 256) are well-understood and recommended
  (e.g., by Ferguson, Schneier, & Kohno (2010) `Cryptography engineering.` Indianapolis,
  Indiana: Wiley).
- Allow for the relatively easy adoption of another
  encryption cipher suite, in the event that a change is necessary for cryptographic
  reasons.
- For clarity, use and return full paths to files, not relative paths.
- Avoid obfuscation. It does
  not enchance security, yet can make data recovery more difficult or expensive.
  So transparency is preferred. For this reason, meta-data are generated by
  default to make things less obscure; meta-data can be suppressed if desired.
- Require OpenSSL version is 0.9.8 or higher.
- Require a public key >= 1024 bits; you should only use 2048 or higher.
- For the AES encryption, a random 256-bit session key (AES password) is
  generated for each encryption event.
- Use standard formats as much as possible.
- Managing the RSA keys is up to the user to do.


Installation
---------------------

pyFileSec
=====================

Install things in the usual way for a python package::

    % pip install pyFileSec

Dependencies
=================

pyFileSec requires (but does not itself package) a copy of OpenSSL and a secure
file-removal tool. Both are typically present on Mac and linux; if so,
installation is complete.

It is also possible to use a non-default (e.g., compiled) version of OpenSSL.
You can specify the path with the ``--openssl path`` option (command-line use),
or using ``pyfilesec.set_openssl(path)`` (python).

**On a Mac**, if you get the same output all is well::

    % which openssl
    /usr/bin/openssl
    % which srm
    /usr/bin/srm

**On Linux**, its typically very similar::

    % which openssl
    /usr/bin/openssl
    % which shred
    /usr/bin/shred

**On Windows**, its also free but not as easy.

1. Download and install OpenSSL from http://slproweb.com/products/Win32OpenSSL.html.
First install the "Visual C++ 2008 Redistributables" (from the same page).
Then install OpenSSL (Light is fine) and run through the installer pages.
It should install to ``C:\OpenSSL-Win32`` by default. pyFileSec should now be
able to detect and use OpenSSL.

2. Download and install ``sdelete`` (free, from Microsoft)
http://technet.microsoft.com/en-us/sysinternals/bb897443.aspx. pyFileSec should
be able to detect ``sdelete.exe``.

You will likely need to run these programs once manually and accept the terms
before being able to use them from pyFileSec.

Getting started
================

Generally, you do not need administrative privildges to work with pyFileSec once
it is installed. (The only exception is that, on Windows, you need to be an admin
to check whether files have other hard links to them.)

Command line usage is likely to be easier with an alias. To find out what path
and syntax to use in an alias, start python interactively (type ``python`` at a
terminal or command prompt) and then:

  >>> import pyfilesec as pfs
  >>> pfs.command_alias()

This will print aliases for bash, csh/tcsh, and DOS. Copy and paste into your
shell as appropriate (or paste elsewhere, like a ~/.bash_profile).

A demos/ directory is in the same directory as pyfilesec.py, and has usage
examples for python scripting ``example_1.py``, and for command-line / shell scripting
``example_2.sh``.

A guide ``readme.txt`` has basic instructions on how to
generate an RSA key-pair using pyFileSec; any valid .pem format key-pair will work.


API
------------------------

The API describes how to work with a SecFile object from within python.
An understanding of the parameters will be useful for command-line / shell-script usage.
Details about command-line syntax can be obtained using the usual ``--help`` option::

    % python pyfilesec.py --help

.. note:: Any references to 'clear text' or 'plain text' simply mean an unencrypted file. It could be a binary file. There is no requirement that it be text.

The main class of interest is SecFile, described next. Three other classes are used
internally, and so are also described here for completeness. There should be
no need to understand anything except a SecFile in order to use it.

class SecFile()
================

.. autoclass:: pyfilesec.SecFile
    :members: encrypt, decrypt, rotate, sign, verify, destroy, pad, unpad

Other available SecFile methods include:

    ``set_file()`` : change the file to work with, and set the ``.file`` property.

        .. note:: Calling ``set_file`` does not rename the existing file on the file system.
            It just tells the sf object to work with a different file. To change
            the underlying file name: ``os.rename(sf.file, new_file); sf.set_file(new_file)``.

    ``read(n)`` : read n lines from the file, return as a single string.

SecFile objects have properties that can be accessed with the usual dot
notation (i.e., as ``sf.property`` where ``sf`` is a SecFile object). Most cannot be set (exceptions
noted).

    ``file`` : the full path to the underlying file on the file system

        .. note:: To change the file to work with, see ``set_file()``.

    ``basename`` : same as ``os.path.basename(sf.file)``, or ``None`` if no file.

    ``size`` : (long int)
        size in bytes on the disk as reported by ``os.path.getsize(sf.file)``.

    ``metadata`` : (dict)
        returns {} for an unencrypted file.

    ``metadataf`` : (string)
        human-friendly version of ``metadata``, e.g., for log files.
        returns '{}' for an unencrypted file.

    ``snippet`` : (string)
        up to 60 characters of the first line of the file; or will return '(encrypted)', or ``None`` if no file

    ``is_encrypted`` : (boolean)
        ``True`` if encrypted by ``pyFileSec.SecFile.encrypt()``; does not detect any-encryption-in-general.

    ``is_in_dropbox`` : (boolean)
        ``True`` if inside the user's Dropbox folder

    ``is_in_writeable_dir`` : (boolean)
        ``True`` if the user has write permission to the file's directory

    ``is_tracked`` : by version control (boolean)
        only git, svn, and mercurial (hg) are detected.

    ``permissions`` : POSIX-style file permissions (int; -1 on Windows)
        if ``sf.permissions`` is 384 (int), then ``oct(sf.permissions)`` will be '0600'.

        .. note:: Can be assigned.

    ``openssl`` : path
        contains the path to the OpenSSL executable file to use.

        .. note:: Can be assigned.

    ``openssl_version`` : (string)
        version of ``sf.openssl``.

    ``hardlinks`` : count of all hardlinks to the file (int)
        the count includes ``sf.file`` as one link. requires Admin priviledges on Windows.

Class SecFileArchive
=====================

A SecFileArchive object manages the encrypted (``.enc``) version of the file. In particular,
an encrypted "file" has three pieces:

    - an encrypted version of the plain_text file (currently encrypted using AES-256-CBC)

    - an encrypted version of the AES password (sometimes called a session key) as encrypted using an RSA public key

    - a file containing meta-data about the encryption event (or a placeholder saying that meta-data were suppressed)

A SecFileArchive takes care of packing and unpacking the three pieces into a
single underlying file on the file system. Currently this is an ordinary ``.tar.gz`` file::

    % echo f > file
    % python pyfilesec.py --encrypt file --pub pub.pem
    % ls file.enc
    file.enc
    % tar xzvf file.enc
    x file.aes256
    x file.aes256.pwdrsa
    x file.meta

The meta-data (``file.meta``) is always clear-text. This is to facillitate human
inspection in archival uses.

.. autoclass:: pyfilesec.SecFileArchive
    :members:

Class RsaKeys
==============

.. autoclass:: pyfilesec.RsaKeys
    :members: update, require, sniff, test

An ``RsaKeys`` object has three properties:

    ``pub`` : path
        contains the path to the public key file.

    ``priv`` : path
        contains the path to the private key file.

    ``pphr`` : (string)
        contains the actual passphrase. If the passphrase was given initially as a path, it is read from the file.


Class GenRSA
================

This class can be used to generate key-pairs that are appropriate for use
with pyFileSec.

.. autoclass:: pyfilesec.GenRSA
    :members: dialog

Class Codec Registry
=====================

Currently there is only one option for a codec.

.. autoclass:: pyfilesec.PFSCodecRegistry
    :members: register, unregister, is_registered, get_function

Tests and performance
----------------------

The built-in tests can be run from the command line::

    $ py.test pyfilesec.py

or from within the main directory just::

    $ py.test

To see log messages during tests::

    $ python pyfilesec.py debug

If you try the 'debug' option, note that some of the tests
are designed to check error situations; i.e., what is being tested is that situations
that should fail, do fail, and are recognized as failure situations. This means
that in the verbose output you should see some things that look exactly like error
messages (e.g., "RSA operation error") because these are logged.

For details of the specific tests, consult the code directly.

Beyond the test-suite
========================

Files encrypted on one machine can be decrypted on a different platform. (Not
tested yet with machines known to be of different endian-ness, however.)

With one exception, the specific version of OpenSSL does not matter. The
known exception is that there are incompatibilities between v0.9.x and v1.0.x
when using sign / verify. Tested with 9 versions of openssl, running on Mac OS
X (10.8), 3 linux distributions, and Windows 7::

    OpenSSL 0.9.8r  8 Feb 2011     Mac 10.8.3, python 2.7.3
    OpenSSL 0.9.8x 10 May 2012     Mac 10.8.4, python 2.7.3
    OpenSSL 1.0.1e 11 Feb 2013     same Mac, openssl via macports
    OpenSSL 1.1.0-dev xx XXX xx    same Mac, clone OpenSSL from github & compile
    OpenSSL 1.0.0-fips 29 Mar 2010 CentOS 6.4, python 2.6.6
    OpenSSL 1.0.1  14 Mar 2012     Ubuntu 12.04.2 LTS, python 2.7.3
    OpenSSL 0.9.8o 01 June 2010    Debian (squeeze), python 2.6.6
    OpenSSL 1.0.1e Light           Windows 7, python 2.7.3
    OpenSSL 1.0.1e                 same Windows

Encryption is basically linear in time and disk space (file size; times
will vary with CPU, disk speed, etc). Example values from a laptop::

    1K takes ~0.2s to encrypt, ~0.1s decrypt
    1M takes ~10s to encrypt,  ~5s decrypt
    1G takes ~90s to encrypt,  ~60s decrypt
    8G takes ~13m to encrypt

If backup software is running, that can greatly reduce a SecFile object's
apparent speed. Presumably, other concurrent and intensive disk usage would also do this.

Large files are fine (max tested is 8G). File-size inflation is consistently 3%::

    1G:  1073741824 plain text --> 1106221296 encrypted
    2G:  2147483648 plain text --> 2212437647 encrypted
    8G:  8589934592 plain text --> 8849744181 encrypted

A fair amount of disk space is used for intermediate files during encryption.
Encrypting an 8G plaintext file will *temporarily* require up tp 28G disk space (total)::

      -rw-------  1 jgray     4357464064 8gig.enc         # grows to 8849744181
      -rw-------  1 jgray     8589934592 8gig.zeros
      -rw-------  1 jgray    11632203140 8gig.zeros.aes256            # deleted
      -rw-------  1 jgray            512 8gig.zeros.aes256pwd.rsa
      -rw-------  1 jgray            667 8gig.zeros.meta

The reason for such space requirements is that, currently, the original file is
only deleted after all the other steps have
been carried out (and carried out successfully). The idea is to ensure as complete check that everything
was indeed successful. Presumably--and with a slightly higher risk of losing data, in
theory--one could delete the original file after the AES encryption and before
archiving it. Only the encrypted (.aes256) file goes in the ``.enc``` archive, not the original.

The larger .aes256 files get removed, leaving::

      -rw-------  1 jgray    8849744181  8gig.enc


FAQ / Questions
----------------

Q: Will encryption make my data safe?

A: Think of it as adding another layer of security, of itself not
being a complete solution. There are many issues involved in securing your
data, and encryption alone does not magically solve all of them. Security needs
to be considered at all stages in the process. The encryption provided
is genuinely strong encryption (and as such could cause problems). Key management
is the hard part. And don't skip physical, legal, and procedural aspects of security.

Q: What if my private RSA private key is no longer private?

A: Obviously, try to avoid this situation. **Fix:** 1) Generate a new
RSA key-pair, and then 2) ``rotate()`` the encryption on all files that were encrypted
using the public key associated with the compromised private key.

The meta-data includes information about what public key was used for
encryption, to make it easier to identify the relevant files. But even without that
information, you could just try ``rotate()``'ing the encryption on all files, and it
would only succeed for those with the right key pair. The meta-data are not
required for key rotation. By design, pyFileSec is not needed for rotation (or decryption).
It is basically just a wrapper to make it easier to work with
standard, strong encryption tools, and document what was done and how.

Q: What should I do if my private RSA private key is reaching its expected end-of-life (see
http://www.keylength.com)?

A: You should expect to do this. The ``rotate()`` function helps make this transition
as easy as possible. Just generate a new RSA key-pair, and ``rotate()`` the encryption.
It would be trivial to write a ``rotate_all()`` function to find all encrypted files
in a directory, and rotate the encryption on those files.

Q: What if the internal (AES) password was disclosed (i.e., not the RSA private
key but the one-time password that is used for the AES encryption)?

A: This is extremely unlikely during normal operation. If it should occur (e.g.,
maybe a power-failure or other crash at `precisely` the wrong time?) it would affect at
most one file. **Fix:** Just ``rotate()`` the encryption for that file, using
the same public key to re-encrypt. A new internal one-time password will be
generated during the re-encryption step. (The internal AES password is never re-used,
which is a crucial difference between the AES password and the RSA key pair.)

Q: What if I lose my private key?

A: Oops. **Fix:** None. The whole idea is that, if you don't have the private key,
data recovery should be prohibitively expensive, if its even possible (and it is
intended to not be possible). You should design your procedures under the
assumption that data recovery will not going to happen if you lose the private key,
even by hiring someone. (In fact, if someone can do so, please send me a private
email with details, I'll want to fix it!)
