
:mod:`pyFileSec` File-oriented privacy and integrity management tools *(beta)*

.. toctree::
   :maxdepth: 2

==================================================================

File security in python
------------------------

**Goal:** Better protect research data from casual inspection or accidental
disclosure in a research lab. Robustness, ease of use, and API stability are
more important than code-execution speed.

pyFileSec is less about encryption (which it does handily), but about managing
the other details when working with files. The target audience is people
who do system administration tasks in a lab setting (without necessarily being
IT professionals), and people who develop software presentation programs for human
subjects research.

**Example use-case:** A researcher might wish to collect--and also protect--data
about a subject's drug-use history. Ideally, this should be done from within the
computer presentation program itself, to keep the possible disclosure window as
small as possible. It is also desirable to be able to encrypt
it without ever needing to be able to decrypt on the same computer or store a
decryption password where is might be copied. Its typically useful to secure-delete
the original file to
avoid leaving sensitive information on the disk. And to obscure the file size,
so that a longer file cannot signal a more extensive history of drug use. And do
so without having to worry about whether someone left Dropbox running on that
testing room computer... Even good people can make mistakes.

**Cautions:** Encryption in a research context involves some special considerations.
Perhaps the most important is that, depending on your circumstances, the use of
encryption can conflict with policies of your boss, institution, or even government.
You are responsible for knowing your situation, and for the consequences of
your decisions about whether and how to use encryption.

pyFileSec's encryption should be easily adequate for the purpose of data transfer
and medium-term (10 year) archiving within a lab. Even so, the overall degree of
achieved security will be higher if a) the data have low
economic value data, and b) the lab has reasonable physical and network security,
and has only trusted people working there. The encryption is definitely strong
enough to cause trouble if used incorrectly. Consider an example:
Although you can lock yourself out of your own car or house, you can hire someone
with training and tools to break in on your behalf. With encryption, however, it
would likely be prohibitively expensive to hire someone to "break in on your behalf",
and hopefully is not possible even for a well-funded adversary. So you could
actually lose data by trying to secure it.

**Status:** As of August 2013, the development status is **beta**, meaning that
the emphasis is mostly on making sure that the current features work as intended
on many platforms, and are complete and documented. One extension is planned (alternative
encryption backend), and being able to set file permissions on Windows needs work
still. Python 3 support would be good; ``2to3`` passes now but I have not tested
at all under python 3. Comments and code contributions are welcome. Feedback can be posted on github
(project pyfilesec; see issues); private email is preferred for anything sensitive, such
as initial reports of any security concerns.

The built-in tests can be run from the command line::

    $ py.test pyfilesec.py

or just::

    $ py.test

or::

    $ python pyfilesec.py debug

All tests pass on Mac and Linux. All except unicode in filename and file permissions
should pass on Windows. If you try the 'debug' option, note that some of the tests
are designed to check error situations; i.e., what is being tested is that situations
that should fail, do fail, and are recognized as failure situations. This means
that in the verbose output you should see some things that look exactly like error
messages (e.g., "RSA operation error") because these are logged.

**Cryptographic strategy:**

Using public-key encryption allows a non-secret "password" (the public key) to
be distributed and used for encryption. This separates encryption from decryption,
allowing their physical separation, which gives considerable flexibility. The idea
is that anyone anywhere can encrypt information that only a trusted process (with
access to the private key) can decrypt. Its the private key that is essential to
keep private.

pyFileSec does not, of itself, contain cryptographic code, but instead relies on
a 3rd party implementation. In particular, cryptographic operations use the
widely used software package, OpenSSL (see openssl.org), using its implementation
of RSA and AES. These are industry standards and can be very secure when used correctly.
The effective weak link is almost certainly not cryptographic but rather in how the
encryption key(s) are handled, which partly depends on you, including what happens during key generation,
storage, and backup. If the keys are bad or compromised, the encryption strength is
basically irrelevant. The strength of the lock on your front door is not
irrelevant if the key is left under the doormat.

Some considerations:

- A test-suite is provided as part of the library.
- OpenSSL is not distributed as part of the library.
- Encrypt and decrypt only on trusted machines, with access limited to trusted people.
  Although encryption can be done anywhere, using a public key, if someone used
  a different public key to encrypt data intended for you, you would not be able
  to access those data.
- By design, the computer used for encryption can be different from the computer used
  for decryption; it can be a different device, operating system, and openssl version.
- "Best practice" is not to move your private key from the machine on which it was
  generated; certainly never ever email it. Its fine to share the public key.
- Some good advice from GnuPG: "If your system allows for encrypted swap partitions,
  please make use of that feature."

Usage Examples
---------------
See the demos/ directory for python and shell script examples.

FAQ / Questions
----------------

Q: Will encryption make my data safe?

A: Think of it as adding another layer of security, of itself not
being a complete solution. There are many issues involved in securing your
data, and encryption alone does not magically solve all of them. Security needs
to be considered at all stages in the process. The encryption provided
is genuinely strong encryption (and as such could cause problems). Key management
is the hard part.

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

Q: What if the internal (AES) password was disclosed (i.e., not the private
key but the one-time password that is used for the AES encryption)?

A: This is extremely unlikely during normal operation. If it should occur (e.g.,
due to a power-failure or other crash at just the wrong time) it would affect at
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

**Known limitations:**

- Intended for use in a lab, with low throughput. The code depends on calls to
  openssl, which is not terribly fast.
- Encrypting files up to 8G (gigabytes) in size works fine. Padding files with
  more than 8G of padding will have problems, but it seems unlikely that such
  massive padding would be needed.
- File permissions are set to conservative values on Mac and Linux. Windows
  permissions will be added at some point, not sure the priority yet.


Principles and Approach
------------------------

- Rely exclusively on standard widely available & supported tools and algorithms.
  OpenSSL and the basic approach (RSA + AES 256) are well-understood and recommended,
  e.g., see Ferguson, Schneier, & Kohno (2010) Cryptography engineering. Indianapolis, Indiana: Wiley.
- Avoid obfuscation and "security through obscurity".
  Obfuscation does not enchance security, yet can make data recovery more difficult
  or expensive. So transparency is more important. For this reason, meta-data
  are generated by default (which can be disabled). In particular, using explicit
  labels in file names does not compromise security; it just makes things less obscure..
- Encryption will refuse to proceed if the OpenSSL version is lower than 0.9.8.
- Encryption will not proceed if the public key < 1024 bits (but go with 2048).
- For the AES encryption, a 256-bit password (session key) is generated, and never re-used for other data.
- Include a hash (sha256) of the encrypted file in the meta-data.
- For ease of archiving and handling everything is bundled as one .tgz file,
  using ".enc" as the extension.
- The program does not try to manage the RSA keys. Its completely up to the user.
- Use and return full paths to files, to reduce ambiguity.


Performance and tests
----------------------

The test-suite
==============

The integrated test-suite is designed to be used with `py.test`. All tests in
`class Tests` are discovered and run::

    % py.test pyfilesec.py

The same tests can also be run via debug mode,
saving logging messages and intermediate files. Invoke from the command line
with option `debug`, and redirect the output to a log file::

    % python pyfilesec.py debug > log

For details of the specific tests, consult the code directly.

Beyond the test-suite
========================

Files encrypted on one machine can be decrypted on a different platform. (Not
tested yet with machines with different endian-ness, however.)

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
will vary with CPU, disk speed, etc)::

    1K takes < 1s
    1M takes ~10s to encrypt, ~5s decrypt
    1G takes ~90s to encrypt, ~60s decrypt
    8G takes ~13m to encrypt

Large files are fine (max tested is 8G). File-size inflation is consistently 3%::

    1G:  1073741824 plain text --> 1106221296 encrypted
    2G:  2147483648 plain text --> 2212437647 encrypted
    8G:  8589934592 plain text --> 8849744181 encrypted

A fair amount of disk space is used for intermediate files during encryption.
An 8G plaintext file will temporarily require ~28G disk space (total)::

      -rw-------  1 jgray     4357464064 8gig.enc         # grows to 8849744181
      -rw-------  1 jgray     8589934592 8gig.zeros
      -rw-------  1 jgray    11632203140 8gig.zeros.aes256            # deleted
      -rw-------  1 jgray            512 8gig.zeros.aes256pwd.rsa
      -rw-------  1 jgray            667 8gig.zeros.meta

The larger .aes256 files get removed, leaving::

      -rw-------  1 jgray    8849744181  8gig.enc


Installation
---------------------

install pyFileSec
=====================

Do things in the usual way for python packages::

    % pip install pyFileSec

pyFileSec does not package a copy of OpenSSL, which you'll need.

install OpenSSL
=================

On Mac and Linux, its very likely that you have OpenSSL already. To check, type
``which openssl`` in a terminal window, and it will probably say ``/usr/bin/openssl``.
It is also possible to install a different version of OpenSSL (e.g., compile a
development release, or use a homebrew version). You then need to specify the
non-default version to use; see command-line option ``--openssl`` and the API function
``set_openssl``.

On Windows, generally you'll need to download and install OpenSSL (free).
Get the latest version from http://slproweb.com/products/Win32OpenSSL.html; a
"Light" version should be fine. There's a good chance that you will first need
to install the "Visual C++ 2008 Redistributables" (free download from the same
page), and then install OpenSSL. OpenSSL will install to ``C:\OpenSSL-Win32`` by default.
pyFileSec should now be able to detect and use OpenSSL.

install secure-delete
========================

On Mac and Linux, a secure file-removal utility should already be present. To confirm
this on a Mac, type ``which srm`` in a terminal. On Linux, type ``which shred``.

On Windows, download a program called ``sdelete`` (free, from Microsoft)
http://technet.microsoft.com/en-us/sysinternals/bb897443.aspx
and install. pyFileSec should now be able to detect and use ``sdelete.exe``.

On windows, the command ``cipher`` has an option to securely erase files that
have already been deleted. However, this can take a long time (20-30 minutes)
and is not suited for file-oriented secure deletion.


API
------------------------

The API describes how to call functions from within python. An understanding of
the parameters will be useful for command-line / shell-script usage.

Command-line syntax is described using the usual ``--help | -h`` option::

    % python pyfilesec.py --help

Encryption, Decryption
============================
.. autofunction:: pyfilesec.encrypt
.. autofunction:: pyfilesec.decrypt
.. autofunction:: pyfilesec.rotate

Sign & verify
============================
.. autofunction:: pyfilesec.sign
.. autofunction:: pyfilesec.verify

Pad (obscure a file's size)
============================
.. autofunction:: pyfilesec.pad
.. autofunction:: pyfilesec.ok_to_pad
.. autofunction:: pyfilesec.pad_len

Secure delete
============================
.. autofunction:: pyfilesec.destroy

Misc helper functions
============================

To set the path to OpenSSL, you can use:

.. autofunction:: pyfilesec.set_openssl

To generate RSA key pairs:

.. autofunction:: pyfilesec.genRsaKeys

Other functions:

.. autofunction:: pyfilesec.command_alias
.. autofunction:: pyfilesec.hmac_sha256
.. autofunction:: pyfilesec.load_metadata
.. autofunction:: pyfilesec.log_metadata
