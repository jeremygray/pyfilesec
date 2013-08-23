
:mod:`pyFileSec` File-oriented privacy and integrity management tools *(beta)*

.. toctree::
   :maxdepth: 2

==================================================================

File security in python
------------------------

**Security goal:** Protect computer files from casual inspection or accidental
disclosure. Robustness, ease of use, and API stability are more important than
the speed of code execution. Privacy assurance is more important than
integrity assurance.

pyFileSec is less about encryption (which it does handily, as do many other
excellent packages), and more about managing all the other issues that surface
when working with files. The target audience is people
who need to do system administration in a research lab (without being IT
professionals), and users and developers of software presentation programs for
human subjects research. Anyone needing file management with compatible
security goals could potentially benefit as well.

**Example use-case:** A researcher might wish to collect data about study
participants' drug-use history (and keep it confidential, even from trusted
people who are working in the lab). Ideally, confidentiality should be
protected through multiple means, including physical and legal.
Cryptographically, sentitive research data is ideally protected from within the
data collection program itself, to keep the potential disclosure window as
small as possible. It is also desirable to be able to encrypt it without ever
needing to be able to decrypt on the same computer, or store a decryption
password where it might be copied or disclosed (obviating the encryption).
Its typically useful to secure-delete the original file to avoid leaving sensitive information
on the disk (otherwise its not actually "gone", and can be readily recovered). And its
desirable to obscure the file size, e.g., so that a longer file cannot signal
greater drug use. And do so without having to worry about whether anyone left
Dropbox running on that testing room computer... Security is hard to achieve,
despite excellent tools for encryption being widely available. Even good and
trustworthy people can make mistakes. And doing so is undesirable and
stressful for eveyrone. pyFileSec can help.

**Cautions:** Using encryption in a research context requires some consideration.
Perhaps the most important thing to keep in mind is that, depending on your
circumstances, the use of encryption (or particular forms of encryption) can conflict with
policies of your boss, institution, or even government. You are responsible for
knowing your situation, and for the consequences of your decisions about whether
and how to use encryption.

pyFileSec's encryption is easily adequate for the purpose of secure data transfer,
and is thought to be appropriate even for medium-term archiving (see
http://www.keylength.com/ and http://www.win.tue.nl/~klenstra/key.pdf).
Even so, the overall degree of achieved security will be higher if the data have
low economic value, and will be much higher if the lab has reasonable physical
and network security, with only trusted people working there. The encryption is
definitely strong enough to cause trouble. Consider an example:
Although you can lock yourself out of your own car or house, you can hire someone
with training and tools to break in on your behalf. With encryption, however, it
would likely be prohibitively expensive to hire someone to "break in on your behalf";
hpefully that is not possible, even for a well-funded adversary. So you could
actually lose data by trying to secure it.

**Development status:** As of version 0.2.0, the development status is **beta**,
meaning that things seem to be working well despite some rough edges and known
limitations, which are hopefully mostly described well enough to know what they
are. Being beta, API changes are still possible, and will be documented in the
changelog. The development emphasis is mostly on making sure that the current
features are as secure as possible and work as intended on Mac, Linux, and
Windows. Documentation is a work in progress. A few extensions are planned
(notably an alternative encryption backend, and zip for archive). Setting file
permissions on Windows needs work. Python 3 support looks easy; ``2to3`` passes
now, but python 3 is completely untested.

Comments and code contributions are welcome. Feedback can be posted on github
(see issues at https://github.com/jeremygray/pyfilesec/). Contact by
private email is preferred for anything sensitive, such as security concerns.


Usage Examples
---------------
See the demos/ directory (and its readme.txt) for python and shell script examples.


Principles and Approach
------------------------

Using public-key encryption allows a non-secret "password" (the public key) to
be distributed and used for encryption. This separates encryption from decryption,
allowing their physical separation, which gives considerable flexibility. The idea
is that anyone anywhere can encrypt information that only a trusted process (with
access to the private key) can decrypt. For example. multiple testing-room computers
could have the public key,
encrypt the data from each subject so that it can be sent to a central computer
for analysis and archiving, without the private key ever needing to be exposed.
Its the private key that is essential to keep private.

pyFileSec does not, of itself, contain cryptographic code, but instead relies on
a 3rd party implementation. In particular, cryptographic operations use the
widely used software package, OpenSSL (see openssl.org), using its implementation
of RSA and AES. These are industry standards and can be very secure when used correctly.
The effective weak link is almost certainly not cryptographic but rather in how the
encryption key(s) are handled, which partly depends on you, including what happens
during key generation, storage, and backup. If the keys are bad or compromised,
the encryption strength is basically irrelevant. The strength of the lock on
your front door is basically irrelevant if you leave the key under the doormat.

Some considerations:

- A test-suite is included as part of the library. The aim is to provide complete
  coverage; we're not there yet.
- OpenSSL is not distributed as part of the library (see installation).
- You should encrypt and decrypt only on machines that are physically secure,
  with access limited to trusted people. Although encryption can be done anywhere,
  using a public key, if someone used a different public key to encrypt data
  intended for you, you would not be able to access those data.
- By design, the computer used for encryption can be different from the computer used
  for decryption; it can be a different device, operating system, and openssl version.
- Ideally, do not move your private key from the machine on which it was
  generated; certainly never ever email it. Its typically fine to share the public
  key, certainly within a small group of trusted people, such as a research lab.
- Some good advice from GnuPG: "If your system allows for encrypted swap partitions,
  please make use of that feature."

- The goal is to rely exclusively on standard, widely available & supported tools and algorithms.
  OpenSSL and the basic approach (RSA + AES 256) are well-understood and recommended,
  e.g., by Ferguson, Schneier, & Kohno (2010) Cryptography engineering. Indianapolis, Indiana: Wiley.
- Always use and return full paths to files, not relative paths.
- Avoid obfuscation and so-called "security through obscurity". Obfuscation does
  not enchance security, yet can make data recovery more difficult or expensive.
  So transparency is more important. For this reason, meta-data are generated by
  default to make things less obscure (although this can be suppressed).
- Encryption will refuse to proceed if the OpenSSL version is lower than 0.9.8.
- Encryption will not proceed if the public key < 1024 bits; you should only use 2048 or higher.
- For the AES encryption, a 256-bit password is generated for each encryption event.
- For ease of archiving and handling, everything is bundled as one ``.tgz`` file,
  with ``.enc`` as the extension. It can be unbundled using ``tar`` but is still
  encrypted.
- pyFileSec does not try to manage the RSA keys. Its up to the user to do so.


Installation
---------------------

pyFileSec
=====================

Do things in the usual way for python packages::

    % pip install pyFileSec

pyFileSec does not package a copy of OpenSSL, which you'll need.

OpenSSL
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

secure-delete
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

Command-line syntax is described using the usual ``--help`` option::

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


Performance and tests
----------------------

The built-in tests can be run from the command line::

    $ py.test pyfilesec.py

or from within the main directory just::

    $ py.test

To see log messages during tests::

    $ python pyfilesec.py debug

All tests pass on Mac and Linux. All except unicode in filename and file permissions
pass on Windows 7. If you try the 'debug' option, note that some of the tests
are designed to check error situations; i.e., what is being tested is that situations
that should fail, do fail, and are recognized as failure situations. This means
that in the verbose output you should see some things that look exactly like error
messages (e.g., "RSA operation error") because these are logged.

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
