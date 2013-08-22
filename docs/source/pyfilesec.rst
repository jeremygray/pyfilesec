
:mod:`pyFileSec` Encryption *(alpha)*

============================================================

Overview
-----------

**Aim:** Better protect psychology and neuroscience lab information (e.g., from
human subjects) from casual inspection or accidental disclosure, using public-key
encryption for security and flexibility.

Example use-case: Encrypt a subject's drug-use questionnaire data on a testing-room
computer, before moving or archiving it. The idea is to so as soon as possible,
ideally from within the questionnaire presentation program itself. It is also desirable to be able to
encrypt it without ever needing to be able to decrypt on the same computer or
store a decryption password in an archive. Secure-delete the original file to
avoid leaving sensitive information on the disk.

Using a public-key encryption allows a non-secret "password" (the public
key) to be distributed and used for encryption. This separates encryption from decryption,
allowing their physical separation, which gives considerable flexibility. The idea
is that anyone anywhere can encrypt information that only a trusted process (with
access to the private key) can decrypt.
Its the private key that is essential to keep private.

Encryption in a research context involves some special considerations. Perhaps the most important
thing to note is that, depending on your circumstances, the use of encryption
can conflict with policies of your boss or institution (or even government).
You are responsible for knowing your situation, and for the consequences of
your decisions about whether and how to use encryption.

The aim is for the encryption to be effective for the  purpose of data transfer
and storage within a lab. The overall approach assumes that a) the data have low
economic value data, and b) the lab has reasonable physical and network security,
and has only trusted people working there. The encryption is definitely strong
enough to cause serious trouble if used incorrectly. Consider an example:
Although you can lock yourself out of your own car or house, you can hire someone with training
and tools to break in on your behalf. With encryption, however, it would likely
be prohibitively expensive to hire someone to "break in on your behalf", and
hopefully is not possible (even for a well-funded adversary). So, a caution:
you could actually lose your data by trying to secure it.

**Status & Caveats:** As of August 2013, this is **alpha** quality software,
made available for **evaluation and testing purposes**. All feedback can be
posted on github (https://github.com/jeremygray/pyfilesec/issues).

The built-in tests can be run from the command line::

    $ py.test pyfilesec.py

or::

    $ python pyfilesec.py debug

All tests pass on Mac and Linux. All except unicode in filename and file permissions
should pass on Windows. If you try the 'debug' option, note that some of the tests
are designed to check error situations; i.e., what is being tested is that situations
that should fail, do fail, and are recognized as failure situations. This means
that in the verbose output you should see some things that look exactly like error
messages (e.g., "RSA operation error") because these are logged.

**Cryptographic strategy:** pyFileSec does not, of itself, contain cryptographic
code, but instead relies on a 3rd party implementation. In particular, all
encryption methods rely only on the widely used software package, OpenSSL
(see openssl.org), using its implementation of RSA and AES. These are industry
standards and are very secure when used correctly. The effective weak link is
almost certainly not cryptographic but rather in how the
encryption key(s) are handled, which partly depends on you, including what happens during key generation,
storage, and backup. If the keys are bad or compromised, the encryption strength is
basically irrelevant. The strength of the lock on your front door is not
irrelevant if the key is left under the doormat.

Some considerations:

- A test-suite is provided as part of the library.
- OpenSSL is not distributed as part of the library. You need to obtain it separately
  (and may already have it; see Installation).
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

**Usage Examples:**

See the demos/ directory for usage examples (python script, shell script).

**Questions:**

Q: Will encryption make my data safe?

A: Think of it as adding another layer of security, of itself not
being a complete solution. There are many issues involved in securing your
data, and encryption alone does not magically solve all of them. Security needs
to be considered at all stages in the process. The encryption provided (RSA + AES)
is genuinely strong encryption (and as such could cause problems). Key management
is the hard part (which is why PsychoPy does not attempt to do it for you.)

Q: What if I think my private RSA private key is no longer private?

A: Obviously, try to avoid this situation. If it happens: 1) Generate a new
RSA key-pair, and then 2) ``rotate()`` the encryption on all files that were encrypted
using the public key associated with the compromised private key.

The meta-data includes information about what public key was used for
encryption, to make it easier to identify the relevant files. But even without that
information, you could just try ``rotate()``'ing the encryption on all files, and it
would only succeed for those with the right key pair. The meta-data are not
required for key rotation. PsychoPy is not needed for rotation (or decryption).
Even opensslwrap is not needed: It is just a wrapper to make it easier to work with
standard, strong encryption tools (i.e., openssl).

Q: What if the internal (AES) password was disclosed (i.e., not the private
key but the one-time password that is used for the AES encryption)?

A: This is extremely unlikely during normal operation. If it should occur (e.g.,
due to a power-failure or other crash at just the wrong time) it would affect at
most one file. Fix: Just ``rotate()``
the encryption for that file, using the same public key to re-encrypt. That is, if you rotate
with the same key pair, a new internal one-time password
will be generated during the re-encryption step. (The internal AES password is never re-used,
which is a crucial difference between the AES password and the RSA key pair.)

Q: What if I lose my private key?

A: Oops. The whole idea is that, if you don't have the private key, data recovery
should be a prohibitively expensive proposition, if its even possible (and it is
intended to not be possible). You should design your procedures under the
assumption that data recovery will not going to happen if you lose the private key,
even by hiring someone. (In fact, if someone can do so, please send me a private
email reporting this as a security bug. I'll want to fix it.)

**Known limitations:**

- Intended for use in a lab, with low throughput. The code depends on calls to
  openssl, which is not terribly fast.
- Files up to 8G (gigabytes) have been tested and seem fine. Avoid padding files
  larger than 8G.
- Testing so far has been in limited testing environments. All tests pass on:

    - Mac 10.6.8  OpenSSL 0.9.8r  python 2.7.1
    - Win XP sp2  OpenSSL 1.0.1  python 2.6.6
    - CentOS 6.2  OpenSSL 1.0.0  python 2.7.2 (without psychopy installed)

    Plus: a file encrypted on a Mac decrypted on both Win XP and CentOS.


See
:ref:`performance`

**Principles and Approach:**

- Rely exclusively on standard widely available & supported tools and algorithms.
  OpenSSL and the basic approach (RSA + AES 256) are well-understood and recommended,
  e.g., http://crypto.stackexchange.com/a/15/ .
- Eventually opensslwrap.py will be signed and verifyable (once its more stable).
- Avoid obfuscation and "security through obscurity".
  Obfuscation does not enchance security, yet can make data recovery more difficult
  or expensive. So transparency is more important. For this reason, meta-data
  are generated by default (which can be disabled). In particular, using explicit
  labels in file names does not compromise security; it just makes things less obscure..
- Encryption will refuse to proceed if the OpenSSL version < '0.9.8'; this will
  eventually go higher.
- Encryption will not proceed if the public key < 1024 bits (but go with 2048).
- AES256 is very strong cryptographically but requires a password (for symmetric
  encryption). A one-time password is generated, and never re-used for other data.
- One key step is to use the password (and salt) to AES-encrypt the data::

    $ openssl enc -e -aes-256-cbc -a -salt -in file.txt -out file.enc -pass file:<pwd_file>

- A second key step is to RSA public-key encrypt the password (using OAEP padding)::

    $ openssl rsautl -in pwd_file.txt -out pwd_file.rsa -inkey public.pem -pubin -oaep -encrypt

- Include a hash (sha256) of the encrypted file in the meta-data.
- Bundle the bits together for ease of archiving and handling (one .tgz file,
  using ".enc" as the extension).
- Decrypt by using the private key to recover the password (which is one of the files in
  the .tgz bundle), and then use the password to recover the data (from the AES-
  encrypted file in the bundle).
- The program does not try to manage the RSA keys. Its completely up to you (the user).
- Use and return full paths to files, to reduce ambiguity.

Installing OpenSSL
---------------------

- Mac & linux: openssl should be installed already, typically in /usr/bin/openssl
  If fact, if openssl is in a different location, a warning will be generated.
- Windows: download from http://www.slproweb.com/products/Win32OpenSSL.html
  On win XP, install into C:\\OpenSSL-Win32\\bin\\openssl.exe;
  Windows Vista and later will try to discover the installation path (not tested)


Encryption, Decryption
------------------------
.. autofunction:: pyfilesec.encrypt
.. autofunction:: pyfilesec.decrypt
.. autofunction:: pyfilesec.rotate

To set the path to OpenSSL, you can use
.. autofunction:: pyfilesec.set_openssl

Sign & verify
---------------------------
.. autofunction:: pyfilesec.sign
.. autofunction:: pyfilesec.verify

Pad (obscure a file's size)
----------------------------------
.. autofunction:: pyfilesec.pad
.. autofunction:: pyfilesec.ok_to_pad
.. autofunction:: pyfilesec.pad_len

Secure delete
---------------------------
.. autofunction:: pyfilesec.destroy

Codec Management
-------------------
.. autoclass:: pyfilesec.PFSCodecRegistry
