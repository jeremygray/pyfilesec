
"""Changelog:

    April 2013:
    - Very helpful code review by Michael Stone.

    May 2013:
    - version update to 0.1.0
    - send / retrieve password to openssl thru stdin instead of a tmp file
    - generate AES password using random.SystemRandom().getrandbits(256)
    - avoid unique filenames growing too long, add "(1)", "(2)", etc
    - wipe() now uses OS-specific system tools: srm, shred, sdelete
      Other changes mean that its less needed than it was before.
      Sets write-permission True before tring to remove.
      Checks for other hardlinks to the same inode, warns if they exist.
      sdelete = http://technet.microsoft.com/en-us/sysinternals/bb897443.aspx
    - compute _sha256() digests in chunks, in case of large files
    - meta-data:
        - use dicts, json.dump/load as files: {date1: {md1}, date2: {md2}, ...}
        - option to suppress orig date, replaced with "(date-time suppressed)"
        - HMAC-SHA256 option:
            HMAC is generated only if a key is provided
            sha256 of the hmac key is saved
    - sign & verify now use openssl 'dgst' instead of 'rsautl'.
        beware of openssl version issues in signatures
    - many additional tests, including whitespace + unicode in paths
    - always chmod decrypted files to 0o600; set umask beforehand
    - try to secure-remove decrypted file if get an exception during decryption
    - set file size limited to 1G; likely could go larger but need to consider
      speed (so does not appear to just hang), free RAM, 32 vs 64-bit, etc
    - can now pad files to be a specific file-size, and unpad. can change the
      padding when rotating the encryption
    - py.test compatible
    - codec registry class. works for defaults but will need
        more work esp file extensions (eg, '.aes256') and how to pass arguments
    - command line options:
        -h | --help, --verbose, --version, --debug
        --openssl=/path/to/openssl  (eg: /usr/local/ssl/bin/openssl )
    - PEP8 compliant code (almost)

    To be added to documentation:
    - an encrypted or decrypted file will be created in the same directory as
      the original
    - the code will always decrypt a /copy/ of data.enc, and not touch orig
    - the command-line mode means that non-python programs can access pyfilesec
      functions if they can do system calls.
    - RSA pub-key is thought to be medium-term-secure if 2048+ bits;
      see http://www.keylength.com
    - tries to use 256 bits for the openssl enc password using
        random.SystemRandon.getrandbits(nbits)
    - *.enc files are simply .tgz files, "tar xvf filename.enc"
    - file time-stamps will leak date-time info even if you set date=False
    - Need to watch that the orig file path doesn't contain anything sensitive;
      it gets saved into the meta-data in clear text
    - file length is not obscured by default; typically in psych / human neuro,
      the file length would not tell you a lot about its contents, although
      there could be exceptions, e.g., for criminal records. for this reason,
      `pad()` and `_unpad_strict()` are provided, but the onus is on the user
      them. Call before `encrypt()` and after `decrypt()`.
    - to encrypt a directory, the user must first bundle it as a single file,
      e.g., using opensslwrap.archive(dir_path), and then encrypt that. *But*
      you must also manage any desired file clean-up / secure delete of the
      orig files. `encrypt()` only secure-deletes the original of the file
      that it was requested to encrypt.
    - expects OpenSSL to use en_US locale in error messages; otherwise errors
      are unlikely to be parsed in detail; the python locale is irrelevant.
    - explain how to do encrypt-then-HMAC (good as a strategy):
        http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)
    - tests for randomness quality could only catch really egregious cases, do
        not seem worth doing
    - a minimal custom codec is provided (see tests) as proof of concept:
        Strongly suggest only add another codec if its demonstrably better than
        RSA+AES256. The point of the codec is to provide a transition path in
        the event that the current choice becomes weak. The point is not to
        provide flexibility for the sake of flexiblity, but rather to give an
        escape hatch: Demonstrate future-proofing, but don't use it until
        forced. You might be forced by a company or university policy for
        example (e.g., only using a specific approved version of pgp).
    - References:
        1. N. Ferguson, B. Schneier, & T. Kohno 2010. Cryptographic
            engineering. Wiley Publishing Inc: Indianapolis IN, USA
        2. http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html

    - tested with 6 versions of openssl, on Mac OS X and 3 linux distributions:
        OpenSSL 0.9.8r  8 Feb 2011     Mac 10.8.3, python 2.7.3
        OpenSSL 1.0.1e 11 Feb 2013     same Mac, openssl via macports
        OpenSSL 1.1.0-dev xx XXX xx    same Mac, clone from github & compile
        OpenSSL 1.0.0-fips 29 Mar 2010 CentOS 6.4, python 2.6.6
        OpenSSL 1.0.1  14 Mar 2012     Ubuntu 12.04.2 LTS, python 2.7.3
        OpenSSL 0.9.8o 01 June 2010    Debian (squeeze), python 2.6.6
      Using rsautl passes on all platforms tested to date; pkeyutl does not.
      Recovering a known file signature only works if the reference sig was
      created by the same version (0.9.8r vs 1.0.*).

    To-do near-term:
    - add generate RSA keys options and documentation; its not easy to export
        PEM format from GPG, you get PGP-format .asc
        docs: note that a good entropy source is not trivial, and getting a
        hardware source is the way to go for demanding applications
    - test everything on Windows, esp mkdtemp, sdelete (what default path?)
        random.SystemRandom(), openssl (what install dir?),
        hardlink detection (in wipe), umask, padding,
        time.time/time.clock (now used in wipe as well),
        how long does 'where /r C:\ openssl.exe' take?
    - add tests for:
        preserve orig file in case of failed encryption
    - docs

    Medium-term:
    - tarfile.TarInfo() for managing owner, permissions, time, etc
    - sphinx docs
    - make _encrypt_x / _decrypt_x truly modular, pass in all needed values
    - MS: CBC is not so great here, esp. if you care about data integrity and
        about secrecy. Instead, you probably want an "authenticated encryption"
        scheme like "Encrypt-then-MAC", the "GCM" cipher mode, or something
        more friendly like the primitives included in NaCl/libsodium:
          http://nacl.cr.yp.to/
          https://github.com/jedisct1/libsodium
        # JRG: unclear about the issue; only because CBC does not do HMAC?
        # OpenSSL added GCM support in 1.0.1;
        # by default macs are still on 0.9.8r
        # the design decision to stick with openssl still seems reasonable;
        #    supporting a pycrypto backend might be useful
        # encrypt-then-MAC is robust as separate steps
        # see http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
      could add _encrypt_aes256gcm function if this becomes urgent

    Long-term (think about):
    - first-run / --setup wizard:
        run self-tests
        enable / disable RSA key generation; don't want to generate keys all
          the time or haphazardly; key proliferation is a bad thing
        set / confirm paths to openssl, sdelete
        add alias to __file__ to shell path for command line usage
    - more to pkeyutl instead of rsautl when possible; currently not:
        -decrypt with passphrase seems to fail, maybe -sign as well
    - use zip instead of tar for file bundle, easier to work with items in mem
    - documentation: when is HMAC or other integrity assurance most useful?
    - decrypt to a tempfile.SpooledTemporaryFile() instead of cleartext file
    - rewrite enc / dec as a class

    Related projects:
    pyOpenSSL - "thin wrapper around (a subset of) the OpenSSL library"
    pycrypto - complete, need to compile; might be a backend but it seems
        like should always prefer OpenSSL if at all possible
    M2Crypto - "M2Crypto is the most complete Python wrapper for OpenSSL"
    pycryptopp - not complete enough: "AES, XSalsa20, and Ed25519 signatures."
    pycogworks.crypto - interesting but no crypto except an ID generator
"""
