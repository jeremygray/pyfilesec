
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
    - always chmod decrypted files to 0o600 (*nix); set umask beforehand
    - try to secure-remove decrypted file if get an exception during decryption
    - can now pad files to be a specific file-size, and unpad. can change the
      padding when rotating the encryption
    - py.test compatible
    - codec registry class. works for defaults but will need
        more work esp file extensions (eg, '.aes256') and how to pass arguments
    - command line options:
        -h | --help, --verbose, --version, debug, genrsa
        --openssl=/path/to/openssl  (eg: /usr/local/ssl/bin/openssl )
    - PEP8 compliant code (almost)
    - gc.set_debug(gc.DEBUG_LEAK) finds nothing uncollectable during
        "python pyfilesec.py debug"

    To be added to documentation:
    - what are the security + management goals, what is primary, what secondary
    - an encrypted or decrypted file will be created in the same directory as
      the original
    - the code will always decrypt a /copy/ of data.enc, and not touch orig
    - the command-line mode means that non-python programs can access pyfilesec
      functions if they can do system calls.
    - RSA pub-key is thought to be medium-term-secure if 2048+ bits;
        see http://www.keylength.com
        keys generated with poor sources of randomness will be weaker, so to
        achieve an effective 2048-bit key a 4096-bit key is not unreasonable.
        8192 is included as a proof-of-feasability, not because its necessary.
    - tries to use 256 bits for the openssl enc password using
        random.SystemRandon.getrandbits(nbits)
    - no attempt made to mitigate side-channel attacks (out of scope)
    - *.enc files are simply .tgz files, "tar xvf filename.enc"
    - file time-stamps will leak date-time info even if you set date=False
    - Need to watch that the orig file path doesn't contain anything sensitive;
      it gets saved into the meta-data in clear text
    - file length is not obscured by default; typically in psych / human neuro,
      the file length would not tell you a lot about its contents, although
      there could be exceptions, e.g., for pedical or criminal records. for this reason,
      `pad()` is provided, but the onus is on the user. Call before `encrypt()`
      and after `decrypt()`, or during `rotate()`.
    - to encrypt a directory, the user must first bundle it as a single file,
      e.g., using make_archive(dir_path), and then encrypt that. *But*
      you must also manage any desired file clean-up / secure delete of the
      orig files. `encrypt()` only secure-deletes the original of the file
      that it was requested to encrypt.
    - expects OpenSSL to use en_US locale in error messages; otherwise errors
      are unlikely to be parsed in detail; the python locale is irrelevant.
    - explain how to do encrypt-then-HMAC (good as a strategy):
        http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)
    - tests for randomness quality could only catch really egregious cases, do
        not seem worth doing
    - a minimal custom codec is provided (see tests) as proof of feasability:
        Strongly suggest only add another codec if its demonstrably better than
        RSA+AES256. The point of the codec is to provide a transition path in
        the event that the current choice is discovered to be weak. The point is not to
        provide flexibility for the sake of flexiblity, but rather to give an
        escape hatch: Demonstrate future-proofing, but don't use it until
        forced to use it. You might be forced by a company or university policy for
        example (e.g., only using a specific approved version of pgp).
    - add generate RSA keys documentation; its not easy to export
        PEM format from GPG, you get PGP-format .asc; not east to import either.
        docs: note that a good entropy source is not trivial, and getting a
        hardware RNG is the way to go for demanding applications.
    - documentation: when is HMAC or other integrity assurance most useful?
        time-based HMAC string: retrieve from remote server that logs the request
        (time, IP address, and actual HMAC key), then also logs upload time of
        the encrypted file
    - approach: http://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope

    - References:
        1. N. Ferguson, B. Schneier, & T. Kohno. 2010. Cryptographic
            engineering: Design prinicples and practical applications.
            Wiley Publishing Inc: Indianapolis IN, USA
            ==> recommend RSA-oaep + AES256-CBC
            ==> use 256 bits to be more sure of getting 128-bit protection
        2. Colin Percival.
            ==> recommend AES256-CTR + separate HMAC, talk about "small attack surface"
            Posted at 2009-06-11 14:20
              http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
            Posted at 2009-06-24 22:15. Encrypt-then-MAC.
              http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
        3. encrypt-then-mac
            http://cseweb.ucsd.edu/~mihir/papers/oem.pdf

    TO-DO Medium-term (milestone 0.3 - 0.5):
    - "now" is localtime, but timezone is not documented in metadata
    - missing or bad metadata:
        internalFormatError to have other than 3 files in the .archive:
            encrypted data, encrypted password, meta-data
            in future, meta-data could become a zip or tar file if need extensibility
        raise InternalFormatError to have no metadata
        need explicit md = {'(date unknown)', None}
    - fix win32 unicode filename
    - win32 file permissions (win32security)
    - willing to support PyCrypto: if you have it through Enthought Canopy
        is easier than installing openssl on win32
    - willing to support gpg for RSA encryption of the AES password
        check for gpg version issues with this approach
        "   --passphrase-fd n
                Read the passphrase from file descriptor n.
            --passphrase-file file
                Read the passphrase from file file.

        encrypt:
        recipient_ID = pub  # not a .pem, like BE98EFB5
        cmd_GPG = ['gpg', '-e', '-r', recipient_ID, datafile]

        decrypt:
        recipient_ID = priv  # but its a GPG id, like BE98EFB5
        cmd_GPG = ['gpg', '-u', recipient_ID, '-d', '--passphrase-fd', '0', datafileEnc]
        pwd = _sysCall(cmd_GPG, stdin=passphrase)
        # cmd_GPG = ['gpg', '-u', recipient_ID, '-o', datafileDec, '-d', '--passphrase-fd', '0', datafileEnc]
        # _sysCall(cmd_GPG, stdin=passphrase)

        # "There is a small security glitch in the OpenPGP (and therefore GnuPG)
        # system; to avoid this you should always sign and encrypt a message
        # instead of only encrypting it."



        return datafileDec
    - test on Python 3.2
    - use zip instead of tar; tarfile.TarInfo() for managing owner, permissions, time, etc
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
        # by default macs are still on 0.9.8r (or 0.9.8x for 10.8.4)
        # the design decision to stick with openssl still seems reasonable;
        #    supporting a pycrypto backend might be good
        # encrypt-then-MAC has some merits as separate steps
        # see http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
      could add _encrypt_aes256gcm function if this becomes urgent

    Long-term (think about):
    - refactor _enc _dec into their own files, get hash, store hash in codec
        registry and meta-data
    - first-run / --setup wizard:
        run self-tests
        enable / disable RSA key generation; don't want to generate keys all
          the time or haphazardly; key proliferation is a bad thing
        set / confirm paths to openssl, sdelete
        add alias to __file__ to shell path for command line usage
        basic benchmarking of performance time to enc/dec by file size so that
          can make inferences about time based on file size when running
    - move to pkeyutl instead of rsautl when possible; currently not:
        -decrypt with passphrase seems to fail, maybe -sign as well
    - use zip instead of tar for file bundle, easier to work with items in mem
    - encrypt/decrypt from/to a tempfile.SpooledTemporaryFile() instead of
      cleartext file; mlock to keep from swap; encrypt the SpooledTempFile
    - rewrite enc / dec as a class

    OpenSSL entropy:
    Jakob Bohm jb-openssl@wisemo.com via openssl.org posted
        "When you use the "openssl genrsa" commandline command, it will load some
        random bytes from /dev/random or /dev/urandom
        and use those to seed the OpenSSL PRNG, which in turn is used to generate
        the private key.

        /dev/random and /dev/urandom reseed themselves from hardware as necessary.

        If you have a source of entropy other than /dev/random, you can pass it
        to "openssl genrsa -rand YourEntropyFile" and it will be used to seed
        the OpenSSL PRNG, by making "openssl genrsa" call RAND_add().

        If you have a source of entropy other than /dev/random and want to use
        it as an additonal seed for /dev/random, just use the non-openssl command
        "cat YourEntropyFile > /dev/random", in fact that is what most
        good hardware entropy device drivers do."

    Related projects:
    **pycrypto** - complete, need to compile; might be a good alternative backend,
        comes in Enthought Canopy; good to support a non-OpenSSL way to encrypt
        (because want modularity)
    M2Crypto - "M2Crypto is the most complete Python wrapper for OpenSSL"
    pyOpenSSL - "thin wrapper around (a subset of) the OpenSSL library"
    pycogworks.crypto - interesting = has pycrypto as dependency
"""
