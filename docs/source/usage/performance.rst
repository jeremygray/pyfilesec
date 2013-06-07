Performance tests
==================


Test suite
-----------

The integrated test-suite is designed to be used with `py.test`. All tests in
`class Tests` are discovered and run::

    % py.test pyfilesec.py

The same tests can also be run via debug mode,
saving logging messages and intermediate files. Invoke from the command line
with option `--debug`, and redirect the output to a log file::

    % python pyfilesec.py --debug > log

For details of the specific tests, consult the code directly.

Additional
-----------

Performance tests beyond the test-suite::

Files encrypted on one machine can be decrypted on a different platform. It
would be good to make sure of this on machines with different endian-ness, not
tested yet.

With one exception, the specific version of OpenSSL does not matter. The
known exception is that there are incompatibilities between v0.9.x and v1.0.x
when using sign / verify. Tested with 7 versions of openssl, running on Mac OS
X and 3 linux distributions:

    OpenSSL 0.9.8r  8 Feb 2011     Mac 10.8.3, python 2.7.3
    OpenSSL 0.9.8x 10 May 2012     Mac 10.8.4, python 2.7.3
    OpenSSL 1.0.1e 11 Feb 2013     same Mac, openssl via macports
    OpenSSL 1.1.0-dev xx XXX xx    same Mac, clone OpenSSL from github & compile
    OpenSSL 1.0.0-fips 29 Mar 2010 CentOS 6.4, python 2.6.6
    OpenSSL 1.0.1  14 Mar 2012     Ubuntu 12.04.2 LTS, python 2.7.3
    OpenSSL 0.9.8o 01 June 2010    Debian (squeeze), python 2.6.6

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

The larger .aes256 files gets removed, leaving::

      -rw-------  1 jgray    8849744181  8gig.enc

Using `openssl rsautl` works on all platforms tested to date. Although  rsautl is
deprecated in favor of pkeyutl, but pkeyutl does not completely work: if the
private key has a password, it can't be loaded and decryption fails.

In some cases, recovering a known file signature only works if the reference
signature was created by the same version (0.9.8r vs 1.0.*).
