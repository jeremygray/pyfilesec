#!/bin/sh

# Demo to illustrate encryption and decryption of a data file using pyFileSec
# using command line syntax.

# This file is shell syntax, and can be executed from command line
# % sh example_2.sh

clear
echo
echo 'Example 2: pyfilesec.SecFile command-line usage'
echo
echo 'This demo should be run from within the pyfilesec/demos/ directory, or files will not be found.'
echo
echo 'A shell command in printed (preceeded by a prompt %), then its ouput.'
echo
/bin/echo -n "  --> Hit return to continue (or Ctrl-C to quit): "
read dummy_var

clear

# we should be in the demo directory; if not, go there:
#cd ..../pyFileSec/demos

# Create a data file with contents:
echo 'sensitive stuff (e.g., HIPAA-covered info)' > datafile.txt
echo '% alias pfs=../pyfilesec/__init__.py'
alias pfs=../pyfilesec/__init__.py

# Pad to change the file size. The new length is reported:
echo
echo 'PAD:'
echo '% pfs --pad datafile.txt'
pfs --pad datafile.txt
# output: 13684

# To encrypt, need an RSA public key, in .pem format. Encrypt returns the
echo
echo 'ENCRYPT:'
echo '% pfs --encrypt datafile.txt --pub pub_RSA_demo_only.pem --nometa'
pfs --encrypt datafile.txt --pub pub_RSA_demo_only.pem --nometa

# The original file is securely deleted by default

# To decrypt, need the matching RSA private key, and its passphrase if any.
echo
echo 'DECRYPT:'
echo '% pfs --decrypt --priv priv_RSA_demo_only.pem --pphr pphr_demo_only datafile.enc'
pfs --decrypt --priv priv_RSA_demo_only.pem --pphr pphr_demo_only datafile.enc

# The new decrypted plain-text file is still padded. Remove padding.
echo
echo 'UNPAD:'
echo '% pfs datafile.txt --unpad'
pfs datafile.txt --unpad

echo

# clean-up the temp files:
/bin/rm -f datafile.enc datafile.txt
