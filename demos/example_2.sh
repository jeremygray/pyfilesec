#!/bin/sh

# Demo to illustrate encryption and decryption of a data file using pyFileSec
# using command line syntax.

# This file is shell syntax, and can be executed from command line
# % sh example_2.sh

echo
echo 'pyFileSec command line examples'
echo
echo 'A description is printed, then a command (preceeded by a prompt %), then the ouput.'
echo
echo 1. Making an alias: pfs
# The path to use can be found like this:
# % python
# >>> import pyfilesec as pfs
# >>> pfs.command_alias()
# bash:  alias pfs="python /Users/jgray/code/pyFileSec/pyfilesec.py"
# *csh:  alias pfs "python /Users/jgray/code/pyFileSec/pyfilesec.py"
# DOS :  doskey pfs=python /Users/jgray/code/pyFileSec/pyfilesec.py $*

#>>>
# in a bash shell, copy and paste this version:
echo '% alias pfs="python /Users/jgray/code/pyFileSec/pyfilesec.py"'
alias pfs="python /Users/jgray/code/pyFileSec/pyfilesec.py"
echo '(no output)'

# we should be in the demo directory; if not, go there:
#cd /Users/jgray/code/pyFileSec/demos

echo
echo 2. Create a data file with contents:
echo 'sensitive stuff (e.g., HIPAA-covered info)' > datafile.txt
echo '% cat datafile.txt'
cat datafile.txt
# output: sensitive stuff (e.g., HIPAA-covered info)
echo

echo 3. pad to change the file size. The new length is reported:
echo '% pfs --pad datafile.txt'
pfs --pad datafile.txt
# output: 13684

echo
echo You can still view the file contents. The new padding note at the end of
echo the file indicates that its padded, and describes how to unpad the file:
echo '% cat datafile.txt'
cat datafile.txt
echo
# output: sensitive stuff (e.g., HIPAA-covered info)
#         pad=0000016341pyFileSec_padded

echo
echo 4. To encrypt, need an RSA public key, in .pem format. Encrypt returns the
echo '   full path to the new encrypted file (ciphertext).'
echo
echo '% pfs --encrypt --pub pub_RSA_demo_only.pem datafile.txt'
pfs --encrypt --pub pub_RSA_demo_only.pem datafile.txt
# output:  /full/path/to/datafile.enc

echo
echo 'The original file is securely deleted by default (use option --keep to retain it).'
echo '% ls datafile.txt'
ls datafile.txt
# output:  ls: datafile.txt: No such file or directory

echo
echo 'A new file with extension .enc is in its place:'
echo '% ls datafile.enc'
ls datafile.enc
# output:  datafile.enc
# less datafile.enc
# output:  "datafile.enc" may be a binary file.  See it anyway? n

echo
echo 5. To decrypt, need the matching RSA private key, and its passphrase if any.
echo '    Decryption could be done on another computer.'
echo '% pfs --decrypt --priv priv_RSA_demo_only.pem --pphr pphr_demo_only datafile.enc'
pfs --decrypt --priv priv_RSA_demo_only.pem --pphr pphr_demo_only datafile.enc
# output: /full/path/to/datafile.txt

echo
echo The encrypted version is not removed:
echo '% ls datafile.enc'
ls datafile.enc
# output:  datafile.enc

echo
echo 'The new decrypted plain-text file is still padded. Remove padding (using size argument: -z 0).'
echo '% pfs datafile.txt --pad -z 0'
pfs datafile.txt --pad -z 0
# output:  43

echo
echo 'View the recovered plain-text, sans padding (same as original):'
echo '% cat datafile.txt'
cat datafile.txt

# clean-up the temp files:
/bin/rm -f datafile.enc datafile.txt datafile.txt.meta

echo
echo 6. You can also call --rotate, --destroy, --sign, and --verify from the
echo command line, with options.
echo
echo Use --help for a quick command summary including yet more options.
echo '% pfs --help'
