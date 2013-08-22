#!/usr/bin/env python
"""Demo to illustrate encryption and decryption of a data file using pyFileSec

This file is python syntax, and can be executed:
% python example_1.py
"""

import pyfilesec as pfs
import os
from os.path import abspath, getsize, split

print "\nExample 1: pyFileSec pad, encrypt, decrypt, unpad\n"
# for the demo, we need a data file, e.g., containing sensitive info:
origfile = abspath('datafile.txt')  # filename
with open(origfile, 'wb') as fd:
    fd.write('sensitive stuff (e.g., HIPAA-covered info)')

# Add padding to change the original file's size (to obscure /encrypted/ size):
print 'original file name: "%s"' % split(origfile)[1]
print 'original file contents: "%s"' % open(origfile, 'rb').read()
print 'original file %5i bytes' % getsize(origfile)
pfs.pad(origfile)
print 'pad()     -->%6i' % getsize(origfile), split(origfile)[1]

# To encrypt, need an RSA public key, in .pem format:
pub  = 'pub_RSA_demo_only.pem'
ciphertext = pfs.encrypt(origfile, pub)  # returns filename
print 'encrypt() -->%6i' % getsize(ciphertext), split(ciphertext)[1], '(contents are protected; original securely removed)'

# To decrypt, need the matching RSA private key, and its passphrase if any.
# Decryption (and priv key storage) could be done on another computer.
priv = 'priv_RSA_demo_only.pem'
pphr = 'pphr_demo_only'
plaintext = pfs.decrypt(ciphertext, priv, pphr)  # returns filename
print 'decrypt() -->%6i' % getsize(plaintext), split(plaintext)[1], '(contents are plaintext; same file name as original)'

# The new decrypted (plain-text) file is still padded, unpad it:
pfs.pad(plaintext, 0)  # this is always safe to do
print 'unpad()   -->%6i %s' % (getsize(plaintext), split(plaintext)[1])

print 'recovered file contents: "%s"\n' % open(plaintext, 'rb').read()

# done with demo, clean-up files:
for f in [ciphertext, plaintext, origfile+'.meta']:
    os.unlink(f)
