#!/usr/bin/env python
"""Demo to illustrate encryption and decryption of a data file using pyFileSec

This file is python syntax, and can be executed:
% python example_1.py
"""

import pyfilesec as pfs
import os
from os.path import abspath, getsize, split

print "\nPython example: pyfilesec.SecFile methods: pad, encrypt, decrypt, unpad\n"
# for the demo, we need a data file, e.g., containing sensitive info:
origfile = abspath('datafile.txt')  # filename
with open(origfile, 'wb') as fd:
    fd.write('sensitive stuff (e.g., HIPAA-covered info)')

# Add padding to change the original file's size (to obscure /encrypted/ size):
print 'original file name:     "%s"' % split(origfile)[1]
print 'original file contents: "%s"' % open(origfile, 'rb').read()
print 'original file:          sf.file\n'
print 'obj.method       bytes  filename'
print 'sf.size      == %6i ' % getsize(origfile), split(origfile)[1]

sf = pfs.SecFile(origfile)
sf.pad()
print '  .pad()     -->%6i ' % getsize(origfile), split(origfile)[1]

# To encrypt, need an RSA public key, in .pem format:
sf.encrypt('pub_RSA_demo_only.pem')

# sf.file now points to the encrypted file
print '  .encrypt() -->%6i ' % getsize(sf.file), split(sf.file)[1], '(contents are cipher_text; original securely removed)'

# To decrypt, need the matching RSA private key, and its passphrase if any.
# Decryption (and priv key storage) could be done on another computer.
# decrypt sf.file, using private key and passphrase:
sf.decrypt('priv_RSA_demo_only.pem', 'pphr_demo_only')

# sf.file now points back to the original file
print '  .decrypt() -->%6i ' % getsize(sf.file), split(sf.file)[1], '(contents are clear_text; same file name as original)'

# The new decrypted (plain-text) file is still padded, unpad it:
sf.pad(0)  # size 0 means remove padding, if any
print '  .unpad()   -->%6i  %s' % (getsize(sf.file), split(sf.file)[1])

print 'recovered file contents (first line): \n  "%s"\n' % sf.read()

# done with demo, clean-up files:
os.unlink(sf.file)
