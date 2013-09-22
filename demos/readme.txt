Demos for pyFileSec

The examples in this directory are intended to be run from the command line
from within this directory (demos/):

Python:
The file python_example.py illustrates how to use pyFileSec functions from with a python script.
To run the example, just type:

    % python python_example.py

Command-line:
The file sh_example.sh illustrates how to use pyFileSec functions from the command line.

    % sh sh_example.sh

The same syntax is used to call pyFileSec from within another program that can make
shell calls. For example, E-Prime can using the function Shell().

Notes:
1. Command line usage is likely to be easier with an alias. To find out what
full path to use in your alias, start python interactively:

    % python
    >>> import pyfilesec as pfs
    >>> pfs.command_alias()

This will print aliases for bash, *csh, and DOS command line. Copy and
paste into your shell as appropriate (or elsewhere, like a .bash_profile).

2. The .pem files in the demos/ directory are for demo purposes only, and should
never be used for anything else (!).

3. You can generate your own keys (.pem files) like this (assuming you have an alias
per Note 1):

    % pfs genrsa

4. Key generation for actual use should not be done casually, and should only
be done: a) when the private key and its passphrase can be kept securely, and b)
on a computer with a good source of entropy.
