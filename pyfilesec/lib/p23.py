# from vlc.py LGPL v2.1

"""
# Python ctypes bindings for VLC
#
# Copyright (C) 2009-2012 the VideoLAN team
# $Id: $
#
# Authors: Olivier Aubert <olivier.aubert at liris.cnrs.fr>
#          Jean Brouwers <MrJean1 at gmail.com>
#          Geoff Salmon <geoff.salmon at gmail.com>
"""

# edited by JRG


import sys

write_mode = 'w'
if sys.version_info[0] > 2:
    PY3 = True
    str = str
    unicode = str
    bytes = bytes
    basestring = (str, bytes)
    read_mode = 'r'
    def str2bytes(s):
        """Translate string or bytes to bytes.
        """
        if isinstance(s, str):
            return bytes(s, sys.getfilesystemencoding())
        else:
            return s

    def bytes2str(b):
        """Translate bytes to string.
        """
        if isinstance(b, bytes):
            return b.decode(sys.getfilesystemencoding())
        else:
            return b
else:
    PY3 = False
    str = str
    unicode = unicode
    bytes = str
    basestring = basestring
    read_mode = 'rU'
    def str2bytes(s):
        """Translate string or bytes to bytes.
        """
        if isinstance(s, unicode):
            return s.encode(sys.getfilesystemencoding())
        else:
            return s

    def bytes2str(b):
        """Translate bytes to unicode string.
        """
        if isinstance(b, str):
            return unicode(b, sys.getfilesystemencoding())
        else:
            return b
