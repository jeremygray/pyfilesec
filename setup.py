#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name='PyFileSec',
    version='0.1.4',
    author='Jeremy R. Gray',
    author_email='jrgray@gmail.com',
    maintainer='Jeremy R. Gray',
    py_modules=['pyfilesec'],
    classifiers=['Development Status :: 3 - Alpha',
                 'Programming Language :: Python :: 2.6',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3',
                 'Operating System :: POSIX :: Linux',
                 'Operating System :: MacOS :: MacOS X',
                 #'Operating System :: Microsoft :: Windows',  # soon!
                 'Intended Audience :: Science/Research',
                 'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                 'Topic :: Scientific/Engineering',
                 'Topic :: Security'
                 ],
    keywords=['encryption', 'security', 'privacy', 'integrity', 'human subjects', 'research'],
    url='https://github.com/jeremygray/pyFileSec',
    description='File privacy & integrity tools, e.g., for human-subjects research',
    long_description=open('README.txt').read(),
    #install_requires=['ctypes'],
)
