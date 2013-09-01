#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name='PyFileSec',
    version='0.2.10 alpha',
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
                 'Operating System :: Microsoft :: Windows',
                 'Intended Audience :: Science/Research',
                 'Intended Audience :: System Administrators',
                 'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                 'Topic :: Scientific/Engineering',
                 'Topic :: System :: Systems Administration',
                 'Topic :: Security'
                 ],
    keywords=['encryption', 'security', 'privacy', 'integrity',
              'human subjects', 'research'],
    #url='http://pythonhosted.org/pyFileSec', # documentation
    url='https://github.com/jeremygray/pyFileSec', # home-page
    description='File-oriented privacy & integrity management tools',
    long_description=open('README.txt').read(),
)
