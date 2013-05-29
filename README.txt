==========
PyFileSec
==========

PyFileSec provides robust yet easy-to-use tools for working with files that may
contain sensitive information. The aim is to achieve a consumer-grade "industry
standard" level of privacy, capable of protecting confidential information
about human research subjects from casual inspection or accidental disclosure.
In addition, integrity assurance may be useful for data archival and provenance
applications.

Public-key encryption is used for security and flexibility, relying on OpenSSL
for all cryptography. The aim is to provide a readily extensible framework for
adding other encryption methods, while retaining the API and meta-data.

The main contribution of PyFileSec is to data management (its certainly not to
cryptography): 1) to make strong encryption tools more accessible to human
neuroscience and psychology when working with data files, and 2) to be able to
document such encryption in meta-data. Other tools are provided to obscure file
length and allow secure file deletion.

Currently all tests pass on Mac OS 10.8 and Linux (CentOS 6.4 and Ubuntu 12).
Windows support to be added soon (will require installing OpenSSL and SDelete).

Contributors
-------------
Jeremy R. Gray - package author

Thanks to
----------
Michael Stone - awesome code review