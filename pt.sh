#/bin/sh

py.test -k-slow --tb=short --cov-report term-missing --cov pyfilesec
