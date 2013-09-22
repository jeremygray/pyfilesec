#!/bin/sh

py.test -k-notravis --cov-report term-missing --cov pyfilesec tests -x
