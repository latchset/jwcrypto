#!/usr/bin/python
#
# Copyright (C) 2015  JWCrypto Project Contributors, see  LICENSE file

from distutils.core import setup

setup(
    name = 'jwcrypto',
    version = '0.0.1',
    license = 'LGPLv3+',
    maintainer = 'JWCrypto Project Contributors',
    maintainer_email = 'simo@redhat.com',
    url='https://github.com/simo5/jwcrypto',
    packages = ['jwcrypto'],
    data_files = [('share/doc/jwcrypto', ['LICENSE', 'README.md'])],
)

