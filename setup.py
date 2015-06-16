#!/usr/bin/python
#
# Copyright (C) 2015  JWCrypto Project Contributors, see  LICENSE file

from setuptools import setup

setup(
    name = 'jwcrypto',
    version = '0.2.0',
    license = 'LGPLv3+',
    maintainer = 'JWCrypto Project Contributors',
    maintainer_email = 'simo@redhat.com',
    url='https://github.com/simo5/jwcrypto',
    packages = ['jwcrypto'],
    description = 'Implementation of JOSE Web standards',
    classifiers = [
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    data_files = [('share/doc/jwcrypto', ['LICENSE', 'README.md'])],
)

