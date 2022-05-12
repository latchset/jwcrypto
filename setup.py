#!/usr/bin/python
#
# Copyright (C) 2015  JWCrypto Project Contributors, see  LICENSE file

import os
from setuptools import setup

# read the contents of your README file
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

version = None
with open(os.path.join('jwcrypto', 'VERSION')) as verfile:
    version = verfile.read().strip()

setup(
    name = 'jwcrypto',
    version = version,
    license = 'LGPLv3+',
    maintainer = 'JWCrypto Project Contributors',
    maintainer_email = 'simo@redhat.com',
    url='https://github.com/latchset/jwcrypto',
    packages = ['jwcrypto'],
    description = 'Implementation of JOSE Web standards',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers = [
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    data_files = [('share/doc/jwcrypto', ['LICENSE', 'README.md'])],
    install_requires = [
        'cryptography >= 2.3',
        'deprecated',
    ],
    python_requires = '>= 3.6',
)
