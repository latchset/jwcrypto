#!/usr/bin/python
#
# Copyright (C) 2015  JWCrypto Project Contributors, see  LICENSE file

# read the contents of your README file
from pathlib import Path

from setuptools import setup

from jwcrypto import version

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

version = version.__version__

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
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    data_files = [('share/doc/jwcrypto', ['LICENSE', 'README.md'])],
    install_requires = [
        'cryptography >= 3.4',
        'typing_extensions >= 4.5.0',
    ],
    python_requires = '>= 3.8',
)
