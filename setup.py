# -*- coding: utf-8 -*-
"""
.. :module:: setup.py
   :platform: Linux
   :synopsis: Setup for the nscertlib package.

   :copyright: (c) 2020 Netskope, Inc. All rights reserved.
.. moduleauthor:: Deepak Swaminathan <sdeepak@netskope.com> (Dec 28, 2020)
"""
import os
import re
from setuptools import setup, find_packages

del os.link  # don't use hard-links (hack for distutils + virtualbox filesystem)

VERSION_STR = '0.0.1'
VERSIONFILE = "src/_version.py"
OS_VERSION = os.getenv('OS_VERSION') if os.getenv('OS_VERSION') else "focal"
if not os.path.exists(VERSIONFILE):
    with open(VERSIONFILE, "w") as version_file:
        version = os.getenv('BUILD_VERSION') if os.getenv('BUILD_VERSION') else "0.0.1"
        data_version = '__version__ = "' + version.split("-")[0] + '"\n'
        data_os_version = '__os_version__ = "' + OS_VERSION + '"\n'
        version_file.writelines([data_version, data_os_version])
        print(f"Version in setup.py {[data_version, data_os_version]}")

# process the version file
VERSION_STR = ''
OS_VERSION = ''
with open(VERSIONFILE, 'rt') as fp:
    _VFILECONTENTS  = fp.readlines()
    _VERSION_REGEX = r"^__version__ = ['\"]([^\"]*)['\"]"
    _MATCH = re.search(_VERSION_REGEX, _VFILECONTENTS[0], re.M)
    if _MATCH:
        VERSION_STR = _MATCH.group(1)
    else:
        raise RuntimeError("Unable to parse version file '%s'." % VERSIONFILE)
    _VERSION_REGEX = r"^__os_version__ = ['\"]([^\"]*)['\"]"
    _MATCH = re.search(_VERSION_REGEX, _VFILECONTENTS[1], re.M)
    if _MATCH:
        OS_VERSION = _MATCH.group(1)
    else:
        raise RuntimeError("Unable to parse version file '%s'." % VERSIONFILE)

# Add your python scripts/services/apps here
PYSCRIPTS = [
    
]

# Add all non-python scripts here (e.g., bash, pyproject-wrap-app scripts, etc.)
NON_PYSCRIPTS = [

]

SCRIPTS = PYSCRIPTS + NON_PYSCRIPTS

setup(
    name             = f'nscertlib-{OS_VERSION}',
    version          = VERSION_STR,
    author           = '''Deepak Swaminathan''',
    author_email     = 'sdeepak@netskope.com',
    url              = 'https://www.netskope.com',
    description      = '''Library for certificate management''',
    long_description = open('README.rst').read(),
    license          = 'Proprietary',
    zip_safe         = False,

    setup_requires = ['setuptools'],

    include_package_data = True,

    install_requires = [
        # netskope packages or third-party packages go here; e.g.:
        # "nslog"
        # "simplejson"
        #
        # You can also specify versions:
        # "simplejson==3.2.1"
        # "nskafka==1.0.8"
        #
        
    ],

    packages    = find_packages('src'),
    package_dir = { '' : 'src' },

    scripts = SCRIPTS,

    # make sure we never accidently upload to PyPI
    classifiers = [
        'Private :: Do Not Upload'
    ]
)

