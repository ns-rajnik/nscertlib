What is nscertlib?
---------------------
For details on this library, please look at -
https://netskope.atlassian.net/wiki/spaces/ENG/pages/42533150/Design+spec+-+NSCertLib

This library is exposed as a python module.

The C++ code is built into _nscertlib.so library. During this compilation swig is used to generate appropriate python
definition. Finally, all this is packaged as a python package using python distutil (setup.py)

FIPS
------------------------

Fips mode is detected using the following methods:

Filesystem:
------------------------

evironmental variable: NSCERTLIB_TEST_FIPS_PATH
    - contains path of file check, contents 1 for enable 0 for disable

proc file system:
/proc/sys/crypto/fips_enable
        - contents 1 for enable 0 for disable

NSCERTLIB_TEST_FIPS_PATH overrides /proc/sys/crypto/fips_enable and
should only be used for testing

Environmental Variables:
------------------------

OPENSSL_FORCE_FIPS_MODE is a global enablement of fips mode
for all applications that use openssl

OPENSSL_FORCE_FIPS_MODE=1
    - enable fips

OPENSSL_FORCE_FIPS_MODE=0
    - disable fips

if only nscertlib requires fips libraries:
NSCERTLIB_FORCE_FIPS_MODE=1
    - enable fips

NSCERTLIB_FORCE_FIPS_MODE=0
    - disable fips

order of precedence:

SCERTLIB_FORCE_FIPS_MOD
OPENSSL_FORCE_FIPS_MOD
NSCERTLIB_TEST_FIPS_PATH
/proc/sys/crypto/fips_enable

It should be noted that FIPS enabled openssl is not 
included in this build yet and must be loaded with
LD_PRELOAD, fips more for nscertlib packagages a fips
compliant version of libICAPI.so. openssl (libcrypto)
that is FIPS compliant will be bundled in future releases.