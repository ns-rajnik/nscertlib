# SWIG expects the library name being wrapped to be of the format -
#   _<module name>.so

nscertlib_SRC_DIR = $(srcdir)/libs/nscertlib

work_DIR = certlib
nscertlib_PKG_DIR_fips 	= $(work_DIR)/src/nscertlib/fips

nscertlib_SWIG_OUT_fips = $(nscertlib_PKG_DIR_fips)
nscertlib_INCLUDES = $(nscertlib_SRC_DIR)/include
nscertlib_SWIG_INTERFACE = $(nscertlib_SRC_DIR)/src/cpp/NSCertLib.i

nscertlib_SWIG_MODULE = nscertlib
nscertlib_SWIG_SRC = libs/nscertlib/src/cpp/NSCertLib.swig.cpp

MOSTLYCLEANFILES += $(nscertlib_SWIG_SRC)
BUILT_SOURCES += $(nscertlib_SWIG_SRC)

SAFENET_MODULE_PATH = /opt/3p/binary/safenet/fips
SAFENET_LIB_PATH = $(SAFENET_MODULE_PATH)/lib
SAFENET_LIB = libICAPI.so

_nscertlib_common_sources = \
    libs/nscertlib/src/cpp/CertificateImpl.cpp \
    libs/nscertlib/src/cpp/CertReqImpl.cpp \
    libs/nscertlib/src/cpp/ErrorImpl.cpp \
    libs/nscertlib/src/cpp/IssuerImpl.cpp \
    libs/nscertlib/src/cpp/KeysImpl.cpp \
    libs/nscertlib/src/cpp/ModuleImpl.cpp \
    libs/nscertlib/src/cpp/NAEToken.cpp \
    libs/nscertlib/src/cpp/PEMHeader.cpp \
    libs/nscertlib/src/cpp/SecItem.cpp \
    libs/nscertlib/src/cpp/Serializer.cpp \
    libs/nscertlib/src/cpp/TestPatch.cpp \
    libs/nscertlib/src/cpp/Utility.cpp \
    libs/nscertlib/src/cpp/WrapperImpl.cpp

_nscertlib_common_cpp_flags = -DARCH=64 -Wno-error=shadow 
_nscertlib_common_c_flags = -DARCH=64 -Wno-implicit-function-declaration \
                       -Wno-int-conversion -Wno-error=missing-prototypes -Wno-switch

if USE_CLANG
_nscertlib_common_cpp_flags += -Wno-deprecated-declarations
_nscertlib_common_c_flags += -Wno-deprecated-declarations
endif

_nscertlib_common_cpp_flags += -Wno-deprecated-declarations
_nscertlib_common_c_flags += -Wno-deprecated-declarations
if !USE_CLANG
_nscertlib_common_cpp_flags += -Wno-format-truncation
endif

_nscertlib_fips_includes = \
    -I$(SAFENET_MODULE_PATH)/include -I$(nscertlib_INCLUDES)

_nscertlib_common_py_cpp_flags = \
    -I@PYTHON_PREFIX@/include/python@PYTHON_VERSION@ \
    -DSWIG=1 $(_nscertlib_common_cpp_flags)

SWIG_INCLUDES = \
    -I/opt/3p/include/swig \
    -I/opt/3p/include/swig/python

# Swig compilation is done as a dependency for _nscertlib.so
$(nscertlib_SWIG_SRC):
	test -d $(nscertlib_PKG_DIR_fips) || $(MKDIR_P) $(nscertlib_PKG_DIR_fips)
	@echo "  SWIG     $@"
	@$(SWIG) $(SWIG_INCLUDES) -c++ -python -py3 -I$(nscertlib_INCLUDES) -module $(nscertlib_SWIG_MODULE) \
		-outdir $(nscertlib_SWIG_OUT_fips) -o $@ $(nscertlib_SWIG_INTERFACE)

libs/nscertlib/tests/nscertlib_ci_smoke/wrappers/smoke1.sh: nscertlib-0.0.1.tar.gz

# This one is for the UT
lib_LTLIBRARIES += libnscertlib_no_swig.la
libnscertlib_no_swig_la_SOURCES = $(_nscertlib_common_sources)
libnscertlib_no_swig_la_CPPFLAGS = $(_nscertlib_fips_includes) $(_nscertlib_common_py_cpp_flags)

# This one has Python bindings and gets shipped to Prod
pyexec_LTLIBRARIES += libcertlib.la
libcertlib_la_SOURCES = $(nscertlib_SWIG_SRC) $(_nscertlib_common_sources)
libcertlib_la_CPPFLAGS = $(_nscertlib_fips_includes) $(_nscertlib_common_py_cpp_flags)
libcertlib_la_LDFLAGS = \
	-L$(SAFENET_LIB_PATH) -Wl,-rpath,$(SAFENET_LIB_PATH) \
	-L/opt/3p/lib -Wl,-rpath,/opt/3p/lib \
	-lcrypto -lICAPI -ljsoncpp -lz

nscertlib: pkg/nscertlib-focal-0.0.1.tar.gz
pkg/nscertlib-focal-0.0.1.tar.gz: libcertlib.la
	@echo Copying...
	cp -f .libs/libcertlib.so $(nscertlib_PKG_DIR_fips)/_nscertlib.so
	touch $(nscertlib_PKG_DIR_fips)/FIPS_ENABLED
	rm -f $(nscertlib_PKG_DIR_fips)/_nscertlib_fips.so

	libs/nscertlib/build_util.sh $(nscertlib_PKG_DIR_fips) \
		.libs/libcertlib.so $(SAFENET_LIB_PATH)/$(SAFENET_LIB)

	test -d $(work_DIR)/src || mkdir -p $(work_DIR)/src
	cp -f $(nscertlib_SRC_DIR)/README.rst $(work_DIR)/

	echo "from .nscertlib import *" > $(nscertlib_PKG_DIR_fips)/__init__.py

	@echo Packaging...
	cp -f $(nscertlib_SRC_DIR)/setup.py $(work_DIR)
	cp -f $(nscertlib_SRC_DIR)/MANIFEST.in $(work_DIR)
	cp -f $(nscertlib_SRC_DIR)/lib_init $(work_DIR)/src/nscertlib/__init__.py

	mkdir -p pkg/
	cd $(work_DIR) && $(PYTHON) setup.py sdist --dist-dir @ABS_BUILD_DIR@/pkg/
