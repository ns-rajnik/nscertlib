bin_PROGRAMS += nscertlib_cpp_test

nscertlib_cpp_test_SOURCES = libs/nscertlib/tests/cpp/nscertlib_test.cpp

nscertlib_cpp_test_SOURCES += libs/nscertlib/tests/cpp/nscertlib_hsm_parse_test.cpp libs/nscertlib/tests/cpp/nscertlib_misc.cpp

nscertlib_test_SRC_DIR = $(srcdir)/libs/nscertlib

nscertlib_cpp_test_CPPFLAGS = \
        -I $(nscertlib_test_SRC_DIR)/include \
        -I $(nscertlib_test_SRC_DIR)/include/cpp \
        -I $(nscertlib_test_SRC_DIR)/src \
        -I $(nscertlib_test_SRC_DIR)/src/cpp \
        -isystem /opt/3p/include/nss \
        -isystem /opt/3p/include/nss/source/private/nss \
        -isystem /opt/3p/include/nspr \
        -isystem /opt/3p/binary/safenet/fips/include \
        -DARCH=64

nscertlib_cpp_test_LDADD = \
        libnscertlib_no_swig.la

nscertlib_cpp_test_LDFLAGS = \
       -Wl,--unresolved-symbols=ignore-in-shared-libs -lcrypto -lgtest -lgmock -ljsoncpp \
       -L$(SAFENET_LIB_PATH) -Wl,-rpath,$(SAFENET_LIB_PATH) -lICAPI

TESTS += nscertlib_cpp_test
