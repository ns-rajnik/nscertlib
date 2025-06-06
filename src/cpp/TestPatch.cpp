#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/engine.h>
#include <openssl/rsa.h>

#include <fstream>

#include "ErrorImpl.hpp"
#include "TestPatch.hpp"

namespace NSCertLib {

bool
patchRSAForTest(ENGINE *engine)
{
    const RSA_METHOD *default_rsa = RSA_get_default_method();
    if (!default_rsa) {
        setError("No default RSA methods found");
        return false;
    }

    RSA_METHOD *dup_rsa = RSA_meth_dup(default_rsa);
    if (!dup_rsa) {
        setOpenSSLError("Unable to duplicate RSA methods");
        return false;
    }

    int (*default_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb) =
        RSA_meth_get_keygen(default_rsa);

    if (!RSA_meth_set_keygen(dup_rsa, default_keygen)) {
        setOpenSSLError("Unable to patch key generation method");
        return false;
    }
    if (!ENGINE_set_RSA(engine, dup_rsa)) {
        setOpenSSLError("Unable to patch RSA methods");
        return false;
    }
    if (!ENGINE_set_default_RSA(engine)) {
        setOpenSSLError("Unable to set patched engine as default");
        return false;
    }
    return true;
}

}  // namespace NSCertLib
