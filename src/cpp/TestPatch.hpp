#pragma once
#include <openssl/engine.h>

namespace NSCertLib {

/*
 * For the purpose of testing, we need to make sure that the right engine/RSA methods
 * are used for creation of asymmetric key pair. At the same time we do not have a live
 # HSM for unit testing, so we do not want gem-engine to contact HSM for key creation.
 # A way we do this is to patch the RSA key creation method of gem-engine to touch
 # a file if used. And since we do not have HSM, the key creation has to always fail.
 # The method below does the required patching on OpenSSL. This patching is done only
 # during testing and does not happen for production
 */
bool patchRSAForTest(ENGINE *engine);

}  // namespace NSCertLib
