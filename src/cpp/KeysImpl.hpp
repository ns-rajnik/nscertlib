#ifndef __NSCERTLIB_KEYS_IMPL_H__
#define __NSCERTLIB_KEYS_IMPL_H__

#include <openssl/rsa.h>

#include <memory>

#include "AutoCleaner.hpp"
#include "cpp/Keys.hpp"

// Note on thread-safety:
// Creation and Initialization is handled by ModuleImpl, which takes care of doing this
// in a single thread. Hence creation and initialization is not required to be thread-safe
// The rest of the calls are thread-safe, as they mainly read the members of this class.
// In short, the user of this library sees KeyPair as thread-safe

namespace NSCertLib {

class ModuleImpl;

/**
 * @brief
 * Implementation of KeyPair interface
 */
class KeyPairImpl : public KeyPair {
public:
    KeyPairImpl() = default;
    KeyPairImpl(const KeyPairImpl &otherKeys);
    ~KeyPairImpl() override;
    KeyPairImpl &setAlgorithm(AsymKeyAlgorithm alg, AsymKeySize keysize);
    KeyPairImpl &setKeys(EVP_PKEY *key, ENGINE *eng);
    KeyPairImpl &setKeys(RawData &privKeyInfo);
    bool initialize(ENGINE *eng = nullptr);
    EVP_PKEY *getKey();
    ENGINE *getEngine();

    bool getPrivateKeyInfo(RawData &privKeyInfo, const char *passwd) override;
    virtual bool getP8PrivateKeyInfo(RawData &privKeyInfo);
    bool getPEMPublicKey(RawData &pubKeyInfo) override;
    bool publicEncrypt(const RawData &bufferIn, RawData &bufferOut) override;
    bool privateDecrypt(const RawData &bufferIn, RawData &bufferOut) override;
    bool sign_digest(const RawData &bufferIn, RawData &bufferOut) override;
    bool _verify_digest(const RawData &bufferIn, const RawData &signDataIn) override;

private:
    AsymKeyAlgorithm m_keyAlg{kInvalidKeyAlg};
    unsigned int m_keySize{0};
    AutoCleaner<EVP_PKEY> m_key;
    ENGINE *m_engine;  // ENGINE is set to non NULL if HSM is used to generate keypair
    friend class ModuleImpl;
    static const EVP_MD *get_evp_md(int signlen);

    bool initializeParams();
    bool initializeKeys(ENGINE *eng = nullptr);

    // Assignment disallowed. Use setKeys() followed by
    // initialize()
    KeyPairImpl &operator=(const KeyPairImpl &other);
};

using KeyPairImplPtr = std::unique_ptr<KeyPairImpl>;

}  // namespace NSCertLib

#endif  //__NSCERTLIB_KEYS_IMPL_H__
