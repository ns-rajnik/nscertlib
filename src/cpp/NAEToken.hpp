#ifndef __NSCERTLIB_NAETOKEN_H__
#define __NSCERTLIB_NAETOKEN_H__

#include <icapi.h>
#include <openssl/evp.h>

#include <string>

#include "AutoCleaner.hpp"
#include "WrapperImpl.hpp"
// Note on thread-safety:
// This class is not guaranteed to be thread-safe. The user of this class
// is incharge of locking before using this class

namespace NSCertLib {

extern const char *kNAEHSMType;

struct HSMConfig {
    std::string type;
    std::string properties;
    std::string username;
    std::string password;
    int32_t nae_key_size{0};

    bool populate(const char *configFile);
};

class WrapperImpl;
class WrapperImpl;
// Class to interface with Safenet Datasecure (HSM)
// The only public interface given is to get the CW key
// which is pretty much what we are using the HSM for.
class NAEToken {
public:
    virtual ~NAEToken();
    // Function to wrap the CW key with pubKey and get the result out of
    // the HSM in wrappedCWKey
    bool getCertWrapKey(SecureItem &wrappedCWKey);

private:
    std::string m_certWrapKeyName;
    const HSMConfig &m_hsmConfig;
    std::string m_wrappingKeyAlg;
    std::string m_wrappingKeySize;

    I_O_Session m_safenetSession{nullptr};
    bool m_connected{false};

    // WrapperImpl alone can create NAEToken as it is the only one
    // currently using it. This ensures that NAEToken is not used
    // used inadvertently in any other manner
    friend class WrapperImpl;
    friend class WrapperImpl;
    NAEToken(const char *certWrapKeyName, const HSMConfig &config);
    NAEToken &setWrappingMethod(const char *alg, const char *keySize);
    bool initialize();
    enum CWKeyStatus { kPresent, kAbsent, kInvalid };
    CWKeyStatus checkCertWrapKey();
    bool createCertWrapKey();
    // NAETOken should not be copyable. It is created by WrapperImpl whenever needed
    NAEToken(const NAEToken &other);
    NAEToken &operator=(const NAEToken &other);
    EVP_PKEY *createKeyPair() const;
    static bool getPubKeyInPEM(EVP_PKEY *key, std::string &pubKey);
    static bool decryptSymKey(EVP_PKEY *key,
                              unsigned char *wrappedKey,
                              int wrappedKeyLen,
                              NSCertLib::SecureItem &symKey);
};

}  // namespace NSCertLib

#endif  //__NSCERTLIB_NAETOKEN_H__
