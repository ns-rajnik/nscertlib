#ifndef __NSCERTLIB_WRAPPER_IMPL_H__
#define __NSCERTLIB_WRAPPER_IMPL_H__

#include <string>

#include "AutoCleaner.hpp"
#include "KeysImpl.hpp"
#include "SecItem.hpp"
#include "cpp/Wrapper.hpp"

// Note on Thread-safety:
// Once WrapperImpl has been created & initialized, none of its data structures get changed
// In addition, all the NSS calls performed after initialization are thread-safe.
// Hence wrap()/unwrap() calls are thread-safe.
// Creation and initialization are done by ModuleImpl, under a lock
// In short this class is thread-safe for the user of this library

namespace NSCertLib {

extern const char *kNAE;
extern const char *kSoftoken;

class ModuleImpl;
struct HSMConfig;

/**
 * @brief
 * Implementation of Wrapper interface
 */
class WrapperImpl : public Wrapper {
public:
    ~WrapperImpl() override;
    bool wrap(KeyPair &keys, RawData &wrappedPrivKey, RawData &derPubKey) override;
    bool wrapData(const RawData &content, RawData &wrappedContent) override;
#ifndef SWIG
    KeyPairPtr unwrap(const RawData &wrappedPrivKey, const RawData &derPubKey) override;
#else
    KeyPair *unwrap(const RawData &wrappedPrivKey, const RawData &derPubKey) override;
#endif
    bool unwrapData(const RawData &wrappedContent, RawData &content) override;
    bool validateWrapper(const char *value, const RawData &wrappedValue) override;
    // Wrapper is a singleton. And it should not be copyable
    WrapperImpl(const WrapperImpl &other) = delete;

private:
    // Ideally should have been const pointer. But NSS calls require this to be
    // non-const
    SecureItem m_symKey;

    // Wrapper object can only be created by ModuleImpl class
    // ModuleImpl provides a reference to the wrapper which users
    // can use for wrapping/unwrapping
    friend class ModuleImpl;
    WrapperImpl();
    bool initialize(const char *certWrapKeyName, const HSMConfig &config);
    SecureItem *getTokenWrapKey();
    SecureItem *getHSMWrapKey(const char *certWrapKeyName, const HSMConfig &config);
    unsigned int getUnwrappedLength(unsigned int wrappedLen);
    unsigned int getWrappedLength(unsigned int len);
    bool getRandomIV(SecureItem &iv);
    bool encrypt(const RawData &plain,
                 const SecureItem &key,
                 const SecureItem &iv,
                 RawData &cipher);
    bool decrypt(const SecureItem &cipher,
                 const SecureItem &key,
                 const SecureItem &iv,
                 RawData &plain);
    void base64Decode(const RawData &encoded, RawData &decoded);
    void base64Encode(const RawData &decode, RawData &encode);
    void addHeaders(const RawData &key, RawData &pkcs8Key);
};

}  // namespace NSCertLib

#endif  //__NSCERTLIB_WRAPPER_IMPL_H__
