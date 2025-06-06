#include <assert.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <cstring>

#include "ErrorImpl.hpp"
#include "NAEToken.hpp"
#include "PEMHeader.hpp"
#include "Serializer.hpp"
#include "WrapperImpl.hpp"

namespace NSCertLib {

const char *kNAE = "NAE";
const char *kSoftoken = "Softoken";

const char *kSoftCertWrapId = "cert_wrap";

// Safenet HSM (NAE) code expects a string equivalent of above
static const char kWrapKeyAlgStr[] = "AES";
// CW key size in bytes
static const int kWrapKeySize = 32;
// Safenet HSM(NAE) code required key size in bits as a string
static const char kWrapKeySizeStr[] = "256";
// Length of IV(Initialization vector) for wrapping
static const unsigned int kIVLength = 16;
// Block size for wrapping
static const unsigned int kAESBlockSize = 16;

WrapperImpl::WrapperImpl() : m_symKey(nullptr, 0) {}

WrapperImpl::~WrapperImpl()
{
    m_symKey.clear();
}

bool
WrapperImpl::encrypt(const RawData &plain,
                     const SecureItem &key,
                     const SecureItem &iv,
                     RawData &cipher)
{
    AutoCleaner<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    if (ctx.get() == nullptr) {
        NSCertLib::setOpenSSLError("Error initializing encryption context");
        return false;
    }
    if (!EVP_EncryptInit_ex(
            ctx.get(), EVP_aes_256_cbc(), nullptr, key.getContent(), iv.getContent())) {
        NSCertLib::setOpenSSLError("Error initializing encryption");
        return false;
    }
    cipher.resize(getWrappedLength(plain.size()));
    int updateLen{0};
    if (!EVP_EncryptUpdate(ctx.get(), cipher.data(), &updateLen, plain.data(), plain.size())) {
        NSCertLib::setOpenSSLError("Error encrypting data");
        return false;
    }
    int finalLen{0};
    if (!EVP_EncryptFinal_ex(ctx.get(), cipher.data() + updateLen, &finalLen)) {
        NSCertLib::setOpenSSLError("Error finalizing encryption");
        return false;
    }
    cipher.resize(updateLen + finalLen);
    return true;
}

bool
WrapperImpl::decrypt(const SecureItem &cipher,
                     const SecureItem &key,
                     const SecureItem &iv,
                     RawData &plain)
{
    AutoCleaner<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    if (ctx.get() == nullptr) {
        NSCertLib::setOpenSSLError("Error initializing decryption");
        return false;
    }
    if (!EVP_DecryptInit_ex(
            ctx.get(), EVP_aes_256_cbc(), nullptr, key.getContent(), iv.getContent())) {
        NSCertLib::setOpenSSLError("Error initializing decryption");
        return false;
    }
    int updateLen{0};
    plain.resize(getUnwrappedLength(cipher.getLength()));
    if (!EVP_DecryptUpdate(
            ctx.get(), plain.data(), &updateLen, cipher.getContent(), cipher.getLength())) {
        NSCertLib::setOpenSSLError("Error decrypting data");
        return false;
    }
    int finalLen{0};
    if (!EVP_DecryptFinal_ex(ctx.get(), plain.data() + updateLen, &finalLen)) {
        NSCertLib::setOpenSSLError("Error finalizing decryption");
        return false;
    }
    plain.resize(updateLen + finalLen);
    return true;
}

// Initialization takes care of setting up the CW key.
// This means creating/fetching CW key on softoken or
// fetching CW key from HSM, based on HSM config
bool
WrapperImpl::initialize(const char *certWrapKeyName, const HSMConfig &config)
{
    if (config.type == kSoftoken) {
        getTokenWrapKey();
    } else if (config.type == kNAE) {
        if (not getHSMWrapKey(certWrapKeyName, config)) {
            return false;
        }
    } else {
        assert(false);  // HSM type is invalid
    }
    // Error already logged
    return not m_symKey.getSECItem()->empty();
}

#define CHECK_INIT(x)                        \
    if (&m_symKey == nullptr) {              \
        setError("Wrapper not initialized"); \
        return x;                            \
    }

void
WrapperImpl::base64Decode(const RawData &encoded, RawData &decoded)
{
    AutoCleaner<BIO> b64(BIO_new(BIO_f_base64()));
    BIO_push(b64.get(), BIO_new_mem_buf(encoded.data(), encoded.size()));
    decoded.resize(BIO_pending(b64.get()));
    BIO_read(b64.get(), decoded.data(), decoded.size());
}

// TODO: derPubKey needs to be removed once openssl migration is complete
bool
WrapperImpl::wrap(KeyPair &keys, RawData &wrappedPrivKey, RawData &derPubKey)
{
    CHECK_INIT(false);
    SecureItem iv;
    if (!getRandomIV(iv)) {
        return false;
    }
    auto &keysImpl = static_cast<KeyPairImpl &>(keys);

    // This is a necessary step since since the NSS function used to
    // encrypt private keys converted the rsa (pkcs1) private key to pkcs8 format
    RawData privateKey;
    if (!keysImpl.getP8PrivateKeyInfo(privateKey)) {
        setError("Unable to convert privateKey to pkcs8 format");
        return false;
    }
    // Decode then encrypt
    // This step is done ensure compatibility with NSS decryption
    RawData decodedKey;
    base64Decode(privateKey, decodedKey);
    if (decodedKey.empty()) {
        setError("Unable to decode private key");
        return false;
    }
    RawData encryptedKey;
    encryptedKey.resize(decodedKey.size());
    if (!encrypt(decodedKey, m_symKey, iv, encryptedKey)) {
        // encrypt() sets the error properly. No need to set here
        return false;
    }

    Serializer serial(wrappedPrivKey);
    if (!serial.serialize(iv) || !serial.serialize(encryptedKey)) {
        setError("Unable to serialize wrapped private key");
        return false;
    }
    // Remove this after nss code has been completely removed
    return keys.getPEMPublicKey(derPubKey);
}

bool
WrapperImpl::wrapData(const RawData &content, RawData &wrappedContent)
{
    CHECK_INIT(false);
    SecureItem iv;
    if (!getRandomIV(iv)) {
        return false;
    }
    RawData encryptedData;
    encryptedData.resize(getWrappedLength(content.size()));
    if (!encrypt(content, m_symKey, iv, encryptedData)) {
        // encrypt() sets the error properly. No need to set here
        return false;
    }
    Serializer serial(wrappedContent);
    if (!serial.serialize(iv) || !serial.serialize(encryptedData)) {
        setError("Unable to serialize wrapped data");
        return false;
    }
    return true;
}

void
WrapperImpl::base64Encode(const RawData &decode, RawData &encode)
{
    BUF_MEM *bptr{nullptr};
    AutoCleaner<BIO> b64(BIO_new(BIO_f_base64()));
    BIO_push(b64.get(), BIO_new(BIO_s_mem()));
    BIO_write(b64.get(), decode.data(), decode.size());
    (void)BIO_flush(b64.get());
    BIO_get_mem_ptr(b64.get(), &bptr);
    encode.resize(bptr->length);
    std::copy(bptr->data, bptr->data + (bptr->length - 1), std::begin(encode));
}

void
WrapperImpl::addHeaders(const RawData &key, RawData &pkcs8Key)
{
    // Add the required headers
    pkcs8Key.insert(pkcs8Key.begin(),
                    PEM::kPrivateKeyHeader,
                    PEM::kPrivateKeyHeader + std::strlen(PEM::kPrivateKeyHeader));
    pkcs8Key.push_back('\0');
    pkcs8Key.push_back('\n');
    pkcs8Key.insert(pkcs8Key.end(), key.data(), key.data() + key.size());
    pkcs8Key.push_back('\0');
    pkcs8Key.push_back('\n');
    pkcs8Key.insert(pkcs8Key.end(),
                    PEM::kPrivateKeyFooter,
                    PEM::kPrivateKeyFooter + std::strlen(PEM::kPrivateKeyFooter));
    pkcs8Key.push_back('\0');
}

#ifdef SWIG
KeyPair*
#else
KeyPairPtr
#endif
// derPubKey needs to be removed once openssl migration is complete
WrapperImpl::unwrap(const RawData &wrappedPrivKey, const RawData & /*derPubKey*/)
{
    CHECK_INIT(nullptr);
    Deserializer deserial(wrappedPrivKey);
    SecureItem iv;
    SecureItem wrappedPrivKeyItem;
    if (!deserial.deserialize(iv) || !deserial.deserialize(wrappedPrivKeyItem)) {
        setError("Unable to deserialize wrapped private key");
        return nullptr;
    }
    RawData decryptedPrivateKey;
    if (!decrypt(wrappedPrivKeyItem, m_symKey, iv, decryptedPrivateKey)) {
        // encrypt() sets the error properly. No need to set here
        return nullptr;
    }
    RawData encodedPrivateKey;
    base64Encode(decryptedPrivateKey, encodedPrivateKey);
    RawData pkcs8Key;
    // Add pkcs8 headers to the private key
    addHeaders(encodedPrivateKey, pkcs8Key);

    KeyPairImplPtr keys(new KeyPairImpl());
    keys->setKeys(pkcs8Key);
    if (!keys->initialize()) {
        // Error already set by KeyPair
        return nullptr;
    }
#ifdef SWIG
    return keys.release();
#else
    return KeyPairPtr(keys.release());
#endif
}

bool
WrapperImpl::unwrapData(const RawData &wrappedContent, RawData &content)
{
    CHECK_INIT(false);
    Deserializer deserial(wrappedContent);
    SecureItem iv;
    SecureItem encryptData;
    if (!deserial.deserialize(iv) || !deserial.deserialize(encryptData)) {
        setError("Unable to deserialize wrapped content");
        return false;
    }
    if (!decrypt(encryptData, m_symKey, iv, content)) {
        // encrypt() sets the error properly. No need to set here
        return false;
    }
    content.shrink_to_fit();
    return true;
}

bool
WrapperImpl::validateWrapper(const char *value, const RawData &wrappedValue)
{
    CHECK_INIT(false);
    RawData unwrappedValue;
    if (!unwrap(wrappedValue, unwrappedValue)) {
        setError("Unable to unwrap for validation");
        return false;
    }
    return memcmp(value, unwrappedValue.data(), unwrappedValue.size()) == 0;
}

// This function creates/fetches CW key on/from given token
SecureItem *
WrapperImpl::getTokenWrapKey()
{
    // Hardcode symkey value since this is only used while testing
    m_symKey.copy((unsigned char *)"01234567890123456789012345678901", kWrapKeySize);
    return &m_symKey;
}

// This function creates/fetches CW key from HSM to given token
SecureItem *
WrapperImpl::getHSMWrapKey(const char *certWrapKeyName, const HSMConfig &config)
{
    // Create NAE Token to access Safenet HSM (Datasecure)
    NAEToken hsmToken(certWrapKeyName, config);
    hsmToken.setWrappingMethod(kWrapKeyAlgStr, kWrapKeySizeStr);
    if (!hsmToken.initialize()) {
        // Error set inside token
        return nullptr;
    }
    SecureItem wrappedCWKey;
    if (!hsmToken.getCertWrapKey(wrappedCWKey)) {
        // Error already set
        return nullptr;
    }

    m_symKey.copy(wrappedCWKey.getContent(), wrappedCWKey.getLength());
    return &m_symKey;
}

// Get the maximum length that the unwrapped content could have
unsigned int
WrapperImpl::getUnwrappedLength(unsigned int wrappedLen)
{
    return wrappedLen;
}

// Get the maximum length that wrapped content could have
unsigned int
WrapperImpl::getWrappedLength(unsigned int len)
{
    return ((len / kAESBlockSize) + 1) * kAESBlockSize;
}

bool
WrapperImpl::getRandomIV(SecureItem &iv)
{
    iv.reserve(kIVLength);
    int rc = RAND_bytes(iv.getSECItem()->data(), kIVLength);
    if (rc == 1) {
        return true;
    }
    setError("Unable to generate random iv");
    iv.getSECItem()->clear();
    return false;
}

}  // namespace NSCertLib
