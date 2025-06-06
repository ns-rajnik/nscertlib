#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cassert>
#include <cstring>
#include <format>
#include <string>

#include "ErrorImpl.hpp"
#include "KeysImpl.hpp"
#include "PEMHeader.hpp"

namespace NSCertLib {

KeyPairImpl::KeyPairImpl(const KeyPairImpl &otherKeys)
    : m_keyAlg(otherKeys.m_keyAlg), m_keySize(otherKeys.m_keySize)
{
    EVP_PKEY *pkey = EVP_PKEY_dup((EVP_PKEY *)otherKeys.m_key.get());
    if (pkey != nullptr) {
        m_key.reset(pkey);
        m_engine = otherKeys.m_engine;
    }
}

KeyPairImpl &
KeyPairImpl::operator=(const KeyPairImpl & /*other*/)
{
    // Assignment operator disallowed!
    assert(false);
    return *this;
}

KeyPairImpl &
KeyPairImpl::setAlgorithm(AsymKeyAlgorithm alg, AsymKeySize keysize)
{
    m_keyAlg = alg;
    m_keySize = keysize;
    return *this;
}

KeyPairImpl &
KeyPairImpl::setKeys(EVP_PKEY *pkey, ENGINE *eng)
{
    if (EVP_PKEY_up_ref(pkey)) {
        m_key.reset(pkey);
        m_engine = eng;
    }
    return *this;
}

KeyPairImpl::~KeyPairImpl() = default;

bool
KeyPairImpl::initialize(ENGINE *eng)
{
    if (!m_key.get()) {
        assert(kInvalidKeyAlg != m_keyAlg);
        assert(0 != m_keySize);
        return initializeKeys(eng);
    }
    return initializeParams();
}

#define CHECK_INIT(x)                        \
    if (!m_key.get()) {                      \
        setError("KeyPair not initialized"); \
        return x;                            \
    }

bool
KeyPairImpl::initializeParams()
{
    // Figure out the mechanism and key size
    if (EVP_PKEY_RSA == EVP_PKEY_get_base_id(m_key.get())) {
        m_keyAlg = kRSA;
    } else {
        setError("Invalid key algorithm - %d", m_keyAlg);
        return false;
    }
    m_keySize = EVP_PKEY_get_bits(m_key.get());
    if (0 == m_keySize) {
        setError("Invalid key size - %u", m_keySize);
        return false;
    }
    return true;
}

bool
KeyPairImpl::initializeKeys(ENGINE *eng)
{
    if ((kInvalidKeyAlg == m_keyAlg) || (0 == m_keySize)) {
        setError("Invalid key generation parameters - alg=%d, size=%u", m_keyAlg, m_keySize);
        return false;
    }

    EVP_PKEY *key = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, eng);
    if (!ctx) {
        if (eng) {
            setError("EVP PKEY CTX new failed for RSA key generation with engine");
        } else {
            setError("EVP PKEY CTX new failed for RSA key generation");
        }
        return false;
    }
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        setError("EVP PKEY CTX init failed");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, m_keySize) <= 0) {
        setError("EVP PKEY CTX set keygen bits %d failed", m_keySize);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_keygen(ctx, &key) != 1) {
        setError("EVP PKEY keygen for RSA failed");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    m_key.reset(key);
    m_engine = eng;
    return true;
}

bool
KeyPairImpl::getPrivateKeyInfo(RawData &privKeyInfo, const char *passwd)
{
    CHECK_INIT(false);
    AutoCleaner<BIO> pbio(BIO_new(BIO_s_mem()));
    if (nullptr == pbio.get()) {
        setOpenSSLError("Unable to create openssl BIO");
        return false;
    }
    const EVP_CIPHER *cipher = nullptr;
    if (passwd) {
        cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
    }
    if (!PEM_write_bio_PKCS8PrivateKey(
            pbio.get(), m_key.get(), cipher, nullptr, 0, nullptr, (unsigned char *)passwd)) {
        setOpenSSLError("Unable to get private key");
        return false;
    }
    int privKeyLen = BIO_pending(pbio.get());
    if (privKeyLen <= 0) {
        setOpenSSLError("Unable to get the amount of pending data from BIO");
        return false;
    }
    privKeyInfo.resize(privKeyLen);
    if (BIO_read(pbio.get(), privKeyInfo.data(), privKeyLen) <= 0) {
        setOpenSSLError("Error in reading private key string");
        return false;
    }
    return true;
}

bool
KeyPairImpl::getPEMPublicKey(RawData &pubKeyInfo)
{
    AutoCleaner<BIO> pbio(BIO_new(BIO_s_mem()));
    if (nullptr == pbio.get()) {
        setOpenSSLError("Unable to create openssl BIO");
        return false;
    }
    if (!PEM_write_bio_PUBKEY(pbio.get(), m_key.get())) {
        setOpenSSLError("Unable to write bio public key");
        return false;
    }
    int pubKeyLen = BIO_pending(pbio.get());
    if (pubKeyLen <= 0) {
        setOpenSSLError("Unable to get the  amount of pending data from BIO");
        return false;
    }
    pubKeyInfo.resize(pubKeyLen + 1);
    if (BIO_read(pbio.get(), pubKeyInfo.data(), pubKeyLen) <= 0) {
        setOpenSSLError("Error in reading public key string");
        return false;
    }
    pubKeyInfo[pubKeyLen] = '\0';
    return true;
}

KeyPairImpl &
KeyPairImpl::setKeys(RawData &pemKey)
{
    AutoCleaner<BIO> evpBio(BIO_new_mem_buf((void *)&pemKey[0], pemKey.size()));
    assert(evpBio.get());

    PEM_read_bio_PrivateKey(evpBio.get(), m_key.getStorage(), nullptr, nullptr);
    assert(m_key.get());
    m_engine = nullptr;
    return *this;
}

EVP_PKEY *
KeyPairImpl::getKey()
{
    return m_key.get();
}

ENGINE *
KeyPairImpl::getEngine()
{
    return m_engine;
}

bool
KeyPairImpl::getP8PrivateKeyInfo(RawData &privKeyInfo)
{
    AutoCleaner<BIO> privbio(BIO_new(BIO_s_mem()));
    if (nullptr == privbio.get()) {
        setOpenSSLError("Unable to create openssl BIO");
        return false;
    }
    if (!PEM_write_bio_PrivateKey(
            privbio.get(), m_key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
    }
    int privKeyLen = BIO_pending(privbio.get()) + 1;
    privKeyInfo.resize(privKeyLen);
    BIO_read(privbio.get(), privKeyInfo.data(), privKeyLen);
    return true;
}

bool
KeyPairImpl::publicEncrypt(const RawData &bufferIn, RawData &bufferOut)
{
    size_t rsaKeySize = EVP_PKEY_get_size(m_key.get());
    bufferOut.resize(rsaKeySize);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(m_key.get(), m_engine);
    if (!ctx) {
        setOpenSSLError("Failed to initialize context");
        return false;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        setOpenSSLError("Failed to initialize context");
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        setOpenSSLError("Failed to set rsa padding.");
        return false;
    }
    size_t encryptedSize = bufferOut.size();
    /* Determine buffer length */
    if (EVP_PKEY_encrypt(
            ctx, bufferOut.data(), &encryptedSize, bufferIn.data(), bufferIn.size()) <= 0) {
        setOpenSSLError("Failed to encrypt buffer.");
        return false;
    }
    if (encryptedSize < 0) {
        setOpenSSLError("Failed to encrypt buffer");
        return false;
    }

    if (encryptedSize != rsaKeySize) {
        bufferOut.resize(encryptedSize);
    }

    return true;
}

bool
KeyPairImpl::privateDecrypt(const RawData &bufferIn, RawData &bufferOut)
{
    size_t rsaKeySize = EVP_PKEY_get_size(m_key.get());

    bufferOut.resize(rsaKeySize);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(m_key.get(), m_engine);
    if (!ctx) {
        setOpenSSLError("Failed to initialize context");
        return false;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        setOpenSSLError("Failed to initialize context");
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        setOpenSSLError("Failed to set rsa padding");
        return false;
    }
    size_t decryptedSize = bufferOut.size();
    /* Determine buffer length */
    if (EVP_PKEY_decrypt(
            ctx, bufferOut.data(), &decryptedSize, bufferIn.data(), bufferIn.size()) <= 0) {
        setOpenSSLError("Failed to decrypt buffer");
        return false;
    }
    if (decryptedSize < 0) {
        setOpenSSLError("Failed to decrypt buffer");
        return false;
    }
    if (decryptedSize != rsaKeySize) {
        bufferOut.resize(decryptedSize);
    }

    return true;
}

bool
KeyPairImpl::sign_digest(const RawData &bufferIn, RawData &bufferOut)
{
    EVP_PKEY *pkey = getKey();

    if (pkey == nullptr) {
        printf("Unable to get Pkey");
        setOpenSSLError("Unable to get Pkey");
        return false;
    }

    EVP_PKEY_CTX_UniquePtr keygen_ctx{EVP_PKEY_CTX_new(pkey, getEngine())};

    if (keygen_ctx == nullptr) {
        setOpenSSLError("Unable to allocate key gen ctx");
        return false;
    }

    if (EVP_PKEY_sign_init(keygen_ctx.get()) != 1) {
        setOpenSSLError(std::format("Signature initialization failed with error :: {0}",
                                    std::to_string(ERR_peek_last_error()))
                            .c_str());
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(keygen_ctx.get(), RSA_PKCS1_PADDING) <= 0) {
        setOpenSSLError("Setting RSA padding failed.");
        return false;
    }

    size_t signlen;

    const EVP_MD *evp_md = KeyPairImpl::get_evp_md(bufferIn.size());
    if (evp_md == nullptr) {
        setOpenSSLError("Please pass correct hash size for setting proper evp_md.");
        return false;
    }

    if (EVP_PKEY_CTX_set_signature_md(keygen_ctx.get(), evp_md) <= 0) {
        setOpenSSLError("Set md hash algorithm to context failed.");
        return false;
    }

    if (EVP_PKEY_sign(keygen_ctx.get(), nullptr, &signlen, bufferIn.data(), bufferIn.size()) <=
        0) {
        setOpenSSLError(std::format("Determine sign length failed :: {0}",
                                    std::to_string(ERR_peek_last_error()))
                            .c_str());
        return false;
    }

    bufferOut.resize(signlen);

    if (EVP_PKEY_sign(
            keygen_ctx.get(), bufferOut.data(), &signlen, bufferIn.data(), bufferIn.size()) <=
        0) {
        setOpenSSLError(std::format("Signing operation failed :: {0}",
                                    std::to_string(ERR_peek_last_error()))
                            .c_str());
        return false;
    }

    return true;
}

bool
KeyPairImpl::_verify_digest(const RawData &bufferIn, const RawData &signDataIn)
{
    EVP_PKEY *pkey = getKey();

    if (pkey == nullptr) {
        setOpenSSLError("Unable to get Pkey");
        return false;
    }

    EVP_PKEY_CTX_UniquePtr keygen_ctx{EVP_PKEY_CTX_new(pkey, getEngine())};

    if (keygen_ctx == nullptr) {
        setOpenSSLError("Unable to allocate key gen ctx.");
        return false;
    }

    if (EVP_PKEY_verify_init(keygen_ctx.get()) <= 0) {
        setOpenSSLError("Unable to initialize verification context.");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(keygen_ctx.get(), RSA_PKCS1_PADDING) <= 0) {
        setOpenSSLError("Setting RSA padding failed in verify operation");
        return false;
    }
    const EVP_MD *evp_md = KeyPairImpl::get_evp_md(bufferIn.size());
    if (evp_md == nullptr) {
        setOpenSSLError("Please pass correct hash size for setting proper evp_md.");
        return false;
    }

    if (EVP_PKEY_CTX_set_signature_md(keygen_ctx.get(), evp_md) <= 0) {
        setOpenSSLError("Set md hash algorithm to context failed");
        return false;
    }

    if (EVP_PKEY_verify(keygen_ctx.get(),
                        signDataIn.data(),
                        signDataIn.size(),
                        bufferIn.data(),
                        bufferIn.size()) <= 0) {
        setOpenSSLError(std::format("Sign verification failed :: {0}",
                                    std::to_string(ERR_peek_last_error()))
                            .c_str());
        return false;
    }
    return true;
}

const EVP_MD *
KeyPairImpl::get_evp_md(int signlen)
{
    if (signlen == 32) {
        return EVP_sha256();
    }
    if (signlen == 48) {
        return EVP_sha384();
    }
    if (signlen == 64) {
        return EVP_sha512();
    }
    return nullptr;
}

}  // namespace NSCertLib
