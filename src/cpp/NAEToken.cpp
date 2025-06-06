// Added OPENSSL_SUPPRESS_DEPRECATED as part of OpenSSL 3.3 migration. This is added in this
// file to use EVP_PKEY_get0_RSA() API for generating PKCS1 format public key.
#define OPENSSL_SUPPRESS_DEPRECATED

#include <assert.h>
#include <icapi.h>
#include <json/json.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <streambuf>
#include <vector>

#include "ErrorImpl.hpp"
#include "NAEToken.hpp"
#include "Utility.hpp"

static const char kHSMConfig[] = "HSM";
// Type of HSM. Currently the only value this takes is NAE i.e. Safenet
static const char kHSMType[] = "type";
// Properties file for the HSM (Safenet datasecure)
static const char kHSMProperties[] = "properties-file";
// User/Pin for the HSM
static const char kHSMUser[] = "user";
static const char kHSMPassword[] = "password";
static const char kNAEKeySize[] = "nae-key-size";
static const size_t kSymKeyBufferSize = 1024;

bool
NSCertLib::HSMConfig::populate(const char *configFile)
{
    Json::Value config;
    if (not loadJsonFromFile(configFile, config)) {
        return false;
    }

    Json::Value hsmRootConfig = config[kHSMConfig];
    if (hsmRootConfig.isNull()) {
        return true;
    }

    if (not hsmRootConfig[kHSMType].isString()) {
        setError("Invalid or missing 'type' for HSM config - %s", configFile);
        return false;
    }
    type = hsmRootConfig[kHSMType].asString();

    if (not hsmRootConfig[kHSMProperties].isString()) {
        setError("Invalid or missing 'properties' for HSM config - %s", configFile);
        return false;
    }
    properties = hsmRootConfig[kHSMProperties].asString();

    if (not hsmRootConfig[kHSMUser].isString()) {
        setError("Invalid or missing 'user' for HSM config - %s", configFile);
        return false;
    }
    username = hsmRootConfig[kHSMUser].asString();

    if (not hsmRootConfig[kHSMPassword].isString()) {
        setError("Invalid or missing 'password' for HSM config - %s", configFile);
        return false;
    }
    password = hsmRootConfig[kHSMPassword].asString();

    // key size is optional, assume 1024 or 4096 for FIPS
    nae_key_size = (OSSL_PROVIDER_available(nullptr, "fips") == 1) ? AsymKeySize::k4096
                                                                   : AsymKeySize::k1024;

    if (type == kNAE) {
        if (not hsmRootConfig[kNAEKeySize].isNull()) {
            if (not hsmRootConfig[kNAEKeySize].isInt()) {
                setError("Invalid value for '%s' (not an int) for HSM config - %s",
                         kNAEKeySize,
                         configFile);
                return false;
            }
            int32_t keysize = hsmRootConfig[kNAEKeySize].asInt();
            if (keysize != AsymKeySize::k1024 && keysize != AsymKeySize::k2048 &&
                keysize != AsymKeySize::k4096) {
                setError("Invalid size for '%s' for HSM config - %s", kNAEKeySize, configFile);
                return false;
            }
            nae_key_size = keysize;
        }
    }

    return true;
}

EVP_PKEY *
NSCertLib::NAEToken::createKeyPair() const
{
    EVP_PKEY *key = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        setOpenSSLError("EVP PKEY CTX new failed for RSA key generation with engine");
        return nullptr;
    }
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        setOpenSSLError("EVP PKEY CTX init failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, m_hsmConfig.nae_key_size) <= 0) {
        setOpenSSLError("EVP PKEY CTX set keygen bits %d failed", m_hsmConfig.nae_key_size);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    if (EVP_PKEY_keygen(ctx, &key) != 1) {
        setOpenSSLError("EVP PKEY keygen for RSA failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

bool
NSCertLib::NAEToken::getPubKeyInPEM(EVP_PKEY *key, std::string &pubKey)
{
    NSCertLib::AutoCleaner<BIO> pbio(BIO_new(BIO_s_mem()));
    if (nullptr == pbio.get()) {
        NSCertLib::setOpenSSLError("Unable to create openssl BIO");
        return false;
    }
    if (not PEM_write_bio_RSAPublicKey(pbio.get(), EVP_PKEY_get0_RSA(key))) {
        NSCertLib::setOpenSSLError("Unable to write public key");
        return false;
    }
    std::vector<char> pubKeyData(BIO_pending(pbio.get()));
    if (BIO_read(pbio.get(), pubKeyData.data(), pubKeyData.size()) < 1) {
        NSCertLib::setOpenSSLError("Unable to read public key BIO");
        return false;
    }
    pubKey.assign(pubKeyData.data(), pubKeyData.size());
    return true;
}

bool
NSCertLib::NAEToken::decryptSymKey(EVP_PKEY *key,
                                   unsigned char *wrappedKey,
                                   int wrappedKeyLen,
                                   NSCertLib::SecureItem &symKey)
{
    NSCertLib::AutoCleaner<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new(key, nullptr));
    if (nullptr == pctx.get()) {
        NSCertLib::setOpenSSLError("Could not create context");
        return false;
    }
    if (EVP_PKEY_decrypt_init(pctx.get()) <= 0) {
        NSCertLib::setOpenSSLError("Could not initialize context for decryption");
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PADDING) <= 0) {
        NSCertLib::setOpenSSLError("Could not set padding for the context");
        return false;
    }

    auto symKeyStr = std::make_unique<unsigned char[]>(kSymKeyBufferSize);
    size_t symKeyLen = kSymKeyBufferSize;
    if (EVP_PKEY_decrypt(pctx.get(), symKeyStr.get(), &symKeyLen, wrappedKey, wrappedKeyLen) <=
        0) {
        NSCertLib::setOpenSSLError("Could not decrypt the key");
        return false;
    }
    symKey.copy(symKeyStr.get(), symKeyLen);
    return true;
}

namespace NSCertLib {

const char *kNAEHSMType = "NAE";

NAEToken::NAEToken(const char *certWrapKeyName, const HSMConfig &config)
    : m_certWrapKeyName(certWrapKeyName), m_hsmConfig(config)
{
}

NAEToken::NAEToken(const NAEToken &other) : m_hsmConfig(other.m_hsmConfig)
{
    // NAEToken is not copyable
    assert(false);
}

NAEToken::~NAEToken()
{
    if (m_connected) {
        I_C_CloseSession(m_safenetSession);
        m_connected = false;
    }
    I_C_Fini();
}

NAEToken &
NAEToken::operator=(const NAEToken & /*other*/)
{
    // NAEToken is not copyable
    assert(false);
    return *this;
}

NAEToken &
NAEToken::setWrappingMethod(const char *alg, const char *keySize)
{
    m_wrappingKeyAlg = alg, m_wrappingKeySize = keySize;
    return *this;
}

bool
NAEToken::initialize()
{
    assert(m_hsmConfig.type == kNAEHSMType);
    I_T_RETURN rc = I_C_Initialize(I_T_Init_File, m_hsmConfig.properties.c_str());
    if ((I_E_ALREADY_INITIALIZED != rc) && (I_E_OK != rc)) {
        setNAEError(
            rc, "Unable to initialize ProtectApp. Is safenet properties file set properly?");
        return false;
    }
    // WARNING:
    // Note that I_C_OpenSession() does not support password auth
    // with KMIP. And without password auth, keys will not get
    // created (as global key creation is disallowed on Safenet
    // datasecure as per our configuration)
    // So as long as we use NAE, we should be fine
    rc = I_C_OpenSession(&m_safenetSession,
                         I_T_Auth_Password,
                         m_hsmConfig.username.c_str(),
                         m_hsmConfig.password.c_str());

    if (rc != I_E_OK) {
        setNAEError(rc,
                    "Unable to connect to safenet datasecure.Are the credentials valid? And "
                    "is NAE configuration proper?");
        return false;
    }
    m_connected = true;
    return true;
}

// Function to check if CW key is present and properly configured.
// If this function returns kInvalid, it should be treated as
// unrecoverable error
NAEToken::CWKeyStatus
NAEToken::checkCertWrapKey()
{
    assert(nullptr != m_safenetSession);
    I_O_AttributeList pSystemAttributeList = nullptr;
    I_O_AttributeList pCustomAttributeList = nullptr;
    // Get the attributes for CW key
    I_T_RETURN rc = I_C_GetKeyAttributes(m_safenetSession,
                                         m_certWrapKeyName.c_str(),
                                         &pSystemAttributeList,
                                         &pCustomAttributeList);
    if (I_E_OK != rc) {
        if (I_E_UNKNOWN_KEY == rc) {
            // Cert wrap key is not yet set
            return kAbsent;
        }
        setNAEError(rc,
                    "Error in retrieving Cert Wrap key details. Has someone fiddled with cert "
                    "wrap key?");
        return kInvalid;
    }
    // Validate the algorithm and key size for Cert wrap key

    char *value{nullptr};
    rc = I_C_FindInAttributeList(pSystemAttributeList, "KeySize", &value);
    if (I_E_OK != rc) {
        setNAEError(rc,
                    "Unable to find key size of Cert Wrap key. Has someone fiddled with cert "
                    "wrap key?");
        I_C_Free(pSystemAttributeList);
        I_C_Free(pCustomAttributeList);
        return kInvalid;
    }
    if (strncmp(m_wrappingKeySize.c_str(), value, strlen(m_wrappingKeySize.c_str())) != 0) {
        setError(
            "Invalid cert wrap key size - %s. Expected - %s. Has someone fiddled with cert "
            "wrap key?",
            value,
            m_wrappingKeySize.c_str());
        I_C_Free(pSystemAttributeList);
        I_C_Free(pCustomAttributeList);
        return kInvalid;
    }
    rc = I_C_FindInAttributeList(pSystemAttributeList, "Algorithm", &value);
    if (I_E_OK != rc) {
        setNAEError(rc,
                    "Unable to find algorithm of Cert Wrap key. Has someone fiddled with cert "
                    "wrap key?");
        I_C_Free(pSystemAttributeList);
        I_C_Free(pCustomAttributeList);
        return kInvalid;
    }
    if (strncmp(m_wrappingKeyAlg.c_str(), value, strlen(m_wrappingKeyAlg.c_str())) != 0) {
        setError(
            "Invalid cert wrap key algorithm - %s. Expected - %s. Has someone fiddled with "
            "cert wrap key?",
            value,
            m_wrappingKeyAlg.c_str());
        I_C_Free(pSystemAttributeList);
        I_C_Free(pCustomAttributeList);
        return kInvalid;
    }
    I_C_Free(pSystemAttributeList);
    I_C_Free(pCustomAttributeList);
    // We are fine
    return kPresent;
}

// Function to create CW key
bool
NAEToken::createCertWrapKey()
{
    I_O_KeyInfo keyInfo{nullptr};
    I_T_RETURN rc = I_C_CreateKeyInfo(
        m_wrappingKeyAlg.c_str(), atoi(m_wrappingKeySize.c_str()), true, true, &keyInfo);
    if (I_E_OK != rc) {
        setNAEError(rc, "Unable to create Cert Wrap key info ");
        return false;
    }
    rc = I_C_CreateKey(m_safenetSession, m_certWrapKeyName.c_str(), keyInfo, nullptr);
    if (I_E_OK != rc) {
        setNAEError(rc, "Unable to create Cert Wrap key");
        return false;
    }
    return true;
}

bool
NAEToken::getCertWrapKey(SecureItem &wrappedCWKey)
{
    if (kAbsent == checkCertWrapKey()) {
        if (!createCertWrapKey()) {
            return false;
        }
    }
    NSCertLib::AutoCleaner<EVP_PKEY> pkey(NAEToken::createKeyPair());
    if (nullptr == pkey.get()) {
        return false;
    }
    std::string pubKey;
    if (!NAEToken::getPubKeyInPEM(pkey.get(), pubKey)) {
        return false;
    }
    I_T_BYTE *wrappedKey = nullptr;

    I_T_UINT wrappedKeyLen = 0;
    I_T_RETURN rc = I_C_ExportWrappedKey(m_safenetSession,
                                         m_certWrapKeyName.c_str(),
                                         (I_T_BYTE *)(pubKey.c_str()),
                                         pubKey.length(),
                                         I_T_ExportKeyWrapFormat_RAW_PKCS1v15,
                                         &wrappedKey,
                                         &wrappedKeyLen);
    if (I_E_OK != rc) {
        setNAEError(rc, "Unable to export wrapped Cert Wrap key");
        return false;
    }
    if (!NAEToken::decryptSymKey(pkey.get(), wrappedKey, wrappedKeyLen, wrappedCWKey)) {
        I_C_Free(wrappedKey);
        return false;
    }
    I_C_Free(wrappedKey);
    return true;
}

}  // namespace NSCertLib
