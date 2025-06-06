#ifndef __NSCERTLIB_KEYS_H__
#define __NSCERTLIB_KEYS_H__

#include <openssl/evp.h>

#include <memory>

#include "Data.hpp"

namespace NSCertLib {

/**
 * @brief
 * Asymmetric Key algorithm
 * We are only supporting RSA today
 */
enum AsymKeyAlgorithm {
    kRSA,  //!< RSA
    kInvalidKeyAlg
};

/**
 * @brief
 * Key size in bits
 */
enum AsymKeySize {
    k1024 = 1024,  //!< 1024 bits
    k2048 = 2048,  //!< 2048 bits
    k4096 = 4096   //!< 4096 bits
};

/**
 * @brief
 * Key generation method
 */
enum AsymKeyGenMethod {
    kSoftware = 0,  // Using Software
    kHSM = 1        // Using HSM
};

/**
 * @brief
 * Class/interface for asymmetric key pair
 * Does not expose much. The main use is an argument
 * for any operation done using other objects
 * eg. certificate creation, wrapping etc.
 */
class KeyPair {
public:
    virtual ~KeyPair() = default;

    /**
     * @brief
     * Method to get (encrypted/raw) private key info in PEM format
     * Right now it generates the info even without password.
     * This is necessary for our current design. In future, we
     * need to make password mandatory
     * Note: If the key is stored in softoken, then raw private key
     * information cannot be obtained i.e. password must be provided
     * else this call will fail
     * @param[out]  privKeyInfo  Private key info in PEM format
     * @param[in]   passwd       Password for encrypting private key info
     *                           (optional)
     * @returns true if successful, else false
     */
    virtual bool getPrivateKeyInfo(RawData &privKeyInfo, const char *passwd) = 0;

    /**
     * @brief
     * Method to provide PEM encoded public key info
     * @params[out] pubKeyInfo  PEM encoded public key info
     * @returns true if public key available (i.e. KeyPair initialized),
     *          false otherwise
     */
    virtual bool getPEMPublicKey(RawData &pubKeyInfo) = 0;

    /**
     * @brief
     * Encrypt buffer using the public RSA key, padding used is
     * RSA_PKCS1_OAEP_PADDING, maximum input buffer size is RSA_size() - 42
     * Only available when OpenSSL is enabled.
     *
     * @param[in]  buffer_in Buffer to encrypt with public key
     * @param[out] buffer_out Content of buffer_in encrypted with public key
     *
     * @returns true if successful, else false
     */
    virtual bool publicEncrypt(const RawData &bufferIn, RawData &bufferOut) = 0;

    /**
     * @brief
     * Decrypt buffer using the private RSA key, padding used is
     * RSA_PKCS1_OAEP_PADDING, maximum input buffer size is RSA_size()
     * Only available when OpenSSL is enabled.
     *
     * @param[in]  buffer_in Buffer encrypted with public key
     * @param[out] buffer_out Content of buffer_in decrypted with private
     * key
     *
     * @returns true if successful, else false
     */
    virtual bool privateDecrypt(const RawData &bufferIn, RawData &bufferOut) = 0;

    virtual bool sign_digest(const RawData &bufferIn, RawData &bufferOut) = 0;
    virtual bool _verify_digest(const RawData &bufferIn, const RawData &signDataIn) = 0;

#ifdef SWIG
        // CAUTION:
        // These are for use with swig (aka python). They should not be used anywhere else!
        // For python it makes a lot of sense to return the object rather than take a reference to object
        // and return boolean (which works well for C++)
        RawData* getPrivateKeyInfo(const char* passwd);
        RawData* getPEMPublicKey();
        RawData* privateDecrypt(const RawData& bufferIn);
        RawData* publicEncrypt(const RawData& bufferIn);
        RawData* sign_digest(const RawData& signingData);
        bool verify_digest(const RawData& signedData, const RawData& tbs);
#endif
};
using KeyPairPtr = std::unique_ptr<KeyPair>;

}  // namespace NSCertLib

#endif  //__NSCERTLIB_KEYS_H__
