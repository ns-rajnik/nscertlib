#ifndef __NSCERTLIB_WRAPPER_H__
#define __NSCERTLIB_WRAPPER_H__

#include "Data.hpp"
#include "Keys.hpp"

namespace NSCertLib {
/**
 * @brief
 * Class/Interface to wrap/unwrap keys and data
 * Concrete object should be obtained from Module interface
 */
class Wrapper {
public:
    virtual ~Wrapper() = default;

    /**
     * @brief
     * Method to wrap asymmetric key pair. Private key is actually
     * wrapped (aka encrypted) using CW key and a random IV. Public
     * key wrapped as Public Key subject info in DER format.
     * The wrapped data is in binary format
     *
     * @param[in]  keys             Asymmetric key pair
     * @param[out] wrappedPrivKey   Wrapped private key
     * @param[out] derPubKey        DER encoded public key info
     * @returns true if successful, else false
     */
    virtual bool wrap(KeyPair &keys, RawData &wrappedPrivKey, RawData &derPubKey) = 0;

    /**
     * @brief
     * Method to wrap given binary content. Wrapping (encryption)
     * happens using CW key and a random IV. The wrapped data consists
     * of the IV and wrapped content, in binary
     *
     * @param[in]  content          Binary content to wrap
     * @param[out] wrappedContent   Wrapped content
     * @returns true if successful, else false
     */
    virtual bool wrapData(const RawData &content, RawData &wrappedContent) = 0;

#ifndef SWIG
    /**
     * @brief
     * Method to unwrap wrapped key pair. Does the opposite of
     * wrap() and return pointer to KeyPair object. This function
     * is slightly different from the other wrap/unwrap calls, in
     * that it returns unique_ptr and not a bool. The reason is that
     * KeyPair can only be created by NSCertLib and not the user of
     * this library
     *
     * @param[in] wrappedPrivKey   Wrapped private key
     * @param[in] derPubKey        DER encoded public key info
     * @returns unique_ptr containing pointer to KeyPair if successful,
     *          else unique_ptr to NULL
     */
    virtual KeyPairPtr unwrap(const RawData &wrappedPrivKey, const RawData &derPubKey) = 0;
#endif

    /**
     * @brief
     * Method to unwrap wrapped binary content. Does the opposite
     * of wrap()
     *
     * @param[in]   wrappedContent  Wrapped binary content
     * @param[out]  content         Unwrapped content
     * @returns true if successful, else false
     */
    virtual bool unwrapData(const RawData &wrappedContent, RawData &content) = 0;

    /**
     * @brief
     * Method to validate that the wrapper is working properly
     * i.e. CW key is intact. Basically unwraps 'encryptedValue'
     * and checks if it matches 'value'
     *
     * @param[in]   value           Unwrapped value to check with
     * @param[in]   wrappedValue    Wrapped value corresponding to the
     *                              supplied unwrapped value
     * @returns true if Wrapper is intact, else false
     */
    virtual bool validateWrapper(const char *value, const RawData &wrappedValue) = 0;

#ifdef SWIG
    // CAUTION:
    // These are for use with swig (aka python). They should not be used anywhere else!
    // For python it makes a lot of sense to return the object rather than take a reference to object
    // and return boolean (which works well for C++)
    RawData* wrapPrivateKey(KeyPair& keys);
    RawData* wrapPublicKey(KeyPair& keys);
    RawData* wrapData(const RawData& data);
    virtual KeyPair* unwrap(const RawData& wrappedPrivKey, const RawData& derPubKey) = 0;
    RawData* unwrapData(const RawData& wrappedData);
#endif
};  // class Wrapper

}  // namespace NSCertLib

#endif  //__NSCERTLIB_WRAPPER_H__
