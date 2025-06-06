#ifndef __NSCERTLIB_CERTREQ_H__
#define __NSCERTLIB_CERTREQ_H__

#include <openssl/x509v3.h>

#include <memory>

#include "Certificate.hpp"
#include "Data.hpp"

namespace NSCertLib {

/**
 * @brief
 * Key usages
 */
enum KeyUsage {
    kDigitalSignature = 0,  //!< Digital signature
    kNonRepudiation,        //!< Non-repudiation
    kKeyEncipherment,       //!< Key encipherment
    kDataEncipherment,      //!< Data encipherment
    kKeyAgreement,          //!< Key agreement
    kKeyCertSign,           // !< Key/certificate signing
    kCrlSign                // !< CRL signing
};

/**
 * @brief
 * Extended key usages
 * To add more extended key usages, this enumeration will need to be
 * extended
 * Enum values are part of database schema creation:
 *     SEC_OID_EXT_KEY_USAGE_SERVER_AUTH = 146,
 *     SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH = 147,
 *     SEC_OID_EXT_KEY_USAGE_CODE_SIGN = 148,
 *     SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT = 149,
 *     SEC_OID_EXT_KEY_USAGE_TIME_STAMP = 150
 * Originallly from nss/lib/util/secoidt.h
 */
enum ExtKeyUsage {
    kServerAuth = 146,       //!< Server authentication
    kClientAuth = 147,       //!< Client authentication
    kCodeSigning = 148,      //!< Code signing
    kEmailProtection = 149,  //!< Email protection
    kTimeStamping = 150,     //!< Time stamping
    kMaxExtKeyUsage = 5
};

/**
 * @brief
 * Netscape certificate type extension values
 */
enum NSCertType {
    kSSLClient = 0,   //!< SSL Client
    kSSLServer,       //!< SSL Server
    kSMime,           //!< S/MIME client
    kObjectSigning,   //!< Object signing
    kSSLCA = 5,       //!< SSL CA
    kSMimeCA,         //!< S/MIME CA
    kObjectSigningCA  //!< Object signing CA
};

/**
 * @brief
 * Class/Interface for certificate request
 * During certificate creation, this object is used to add
 * all the required certificate extensions/values
 */
class CertReq {
public:
    virtual ~CertReq() = default;

    /**
     * @brief
     * Method to add an alternate domain name
     * No UTF support yet
     * @param[in] altName   Alternate domain name as a C-string
     * @return true if successful, else false
     */
    virtual bool addAlternateName(const char *altName) = 0;

    /**
     * @brief
     * Method to set the certificate (request) as that for CA
     * @returns true if successful, else false
     */
    virtual bool setCA(int pathLen = -1) = 0;

    /**
     * @brief
     * Method to set a key usage
     * @returns true if successful, else false
     */
    virtual bool addKeyUsage(KeyUsage usage) = 0;

    /**
     * @brief
     * Method to set an extended key usage
     * @returns true if successful, else false
     */
    virtual bool addExtKeyUsage(ExtKeyUsage extUsage) = 0;

    /**
     * @brief
     * Method to set Netscape certificate type
     * @returns true if successful, else false
     */
    virtual bool addNSCertType(NSCertType type) = 0;

    /**
     * @brief
     * Method to get serial number set in the authority key ID
     * @returns true if successful, else false
     */
    virtual bool setSerialInAuthKeyId() = 0;

    /**
     * @brief
     * Method to get csr
     * @returns true if successful, else false
     */
    virtual bool getCsr(NSCertLib::SignatureAlgorithm alg, RawData &csr) = 0;
#ifdef SWIG
        // CAUTION:
        // These are for use with swig (aka python). They should not be used anywhere else!
        // For python it makes a lot of sense to return the object rather than take a reference to object
        // and return boolean (which works well for C++)
        RawData* getCsr(NSCertLib::SignatureAlgorithm alg);
#endif
};  // class CertReq

using CertReqPtr = std::unique_ptr<CertReq>;

}  // namespace NSCertLib
#endif  //__NSCERTLIB_CERTREQ_H__
