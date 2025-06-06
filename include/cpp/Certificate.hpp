#ifndef __NSCERTLIB_CERTIFICATE_H__
#define __NSCERTLIB_CERTIFICATE_H__

#include <memory>
#include "Data.hpp"
#include "Issuer.hpp"
#include "Keys.hpp"

namespace NSCertLib {

/**
 * @brief
 * Signature algorithms
 * Currently we support only variants of SHA
 */
enum SignatureAlgorithm {
    kSHA1,    //!< SHA-1
    kSHA256,  //!< SHA-256
    kSHA512   //!< SHA-512
};

/**
 * @brief
 * Certificate formats
 */
enum CertificateFormat {
    kPEM,    //!< PEM encoded
    kPKCS12  //!< PKCS12
};

/**
 * @brief
 * Class/Interface for certificate operations
 * Mainly for getting/converting certificate to required format
 */
class Certificate {
public:
    virtual ~Certificate() = default;

    /**
     * @brief
     * Method to convert certificate to given format
     * @param[in]   format          Format of certificate required
     * @param[out]  certificate     Certificate in required format
     * @param[in]   passwd          Password to use for certificate (optional)
     *                              TODO: Need to make password mandatory
     * @returns true if successful, else false
     */
    virtual bool getCertificate(CertificateFormat format,
                                RawData &certificate,
                                const char *passwd = nullptr) = 0;

    /**
     * @brief
     * Method to get reference to key pair for this certificate
     * NOTE: If the certificate is not initialized, the key pair
     * returned will be of no use (all relevant KeyPair calls will fail)
     * @returns KeyPair for the certificate
     */
    virtual KeyPair &getKeys() = 0;

    /**
     * @brief
     * Method to get certificate serial number
     * @param[out]  serial      RawData container in which serial number is returned
     * @returns true if successful
     *          else false
     */
    virtual bool getSerial(RawData &serial) = 0;

    /**
     * @brief
     * Method to get Issuer's name for this certificate. If certificate
     * is not initialized then it will return NULL
     * @returns Issuer's name for the certificate
     */
    virtual bool getIssuerName(RawData &issuer) = 0;

    /**
     * @brief
     * Method to get Subject name for this certificate. If certificate
     * is not initialized then it will return NULL
     * @returns Subject name for the certificate
     */
    virtual bool getSubjectName(RawData &) = 0;

    /**
     * @brief
     * Method to get subject key identifier for this certificate.
     * @param[out]  subjectKeyId    Subject key identifier
     * @returns true if subject key identifier found. Else false
     */
    virtual bool getSubjectKeyId(RawData &subjectKeyId) = 0;

    /**
     * @brief
     * Method to get validity start date for the certificate in
     * seconds since epoch.
     */
    virtual unsigned int getValidityStart() = 0;

    /**
     * @brief
     * Method to get validity end date for the certificate in
     * seconds since epoch
     */
    virtual unsigned int getValidityEnd() = 0;

    /**
     * @brief
     * Method to tell if given certificate is a CA certificate
     * @returns true if CA certificate else false
     */
    virtual bool isCA() = 0;

    /**
     * @brief
     * Method to get a resigned certificate using the given signature algorithm. After
     * resigning the new certificate can be obtained using getCertificate()
     * @param[in]   issuer          Issuer who is to sign the certificate
     * @param[in]   serial          New serial number to use for resigning
     * @param[in]   alg             Signature algorithm to use for signing
     * @returns true if successful else false
     */
    virtual bool resign(NSCertLib::Issuer *issuer,
                        const RawData &serial,
                        SignatureAlgorithm alg) = 0;

#ifdef SWIG
    // CAUTION:
    // These are for use with swig (aka python). They should not be used anywhere else!
    // For python it makes a lot of sense to return the object rather than take a reference to object
    // and return boolean (which works well for C++)
    RawData* getCertificate(CertificateFormat format, const char* passwd = nullptr);
    RawData* getSubjectKeyId();
    RawData* getSerial();
    RawData* getSubjectName();
    RawData* getIssuerName();
#endif
};

using CertificatePtr = std::unique_ptr<Certificate>;

}  // namespace NSCertLib

#endif //__NSCERTLIB_CERTIFICATE_H__
