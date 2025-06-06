#ifndef __NSCERTLIB_MODULE_H__
#define __NSCERTLIB_MODULE_H__

#include <map>
#include <memory>

#include "CertReq.hpp"
#include "Certificate.hpp"
#include "Data.hpp"
#include "Issuer.hpp"
#include "Keys.hpp"
#include "Wrapper.hpp"

namespace NSCertLib {

/**
 * @brief
 * Class/interface to generate other objects of interest
 * This is a singleton per process.
 * IMPORTANT:
 * 1) Attempts to create multiple Module instances in a single process can result in
 *    undefined behavior
 * 2) This does not handle fork() very well. Hence Module instance must be created
 *    after fork() call, if fork() is to be used.
 * Same applies to python as well
 */
class Module {
public:
    virtual ~Module() = default;

    /**
     * @brief
     * Method to check if Module has been initialized properly
     * @returns true if initialized else false
     */
    virtual bool isInitialized() = 0;

#ifndef SWIG

    /**
     * @brief
     * Method to generate an asymmetric key pair of given key size
     *
     * @param[in]   alg         Algorithm for keys
     * @param[in]   keysize     Key size of the generated keys
     * @param[in]   meth        Key generation method
     * @returns unique_ptr containing pointer to KeyPair if successful,
     *          else unique_ptr with NULL
     */
    virtual KeyPairPtr createAsymKeyPair(AsymKeyAlgorithm alg,
                                         AsymKeySize keysize,
                                         AsymKeyGenMethod meth = kSoftware) = 0;

    /**
     * @brief
     * Copy an existing asymetric key pair
     *
     * @param[in]   KeyPair   keypair to copy
     * @returns unique_ptr containing pointer to KeyPair if successful,
     *          else unique_ptr with NULL
     */
    virtual KeyPairPtr copyAsymKeyPair(const KeyPair &keyPair) = 0;

    /**
     * @brief
     * Method to create issuer(CA)
     *
     * @param[in] issuerCert    Issuer's certificate in PEM format
     * @param[in] issuerKeys    Issuer's key pair
     * @returns unique_ptr with pointer to Issuer if successful,
     *          else unique_ptr with NULL
     */
    virtual IssuerPtr createIssuer(const RawData &issuerCert, KeyPair &issuerKeys) = 0;

    /**
     * @brief
     * Method to create a new certificate request
     *
     * @param[in] subject   map of key value pairs for subject line
     * @param[in] keys      Asymmetric key pair for which certificate request
     *                      is to be generated
     * @returns unique_ptr with pointer to CertReq if successful,
     *          else unique_ptr with NULL
     */
    virtual CertReqPtr createCertificateRequest(X509NameMap &subject, KeyPair &keys) = 0;

    /**
     * @brief
     * Method to create a new certificate request with the subject encoded as
     * ASN1_PRINTABLESTRING, if "emailAddress" is present it will be
     * encoded as ASN1_IA5STRING
     *
     * @param[in] subject   map of key value pairs for subject line
     * @param[in] keys      Asymmetric key pair for which certificate request
     *                      is to be generated
     * @returns unique_ptr with pointer to CertReq if successful,
     *          else unique_ptr with NULL
     */
    virtual CertReqPtr createCertificateRequestPrintableSubjectEncoding(X509NameMap &subject,
                                                                        KeyPair &keys) = 0;

    /**
     * @brief
     * Method to create a new certificate request with defined DN position in subject line
     *
     * @param[in] subject            Map of key value pairs for subject line
     * @param[in] keys               Asymmetric key pair for which certificate request
     *                               is to be generated
     * @param[in] position_list      List of DNs in their respective positions
     *
     * @returns unique_ptr with pointer to CertReq if successful,
     *          else unique_ptr with NULL
     */
    virtual CertReqPtr createCertificateRequestWithDNPosition(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list) = 0;

    /**
     * @brief
     * Method to create a new certificate request with defined DN position in subject line
     * with the subject encoded as ASN1_PRINTABLESTRING, if "emailAddress" is present it
     * will be encoded as ASN1_IA5STRING
     *
     * @param[in] subject            Map of key value pairs for subject line
     * @param[in] keys               Asymmetric key pair for which certificate request
     *                               is to be generated
     * @param[in] position_list      List of DNs in their respective positions
     *
     * @returns unique_ptr with pointer to CertReq if successful,
     *          else unique_ptr with NULL
     */
    virtual CertReqPtr createCertificateRequestWithDNPositionPrintableSubjectEncoding(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list) = 0;

    /**
     * @brief
     * Method to create a certificate out of a certificate request
     * @param[in]   certRequest         Certificate request
     * @param[in]   alg                 Signature algorithm to use for signing
     * @param[in]   serial              Serial number for the certificate
     * @param[in]   issuer              Issuer (CA) signing the certificate
     * @param[in]   validDays           Number of days for which the certificate is to be valid
     * @returns unique_ptr with pointer to Certificate if successful,
     *          else unique_ptr with NULL
     */
    virtual CertificatePtr createCertificate(CertReq &certRequest,
                                             SignatureAlgorithm alg,
                                             const RawData &serial,
                                             Issuer *issuer,
                                             unsigned int validDays) = 0;

    /**
     * @brief
     * Method to create a certificate out of a certificate request with a csr
     * @param[in]   certReq             Certificate request in pem format csr
     * @param[in]   alg                 Signature algorithm to use for signing
     * @param[in]   serial              Serial number for the certificate
     * @param[in]   issuer              Issuer (CA) signing the certificate
     * @param[in]   validDays           Number of days for which the certificate is to be valid
     * @returns unique_ptr with pointer to Certificate if successful,
     *          else unique_ptr with NULL
     */
    virtual CertificatePtr createCertificatewithCSR(const RawData &certReq,
                                                    SignatureAlgorithm alg,
                                                    const RawData &serial,
                                                    Issuer *issuer,
                                                    unsigned int validDays) = 0;
    /**
     * @brief
     * Method to get a certificate object from certificate data in various formats
     * @param[in]   format      Format of certdata
     * @param[in]   certdata    Actual certificate data in given format
     * @param[in]   passwd      Password used to protect certificate/password. This is optional
     * @returns unique_ptr containing Certificate if successful,
     *          else unique_ptr with NULL
     */
    virtual CertificatePtr getCertificate(CertificateFormat format,
                                          const RawData &certdata,
                                          const char *passwd = NULL) = 0;

    virtual CertificatePtr getCertificateWithKey(CertificateFormat format,
                                                 const RawData &certdata,
                                                 KeyPair &keys) = 0;
#else
    // CAUTION:
    // These are for use with swig (aka python). They should not be used anywhere else!
    // For python it makes a lot of sense to return the object rather than take a reference to
    // object and return boolean (which works well for C++)
    virtual KeyPair *createAsymKeyPair(AsymKeyAlgorithm alg,
                                       AsymKeySize keysize,
                                       AsymKeyGenMethod meth = kSoftware) = 0;
    virtual KeyPair *copyAsymKeyPair(const KeyPair &keyPair) = 0;
    virtual Issuer *createIssuer(const RawData &issuerCert, KeyPair &issuerKeys) = 0;
    virtual CertReq *createCertificateRequest(X509NameMap &subject, KeyPair &keys) = 0;
    virtual CertReq *createCertificateRequestWithDNPosition(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list) = 0;
    virtual CertReq *createCertificateRequestWithDNPositionPrintableSubjectEncoding(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list) = 0;
    virtual CertReq *createCertificateRequestPrintableSubjectEncoding(X509NameMap &subject,
                                                                      KeyPair &keys) = 0;
    virtual Certificate *createCertificate(CertReq &certRequest,
                                           SignatureAlgorithm alg,
                                           const RawData &serial,
                                           Issuer *issuer,
                                           unsigned int validDays) = 0;
    virtual Certificate *createCertificatewithCSR(const RawData &certReq,
                                                  SignatureAlgorithm alg,
                                                  const RawData &serial,
                                                  Issuer *issuer,
                                                  unsigned int validDays) = 0;
    virtual Certificate *getCertificate(CertificateFormat format,
                                        const RawData &certdata,
                                        const char *passwd = nullptr) = 0;
    virtual Certificate *getCertificateWithKey(CertificateFormat format,
                                               const RawData &certdata,
                                               KeyPair &keys) = 0;
#endif
    /**
     * @brief
     * Method to get the wrapper object
     * @returns reference to wrapper object
     */
    virtual Wrapper &getWrapper(const char *certWrapKey = nullptr) = 0;

};  // Class Module

using ModulePtr = std::unique_ptr<Module>;
}  // namespace NSCertLib

#endif  //__NSCERTLIB_MODULE_H__
