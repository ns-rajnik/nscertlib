#ifndef __NSCERTLIB_CERTIFICATE_IMPL_H__
#define __NSCERTLIB_CERTIFICATE_IMPL_H__

#include <memory>
#include <string>

#include "AutoCleaner.hpp"
#include "IssuerImpl.hpp"
#include "KeysImpl.hpp"
#include "cpp/Certificate.hpp"

namespace NSCertLib {

class CertificateImpl : public Certificate {
public:
    enum CertDataType { kCertContentType, kCertReqType };

    explicit CertificateImpl(CertDataType type);
    // CertificateImpl should not be copyable
    CertificateImpl(const CertificateImpl &other) = delete;
    void operator=(const CertificateImpl &other) = delete;

    CertificateImpl &setCertData(CertificateFormat format,
                                 const RawData &certdata,
                                 const char *passwd = nullptr);
    CertificateImpl &setCertData(CertificateFormat format,
                                 const RawData &certdata,
                                 KeyPairImpl &keys);
    CertificateImpl &setCertRequest(X509_REQ *certReq);
    CertificateImpl &setKeys(KeyPairImpl &keys);
    CertificateImpl &setIssuer(IssuerImpl &issuer);
    CertificateImpl &setSerial(const RawData &serial);
    CertificateImpl &setSignatureAlgorithm(SignatureAlgorithm alg);
    CertificateImpl &setValidity(unsigned int validDays);
    CertificateImpl &setSerialInAuthKeyId();
    bool initialize();
    bool getCertificate(CertificateFormat format,
                        RawData &certificate,
                        const char *passwd = nullptr) override;
    KeyPair &getKeys() override;
    bool getSerial(RawData &serial) override;
    bool getIssuerName(RawData &issuer) override;
    bool getSubjectName(RawData &subject) override;
    bool getSubjectKeyId(RawData &subjectKeyId) override;
    unsigned int getValidityStart() override;
    unsigned int getValidityEnd() override;
    bool isCA() override;
    bool resign(Issuer *issuer, const RawData &serial, SignatureAlgorithm alg) override;

private:
    struct CertContent {
        CertificateFormat format{kPEM};
        RawData content;
        std::string password;
        bool gotKeys{false};
    };
    struct CertReqData {
        AutoCleaner<X509_REQ> certReq;
        RawData serial;
        IssuerImpl issuer;
        SignatureAlgorithm alg;
        unsigned int validDays;
        bool serialInAuthKeyId{false};
    };

    CertDataType m_type;
    CertContent m_certContent;
    CertReqData m_certReq;
    KeyPairImpl m_keys;
    AutoCleaner<X509> m_certificate;

    bool initializeFromPKCS12();
    bool initializeFromPEM();
    bool initializeFromCertReq();
    bool generatePKCS12(RawData &certificate, const char *passwd);
    bool generatePEM(RawData &certificate, const char *passwd);
    bool signCertificate();
    bool getPEMCert(const RawData &certData, RawData &pemCert);
    bool copyExtensions();
};

using CertificateImplPtr = std::unique_ptr<CertificateImpl>;

}  // namespace NSCertLib

#endif  //__NSCERTLIB_CERTIFICATE_IMPL_H__
