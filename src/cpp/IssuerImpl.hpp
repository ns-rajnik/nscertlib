#ifndef __NSCERTLIB_ISSUERIMPL_H__
#define __NSCERTLIB_ISSUERIMPL_H__

#include "AutoCleaner.hpp"
#include "KeysImpl.hpp"
#include "cpp/Certificate.hpp"
#include "cpp/Data.hpp"
#include "cpp/Issuer.hpp"

namespace NSCertLib {

class IssuerImpl : public Issuer {
public:
    IssuerImpl() = default;
    ~IssuerImpl() override = default;
    IssuerImpl(const IssuerImpl &) = delete;

    void set(IssuerImpl &issuer);
    bool initialize(const RawData &issuerCert, KeyPairImpl &issuerKeys);
    bool initialize(X509 *cert, KeyPairImpl &keys);
    X509_NAME *getSubject();
    bool setAuthKeyId(X509 *extHandle, bool serialInAuthKeyId);
    bool signCertificate(X509 *cert, SignatureAlgorithm alg);
    int tssgh();

private:
    AutoCleaner<X509> m_issuerCert;
    KeyPairImpl m_issuerKeys;
    bool copySubject(X509 *issuerCert);
    bool copySerial(X509 *issuerCert);
    bool copyExtensions(X509 *issuerCert);
};

using IssuerImplPtr = std::unique_ptr<IssuerImpl>;
}  // namespace NSCertLib
#endif  //__NSCERTLIB_ISSUERIMPL_H__
