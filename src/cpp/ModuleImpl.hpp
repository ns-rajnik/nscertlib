#pragma once

#include <openssl/rsa.h>

#include <map>
#include <string>

#include "AutoCleaner.hpp"
#include "CertReqImpl.hpp"
#include "CertificateImpl.hpp"
#include "IssuerImpl.hpp"
#include "KeysImpl.hpp"
#include "NAEToken.hpp"
#include "WrapperImpl.hpp"
#include "cpp/Module.hpp"

// Note on thread-safety:
// The creation/initialization/fetch of ModuleImpl is handled by getModule() call
// This call uses a lock to synchronize and make itself thread-safe.
// The rest of the operations either create new objects or read the members of
// ModuleImpl. Hence they are thread-safe

namespace NSCertLib {

/**
 * @brief
 * Implementation of Module interface
 */
class ModuleImpl : public Module {
    // allow use of std::make_unique
    struct PrivateToken {};

public:
    explicit ModuleImpl(const char *configFile, PrivateToken ptoken);
    ~ModuleImpl() override = default;
    ModuleImpl(const ModuleImpl &other) = delete;
#ifndef SWIG
    virtual KeyPairPtr createAsymKeyPair(AsymKeyAlgorithm alg,
                                         AsymKeySize keysize,
                                         AsymKeyGenMethod meth = kSoftware);
    virtual KeyPairPtr copyAsymKeyPair(const KeyPair &keyPair);
    virtual IssuerPtr createIssuer(const RawData &issuerCert, KeyPair &issuerKeys);
    virtual CertReqPtr createCertificateRequest(X509NameMap &subject, KeyPair &keys);
    virtual CertReqPtr createCertificateRequestPrintableSubjectEncoding(X509NameMap &subject,
                                                                        KeyPair &keys);
    virtual CertReqPtr createCertificateRequestWithDNPosition(X509NameMap &subject,
                                                              KeyPair &keys,
                                                              X509NamePosition &position_list);
    virtual CertReqPrt createCertificateRequestWithDNPositionPrintableSubjectEncoding(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list);
    virtual CertificatePtr createCertificatewithCSR(const RawData &certReq,
                                                    SignatureAlgorithm alg,
                                                    const RawData &serial,
                                                    Issuer *issuer,
                                                    unsigned int validDays);
    virtual CertificatePtr createCertificate(CertReq &certRequest,
                                             SignatureAlgorithm alg,
                                             const RawData &serial,
                                             Issuer *issuer,
                                             unsigned int validDays);
    virtual CertificatePtr getCertificate(CertificateFormat format,
                                          const RawData &certdata,
                                          const char *passwd = NULL);
    virtual CertificatePtr getCertificateWithKey(CertificateFormat format,
                                                 const RawData &certdata,
                                                 KeyPair &keys);
#else
    KeyPair *createAsymKeyPair(AsymKeyAlgorithm alg,
                               AsymKeySize keysize,
                               AsymKeyGenMethod meth = kSoftware) override;
    KeyPair *copyAsymKeyPair(const KeyPair &keyPair) override;
    Issuer *createIssuer(const RawData &issuerCert, KeyPair &issuerKeys) override;
    CertReq *createCertificateRequest(X509NameMap &subject, KeyPair &keys) override;
    CertReq *createCertificateRequestPrintableSubjectEncoding(X509NameMap &subject,
                                                              KeyPair &keys) override;
    CertReq *createCertificateRequestWithDNPosition(X509NameMap &subject,
                                                    KeyPair &keys,
                                                    X509NamePosition &position_list) override;
    CertReq *createCertificateRequestWithDNPositionPrintableSubjectEncoding(
        X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list) override;
    Certificate *createCertificatewithCSR(const RawData &,
                                          SignatureAlgorithm alg,
                                          const RawData &serial,
                                          Issuer *issuer,
                                          unsigned int validDays) override;
    Certificate *createCertificate(CertReq &certRequest,
                                   SignatureAlgorithm alg,
                                   const RawData &serial,
                                   Issuer *issuer,
                                   unsigned int validDays) override;
    Certificate *getCertificate(CertificateFormat format,
                                const RawData &certdata,
                                const char *passwd = nullptr) override;
    Certificate *getCertificateWithKey(CertificateFormat format,
                                       const RawData &certdata,
                                       KeyPair &keys) override;
#endif
    Wrapper &getWrapper(const char *certWrapKey = nullptr) override;
    bool isInitialized() override;

    // ModuleImpl can only be created by ModuleImpl::getModule(). This ensures
    // that no more than one instance of ModuleImpl gets create inadvertently
    // and ModuleImpl remains a singleton
    static Module &getModule(const char *configFile, bool useGemEngine);

private:
    std::string m_certWrapKeyName;
    /* change to  WrapperImpl  when wrapper changes are merged to feature branch */
    std::map<std::string, std::unique_ptr<WrapperImpl>> m_wrappers;
    std::string m_configFile;
    bool m_initialized{false};
    HSMConfig m_hsmConfig;
    // TODO Make m_engine as static
    ENGINE *m_engine{nullptr};
    // Pointer to OpenSSL RSA algorithms in software
    // We override these in openssl later during module initialization
    // when gem-engine is loaded. Hence storing a copy here.
    const RSA_METHOD *m_softRsa{nullptr};
    static ModulePtr m_moduleOpenSSL;
    void initialize(bool useGemEngine);
    bool initializeWrapper();

    bool initializeRandomness();
    bool parseConfig(const char *configFile,
                     std::string &certWrapKeyName,
                     std::string &enginePath,
                     HSMConfig &hsmConfig);
    bool loadGemEngine(const std::string &enginePath);

#ifdef SWIG
    CertReq *exCreateCertificateRequest(X509NameMap &subject,
                                        KeyPair &keys,
                                        X509NamePosition &position_list,
                                        bool ia5_for_email,
                                        bool printable_subject);
#else
    CertReqPtr exCreateCertificateRequest(X509NameMap &subject,
                                          KeyPair &keys,
                                          X509NamePosition &position_list,
                                          bool ia5_for_email,
                                          bool printable_subject);
#endif
};

}  // namespace NSCertLib
