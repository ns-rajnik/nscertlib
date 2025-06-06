#ifndef __NSCERTLIB_CERTREQ_IMPL_H__
#define __NSCERTLIB_CERTREQ_IMPL_H__

#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "AutoCleaner.hpp"
#include "KeysImpl.hpp"
#include "cpp/CertReq.hpp"
#include "cpp/Data.hpp"

// Note on thread-safety:
// This class uses a single lock m_certReqLock to make all the public calls thread-safe.

namespace NSCertLib {

class CertReqImpl : public CertReq {
public:
    CertReqImpl();
    explicit CertReqImpl(const RawData &certReq);
    ~CertReqImpl() override;
    bool setSubject(X509NameMap &subject, bool ia5_for_email);
    bool setSubjectEncodingPrintableString();
    void setKeys(KeyPairImpl &keys);
    bool initialize();
    bool addAlternateName(const char *altName) override;
    bool setCA(int pathLen = -1) override;
    bool addKeyUsage(KeyUsage usage) override;
    bool addExtKeyUsage(ExtKeyUsage extUsage) override;
    bool addNSCertType(NSCertType type) override;
    bool setSerialInAuthKeyId() override;
    bool isSerialInAuthKeyId() const;
    void setPositionList(X509NamePosition &position_list);
    X509_REQ *finalize(SignatureAlgorithm alg);
    X509_REQ *getx509Req();
    KeyPairImpl &getKeys();
    bool getCsr(SignatureAlgorithm alg, RawData &csr) override;
    CertReqImpl(const CertReqImpl &other) = delete;
    void operator=(const CertReqImpl &other) = delete;

private:
    std::string m_keyUsage;
    std::string m_extKeyUsage;
    std::string m_nsType;
    std::string m_altNames;
    std::string m_path;
    X509NamePosition m_position_list;

    bool m_ca;
    bool m_serialInAuthKeyId;
    int m_ia5_for_email;
    int m_use_printable_encoding_in_subject;
    KeyPairImpl m_keys;
    int m_extKeyUsageCount;
    X509NameMap m_subjectValues;
    // RW lock for all the public facing methods
    std::mutex m_lock;
    AutoCleaner<X509_REQ> m_req;

    bool addExtensions(STACK_OF(X509_EXTENSION) * stack, int nid, char *value);
};

using CertReqImplPtr = std::unique_ptr<CertReqImpl>;

} // namespace NSCertLib;
#endif  //__NSCERTLIB_CERTREQ_IMPL_H__
