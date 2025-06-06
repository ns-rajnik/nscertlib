#include <openssl/x509v3.h>

#include <sstream>
#include <string>
#include <vector>

#include "CertReqImpl.hpp"
#include "ErrorImpl.hpp"
#include "PEMHeader.hpp"
#include "Utility.hpp"
#include "cpp/Data.hpp"

namespace NSCertLib {

static X509_REQ *
PEM_to_X509_REQ(const unsigned char *pem)
{
    AutoCleaner<X509_REQ> certReq(X509_REQ_new());

    if (pem == nullptr) {
        return nullptr;
    }

    AutoCleaner<BIO> bio(BIO_new_mem_buf(pem, -1));
    if (bio.get() == nullptr) {
        return nullptr;
    }

    if (!PEM_read_bio_X509_REQ(bio.get(), certReq.getStorage(), nullptr, nullptr)) {
        setOpenSSLError("Unable to parse cert req into X509 data struct");
        return nullptr;
    }
    return certReq.release();
}

static bool
X509_REQ_to_PEM(X509_REQ *csr, RawData &subject)
{
    AutoCleaner<BIO> out(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_X509_REQ(out.get(), csr) <= 0) {
        setOpenSSLError("\nUnable to get the subjectName\n");
        return false;
    }
    int subjectLen = BIO_pending(out.get());
    subject.resize(subjectLen + 1);
    if (BIO_read(out.get(), subject.data(), subjectLen) <= 0) {
        setOpenSSLError("Error converting x509 to string");
        return false;
    }
    subject[subjectLen] = '\0';
    return true;
}

CertReqImpl::CertReqImpl()
    : m_ca(false),
      m_serialInAuthKeyId(false),
      m_ia5_for_email(false),
      m_use_printable_encoding_in_subject(false),
      m_extKeyUsageCount(0)
{
}

CertReqImpl::CertReqImpl(const RawData &certReq)
    : m_ca(false),
      m_serialInAuthKeyId(false),
      m_ia5_for_email(false),
      m_use_printable_encoding_in_subject(false),
      m_extKeyUsageCount(0)
{
    // If initialized using csr do not run the finalize() function
    // Parse the vaule of m_serialInAuthKeyId
    const char isSerialInAuthKeyId = certReq.back();
    m_serialInAuthKeyId = isSerialInAuthKeyId == '1';
    m_req.reset(PEM_to_X509_REQ(certReq.data()));
    m_keys.setKeys(X509_REQ_get_pubkey(m_req.get()), nullptr);
}

CertReqImpl::~CertReqImpl() = default;

bool
CertReqImpl::addAlternateName(const char *altName)
{
    if (!m_altNames.empty()) m_altNames += ",";

    m_altNames += "DNS:";
    m_altNames += altName;
    return true;
}

bool
CertReqImpl::setCA(int pathLen)
{
    std::lock_guard<std::mutex> lockHolder(m_lock);
    m_ca = true;
    if (pathLen >= 0) m_path += "critical,CA:TRUE,pathlen:" + std::to_string(pathLen);
    return true;
}

bool
CertReqImpl::addKeyUsage(KeyUsage usage)
{
    std::lock_guard<std::mutex> lockHolder(m_lock);
    if (!m_keyUsage.empty()) m_keyUsage += ",";

    switch (usage) {
    case kDigitalSignature:
        m_keyUsage += "digitalSignature";
        return true;
    case kNonRepudiation:
        m_keyUsage += "nonRepudiation";
        return true;
    case kKeyEncipherment:
        m_keyUsage += "keyEncipherment";
        return true;
    case kDataEncipherment:
        m_keyUsage += "dataEncipherment";
        return true;
    case kKeyAgreement:
        m_keyUsage += "keyAgreement";
        return true;
    case kKeyCertSign:
        m_keyUsage += "keyCertSign";
        return true;
    case kCrlSign:
        m_keyUsage += "cRLSign";
        return true;
    default:
        return false;
    }
}

bool
CertReqImpl::addExtKeyUsage(ExtKeyUsage extUsage)
{
    std::lock_guard<std::mutex> lockHolder(m_lock);
    if (m_extKeyUsageCount >= kMaxExtKeyUsage) {
        setError("Cannot support these many extended key usages. Maximum allowed is %d",
                 kMaxExtKeyUsage);
        return false;
    }
    m_extKeyUsageCount++;
    if (!m_extKeyUsage.empty()) m_extKeyUsage += ",";

    switch (extUsage) {
    case kServerAuth:
        m_extKeyUsage += "serverAuth";
        return true;
    case kClientAuth:
        m_extKeyUsage += "clientAuth";
        return true;
    case kCodeSigning:
        m_extKeyUsage += "codeSigning";
        return true;
    case kEmailProtection:
        m_extKeyUsage += "emailProtection";
        return true;
    case kTimeStamping:
        m_extKeyUsage += "timeStamping";
        return true;
    default:
        return false;
    }
}

// Acceptable values for nsCertType are: client, server, email, objsign, reserved, sslCA,
// emailCA, objCA.
bool
CertReqImpl::addNSCertType(NSCertType type)
{
    std::lock_guard<std::mutex> lockHolder(m_lock);

    if (!m_nsType.empty()) m_nsType += ",";

    switch (type) {
    case kSSLClient:
        m_nsType += "client";
        return true;
    case kSSLServer:
        m_nsType += "server";
        return true;
    case kSMime:
        m_nsType += "email";
        return true;
    case kObjectSigning:
        m_nsType += "objsign";
        return true;
    case kSSLCA:
        m_nsType += "sslCA";
        return true;
    case kSMimeCA:
        m_nsType += "emailCA";
        return true;
    case kObjectSigningCA:
        m_nsType += "objCA";
        return true;
    default:
        return false;
    }
}

bool
CertReqImpl::setSerialInAuthKeyId()
{
    m_serialInAuthKeyId = true;
    return true;
}

bool
CertReqImpl::isSerialInAuthKeyId() const
{
    return m_serialInAuthKeyId;
}

bool
CertReqImpl::setSubject(X509NameMap &subject, bool ia5_for_email)
{
    m_subjectValues = subject;
    m_ia5_for_email = ia5_for_email;
    return true;
}

bool
CertReqImpl::setSubjectEncodingPrintableString()
{
    m_use_printable_encoding_in_subject = true;
    return true;
}

void
CertReqImpl::setPositionList(X509NamePosition &position_list)
{
    m_position_list = position_list;
}

void
CertReqImpl::setKeys(KeyPairImpl &keys)
{
    m_keys.setKeys(keys.getKey(), keys.getEngine());
}

X509_REQ *
CertReqImpl::getx509Req()
{
    return m_req.release();
}

bool
CertReqImpl::getCsr(SignatureAlgorithm alg, RawData &csr)
{
    AutoCleaner<X509_REQ> req(finalize(alg));
    X509_REQ_to_PEM(req.get(), csr);
    // Storing the m_serialInAuthKeyId as part of the csr
    // since it required for the cert creation
    if (isSerialInAuthKeyId()) {
        csr.push_back('1');
    } else {
        csr.push_back('0');
    }
    return true;
}

bool
CertReqImpl::initialize()
{
    assert(m_keys.getKey());
    m_req.reset(X509_REQ_new());
    return m_keys.initialize();
}

/*
 * Build subject
 * Add public key to cert request
 * Apply below extensions:
 * basicConstraints
 * keyusage
 * ext keyusage
 * nscerttype
 * subject key identifier
 * alternative subject
 * Sign certreq with private key
 */
X509_REQ *
CertReqImpl::finalize(SignatureAlgorithm alg)
{
    std::lock_guard<std::mutex> lockHolder(m_lock);
    assert(m_req.get());

    if (m_ca and m_subjectValues.empty()) {
        // see rfc5280 section-4.1.2.6
        setError("Empty subject line not allowed for CA");
        return nullptr;
    }

    // note: non CA certificates may have empty subject lines, however
    // the subject alt name must be set to critical, certificates exist
    // at netskope in various states of compliance with the RFC therefore
    // strict compliance may not be possible with certificate rotation
    // at this time

    NSCertLib::X509Name_UniquePtr name{nullptr};

    int subject_encoding = V_ASN1_UTF8STRING;

    if (m_use_printable_encoding_in_subject) {
        subject_encoding = V_ASN1_PRINTABLESTRING;
    }

    if (m_position_list.empty()) {
        name = parseNameFromPair(m_subjectValues, subject_encoding, m_ia5_for_email);
    } else {
        if (m_subjectValues.size() != m_position_list.size()) {
            NSCertLib::setError(
                "position list size must be equal to number of subject values list: %zu "
                "subject: %zu",
                m_position_list.size(),
                m_subjectValues.size());
            return nullptr;
        }
        auto lookup = [this](int position) -> const std::string & {
            return this->m_position_list.at(position);
        };

        name = parseNameFromPair(m_subjectValues,
                                 subject_encoding,
                                 m_ia5_for_email,
                                 lookup,
                                 m_position_list.size());
    }

    if (!name.get()) {
        return nullptr;
    }

    if (!X509_REQ_set_subject_name(m_req.get(), name.get())) {
        NSCertLib::setOpenSSLError("Unable to set the subject name in certificate request");
        return nullptr;
    }

    if (!X509_REQ_set_version(m_req.get(), 2)) {
        NSCertLib::setOpenSSLError("Unable to set the version in certificate request");
        return nullptr;
    }

    if (!X509_REQ_set_pubkey(m_req.get(), m_keys.getKey())) {
        NSCertLib::setOpenSSLError("Unable to set the public key in certificate request");
        return nullptr;
    }

    AutoCleaner<STACK_OF(X509_EXTENSION)> exts(sk_X509_EXTENSION_new_null());

    // Basic Constraints extension
    if (!m_path.empty()) {
        if (m_ca &&
            !addExtensions(
                exts.get(), NID_basic_constraints, const_cast<char *>(m_path.c_str()))) {
            return nullptr;
        }
    } else if (m_ca && !addExtensions(exts.get(),
                                      NID_basic_constraints,
                                      const_cast<char *>("critical,CA:TRUE"))) {
        return nullptr;
    }

    // Subject Alternative Name
    if (!m_altNames.empty() &&
        !addExtensions(
            exts.get(), NID_subject_alt_name, const_cast<char *>(m_altNames.c_str()))) {
        return nullptr;
    }

    // Key Usage
    if (!m_keyUsage.empty() &&
        !addExtensions(exts.get(), NID_key_usage, const_cast<char *>(m_keyUsage.c_str()))) {
        return nullptr;
    }

    //  Extended Key Usage
    if (!m_extKeyUsage.empty() &&
        !addExtensions(
            exts.get(), NID_ext_key_usage, const_cast<char *>(m_extKeyUsage.c_str()))) {
        return nullptr;
    }

    //  Netscape Cert Type
    if (!m_nsType.empty() &&
        !addExtensions(
            exts.get(), NID_netscape_cert_type, const_cast<char *>(m_nsType.c_str()))) {
        return nullptr;
    }

    // Subject Key Identifier
    if (!addExtensions(exts.get(), NID_subject_key_identifier, const_cast<char *>("hash"))) {
        return nullptr;
    }

    if (!X509_REQ_add_extensions(m_req.get(), exts.get())) {
        NSCertLib::setOpenSSLError("Unable to add extensions in  certificate request");
        return nullptr;
    }

    const EVP_MD *hashingAlg = nullptr;
    switch (alg) {
    case kSHA1:
        hashingAlg = EVP_sha1();
        break;
    case kSHA256:
        hashingAlg = EVP_sha256();
        break;
    case kSHA512:
        hashingAlg = EVP_sha512();
        break;
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        NSCertLib::setOpenSSLError("EVP MD CTX new failed");
        return nullptr;
    }
    if (!EVP_DigestSignInit(mdCtx, nullptr, hashingAlg, m_keys.getEngine(), m_keys.getKey())) {
        if (m_keys.getEngine()) {
            NSCertLib::setOpenSSLError("EVP MD CTX new init with engine failed");
        } else {
            NSCertLib::setOpenSSLError("EVP MD CTX new init failed");
        }
        EVP_MD_CTX_free(mdCtx);
        return nullptr;
    }
    if (X509_REQ_sign_ctx(m_req.get(), mdCtx) <= 0) {
        if (m_keys.getEngine()) {
            NSCertLib::setOpenSSLError("X509 sign with engine failed");
        } else {
            NSCertLib::setOpenSSLError("X509 sign failed");
        }
        EVP_MD_CTX_free(mdCtx);
        return nullptr;
    }
    EVP_MD_CTX_free(mdCtx);

    return m_req.release();
}

KeyPairImpl &
CertReqImpl::getKeys()
{
    return m_keys;
}

bool
CertReqImpl::addExtensions(STACK_OF(X509_EXTENSION) * stack, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, m_req.get(), nullptr, 0);
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);

    if (ex == nullptr) {
        NSCertLib::setOpenSSLError("Unable to set nid: %d, value:  \"/%d=%s\"\n", nid, value);
        return false;
    }
    sk_X509_EXTENSION_push(stack, ex);
    return true;
}
}  // namespace NSCertLib
