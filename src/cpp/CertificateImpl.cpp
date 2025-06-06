#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <functional>

#include "CertificateImpl.hpp"
#include "ErrorImpl.hpp"
#include "Utility.hpp"

namespace NSCertLib {

// Constructor without timeslot
CertificateImpl::CertificateImpl(CertDataType type) : m_type(type) {}

CertificateImpl &
CertificateImpl::setCertData(CertificateFormat format,
                             const RawData &certdata,
                             const char *passwd)
{
    assert(kCertContentType == m_type);
    m_certContent.format = format;
    m_certContent.content = certdata;
    if (passwd) {
        if (!m_certContent.password.empty()) {
            m_certContent.password.clear();
        }
        m_certContent.password = passwd;
    }
    return *this;
}

CertificateImpl &
CertificateImpl::setCertData(CertificateFormat format,
                             const RawData &certdata,
                             KeyPairImpl &keys)
{
    assert(kCertContentType == m_type);
    m_certContent.format = format;
    m_certContent.content = certdata;
    m_certContent.gotKeys = true;
    m_keys.setKeys(keys.getKey(), keys.getEngine());
    return *this;
}

CertificateImpl &
CertificateImpl::setCertRequest(X509_REQ *certReq)
{
    assert(kCertReqType == m_type);
    m_certReq.certReq.reset(certReq);
    return *this;
}

CertificateImpl &
CertificateImpl::setKeys(KeyPairImpl &keys)
{
    assert(kCertReqType == m_type);
    m_keys.setKeys(keys.getKey(), keys.getEngine());
    return *this;
}

CertificateImpl &
CertificateImpl::setIssuer(IssuerImpl &issuer)
{
    assert(kCertReqType == m_type);
    assert(issuer.getSubject() != nullptr);
    m_certReq.issuer.set(issuer);
    return *this;
}

CertificateImpl &
CertificateImpl::setSerial(const RawData &serial)
{
    assert(kCertReqType == m_type);
    m_certReq.serial = serial;
    return *this;
}

CertificateImpl &
CertificateImpl::setSignatureAlgorithm(SignatureAlgorithm alg)
{
    assert(kCertReqType == m_type);
    m_certReq.alg = alg;
    return *this;
}

CertificateImpl &
CertificateImpl::setValidity(unsigned int validDays)
{
    assert(kCertReqType == m_type);
    m_certReq.validDays = validDays;
    return *this;
}

CertificateImpl &
CertificateImpl::setSerialInAuthKeyId()
{
    m_certReq.serialInAuthKeyId = true;
    return *this;
}

bool
CertificateImpl::initialize()
{
    if (kCertReqType == m_type) {
        assert(m_keys.getKey());
        assert(m_certReq.certReq.get());
        return initializeFromCertReq();
    }
    assert(!m_certContent.content.empty());
    switch (m_certContent.format) {
    case kPKCS12:
        return initializeFromPKCS12();
    case kPEM:
        return initializeFromPEM();
    }
    assert(false);
    return false;
}

bool
CertificateImpl::getCertificate(CertificateFormat format,
                                RawData &certificate,
                                const char *passwd)
{
    if (!m_certificate.get()) {
        setError("Certificate not initialized");
        return false;
    }
    switch (format) {
    case kPKCS12:
        return generatePKCS12(certificate, passwd);
    case kPEM:
        return generatePEM(certificate, passwd);
    }
    assert(false);
    return false;
}

bool
CertificateImpl::getSubjectName(RawData &subject)
{
    return getNameFromX509(m_certificate.get(), subject, X509_get_subject_name);
}

bool
CertificateImpl::getSerial(RawData &serial)
{
    if (!m_certificate.get()) {
        setOpenSSLError("Unable to get serial number [no certificate]");
        return false;
    }
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(m_certificate.get());
    if (not serialNumber) {
        setOpenSSLError("Unable to get serial number [extract failed]");
        return false;
    }
    serial.insert(
        serial.begin(), serialNumber->data, serialNumber->data + serialNumber->length);
    return true;
}

bool
CertificateImpl::getIssuerName(RawData &issuer)
{
    return getNameFromX509(m_certificate.get(), issuer, X509_get_issuer_name);
}

bool
CertificateImpl::getSubjectKeyId(RawData &subjectKeyId)
{
    if (!m_certificate.get()) {
        return false;
    }
    // Returns an internal pointer to the subject key identifier.
    const ASN1_OCTET_STRING *keyId = X509_get0_subject_key_id(m_certificate.get());
    if (keyId == nullptr) {
        setOpenSSLError("Unable to get subject key ID");
        return false;
    }
    /* Returns an internal pointer to the data of KeyId.
     Since this is an internal pointer it should not be freed or modified in any way */
    const unsigned char *data = ASN1_STRING_get0_data(keyId);
    if (data == nullptr) {
        setOpenSSLError("Unable to convert ASN1_OCTET_STRING key ID");
        return false;
    }
    int length = ASN1_STRING_length(keyId);
    subjectKeyId.insert(subjectKeyId.begin(), data, data + length);
    return true;
}

unsigned int
CertificateImpl::getValidityStart()
{
    // Internal pointer returned. Do not free!
    const ASN1_TIME *asn_tm = X509_get_notBefore(m_certificate.get());
    if (asn_tm == nullptr) {
        setOpenSSLError("Unable to get the not before date for the cert");
        return 0;
    }
    tm validityStart{};
    ASN1_TIME_to_tm(asn_tm, &validityStart);
    time_t startTime = mktime(&validityStart);
    return startTime != -1 ? startTime : 0;
}

unsigned int
CertificateImpl::getValidityEnd()
{
    // Internal pointer returned. Do not free!
    const ASN1_TIME *asn_tm = X509_get_notAfter(m_certificate.get());
    if (asn_tm == nullptr) {
        setOpenSSLError("Unable to get the not before date for the cert");
        return 0;
    }
    tm validityEnd{};
    ASN1_TIME_to_tm(asn_tm, &validityEnd);
    time_t endTime = mktime(&validityEnd);
    return endTime != -1 ? endTime : 0;
}

bool
CertificateImpl::isCA()
{
    X509 *cert = m_certificate.get();
    if (!cert) {
        return false;
    }
    // Look into basic constraints to figure out if this guy is a CA
    // Todo: SHould this be freed??
    auto basicConstraint =
        (BASIC_CONSTRAINTS *)X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr);
    if (basicConstraint == nullptr) {
        return false;
    }
    return basicConstraint->ca != 0;
}

bool
CertificateImpl::resign(Issuer *issuer, const RawData &serial, SignatureAlgorithm alg)
{
    IssuerImplPtr selfIssuser;
    auto realIssuerPtr = static_cast<IssuerImpl *>(issuer);
    if (!realIssuerPtr) {
        selfIssuser = std::make_unique<IssuerImpl>();
        if (!selfIssuser->initialize(m_certificate.get(), m_keys)) {
            setOpenSSLError("Unable to resign self signed certificate");
            return false;
        }
        realIssuerPtr = selfIssuser.get();
    }
    IssuerImpl &realIssuer = *realIssuerPtr;
    AutoCleaner<BIGNUM> bn(BN_bin2bn(serial.data(), serial.size(), nullptr));
    if (bn.get() == nullptr) {
        setOpenSSLError("Unable to convert to BIGNUM");
        return false;
    }
    AutoCleaner<ASN1_INTEGER> asnInt(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if (asnInt.get() == nullptr) {
        setOpenSSLError("Unable to get ASN1_INTEGER from BIGNUM");
        return false;
    }
    if (!X509_set_serialNumber(m_certificate.get(), asnInt.get())) {
        setOpenSSLError("Unable to set the serial number");
        return false;
    }
    X509_NAME *issuerName = realIssuer.getSubject();
    if (!issuerName) return false;
    if (!X509_set_issuer_name(m_certificate.get(), issuerName)) {
        setOpenSSLError("Unable to set the issuer_name");
        return false;
    }
    // Clear up the authkey identifier extension & set it to the
    // ID of the new issuer
    int indexAuthKeyID =
        X509_get_ext_by_NID(m_certificate.get(), NID_authority_key_identifier, -1);
    if (X509_get_ext(m_certificate.get(), indexAuthKeyID)) {
        AutoCleaner<X509_EXTENSION> tmp(X509_delete_ext(m_certificate.get(), indexAuthKeyID));
    }
    bool serialInAuthKeyId = !serial.empty();
    if (!realIssuer.setAuthKeyId(m_certificate.get(), serialInAuthKeyId)) {
        setOpenSSLError("Unable to set the  Auth key id");
        return false;
    }

    return realIssuer.signCertificate(m_certificate.get(), alg);
}

KeyPair &
CertificateImpl::getKeys()
{
    return m_keys;
}

bool
CertificateImpl::initializeFromPKCS12()
{
    AutoCleaner<EVP_PKEY> pkey;
    AutoCleaner<BIO> p12Bio(
        BIO_new_mem_buf(m_certContent.content.data(), m_certContent.content.size()));
    if (not p12Bio.get()) {
        setOpenSSLError("Unable to read the pkcs12 cert content");
        return false;
    }
    AutoCleaner<PKCS12> p12Cert(d2i_PKCS12_bio(p12Bio.get(), nullptr));
    if (not p12Cert.get()) {
        return false;
    }
    X509 *certificate{nullptr};
    AutoCleaner<EVP_PKEY> pKeys;

    if (not PKCS12_parse(p12Cert.get(),
                         m_certContent.password.c_str(),
                         pKeys.getStorage(),
                         &certificate,
                         nullptr)) {
        setOpenSSLError("Unable to parse the pkcs12 archive");
        return false;
    }

    m_certificate.reset(certificate);
    if (not m_certificate.get()) {
        setOpenSSLError("Certificate not present in pkcs12 archive");
        return false;
    }
    m_keys.setKeys(pKeys.get(), nullptr);
    return m_keys.initialize();
}

bool
CertificateImpl::initializeFromPEM()
{
    AutoCleaner<BIO> evpBio(
        BIO_new_mem_buf((void *)m_certContent.content.data(), m_certContent.content.size()));
    if (!evpBio.get()) {
        setOpenSSLError("Unable to allocate the buffer to read cert content");
    }
    RawData pemCert;
    X509 *x509Cert = PEM_read_bio_X509(evpBio.get(), nullptr, nullptr, nullptr);
    if (x509Cert == nullptr) {
        setOpenSSLError("Unable to open certificate");
        return false;
    }
    m_certificate.reset(x509Cert);
    if (!m_certificate.get()) {
        setOpenSSLError("Unable to decode given PEM certificate");
        return false;
    }
    // Optional. Read private key if provided
    AutoCleaner<EVP_PKEY> pkeys;
    PEM_read_bio_PrivateKey(evpBio.get(), pkeys.getStorage(), nullptr, nullptr);
    if (pkeys.get() != nullptr) {
        m_keys.setKeys(pkeys.get(), nullptr);
    }
    return true;
}

bool
CertificateImpl::initializeFromCertReq()
{
    if (!m_keys.initialize()) {
        return false;
    }
    m_certificate.reset(X509_new());
    if (!m_certificate.get()) {
        setOpenSSLError("Unable to create new X509 object");
        return false;
    }
    // TODO: Not sure if we really need this. We are using CSR that nscertlib
    // has generated so may be this step is unnecessary.
    if (!X509_REQ_verify(m_certReq.certReq.get(), m_keys.getKey())) {
        setOpenSSLError("Invalid certificate request");
        return false;
    }
    AutoCleaner<BIGNUM> bn(
        BN_bin2bn(m_certReq.serial.data(), m_certReq.serial.size(), nullptr));
    if (bn.get() == nullptr) {
        setOpenSSLError("Unable to convert to BIGNUM");
        return false;
    }
    AutoCleaner<ASN1_INTEGER> asnInt(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if (asnInt.get() == nullptr) {
        setOpenSSLError("Unable to get ASN1_INTEGER from BIGNUM");
        return false;
    }
    if (!X509_set_serialNumber(m_certificate.get(), asnInt.get())) {
        setOpenSSLError("Unable to set the serial number");
        return false;
    }
    if (!X509_gmtime_adj(X509_get_notBefore(m_certificate.get()), 0)) {
        setOpenSSLError("Unable to set the start date");
        return false;
    }
    if (!X509_gmtime_adj(
            X509_get_notAfter(m_certificate.get()),
            static_cast<long>(60 * 60 * 24 * static_cast<long>(m_certReq.validDays)))) {
        setOpenSSLError("Unable to set the end date");
        return false;
    }

    X509_NAME *name = X509_REQ_get_subject_name(m_certReq.certReq.get());
    if (!name) {
        setOpenSSLError("Unable to get the subject name from the certReq");
        return false;
    }
    if (!X509_set_subject_name(m_certificate.get(), name)) {
        setOpenSSLError("Unable to set the subject of the certReq to cert");
        return false;
    }
    if (!X509_set_pubkey(m_certificate.get(), m_keys.getKey())) {
        setOpenSSLError("Unable to set the public key");
        return false;
    }
    if (!copyExtensions()) {
        return false;
    }
    if (!X509_set_version(m_certificate.get(), 2)) {
        setOpenSSLError("Unable to set the version");
        return false;
    }

    X509_NAME *issuerName = m_certReq.issuer.getSubject();
    if (!issuerName) {
        // Self signed certificate
        issuerName = name;
        if (!m_certReq.issuer.initialize(m_certificate.get(), m_keys)) {
            return false;
        }
    }
    if (!X509_set_issuer_name(m_certificate.get(), issuerName)) {
        setOpenSSLError("Unable to set the issuer_name");
        return false;
    }
    if (!m_certReq.issuer.setAuthKeyId(m_certificate.get(), m_certReq.serialInAuthKeyId)) {
        setOpenSSLError("Unable to set the  Auth key id");
        return false;
    }
    return signCertificate();
}

bool
CertificateImpl::copyExtensions()
{
    AutoCleaner<STACK_OF(X509_EXTENSION)> extensions(
        X509_REQ_get_extensions(m_certReq.certReq.get()));
    if (sk_X509_EXTENSION_num(extensions.get()) > 0) {
        for (int i = 0; i < sk_X509_EXTENSION_num(extensions.get()); i++) {
            X509_EXTENSION *extension = sk_X509_EXTENSION_value(extensions.get(), i);
            if (!X509_add_ext(m_certificate.get(), extension, -1)) {
                setOpenSSLError("Unable to add the extension");
                return false;
            }
        }
    }
    return true;
}

bool
CertificateImpl::signCertificate()
{
    return m_certReq.issuer.signCertificate(m_certificate.get(), m_certReq.alg);
}

// Retaining the same function as CertificateImpl
bool
CertificateImpl::generatePKCS12(RawData &certificate, const char *passwd)
{
    if (!passwd) {
        setError("Cannot generate PKCS12 without password");
        return false;
    }
    RawData pemKey;
    if (!m_keys.getPrivateKeyInfo(pemKey, nullptr)) {
        // Error already set
        return false;
    }
    AutoCleaner<BIO> evpBio(BIO_new_mem_buf((void *)&pemKey[0], pemKey.size()));
    if (!evpBio.get()) {
        setOpenSSLError("Unable to get BIO for private key");
        return false;
    }
    AutoCleaner<EVP_PKEY> pkey(
        PEM_read_bio_PrivateKey(evpBio.get(), nullptr, nullptr, nullptr));
    if (!pkey.get()) {
        setOpenSSLError("Unable to open private key");
        return false;
    }
    RawData pemCert;
    if (!generatePEM(pemCert, nullptr)) {
        // Error already set
        return false;
    }
    AutoCleaner<BIO> x509Bio(BIO_new_mem_buf((void *)&pemCert[0], pemCert.size()));
    if (!x509Bio.get()) {
        setOpenSSLError("Unable to create BIO for certificate");
        return false;
    }
    AutoCleaner<X509> x509Cert(PEM_read_bio_X509(x509Bio.get(), nullptr, nullptr, nullptr));
    if (!x509Cert.get()) {
        setOpenSSLError("Unable to open certificate");
        return false;
    }

    int nid = is_fips_mode() ? NID_pbe_WithSHA1And3_Key_TripleDES_CBC : 0;

    AutoCleaner<PKCS12> pkcs12(PKCS12_create(const_cast<char *>(passwd),
                                             const_cast<char *>("user"),
                                             pkey.get(),
                                             x509Cert.get(),
                                             nullptr,
                                             nid,
                                             nid,
                                             0,
                                             0,
                                             0));
    if (!pkcs12.get()) {
        setOpenSSLError("Unable to convert to PKCS12");
        return false;
    }
    AutoCleaner<BIO> pbio(BIO_new(BIO_s_mem()));
    if (!pbio.get()) {
        setOpenSSLError("Unable to create BIO for PKCS12");
        return false;
    }
    int bytes = i2d_PKCS12_bio(pbio.get(), pkcs12.get());
    if (bytes <= 0) {
        setOpenSSLError("Unable to encode PKCS12");
        return false;
    }
    BUF_MEM *bptr{nullptr};
    BIO_get_mem_ptr(pbio.get(), &bptr);
    certificate.assign(bptr->data, bptr->data + bptr->length);
    return true;
}

bool
CertificateImpl::generatePEM(RawData &certificate, const char * /*passwd*/)
{
    AutoCleaner<BIO> bioPem(BIO_new(BIO_s_mem()));
    if (!bioPem.get()) {
        setOpenSSLError("Unable to get the new bio");
        return false;
    }
    if (!PEM_write_bio_X509(bioPem.get(), m_certificate.get())) {
        setOpenSSLError("Unable to write cert in pem format");
        return false;
    }

    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(bioPem.get(), &mem);
    if (!mem || !mem->data || !mem->length) {
        setOpenSSLError("BIO_get_mem_ptr failed, error ");
        return false;
    }
    certificate.insert(certificate.begin(), mem->data, mem->data + mem->length);
    return true;
}

}  // namespace NSCertLib
