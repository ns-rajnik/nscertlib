#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <iterator>
#include <iostream>
#include <vector>
#include <iomanip>

#include "CertificateImpl.hpp"
#include "ErrorImpl.hpp"
#include "IssuerImpl.hpp"
#include "PEMHeader.hpp"
#include "Utility.hpp"

namespace NSCertLib {

void
IssuerImpl::set(IssuerImpl &issuer)
{
    m_issuerCert.reset(X509_dup(issuer.m_issuerCert.get()));
    if (!m_issuerCert.get()) {
        NSCertLib::setOpenSSLError("Unable to copy issuer");
        return;
    }

    m_issuerKeys.setKeys(issuer.m_issuerKeys.getKey(), issuer.m_issuerKeys.getEngine());
}

bool
IssuerImpl::initialize(const RawData &issuerCert, KeyPairImpl &issuerKeys)
{
    AutoCleaner<BIO> evpBio(BIO_new_mem_buf((void *)&issuerCert[0], issuerCert.size()));
    if (!evpBio.get()) {
        setOpenSSLError("Unable to get BIO for certificate");
        return false;
    }

    m_issuerCert.reset(PEM_read_bio_X509(evpBio.get(), nullptr, nullptr, nullptr));
    if (!m_issuerCert.get()) {
        setOpenSSLError("Unable to load certificate");
        return false;
    }

    m_issuerKeys.setKeys(issuerKeys.getKey(), issuerKeys.getEngine());
    return true;
}

bool
IssuerImpl::initialize(X509 *issuerCert, KeyPairImpl &issuerKeys)
{
    m_issuerCert.reset(X509_new());
    if (!m_issuerCert.get()) {
        NSCertLib::setOpenSSLError("Unable to initialize issuer");
        return false;
    }

    if (!copySubject(issuerCert) || !copySerial(issuerCert) || !copyExtensions(issuerCert)) {
        return false;
    }

    m_issuerKeys.setKeys(issuerKeys.getKey(), issuerKeys.getEngine());
    return true;
}

X509_NAME *
IssuerImpl::getSubject()
{
    if (!m_issuerCert.get()) {
        return nullptr;
    }
    return X509_get_subject_name(m_issuerCert.get());
}

bool
IssuerImpl::copySubject(X509 *issuerCert)
{
    // The returned value is an internal pointer which MUST NOT be freed.
    X509_NAME *subj = X509_get_subject_name(issuerCert);
    if (nullptr == subj) {
        NSCertLib::setOpenSSLError("Unable get subject name");
        return false;
    }

    if (!X509_set_subject_name(m_issuerCert.get(), subj)) {
        NSCertLib::setOpenSSLError("Unable set subject name");
        return false;
    }

    return true;
}

bool
IssuerImpl::copySerial(X509 *issuerCert)
{
    // The value returned is an internal pointer which MUST NOT be freed up after the call.
    ASN1_INTEGER *serial = X509_get_serialNumber(issuerCert);
    if (nullptr == serial) {
        NSCertLib::setOpenSSLError("Unable get serial name");
        return false;
    }
    if (!X509_set_serialNumber(m_issuerCert.get(), serial)) {
        NSCertLib::setOpenSSLError("Unable set serial name");
        return false;
    }

    return true;
}

bool
IssuerImpl::copyExtensions(X509 *issuerCert)
{
    STACK_OF(X509_EXTENSION) const *extList = nullptr;
    extList = X509_get0_extensions(issuerCert);

    if (sk_X509_EXTENSION_num(extList) > 0) {
        for (int i = 0; i < sk_X509_EXTENSION_num(extList); i++) {
            X509_EXTENSION *ext = nullptr;
            ext = sk_X509_EXTENSION_value(extList, i);
            if (!X509_add_ext(m_issuerCert.get(), ext, -1)) {
                NSCertLib::setOpenSSLError("Unable to add extensions to issuer's certificate");
                return false;
            }
        }
    }
    return true;
}

/*
    Set Authority Key Identifier(NID_authority_key_identifier) extension:
        if serial is present then set keyid, serial and subject
            Eg:
            X509v3 Authority Key Identifier:
                    keyid:6D:82:EE:DD:60:46:DF:14:FC:D0:00:8A:FC:96:55:24:FC:7D:05:0E
                    DirName:/CN=RootCA
                    serial:01
        if serial is not present then set only keyid
            Eg:
            X509v3 Authority Key Identifier:
                    keyid:6D:82:EE:DD:60:46:DF:14:FC:D0:00:8A:FC:96:55:24:FC:7D:05:0E
*/
bool
IssuerImpl::setAuthKeyId(X509 *cert, bool serialInAuthKeyId)
{
    if (!m_issuerCert.get()) {
        return false;
    }

    // Get Subject Key Identifier from issuer
    int idx = X509_get_ext_by_NID(m_issuerCert.get(), NID_subject_key_identifier, -1);
    X509_EXTENSION *issuerExt = X509_get_ext(m_issuerCert.get(), idx);
    if (!issuerExt) {
        NSCertLib::setOpenSSLError("Unable to get Issuer's subject key ID");
        return false;
    }

    AutoCleaner<X509_EXTENSION> certExt;
    X509V3_CTX ctx;
    // This sets the 'context' of the extensions
    // No configuration database
    X509V3_set_ctx_nodb(&ctx);
    // Issuer and subject certs
    X509V3_set_ctx(&ctx, m_issuerCert.get(), cert, nullptr, nullptr, 0);
    if (!serialInAuthKeyId) {
        certExt.reset(
            X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always"));
    } else {
        certExt.reset(X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_authority_key_identifier, "keyid:always,issuer:always"));
    }
    if (!certExt.get()) {
        NSCertLib::setOpenSSLError("Unable to set issuer detials for auth key ID");
        return false;
    }

    if (!X509_add_ext(cert, certExt.get(), -1)) {
        NSCertLib::setOpenSSLError("Unable to set auth key ID extension");
        return false;
    }

    return true;
}

bool
IssuerImpl::signCertificate(X509 *cert, SignatureAlgorithm alg)
{
    if (!ENGINE_set_default_RSA(g_engine)) {
        setOpenSSLError("Unable to set gemengine as default for RSA operations");
        return false;
    }
    tssgh();
    //return false;
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

    EVP_PKEY * privateKey = ENGINE_load_private_key(g_engine, "/opt/ns/cfg/priv.pem", nullptr, nullptr);
    int res = X509_sign(cert, privateKey, hashingAlg) ;

    if (res != 0 ) {
	NSCertLib::setOpenSSLError("X509_sign failes");
    }


   /* EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        NSCertLib::setOpenSSLError("EVP MD CTX new failed");
        return false;
    }
    if (!EVP_DigestSignInit(
            mdCtx, nullptr, hashingAlg, g_engine, m_issuerKeys.getKey())) {
        if (m_issuerKeys.getEngine()) {
            NSCertLib::setOpenSSLError("EVP MD CTX new init with engine failed");
        } else {
            NSCertLib::setOpenSSLError("EVP MD CTX new init failed");
        }
        EVP_MD_CTX_free(mdCtx);
        return false;
    }
    if (X509_sign_ctx(cert, mdCtx) <= 0) {
        if (m_issuerKeys.getEngine()) {
            NSCertLib::setOpenSSLError("X509 sign with engine failed");
        } else {
            NSCertLib::setOpenSSLError("X509 sign failed");
        }
        EVP_MD_CTX_free(mdCtx);
        return false;
    }
    EVP_MD_CTX_free(mdCtx);*/
    return true;
}

int
IssuerImpl::tssgh() {

    /*if (!ENGINE_set_default(g_engine,ENGINE_METHOD_ALL)) {
        setOpenSSLError("Unable to set gemengine as default for RSA operations");
        return 1;
    }*/


    EVP_PKEY * privateKey = ENGINE_load_private_key(g_engine, "/opt/ns/cfg/priv.pem", nullptr, nullptr);
     printf("%p\n", privateKey);
     fflush(stdout);

    // 2. Data to Sign
    std::vector<unsigned char> dataToSign = {
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!'
    };

    std::cout<<"fndkbfkdfkdskcfkdcfkdskcfdknknskncfkdsbvcsdkvksdksnd"<<std::endl;

     printf("%p\n", g_engine);
     fflush(stdout);

    // 3. Initialize EVP_PKEY_CTX
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, g_engine);
    if (!ctx) {
        NSCertLib::setOpenSSLError("EVP_PKEY_CTX_new");
        std::cerr << "Error creating EVP_PKEY_CTX." << std::endl;
        EVP_PKEY_free(privateKey);
        return 1;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        NSCertLib::setOpenSSLError("EVP_PKEY_sign_init");
        std::cerr << "Error initializing EVP_PKEY_sign." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        //EVP_PKEY_free(privateKey);
        return 1;
    }

    // Set the padding mode (e.g., RSA_PKCS1_PADDING)
    /*if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
         NSCertLib::setOpenSSLError("EVP_PKEY_CTX_set_rsa_padding");
        std::cerr << "Error setting padding mode." << std::endl;
        EVP_PKEY_CTX_free(ctx);
       // EVP_PKEY_free(privateKey);
        return 1;
    }*/

    // 4. Determine Signature Length
    size_t siglen;
    if (EVP_PKEY_sign(ctx, nullptr, &siglen, dataToSign.data(), dataToSign.size()) <= 0) {
         NSCertLib::setOpenSSLError("EVP_PKEY_sign");
      std::cerr << "Error determining signature length." << std::endl;
        EVP_PKEY_CTX_free(ctx);
       // EVPumb_PKEY_free(privateKey);
      return 1;
    }

    // 5. Allocate Memory for Signature
    std::vector<unsigned char> signature(siglen);

    // 6. Sign Data
    if (EVP_PKEY_sign(ctx, signature.data(), &siglen, dataToSign.data(), dataToSign.size()) <= 0) {
         NSCertLib::setOpenSSLError("EVP_PKEY_sign1");
        std::cerr << "Error signing data." << std::endl;
        EVP_PKEY_CTX_free(ctx);
       // EVP_PKEY_free(privateKey);
        return 1;
    }
      NSCertLib::setOpenSSLError("EVP_PKEY_sign success");
    signature.resize(siglen);

    // 7. Output Signature
    std::cout << "Signature: ";
    for (unsigned char byte : signature) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::endl;

    // Cleanup
    EVP_PKEY_CTX_free(ctx);
   // EVP_PKEY_free(privateKey);
  


    FILE* fp = fopen("/opt/ns/cfg/pub.pem", "r");
    if (!fp) {
        std::cerr << "Error opening file: " <<  std::endl;
        return 1;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);



   // 3. Initialize EVP_PKEY_CTX
    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!vctx) {
        NSCertLib::setOpenSSLError("EVP_PKEY_CTX_new");
        std::cerr << "Error creating EVP_PKEY_CTX." << std::endl;
       // EVP_PKEY_free(privateKey);
        return 1;
    }

     if (EVP_PKEY_verify_init(vctx) <= 0) {
        std::cerr << "Error initializing verify" << std::endl;
        //EVP_PKEY_CTX_free(ctx);
        return 1;
    }

      /*if (EVP_PKEY_CTX_set_rsa_padding(vctx, RSA_PKCS1_PADDING) <= 0) {
        std::cerr << "Error setting padding" << std::endl;
       // EVP_PKEY_CTX_free(ctx);
        return 1;
    }*/


    int result = EVP_PKEY_verify(vctx, signature.data(), siglen, dataToSign.data(), dataToSign.size());
    EVP_PKEY_CTX_free(vctx);

    if (result == 1) {
        return true; // Verification successful
    } else if (result == 0) {
         NSCertLib::setOpenSSLError("verification failed");
        std::cerr << "1   Verification failed" << std::endl;
        return false; // Verification failed
    } else {
         NSCertLib::setOpenSSLError("1 verification failed");
        std::cerr << "Error during verification" << std::endl;
        return false; // Error during verification
    }

    return 0;
}

}  // namespace NSCertLib
