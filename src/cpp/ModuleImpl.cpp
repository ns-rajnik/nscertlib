// Added OPENSSL_SUPPRESS_DEPRECATED as part of OpenSSL 3.3 migration. This is added in this
// file to continue using deprecated ENGINE APIs for gem HSM.
#define OPENSSL_SUPPRESS_DEPRECATED

#include <assert.h>
#include <errno.h>
#include <json/json.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <streambuf>
#include <string>

#include "ErrorImpl.hpp"
#include "ModuleImpl.hpp"
#include "NAEToken.hpp"
#include "TestPatch.hpp"
#include "Utility.hpp"

ENGINE *g_engine = NULL;

namespace NSCertLib {

// Configuration items in the JSON config provided for module initialization
static const char kCertificateConfig[] = "certificates";
// Name of certwrap key in HSM
static const char kCertWrapKeyName[] = "cert-wrap-key-name";
static const char kEnginePath[] = "engine-path";

ModulePtr ModuleImpl::m_moduleOpenSSL;

// Function to parse JSON configuration for module initialization
bool
ModuleImpl::parseConfig(const char *configFile,
                        std::string &certWrapKeyName,
                        std::string &enginePath,
                        HSMConfig &hsmConfig)
{
    Json::Value configRoot;
    if (not loadJsonFromFile(configFile, configRoot)) {
        return false;
    }

    if (not configRoot[kEnginePath].isString()) {
        setError("Invalid or missing 'engine-path' config = %s", configFile);
        return false;
    }
    enginePath = configRoot[kEnginePath].asString();
    Json::Value nssConfig = configRoot[kCertificateConfig];
    if (nssConfig.isNull()) {
        setError("Unable to find 'certificates' config in the configuration file - %s",
                 configFile);
        return false;
    }
    if (not nssConfig[kCertWrapKeyName].isString()) {
        setError("Invalid or missing 'cert-wrap-key-name' config - %s", configFile);
        return false;
    }
    certWrapKeyName = nssConfig[kCertWrapKeyName].asString();

    return hsmConfig.populate(configFile);
}

bool
ModuleImpl::loadGemEngine(const std::string &enginePath)
{
    //ENGINE_load_dynamic();
    g_engine = ENGINE_by_id("gem");
    /*if (!ENGINE_ctrl_cmd_string(g_engine, "SO_PATH", enginePath.c_str(), 0)) {
        setOpenSSLError("Failed to setup gemengine library path for loading engine");
        return false;
    }*/
    /*if (!ENGINE_ctrl_cmd_string(g_engine, "ID", "gem", 0)) {
        setOpenSSLError("Failed to set ID for loading engine");
        return false;
    }*/
    /*if (!ENGINE_ctrl_cmd(g_engine, "LIST_ADD", 1, nullptr, nullptr, 0)) {
        setOpenSSLError("Failed to set LIST_ADD for loading engine");
        return false;
    }
    if (!ENGINE_ctrl_cmd_string(g_engine, "LOAD", nullptr, 0)) {
        setOpenSSLError("Failed to set LOAD for loading engine");
        return false;
    }*/
    if (!ENGINE_init(g_engine)) {
        setOpenSSLError("Unable to initialize engine");
        return false;
    }
    /*if (!ENGINE_set_default_RSA(g_engine)) {
        setOpenSSLError("Unable to set gemengine as default for RSA operations");
        return false;
    }*/

    const char *test_env = std::getenv("TESTENV");
    if (test_env && !patchRSAForTest(g_engine)) {
        setOpenSSLError("Unable to patch RSA key gen method for testing");
        return false;
    }
    return true;
}

ModuleImpl::ModuleImpl(const char *configFile, PrivateToken) : m_configFile(configFile) {}

void
ModuleImpl::initialize(bool useGemEngine)
{
    if (m_configFile.empty()) {
        setError("No config file");
        return;
    }
    std::string enginePath;
    if (!parseConfig(m_configFile.c_str(), m_certWrapKeyName, enginePath, m_hsmConfig)) {
        // Error already set by parseConfig()
        return;
    }
    if (!initializeRandomness()) {
        // Error already set by initializeRandomness()
        return;
    }

    // Initialize openssl
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    // Load OpenSSL legacy provider to support older algorithms (e.g. RC2-40-CBC)
    // required for parsing our PKCS12 files. This is needed in OpenSSL 3.x as these
    // algorithms are disabled by default for security reasons.
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        setOpenSSLError("Failed to load OpenSSL legacy provider");
        return;
    }

    if (is_fips_mode()) {
        // Load OpenSSL FIPS provider when in FIPS mode.
        // Return error if failed, due to FIPS compliance requirement.
        OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
        if (!fips) {
            setOpenSSLError("Failed to load OpenSSL FIPS provider");
            return;
        }
    }

    // Save a copy of the software-based algorithms
    m_softRsa = RSA_get_default_method();
    // Load gemengine
    if (useGemEngine && !loadGemEngine(enginePath)) {
        return;
    }
    if (m_hsmConfig.type != kNAE && m_hsmConfig.type != kSoftoken) {
        setError("Unsupported HSM type %s mentioned in config - %s",
                 m_hsmConfig.type.c_str(),
                 m_configFile.c_str());
        return;
    }
    if (!initializeWrapper()) {
        return;
    }
    m_initialized = true;
}

#ifdef SWIG
KeyPair*
#else
KeyPairPtr
#endif
ModuleImpl::createAsymKeyPair(AsymKeyAlgorithm alg,
                              AsymKeySize keysize,
                              AsymKeyGenMethod meth /*=kSoftware*/)
{
    ENGINE *engine = nullptr;
    if (meth == kHSM) {
        if (m_engine) {
            engine = m_engine;
        } else {
            setError("HSM's engine is not initialized");
            return nullptr;
        }
    }

    KeyPairImplPtr keys(new KeyPairImpl());
    if (!keys.get()) {
        setError("Memory error during key creation");
        return nullptr;
    }
    keys->setAlgorithm(alg, keysize);
    if (!keys->initialize(engine)) {
        return nullptr;
    }
#ifdef SWIG
            return keys.release();
#else
    return KeyPairPtr(keys.release());
#endif
}

#ifdef SWIG
Issuer*
#else
IssuerPtr
#endif
ModuleImpl::createIssuer(const RawData &issuerCert, KeyPair &issuerKeys)
{
    IssuerImplPtr issuer(new IssuerImpl());
    if (!issuer->initialize(issuerCert, static_cast<KeyPairImpl &>(issuerKeys))) {
        issuer.reset(nullptr);
    }
#ifdef SWIG
        return issuer.release();
#else
    return IssuerPtr(issuer.release());
#endif
}

#ifdef SWIG
CertReq*
#else
CertReqPtr
#endif
ModuleImpl::createCertificateRequest(X509NameMap &subject, KeyPair &keys)
{
    X509NamePosition position_list = X509NamePosition();
    return exCreateCertificateRequest(subject, keys, position_list, false, false);
}

#ifdef SWIG
CertReq*
#else
CertReqPtr
#endif
ModuleImpl::createCertificateRequestPrintableSubjectEncoding(X509NameMap &subject,
                                                             KeyPair &keys)
{
    X509NamePosition position_list = X509NamePosition();
    return exCreateCertificateRequest(subject, keys, position_list, true, true);
}

#ifdef SWIG
CertReq*
#else
CertReqPtr
#endif
ModuleImpl::createCertificateRequestWithDNPosition(X509NameMap &subject,
                                                   KeyPair &keys,
                                                   X509NamePosition &position_list)
{
    return exCreateCertificateRequest(subject, keys, position_list, false, false);
}
#ifdef SWIG
CertReq*
#else
CertReqPtr
#endif
ModuleImpl::createCertificateRequestWithDNPositionPrintableSubjectEncoding(
    X509NameMap &subject, KeyPair &keys, X509NamePosition &position_list)
{
    return exCreateCertificateRequest(subject, keys, position_list, true, true);
}

#ifdef SWIG
CertReq*
#else
CertReqPtr
#endif
ModuleImpl::exCreateCertificateRequest(X509NameMap &subject,
                                       KeyPair &keys,
                                       X509NamePosition &position_list,
                                       bool ia5_for_email,
                                       bool printable_subject)
{
    CertReqImplPtr certReq(new CertReqImpl());
    if (!certReq.get()) {
        setError("Memory error during certreq creation");
        return nullptr;
    }
    if (not certReq->setSubject(subject, ia5_for_email)) {
        return nullptr;
    }

    if (printable_subject) {
        certReq->setSubjectEncodingPrintableString();
    }

    certReq->setPositionList(position_list);

    certReq->setKeys(static_cast<KeyPairImpl &>(keys));

    if (!certReq->initialize()) {
        return nullptr;
    }
#ifdef SWIG
        return certReq.release();
#else
    return CertReqPtr(certReq.release());
#endif
}

#ifdef SWIG
Certificate*
#else
CertificatePtr
#endif
ModuleImpl::createCertificatewithCSR(const RawData &certReq,
                                     SignatureAlgorithm alg,
                                     const RawData &serial,
                                     Issuer *issuer,
                                     unsigned int validDays)
{
    CertificateImplPtr cert(new CertificateImpl(CertificateImpl::kCertReqType));
    if (!cert.get()) {
        setError("Memory error during certificate creation");
        return nullptr;
    }

    // Parse CSR to X509_req object
    CertReqImpl certReqImpl(certReq);
    AutoCleaner<X509_REQ> certReqPtr(certReqImpl.getx509Req());
    if (!certReqPtr.get()) {
        // Error already set
        return nullptr;
    }
    cert->setCertRequest(certReqPtr.release())
        .setKeys(certReqImpl.getKeys())
        .setSerial(serial)
        .setSignatureAlgorithm(alg)
        .setValidity(validDays);
    if (issuer) {
        cert->setIssuer(static_cast<IssuerImpl &>(*issuer));
    }
    if (certReqImpl.isSerialInAuthKeyId()) {
        cert->setSerialInAuthKeyId();
    }
    if (!cert->initialize()) {
        return nullptr;
    }

#ifdef SWIG
        return cert.release();
#else
    return CertificatePtr(cert.release());
#endif
}

#ifdef SWIG
Certificate*
#else
CertificatePtr
#endif
ModuleImpl::createCertificate(CertReq &certReq,
                              SignatureAlgorithm alg,
                              const RawData &serial,
                              Issuer *issuer,
                              unsigned int validDays)
{
    CertificateImplPtr cert(new CertificateImpl(CertificateImpl::kCertReqType));
    if (!cert.get()) {
        setError("Memory error during certificate creation");
        return nullptr;
    }

    auto &certReqImpl = static_cast<CertReqImpl &>(certReq);
    AutoCleaner<X509_REQ> certReqPtr(certReqImpl.finalize(alg));
    if (!certReqPtr.get()) {
        // Error already set
        return nullptr;
    }
    cert->setCertRequest(certReqPtr.release())
        .setKeys(certReqImpl.getKeys())
        .setSerial(serial)
        .setSignatureAlgorithm(alg)
        .setValidity(validDays);
    if (issuer) {
        cert->setIssuer(static_cast<IssuerImpl &>(*issuer));
    }
    if (certReqImpl.isSerialInAuthKeyId()) {
        cert->setSerialInAuthKeyId();
    }
    if (!cert->initialize()) {
        return nullptr;
    }
#ifdef SWIG
        return cert.release();
#else
    return CertificatePtr(cert.release());
#endif
}

#ifdef SWIG
Certificate*
#else
CertificatePtr
#endif
ModuleImpl::getCertificate(CertificateFormat format,
                           const RawData &certdata,
                           const char *passwd)
{
    CertificateImplPtr cert(new CertificateImpl(CertificateImpl::kCertContentType));
    if (!cert.get()) {
        setError("Memory error while getting certificate");
        return nullptr;
    }
    cert->setCertData(format, certdata, passwd);
    if (!cert->initialize()) {
        return nullptr;
    }
#ifdef SWIG
        return cert.release();
#else
    return CertificatePtr(cert.release());
#endif
    return nullptr;
}

#ifdef SWIG
Certificate*
#else
CertificatePtr
#endif
ModuleImpl::getCertificateWithKey(CertificateFormat format,
                                  const RawData &certdata,
                                  KeyPair &keys)
{
    auto &realKeys = static_cast<KeyPairImpl &>(keys);
    CertificateImplPtr cert(new CertificateImpl(CertificateImpl::kCertContentType));
    if (!cert.get()) {
        setError("Memory error while getting certificate with key");
        return nullptr;
    }
    cert->setCertData(format, certdata, realKeys);
    if (!cert->initialize()) {
        return nullptr;
    }
#ifdef SWIG
        return cert.release();
#else
    return CertificatePtr(cert.release());
#endif
    return nullptr;
}

Wrapper &
ModuleImpl::getWrapper(const char *certWrapKey)
{
    if (certWrapKey == nullptr) certWrapKey = m_certWrapKeyName.c_str();

    auto itr = m_wrappers.find(certWrapKey);
    if (itr != m_wrappers.end()) return static_cast<Wrapper &>(*itr->second);

    std::unique_ptr<WrapperImpl> wrapper(new WrapperImpl());
    wrapper->initialize(certWrapKey, m_hsmConfig);
    m_wrappers[certWrapKey] = (std::unique_ptr<WrapperImpl>)wrapper.release();
    return static_cast<Wrapper &>(*(m_wrappers[certWrapKey].get()));
}

bool
ModuleImpl::isInitialized()
{
    return m_initialized;
}

bool
ModuleImpl::initializeWrapper()
{
    auto itr = m_wrappers.find(m_certWrapKeyName);
    if (itr != m_wrappers.end()) {
        return true;
    }

    std::unique_ptr<WrapperImpl> wrapper(new WrapperImpl());
    // For WrapperImpl always software crypto is used
    bool rv = wrapper->initialize(m_certWrapKeyName.c_str(), m_hsmConfig);
    if (rv) {
        m_wrappers[m_certWrapKeyName] = std::move(wrapper);
    }
    return rv;
}

bool
ModuleImpl::initializeRandomness()
{
    std::ifstream urandom("/dev/urandom", std::ifstream::in);
    if (!urandom.is_open()) {
        setError("Unable to open /dev/urandom");
        return false;
    }
    urandom.close();
    return true;
}

#ifdef SWIG
KeyPair*
#else
KeyPairPtr
#endif
ModuleImpl::copyAsymKeyPair(const KeyPair &keyPair)
{
    auto keys{std::make_unique<KeyPairImpl>(dynamic_cast<const KeyPairImpl &>(keyPair))};
#ifdef SWIG
    return keys.release();
#else
    return KeyPairPtr(keys.release());
#endif
}

std::mutex g_ModuleLock;

Module &
ModuleImpl::getModule(const char *configFile, bool useGemEngine)
{
    std::lock_guard<std::mutex> lockHolder(g_ModuleLock);
    if (not m_moduleOpenSSL) {
        m_moduleOpenSSL = std::make_unique<ModuleImpl>(configFile, ModuleImpl::PrivateToken());
        // Might as well assert. If memory allocation fails at this point
        // we are pretty much done for.
        assert(nullptr != m_moduleOpenSSL);
        auto &moduleImpl = static_cast<ModuleImpl &>(*(m_moduleOpenSSL.get()));
        moduleImpl.initialize(useGemEngine);
        return *m_moduleOpenSSL.get();
    }
    auto &moduleImpl = static_cast<ModuleImpl &>(*(m_moduleOpenSSL.get()));
    if (!moduleImpl.isInitialized()) {
        // Just retry initializing wrapper. This could be because, we might
        // have just got certificate/other configuration set properly for
        // HSM
        if (moduleImpl.initializeWrapper()) {
            moduleImpl.m_initialized = true;
        }
    }
    // We cannot have multiple ModuleImpl objects in same process
    // Simply assert and exit
    assert(moduleImpl.m_configFile == configFile);
    return *m_moduleOpenSSL.get();
}

#ifdef SWIG
Module& getModule(const char* configFile, bool useGemEngine)
{
    // TODO: ENG-120870 remove all NSS, only use openssl moving forward
    return NSCertLib::ModuleImpl::getModule(configFile, useGemEngine);
}
#endif

}  // namespace NSCertLib
