#include "PEMHeader.hpp"

namespace NSCertLib::PEM {

const char *kCertHeader = "-----BEGIN CERTIFICATE-----";
const char *kCertFooter = "-----END CERTIFICATE-----";

const char *kPrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
const char *kPrivateKeyFooter = "-----END PRIVATE KEY-----";

const char *kRSAPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
const char *kRSAPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";

const char *kEncryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const char *kEncryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";

const char *kRSAPublicKeyHeader = "-----BEGIN RSA PUBLIC KEY-----";
const char *kRSAPublicKeyFooter = "-----END RSA PUBLIC KEY-----";

const char *kPublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
const char *kPublicKeyFooter = "-----END PUBLIC KEY-----";

const char *kCertReqHeader = "-----BEGIN CERTIFICATE REQUEST-----";
const char *kCertReqFooter = "-----END CERTIFICATE REQUEST-----";

}  // namespace NSCertLib::PEM
