#pragma once

#include <openssl/bio.h>

#include <functional>
#include <map>
#include <string>

#include "AutoCleaner.hpp"
#include "cpp/Data.hpp"
#include <openssl/engine.h>

namespace Json {
class Value;
}

inline constexpr int MAX_POSITIONS = 7;

using X509NameFunc = std::function<X509_NAME *(const X509 *)>;
using X509PositionFunc = std::function<const std::string &(int)>;
std::string readFile(const char *file);
bool loadJsonFromFile(const char *file, Json::Value &root);
bool bioToRawData(BIO *bio, NSCertLib::RawData &data);
const std::string &lookup_x509_subject_name_position(int position);
NSCertLib::X509Name_UniquePtr parseNameFromPair(
    NSCertLib::X509NameMap &key_value,
    int chType,
    bool ia5_for_email,
    X509PositionFunc name_pos = lookup_x509_subject_name_position,
    int max_positions = MAX_POSITIONS);
std::string copyAndTrim(std::string s);
bool getNameFromX509(X509 *certificate, NSCertLib::RawData &name, X509NameFunc name_func);
// FIPS mode detection, custom_path is only used for testing
bool is_fips_mode(const char *custom_path = nullptr);
extern ENGINE *g_engine;
