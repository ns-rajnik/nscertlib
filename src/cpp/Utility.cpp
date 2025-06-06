#include <json/json.h>

#include <algorithm>
#include <array>
#include <fstream>

#include "AutoCleaner.hpp"
#include "ErrorImpl.hpp"
#include "Utility.hpp"
#include "cpp/Data.hpp"

#define DN_EMAIL_ADDRESS "emailAddress"

// Variable to check if FIPS mode check has been done.
// This is to avoid checking FIPS mode multiple times.
static bool g_fips_mode_checked{false};
// Variable to store if FIPS mode is enabled.
static bool g_fips_mode_enabled{false};

const std::string &
lookup_x509_subject_name_position(int position)
{
    static const std::array<std::string, MAX_POSITIONS> lookup{
        {"emailAddress", "CN", "OU", "O", "L", "ST", "C"}};
    return lookup.at(position);
}

std::string
readFile(const char *file)
{
    std::ifstream fileStream(file, std::ifstream::in);
    std::string content;
    if (!fileStream) {
        NSCertLib::setError("Unable to read config file - %s", file);
        return content;
    }
    fileStream.seekg(0, std::ios::end);
    content.reserve(fileStream.tellg());
    fileStream.seekg(0, std::ios::beg);
    content.assign((std::istreambuf_iterator<char>(fileStream)),
                   std::istreambuf_iterator<char>());
    return content;
}

bool
loadJsonFromFile(const char *file, Json::Value &root)
{
    if (not file) {
        NSCertLib::setError("config file is null");
        return false;
    }
    std::string configValue = readFile(file);
    if (configValue.empty()) {
        // Error already set
        return false;
    }
    Json::Reader configReader(Json::Features::all());
    if (!configReader.parse(configValue, root)) {
        auto errors = configReader.getFormatedErrorMessages();
        NSCertLib::setError("Unable to parse config file - %s - %s", file, errors.c_str());
        return false;
    }
    return true;
}

bool
bioToRawData(BIO *bio, NSCertLib::RawData &data)
{
    if (not bio) {
        return false;
    }
    const uint32_t read_len{1024};
    uint32_t index{0};
    int32_t bytes_read{0};
    data.resize(read_len);
    while ((bytes_read = BIO_read(bio, &data[index], read_len)) > 0) {
        index += bytes_read;
        data.resize(data.size() + read_len);
    }
    data.resize(index);
    return true;
}

template <typename T>
T
ltrim(T s)
{
    if (s.empty()) {
        return s;
    }
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
    return s;
}

template <typename T>
T
rtrim(T s)
{
    if (s.empty()) {
        return s;
    }
    s.erase(
        std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); })
            .base(),
        s.end());
    return s;
}
template <typename T>
T
trim(T s)
{
    return rtrim<T>(ltrim<T>(s));
}

// trim from both ends
std::string
copyAndTrim(std::string s)
{
    return trim<std::string &>(s);
}

NSCertLib::X509Name_UniquePtr
parseNameFromPair(NSCertLib::X509NameMap &key_value,
                  int chType,
                  bool ia5_for_email,
                  X509PositionFunc position_func,
                  int max_positions)
{
    NSCertLib::X509Name_UniquePtr name{X509_NAME_new()};
    if (!name.get()) {
        NSCertLib::setError("Failed to allocate new X509_NAME");
        return {};
    }

    if (key_value.empty()) {
        return name;
    }

    bool has_entries{false};

    try {
        for (int i{0}; i < max_positions; ++i) {
            const auto &key_name = position_func(i);

            if (auto it{key_value.find(key_name)}; it != std::end(key_value)) {
                auto &[k, v] = *it;

                if (k.empty() or v.empty()) {
                    NSCertLib::setError("Subject key/value entries must not be empty");
                    return {};
                }
                auto key = copyAndTrim(k);
                auto value = copyAndTrim(v);

                int nid{OBJ_txt2nid(key.c_str())};

                if (nid == NID_undef) {
                    /* Skipping unknown name */
                    continue;
                }
                int encoding_type = chType;
                if (ia5_for_email and key == DN_EMAIL_ADDRESS) {
                    encoding_type = V_ASN1_IA5STRING;
                }
                // create single RDN, position of names dictated by index returned by
                // lookup_x509_subject_name_position to conform with current subject
                // line used at netskope
                if (not X509_NAME_add_entry_by_NID(
                        name.get(),
                        nid,
                        encoding_type,
                        reinterpret_cast<unsigned char *>(const_cast<char *>(value.c_str())),
                        -1,
                        -1,
                        1)) {
                    NSCertLib::setOpenSSLError("Error adding %s name attribute \"/%s=%s\"\n",
                                               key.c_str(),
                                               value.c_str());

                    return {};
                }
                has_entries = true;
            }
        }
        if (not has_entries) {
            NSCertLib::setError("subject line did not contain at least one valid entry");
            return {};
        }
    } catch (const std::out_of_range &e) {
        NSCertLib::setError("name position element is out of range %s", e.what());
        return {};
    }

    return name;
}

bool
getNameFromX509(X509 *certificate,
                NSCertLib::RawData &name,
                std::function<X509_NAME *(const X509 *)> name_func)
{
    NSCertLib::BIO_UniquePtr bio_out{BIO_new(BIO_s_mem())};

    if (not bio_out) {
        NSCertLib::setOpenSSLError("Failed to create bio");
        return false;
    }

    const unsigned long flags =
        ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE | XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN;
    if (X509_NAME_print_ex(bio_out.get(), name_func(certificate), 0, flags) == -1) {
        NSCertLib::setOpenSSLError("Unable to get x509 name");
        return false;
    }
    if (not bioToRawData(bio_out.get(), name)) {
        NSCertLib::setError("Unable convert x509 name BIO to RawData");
        return false;
    }
    return true;
}

bool
is_fips_mode(const char *custom_path)
{
    if (custom_path) {
        g_fips_mode_checked = false;
    }
    std::string path = custom_path ? custom_path : "/proc/sys/crypto/fips_enabled";
    if (!g_fips_mode_checked) {
        std::ifstream fips_file(path);
        if (fips_file.is_open()) {
            char value;
            fips_file >> value;
            fips_file.close();
            g_fips_mode_enabled = (value == '1');
        }
        g_fips_mode_checked = true;
    }
    return g_fips_mode_enabled;
}
