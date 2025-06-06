#include <NAEToken.hpp>
#include <array>
#include <filesystem>
#include <string>

#include "gtest/gtest.h"
#include "ns_test_settings.hpp"

using namespace NSCertLib;

struct HSMParams {
    std::string name;
    std::string config_file;
    bool path_is_valid{false};
    HSMConfig hsm_config;
};

bool
HSMConfigEqual(const HSMConfig &lhs, const HSMConfig &rhs)
{
    bool equal = true;
    equal &= lhs.type == rhs.type;
    equal &= lhs.properties == rhs.properties;
    equal &= lhs.password == rhs.password;
    equal &= lhs.username == rhs.username;
    equal &= lhs.nae_key_size == rhs.nae_key_size;
    return equal;
}

static const auto g_source_path =
    tests::GetAbsoluteSourceDirectory() + "/libs/nscertlib/tests/cpp/configs/";

static const std::array hsm_positive_test_values{
    HSMParams{"nae_key_default",
              "cert_config_nae_default.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"nae_key_1024",
              "cert_config_nae_1024.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"nae_key_2048",
              "cert_config_nae_2048.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 2048}},
    HSMParams{"nae_key_4096",
              "cert_config_nae_4096.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 4096}},
    HSMParams{"soft_token",
              "cert_config_soft_token.json",
              true,
              {"Softoken", "sample_safenet.properties", "cert", "netskope", 1024}}};

static const std::array hsm_negative_test_values{
    HSMParams{"nae_key_bad_key_size",
              "cert_config_nae_bad_key_size.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"missing_type",
              "cert_config_missing_type.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"missing_properties",
              "cert_config_missing_properties.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"missing_user",
              "cert_config_missing_user.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"missing_password",
              "cert_config_missing_password.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"bad_json",
              "cert_config_bad_json.json",
              true,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}},
    HSMParams{"bad_path",
              "cert_config_bad_path.json",
              false,
              {"NAE", "sample_safenet.properties", "cert", "netskope", 1024}}};

class HSMConfigParseBase : public ::testing::TestWithParam<HSMParams> {
public:
    void SetUp() override
    {
        m_params = GetParam();
        m_config_path = g_source_path + m_params.config_file;
        if (m_params.path_is_valid) {
            ASSERT_TRUE(std::filesystem::exists(m_config_path));
        } else {
            ASSERT_FALSE(std::filesystem::exists(m_config_path));
        }
    }
    std::string m_config_path;
    HSMParams m_params;
};

class HSMConfigParsePosFixture : public HSMConfigParseBase {};

class HSMConfigParseNegFixture : public HSMConfigParseBase {};

TEST_P(HSMConfigParsePosFixture, hsm_config_parse_positive)
{
    HSMConfig config;
    ASSERT_TRUE(config.populate(m_config_path.c_str()));
    ASSERT_TRUE(HSMConfigEqual(m_params.hsm_config, config));
}

TEST_P(HSMConfigParseNegFixture, hsm_config_parse_negative)
{
    HSMConfig config;
    ASSERT_FALSE(config.populate(m_config_path.c_str()));
}

INSTANTIATE_TEST_SUITE_P(
    HSMConfigParsePosTests,
    HSMConfigParsePosFixture,
    ::testing::ValuesIn(hsm_positive_test_values),
    [](const testing::TestParamInfo<HSMConfigParsePosFixture::ParamType> &paramInfo) {
        auto test = static_cast<HSMParams>(paramInfo.param);
        return test.name;
    });

INSTANTIATE_TEST_SUITE_P(
    HSMConfigParseNegTests,
    HSMConfigParseNegFixture,
    ::testing::ValuesIn(hsm_negative_test_values),
    [](const testing::TestParamInfo<HSMConfigParseNegFixture::ParamType> &paramInfo) {
        auto test = static_cast<HSMParams>(paramInfo.param);
        return test.name;
    });
