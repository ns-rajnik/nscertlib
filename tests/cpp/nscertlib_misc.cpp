#include <algorithm>
#include <string>

#include "AutoCleaner.hpp"
#include "Utility.hpp"
#include "cpp/CertReq.hpp"
#include "cpp/Data.hpp"
#include "gtest/gtest.h"

using namespace NSCertLib;

TEST(Misc, ExtKeyUsage)
{
    // These values must never change, they are
    // used in nscertservice schema creation
    ASSERT_EQ(146, ExtKeyUsage::kServerAuth);
    ASSERT_EQ(147, ExtKeyUsage::kClientAuth);
    ASSERT_EQ(148, ExtKeyUsage::kCodeSigning);
    ASSERT_EQ(149, ExtKeyUsage::kEmailProtection);
    ASSERT_EQ(150, ExtKeyUsage::kTimeStamping);
}

TEST(Misc, BioToRawData)
{
    RawData test_data{'t', 'e', 's', 't', '1', '2', '3'};
    BIO_UniquePtr bio{BIO_new(BIO_s_mem())};
    BIO_write(bio.get(), test_data.data(), test_data.size());
    RawData data;
    ASSERT_TRUE(bioToRawData(bio.get(), data));
    ASSERT_EQ(test_data, data);
}

TEST(Misc, BioToRawData_nullptr)
{
    RawData data;
    ASSERT_FALSE(bioToRawData(nullptr, data));
}

TEST(Misc, BioToRawData_empty)
{
    RawData test_data;
    BIO_UniquePtr bio{BIO_new(BIO_s_mem())};
    RawData data;
    ASSERT_TRUE(bioToRawData(bio.get(), data));
    ASSERT_EQ(test_data, data);
}

struct TrimParam {
    std::string out;
    std::string in;
};

class TrimFixture : public ::testing::TestWithParam<TrimParam> {
public:
    void SetUp() override { m_param = GetParam(); }
    TrimParam m_param;
};

TEST_P(TrimFixture, string_combos)
{
    ASSERT_STREQ(std::string(m_param.out).c_str(), copyAndTrim(m_param.in).c_str());
}

static const std::array trim_test_values{TrimParam{"test123", " test123 "},
                                         TrimParam{"test123", " test123"},
                                         TrimParam{"test123", "test123 "},
                                         TrimParam{"test123", "test123"},
                                         TrimParam{"test123 test123", "test123 test123"},
                                         TrimParam{"test123 test123", " test123 test123"},
                                         TrimParam{"test123 test123", "test123 test123 "},
                                         TrimParam{"test123 test123", " test123 test123 "},
                                         TrimParam{"", " "},
                                         TrimParam{"", ""}};

INSTANTIATE_TEST_SUITE_P(TrimTests,
                         TrimFixture,
                         ::testing::ValuesIn(trim_test_values),
                         [](const testing::TestParamInfo<TrimFixture::ParamType> &paramInfo)
                             -> std::string {
                             auto test = static_cast<TrimParam>(paramInfo.param);
                             std::string name{test.in};
                             if (name.empty()) {
                                 return "empty_string";
                             }
                             std::replace(std::begin(name), std::end(name), ' ', '_');
                             return name;
                         });
