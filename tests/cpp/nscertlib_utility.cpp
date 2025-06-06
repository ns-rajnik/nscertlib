#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "Utility.hpp"

class TempFileCreator {
private:
    const std::string filename;

public:
    TempFileCreator(const std::string &content)
        : filename("/tmp/fips_test_" + std::to_string(getpid()))
    {
        std::ofstream file(filename);
        file << content;
        file.close();
    }

    ~TempFileCreator() { std::remove(filename.c_str()); }

    std::string getFilename() const { return filename; }
};

TEST(FipsModeTest, FipsEnabled)
{
    TempFileCreator fips_file("1");
    ASSERT_TRUE(is_fips_mode(fips_file.getFilename().c_str()));
}

TEST(FipsModeTest, FipsDisabled)
{
    TempFileCreator fips_file("0");
    ASSERT_FALSE(is_fips_mode(fips_file.getFilename().c_str()));
}

TEST(FipsModeTest, FileNotPresent)
{
    ASSERT_FALSE(is_fips_mode("/tmp/this_file_does_not_exist"));
}
