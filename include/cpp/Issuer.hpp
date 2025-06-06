#pragma once

#include <memory>

namespace NSCertLib {

/**
 * @brief
 * Class/interface to represent CA (issuer)
 * This is mainly used for signing a certificate using Module
 */
class Issuer {
public:
    virtual ~Issuer() = default;
};

using IssuerPtr = std::unique_ptr<Issuer>;
}  // namespace NSCertLib
