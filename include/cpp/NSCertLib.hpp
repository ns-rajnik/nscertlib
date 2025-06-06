#ifndef __NSCERTLIB_NSCERTLIB_H__
#define __NSCERTLIB_NSCERTLIB_H__

#include "Data.hpp"
#include "Keys.hpp"
#include "CertReq.hpp"
#include "Certificate.hpp"
#include "Issuer.hpp"
#include "Wrapper.hpp"
#include "Module.hpp"
#include "Error.hpp"

namespace NSCertLib {
Module &getModule(const char *configFile, bool useGemEngine);
}
#endif //__NSCERTLIB_NSCERTLIB_H__
