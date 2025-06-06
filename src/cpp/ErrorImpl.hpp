#ifndef __NSCERTLIB_ERRORIMPL_H__
#define __NSCERTLIB_ERRORIMPL_H__

#include <stdarg.h>

#include "cpp/Error.hpp"

namespace NSCertLib {

void setNAEError(int rc, const char *msg, ...);

void setError(const char *msg, ...);

void setOpenSSLError(const char *mssg, ...);
}  // namespace NSCertLib

#endif  // __NSCERTLIB_ERRORIMPL_H__
