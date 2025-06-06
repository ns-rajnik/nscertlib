#ifndef __NSCERTLIB_DATA_H__
#define __NSCERTLIB_DATA_H__

#include <map>
#include <string>
#include <vector>

namespace NSCertLib {
using StringData = std::string;
using RawData = std::vector<unsigned char>;
using X509NameMap = std::map<std::string, std::string>;
using X509NamePosition = std::vector<std::string>;
}  // namespace NSCertLib

#endif  //__NSCERTLIB_DATA_H__
