#ifndef __NSCERTLIB_SERIALIZER_H__
#define __NSCERTLIB_SERIALIZER_H__
#include "cpp/Data.hpp"

// Note on thread-safety:
// This class is not thread-safe!
// It has to be created/used/deleted within a single thread
// which is how it is used throughout NSCertLib

namespace NSCertLib {

class SecureItem;
class Serializer {
public:
    explicit Serializer(RawData &data);
    bool serialize(SecureItem &item);
    bool serialize(RawData &data);

private:
    RawData &m_outData;
};

class Deserializer {
public:
    explicit Deserializer(const RawData &data);
    bool deserialize(SecureItem &item);
    bool deserialize(RawData &data);

private:
    const RawData &m_inData;
    unsigned int m_currentPos{0};
};

}  // namespace NSCertLib

#endif  // __NSCERTLIB_SERIALIZER_H__
