#include "Serializer.hpp"

#include <cstdint>
#include <cstring>

#include "SecItem.hpp"

namespace NSCertLib {

struct SerialItem {
    explicit SerialItem(unsigned char *location)
    {
        len = reinterpret_cast<uint32_t*>(location);
        content = location + sizeof(uint32_t);
    };

    void setData(const unsigned char *data, unsigned int size) const
    {
        *len = size;
        memcpy(content, data, size);
    };

    uint32_t* len;
    uint8_t* content;
};

struct DeserialItem {
    explicit DeserialItem(const unsigned char *location)
    {
        len = reinterpret_cast<const uint32_t*>(location);
        content = location + sizeof(uint32_t);
    };

    bool validate(unsigned int availableLen) const
    {
        return availableLen >= *len;
    };

    void getData(unsigned char *data, unsigned int &size) const
    {
        size = *len;
        memcpy(data, content, size);
    };

    unsigned int length() const { return *len + sizeof(uint32_t); };

    const uint32_t* len;
    const uint8_t* content;
};


Serializer::Serializer(RawData& data)
    : m_outData(data)
{
}

bool
Serializer::serialize(RawData &data)
{
    unsigned int oldSize = m_outData.size();
    m_outData.resize(oldSize + sizeof(uint32_t) + data.size());
    SerialItem serialItem(m_outData.data() + oldSize);
    serialItem.setData(data.data(), data.size());
    return true;
}

bool
Serializer::serialize(SecureItem &data)
{
    return serialize(*(data.getSECItem()));
}

Deserializer::Deserializer(const RawData &data) : m_inData(data) {}

bool Deserializer::deserialize(RawData& data)
{
    if (m_currentPos >= m_inData.size()) {
        return false;
    }
    DeserialItem serialItem(m_inData.data() + m_currentPos);
    if (!serialItem.validate(m_inData.size() - m_currentPos)) {
        return false;
    }
    unsigned int len = *(serialItem.len);
    data.resize(len);
    serialItem.getData(data.data(), len);
    m_currentPos += serialItem.length();
    return true;
}

bool
Deserializer::deserialize(SecureItem &item)
{
    return deserialize(*(item.getSECItem()));
}

}  // namespace NSCertLib
