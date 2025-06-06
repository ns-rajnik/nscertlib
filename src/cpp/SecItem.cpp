/**
 * Filename: SecItem.cpp
 *
 * Copyright (c) 2023 netSkope, Inc.
 * All rights reserved.
 */
#include <vector>

#include "SecItem.hpp"

namespace NSCertLib {

SecureItem::SecureItem(const unsigned char *content, unsigned int len)
{
    copy(content, len);
}

SecureItem::SecureItem(unsigned int maxLen)
{
    reserve(maxLen);
}

SecureItem::SecureItem(SecureItem &item)
{
    copy(item.getSECItem(), false);
}

const unsigned char* SecureItem::getContent() const
{
    return m_item.data();
}

unsigned int SecureItem::getLength() const
{
    return m_item.size();
}

SECItem* SecureItem::getSECItem()
{
    return &m_item;
}

void SecureItem::reserve(unsigned int len)
{
    clear();
    m_item.resize(len);
}

void
SecureItem::copy(SECItem *item, bool)
{
    clear();
    reserve(item->size());
    std::copy(std::cbegin(*item), std::cend(*item), std::begin(m_item));
}

void SecureItem::copy(const unsigned char* content, unsigned int len)
{
    clear();
    reserve(len);
    std::copy(content, content + len, std::begin(m_item));
}

void SecureItem::clear()
{
    m_item.clear();
}

void
SecureItem::transfer(RawData &data) const
{
    data.insert(std::begin(data), std::cbegin(m_item), std::cend(m_item));
}

}  // namespace NSCertLib
