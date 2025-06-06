#ifndef __NSCERTLIB_SECITEM_H__
#define __NSCERTLIB_SECITEM_H__

#include "cpp/Data.hpp"

// Note on thread-safety
// This class is not thread-safe!
// It has to be created/used/deleted within a single thread of execution
// which is how it is used throughout NSCertLib

namespace NSCertLib {

using SECItem = RawData;
// This class is used throughout the NSCertLib code as an alternative to
// NSS library's SECItem. This provides the advantage of handling all
// memory management that it needs - something that is not provided
// by SECItem
class SecureItem {
public:
    // Constructors -
    // 1) Copy the content of given length
    SecureItem(const unsigned char *content, unsigned int len);
    // 2) Only allocate memory for given length. Content to come later
    explicit SecureItem(unsigned int maxLen);
    // 3) Copy constructor (The other item's contents will be cleared
    //    after copying)
    SecureItem(SecureItem &item);

    SecureItem() = default;
    virtual ~SecureItem() = default;

    // Const methods
    const unsigned char *getContent() const;
    unsigned int getLength() const;
    SECItem *getSECItem();

    // Reserve space and fill it later
    void reserve(unsigned int len);
    // Copy given SECItem and free it if freeNSSItem is true
    // If SecureItem holds anything, it will be cleared before
    // copy
    void copy(SECItem *item, bool freeNSSItem);
    // Copy given content of given length
    // If SecureItem holds anything, it will be cleared before
    // copy
    void copy(const unsigned char *content, unsigned int len);
    // Clear all the contents
    void clear();

    // Transfer the contents to given RawData
    void transfer(RawData &data) const;

private:
    SECItem m_item;
};

}  // namespace NSCertLib

#endif //__NSCERTLIB_SECITEM_H__
