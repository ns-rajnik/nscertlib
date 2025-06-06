#pragma once

#include <assert.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <memory>
// Note on Thread-safety:
// This class is not thread-safe!
// AutoCleaner<> objects must be created, used and destroyed within a single
// thread. Which is how it is used through NSCertLib

namespace NSCertLib {

/**
 * @brief
 * Class to hold pointers to NSS objects
 * Takes care of cleaning up the objects in
 * an appropriate manner
 */
template <class Type>
class AutoCleaner {
public:
    // Variety of constructors
    // 1) Empty constructor
    AutoCleaner() = default;

    // 2) Constructor taking an object pointer
    explicit AutoCleaner(Type *t) { m_object = t; }

    // 3) Move constructor with rvalue reference
    AutoCleaner(AutoCleaner<Type> &&other) : m_object(other.m_object)
    {
        other.m_object = nullptr;
    }

    virtual ~AutoCleaner() { clear(); }

    // Reset the object stored to given one. Cleans up the
    // old object
    void reset(Type *t)
    {
        clear();
        m_object = t;
    }

    void reset(AutoCleaner<Type> &&other)
    {
        clear();
        m_object = other.m_object;
        other.m_object = nullptr;
    }

    // Get a pointer to the stored object
    // Ideally this should have been const method. But
    // NSS requires non-const pointers at various places
    Type *get() { return m_object; }

    // Const version of the above
    const Type *get() const { return m_object; }
    // Access operator
    Type *operator->() { return m_object; }

    // Get pointer to storage of object
    // This seems like a rather wrong way but it works for NSS
    Type **getStorage() { return &m_object; }

    // Release the content. This does not clean up
    // the stored object. After this call, AutoCleaner<>
    // is no longer incharge of the object
    Type *release()
    {
        Type *t = m_object;
        m_object = nullptr;
        return t;
    }

    // Assignment disallowed. Use reset() so that the assignment is explicit
    AutoCleaner<Type> &operator=(const AutoCleaner<Type> &) = delete;
    AutoCleaner<Type> &operator=(const Type *) = delete;

private:
    Type *m_object{nullptr};

    // This function has no default version
    // Cleaning up of each object in NSS is different
    // Hence we have specializations which take care of
    // destruction
    // For any new type handled by AutoCleaner<>, a
    // corresponding specialization of clear() needs to be
    // added
    void clear();
};

template <>
inline void
AutoCleaner<BIO>::clear()
{
    if (m_object) {
        BIO_free_all(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<EVP_PKEY>::clear()
{
    if (m_object) {
        EVP_PKEY_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<X509>::clear()
{
    if (m_object) {
        X509_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<PKCS12>::clear()
{
    if (m_object) {
        PKCS12_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<EVP_PKEY_CTX>::clear()
{
    if (m_object) {
        EVP_PKEY_CTX_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<X509_REQ>::clear()
{
    if (m_object) {
        X509_REQ_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<X509_EXTENSION>::clear()
{
    if (m_object) {
        X509_EXTENSION_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<STACK_OF(X509_EXTENSION)>::clear()
{
    if (m_object) {
        sk_X509_EXTENSION_pop_free(m_object, X509_EXTENSION_free);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<EVP_CIPHER_CTX>::clear()
{
    if (m_object) {
        EVP_CIPHER_CTX_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<BIGNUM>::clear()
{
    if (m_object) {
        BN_free(m_object);
        m_object = nullptr;
    }
}

template <>
inline void
AutoCleaner<ASN1_INTEGER>::clear()
{
    if (m_object) {
        ASN1_INTEGER_free(m_object);
        m_object = nullptr;
    }
}

struct BIO_Deleter {
    void operator()(BIO *r)
    {
        if (r) {
            BIO_free_all(r);
        }
    }
};

struct X509Name_Deleter {
    void operator()(X509_NAME *r)
    {
        if (r) {
            X509_NAME_free(r);
        }
    }
};

struct EVP_PKEY_CTX_deleter {
    void operator()(EVP_PKEY_CTX *keygen_ctx)
    {
        if (keygen_ctx) {
            EVP_PKEY_CTX_free(keygen_ctx);
        }
    }
};

using EVP_PKEY_CTX_UniquePtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_deleter>;
using BIO_UniquePtr = std::unique_ptr<BIO, BIO_Deleter>;
using X509Name_UniquePtr = std::unique_ptr<X509_NAME, X509Name_Deleter>;
}  // namespace NSCertLib
