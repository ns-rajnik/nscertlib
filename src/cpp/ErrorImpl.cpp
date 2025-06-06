#include <assert.h>
#include <icapi.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <pthread.h>

#include "ErrorImpl.hpp"

namespace NSCertLib {

static const int kMaxMsgSize = 512;
static const int kMaxErrCodeSize = 256;

void
errorMsgDestroy(void *arg)
{
    if (!arg) {
        return;
    }
    auto errorMsg = (char *)arg;
    delete[] errorMsg;
}

// In case of multi-threading, multiple threads will be performing
// various operations and might land up in various errors.
// Error class ensures that the error messages are stored in thread-specific
// storage. This ensures that each thread gets its own error

class Error {
public:
    Error() { assert(pthread_key_create(&m_errorKey, errorMsgDestroy) == 0); }

    ~Error() { pthread_key_delete(m_errorKey); }

    void set(const char *msg, const char *code = nullptr) const
    {
        auto errorMsg = (char *)pthread_getspecific(m_errorKey);
        if (!errorMsg) {
            errorMsg = new char[kMaxMsgSize + kMaxErrCodeSize];
            pthread_setspecific(m_errorKey, errorMsg);
        }
        int msgLen = snprintf(errorMsg, kMaxMsgSize - 1, "%s", msg);
        if (code) {
            snprintf(errorMsg + msgLen, kMaxErrCodeSize, "%s", code);
        }
        errorMsg[kMaxErrCodeSize + kMaxMsgSize - 1] = 0;
    }

    const char *get() const { return (char *)pthread_getspecific(m_errorKey); }

private:
    pthread_key_t m_errorKey;
} g_error;

void
setNAEError(int rc, const char *msg, ...)
{
    char naeMsg[kMaxMsgSize];
    va_list args;
    va_start(args, msg);
    vsnprintf(naeMsg, kMaxMsgSize, msg, args);
    va_end(args);
    naeMsg[kMaxMsgSize - 1] = 0;
    char naeCode[kMaxErrCodeSize];
    snprintf(naeCode, kMaxErrCodeSize, "NAE Error message: %s", I_C_GetErrorString(rc));
    naeCode[kMaxErrCodeSize - 1] = 0;
    g_error.set(naeMsg, naeCode);
}

void
setError(const char *msg, ...)
{
    char errMsg[kMaxMsgSize];
    va_list args;
    va_start(args, msg);
    vsnprintf(errMsg, kMaxMsgSize, msg, args);
    va_end(args);
    errMsg[kMaxMsgSize - 1] = 0;
    g_error.set(errMsg);
}

void
setOpenSSLError(const char *msg, ...)
{
    char errMsg[kMaxMsgSize];
    va_list args;
    va_start(args, msg);
    vsnprintf(errMsg, kMaxMsgSize, msg, args);
    va_end(args);
    errMsg[kMaxMsgSize - 1] = 0;
    int opensslErrno = ERR_get_error();
    const char *opensslErr = ERR_error_string(opensslErrno, nullptr);
    g_error.set(errMsg, opensslErr);
}

}  // namespace NSCertLib

std::string
getNSCertLibError()
{
    const char *errorMsg = NSCertLib::g_error.get();
    if (errorMsg) {
        return errorMsg;
    }
    return "";
}
