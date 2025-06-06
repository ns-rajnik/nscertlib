%module NSCertLib

%include <std_string.i>

%inline %{
#define SWIG 1
#include "cpp/Data.hpp"
#include "cpp/Error.hpp"
#include "cpp/Wrapper.hpp"
#include "cpp/Keys.hpp"
#include "cpp/CertReq.hpp"
#include "cpp/Issuer.hpp"
#include "cpp/Certificate.hpp"
#include "cpp/Module.hpp"
#include "cpp/NSCertLib.hpp"
%}

%{
#include "cpp/Issuer.hpp"
%}


%inline %{


std::string convert_pystr_to_std_string(PyObject* pyKey) 
{

    if (!PyUnicode_Check(pyKey)) 
    {
        PyErr_SetString(PyExc_TypeError, "must be a string");
        throw;
    }

    PyObject *utf8str = PyUnicode_AsUTF8String(pyKey);

    if (not utf8str) {
       PyErr_SetString(PyExc_TypeError, "could not decode string as utf8");
       throw;
    }

    const char *strtmp = 0;
    strtmp = PyBytes_AsString(utf8str);
    std::string ret = std::string(strtmp);
    Py_DECREF(utf8str);
    return ret;
}
%}

%typemap(in) std::vector<std::string>& {

    if (!PyList_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected a list");
        SWIG_fail;
    }

    std::vector<std::string> *tmpVector = new std::vector<std::string>();

    size_t size = PyList_Size($input);
    tmpVector->reserve(size);
    for (size_t i = 0; i < size; ++i) {
        PyObject* item = PyList_GetItem($input, i);
        std::string strValue = convert_pystr_to_std_string(item);
        tmpVector->emplace_back(strValue);
    }
    $1 = tmpVector;
}

%typemap(freearg) std::vector<std::string>& {
    delete $1;
}

%typemap(typecheck) std::vector<std::string>& () {
    $1 = PyList_Check($input) ? 1: 0
}

%typemap(in) std::map<std::string, std::string>& {
    std::map<std::string, std::string> *tmpMap = new std::map<std::string, std::string>();
   
    if (!PyDict_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected a dictionary");
        SWIG_fail;
    }
    PyObject* inpObj = $input;

    PyObject* pyKey = NULL;
    PyObject* pyValue = NULL;
    Py_ssize_t pos = 0;
    try{
        while (PyDict_Next(inpObj, &pos, &pyKey, &pyValue)) {
            std::string key = convert_pystr_to_std_string(pyKey);
            std::string value = convert_pystr_to_std_string(pyValue);

            (*tmpMap)[key] = value;
    }
    }catch(...){
    }
    $1 = tmpMap;
}

%typemap(freearg) std::map<std::string, std::string>& {
    delete $1;
}

%typemap(typecheck) std::map<std::string, std::string>& () {
    $1 = PyDict_Check($input) ? 1: 0
}

%typemap(in) const NSCertLib::RawData& {
    $1 = new NSCertLib::RawData;
    // Handling of unicode
    PyObject* inpObj = $input;
    if (PyUnicode_Check($input)) {
        inpObj = PyUnicode_AsASCIIString($input);
    }
    $1->resize(PyString_Size(inpObj));
    memcpy($1->data(), PyString_AsString(inpObj), $1->size());
}

%typemap(freearg) const NSCertLib::RawData& {
    delete $1;
}

%typemap(typecheck) const NSCertLib::RawData& {
    $1 = PyString_Check($input);
}

%typemap(out) NSCertLib::RawData* {
    if ($1) {
        $result = PyBytes_FromStringAndSize((const char*)$1->data(), $1->size());
        delete $1;
    } else {
        $result = Py_None;
    }
}

%typemap(out) bool {
    $result = PyBool_FromLong($1 ? 1 : 0);
}

%ignore *::getCertificate(CertificateFormat, RawData&, const char*);
%ignore *::getCertificate(CertificateFormat, RawData&);
%ignore *::getSubjectName(RawData&);
%ignore *::getIssuerName(RawData&);
%ignore *::getPrivateKeyInfo(RawData&);
%ignore *::getPEMPublicKey(RawData&);
%ignore *::wrap(KeyPair&, RawData&, RawData&);
%ignore *::wrapData(const RawData&, RawData&);
%ignore *::unwrapData(const RawData&, RawData&);
%ignore *::getCsr(SignatureAlgorithm,RawData&);

%newobject NSCertLib::Certificate::getCertificate;
%newobject NSCertLib::Certificate::getSubjectKeyId;
%newobject NSCertLib::Certificate::getSubjectName;
%newobject NSCertLib::Certificate::getIssuerName;
%newobject NSCertLib::Certificate::getSerial;
%newobject NSCertLib::CertReq::getCsr;
%newobject NSCertLib::KeyPair::getPrivateKeyInfo;
%newobject NSCertLib::KeyPair::getPEMPublicKey;
%newobject NSCertLib::KeyPair::sign;
%newobject NSCertLib::KeyPair::verify;
%newobject NSCertLib::Module::createAsymKeyPair;
%newobject NSCertLib::Module::copyAsymKeyPair;
%newobject NSCertLib::Module::createIssuer;
%newobject NSCertLib::Module::createCertificateRequest;
%newobject NSCertLib::Module::createCertificateRequestWithDNPosition;
%newobject NSCertLib::Module::createCertificatewithCSR;
%newobject NSCertLib::Module::createCertificate;
%newobject NSCertLib::Module::getCertificate;
%newobject NSCertLib::Module::getCertificateWithKey;
%newobject NSCertLib::Wrapper::wrapPrivateKey;
%newobject NSCertLib::Wrapper::wrapPublicKey;
%newobject NSCertLib::Wrapper::unwrap;
%newobject NSCertLib::Wrapper::wrapData;
%newobject NSCertLib::Wrapper::unwrapData;

%include "cpp/Data.hpp"
%include "cpp/Error.hpp"
%include "cpp/Keys.hpp"
%include "cpp/Wrapper.hpp"
%include "cpp/CertReq.hpp"
%include "cpp/Certificate.hpp"
%include "cpp/Issuer.hpp"
%include "cpp/Module.hpp"
%include "cpp/NSCertLib.hpp"

%inline %{

namespace NSCertLib {

    RawData* Certificate::getCertificate(CertificateFormat format, const char* passwd)
    {
        RawData* cert = new RawData;
        if (!getCertificate(format, *cert, passwd)) {
            delete cert;
            return nullptr;
        }
        return cert;
    }

    RawData* Certificate::getSubjectKeyId()
    {
        RawData* keyId = new RawData;
        if (!getSubjectKeyId(*keyId)) {
            delete keyId;
            return nullptr;
        }
        return keyId;
    }

    RawData* Certificate::getSubjectName()
    {
        RawData* subject = new RawData;
        if(!getSubjectName(*subject)) {
            delete subject;
            return nullptr;
        }
        return subject;
    }

    RawData* Certificate::getIssuerName()
    {
        RawData* issuer = new RawData;
        if(!getIssuerName(*issuer)) {
            delete issuer;
            return nullptr;
        }
        return issuer;
    }

    RawData* Certificate::getSerial()
    {
        RawData* serial = new RawData;
        if (!getSerial(*serial)) {
            delete serial;
            return nullptr;
        }
        return serial;
    }

    RawData* CertReq::getCsr(SignatureAlgorithm alg)
    {
        RawData* csr = new RawData;
        if (!getCsr(alg, *csr)) {
            delete csr;
            return nullptr;
        }
        return csr;
    }

    RawData* KeyPair::sign_digest(const RawData& signingData)
    {
        RawData* signedData = new RawData;
        if (!sign_digest(signingData, *signedData)) {
            delete signedData;
            return nullptr;
        }
        return signedData;
    }

    bool KeyPair::verify_digest(const RawData& signedData, const RawData& tbs)
    {
        if (!_verify_digest(signedData, tbs)) {
            return false;
        }
        return true;
    }

    RawData* KeyPair::getPrivateKeyInfo(const char* passwd)
    {
        RawData* keyInfo = new RawData;
        if (!getPrivateKeyInfo(*keyInfo, passwd)) {
            delete keyInfo;
            return nullptr;
        }
        return keyInfo;
    }

    RawData* KeyPair::getPEMPublicKey()
    {
        RawData* pubKeyInfo = new RawData;
        if (!getPEMPublicKey(*pubKeyInfo)) {
            delete pubKeyInfo;
            return nullptr;
        }
        return pubKeyInfo;
    }

    RawData* KeyPair::publicEncrypt(const RawData& bufferIn)
    {
        RawData* bufferOut = new RawData;
        if (!publicEncrypt(bufferIn,*bufferOut)) {
            delete bufferOut;
            return nullptr;
        }
        return bufferOut;
    }

    RawData* KeyPair::privateDecrypt(const RawData& bufferIn)
    {
        RawData* bufferOut = new RawData;
        if (!privateDecrypt(bufferIn,*bufferOut)) {
            delete bufferOut;
            return nullptr;
        }
        return bufferOut;
    }

    RawData* Wrapper::wrapPrivateKey(KeyPair& keys)
    {
        RawData dummy;
        RawData* wrappedPrivKey = new RawData;
        if (!wrap(keys, *wrappedPrivKey, dummy)) {
            delete wrappedPrivKey;
            return nullptr;
        }
        return wrappedPrivKey;
    }

    RawData* Wrapper::wrapPublicKey(KeyPair& keys)
    {
        RawData dummy;
        RawData* derPubKey = new RawData;
        if (!wrap(keys, dummy, *derPubKey)) {
            delete derPubKey;
            return nullptr;
        }
        return derPubKey;
    }

    RawData* Wrapper::wrapData(const RawData& data)
    {
        RawData* wrappedData = new RawData;
        if (!wrapData(data, *wrappedData)) {
            delete wrappedData;
            return nullptr;
        }
        return wrappedData;
    }

    RawData* Wrapper::unwrapData(const RawData& wrappedData)
    {
        RawData* data = new RawData;
        if (!unwrapData(wrappedData, *data)) {
            delete data;
            return nullptr;
        }
        return data;
    }

} // namespace NSCertLib
%}
