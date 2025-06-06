import os
os.environ['TESTENV'] = "1"

import base64
import pytest
from cryptography.hazmat.primitives.serialization import pkcs12
from OpenSSL import crypto
import nscertlib
import validation
import copy
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

CERTS_PATH = os.path.dirname(os.path.realpath(__file__)) + '/certs'

class InOut:
    def __init__(self,input,output,should_fail = False,is_ca = True):
        self.input = input
        self.output = output
        self.should_fail = should_fail
        self.is_ca = is_ca

@pytest.mark.parametrize(
    "use_gem_engine", [
        pytest.param(True, id="use_gem_engine"),
        pytest.param(False, id="dont_use_gem_engine")
    ]
)
@pytest.mark.forked
class TestBase:
    CERT_CONFIG = os.path.dirname(os.path.realpath(__file__)) + '/cert_config.json'
    count =0

    @pytest.fixture(autouse=True)
    def module(self, use_gem_engine):
        self.module = nscertlib.getModule(self.CERT_CONFIG, use_gem_engine)

    def test_module_initialization(self):
        assert self.module.isInitialized(), "Module initialization failed"

    def test_key_creation(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert keys is not None, "Unable to create keys"
        pemPubKey = keys.getPEMPublicKey()
        assert pemPubKey, "Unable to get public key"
        privKeyInfo = keys.getPrivateKeyInfo(None)
        assert privKeyInfo, "Unable to get raw private key"
        validation.matchKeyPair(privKeyInfo, pemPubKey)

    def test_enc_key_creation(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert keys is not None, "Unable to create keys"
        privKeyInfo = keys.getPrivateKeyInfo(None)
        assert privKeyInfo, "Unable to get raw private key"
        encryptedPrivKey = keys.getPrivateKeyInfo('netskope')
        assert encryptedPrivKey, "Unable to get encrypted private key"
        validation.matchEncryptedKey(privKeyInfo, encryptedPrivKey, 'netskope')

    def test_key_pair_copy(self, request, use_gem_engine):
        if use_gem_engine is True:
            pytest.skip(f"{request.node.name} Feature not used with GEM engine")
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        copied_keys = self.module.copyAsymKeyPair(keys)
        assert keys.getPrivateKeyInfo(None) == copied_keys.getPrivateKeyInfo(None)
        assert keys.getPEMPublicKey() == copied_keys.getPEMPublicKey()
        test_data = b"test123"
        encrypted = keys.publicEncrypt(test_data)
        assert test_data != encrypted
        assert test_data == copied_keys.privateDecrypt(encrypted)

    def test_key_wrapping(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert keys, "Unable to create keys"
        wrapper = self.module.getWrapper()
        wrappedKey = wrapper.wrapPrivateKey(keys)
        derPubKey = wrapper.wrapPublicKey(keys)
        assert wrappedKey is not None and derPubKey is not None, "Unable to wrap keys"
        newKeys = wrapper.unwrap(wrappedKey, derPubKey)
        assert newKeys, "Unable to unwrap keys"
        oldPemPubKey = keys.getPEMPublicKey()
        newPemPubKey = newKeys.getPEMPublicKey()
        assert oldPemPubKey and newPemPubKey, "Unable to get public keys"
        assert oldPemPubKey == newPemPubKey, "Public key doesnt match after unwrapping"
        oldPrivKeyInfo = keys.getPrivateKeyInfo(None)
        newPrivKeyInfo = newKeys.getPrivateKeyInfo(None)
        assert oldPrivKeyInfo and newPrivKeyInfo, "Unable to get private keys"
        assert oldPrivKeyInfo == newPrivKeyInfo, "Private key doesnt match after unwrapping"

    def test_data_wrapping(self):
        kTestData = "Testing python wrapping"
        wrapper = self.module.getWrapper()
        encryptedData = wrapper.wrapData(kTestData)
        assert encryptedData, "Unable to wrap data"
        newData = wrapper.unwrapData(encryptedData)
        assert newData, "Unable to unwrap data"
        assert kTestData == newData.decode(), "Unwrapped data does not match the original one"

    def test_key_wrapping_cwkey(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert keys, "Unable to create keys"
        wrapper = self.module.getWrapper("Cert_Wrap")
        wrappedKey = wrapper.wrapPrivateKey(keys)
        derPubKey = wrapper.wrapPublicKey(keys)
        assert wrappedKey is not None and derPubKey is not None, "Unable to wrap keys"
        newKeys = wrapper.unwrap(wrappedKey, derPubKey)
        assert newKeys, "Unable to unwrap keys"
        oldPemPubKey = keys.getPEMPublicKey()
        newPemPubKey = newKeys.getPEMPublicKey()
        assert oldPemPubKey and newPemPubKey, "Unable to get public keys"
        assert oldPemPubKey == newPemPubKey, "Public key doesnt match after unwrapping"
        oldPrivKeyInfo = keys.getPrivateKeyInfo(None)
        newPrivKeyInfo = newKeys.getPrivateKeyInfo(None)
        assert oldPrivKeyInfo and newPrivKeyInfo, "Unable to get private keys"
        assert oldPrivKeyInfo == newPrivKeyInfo, "Private key doesnt match after unwrapping"

    def test_data_wrapping_cwkey(self):
        kTestData = "Testing python wrapping"
        wrapper = self.module.getWrapper("Cert_Wrap")
        encryptedData = wrapper.wrapData(kTestData)
        assert encryptedData, "Unable to wrap data"
        newData = wrapper.unwrapData(encryptedData)
        assert newData, "Unable to unwrap data"
        assert kTestData == newData.decode(), "Unwrapped data does not match the original one"

    def generate_root_ca(self):
        key = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert key, "Unable to create root keys"
        certReq = self.module.createCertificateRequest({"CN" : "RootCA"}, key)
        assert certReq, "Unable to create certificate request"
        assert certReq.setCA(), "Unable to set certificate request as CA"
        assert ( \
            certReq.addKeyUsage(nscertlib.kDigitalSignature) and \
            certReq.addKeyUsage(nscertlib.kNonRepudiation) and \
           certReq.addKeyUsage(nscertlib.kKeyCertSign) \
        ), "Unable to add key usage extensions"
        cert = self.module.createCertificate(certReq, nscertlib.kSHA256, '1', None, 365)
        assert cert, "Unable to create certificate"
        return key, cert
    
    def generate_root_ca_printable_subject(self,subject,subject_order = None):
        key = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert key, "Unable to create root keys"
        if subject_order is None:
            certReq = self.module.createCertificateRequestPrintableSubjectEncoding(subject, key)
        else:
            certReq = self.module.createCertificateRequestWithDNPositionPrintableSubjectEncoding(subject, key,subject_order)
        assert certReq, "Unable to create certificate request"
        assert certReq.setCA(), "Unable to set certificate request as CA"
        cert = self.module.createCertificate(certReq, nscertlib.kSHA256, '1', None, 365)
        assert cert, "Unable to create certificate"
        return key, cert

    def test_root_ca_pathlen(self):
        key = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert key, "Unable to create root keys"
        for pathlen in [-1,0,1]:
            certReq = self.module.createCertificateRequest({"CN" : "RootCA"}, key)
            assert certReq, "Unable to create certificate request"
            assert certReq.setCA(pathlen), "Unable to set certificate request as CA"
            cert = self.module.createCertificate(certReq, nscertlib.kSHA256, '1', None, 365)
            assert cert, "Unable to create certificate"
            pem_cert = cert.getCertificate(nscertlib.kPEM)
            assert pem_cert, "Unable to convert root CA to PEM format"
            validation.checkCA(pem_cert)
            validation.checkCAPathlen(pem_cert, pathlen)

    def generate_cert(self, root_key, root_cert,subject=None,cert_creation_should_fail=False,is_ca=True,dn_order = None):
        key = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert key, "Unable to create keys"
        if subject is None:
            subject = { "emailAddress" : "sdeepak@netsÃkope.com","CN" : "DEEPAK", "OU":"QAÃ", "O":"netSkope Inc大", "L" : "San Jose", "ST" : "CÃlifornia","C":"US"}
        if dn_order is None:
            cert_req = self.module.createCertificateRequest(subject, key)
        else:
            cert_req = self.module.createCertificateRequestWithDNPosition(subject, key, dn_order)
        if cert_req is None:
            return None,None
        assert cert_req, "Unable to create certificate request"
        if is_ca:
            assert cert_req.setCA(), "Unable to set certificate request as CA"
        assert ( \
            cert_req.addKeyUsage(nscertlib.kDigitalSignature) and \
            cert_req.addKeyUsage(nscertlib.kDataEncipherment) \
        ), "Unable to set key usage extensions"
        assert ( \
            cert_req.addAlternateName("www.deepak1.com") and \
            cert_req.addAlternateName("www.deepak2.com") \
        ), "Unable to add alternate names"
        assert ( \
            cert_req.addExtKeyUsage(nscertlib.kServerAuth) and \
            cert_req.addExtKeyUsage(nscertlib.kClientAuth) \
        ), "Unable to add extended key usage extensions"
        assert ( \
            cert_req.addNSCertType(nscertlib.kSSLClient) and \
           cert_req.addNSCertType(nscertlib.kSSLServer) \
        ), "Unable to add netscape certificate extensions"
        cert_req.setSerialInAuthKeyId()
        pem_root_cert = root_cert.getCertificate(nscertlib.kPEM)
        assert pem_root_cert, "Unable to convert certificate to PEM format"
        issuer = self.module.createIssuer(pem_root_cert, root_key)
        assert issuer, "Unable to create issuer"
        cert = self.module.createCertificate(cert_req, nscertlib.kSHA256, '2', issuer, 365)
        if cert_creation_should_fail:
            assert cert is None
        else:
            assert cert, "Unable to create certificate: {}".format(nscertlib.getNSCertLibError())
        return key, cert

    def generate_cert_csr(self, root_key, root_cert):
        key = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert key, "Unable to create keys"
        subject = {"emailAddress":"sdeepak@netsÃkope.com", "CN" :"DEEPAK", "OU":"QAÃ", "O":"netSkope Inc大","L" : "San Jose", "ST":"CÃlifornia", "C":"US"}
        csr_cert_req = self.module.createCertificateRequest(subject, key)
        assert csr_cert_req, "Unable to create certificate request"
        assert csr_cert_req.setCA(), "Unable to set certificate request as CA"
        assert ( \
            csr_cert_req.addKeyUsage(nscertlib.kDigitalSignature) and \
            csr_cert_req.addKeyUsage(nscertlib.kDataEncipherment) \
        ), "Unable to set key usage extensions"
        assert ( \
            csr_cert_req.addAlternateName("www.deepak1.com") and \
            csr_cert_req.addAlternateName("www.deepak2.com") \
        ), "Unable to add alternate names"
        assert ( \
            csr_cert_req.addExtKeyUsage(nscertlib.kServerAuth) and \
            csr_cert_req.addExtKeyUsage(nscertlib.kClientAuth) \
        ), "Unable to add extended key usage extensions"
        assert ( \
            csr_cert_req.addNSCertType(nscertlib.kSSLClient) and \
            csr_cert_req.addNSCertType(nscertlib.kSSLServer) \
        ), "Unable to add netscape certificate extensions"
        csr_cert_req.setSerialInAuthKeyId()
        pem_root_cert = root_cert.getCertificate(nscertlib.kPEM)
        assert pem_root_cert, "Unable to convert certificate to PEM format"
        issuer = self.module.createIssuer(pem_root_cert, root_key)
        assert issuer, "Unable to create issuer"
        csreq = csr_cert_req.getCsr(nscertlib.kSHA256)
        csr_cert = self.module.createCertificatewithCSR(csreq, nscertlib.kSHA256, '2', issuer, 365)
        assert csr_cert, "Unable to create certificate: {}".format(nscertlib.getNSCertLibError())
        
        return key, csr_cert

    def test_root_ca_creation(self):
        key, cert = self.generate_root_ca()
        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert root CA to PEM format"
        validation.matchCertAndKey(pem_cert, key.getPrivateKeyInfo(None))
        validation.validateSubject(pem_cert, 'subject= /CN=RootCA')
        validation.validateIssuer(pem_cert, 'issuer= /CN=RootCA')
        validation.validateSerial(pem_cert, 'serial=31')
        validation.checkStartDate(pem_cert)
        validation.checkEndDate(pem_cert, 365)
        validation.checkCA(pem_cert)
        validation.checkCAPathlen(pem_cert)
        validation.checkExtension(pem_cert, 'Digital Signature')
        validation.checkExtension(pem_cert, 'Non Repudiation')
        validation.checkExtension(pem_cert, 'Certificate Sign')
        validation.validateSelfSigned(pem_cert)

    def test_cert_creation(self):
        root_key, root_cert = self.generate_root_ca()
        key, cert = self.generate_cert(root_key, root_cert)

        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert certificate to PEM format"
        validation.matchCertAndKey(pem_cert, key.getPrivateKeyInfo(None))
        expected_subject = "/emailAddress=sdeepak@nets\\xC3\\x83kope.com/CN=DEEPAK/OU=QA\\xC3\\x83/O=netSkope Inc\\xE5\\xA4\\xA7/L=San Jose/ST=C\\xC3\\x83lifornia/C=US"
        validation.validateSubject(
            pem_cert,
            'subject= {}'.format(expected_subject)
        )
        validation.validateIssuer(pem_cert, 'issuer= /CN=RootCA')
        validation.validateSerial(pem_cert, 'serial=32')
        validation.checkStartDate(pem_cert)
        validation.checkEndDate(pem_cert, 365)
        validation.checkExtension(pem_cert, 'SSL Client')
        validation.checkExtension(pem_cert, 'SSL Server')
        validation.checkExtension(pem_cert, 'TLS Web Server Authentication')
        validation.checkExtension(pem_cert, 'TLS Web Client Authentication')
        validation.checkExtension(pem_cert, 'Digital Signature')
        validation.checkExtension(pem_cert, 'Data Encipherment')
        validation.checkExtension(pem_cert, 'DNS:www.deepak1.com')
        validation.checkExtension(pem_cert, 'DNS:www.deepak2.com')
        validation.validateCert(pem_cert, root_cert.getCertificate(nscertlib.kPEM))

    def test_cert_creation_csr(self):
        root_key, root_cert = self.generate_root_ca()
        key, cert = self.generate_cert_csr(root_key, root_cert)

        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert certificate to PEM format"
        validation.matchCertAndKey(pem_cert, key.getPrivateKeyInfo(None))
        expected_subject = "/emailAddress=sdeepak@nets\\xC3\\x83kope.com/CN=DEEPAK/OU=QA\\xC3\\x83/O=netSkope Inc\\xE5\\xA4\\xA7/L=San Jose/ST=C\\xC3\\x83lifornia/C=US"
        validation.validateSubject(
            pem_cert,
            'subject= {}'.format(expected_subject)
        )
        validation.validateIssuer(pem_cert, 'issuer= /CN=RootCA')
        validation.validateSerial(pem_cert, 'serial=32')
        validation.checkStartDate(pem_cert)
        validation.checkEndDate(pem_cert, 365)
        validation.checkExtension(pem_cert, 'SSL Client')
        validation.checkExtension(pem_cert, 'SSL Server')
        validation.checkExtension(pem_cert, 'TLS Web Server Authentication')
        validation.checkExtension(pem_cert, 'TLS Web Client Authentication')
        validation.checkExtension(pem_cert, 'Digital Signature')
        validation.checkExtension(pem_cert, 'Data Encipherment')
        validation.checkExtension(pem_cert, 'DNS:www.deepak1.com')
        validation.checkExtension(pem_cert, 'DNS:www.deepak2.com')
        validation.validateCert(pem_cert, root_cert.getCertificate(nscertlib.kPEM))

    def test_cert_creation_p12(self):
        root_key, root_cert = self.generate_root_ca()
        key, cert = self.generate_cert(root_key, root_cert)
        p12_cert = cert.getCertificate(nscertlib.kPKCS12, 'netskope')
        assert p12_cert, "Unable to convert certificate to PKCS12 format"
        pem_cert = validation.convertP12ToPem(p12_cert, 'netskope')
        validation.matchCertAndKey(pem_cert, key.getPrivateKeyInfo(None))
        expected_subject = "/emailAddress=sdeepak@nets\\xC3\\x83kope.com/CN=DEEPAK/OU=QA\\xC3\\x83/O=netSkope Inc\\xE5\\xA4\\xA7/L=San Jose/ST=C\\xC3\\x83lifornia/C=US"
        validation.validateSubject(
            pem_cert,
            'subject= {}'.format(expected_subject)
        )
        validation.validateIssuer(pem_cert, 'issuer= /CN=RootCA')
        validation.validateSerial(pem_cert, 'serial=32')
        validation.checkStartDate(pem_cert)
        validation.checkEndDate(pem_cert, 365)
        validation.checkExtension(pem_cert, 'SSL Client')
        validation.checkExtension(pem_cert, 'SSL Server')
        validation.checkExtension(pem_cert, 'TLS Web Server Authentication')
        validation.checkExtension(pem_cert, 'TLS Web Client Authentication')
        validation.checkExtension(pem_cert, 'Digital Signature')
        validation.checkExtension(pem_cert, 'Data Encipherment')
        validation.checkExtension(pem_cert, 'DNS:www.deepak1.com')
        validation.checkExtension(pem_cert, 'DNS:www.deepak2.com')
        validation.validateCert(pem_cert, root_cert.getCertificate(nscertlib.kPEM))

    def test_get_p12_cert(self):
        with open(CERTS_PATH + '/checking_cert.p12', 'rb') as fp:
            p12_data = fp.read()
        cert = self.module.getCertificate(nscertlib.kPKCS12, p12_data, 'netskope')
        assert cert, "Unable to parse PKCS12 certificate"
        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert certificate to PEM format"
        validation.validateSubject(
            pem_cert,
            'subject= /C=US/ST=CA/L=Los Altos/O=Umbrella Corp/OU=OPS/CN=encrypt.umbrella.stg.local/emailAddress=certadmin@netskope.com',
        )
        validation.validateIssuer(
            pem_cert,
            'issuer= /C=US/ST=CA/L=Los Altos/O=Umbrella Corp/OU=OPS/CN=ca.umbrella.stg.local/emailAddress=certadmin@netskope.com',
        )
        validation.checkExtension(pem_cert, 'SSL Client')
        keys = cert.getKeys()
        privKeyInfo = keys.getPrivateKeyInfo(None)
        pubKeyInfo = keys.getPEMPublicKey()
        assert privKeyInfo and pubKeyInfo, 'Unable to get keys'
        validation.matchKeyPair(privKeyInfo, pubKeyInfo)
        validation.matchCertAndKey(pem_cert, privKeyInfo)
        cert = validation.convertP12ToPem(p12_data, 'netskope')
        serial = validation.getSerial(cert)
        validation.validateSerial(pem_cert, serial)

    def test_get_p12_passless_cert(self):
        with open(CERTS_PATH + '/passless.p12', 'rb') as fp:
            p12_data = fp.read()
        cert = self.module.getCertificate(nscertlib.kPKCS12, p12_data, None)
        assert cert, "Unable to get certificate for PKCS12 file"
        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert to PEM format"
        keys = cert.getKeys()
        privKeyInfo = keys.getPrivateKeyInfo(None)
        pubKeyInfo = keys.getPEMPublicKey()
        assert privKeyInfo and pubKeyInfo, "Unable to get keys"
        validation.matchKeyPair(privKeyInfo, pubKeyInfo)
        validation.matchCertAndKey(pem_cert, privKeyInfo)
        cert = validation.convertP12ToPem(p12_data, '')
        serial = validation.getSerial(cert)
        validation.validateSerial(pem_cert, serial)

    def test_get_pem_cert(self):
        with open(CERTS_PATH + '/checking_cert.pem', 'rb') as fp:
            pem_data = fp.read()
        cert = self.module.getCertificate(nscertlib.kPEM, pem_data)
        assert cert, "Unable to parse PEM certificate"
        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert back to PEM format"
        keys = cert.getKeys()
        privKeyInfo = keys.getPrivateKeyInfo(None)
        validation.matchPemCerts(pem_data, pem_cert + b'\n' + privKeyInfo)
        serial = validation.getSerial(pem_data)
        validation.validateSerial(pem_cert, serial)

    def test_resign_cert(self):
        root_key, root_cert = self.generate_root_ca()
        pem_root_cert = root_cert.getCertificate(nscertlib.kPEM)
        assert pem_root_cert, "Unable to convert to PEM format"
        issuer = self.module.createIssuer(pem_root_cert, root_key)
        with open(CERTS_PATH + "/checking_cert.pem", 'rb') as fp:
            pem_cert = fp.read()
        cert = self.module.getCertificate(nscertlib.kPEM, pem_cert)
        assert cert, "Unable to parse PEM certificate"
        assert cert.resign(issuer, '\t', nscertlib.kSHA256), "Unable to resign certificate"
        pem_cert = cert.getCertificate(nscertlib.kPEM)
        assert pem_cert, "Unable to convert to PEM format"
        validation.validateSubject(
            pem_cert,
            'subject= /C=US/ST=California/L=Los Altos/O=netSkope Inc/OU=IndiaDev/CN=caadmin.indiadev.local/emailAddress=linto@netskope.com',
        )
        validation.validateIssuer(pem_cert, 'issuer= /CN=RootCA')
        validation.checkCA(pem_cert)
        validation.validateCert(pem_cert, pem_root_cert)
        validation.checkExtension(pem_cert, 'Signature Algorithm: sha256WithRSAEncryption')
        validation.validateSerial(pem_cert, 'serial=09')


    @pytest.mark.parametrize(        
        'params', [
                   pytest.param(InOut({},"",is_ca=False), id="empty_leaf"), 
                   pytest.param(InOut({},"",should_fail=True), id="empty_ca"), 
                   pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, L=San Jose, ST=California, C=US"), id="all_values"),
                    pytest.param(InOut({"CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "ST":"California", "C":"US"},
                                        "CN=DEEPAK, OU=QA, O=netSkope Inc, L=San Jose, ST=California, C=US"), id="no email"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, OU=QA, O=netSkope Inc, L=San Jose, ST=California, C=US"), id="no_cn"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "O" : "netSkope Inc","L" : "San Jose", "ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, O=netSkope Inc, L=San Jose, ST=California, C=US"), id="no_ou"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "L" : "San Jose", "ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, L=San Jose, ST=California, C=US"), id="no_o"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, ST=California, C=US"), id="no_l"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, L=San Jose, C=US"), id="no_st"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "ST":"California"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, L=San Jose, ST=California"), id="no_c"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK","Y":"YY", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose", "ST":"California", "C":"US","X":"XX"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, L=San Jose, ST=California, C=US"), id="unknown_name"),
                    pytest.param(InOut({"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "O" : "netSkope Inc","L" : "San Jose,comma,comma", "ST":"California", "C":"US"},
                                        "emailAddress=sdeepak@netskope.com, CN=DEEPAK, OU=QA, O=netSkope Inc, L=\"San Jose,comma,comma\", ST=California, C=US"), id="commas"),
                    pytest.param(InOut({"emailAddress" : "sdఆepak@netskope.com","CN":"DEோPAK", "OU" :"QA", "O" : "netSkopeぉ Inc","L" : "San 	ᑚJose", "ST":"Califほornia", "C":"US"},
                                        "emailAddress=sd\\E0\\B0\\86epak@netskope.com, CN=DE\\E0\\AF\\8BPAK, OU=QA, O=netSkope\\E3\\81\\89 Inc, L=San \\09\\E1\\91\\9AJose, ST=Calif\\E3\\81\\BBornia, C=US"), id="unicode")                    
                   ])
    def test_subject(self,params):
        root_key, root_cert = self.generate_root_ca()
        _, cert = self.generate_cert(root_key, root_cert,params.input,cert_creation_should_fail=params.should_fail,is_ca=params.is_ca)
        if params.should_fail:
            assert cert is None
        else:
            with open(f"/tmp/cert_{self.count}","w+") as f:
                cert_pem = cert.getCertificate(nscertlib.kPEM)
                assert cert_pem
                f.write(cert_pem.decode())
            self.count += 1
            assert params.output == cert.getSubjectName().decode('utf-8')
    def test_bad_cert(self):
        #this certificate has additional certs, which caused a segfault due to 
        #an unintalized stack of 509 pointer (ENG-388261)
        cert = "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCClYwgDCABgkqhkiG9w0BBwGggCSABIIFNjCCBTIwggUuBgsqhkiG9w0BDAoBAqCCBPYwggTyMCQGCiqGSIb3DQEMAQMwFgQQ/Rx1qScZ3xlIKSw8Mth1GgICB9AEggTIKuf/0Z3XAhpqfDGARNFkpTbRka6eWRcm4qNg0PJqQuQ1vCf2+yb44mwynJoDXIQPlCouDtYyPoDxMgDZE9jYW4YhYftPKfc7uewqo7hGgk96OJlD4UrKPyZ2L3zgctqy+RsI8ucRnJCv7nqa66Car0tGQuQbUtd0Lu2kd6qhTCQC/yXBrsM8NuuV783Lg9IKpbBobs5CPmMMTkYzXBZ3VMYlpMfcjM35KIYvz6t6iq8ATMj14DTFTfTipkQ2nlVfY12D9snFzMDMFFvn1r9hBcYiqWW9Gi+vnc/96i9soBbRjRYPV+paw69pQ63pw/LfPlwMKNLEYOf9GG1F3rAKXzmuaWt9pKrk2UCZp7MtSNnNTNquzMQiDhWIu8A7fXPxuCM9vDf++VhO2t0Vdx+/kxtUtjD9JhbIBoVMZL0RV5qbn5VhsRoP8TaaimrxkXlMyjNncYmmJouhtj8nKQxsM+7kCubvrZB9Hu1uplzbedCjiISm5Pjh75yL2muQUD9jCxOaWuUqQe7rbvcTQCBIu0vm6UzK8Iwwa/HbmeMTJRZvpzv7OLzSHTL8yCZwgJ6eqTDDZ9GHsNM/HkHeuO/5OqiArsyLPpePTZUgDdOjhmUo8zmWLkOveNGYTdllDDziufZv7ZsxpMeFAtiwI7JszenfbdKxRYz70ThVyIRZvNzzcuKD12mI0qdfnns4d7tPLtd0u8Cs2VFxSxc+YqyTPUYCZpCKpPGZvZ6XEyvejHFmcq03oySaEnVoD45mYoWKexiQ19CKd8e8/ve+cTNGwb3jQjw70AdMJI2TCT6+SXZuPtI5KuGo9NQ7LyWyqQkv/xcUOrE7s/5Y1LLgXkUFWkIZcDxWMsFNQqRVTBXl2f2/2tgBfvQWUHmZ2zMiZSJqMukSX4R60bESIwQbfGovfTRvPJZidk2uEkyig9aCMVoIv0UrKLLjyS3pxXbhzsF8ML9W1429swILjHM2JsP2IohjvFE9Nwj8c6RdWMq7j9dctrNBbkLPBsFOyvIqse8PpQqMwZ++5PqmsDNbJINF/g0gXDggBwI+OdG0s2tUhtdy1ADqUckdxdeFsqYrM7AM+c/n+stcWzLa5UXxf+rVSfP438N+SPEr2k0rWOraMdrN/5m+xtgxuT1AZb367UfuWwJMS/QUG9fLaX6CsTBRgH9jobz8bnKTpGUONN/FpTYtJzrIVsHosakRFfIieY8J5FH+LFBOZPuFR8rSZ8mf2/clVbIxYCQ+WKXB18FaieBdJRNnkv/7G0XfwdQtHzRj4RxqlHX3frpIOTBeavmbW+IC/xoWLYd3Z1VI4zPo87LCy9OmshC87EIKFNBtFAWlbtkKZfpE7B40n/rDGgeEkGIwdVbKCLf2M1kpETClgji0VWytbXJt5RUkP4/fgDerZBf5dg+0d1uvTer68ZMjI0lMNr7HQTKQlck24y+Bs6VXusYR1/qzyDTLRrUD3OsQugiF1snCRWmq8xlIHmWu1t15n6aa3Lvocf0uSQd+5uP+G1kISuc+CtEUuuvVl/EFlxprTl4nGZUA0zimuFfSVMjzSfntbmhRj/mZXb6hiL+0SfF2Xt5JWefzNo0zzZYXst3ugScmMo86et7v2t+B+v44PHC9tiyfMSUwIwYJKoZIhvcNAQkVMRYEFHOFxy/uorOtW0qrNyqNw2wGgAC/AAAAAAAAMIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMCQGCiqGSIb3DQEMAQYwFgQQGGRHUDKGtrvuJn1DOaWPVgICB9CggASCBKA+q9TLrU1LZifAIz2yQ00nJ2YbeI5lkhIH77YhBK49xBwc0jvZDxl2jAnueUr/FLaUBZKN780XFkojtnBq2Y3Kn0iZ7aCH4kTlPDL9zxFPy6kW6vQQUVaPEPkUY1Vn5znYNne5uBkBels+V8TVa3TP1hMiuzE9Wa7GMbT4vLQqM3d/dOT0xjMY6B63cagDQeXDvzuRoq9vpC2vMdujLLmt7eYeYMdJMAsGIpFfPpi4EKKF5nIE23b0/IGq+/Z2E4v2veHf/gBoTagORGnWGolHiY98xwle6bxSVnlv8Q8mtTMlMmFTI3/498gd1fcuVvJepswL6w85EB22Cz8kJHW9bqhoWLAZ/bXEm7jKVgSXKhIikwQazvQspW/Zs5/FbjNV2xX5SRwyTKfbJPP05lBvOGPa/bGp481CxWd6ts4w35oP+anyyhUvK/2RweLfawmP5hiaeBZjK85Bfskhtza7Y7s5uS8c0N2R07qeu3fokVvPCBfwosOwVMd4Y7//cULMSvNOROqZ1mwr9FOgzJmv+RDtYnhzbi0f9uVFyXwuxRVc+qfRl8lHvwo/+ZBs0TBFOJ4d2l4ah+w69ZT5ZsngatUt+nM5nKH7IflHHLL5JS0wlDQKL/5U9AyphZYc163sa9KZYMybSRnA3N+wDT+N/Uey1qGm2/L50dndAyK2FrRG21xA6pAngmPeVq1gmGJf4fkuQq7ylUtDCHJyno0cXcZUS1lVYWd46kiMIJ2jOqS8kB9e4FfMyNvAK/cloJBkXIios92W01iZpKfPeLW2elcm4lOzA4meWpz8ShUYYSVlw8Hg9n4h1ipmhczA2BF1XzZhXREYhmbvj0JgwST3GKPjmn8MlWExraUNMkhX0R1WQL67JjBizvK5OvkB4IyP8RSqbhBhWe+7r60/uYi5mHtvz3afNx9dwJkIzAtEYfgkl1RpTpPAT91CTnJQVIItE/fjEWQXe4fn+Fbok2QEA2sPeTVjvfADbIEpb6SdnNOOogULc+NWajYc+je8GI5etFSLFGn5vdaUjHffTmcS8OVBw+bSt6C8oco2wjYDx1P3fA3ZsCEjcWk1JXsoOQ72ZV02ZcYyAHbentJfJTGHaHjnwxF28NgLlSemxe8CM3bdpuIDdFR8pZp4qmGTcvZDOMbxAKvNS48/gNqGpWVm0YLTaPdC7oecd42yFl8ZjDXhB27GV8jfQ9waXuE2Iz8wXSI4KZhPaTsL64OXeOqMhBQDaKajC9IpF0QMzheAA9DrAd4qhTXmo2N7XaG7QXzKwIGZ/9O8P9ZyDdmYuJTxb+ovcar5IsiMRHwlLzIIjbnQh59YBuzEn6Y052a7h6aDenxwZP3HXYfR7iKITzyFoGCDX9yf50X6Nu9AziXES8lZ+4x+m5i1QcPS+6USZkevkibCZB2KbqXu2OECRHXVv2dyhJkXTWEnYItQVUFf7E4hbYk65XfexsBXkke82oq4Zqc/rHJC2Jusj/GQW71le5O4DqJ5ij52Gnmf+ioTxL3Kj/ALyrh7dG4BwySM0M2svqlriB2EVzd4dZQ3Dseo1kqnO4MQRdSyO3zGlNpGuQQIUVoaJu7lTwQAAAAAAAAAAAAAAAAAAAAAAAAwOTAhMAkGBSsOAwIaBQAEFAkeVE8VbUHAAL1kBtD6HbaNnh8OBBC8cscFMidNngQ+4VatGMvLAgIH0AAA"
        pkcs12_decoded = base64.b64decode(cert)
        module = nscertlib.getModule(self.CERT_CONFIG, False)
        nscerlib_cert_obj = module.getCertificate(nscertlib.kPKCS12,pkcs12_decoded,"")
        assert nscerlib_cert_obj is None #no cert in pkcs12 archive
        assert "Certificate not present in pkcs12 archive" in nscertlib.getNSCertLibError() 
        pkcs12_cert = pkcs12.load_pkcs12(pkcs12_decoded,b"")
        assert pkcs12_cert.additional_certs is not None #there are additional cert certs in the archive
    
    @pytest.mark.parametrize(        
        'params', [
                   pytest.param({"subject" :{"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "L" : "San Jose", "ST":"California", "C":"US","O":"None"},
                                "order" : ["C","OU","L","O","emailAddress","ST","CN"],
                                "fail" : False  }, id="order_all"),
                    pytest.param({"subject" :{"emailAddress" : "sdeepak@netskope.com"},
                                "order" : ["emailAddress"] ,
                                "fail" : False  }, id="order_email_only"),
                    pytest.param({"subject" :{},
                                "order" : [],"fail" : False  }, id="empty subject, empty order"),
                    pytest.param({"subject" :{},
                                "order" : ["C","OU","L","O","emailAddress","ST","CN"],"fail" : True  }, id="empty subject, populated order"),
                    pytest.param({"subject" :{"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA"},
                                "order" : ["C","OU","L","O","emailAddress","ST","CN"], "fail" : True }, id="order_more_than_subject"),
                    pytest.param({"subject" :{"emailAddress" : "sdeepak@netskope.com","CN":"DEEPAK", "OU" :"QA", "L" : "San Jose", "ST":"California", "C":"US","O":"None"},
                                "order" : ["C","OU","L","O"],"fail" : True  }, id="order_less_than_subject"),
        ]
    )
    def test_subject_ordering(self,params):
        root_key, root_cert = self.generate_root_ca()
        subject = copy.deepcopy(params["subject"])
        dn_order = copy.deepcopy(params["order"])
        _, cert = self.generate_cert(root_key, root_cert,subject,cert_creation_should_fail=params["fail"],is_ca=False,dn_order=dn_order)

        if params["fail"]:
            assert cert is None
            assert "position list size must be equal to number of subject values list" in nscertlib.getNSCertLibError()
        else:
            cert : nscertlib.Certificate = cert
            cert_pem = cert.getCertificate(nscertlib.kPEM)
            x509_cert =  crypto.load_certificate(crypto.FILETYPE_PEM,cert_pem)

            for name,value in x509_cert.get_subject().get_components():
                dn_order.pop(0) == name.decode()
                assert subject[name.decode()] == value.decode()
    
    @pytest.mark.parametrize(
        'params', [
                pytest.param({"subject": {"emailAddress": "admin@netskope.com", "CN": "ADMIN", "OU": "QA", "L": "San Jose", "ST": "California", "C": "US", "O": "netSkope Inc"},
                              "order": ["C", "OU", "L", "O", "emailAddress", "ST", "CN"],
                              "expected": "C=US, OU=QA, L=San Jose, O=netSkope Inc, emailAddress=admin@netskope.com, ST=California, CN=ADMIN"}, id="ordered"),
                pytest.param({"subject": {"emailAddress": "admin@netskope.com", "CN": "ADMIN", "OU": "QA", "L": "San Jose", "ST": "California", "C": "US", "O": "netSkope Inc"},
                              "order": None,
                              "expected": "emailAddress=admin@netskope.com, CN=ADMIN, OU=QA, O=netSkope Inc, L=San Jose, ST=California, C=US"},
                             id="default_order"),
            ]
    )
    def test_subject_printable_encoding(self, params):
        _, cert = self.generate_root_ca_printable_subject(
            params["subject"], params["order"])
        assert params["expected"] == cert.getSubjectName().decode('utf-8')
        x509_cert = load_pem_x509_certificate(
            cert.getCertificate(nscertlib.kPEM))
        rdns = x509_cert.subject.rdns
        for r_entry in rdns:
            for attribute in r_entry:
                if attribute._oid == NameOID.EMAIL_ADDRESS:
                    assert attribute._type == _ASN1Type.IA5String
                else:
                    assert attribute._type == _ASN1Type.PrintableString
