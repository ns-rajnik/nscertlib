import os
os.environ['TESTENV'] = "1"

import pytest
import nscertlib


CERTS_PATH = os.path.dirname(os.path.realpath(__file__)) + '/certs'

@pytest.mark.parametrize(
    "use_gem_engine", [
        pytest.param(True, id="use_gem_engine"),
        pytest.param(False, id="dont_use_gem_engine")
    ]
)
@pytest.mark.forked
class TestPrivateDecrypt:
    CERT_CONFIG = os.path.dirname(os.path.realpath(__file__)) + '/cert_config.json'

    @pytest.fixture(autouse=True)
    def module(self, use_gem_engine):
        self.module = nscertlib.getModule(self.CERT_CONFIG, use_gem_engine)
    
    @pytest.mark.parametrize(        
        'key_len', [ pytest.param(nscertlib.k1024, id='rsa_1024'),
                     pytest.param(nscertlib.k2048, id='rsa_2048'),
                     pytest.param(nscertlib.k4096, id='rsa_4096') ])
    def test_encrypt_decrypt(self, key_len):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, key_len)
        buffer = b'1234567891234567698621367897218'
        encbuffer = keys.publicEncrypt(buffer)
        x = nscertlib.getNSCertLibError()
        assert encbuffer is not None
        assert encbuffer != buffer
        decbuffer = keys.privateDecrypt(encbuffer)
        assert decbuffer == buffer

    @pytest.mark.parametrize(        
        'key_len', [ pytest.param(nscertlib.k1024, id='rsa_1024'),
                     pytest.param(nscertlib.k2048, id='rsa_2048'),
                     pytest.param(nscertlib.k4096, id='rsa_4096') ])
    def test_encrypt_input_size(self, key_len):
        #check around (RSA key size - 42) which is the size of PKCS1 OEAP padding len
        keys = self.module.createAsymKeyPair(nscertlib.kRSA,key_len)
        
        rsa_size_bytes = int(key_len / 8)

        input_max_valid = bytearray(rsa_size_bytes - 42)
        mid = int(len(input_max_valid) / 2)
        input_max_valid[mid] = 1
        input_max_valid[mid - 1] = 2
        input_max_valid[mid + 1] = 3
        encbuffer = keys.publicEncrypt(bytes(input_max_valid))
        decbuffer = keys.privateDecrypt(encbuffer)
        assert encbuffer != None and decbuffer == bytes(input_max_valid)

        encbuffer = keys.publicEncrypt(bytes(bytearray(rsa_size_bytes - 43)))
        assert encbuffer != None

        encbuffer = keys.publicEncrypt(bytes(bytearray(rsa_size_bytes - 41)))
        assert encbuffer == None

    def test_private_decrypt_fail(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        assert keys.privateDecrypt(b'0000') is None
