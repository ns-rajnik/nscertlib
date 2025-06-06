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
class TestSignAndVerify:
    CERT_CONFIG = os.path.dirname(os.path.realpath(__file__)) + '/cert_config.json'

    @pytest.fixture(autouse=True)
    def module(self, use_gem_engine):
        self.module = nscertlib.getModule(self.CERT_CONFIG, use_gem_engine)

    @pytest.mark.parametrize(
        "param",[
            pytest.param({'buffer':b'12345678999991111991919199199999'},id="32_byte"),
            pytest.param({'buffer':b'123456789999911119919191991999995432345678765432'},id="48_byte"),
            pytest.param({'buffer':b'1234567899999111199191919919999954323456787654328765434567876543'},id="64_byte"),
    ])
    def test_sign_and_verify(self, param):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        encbuffer = keys.sign_digest(param['buffer'])
        assert encbuffer != None
        assert keys.verify_digest(param['buffer'], encbuffer)

    def test_sign_fail(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        encbuffer = keys.sign_digest(b'1234567899999111199191919919999')
        assert encbuffer == None

    def test_verify_fail(self):
        keys = self.module.createAsymKeyPair(nscertlib.kRSA, nscertlib.k2048)
        buffer = b'12345678999991111991919199199999'
        malformed_buffer = b'2345678999991111991919199199999'
        encbuffer = keys.sign_digest(buffer)
        assert keys.verify_digest(malformed_buffer, encbuffer) == False
