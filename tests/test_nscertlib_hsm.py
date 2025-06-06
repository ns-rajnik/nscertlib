import pytest
import nscertlib
import os
import importlib

CERTS_PATH = os.path.dirname(os.path.realpath(__file__)) + '/certs'

@pytest.fixture(scope="module", params=[
    { 'useGemEngine': True },
    { 'useGemEngine': False }
])
def feature_flags(request):
    os.environ['TESTENV'] = "1"
    return request.param

class TestBase:

    CERT_CONFIG_HSM = os.path.dirname(os.path.realpath(__file__)) + '/cert_config_hsm.json'

    def module_hsm(self, feature_flags):
        return nscertlib.getModule(self.CERT_CONFIG_HSM, feature_flags['useGemEngine'])
    
    @pytest.mark.forked
    def test_module_initialization_hsm(self, feature_flags):
        assert self.module_hsm(feature_flags).isInitialized() == False, "Module initialization passed"
