"""Tests for certbot_plugin_edgedns.edgedns."""

import unittest
import copy
import mock
import json
import requests_mock
import requests

from certbot import errors
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_ACCESS_TOKEN = "akab-1234567890qwerty-asdfghjklzxcvtnu"
FAKE_CLIENT_TOKEN = "akab-mnbvcxzlkjhgfdsapoiuytrewq1234567"
FAKE_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG="
FAKE_HOST = "akab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.luna.akamaiapis.net"

PATH = ""

class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_plugin_edgedns.edgedns import Authenticator

        creds_ini_path = os.path.join(self.tempdir, "file_creds.ini")
        dns_test_common.write(
            {
                "edgedns_client_token": FAKE_CLIENT_TOKEN,
                "edgedns_client_secret": FAKE_CLIENT_SECRET,
                "edgedns_access_token": FAKE_ACCESS_TOKEN,
                "edgedns_host": FAKE_HOST,
            },
            creds_ini_path,
        )
        
        dot_edgerc_path = os.path.join(self.tempdir, ".edgerc")
        with open(dot_edgerc_path, 'w') as h:
            h.write('[default]')
        dns_test_common.write(
            {
                "client_token": FAKE_CLIENT_TOKEN,
                "client_secret": FAKE_CLIENT_SECRET,
                "access_token": FAKE_ACCESS_TOKEN,
                "host": FAKE_HOST,
            },
            dot_edgerc_path,
        )
        edgerc_ini_path = os.path.join(self.tempdir, "file_edgerc.ini")
        dns_test_common.write(
            {
                "edgedns_edgerc_path": dot_edgerc_path,
                "edgedns_edgerc_section": "default",
            },
            edgerc_ini_path,
        )

        super(AuthenticatorTest, self).setUp()
        # creds ini path 
        self.config = mock.MagicMock(
            edgedns_credentials=creds_ini_path, _edgedns_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "edgedns")

        # creds edgerc file
        self.config_edgerc = mock.MagicMock(
            edgedns_credentials=creds_ini_path, _edgedns_propagation_seconds=0
        )  # don't wait during tests

        self.auth_edgerc = Authenticator(self.config_edgerc, "edgedns")

        # ini creds
        self.mock_client = mock.MagicMock()
        # _get_edgedns_client | pylint: disable=protected-access
        self.auth._get_edgedns_client = mock.MagicMock(return_value=self.mock_client)

        # edgerc
        self.mock_client_edgerc = mock.MagicMock()
        # _get_edgedns_client | pylint: disable=protected-access
        self.auth_edgerc._get_edgedns_client = mock.MagicMock(return_value=self.mock_client_edgerc)

    def test_perform(self):

        # creds ini
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

        # edgerc 
        self.auth_edgerc.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client_edgerc.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access

        # creds ini
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

        # edgerc
        self.auth_edgerc._attempt_cleanup = True
        self.auth_edgerc.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY,
            )
        ]
        self.assertEqual(expected, self.mock_client_edgerc.mock_calls)


class EdgeDNSClientTest(unittest.TestCase):

    FAKE_ENDPOINT = "https://" + FAKE_HOST + "/config-dns/v2"
    TEST_ZONE = "certbottest.zone"
    RECORD_NAME = "certbot_txt"
    RECORD_CONTENT = "1234567890abcdefghijklmnopqrstuvwxyz"
    RECORD_ADDTL_CONTENT = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    RECORD_TTL = 400

    GET_ZONE_RESP =  {
        "contractId": "1-2ABCDE",
        "zone": TEST_ZONE,
        "type": "primary",
        "aliasCount": 1,
        "signAndServe": True,
        "signAndServeAlgorithm": "RSA_SHA256",
        "versionId": "ae02357c-693d-4ac4-b33d-8352d9b7c786",
        "lastModifiedDate": "2017-01-03T12:00:00Z",
        "lastModifiedBy": "user28",
        "lastActivationDate": "2017-01-03T12:00:00Z",
        "activationState": "ACTIVE"
    }

    TXT_GET_RECSET_RESP = {
        "name": "{0}.{1}".format(RECORD_NAME, TEST_ZONE),
        "type": "TXT",
        "ttl": RECORD_TTL,
        "rdata": [ RECORD_CONTENT ]
    }

    def setUp(self):
        from certbot_plugin_edgedns.edgedns import _EdgeDNSClient

        self.session = requests.Session()
        self.adapter = requests_mock.Adapter()
        self.session.mount('https://', self.adapter)
        
        EDGEGRID_CREDS = {"client_token": FAKE_CLIENT_TOKEN,
                          "client_secret": FAKE_CLIENT_SECRET,
                          "access_token": FAKE_ACCESS_TOKEN,
                          "host": FAKE_HOST}

        self.client = _EdgeDNSClient(EDGEGRID_CREDS)

    def _register_response(
        self, req_op, req_uri, url_params=None, response=None, message=None, additional_matcher=None, **kwargs
    ):
        resp = {"code": "ok", "message": message, "response": response}
        if message is not None:
            resp["code"] = "remote_failure"
        url = req_uri
        if url_params is not None:
            url += "?" + url_params
        self.adapter.register_uri(
            req_op,
            "{0}".format(url),
            text=response,
            **kwargs
        )

    def test_add_txt_record(self):
        print("*** test_add_txt_record ***")
        self.adapter.reset()								# clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, response=zone_resp_json, status_code=200)

        # Get Recordset... Doesn't exist
        recset_resp_json = json.dumps(self.TXT_GET_RECSET_RESP)
        recordset_get_url = "{0}/zones/{1}/names/{2}/types/TXT".format(self.FAKE_ENDPOINT, self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"])
        self._register_response('GET', recordset_get_url, message='Not Found', status_code=404)

        # Add Recordset (create recordset)
        recordset_json = json.dumps(self.TXT_GET_RECSET_RESP)
        self._register_response('POST', recordset_get_url, response=recset_resp_json, status_code=201)

        # add_txt_record(self, domain, record_name, record_content, record_ttl=RECORD_TTL)
        self.client.add_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_CONTENT, self.RECORD_TTL)

    def test_add_existing_txt_record(self):
        print("*** test_add_existing_txt_record ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, response=zone_resp_json, status_code=200)

        # Get Recordset
        recset_resp_json = json.dumps(self.TXT_GET_RECSET_RESP)
        recordset_get_url = "{0}/zones/{1}/names/{2}/types/TXT".format(self.FAKE_ENDPOINT, self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"])
        self._register_response('GET', recordset_get_url, response=recset_resp_json, status_code=200)

        # Add Recordset (create recordset)
        recset_copy = copy.deepcopy(self.TXT_GET_RECSET_RESP)
        recset_copy["rdata"].append(self.RECORD_ADDTL_CONTENT)
        recset_resp_json = json.dumps(recset_copy)
        self._register_response('PUT', recordset_get_url, response=recset_resp_json, status_code=201)

        # add_txt_record(self, domain, record_name, record_content, record_ttl=RECORD_TTL)
        self.client.add_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT, self.RECORD_TTL)

    def test_add_txt_record_fail_to_find_domain(self):
        print("*** test_add_txt_record_fail_to_find_domain ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, "FailDomainGet")
        self._register_response('GET', zone_get_url, message="Not Found", status_code=404)

        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT, self.RECORD_TTL)

    def test_add_txt_record_fail_to_authenticate(self):
        print("*** test_add_txt_record_fail_to_authenticate ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        self._register_response('GET', zone_get_url, message="Not Authorized", status_code=403)

        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT, self.RECORD_TTL)
 
    def test_del_txt_record(self):
        print("*** test_del_txt_record ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, response=zone_resp_json, status_code=200)

        # Get Recordset
        recset_resp_json = json.dumps(self.TXT_GET_RECSET_RESP)
        recordset_get_url = "{0}/zones/{1}/names/{2}/types/TXT".format(self.FAKE_ENDPOINT, self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"])
        self._register_response('GET', recordset_get_url, response=recset_resp_json, status_code=200)

        # Delete Recordset (delete recordset)
        self._register_response('DELETE', recordset_get_url, status_code=204)

        # del_txt_record(self, domain, record_name, record_content)
        self.client.del_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_CONTENT)

    def test_del_existing_txt_record(self):
        print("*** test_del_existing_txt_record ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, response=zone_resp_json, status_code=200)

        # Get Recordset
        recset_copy = copy.deepcopy(self.TXT_GET_RECSET_RESP)
        recset_copy["rdata"].append(self.RECORD_ADDTL_CONTENT)
        recset_resp_json = json.dumps(recset_copy)
        recordset_get_url = "{0}/zones/{1}/names/{2}/types/TXT".format(self.FAKE_ENDPOINT, self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"])
        self._register_response('GET', recordset_get_url, response=recset_resp_json, status_code=200)

        # Delete Recordset (update)
        recordset_json = json.dumps(self.TXT_GET_RECSET_RESP)
        self._register_response('PUT', recordset_get_url, response=recset_resp_json, status_code=200)

        # add_txt_record(self, domain, record_name, record_content, record_ttl=RECORD_TTL)
        self.client.del_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT)

    def test_del_txt_record_fail_to_find_domain(self):
        print("*** test_del_txt_record_fail_to_find_domain ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, "FailDomainGet")
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, message="Not Found", status_code=404)

        with self.assertRaises(errors.PluginError) as context:
            self.client.del_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT)


    def test_del_txt_record_fail_to_authenticate(self):
        print("*** test_del_txt_record_fail_to_authenticate ***")
        self.adapter.reset()                                                            # clear any existing uri mappings
        self.client.set_session(self.session)

        # Get Zone
        zone_get_url = "{0}/zones/{1}".format(self.FAKE_ENDPOINT, self.TEST_ZONE)
        zone_resp_json = json.dumps(self.GET_ZONE_RESP)
        self._register_response('GET', zone_get_url, message="Unauthorized", status_code=403)

        with self.assertRaises(errors.PluginError) as context:
            self.client.del_txt_record(self.TEST_ZONE, self.TXT_GET_RECSET_RESP["name"], self.RECORD_ADDTL_CONTENT)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
