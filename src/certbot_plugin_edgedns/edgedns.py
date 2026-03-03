"""DNS Authenticator for Akamai EdgeDNS."""
import copy
import json
import logging
import requests
import threading
from certbot.compat import os
import sys
import zope.interface

from urllib.parse import urljoin

from akamai.edgegrid import EdgeGridAuth, EdgeRc

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

EDGEGRID_URL = 'https://developer.akamai.com/api/getting-started'
EDGEGRID_CREDS = {"client_token": "",
                  "access_token": "",
                  "client_secret": "",
                  "host": "",
                  "edgerc_path": "",
                  "edgerc_section": "",
                  "account_key": ""
                 }
RECORD_TTL = 600
DEFAULT_PROPAGATION_DELAY = 180

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Akamai EdgeDNS

    This Authenticator uses the Akamai EdgeDNS v2 REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Akamai EdgeDNS for DNS)."
    section = "default" 

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None
        self.edge_client = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super().add_parser_arguments(
            add, default_propagation_seconds=DEFAULT_PROPAGATION_DELAY
        )
        add("credentials", help="EdgeDNS credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the EdgeDNS Remote REST API."
        )

    def _validate_credentials(self):

        EDGEGRID_CREDS["edgerc_path"] = edgerc = self.credentials.confobj.get('edgerc_path')
        EDGEGRID_CREDS["edgerc_section"] = section = self.credentials.confobj.get('edgerc_section')
        if edgerc:
            if not section:
                EDGEGRID_CREDS["edgerc_section"] = "default"
                print("No edgerc section provided. Using 'default'")
            return

        EDGEGRID_CREDS["client_token"] = client_token = self.credentials.confobj.get('client_token')
        EDGEGRID_CREDS["client_secret"] = client_secret = self.credentials.confobj.get('client_secret')
        EDGEGRID_CREDS["access_token"] = access_token = self.credentials.confobj.get('access_token')
        EDGEGRID_CREDS["host"] = host = self.credentials.confobj.get('host')
        EDGEGRID_CREDS["account_key"] = self.credentials.confobj.get('account_key')

        errmsg = ''
        missing = 0
        if not client_token:	
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'client_token'
        if not client_secret:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'client_secret'
        if not access_token:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'access_token'
        if not host:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'host'
        if not edgerc and missing == 4:
            raise errors.PluginError(
                f"{self.credentials.confobj.filename}: Either an edgerc_path or individual edgegrid credentials are required "
                f"when using the EdgeDNS API (see {EDGEGRID_URL})"
            )
        if errmsg != '':
            if missing == 1:
                errmsg += ' is '
            else:
                errmsg += ' are '
            errmsg += 'required when specifying individual edgegrid credentials ' 
            raise errors.PluginError(
                f"{self.credentials.confobj.filename}: {errmsg} for using the EdgeDNS API (see {EDGEGRID_URL})"
            )

    def _setup_credentials(self):

        self.credentials = self._configure_credentials(
            "credentials",
            "EdgeDNS credentials INI file",
            None,
        )

        try:
            self._validate_credentials()
        except errors.PluginError:
            raise

    def _perform(self, domain, validation_name, validation):
        logger.debug(f"EDGEDNS: _perform. domain: {domain}, name: {validation_name}, content: {validation}")
        self._get_edgedns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        logger.debug(f"EDGEDNS: _cleanup. domain: {domain}, name: {validation_name}, content: {validation}")
        self._get_edgedns_client().del_txt_record(domain, validation_name, validation)

    def _get_edgedns_client(self):
        if not self.edge_client:
            try:
                self.edge_client = _EdgeDNSClient(self.credentials)
            except errors.PluginError as e:
                raise e
        return self.edge_client

class _EdgeDNSClient:
    """
    Encapsulates all communication with the EdgeDNS Remote REST API.
    """

    BASEURL = "https://{0}"       # placeholder for host
    TXT_RECORDSET_TEMPLATE = {"name": "www.example.com", "type": "TXT", "ttl": RECORD_TTL, "rdata": []}

    recordset_semaphore = threading.Semaphore() 
    session = None					

    def __init__(self, edgedns_creds):
        self.http_parameters = {}
        #self.session = None
        logger.debug("creating _EdgeDNSClient")
        pathhost = ""
        if EDGEGRID_CREDS["edgerc_path"]:
            section = EDGEGRID_CREDS.get("edgerc_section", "default")
            edgerc = EdgeRc(EDGEGRID_CREDS["edgerc_path"])
            pathhost = edgerc.get(section, 'host')
            self.edgegrid_auth = EdgeGridAuth.from_edgerc(EDGEGRID_CREDS["edgerc_path"], section)

            if edgerc.has_option(section, 'account_key'):
                account_key = edgerc.get(section, 'account_key')
                self.http_parameters['accountSwitchKey'] = account_key
                print(f"[INFO] account_key from .edgerc: {account_key}")
        else:
            pathhost = EDGEGRID_CREDS["host"]
            self.edgegrid_auth = EdgeGridAuth(client_token = EDGEGRID_CREDS["client_token"],
                                              client_secret = EDGEGRID_CREDS["client_secret"],
                                              access_token = EDGEGRID_CREDS["access_token"])
            ## Adding parameters
            #self.http_parameters = {}
            account_key = EDGEGRID_CREDS.get('account_key')
            if account_key:
                self.http_parameters['accountSwitchKey'] = account_key
                print(f"[INFO] account_key from credentials: {account_key}")
        

        # Error checking the .edgerc file
        if not pathhost:
            raise errors.PluginError("EdgeDNS: Missing required 'host' value.")

        if '://' in pathhost:
            raise errors.PluginError("EdgeDNS: Invalid 'host' value. Remove the http(s):// prefix.")

        root_path = self.BASEURL.format(pathhost)
        self.EDGEDNSROOTURL = urljoin(root_path, "/config-dns/v2/") 
        self.EDGEDNSZONESURL = self.EDGEDNSROOTURL + "zones/"
        self.EDGEDNSCHANGESURL = self.EDGEDNSROOTURL + "changelists"

        self.recordset_semaphore = threading.Semaphore()

        return

    def set_session(self, sess):
        """ 
        Set request session value. Used by external callers
        :param session Session object to use
        """
        self.session = sess

    def get_text_record(self, domain, record_name, record_ttl=RECORD_TTL):
        """ 
        Get text record if it exists

        :param str zone: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :returns: Recordset
        :rtype: dict
        :raises certbot.errors.PluginError: if an error occurs communicating with the EdgeDNS API
        """

        logger.debug(f"EDGEDNS: get_text_record. domain: {domain}, name: {record_name}")
        self.recordset_semaphore.acquire() 
        if self.session is None:
            self.session = requests.Session()
        try: 
            zone = self._find_managed_zone(domain)
        except:
            self.recordset_semaphore.release()
            raise 
        if zone is None:
            self.recordset_semaphore.release()
            raise errors.PluginError(f"Managed zone not found in domain {domain}")
        self.session.auth = self.edgegrid_auth
        self.session.params = self.http_parameters

        self.session.headers.update({'Content-Type': 'application/json'})
        getpathurl = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, record_name)
        logger.debug(f"EDGEDNS: get_text_record. GET url: {getpathurl}")
        try:
            result = self.session.get(getpathurl)
        except:
            self.recordset_semaphore.release()
            raise errors.PluginError(
                f"EdgeDNS: API Get recordset invocation resulted in a session error: {sys.exc_info()[0]}"
            )

        logger.debug(f"Get Recordset response: {result.text}")
        if result.status_code == 403:
            self.recordset_semaphore.release()
            raise errors.PluginError(
                f"EdgeDNS: Provided credentials do not have the correct permission for this GET API call: ({result.text})"
            )
        elif result.status_code == 200:
            try:
                self.recordset_semaphore.release()
                return result.json(), zone
            except:
                self.recordset_semaphore.release()
                raise errors.PluginError(
                    f"EdgeDNS: Response body conversion to JSON failed with an error: {sys.exc_info()[0]}"
                )
        elif result.status_code == 404:
            logger.debug("Get record not found. Constructing MT record")
            mt_recordset = {}
            mt_recordset["name"] = record_name
            mt_recordset["ttl"] = record_ttl
            mt_recordset["rdata"] = []
            mt_recordset["type"] = "TXT"
            self.recordset_semaphore.release()
            return mt_recordset, zone

        self.recordset_semaphore.release()
        raise errors.PluginError(
            f"EdgeDNS: API Get response with an unknown error: {result.status_code} {result.reason}"
        )

    def add_txt_record(self, domain, record_name, record_content, record_ttl=RECORD_TTL):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the EdgeDNS API
        """

        logger.debug(f"EDGEDNS: add_text_record. domain: {domain}, name: {record_name}, content: {record_content}")
        try:
            txt_recordset, zone = self.get_text_record(domain, record_name, record_ttl)
        except errors.PluginError as pe:
            raise pe
        except:
           raise errors.PluginError(f"{sys.exc_info()[0]}")

        self.recordset_semaphore.acquire()
        if self.session is None:
            self.session = requests.Session()
        with self.session as session:
            session.auth = self.edgegrid_auth
            self.session.params = self.http_parameters
            try:
                self._process_add_record(session, zone, txt_recordset, record_content)
            except errors.PluginError as pe:
                self.recordset_semaphore.release()
                raise pe
            except:
                self.recordset_semaphore.release()
                raise errors.PluginError(
                    f"EdgeDNS: API invocation resulted in a session error: {sys.exc_info()[0]}"
                )

        self.recordset_semaphore.release()
        return


    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.
        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the EdgeDNS managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if managed zone doesn't exist
        """

        logger.debug(f"EDGEDNS: del_text_record. domain: {domain}, name: {record_name}, content: {record_content}")
        try:
            txt_recordset, zone = self.get_text_record(domain, record_name)
        except errors.PluginError as e:
            raise e
        except:
           raise errors.PluginError(f"{sys.exc_info()[0]}")

        if len(txt_recordset["rdata"]) == 0:
            # no record found
            return

        self.recordset_semaphore.acquire()
        if self.session is None:
            self.session = requests.Session()
        with self.session as session:
            session.auth = self.edgegrid_auth
            self.session.params = self.http_parameters
            try:
                self._process_del_record(session, zone, txt_recordset, record_content)
            except errors.PluginError as pe:
                self.recordset_semaphore.release()
                logger.error(f"EdgeDNS: Record delete errored: {pe}. Ignoring")
            except:
                self.recordset_semaphore.release()
                logger.error(f"EdgeDNS: API invocation resulted in a session error: {sys.exc_info()[0]}. Ignored")

        self.recordset_semaphore.release()
        return

    def _find_managed_zone(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: Zone
        :rtype: string
        :returns: The managed zone name, if found.
        """
        logger.debug(f"EDGEDNS: _find_managed_zone. domain: {domain}")

        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)
        
        self.session.auth = self.edgegrid_auth
        self.session.params = self.http_parameters

        for zone_name in zone_dns_name_guesses:
            # get the zone id
            try:
                logger.debug(f"EdgeDNS: looking for zone: {zone_name}")
                result = self.session.get(self.EDGEDNSZONESURL + zone_name)
                if result.status_code == 200:
                    logger.debug(f"EDGEDNS: _find_managed_zone found. zone: {zone_name}")
                    return zone_name
                elif result.status_code == 404:
                    continue
                else:
                    raise errors.PluginError(
                    f"EdgeDNS: API zone retrieval invocation resulted in a error: {result.status_code} {result.text}"
                )
            except Exception as e:
                logger.error("ZONE RETRIEVAL Error: %s", str(e))
                raise errors.PluginError(f"EdgeDNS: API invocation resulted in a session error: {e}")

            
        logger.debug("EDGEDNS: _find_managed_zone NOT found.")

        return None

    def _process_add_record(self, session, zone, txt_recordset, record_content):

        session.headers.update({'Content-Type': 'application/json'})
        if len(txt_recordset["rdata"]) == 0:
            # create new
            txt_recordset["rdata"].append(record_content)
            postpathsegment = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, txt_recordset["name"])
            logger.debug(f"EdgeDNS: Recordset Add POST URL: {postpathsegment}")

            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.post(postpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                raise errors.PluginError(
                    f"EdgeDNS: Add record API invocation resulted in a http request session error: {e}"
                )
        else:
            # Recordset already exists
            for x in txt_recordset["rdata"]:
                # Data coming back may be in quotes
                if record_content in x:
                    return
            txt_recordset["rdata"].append(record_content)
            putpathsegment = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, txt_recordset["name"])
            logger.debug(f"EdgeDNS: Recordset Add PUT URL: {putpathsegment}")

            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.put(putpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                raise errors.PluginError(
                    f"EdgeDNS: API invocation resulted in a session error: {e}"
                )

        if not result.status_code == 200 and not result.status_code == 201:
            raise errors.PluginError(
                f"EdgeDNS: Add TXT recordset thru EdgeDNS API failed: ({result.status_code} {result.reason})"
            )

        return

    def _process_del_record(self, session, zone, txt_recordset, record_content):

        putpathsegment = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, txt_recordset["name"])
        session.headers.update({'Content-Type': 'application/json'})
        text_index = None
        for x in txt_recordset["rdata"]:
            # Data coming back may be in quotes
            if record_content in x:
                text_index = txt_recordset["rdata"].index(x)
                break
        if text_index is None:
            return
        txt_recordset["rdata"].pop(text_index)
        if len(txt_recordset["rdata"]) > 0:
            # Update
            logger.debug(f"EdgeDNS: Recordset Delete PUT URL: {putpathsegment}")
            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.put(putpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                logger.warning(f"EdgeDNS: API Delete recordset invocation resulted in a session error: {e}. Ignoring")
                return

            if not result.status_code == 200:
                logger.error(f"EdgeDNS: API Update recordset invocation resulted in an error: {result.status_code} {result.reason}. Ignoring")
        else:
            # Delete
            logger.debug(f"EdgeDNS: Recordset Delete DELETE URL: {putpathsegment}")
            try:
                result = session.delete(putpathsegment)
            except:
                e = sys.exc_info()[0]
                logger.warning(f"EdgeDNS: API Delete recordset invocation resulted in a session error: {e}. Ignoring")

        return

