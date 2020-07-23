"""DNS Authenticator for Akamai EdgeDNS."""
import copy
import json
import logging
import requests
import threading
from certbot.compat import os
import sys
import zope.interface

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

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
                  "edgerc_section": ""
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
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.edge_client = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=DEFAULT_PROPAGATION_DELAY
        )
        add("credentials", help="EdgeDNS credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the EdgeDNS Remote REST API."
        )

    def _validate_credentials(self):

        EDGEGRID_CREDS["edgerc_path"] = edgerc = self.credentials.conf('edgerc_path')
        EDGEGRID_CREDS["edgerc_section"] = section = self.credentials.conf('edgerc_section')
        if edgerc:
            if not section:
                EDGEGRID_CREDS["edgerc_section"] = "default"
                print("No edgerc section provided. Using 'default'")
            return

        EDGEGRID_CREDS["client_token"] = client_token = self.credentials.conf('client_token')
        EDGEGRID_CREDS["client_secret"] = client_secret = self.credentials.conf('client_secret')
        EDGEGRID_CREDS["access_token"] = access_token = self.credentials.conf('access_token')
        EDGEGRID_CREDS["host"] = host = self.credentials.conf('host')
        errmsg = ''
        missing = 0
        if not client_token:	
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'edgedns_client_token'
        if not client_secret:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += 'edgedns_client_secret'
        if not access_token:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += ', edgedns_access_token'
        if not host:
            missing += 1
            if errmsg != '':
                errmsg += ', '
            errmsg += ', edgedns_host'
        if not edgerc and missing == 4:
            raise errors.PluginError('{0}:Either an edgerc_path or individual edgegrid crendentials are required '
                                         ' when using the EdgeDNS API (see {1})'
                                         .format(self.credentials.confobj.filename, EDGEGRID_URL))
        if errmsg != '':
            if missing == 1:
                errmsg += ' is '
            else:
                errmsg += ' are '
            errmsg += 'required when specifying individual edgegrid credentials ' 
            raise errors.PluginError('{0}: ' + errmsg + ' for using the EdgeDNS API (see {1})'
                                     .format(self.credentials.confobj.filename, EDGEGRID_URL))

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

        logger.debug("EDGEDNS: _perform. domain: {0}, name: {1}, content: {2}".format(domain, validation_name, validation))

        self._get_edgedns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):

        logger.debug("EDGEDNS: _cleanup. domain: {0}, name: {1}, content: {2}".format(domain, validation_name, validation))

        self._get_edgedns_client().del_txt_record(domain, validation_name, validation)

    def _get_edgedns_client(self):
        if not self.edge_client:
            try:
                self.edge_client = _EdgeDNSClient(self.credentials)
            except errors.PluginError as e:
                raise e
        return self.edge_client

class _EdgeDNSClient(object):
    """
    Encapsulates all communication with the EdgeDNS Remote REST API.
    """

    BASEURL = "https://{0}"       # placeholder for host
    TXT_RECORDSET_TEMPLATE = {"name": "www.example.com", "type": "TXT", "ttl": RECORD_TTL, "rdata": []}

    recordset_semaphore = threading.Semaphore() 
    session = None					# 

    def __init__(self, edgedns_creds):
        logger.debug("creating _EdgeDNSClient")
        pathhost = ""
        if EDGEGRID_CREDS["edgerc_path"]:
            section = 'default'
            if EDGEGRID_CREDS["edgerc_section"]:
                section = EDGEGRID_CREDS["edgerc_section"]
            pathhost = EdgeRc(EDGEGRID_CREDS["edgerc_path"]).get(section, 'host')
            self.edgegrid_auth = EdgeGridAuth.from_edgerc(EDGEGRID_CREDS["edgerc_path"], section)
        else:
            pathhost = EDGEGRID_CREDS["host"]
            self.edgegrid_auth = EdgeGridAuth(client_token = EDGEGRID_CREDS["client_token"],
                                              client_secret = EDGEGRID_CREDS["client_secret"],
                                              access_token = EDGEGRID_CREDS["access_token"])
        # Error checking the .edgerc file
        if pathhost.find('://') > 0:
            raise errors.PluginError('{0}: You have specified an invalid host entry '
                                         'Please remove the http(s):// at the beginning.'
            )
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

        logger.debug("EDGEDNS: get_text_record. domain: {0}, name: {1}".format(domain,  record_name))
        self.recordset_semaphore.acquire() 
        if self.session == None:
            self.session = requests.Session()
        try: 
            zone = self._find_managed_zone(domain)
        except:
            self.recordset_semaphore.release()
            raise 
        if zone is None:
            self.recordset_semaphore.release()
            raise errors.PluginError('Managed zone not found in domain {0}'.format(domain)
            )
        self.session.auth = self.edgegrid_auth
        self.session.headers.update({'Content-Type': 'application/json'})
        getpathurl = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, record_name)
        logger.debug("EDGEDNS: get_text_record. GET url: {0}".format(getpathurl)) 
        try:
            result = self.session.get(getpathurl)
        except:
            self.recordset_semaphore.release()
            raise errors.PluginError("EdgeDNS: API Get recordset invocation resulted in a session error: {0}".format(sys.exc_info()[0]))

        logger.debug("Get Recordset response: {0}".format(result.text))
        if result.status_code == 403:
            self.recordset_semaphore.release()
            raise errors.PluginError('EdgeDNS: Provided credentials do not have the correct permission for this GET API call: ({0})'.format(result.message)
            )
        elif result.status_code == 200:
            try:
                self.recordset_semaphore.release()
                return result.json(), zone
            except:
                self.recordset_semaphore.release()
                raise errors.PluginError(
                    "EdgeDNS: Response body conversion to JSON failed with an error: {0}".format(sys.exc_info()[0])
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
            "EdgeDNS: API Get response with an unknown error: {0} {1}".format(result.status_code, result.reason)
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

        logger.debug("EDGEDNS: add_text_record. domain: {0}, name: {1}, content: {2}".format(domain, record_name, record_content))
        try:
            txt_recordset, zone = self.get_text_record(domain, record_name, record_ttl)
        except errors.PluginError as pe:
            raise pe
        except:
           raise errors.PluginError("{0}".format(sys.exc_info()[0]))

        self.recordset_semaphore.acquire()
        if self.session == None:
            self.session = requests.Session()
        with self.session as session:
            session.auth = self.edgegrid_auth
            try:
                self._process_add_record(session, zone, txt_recordset, record_content)
            except errors.PluginError as pe:
                self.recordset_semaphore.release()
                raise pe
            except:
                self.recordset_semaphore.release()
                raise errors.PluginError(
                    "EdgeDNS: API invocation resulted in a session error: {0}".format(sys.exc_info()[0])
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

        logger.debug("EDGEDNS: del_text_record. domain: {0}, name: {1}, content: {2}".format(domain, record_name, record_content))
        try:
            txt_recordset, zone = self.get_text_record(domain, record_name)
        except errors.PluginError as e:
            raise e
        except:
           raise errors.PluginError("{0}".format(sys.exc_info()[0]))

        if len(txt_recordset["rdata"]) == 0:
            # no record found
            return

        self.recordset_semaphore.acquire()
        if self.session == None:
            self.session = requests.Session()
        with self.session as session:
            session.auth = self.edgegrid_auth
            try:
                self._process_del_record(session, zone, txt_recordset, record_content)
            except errors.PluginError as pe:
                self.recordset_semaphore.release()
                logger.error("EdgeDNS: Record delete errored: {0}. Ignoring".format(pe))
            except:
                self.recordset_semaphore.release()
                logger.error("EdgeDNS: API invocation resulted in a session error: {0}. Ignored".format(sys.exc_info()[0]))

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
        logger.debug("EDGEDNS: _find_managed_zone. domain: {0}".format(domain))

        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)
        
        self.session.auth = self.edgegrid_auth

        for zone_name in zone_dns_name_guesses:
            # get the zone id
            try:
                logger.debug("EdgeDNS: looking for zone: {0}".format(zone_name))
                result = self.session.get(self.EDGEDNSZONESURL + zone_name)
                if result.status_code == 200:
                    logger.debug("EDGEDNS: _find_managed_zone found. zone: {0}".format(zone_name))
                    return zone_name
                elif result.status_code == 404:
                    continue
                else:
                    raise errors.PluginError(
                    "EdgeDNS: API zone retrieval invocation resulted in a error: {0} {1}".format(result.status_code, result.message)
                )
            except:
                logger.error(" ZONE RETRIEVAL Error: {0}".format(sys.exc_info()[0]))
                raise errors.PluginError(
                    "EdgeDNS: API invocation resulted in a session error: {0}".format(sys.exc_info()[0])
                )

        logger.debug("EDGEDNS: _find_managed_zone NOT found.")

        return None

    def _process_add_record(self, session, zone, txt_recordset, record_content):

        session.headers.update({'Content-Type': 'application/json'})
        if len(txt_recordset["rdata"]) == 0:
            # create new
            txt_recordset["rdata"].append(record_content)
            postpathsegment = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, txt_recordset["name"])
            logger.debug('EdgeDNS: Recordset Add POST URL: {0}'.format(postpathsegment))

            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.post(postpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                raise errors.PluginError(
                    "EdgeDNS: Add record API invocation resulted in a http request session error: {0}".format(e)
                )
        else:
            # Recordset already exists
            for x in txt_recordset["rdata"]:
                # Data coming back may be in quotes
                if record_content in x:
                    return
            txt_recordset["rdata"].append(record_content)
            putpathsegment = self.EDGEDNSZONESURL + '{0}/names/{1}/types/TXT'.format(zone, txt_recordset["name"])
            logger.debug('EdgeDNS: Recordset Add PUT URL: {0}'.format(putpathsegment))

            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.put(putpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                raise errors.PluginError(
                    "EdgeDNS: API invocation resulted in a session error: {0}".format(e)
                )

        if not result.status_code == 200 and not result.status_code == 201:
            raise errors.PluginError('EdgeDNS: Add TXT recordset thru EdgeDNS API failed: ({0} {1})'.format(result.status_code, result.reason)
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
            logger.debug('EdgeDNS: Recordset Delete PUT URL: {0}'.format(putpathsegment))
            try:
                recordset_json = json.dumps(txt_recordset)
                result = session.put(putpathsegment, data=recordset_json)
            except:
                e = sys.exc_info()[0]
                logger.warning("EdgeDNS: API Delete recordset invocation resulted in a session error: {0}. Ignoring".format(e))
                return

            if not result.status_code == 200:
                logger.error("EdgeDNS: API Update recordset invocation resulted in an  error: {0} {1}. Ignoring".format(result.status_code, result.reason))
        else:
            # Delete
            logger.debug('EdgeDNS: Recordset Delete DELETE URL: {0}'.format(putpathsegment))
            try:
                result = session.delete(putpathsegment)
            except:
                e = sys.exc_info()[0]
                logger.warning("EdgeDNS: API Delete recordset invocation resulted in a session error: {0}. Ignoring".format(e))

        return

