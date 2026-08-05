certbot-plugin-edgedns
======================

Akamai `Edge DNS <https://techdocs.akamai.com/edge-dns/docs/welcome-edge-dns>`_ Authenticator plugin for Certbot.

This plugin automates the process of completing a ``dns-01`` challenge by creating, and subsequently removing, TXT records 
using the Akamai Edge DNS.

Configuration of EdgeDNS
------------------------

The Akamai Edge DNS certbot plugin utilizes the Akamai `OPEN Edge DNS API <https://techdocs.akamai.com/edge-dns/reference/edge-dns-api>`_. To facilitate access, the plugin uses the standard Akamai OPEN credentials file, .edgerc.
By default, this file is typically located in your HOME directory.

The Akamai OPEN credentials file location, and the section, must be specified in the certbot credentials file described in the
following sections. Alternatively, the individual Akamai OPEN credential keys and values can be specified in the certbot 
credentials file as described in the following sections.

To set up your Akamai OPEN CREDENTIALS, and .edgerc file, see the `authentication credentials <https://techdocs.akamai.com/developer/docs/edgegrid>`_ section of the Akamai Developer documentation.

.. _EdgeDNS: https://techdocs.akamai.com/edge-dns/docs/welcome-edge-dns
.. _certbot: https://certbot.eff.org/

Installation
------------
Note: Python 3.12 or higher is required due to dependency requirements. 

::

    pip install certbot-plugin-edgedns


Named Arguments
---------------

To start using DNS authentication for edge DNS, pass the following arguments on
certbot's command line:

==================================  =============================================================
Argument                            Description
==================================  =============================================================
``--authenticator edgedns``         Select the authenticator plugin (Required)

``--edgedns-credentials``           Akamai EdgeDNS Auth credentials INI file. (Required)

``--edgedns-propagation-seconds``   Waiting time for DNS to propagate before asking
                                    the ACME server to verify the DNS record.
                                    (Default: 180, Recommended: >= 600)
==================================  =============================================================


Credentials
-----------

An example ``credentials.ini`` file using Open Edgegrid keys directly:

.. code-block:: ini

   client_token = akab-mnbvcxzlkjhgfdsapoiuytrewq1234567
   access_token = akab-1234567890qwerty-asdfghjklzxcvtnu
   client_secret = abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG= 
   host = akab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.luna.akamaiapis.net
   account_key = 1-2ABCD3 (OPTIONAL)

An example ``credentials.ini`` file using Open Edgegrid .edgerc file:

.. code-block:: ini

   edgerc_path = /home/testuser/.edgerc
   edgerc_section = default


The path to this file can be provided interactively or using the
``--edgedns-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should take proactive steps to protect these API credentials. 
Users who can read this file can use these credentials to issue arbitrary API calls 
on your behalf. Users who can cause Certbot to run using these credentials can complete 
a ``dns-01`` challenge to acquire new certificates or revoke existing certificates for 
associated domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 900 seconds for DNS propagation:

.. code-block:: bash

   certbot certonly \
     --csr ./example.com.pem \
     --authenticator edgedns \
     --edgedns-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
     --edgedns-propagation-seconds 900 \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'example.com' \
     -d '*.example.com'


Docker
------

In order to create a docker container with a certbot-dns-edgedns installation,
create an empty directory with the following ``Dockerfile``:

.. code-block:: docker

    FROM certbot/certbot
    RUN pip install certbot-plugin-edgedns

Proceed to build the image::

    docker build -t certbot/edgedns .

Once that's finished, the application can be run as follows::

    docker run --rm \
       -v /var/lib/letsencrypt:/var/lib/letsencrypt \
       -v /etc/letsencrypt:/etc/letsencrypt \
       --cap-drop=all \
       certbot/edgedns certonly \
       --authenticator edgedns \
       --edgedns-propagation-seconds 900 \
       --edgedns-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
       --keep-until-expiring --non-interactive --expand \
       --server https://acme-v02.api.letsencrypt.org/directory \
       --agree-tos \
       -d example.com -d '*.example.com'

It is strongly suggested that the folder be secured by taking the following steps:

1. chown root:root /etc/letsencrypt/.secrets
2. chmod 600 /etc/letsencrypt/.secrets

