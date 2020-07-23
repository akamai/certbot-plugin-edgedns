"""
The `~certbot_plugin_edgedns.edgedns` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Akamai Edge DNS REST API.

NOTE: The plugin prefix is required for certbot releases prior to
1.7.0 for named command arguments and credentials arguments.

Named Arguments
---------------

========================================================     =====================================
``--[certbot-plugin-edgedns:]edgedns-credentials``           Edge DNS Remote API credentials_
                                                             INI file.  
``--[certbot-plugin-edgedns:]edgedns-propagation-seconds``   The number of seconds to wait for DNS
                                                             to propagate before asking the ACME
                                                             server to verify the DNS record.
                                                             (Default: 180)
========================================================     =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing individual Edge DNS 
Remote API credentials or .edgrc file path and section containing Remote Edge DNS 
API credentials.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Edge DNS API credentials used by Certbot
   [certbot_plugin_edgedns:]edgedns_client_token = akab-mnbvcxzlkjhgfdsapoiuytrewq1234567
   [certbot_plugin_edgedns:]edgedns_access_token = akab-1234567890qwerty-asdfghjklzxcvtnu
   [certbot_plugin_edgedns:]edgedns_client_secret = abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG= 
   [certbot_plugin_edgedns:]edgedns_host = akab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.luna.akamaiapis.net
   #--OR--
   #[certbot_plugin_edgedns:]edgedns_edgerc_path = /home/testuser/.edgerc
   #[certbot_plugin_edgedns:]edgedns_edgerc_section = certbot

The path to this file can be provided interactively or using the
``--[certbot-plugin-edgedns:]edgedns-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue arbitrary API calls on
   your behalf. Users who can cause Certbot to run using these credentials can
   complete a ``dns-01`` challenge to acquire new certificates or revoke
   existing certificates for associated domains, even if those domains aren't
   being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --authenticator edgedns \\
     --edgedns-credentials ./.secrets/certbot/edgedns.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --csr ./example.com.pem \\
     --authenticator edgedns \\
     --edgedns-credentials ./.secrets/certbot/edgedns.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 240 seconds
             for DNS propagation

   certbot certonly \\
     --authenticator dns-edgedns \\
     --edgedns-credentials ./.secrets/certbot/edgedns.ini \\
     --edgedns-propagation-seconds 240 \\
     -d example.com

"""
