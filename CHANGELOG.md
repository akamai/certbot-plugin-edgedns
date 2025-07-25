# Changelog

## Version 0.2.0 (July, 2025)

### Changes made
- Removed support for Python 2 as `edgegrid-python` v2.0.2 no longer supports Python 2, so compatibility has been dropped.
- Python 3.9.2+ required due to dependancy requirements
- Added support for account_key
- added pyproject.toml file 
  
- Updated dependencies:
  - `acme` and `certbot` upgraded to v4.1.1
  - `edgegrid-python` upgraded to v2.0.2

- The `certbot-plugin-edgedns:` prefix is no longer required in CLI options.
