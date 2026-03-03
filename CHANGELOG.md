# Changelog

## Version 0.2.0 (February, 2026)

### Changes made
- Removed support for Python 2 as `edgegrid-python` v2.0.5 no longer supports Python 2, so compatibility has been dropped.
- Python 3.12+ required due to dependancy requirements
- Added support for account_key
- Added pyproject.toml file 
  
- Updated dependencies:
  - `acme` and `certbot` upgraded to >= v5.2.2
  - `edgegrid-python` upgraded to >= v2.0.5

- The `certbot-plugin-edgedns:` prefix is no longer required in CLI options.
