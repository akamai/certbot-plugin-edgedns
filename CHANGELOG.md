# Changelog

## Version 0.3.0 (July, 2026)

### Changes made
- Removed `wheel` from build-system dependencies (redundant since PEP 517)
- Updated build tooling:
  - `setuptools` upgraded to >= v83.0.0
- Updated dependencies:
  - `acme` and `certbot` upgraded to >= v5.7.0
  - `edgegrid-python` upgraded to >= v2.0.7
  - `requests` pinned to >= v2.34.2
  - `urllib3` pinned to >= v2.7.0
  - `zope.interface` pinned to >= v8.5
  - `requests_mock` pinned to >= v1.12.1
  - `mock` pinned to >= v5.2.0

## Version 0.2.0 (February, 2026)

### Changes made
- Removed support for Python 2 as `edgegrid-python` v2.0.5 no longer supports Python 2, so compatibility has been dropped.
- Python 3.12+ required due to dependency requirements
- Added support for account_key
- Added pyproject.toml file 
  
- Updated dependencies:
  - `acme` and `certbot` upgraded to >= v5.2.2
  - `edgegrid-python` upgraded to >= v2.0.5

- The `certbot-plugin-edgedns:` prefix is no longer required in CLI options.
