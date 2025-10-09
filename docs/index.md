The TLS Certificate Interface is the library which contains the Requires and Provides classes for handling the TLS Certificates.

## Deprecation notice

**WARNING** This Charmhub-hosted library is deprecated in favour of ``charmlibs.interfaces.tls_certificates``.
It will not receive feature updates or bugfixes.
``charmlibs.interfaces.tls_certificates`` 1.0 is a bug-for-bug compatible migration of this library.

To migrate:
1. Add 'charmlibs-interfaces-tls-certificates~=1.0' to your charm's dependencies,
   and remove this Charmhub-hosted library from your charm.
2. You can also remove any dependencies added to your charm only because of this library.
3. Replace `from charms.tls_certificates_interface.v4 import tls_certificates`
   with `from charmlibs.interfaces import tls_certificates`.

Read more:
- https://documentation.ubuntu.com/charmlibs
- https://pypi.org/project/charmlibs-interfaces-tls-certificates

## Usage

This charm should not be deployed as it's a placeholder for the library. This library could be fetched and used to request and provide the certificates in the charms when it is needed. 

## Project and community
The TLS Certificate Interface Library is an open-source project that welcomes community contributions, suggestions, fixes and constructive feedback.
- [Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct)
- [Join the Discourse forum](https://discourse.charmhub.io/tag/tls-cert-interface)
- Contribute and report bugs to [tls-certificates-interface](https://github.com/canonical/tls-certificates-interface)
