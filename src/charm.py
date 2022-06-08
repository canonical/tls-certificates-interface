#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains examples of provider and requirer charms for the TLS certificates interface."""

from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    TLSCertificatesProvides,
    TLSCertificatesRequires,
)
from ops.charm import CharmBase


class ExampleProviderCharm(CharmBase):
    """Example Provider Charm for TLS certificates."""

    def __init__(self, *args):
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvides(self, "certificates")
        self.framework.observe(
            self.tls_certificates.on.certificates_request, self._on_certificate_request
        )

    def _on_certificate_request(self, event):
        common_name = event.common_name
        sans = event.sans
        cert_type = event.cert_type
        certificate = self._generate_certificate(common_name, sans, cert_type)

        self.tls_certificates.set_relation_certificate(
            certificate=certificate, relation_id=event.relation.id
        )

    def _generate_certificate(self, common_name: str, sans: list, cert_type: str) -> Cert:
        return Cert(
            common_name=common_name, cert="whatever cert", key="whatever key", ca="whatever ca"
        )


class ExampleRequirerCharm(CharmBase):
    """Example Requirer Charm for TLS certificates."""

    def __init__(self, *args):
        super().__init__(*args)

        self.tls_certificates = TLSCertificatesRequires(self, "certificates")
        self.framework.observe(
            self.tls_certificates.on.certificate_available, self._on_certificate_available
        )
        self.tls_certificates.request_certificate(
            cert_type="client",
            common_name="whatever common name",
        )

    def _on_certificate_available(self, event):
        certificate_data = event.certificate_data
        print(certificate_data["common_name"])
        print(certificate_data["key"])
        print(certificate_data["ca"])
        print(certificate_data["cert"])
