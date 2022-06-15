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

    def _on_certificate_request(self, event) -> None:
        """Handler triggerred on certificates request event.

        Here insert the code that generates a TLS certificate and then use the
        `set_relation_certificate` to pass it back to the requirer.

        Args:
            event: Juju event

        Returns:
            None
        """
        common_name = event.common_name
        sans = event.sans
        cert_type = event.cert_type
        certificate = self._generate_certificate(common_name, sans, cert_type)

        self.tls_certificates.set_relation_certificate(
            certificate=certificate, relation_id=event.relation.id
        )

    def _generate_certificate(self, common_name: str, sans: list, cert_type: str) -> Cert:
        """Placeholder method to generates TLS Certificate.

        Args:
            common_name (str): Common Name
            sans (list): Subject Alternative Names
            cert_type (str): Certificate type ("client" or "server")

        Returns:
            Cert: Certificate object.
        """
        return Cert(
            common_name=common_name, cert="whatever cert", key="whatever key", ca="whatever ca"
        )


class ExampleRequirerCharm(CharmBase):
    """Example Requirer Charm for TLS certificates."""

    CERT_PATH = "/certs"
    COMMON_NAME = "whatever common_name"

    def __init__(self, *args):
        super().__init__(*args)
        self._container = self.unit.get_container(container_name="placeholder")
        self.tls_certificates = TLSCertificatesRequires(self, "certificates")
        self.framework.observe(
            self.tls_certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )

    def _on_certificates_relation_joined(self, event) -> None:
        """Handler triggerred on certificates relation joined event.

        Here insert the certificate request.

        Args:
            event: Juju event

        Returns:
            None
        """
        self.tls_certificates.request_certificate(
            cert_type="server",
            common_name=self.COMMON_NAME,
        )

    def _on_certificate_available(self, event) -> None:
        """Handler triggerred on certificate available events.

        Here insert the code that handles certificates (ex. push to workload container).

        Args:
            event: Juju event

        Returns:
            None
        """
        certificate_data = event.certificate_data
        if event.certificate_data["common_name"] == self.COMMON_NAME:
            self._container.push(f"{self.CERT_PATH}/private_key.key", certificate_data["key"])
            self._container.push(f"{self.CERT_PATH}/certificate.pem", certificate_data["cert"])
            self._container.push(f"{self.CERT_PATH}/rootca.pem", certificate_data["ca"])
