#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains examples of provider charm for the TLS certificates interface."""

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateCreationRequestEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV1,
    generate_private_key,
)
from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus


def generate_ca(private_key: bytes, subject: str) -> str:
    """Generates CA."""
    return "whatever ca content"


def generate_certificate(ca: str, private_key: str, csr: str) -> str:
    """Generates certificate."""
    return "Whatever certificate"


class ExampleProviderCharm(CharmBase):
    """Example Provider Charm for TLS certificates."""

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesProvidesV1(self, "certificates")
        self.framework.observe(
            self.certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(
            self.certificates.on.certificate_revoked, self._on_certificate_revoked
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent) -> None:
        """Triggered on install events."""
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        ca_certificate = generate_ca(private_key=private_key, subject="whatever")
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update(
            {
                "private_key_password": "banana",
                "private_key": private_key,
                "ca_certificate": ca_certificate,
            }
        )
        self.unit.status = ActiveStatus()

    def _on_certificate_request(self, event: CertificateCreationRequestEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        ca_certificate = replicas_relation.data[self.app].get("ca_certificate")
        private_key = replicas_relation.data[self.app].get("private_key")
        certificate = generate_certificate(
            ca=ca_certificate,
            private_key=private_key,
            csr=event.certificate_signing_request,
        )

        self.certificates.set_relation_certificate(
            certificate=certificate,
            certificate_signing_request=event.certificate_signing_request,
            ca=ca_certificate,
            chain=ca_certificate,
            relation_id=event.relation_id,
        )

    def _on_certificate_revoked(self, event: CertificateRevocationRequestEvent) -> None:
        # Do what you want to do with this information
        pass


if __name__ == "__main__":
    main(ExampleProviderCharm)
