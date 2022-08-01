#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains examples of provider and requirer charms for the TLS certificates interface."""

import logging

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestEvent,
    TLSCertificatesProvides,
    TLSCertificatesRequires,
    generate_private_key,
)
from ops.charm import CharmBase, InstallEvent, RelationJoinedEvent
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


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
        self.certificates = TLSCertificatesProvides(self, "certificates")
        self.framework.observe(
            self.certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent) -> None:
        """Triggered on install events."""
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        ca_certificate = generate_ca(private_key=private_key, subject="whatever")
        replicas = self.model.get_relation("replicas")
        replicas.data[self.app].update(  # type: ignore[union-attr]
            {
                "private_key_password": "banana",
                "private_key": private_key,
                "ca_certificate": ca_certificate,
            }
        )

    def _on_certificate_request(self, event: CertificateRequestEvent) -> None:
        replicas = self.model.get_relation("replicas")
        ca_certificate = replicas.data[self.app].get("ca_certificate")  # type: ignore[union-attr]
        private_key = replicas.data[self.app].get("private_key")  # type: ignore[union-attr]
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
        self.unit.status = ActiveStatus()


class ExampleRequirerCharm(CharmBase):
    """Example Requirer Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesRequires(self, "certificates")
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event) -> None:
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        replicas = self.model.get_relation("replicas")
        replicas.data[self.app].update(  # type: ignore[union-attr]
            {"private_key_password": "banana", "private_key": private_key}
        )

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        replicas = self.model.get_relation("replicas")
        private_key_password = replicas.data[self.app].get("private_key_password")  # type: ignore[union-attr]  # noqa: E501
        private_key = replicas.data[self.app].get("private_key")  # type: ignore[union-attr]
        csr = self.certificates.request_certificate(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="banana.com",
        )
        logger.info(csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        logger.info(event.certificate)
        logger.info(event.certificate_signing_request)
        logger.info(event.ca)
        logger.info(event.chain)
        self.unit.status = ActiveStatus()
