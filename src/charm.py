#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains examples of provider and requirer charms for the TLS certificates interface."""

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAlmostExpiredEvent,
    CertificateAvailableEvent,
    CertificateRequestEvent,
    TLSCertificatesProvides,
    TLSCertificatesRequires,
    generate_csr,
    generate_private_key,
)
from ops.charm import CharmBase, InstallEvent, RelationJoinedEvent
from ops.model import ActiveStatus


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
            {"private_key_password": "banana", "private_key": private_key.decode()}
        )

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        replicas = self.model.get_relation("replicas")
        private_key_password = replicas.data[self.app].get("private_key_password")  # type: ignore[union-attr]  # noqa: E501
        private_key = replicas.data[self.app].get("private_key")  # type: ignore[union-attr]
        csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject="whatever",
        )
        replicas.data[self.app].update({"csr": csr.decode()})  # type: ignore[union-attr]
        self.certificates.request_certificate(csr=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        replicas = self.model.get_relation("replicas")
        event_csr = event.certificate_signing_request
        stored_csr = replicas.data[self.app].get("csr")  # type: ignore[union-attr]
        if stored_csr == event_csr:
            replicas.data[self.app].update({"certificate": event.certificate})  # type: ignore[union-attr]  # noqa: E501
            replicas.data[self.app].update({"ca": event.ca})  # type: ignore[union-attr]  # noqa: E501
            replicas.data[self.app].update({"chain": event.chain})  # type: ignore[union-attr]  # noqa: E501
            self.unit.status = ActiveStatus()

    def _on_certificate_almost_expired(self, event: CertificateAlmostExpiredEvent) -> None:
        replicas = self.model.get_relation("replicas")
        private_key_password = replicas.data[self.app].get(  # type: ignore[union-attr]  # noqa: E501
            "private_key_password"
        )
        private_key = replicas.data[self.app].get("private_key")  # type: ignore[union-attr]
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject="whatever",
        )
        self.certificates.request_certificate(csr=new_csr)
        existing_csr = replicas.data[self.app].get("csr")  # type: ignore[union-attr]
        self.certificates.revoke_certificate(certificate_signing_request=existing_csr.encode())
        replicas.data[self.app].update({"csr": new_csr.decode()})  # type: ignore[union-attr]
