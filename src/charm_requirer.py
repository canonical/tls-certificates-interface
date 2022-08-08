#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains examples of requirer charm for the TLS certificates interface."""

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateRevokedEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from ops.charm import CharmBase, RelationJoinedEvent
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus


class ExampleRequirerCharm(CharmBase):
    """Example Requirer Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.cert_subject = "whatever"
        self.certificates = TLSCertificatesRequiresV1(self, "certificates")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.on.certificates.on.certificate_revoked, self._on_certificate_revoked
        )

    def _on_install(self, event) -> None:
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update(
            {"private_key_password": "banana", "private_key": private_key.decode()}
        )

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self.cert_subject,
        )
        replicas_relation.data[self.app].update({"csr": csr.decode()})
        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update({"certificate": event.certificate})
        replicas_relation.data[self.app].update({"ca": event.ca})
        replicas_relation.data[self.app].update({"chain": event.chain})
        self.unit.status = ActiveStatus()

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        old_csr = replicas_relation.data[self.app].get("csr")
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self.cert_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )
        replicas_relation.data[self.app].update({"csr": new_csr.decode()})

    def _on_certificate_revoked(self, event: CertificateRevokedEvent):
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        stored_csr = replicas_relation.data[self.app].get("csr")
        if event.certificate_signing_request == stored_csr:
            private_key_password = replicas_relation.data[self.app].get("private_key_password")
            private_key = replicas_relation.data[self.app].get("private_key")
            new_csr = generate_csr(
                private_key=private_key.encode(),
                private_key_password=private_key_password.encode(),
                subject=self.cert_subject,
            )
            self.certificates.request_certificate_renewal(
                old_certificate_signing_request=stored_csr, new_certificate_signing_request=new_csr
            )
            replicas_relation.data[self.app].update({"csr": new_csr.decode()})


if __name__ == "__main__":
    main(ExampleRequirerCharm)
