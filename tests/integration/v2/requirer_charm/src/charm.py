#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from typing import List, Optional

from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from ops.charm import ActionEvent, CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)


CONFIG_CHANGED = "banana"


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV2(
            self,
            "certificates",
            expiry_notification_time=0.1,  # type: ignore
        )
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_invalidated, self._on_certificate_invalidated
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)

    @property
    def _stored_private_key(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="private_key")

    @property
    def _stored_csr(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="csr")

    @property
    def _stored_certificate(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="certificate")

    @property
    def _stored_ca_certificate(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="ca")

    @property
    def _stored_ca_chain(self) -> Optional[str]:
        chain = self._get_item_from_peer_relation_data(key="chain")
        if not chain:
            return None
        return json.loads(chain)

    @property
    def _replicas_relation_created(self) -> bool:
        return self._relation_created("replicas")

    def _store_private_key(self, private_key: str) -> None:
        self._store_item(key="private_key", value=private_key)

    def _store_csr(self, csr: str) -> None:
        self._store_item(key="csr", value=csr.strip())

    def _store_certificate(self, certificate: str) -> None:
        self._store_item(key="certificate", value=certificate)

    def _store_ca_certificate(self, certificate: str) -> None:
        self._store_item(key="ca", value=certificate)

    def _store_ca_chain(self, chain: List[str]) -> None:
        self._store_item(key="chain", value=json.dumps(chain))

    def _store_item(self, key: str, value: str) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            raise RuntimeError("Peer relation not created")
        replicas_relation.data[self.unit].update({key: value})

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: True/False
        """
        try:
            if self.model.get_relation(relation_name):
                return True
            return False
        except KeyError:
            return False

    def _get_item_from_peer_relation_data(self, key: str) -> Optional[str]:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            raise RuntimeError("Peer relation not created")
        return replicas_relation.data[self.unit].get(key, None)

    def _request_certificate(self) -> None:
        """Request TLS certificates.

        Returns:
            None
        """
        if not self._stored_private_key:
            raise RuntimeError("Private key not stored.")
        csr = generate_csr(
            private_key=self._stored_private_key.encode(),
            subject=CONFIG_CHANGED,
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        self._store_csr(csr.decode())
        self.unit.status = MaintenanceStatus("Requesting new certificate")

    def _generate_private_key(self) -> None:
        """Generate root certificate to be used to sign certificates.

        Returns:
            None
        """
        private_key = generate_private_key()
        self._store_private_key(private_key.decode())
        logger.info("Private key generated and stored.")

    def _on_install(self, event: InstallEvent) -> None:
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Waiting for replicas relation to be created")
            event.defer()
            return
        self._generate_private_key()
        self.unit.status = BlockedStatus("Waiting for relation to be created")

    def _on_certificates_relation_joined(self, event) -> None:
        self._request_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if event.certificate_signing_request != self._stored_csr:
            logger.info("Event CSR doesn't match stored CSR")
            return
        if event.certificate == self._stored_certificate:
            logger.info("Certificate is already stored")
            return
        self._store_certificate(event.certificate)
        self._store_ca_certificate(event.ca)
        self._store_ca_chain(event.chain)
        logger.info(f"New certificate is stored: {event.certificate}")
        self.unit.status = ActiveStatus()

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self._replicas_relation_created:
            event.fail("Replicas relation not created.")
            return
        if self._stored_certificate:
            event.set_results(
                {
                    "certificate": self._stored_certificate,
                    "ca": self._stored_ca_certificate,
                    "chain": self._stored_ca_chain,
                }
            )
        else:
            event.fail("Certificate not available")

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        logger.info("Certificate about to expire")
        self.unit.status = MaintenanceStatus("Certificate about to expire")

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        logger.info("Certificate expired")
        if self.unit.status == MaintenanceStatus("Certificate about to expire"):
            self.unit.status = BlockedStatus("Told you, now your certificate expired")
        else:
            self.unit.status = BlockedStatus("Surprise! Certificate expired")


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
