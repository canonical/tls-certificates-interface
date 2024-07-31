#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Optional, Tuple, cast

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequest,
    Mode,
    TLSCertificatesRequiresV4,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        certificate_request = self._get_certificate_request()
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=[certificate_request],
            mode=Mode.UNIT,
            refresh_events=[self.on.config_changed],
        )
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        if not self._relation_created("certificates"):
            event.add_status(BlockedStatus("Missing relation to certificates provider"))
            return
        cert, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        if not cert:
            event.add_status(WaitingStatus("Waiting for certificate"))
            return
        event.add_status(ActiveStatus())

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        if not certificate:
            event.fail("Certificate not available")
            return
        event.set_results(
            {
                "certificate": str(certificate.certificate),
                "ca": str(certificate.ca),
                "chain": str(certificate.chain),
            }
        )

    def _relation_created(self, relation_name: str) -> bool:
        try:
            if self.model.get_relation(relation_name):
                return True
            return False
        except KeyError:
            return False

    def _get_certificate_request(self) -> CertificateRequest:
        return CertificateRequest(
            common_name=self._get_config_common_name(),
            sans_dns=self._get_config_sans_dns(),
            organization=self._get_config_organization_name(),
            organizational_unit=self._get_config_organization_unit_name(),
            email_address=self._get_config_email_address(),
            country_name=self._get_config_country_name(),
            state_or_province_name=self._get_config_state_or_province_name(),
            locality_name=self._get_config_locality_name(),
        )

    def _get_config_common_name(self) -> str:
        return cast(str, self.model.config.get("common_name"))

    def _get_config_sans_dns(self) -> Tuple[str, ...]:
        config_sans_dns = cast(str, self.model.config.get("sans_dns", ""))
        return tuple(config_sans_dns.split(",") if config_sans_dns else [])

    def _get_config_organization_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("organization_name"))

    def _get_config_organization_unit_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("organization_unit_name"))

    def _get_config_email_address(self) -> Optional[str]:
        return cast(str, self.model.config.get("email_address"))

    def _get_config_country_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("country_name"))

    def _get_config_state_or_province_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("state_or_province_name"))

    def _get_config_locality_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("locality_name"))


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
