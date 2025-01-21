# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Any, FrozenSet, List, Optional, cast

from ops.charm import ActionEvent, CharmBase
from ops.main import main

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args: Any):
        super().__init__(*args)
        certificate_requests = self._get_certificate_requests()
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=certificate_requests,
            mode=Mode.UNIT,
            refresh_events=[self.on.config_changed],
            private_key=self.get_private_key(),
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.regenerate_private_key_action, self._on_regenerate_private_key_action
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        self.framework.observe(
            self.on.renew_certificates_action, self._on_renew_certificates_action
        )

    def get_private_key(self) -> PrivateKey:
        private_key_path = "tests/unit/charms/tls_certificates_interface/v4/dummy_requirer_charm/private_key.pem"  # noqa: E501
        with open(private_key_path, "r") as f:
            private_key = f.read()
        return PrivateKey.from_string(private_key)

    def _get_certificate_requests(self) -> List[CertificateRequestAttributes]:
        if not self._get_config_common_name():
            return []
        return [
            CertificateRequestAttributes(
                common_name=self._get_config_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                organizational_unit=self._get_config_organization_unit_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
                is_ca=self._get_config_is_ca(),
            )
        ]

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        if not event.certificate:
            print("Certificate not available")
            return
        print("Certificate available for common name:", event.certificate.common_name)

    def _on_regenerate_private_key_action(self, event: ActionEvent) -> None:
        self.certificates.regenerate_private_key()

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not certificate:
            event.fail("Certificate not available")
            return
        event.set_results(
            {
                "certificate": str(certificate.certificate),
                "ca": str(certificate.ca),
                "csr": str(certificate.certificate_signing_request),
            }
        )

    def _on_renew_certificates_action(self, event: ActionEvent) -> None:
        certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not certificate:
            event.fail("Not certificates available")
            return
        self.certificates.renew_certificate(
            certificate=certificate,
        )

    def _get_config_common_name(self) -> str:
        return cast(str, self.model.config.get("common_name"))

    def _get_config_sans_dns(self) -> FrozenSet[str]:
        config_sans_dns = cast(str, self.model.config.get("sans_dns", ""))
        return frozenset(config_sans_dns.split(",") if config_sans_dns else [])

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

    def _get_config_is_ca(self) -> bool:
        return cast(bool, self.model.config.get("is_ca", False))


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
