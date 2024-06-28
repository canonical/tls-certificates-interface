# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import List, Optional, cast

from ops.charm import CharmBase, ConfigChangedEvent
from ops.main import main

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequest,
    Mode,
    TLSCertificatesRequiresV4,
)


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        certificate_requests = self._get_certificate_requests()
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=certificate_requests,
            mode=Mode.UNIT,
            refresh_events=[self.on.config_changed],
        )
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )

    def _get_certificate_requests(self) -> List[CertificateRequest]:
        return [
            CertificateRequest(
                common_name=self._get_config_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                organizational_unit=self._get_config_organization_unit_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
            )
        ]

    def _configure(self, event: ConfigChangedEvent):
        pass

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        pass

    def _get_config_common_name(self) -> str:
        return cast(str, self.model.config.get("common_name"))

    def _get_config_sans_dns(self) -> List[str]:
        config_sans_dns = cast(str, self.model.config.get("sans_dns", ""))
        return config_sans_dns.split(",") if config_sans_dns else []

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
