# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Any

from ops.charm import CharmBase
from ops.main import main

from lib.charms.tls_certificates_interface.v3.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV3,
)


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args: Any):
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV3(
            self, "certificates", expiry_notification_time=168
        )
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
            self.certificates.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated,
        )

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        pass

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        pass

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        pass

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent) -> None:
        pass


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
