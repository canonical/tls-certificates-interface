# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

from ops.charm import CharmBase
from ops.main import main

from lib.charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiredEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV1,
)


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.cert_subject = "whatever"
        self.certificates = TLSCertificatesRequiresV1(
            self, "certificates", expiry_notification_time=168
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_expired, self._on_certificate_expired
        )

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        pass

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        pass

    def _on_certificate_expired(self, event: CertificateExpiredEvent) -> None:
        pass


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
