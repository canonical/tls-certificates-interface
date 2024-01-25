# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from ops.charm import CharmBase
from ops.main import main

from lib.charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateCreationRequestEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV3,
)


class DummyTLSCertificatesProviderCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesProvidesV3(self, "certificates")
        self.framework.observe(
            self.certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(
            self.certificates.on.certificate_revocation_request,
            self._on_certificate_revocation_request,
        )

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        pass

    def _on_certificate_revocation_request(self, event: CertificateRevocationRequestEvent) -> None:
        pass


if __name__ == "__main__":
    main(DummyTLSCertificatesProviderCharm)
