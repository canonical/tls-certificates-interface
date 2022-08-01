# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for the tls-certificates relation.

This library contains the Requires and Provides classes for handling the tls-certificates
interface.

## Getting Started
From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v1.tls_certificates
```

Add the following library to the charm's `requirements.txt` file:
- jsonschema
- cryptography

Add the following section to the charm's `charmcraft.yaml` file:
```yaml
parts:
  charm:
    build-packages:
      - libffi-dev
      - libssl-dev
      - rustc
      - cargo
```

### Provider charm
The provider charm is the charm providing certificates to another charm that requires them.

Example:
```python

import logging

from ops.charm import CharmBase, InstallEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateRequestEvent,
    TLSCertificatesProvides,
)

logger = logging.getLogger(__name__)


class ExampleProviderCharm(CharmBase):

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesProvides(self, "certificates")
        self._stored.set_default(ca_private_key=b"", ca_certificate=b"")
        self.framework.observe(
            self.certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent) -> None:
        self._stored.ca_private_key = generate_private_key()
        self._stored.ca_certificate = generate_ca(
            private_key=self._stored.ca_private_key, subject="whatever"
        )

    def _on_certificate_request(self, event: CertificateRequestEvent) -> None:
        certificate = generate_certificate(
            ca=self._stored.ca_certificate,
            ca_key=self._stored.ca_private_key,
            csr=event.certificate_signing_request.encode()
        )

        self.certificates.set_relation_certificate(
            certificate=certificate.decode("utf-8"),
            certificate_signing_request=event.certificate_signing_request,
            ca=self._stored.ca_certificate.decode("utf-8"),
            chain=self._stored.ca_certificate.decode("utf-8"),
            relation_id=event.relation_id
        )
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(ExampleProviderCharm)
```

### Requirer charm
The requirer charm is the charm requiring certificates from another charm that provides them.

Example:
```python
import logging

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequires,
    generate_private_key
)
from ops.framework import StoredState
from ops.charm import CharmBase, RelationJoinedEvent
from ops.model import ActiveStatus
from ops.main import main


logger = logging.getLogger(__name__)


class ExampleRequirerCharm(CharmBase):

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesRequires(self, "certificates")
        self._stored.set_default(private_key=b"", private_key_password=b"")
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event) -> None:
        self._stored.private_key_password = b"banana"
        self._stored.private_key = generate_private_key(password=self._stored.private_key_password)

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        csr = self.certificates.request_certificate(
            private_key=self._stored.private_key,
            private_key_password=self._stored.private_key_password,
            common_name="banana.com",
        )
        logger.info(csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        logger.info(event.certificate)
        logger.info(event.certificate_signing_request)
        logger.info(event.ca)
        logger.info(event.chain)
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(ExampleRequirerCharm)
```
"""

import json
import logging
from datetime import datetime
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jsonschema import exceptions, validate  # type: ignore[import]
from ops.charm import CharmBase, CharmEvents, RelationChangedEvent, UpdateStatusEvent
from ops.framework import EventBase, EventSource, Object

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0

REQUIRER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$id": "https://canonical.github.io/charm-relation-interfaces/tls_certificates/v1/schemas/requirer.json",
    "type": "object",
    "title": "`tls_certificates` requirer root schema",
    "description": "The `tls_certificates` root schema comprises the entire requirer databag for this interface.",
    "examples": [
        {
            "certificate_signing_requests": [
                {
                    "certificate_signing_request": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2FUQ0NBVkVDQVFBd0pERUxNQWtHQTFVRUJoTUNWVk14RlRBVEJnTlZCQU1NRENvdVltRnVZVzVoTG1OdgpiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNaDQxVkdjajJ1c2F1L3R6amd3CkVCcEoxM3lCWDYvQUZjL25Na1R4VTYxT2JycldkVjkwQlcwbS9ZVWdxN0VRNWR3UkJIOFB3L3ZFN3NaN0FoVk0KOENncllKTzQxYWxmRTlFcjU2aFNxSlVpeFV2VXNtWUppcUtwTVpjT3QzSW14cnNHRkh2MXBoN0NoL3R1bCtXNgpNY3RXZnYrNWIreGhEYWZMcC8rMUZSQWhYTHlqZkd0ZCsrUTJISzV6ZS9qQUN4YzF3a3pFNmpwTkxwNHJGL1h5CjFKVXdkZDVYVURkWjVmL1JrWWNKaEJ2OHpWbjd0WEYvZ0FOVDc2bHI4ZS82VWZHK0FQUURvL1UrMUdpeG4yL0sKdHVnYVBNRFlBZ2xLYm9JQVh3em9HbEpIR1crcEZZTGU2eGhHTE15RWhCRmJ0a1BKNGRDS0l5Tnh1T29rSHp3Ygp5aDhDQXdFQUFhQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNZa0g1aVNhT0dGSnREWHhCd0xRNldxc0JhCnU3VkxhMHJubksrbCtmUjNwV2Q5UThqOG5PTXI4d2szb2FNQ2JFQ3RaSitqYjZEN2Y0aS9IN1BOOElOVzl6S0IKVjltVTh0YnhhRTdub2x0UW9XQTgwU3hSN3BhWWF3Tit0NnNWUTN3aTJyZ3F2aGpGVEJKQStiYmZsQjZRM3FzYgpOSDAwYUo3eTdrU1d1MWxxNkhERnh4L0FlMEZLVUNqQVNrWnhsU0taUEJYcWF1UG9tU3hCMVhGN1pWN244eGtOCjNIcU1UdnhiUDR5bU1RQ1hxaktzN2hBQUVmK0I3UjNHYzdmbnhQRDNMMGREU3dGanJXL2tvZy8wSTRNa1RiaGUKT29FRGdpT09UQmlHaDcvZ3RXTXVXcHBmYys0ckloR1FEMGRLR1NpUVFjL2tPMlExZmNyME1YM0Z0dnUwCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo="
                },
                {
                    "certificate_signing_request": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2FEQ0NBVkFDQVFBd0l6RUxNQWtHQTFVRUJoTUNWVk14RkRBU0JnTlZCQU1NQ3lvdVltRnVZVzVoTG1OaApNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXNKRFFiY0IxZVNwYjRjUmpEZXNWCm1lbmMvT0ZXMEZrcUQ3aUtDVVZmakFjSjdVOGowTTZmZC9FL3o1OFRrY0htQmRqbGlqcitoTStmVWRKMXhpQ3gKanlEMTkwZjU0N2s1RmZkYUFkcFhkaHpQZVJmVWt5MFlwTUY0M1BPVnc3MXhCQm8wQXgvK1RGNE9zd2tBa1J3egpFQVhpZkZTdlhPcUFnNG9BVG9MbVYrclh4cmFidFlBM1VFcGxxRTc2ZVdCdVdJbWpGZ2IzbDVWb25Sc1pPUXE1CjlVNE1aSzhoMi9LeEVqMUpGcFpSNnJteDdiUEZxOUNzbjhYb1V2MlRoRFBvNlNWRXJxUWxSdGNXVVFGSG9Ic2UKK0JUUmI5Q255WW5hdFF5YThaU0Y3QnZ4RFIrY0hyV04vNHhIeW1YdkU2VDJ4STFSN3pqQkZvQ3hISEVaY3MwTgowUUlEQVFBQm9BQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBSmNlTTY2SnpwaFVwZm9NY1VNd3NhYU1YczVQCjFEQTFnYkMzOE9sZEkrU2NtMkJxeWlkVmNRVXBaclhBSTdhdUJ1ZzVQUlJmcEpVSWZKSExxYlUraTJJODRwQlAKOG4xR0RKeTg0dGllM2RaVlcvakhzVGQ4QVpNTGJVZkFPZUgxREVWRzdFK0dXWlRtd25UZnJKZnNNSy9mN3Y0YwpxemdsTGpBd29Cbjl5QWhvdVBpU1JZY0Vhdng2bzhVbFpLZFBuQ0tzb240WGV5RUh1cjUwLzlmS05sWlhRMENvCndmQ3E2MzJkQ2Q2L0VyRkpOQTVEemRzVnp3aDZiWXJIU3R0UlFMN012NThpaEEzeVBwN3dUYVg3UTBxK1hvZTEKYksvU1gvT3U3V1pGUXFzZy8raENHZHBxL3NUYy9RaGRBcjNaMTk1NmpiS2k5bjg2d2FzZTdwYjhGcGc9Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo="
                },
            ]
        }
    ],
    "properties": {
        "certificate_signing_requests": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"certificate_signing_request": {"type": "string"}},
                "required": ["certificate_signing_request"],
            },
        }
    },
    "required": ["certificate_signing_requests"],
    "additionalProperties": True,
}

PROVIDER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$id": "https://canonical.github.io/charm-relation-interfaces/tls_certificates/v1/schemas/provider.json",  # noqa: E501
    "type": "object",
    "title": "`tls_certificates` provider root schema",
    "description": "The `tls_certificates` root schema comprises the entire provider databag for this interface.",  # noqa: E501
    "example": [
        {
            "certificates": [
                {
                    "ca": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNVENDQWhtZ0F3SUJBZ0lVRWg5dWl3Q0tQVXRLaTY3bFd6aFk1ckJoS1dFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0tERUxNQWtHQTFVRUJoTUNWVk14R1RBWEJnTlZCQU1NRUhKdmIzUmpZUzV3YVhwNllTNWpiMjB3SGhjTgpNakl3TnpJME1UY3lOVE15V2hjTk16SXdOekl4TVRjeU5UTXlXakFvTVFzd0NRWURWUVFHRXdKVlV6RVpNQmNHCkExVUVBd3dRY205dmRHTmhMbkJwZW5waExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0MKQVFvQ2dnRUJBSTJ3MGlVbUVrcTR6aWpaNllIcEtmQ1NhaGZuQjZMVTR6SW9YWFhnck9mRzNORkxuMlVpckQ3NgovNzdPSU9SR0k5TGk3czlScEQwZ21hY3lNK0o1S2RBbCsxUzJpWFRLSEhsWU9jd0EzZUZ3V0ZtTFBGY1poSjVJCjQ5b3BhL1NyVXkrMFFsbFlKUTdVSGdNNm1BSncyRUxtd3FPMlJsRGsvWnBDaTdieEtoR2VmcDR6K1l3dGNxVDMKMWduSzBEaE1yNVlYRHNHaDBPVWhjaWdjYmxBRW43bHBYdTREQThDSHpkdTZ5SlRuTmZXSXVSNXRwTHN5WFB3QgpWNzBORmQ0SnV6dW45L2tRZ2s0cmJtYWJYWi9wdzVPZ1NnMzVCTzNlRlU4RkxoM2dpTFRqQXJQOUx2M1hMN0NXCmE4MXMvZkpKK2xaRUs0aEVoUVlSMUc2UDMxRS9mWUVDQXdFQUFhTlRNRkV3SFFZRFZSME9CQllFRko4Qk10MUcKY1QvY1M5QVNFVEgvbW1pRzNhOWJNQjhHQTFVZEl3UVlNQmFBRko4Qk10MUdjVC9jUzlBU0VUSC9tbWlHM2E5YgpNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQXlERWdpUzIzaUMxM3RwCmtTMFlXOXMyNlk2RnJ4T2FMYVE0RWpPTXE2MkR5aGhKL1lKVjhlbExLd0RGd2NzSXVpMGN4eDBBT3V2TnAxaTQKNUJWYnIvMzN3SlQ5bVBSaklPK2FOWUtQSk9VNmw3UzV5MDBCb0FTekZoaGdVR1Q3aGhTK0crU2ZiTVZ1dUlxUgo1MU9RLzNsOFFBUzVKaWp5akN6cGdwY2tKVldoOUdiV2lYdkFwczMwb3dHdGh1Umpkd1NQUVY2V284eE13M3FkCmF0bDV2ekd0WkVqeG5hRzhtK1ppVkdUbVg4MWtUeVJQN0hlTndRZ3NMSUNQVzQyUThIVnNOL2g3VmVRTVVIdWcKenFrMFpTdWM5aDlpZ3dwc1lDNndpQUoyckxEOE8wRkZYNkV6elZmQlZEbjUxQW9WRklRS256UU1udDF6T1g0YgpPWjV4MStNPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",  # noqa: E501
                    "chain": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNVENDQWhtZ0F3SUJBZ0lVRWg5dWl3Q0tQVXRLaTY3bFd6aFk1ckJoS1dFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0tERUxNQWtHQTFVRUJoTUNWVk14R1RBWEJnTlZCQU1NRUhKdmIzUmpZUzV3YVhwNllTNWpiMjB3SGhjTgpNakl3TnpJME1UY3lOVE15V2hjTk16SXdOekl4TVRjeU5UTXlXakFvTVFzd0NRWURWUVFHRXdKVlV6RVpNQmNHCkExVUVBd3dRY205dmRHTmhMbkJwZW5waExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0MKQVFvQ2dnRUJBSTJ3MGlVbUVrcTR6aWpaNllIcEtmQ1NhaGZuQjZMVTR6SW9YWFhnck9mRzNORkxuMlVpckQ3NgovNzdPSU9SR0k5TGk3czlScEQwZ21hY3lNK0o1S2RBbCsxUzJpWFRLSEhsWU9jd0EzZUZ3V0ZtTFBGY1poSjVJCjQ5b3BhL1NyVXkrMFFsbFlKUTdVSGdNNm1BSncyRUxtd3FPMlJsRGsvWnBDaTdieEtoR2VmcDR6K1l3dGNxVDMKMWduSzBEaE1yNVlYRHNHaDBPVWhjaWdjYmxBRW43bHBYdTREQThDSHpkdTZ5SlRuTmZXSXVSNXRwTHN5WFB3QgpWNzBORmQ0SnV6dW45L2tRZ2s0cmJtYWJYWi9wdzVPZ1NnMzVCTzNlRlU4RkxoM2dpTFRqQXJQOUx2M1hMN0NXCmE4MXMvZkpKK2xaRUs0aEVoUVlSMUc2UDMxRS9mWUVDQXdFQUFhTlRNRkV3SFFZRFZSME9CQllFRko4Qk10MUcKY1QvY1M5QVNFVEgvbW1pRzNhOWJNQjhHQTFVZEl3UVlNQmFBRko4Qk10MUdjVC9jUzlBU0VUSC9tbWlHM2E5YgpNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQXlERWdpUzIzaUMxM3RwCmtTMFlXOXMyNlk2RnJ4T2FMYVE0RWpPTXE2MkR5aGhKL1lKVjhlbExLd0RGd2NzSXVpMGN4eDBBT3V2TnAxaTQKNUJWYnIvMzN3SlQ5bVBSaklPK2FOWUtQSk9VNmw3UzV5MDBCb0FTekZoaGdVR1Q3aGhTK0crU2ZiTVZ1dUlxUgo1MU9RLzNsOFFBUzVKaWp5akN6cGdwY2tKVldoOUdiV2lYdkFwczMwb3dHdGh1Umpkd1NQUVY2V284eE13M3FkCmF0bDV2ekd0WkVqeG5hRzhtK1ppVkdUbVg4MWtUeVJQN0hlTndRZ3NMSUNQVzQyUThIVnNOL2g3VmVRTVVIdWcKenFrMFpTdWM5aDlpZ3dwc1lDNndpQUoyckxEOE8wRkZYNkV6elZmQlZEbjUxQW9WRklRS256UU1udDF6T1g0YgpPWjV4MStNPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",  # noqa: E501
                    "certificate_signing_request": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2FEQ0NBVkFDQVFBd0l6RUxNQWtHQTFVRUJoTUNWVk14RkRBU0JnTlZCQU1NQ3lvdWNHbDZlbUV1WTI5dApNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTJNTkVqM2VNelp3Y2NzbE1ld1JDClE1bTdVYko5dDBrUFlhcmNlb0JmOUlyT2Rkd2F1Z012TCtHcnlaMjdMOGE3b2JDMVlHeVV5Uzh4YUpBYkxSamMKY1RDYTJrV2NVMUJ1NnRrTGtyVmhpc1ZHTWNKT3FBek1lRWdrczRQTTU2RndNdFFaSUxKblFDNGd4c21rMnVQTgpMeXpMOFA5MUFZN2twaitLaUVyVEF1cy9PYzZMRW9WcW5pRklZMzZscTlSckdDL1IzOGNqVWRQRnZjU3hGRmYwCmVuSFJtYkNkd1J6ZmZQYzVoT2YwUFl2cCtuKzVQWGcyYjZjRlFvV0FaQTYvQjhTS3IvZmxRTmFEd3cwb2E3WHQKdjlUZSsrNzY2UHB0dDkwU1JVSXRta3FFNkZiaWdqZVlmWUVEWVRPRWwweU9DbzNEUlZUcVptNjFsSFBoUzU4VApnUUlEQVFBQm9BQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRXR4M1BJb2ozRko1VG41czZhU1NobHcwL3VSCkxKQkxYUCtSZUNRNkxTT3NabWpiUE1QVHo2ZVpKejR3cko1Zy9yRmJBeGp1VW03T2pWTUwzNDdkNzNteERVM2cKaENFd1NGN1NMSllwbUl6MnRPNTB1YmdDVFM5UnBZdDNWMkU4TEhVY3piVUhXQmRCUDE1TElTZVRQZWxvRlFIUgppb3I4VElQSHV1N0JGK3dwYlovdVZ0SE5TOUE3K2tlbmtHNjhlN2NJakNTZFl5Q0NaTnZLUkZLYU1IT3dHVWNICkpDZmNmbkErOGo5VUh6S0NTOWNIZjRhQmpBMm9QZ0lVanZCWlNRd0hlQnYzOFVFdXg5VmJRdXdHVHZEYlo3R3QKSFh5RnJRUWRBNW80RmFjMWNCMVhwc2JmbDZXRXNaSUNwOXF0Rmtsb1ZqK3FzbytBY2o0ZFZxQ0hjazg9Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=",  # noqa: E501
                    "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURmekNDQW1lZ0F3SUJBZ0lVTWJRVk1uK3JOVjlOUjlCQ1pRRE9CZkg5NkJVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0tERUxNQWtHQTFVRUJoTUNWVk14R1RBWEJnTlZCQU1NRUhKdmIzUmpZUzV3YVhwNllTNWpiMjB3SGhjTgpNakl3TnpJME1UY3lOVE15V2hjTk1qUXhNREkyTVRjeU5UTXlXakFqTVFzd0NRWURWUVFHRXdKVlV6RVVNQklHCkExVUVBd3dMS2k1d2FYcDZZUzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUIKQVFEWXcwU1BkNHpObkJ4eXlVeDdCRUpEbWJ0UnNuMjNTUTlocXR4NmdGLzBpczUxM0JxNkF5OHY0YXZKbmJzdgp4cnVoc0xWZ2JKVEpMekZva0JzdEdOeHhNSnJhUlp4VFVHN3EyUXVTdFdHS3hVWXh3azZvRE14NFNDU3pnOHpuCm9YQXkxQmtnc21kQUxpREd5YVRhNDgwdkxNdncvM1VCanVTbVA0cUlTdE1DNno4NXpvc1NoV3FlSVVoamZxV3IKMUdzWUw5SGZ4eU5SMDhXOXhMRVVWL1I2Y2RHWnNKM0JITjk4OXptRTUvUTlpK242ZjdrOWVEWnZwd1ZDaFlCawpEcjhIeElxdjkrVkExb1BERFNocnRlMi8xTjc3N3ZybyttMjMzUkpGUWkyYVNvVG9WdUtDTjVoOWdRTmhNNFNYClRJNEtqY05GVk9wbWJyV1VjK0ZMbnhPQkFnTUJBQUdqZ2FVd2dhSXdDUVlEVlIwVEJBSXdBREJWQmdOVkhSRUUKVGpCTWdnc3FMbkJwZW5waExtTnZiWUlQS2k1dWJYTXVjR2w2ZW1FdVkyOXRnaE1xTG5OMFlXZHBibWN1Y0dsNgplbUV1WTI5dGdoY3FMbTV0Y3k1emRHRm5hVzVuTG5CcGVucGhMbU52YlRBZEJnTlZIUTRFRmdRVThWbDBWWFZJCmJiN1lrTm1UTXVVNldlTjVQVDh3SHdZRFZSMGpCQmd3Rm9BVW53RXkzVVp4UDl4TDBCSVJNZithYUliZHIxc3cKRFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUFOc1hBRWZlS3VkSjNpQkhpVHJEZDRoV055cCtvTEVzcEVlQ01pawpQTmdZaGROMGE5bDdRcVU2TVFtWGtXTy9hYzJPN0NrTklmU0UyNHkvOTZ2dXQyRXhLelM3UzR3LzZsempMaFNqCkV3ZUVJQjhvYTZPWVIycmlaakxMV2k4REdrZkw5cFdDcEorU2lzRkpuL1JCa2JvT0VmMDV5U1Y2aCtXNVdrRS8KOUxCU2NxZUJWUDRLelRiQ200S1dmNkc1RjhsQzBGMEZYNGtBY1RtSDhnalRoSzhqYTFNOGIxS1lXTnZzSW43dgo3dG9nNHIzVTk5eGZxRHhLdUxLRFFDclU5Wk9pc1hkVTRFbmwyUzFWaUI2Yld6RW9VekZxVHJBNmpPMUpNdTI3CkhiS3I1Mm5laWp1QndsWTY4VlZDMUpHRU9yQmtDdmxGaFNuS0hET1daOUhpbXVnPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",  # noqa: E501
                }
            ]
        }
    ],
    "properties": {
        "certificates": {
            "$id": "#/properties/certificates",
            "type": "array",
            "items": {
                "$id": "#/properties/certificates/items",
                "type": "object",
                "required": ["certificate_signing_request", "certificate", "ca", "chain"],
                "properties": {
                    "certificate_signing_request": {
                        "$id": "#/properties/certificates/items/certificate_signing_request",
                        "type": "string",
                    },
                    "certificate": {
                        "$id": "#/properties/certificates/items/certificate",
                        "type": "string",
                    },
                    "ca": {"$id": "#/properties/certificates/items/ca", "type": "string"},
                    "chain": {"$id": "#/properties/certificates/items/chain", "type": "string"},
                },
            },
        }
    },
    "required": ["certificates"],
}

logger = logging.getLogger(__name__)


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a TLS certificate is available."""

    def __init__(
        self, handle, certificate: str, certificate_signing_request: str, ca: str, chain: str
    ):
        super().__init__(handle)
        self.certificate = certificate
        self.certificate_signing_request = certificate_signing_request
        self.ca = ca
        self.chain = chain

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {
            "certificate": self.certificate,
            "certificate_signing_request": self.certificate_signing_request,
            "ca": self.ca,
            "chain": self.chain,
        }

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]
        self.certificate_signing_request = snapshot["certificate"]
        self.ca = snapshot["ca"]
        self.chain = snapshot["chain"]


class CertificateAlmostExpiredEvent(EventBase):
    """Charm Event triggered when a TLS certificate is almost expired."""

    def __init__(self, handle, certificate: str, expiry: int):
        """CertificateAlmostExpiredEvent.

        Args:
            handle (Handle): Juju framework handle
            certificate (str): TLS Certificate
            expiry (int): Days before expiry
        """
        super().__init__(handle)
        self.certificate = certificate
        self.expiry = expiry

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {"certificate": self.certificate, "expiry": self.expiry}

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]
        self.expiry = snapshot["expiry"]


class CertificateExpiredEvent(EventBase):
    """Charm Event triggered when a TLS certificate is expired."""

    def __init__(self, handle, certificate: str):
        super().__init__(handle)
        self.certificate = certificate

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {"certificate": self.certificate}

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]


class CertificateRequestEvent(EventBase):
    """Charm Event triggered when a TLS certificate is required."""

    def __init__(self, handle, certificate_signing_request: str, relation_id: int):
        super().__init__(handle)
        self.certificate_signing_request = certificate_signing_request
        self.relation_id = relation_id

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {
            "certificate_signing_request": self.certificate_signing_request,
            "relation_id": self.relation_id,
        }

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate_signing_request = snapshot["certificate_signing_request"]
        self.relation_id = snapshot["relation_id"]


def _load_relation_data(raw_relation_data: dict) -> dict:
    """Loads relation data from the relation data bag.

    Json loads all data.

    Args:
        raw_relation_data: Relation data from the databag

    Returns:
        dict: Relation data in dict format.
    """
    certificate_data = dict()
    for key in raw_relation_data:
        try:
            certificate_data[key] = json.loads(raw_relation_data[key])
        except json.decoder.JSONDecodeError:
            certificate_data[key] = raw_relation_data[key]
    return certificate_data


def generate_private_key(
    password: bytes,
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> bytes:
    """Generates a private key.

    Args:
        password (bytes): Password for decrypting the private key
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        bytes: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    return key_bytes


def generate_csr(
    private_key: bytes, private_key_password: bytes, subject: str, sans: Optional[List[str]] = None
) -> bytes:
    """Generates a CSR using private key and subject.

    Args:
        private_key (bytes): Private key
        private_key_password (bytes): Private key password
        subject (str): CSR Subject.
        sans (list): List of subject alternative names

    Returns:
        bytes: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
    csr = x509.CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
            ]
        )
    )
    if sans:
        csr.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]), critical=False
        )
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM)


class CertificatesProviderCharmEvents(CharmEvents):
    """List of events that the TLS Certificates provider charm can leverage."""

    certificate_request = EventSource(CertificateRequestEvent)


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)
    certificate_almost_expired = EventSource(CertificateAlmostExpiredEvent)
    certificate_expired = EventSource(CertificateExpiredEvent)


class TLSCertificatesProvides(Object):
    """TLS certificates provider class to be instantiated by TLS certificates providers."""

    on = CertificatesProviderCharmEvents()

    def __init__(self, charm: CharmBase, relationship_name: str):
        super().__init__(charm, relationship_name)
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.charm = charm
        self.relationship_name = relationship_name

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        """Uses JSON schema validator to validate relation data content.

        Args:
            certificates_data (dict): Certificate data dictionary as retrieved from relation data.

        Returns:
            bool: True/False depending on whether the relation data follows the json schema.
        """
        try:
            validate(instance=certificates_data, schema=REQUIRER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def set_relation_certificate(
        self,
        certificate: str,
        certificate_signing_request: str,
        ca: str,
        chain: str,
        relation_id: int,
    ) -> None:
        """Adds certificates to relation data.

        Args:
            certificate (str): Certificate
            certificate_signing_request (str): Certificate signing request
            ca (str): CA Certificate
            chain (str): CA Chain certificate
            relation_id (int): Juju relation ID

        Returns:
            None
        """
        certificates_relation = self.model.get_relation(
            relation_name=self.relationship_name, relation_id=relation_id
        )
        relation_data = certificates_relation.data[self.model.unit]  # type: ignore[union-attr]
        loaded_relation_data = _load_relation_data(relation_data)
        new_certificate = {
            "certificate": certificate,
            "certificate_signing_request": certificate_signing_request,
            "ca": ca,
            "chain": chain,
        }
        if "certificates" not in loaded_relation_data:
            certificates = [new_certificate]
        else:
            certificates = loaded_relation_data["certificates"]
            for i in range(len(certificates)):
                if certificates[i]["certificate_signing_request"] == certificate_signing_request:
                    certificates.pop(i)
            loaded_relation_data["certificates"].append(new_certificate)

        relation_data["certificates"] = json.dumps(certificates)

    def _on_relation_changed(self, event) -> None:
        """Handler triggerred on relation changed event.

        Looks at cert_requests and client_cert_requests fields in relation data and emit
        certificate request events for each entry.

        Args:
            event: Juju event

        Returns:
            None
        """
        relation_data = _load_relation_data(event.relation.data[event.unit])
        if not relation_data:
            logger.info("No relation data - Deferring")
            return
        if not self._relation_data_is_valid(relation_data):
            logger.warning("Relation data did not pass JSON Schema validation - Deferring")
            return
        for certificate_request in relation_data.get("certificate_signing_requests", {}):
            self.on.certificate_request.emit(
                certificate_signing_request=certificate_request.get("certificate_signing_request"),
                relation_id=event.relation.id,
            )


class TLSCertificatesRequires(Object):
    """TLS certificates requirer class to be instantiated by TLS certificates requirers."""

    on = CertificatesRequirerCharmEvents()

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
    ):
        """Generates/use private key and observes relation changed event.

        Args:
            charm: Charm object
            relationship_name: Juju relation name
        """
        super().__init__(charm, relationship_name)
        self.relationship_name = relationship_name
        self.charm = charm
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.framework.observe(charm.on.update_status, self._on_update_status)

    def request_certificate(
        self,
        private_key: bytes,
        private_key_password: bytes,
        common_name: str,
        sans: list = None,
    ) -> bytes:
        """Request TLS certificate to provider charm.

        Args:
            private_key (bytes): Private key
            private_key_password (bytes): Private key password
            common_name (str): Common name.
            sans (list): Subject Alternative Name

        Returns:
            bytes: The CSR passed in the relation data
        """
        logger.info("Received request to create certificate")
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            message = (
                f"Relation {self.relationship_name} does not exist - "
                f"The certificate request can't be completed"
            )
            logger.error(message)
            raise RuntimeError(message)
        relation_data = _load_relation_data(relation.data[self.model.unit])
        csr = generate_csr(
            private_key=private_key,
            private_key_password=private_key_password,
            subject=common_name,
            sans=sans,
        )
        new_certificate_request = {"certificate_signing_request": csr.decode()}
        if "certificate_signing_requests" in relation_data:
            certificate_request_list = relation_data["certificate_signing_requests"]
            if new_certificate_request in certificate_request_list:
                logger.info("Request was already made - Doing nothing")
                return csr
            certificate_request_list.append(new_certificate_request)
        else:
            certificate_request_list = [new_certificate_request]
        relation.data[self.model.unit]["certificate_signing_requests"] = json.dumps(
            certificate_request_list
        )
        logger.info("Certificate request sent to provider")
        return csr

    def revoke_certificate(self, certificate_signing_request: str) -> None:
        """Removes CSR from relation data.

        The provider of this relation is then expected to remove certificates associated to this
        CSR from the relation data as well and emit a revoke_certificate event for the provider
        charm to interpret.

        Args:
            certificate_signing_request: Certificate Signing Request

        Returns:
            None
        """
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            message = (
                f"Relation {self.relationship_name} does not exist - "
                f"The certificate request can't be completed"
            )
            logger.error(message)
            raise RuntimeError(message)
        print(self.model.unit)
        relation_data = _load_relation_data(relation.data[self.model.unit])
        certificate_request_list = relation_data.get("certificate_signing_requests")
        if not certificate_request_list:
            logger.info("No CSR in relation data.")
            return
        for i in range(len(certificate_request_list)):
            if (
                certificate_request_list[i]["certificate_signing_request"]
                == certificate_signing_request
            ):
                certificate_request_list.pop()

        relation.data[self.model.unit]["certificate_signing_requests"] = json.dumps(
            certificate_request_list
        )
        logger.info("Certificate revocation sent to provider")

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        """Checks whether relation data is valid based on json schema.

        Args:
            certificates_data: Certificate data in dict format.

        Returns:
            bool: Whether relation data is valid.
        """
        try:
            validate(instance=certificates_data, schema=PROVIDER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handler triggerred on relation changed events.

        Args:
            event: Juju event

        Returns:
            None
        """
        relation_data = _load_relation_data(event.relation.data[event.unit])
        if not self._relation_data_is_valid(relation_data):
            logger.warning("Relation data did not pass JSON Schema validation - Deferring")
            event.defer()
            return

        for certificate in relation_data["certificates"]:
            self.on.certificate_available.emit(
                certificate_signing_request=certificate["certificate_signing_request"],
                certificate=certificate["certificate"],
                ca=certificate["ca"],
                chain=certificate["chain"],
            )

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Triggered on update status event.

        Goes through each certificate in the "certificates" relation and checks their expiry date.
        If they are close to expire (<7 days), emits a CertificateAlmostExpiredEvent event and if
        they are expired, emits a CertificateExpiredEvent.

        Args:
            event (UpdateStatusEvent): Juju event

        Returns:
            None
        """
        logger.info("Update status event")
        relation = self.model.get_relation("certificates")
        if not relation:
            return
        for unit in relation.units:
            relation_data = _load_relation_data(relation.data[unit])
            if self._relation_data_is_valid(relation_data):
                logger.info("Relation data is valid")
                certificates = relation_data.get("certificates")
                if not certificates:
                    continue
                for certificate_dict in certificates:
                    certificate = certificate_dict["certificate"]
                    logger.info(type(certificate_dict))
                    certificate_object = x509.load_pem_x509_certificate(data=certificate.encode())
                    logger.info(certificate_object.not_valid_after)
                    logger.info(datetime.now())
                    time_difference = certificate_object.not_valid_after - datetime.now()
                    if time_difference.days < 0:
                        logger.info("Certificate is expired")
                        self.on.certificate_expired.emit(certificate=certificate)
                        self.revoke_certificate(certificate)
                        continue
                    if time_difference.days < 7:
                        logger.info("Certificate almost expired")
                        self.on.certificate_almost_expired.emit(certificate=certificate)
