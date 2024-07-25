# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm library for managing TLS certificates (V4) - BETA.

> Warning: This is a beta version of the tls-certificates interface library.
> Use at your own risk.

This library contains the Requires and Provides classes for handling the tls-certificates
interface.

Pre-requisites:
  - Juju >= 3.1.8

## Getting Started
From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v4.tls_certificates
```

Add the following libraries to the charm's `requirements.txt` file:
- cryptography >= 42.0.0
- pydantic >= 2.0.0

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

### Requirer charm
The requirer charm is the charm requiring certificates from another charm that provides them.

#### Example

In the following example, the requiring charm requests a certificate using attributes
from the Juju configuration options.

```python
from typing import List, Optional, cast

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequest,
    Mode,
    TLSCertificatesRequiresV4,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus


class TLSCertificatesRequirer(CharmBase):
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
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        if not certificate:
            event.fail("Certificate not available")
            return
        event.set_results(
            {
                "certificate": certificate.certificate,
                "ca": certificate.ca,
                "chain": certificate.chain,
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
    main(TLSCertificatesRequirer)
```

You can integrate both charms by running:

```bash
juju integrate <tls-certificates provider> <tls-certificates requirer>
```
"""  # noqa: D214, D405, D411, D416

import copy
import ipaddress
import json
import logging
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, MutableMapping, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ops import BoundEvent, CharmBase, CharmEvents, SecretExpiredEvent
from ops.framework import EventBase, EventSource, Handle, Object
from ops.jujuversion import JujuVersion
from ops.model import (
    Application,
    ModelError,
    SecretNotFoundError,
    Unit,
)
from pydantic import BaseModel, ConfigDict, ValidationError

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 4

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0

PYDEPS = ["cryptography", "pydantic"]

logger = logging.getLogger(__name__)


class TLSCertificatesError(Exception):
    """Base class for custom errors raised by this library."""


class DataValidationError(TLSCertificatesError):
    """Raised when data validation fails."""


class DatabagModel(BaseModel):
    """Base databag model."""

    model_config = ConfigDict(
        # tolerate additional keys in databag
        extra="ignore",
        # Allow instantiating this class by field name (instead of forcing alias).
        populate_by_name=True,
        # Custom config key: whether to nest the whole datastructure (as json)
        # under a field or spread it out at the toplevel.
        _NEST_UNDER=None,
    )  # type: ignore
    """Pydantic config."""

    @classmethod
    def load(cls, databag: MutableMapping):
        """Load this model from a Juju databag."""
        nest_under = cls.model_config.get("_NEST_UNDER")
        if nest_under:
            return cls.model_validate(json.loads(databag[nest_under]))

        try:
            data = {
                k: json.loads(v)
                for k, v in databag.items()
                # Don't attempt to parse model-external values
                if k in {(f.alias or n) for n, f in cls.model_fields.items()}
            }
        except json.JSONDecodeError as e:
            msg = f"invalid databag contents: expecting json. {databag}"
            logger.error(msg)
            raise DataValidationError(msg) from e

        try:
            return cls.model_validate_json(json.dumps(data))
        except ValidationError as e:
            msg = f"failed to validate databag: {databag}"
            logger.debug(msg, exc_info=True)
            raise DataValidationError(msg) from e

    def dump(self, databag: Optional[MutableMapping] = None, clear: bool = True):
        """Write the contents of this model to Juju databag.

        Args:
            databag: The databag to write to.
            clear: Whether to clear the databag before writing.

        Returns:
            MutableMapping: The databag.
        """
        if clear and databag:
            databag.clear()

        if databag is None:
            databag = {}
        nest_under = self.model_config.get("_NEST_UNDER")
        if nest_under:
            databag[nest_under] = self.model_dump_json(
                by_alias=True,
                # skip keys whose values are default
                exclude_defaults=True,
            )
            return databag

        dct = self.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        databag.update({k: json.dumps(v) for k, v in dct.items()})
        return databag


class Certificate(BaseModel):
    """Certificate model."""

    ca: str
    certificate_signing_request: str
    certificate: str
    chain: Optional[List[str]] = None
    recommended_expiry_notification_time: Optional[int] = None
    revoked: Optional[bool] = None


class CertificateSigningRequest(BaseModel):
    """Certificate signing request model."""

    certificate_signing_request: str
    ca: Optional[bool]


class ProviderApplicationData(DatabagModel):
    """Provider application data model."""

    certificates: List[Certificate]


class RequirerData(DatabagModel):
    """Requirer data model.

    The same model is used for the unit and application data.
    """

    certificate_signing_requests: List[CertificateSigningRequest]


class ProviderSchema(BaseModel):
    """Provider schema for TLS Certificates."""

    app: ProviderApplicationData


class RequirerSchema(BaseModel):
    """Requirer schema for TLS Certificates."""

    app: RequirerData
    unit: RequirerData


class Mode(Enum):
    """Enum representing the mode of the certificate request.

    UNIT (default): Request a certificate for the unit.
        Each unit will have its own private key and certificate.
    APP: Request a certificate for the application.
        The private key and certificate will be shared by all units.
    """

    UNIT = 1
    APP = 2


@dataclass
class CertificateRequest:
    """This class represents a certificate request."""

    common_name: str
    sans_dns: Optional[List[str]] = None
    sans_ip: Optional[List[str]] = None
    sans_oid: Optional[List[str]] = None
    email_address: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    is_ca: bool = False

    def is_valid(self) -> bool:
        """Check whether the certificate request is valid."""
        if not self.common_name:
            return False
        return True

    @staticmethod
    def from_string(csr: str) -> Optional["CertificateRequest"]:
        """Create a CertificateRequest object from a CSR."""
        try:
            csr_object = x509.load_pem_x509_csr(csr.encode())
        except ValueError as e:
            logger.error("Could not load CSR: %s", e)
            return None
        common_name = csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        country_name = csr_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        state_or_province_name = csr_object.subject.get_attributes_for_oid(
            NameOID.STATE_OR_PROVINCE_NAME
        )
        locality_name = csr_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        organization_name = csr_object.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        email_address = csr_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        try:
            sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans_dns = [
                str(san)
                for san in sans.get_values_for_type(x509.DNSName)
                if isinstance(san, x509.DNSName)
            ]
            sans_ip = [
                str(san)
                for san in sans.get_values_for_type(x509.IPAddress)
                if isinstance(san, x509.IPAddress)
            ]
            sans_oid = [
                str(san)
                for san in sans.get_values_for_type(x509.RegisteredID)
                if isinstance(san, x509.RegisteredID)
            ]
        except x509.ExtensionNotFound:
            sans = []
            sans_dns = []
            sans_ip = []
            sans_oid = []
        return CertificateRequest(
            common_name=str(common_name[0].value),
            country_name=str(country_name[0].value) if country_name else None,
            state_or_province_name=str(state_or_province_name[0].value)
            if state_or_province_name
            else None,
            locality_name=str(locality_name[0].value) if locality_name else None,
            organization=str(organization_name[0].value) if organization_name else None,
            email_address=str(email_address[0].value) if email_address else None,
            sans_dns=sans_dns,
            sans_ip=sans_ip if sans_ip else None,
            sans_oid=sans_oid if sans_oid else None,
        )


@dataclass
class ProviderCertificate:
    """This class represents a certificate provided by the TLS provider."""

    common_name: str
    sans_dns: Optional[List[str]] = None
    sans_ip: Optional[List[str]] = None
    sans_oid: Optional[List[str]] = None
    email_address: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    expiry_time: Optional[datetime] = None
    validity_start_time: Optional[datetime] = None

    @staticmethod
    def from_string(certificate: str) -> Optional["ProviderCertificate"]:
        """Create a ProviderCertificate object from a certificate."""
        try:
            certificate_object = x509.load_pem_x509_certificate(data=certificate.encode())
        except ValueError as e:
            logger.error("Could not load certificate: %s", e)
            return None
        common_name = certificate_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        country_name = certificate_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        state_or_province_name = certificate_object.subject.get_attributes_for_oid(
            NameOID.STATE_OR_PROVINCE_NAME
        )
        locality_name = certificate_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        organization_name = certificate_object.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        email_address = certificate_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        try:
            sans = certificate_object.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            sans_dns = [
                str(san)
                for san in sans.get_values_for_type(x509.DNSName)
                if isinstance(san, x509.DNSName)
            ]
            sans_ip = [
                str(san)
                for san in sans.get_values_for_type(x509.IPAddress)
                if isinstance(san, x509.IPAddress)
            ]
            sans_oid = [
                str(san)
                for san in sans.get_values_for_type(x509.RegisteredID)
                if isinstance(san, x509.RegisteredID)
            ]
        except x509.ExtensionNotFound:
            sans_dns = []
            sans_ip = []
            sans_oid = []
        expiry_time = certificate_object.not_valid_after_utc
        validity_start_time = certificate_object.not_valid_before_utc

        return ProviderCertificate(
            common_name=str(common_name[0].value),
            country_name=str(country_name[0].value) if country_name else None,
            state_or_province_name=str(state_or_province_name[0].value)
            if state_or_province_name
            else None,
            locality_name=str(locality_name[0].value) if locality_name else None,
            organization=str(organization_name[0].value) if organization_name else None,
            email_address=str(email_address[0].value) if email_address else None,
            sans_dns=sans_dns,
            sans_ip=sans_ip if sans_ip else None,
            sans_oid=sans_oid if sans_oid else None,
            expiry_time=expiry_time,
            validity_start_time=validity_start_time,
        )


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a TLS certificate is available."""

    def __init__(
        self,
        handle: Handle,
        certificate: str,
        certificate_signing_request: str,
        ca: str,
        chain: List[str],
    ):
        super().__init__(handle)
        self.certificate = certificate
        self.certificate_signing_request = certificate_signing_request
        self.ca = ca
        self.chain = chain

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "certificate": self.certificate,
            "certificate_signing_request": self.certificate_signing_request,
            "ca": self.ca,
            "chain": self.chain,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.certificate = snapshot["certificate"]
        self.certificate_signing_request = snapshot["certificate_signing_request"]
        self.ca = snapshot["ca"]
        self.chain = snapshot["chain"]

    def chain_as_pem(self) -> str:
        """Return full certificate chain as a PEM string."""
        return "\n\n".join(reversed(self.chain))


def _get_closest_future_time(
    expiry_notification_time: datetime, expiry_time: datetime
) -> datetime:
    """Return expiry_notification_time if not in the past, otherwise return expiry_time.

    Args:
        expiry_notification_time (datetime): Notification time of impending expiration
        expiry_time (datetime): Expiration time

    Returns:
        datetime: expiry_notification_time if not in the past, expiry_time otherwise
    """
    return (
        expiry_notification_time
        if datetime.now(timezone.utc) < expiry_notification_time
        else expiry_time
    )


def calculate_expiry_notification_time(
    validity_start_time: datetime,
    expiry_time: datetime,
    provider_recommended_notification_time: Optional[int],
) -> datetime:
    """Calculate a reasonable time to notify the user about the certificate expiry.

    It takes into account the time recommended by the provider.
    Time recommended by the provider is preferred,
    then dynamically calculated time.

    Args:
        validity_start_time: Certificate validity time
        expiry_time: Certificate expiry time
        provider_recommended_notification_time:
            Time in hours prior to expiry to notify the user.
            Recommended by the provider.

    Returns:
        datetime: Time to notify the user about the certificate expiry.
    """
    if provider_recommended_notification_time is not None:
        provider_recommended_notification_time = abs(provider_recommended_notification_time)
        provider_recommendation_time_delta = expiry_time - timedelta(
            hours=provider_recommended_notification_time
        )
        if validity_start_time < provider_recommendation_time_delta:
            return provider_recommendation_time_delta
    calculated_hours = (expiry_time - validity_start_time).total_seconds() / (3600 * 3)
    return expiry_time - timedelta(hours=calculated_hours)


def generate_private_key(
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> str:
    """Generate a private key with the RSA algorithm.

    Args:
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        str: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_bytes.decode()


def generate_csr(  # noqa: C901
    private_key: str,
    common_name: str,
    add_unique_id_to_subject_name: bool = True,
    organization: Optional[str] = None,
    email_address: Optional[str] = None,
    country_name: Optional[str] = None,
    state_or_province_name: Optional[str] = None,
    locality_name: Optional[str] = None,
    sans: Optional[List[str]] = None,
    sans_oid: Optional[List[str]] = None,
    sans_ip: Optional[List[str]] = None,
    sans_dns: Optional[List[str]] = None,
    additional_critical_extensions: Optional[List] = None,
) -> str:
    """Generate a CSR using private key and subject.

    Args:
        private_key (str): Private key
        common_name (str): CSR Common Name that can be an IP or a
            Full Qualified Domain Name (FQDN).
        add_unique_id_to_subject_name (bool): Whether a unique ID must be added to the CSR's
            subject name. Always leave to "True" when the CSR is used to request certificates
            using the tls-certificates relation.
        organization (str): Name of organization.
        email_address (str): Email address.
        country_name (str): Country Name.
        state_or_province_name (str): State or Province Name.
        locality_name (str): Locality Name.
        sans (list): Use sans_dns - this will be deprecated in a future release
            List of DNS subject alternative names (keeping it for now for backward compatibility)
        sans_oid (list): List of registered ID SANs
        sans_dns (list): List of DNS subject alternative names (similar to the arg: sans)
        sans_ip (list): List of IP subject alternative names
        additional_critical_extensions (list): List of critical additional extension objects.
            Object must be a x509 ExtensionType.

    Returns:
        str: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key.encode(), password=None)
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    if add_unique_id_to_subject_name:
        unique_identifier = uuid.uuid4()
        subject_name.append(
            x509.NameAttribute(x509.NameOID.X500_UNIQUE_IDENTIFIER, str(unique_identifier))
        )
    if organization:
        subject_name.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization))
    if email_address:
        subject_name.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email_address))
    if country_name:
        subject_name.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name))
    if state_or_province_name:
        subject_name.append(
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name)
        )
    if locality_name:
        subject_name.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality_name))
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))

    _sans: List[x509.GeneralName] = []
    if sans_oid:
        _sans.extend([x509.RegisteredID(x509.ObjectIdentifier(san)) for san in sans_oid])
    if sans_ip:
        _sans.extend([x509.IPAddress(ipaddress.ip_address(san)) for san in sans_ip])
    if sans:
        _sans.extend([x509.DNSName(san) for san in sans])
    if sans_dns:
        _sans.extend([x509.DNSName(san) for san in sans_dns])
    if _sans:
        csr = csr.add_extension(x509.SubjectAlternativeName(set(_sans)), critical=False)

    if additional_critical_extensions:
        for extension in additional_critical_extensions:
            csr = csr.add_extension(extension, critical=True)

    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM).decode()


def get_sha256_hex(data: str) -> str:
    """Calculate the hash of the provided data and return the hexadecimal representation."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize().hex()


def csr_matches_private_key(csr: str, key: str) -> bool:
    """Check if a CSR matches a private key.

    This function only works with RSA keys.

    Args:
        csr (str): Certificate Signing Request as a string
        key (str): Private key as a string
    Returns:
        bool: True/False depending on whether the CSR matches the private key.
    """
    try:
        csr_object = x509.load_pem_x509_csr(csr.encode("utf-8"))
        key_object = serialization.load_pem_private_key(data=key.encode("utf-8"), password=None)
        key_object_public_key = key_object.public_key()
        csr_object_public_key = csr_object.public_key()
        if not isinstance(key_object_public_key, rsa.RSAPublicKey):
            logger.warning("Key is not an RSA key")
            return False
        if not isinstance(csr_object_public_key, rsa.RSAPublicKey):
            logger.warning("CSR is not an RSA key")
            return False
        if csr_object_public_key.public_numbers().n != key_object_public_key.public_numbers().n:
            logger.warning("Public key numbers between CSR and key do not match")
            return False
    except ValueError:
        logger.warning("Could not load certificate or CSR.")
        return False
    return True


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)


class TLSCertificatesRequiresV4(Object):
    """A class to manage the TLS certificates interface for a unit or app."""

    on = CertificatesRequirerCharmEvents()  # type: ignore[reportAssignmentType]

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
        certificate_requests: List[CertificateRequest],
        mode: Mode = Mode.UNIT,
        refresh_events: List[BoundEvent] = [],
    ):
        """Create a new instance of the TLSCertificatesRequiresV4 class.

        Args:
            charm (CharmBase): The charm instance to relate to.
            relationship_name (str): The name of the relation that provides the certificates.
            certificate_requests (List[CertificateRequest]): A list of certificate requests.
            mode (Mode): Whether to use unit or app certificates mode. Default is Mode.UNIT.
            refresh_events (List[BoundEvent]): A list of events to trigger a refresh of
              the certificates.
        """
        super().__init__(charm, relationship_name)
        if not JujuVersion.from_environ().has_secrets:
            logger.warning("This version of the TLS library requires Juju secrets (Juju >= 3.0)")
        if not self._mode_is_valid(mode):
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP")
        for certificate_request in certificate_requests:
            if not certificate_request.is_valid():
                raise TLSCertificatesError("Invalid certificate request")
        self.charm = charm
        self.relationship_name = relationship_name
        self.certificate_requests = certificate_requests
        self.mode = mode
        self.framework.observe(charm.on[relationship_name].relation_created, self._configure)
        self.framework.observe(charm.on[relationship_name].relation_changed, self._configure)
        self.framework.observe(charm.on.secret_expired, self._on_secret_expired)
        for event in refresh_events:
            self.framework.observe(event, self._configure)

    def _configure(self, _: EventBase):
        """Handle TLS Certificates Relation Data.

        This method is called during any TLS relation event.
        It will generate a private key if it doesn't exist yet.
        It will send certificate requests if they haven't been sent yet.
        It will find available certificates and emit events.
        """
        if not self._tls_relation_created():
            logger.debug("TLS relation not created yet.")
            return
        self._generate_private_key()
        self._send_certificate_requests()
        self._find_available_certificates()
        self._cleanup_certificate_requests()

    def _mode_is_valid(self, mode) -> bool:
        return mode in [Mode.UNIT, Mode.APP]

    def _on_secret_expired(self, event: SecretExpiredEvent) -> None:
        """Handle Secret Expired Event.

        Renews certificate requests and removes the expired secret.
        """
        if not event.secret.label or not event.secret.label.startswith(f"{LIBID}-certificate"):
            return
        csr = event.secret.get_content(refresh=True)["csr"]
        self._renew_certificate_request(csr)
        event.secret.remove_all_revisions()

    def _renew_certificate_request(self, csr: str):
        """Remove existing CSR from relation data and create a new one."""
        self._remove_requirer_csr_from_relation_data(csr)
        self._send_certificate_requests()

    def _remove_requirer_csr_from_relation_data(self, csr: str) -> None:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        if not self.get_csrs_from_requirer_relation_data():
            logger.info("No CSRs in relation data - Doing nothing")
            return
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            logger.warning("Invalid relation data - Skipping removal of CSR")
            return
        new_relation_data = copy.deepcopy(requirer_relation_data.certificate_signing_requests)
        for requirer_csr in new_relation_data:
            if requirer_csr.certificate_signing_request.strip() == csr.strip():
                new_relation_data.remove(requirer_csr)
        try:
            RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[app_or_unit]
            )
            logger.info("Removed CSR from relation data")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _get_app_or_unit(self) -> Union[Application, Unit]:
        """Return the unit or app object based on the mode."""
        if self.mode == Mode.UNIT:
            return self.model.unit
        elif self.mode == Mode.APP:
            return self.model.app
        raise TLSCertificatesError("Invalid mode")

    @property
    def private_key(self) -> str | None:
        """Return the private key."""
        if not self._private_key_generated():
            return None
        secret = self.charm.model.get_secret(label=self._get_private_key_secret_label())
        private_key = secret.get_content(refresh=True)["private-key"]
        return private_key

    def _generate_private_key(self) -> None:
        if self._private_key_generated():
            return
        private_key = generate_private_key()
        self.charm.unit.add_secret(
            content={"private-key": private_key},
            label=self._get_private_key_secret_label(),
        )
        logger.info("Private key generated")

    def regenerate_private_key(self) -> None:
        """Regenerate the private key.

        Generate a new private key, remove old certificate requests and send new ones.
        """
        if not self._private_key_generated():
            logger.warning("No private key to regenerate")
            return
        self._regenerate_private_key()
        self._cleanup_certificate_requests()
        self._send_certificate_requests()

    def _regenerate_private_key(self) -> None:
        secret = self.charm.model.get_secret(label=self._get_private_key_secret_label())
        secret.set_content({"private-key": generate_private_key()})

    def _private_key_generated(self) -> bool:
        try:
            self.charm.model.get_secret(label=self._get_private_key_secret_label())
        except (SecretNotFoundError, KeyError):
            return False
        return True

    def _csr_matches_request_attributes(self, csr: str) -> bool:
        for certificate_request in self.certificate_requests:
            if CertificateRequest.from_string(csr=csr) == certificate_request:
                return True
        return False

    def _certificate_requested(self, certificate_request: CertificateRequest) -> bool:
        if not self.private_key:
            return False
        csr = self._certificate_requested_for_attributes(certificate_request)
        if not csr:
            return False
        if not csr_matches_private_key(csr=csr, key=self.private_key):
            return False
        return True

    def _certificate_requested_for_attributes(
        self, certificate_request: CertificateRequest
    ) -> Optional[str]:
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            csr_str = requirer_csr.certificate_signing_request
            if CertificateRequest.from_string(csr_str) == certificate_request:
                return csr_str
        return None

    def get_csrs_from_requirer_relation_data(self) -> List[CertificateSigningRequest]:
        """Return list of requirer's CSRs from relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        return requirer_relation_data.certificate_signing_requests

    def get_provider_certificates(self) -> List[Certificate]:
        """Return list of certificates from the provider's relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        if not relation.app:
            logger.debug("No remote app in relation: %s", self.relationship_name)
            return []
        try:
            provider_relation_data = ProviderApplicationData.load(relation.data[relation.app])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        return provider_relation_data.certificates

    def _request_certificate(self, csr: str, is_ca: bool) -> None:
        """Add CSR to relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        new_csr = CertificateSigningRequest(certificate_signing_request=csr.strip(), ca=is_ca)
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            requirer_relation_data = RequirerData(
                certificate_signing_requests=[],
            )
        new_relation_data = copy.deepcopy(requirer_relation_data.certificate_signing_requests)
        new_relation_data.append(new_csr)
        try:
            RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[app_or_unit]
            )
            logger.info("Certificate signing request added to relation data.")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _send_certificate_requests(self):
        if not self.private_key:
            logger.debug("Private key not generated yet.")
            return
        for certificate_request in self.certificate_requests:
            if not self._certificate_requested(certificate_request):
                csr = generate_csr(
                    private_key=self.private_key,
                    sans_dns=certificate_request.sans_dns,
                    common_name=certificate_request.common_name,
                    organization=certificate_request.organization,
                    email_address=certificate_request.email_address,
                    country_name=certificate_request.country_name,
                    state_or_province_name=certificate_request.state_or_province_name,
                    locality_name=certificate_request.locality_name,
                )
                self._request_certificate(csr=csr, is_ca=certificate_request.is_ca)

    def get_assigned_certificate(
        self, certificate_request: CertificateRequest
    ) -> Tuple[Certificate | None, str | None]:
        """Get the certificate that was assigned to the given certificate request."""
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if (
                CertificateRequest.from_string(csr=requirer_csr.certificate_signing_request)
                == certificate_request
            ):
                return self._find_certificate_in_relation_data(
                    requirer_csr.certificate_signing_request
                ), self.private_key
        return None, None

    def get_assigned_certificates(self) -> Tuple[List[Certificate], str | None]:
        """Get a list of certificates that were assigned to this or app."""
        assigned_certificates = []
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if cert := self._find_certificate_in_relation_data(
                requirer_csr.certificate_signing_request
            ):
                assigned_certificates.append(cert)
        return assigned_certificates, self.private_key

    def _find_certificate_in_relation_data(self, csr: str) -> Optional[Certificate]:
        """Return the certificate that match the given CSR."""
        for provider_certificate in self.get_provider_certificates():
            if provider_certificate.certificate_signing_request.strip() != csr.strip():
                continue
            return provider_certificate
        return None

    def _find_available_certificates(self):
        """Find available certificates and emit events.

        This method will find certificates that are available for the requirer's CSRs.
        If a certificate is found, it will be set as a secret and an event will be emitted.
        If a certificate is revoked, the secret will be removed and an event will be emitted.
        """
        requirer_csrs = [
            certificate_creation_request.certificate_signing_request
            for certificate_creation_request in self.get_csrs_from_requirer_relation_data()
        ]
        provider_certificates = self.get_provider_certificates()
        for certificate in provider_certificates:
            if certificate.certificate_signing_request in requirer_csrs:
                secret_label = self._get_csr_secret_label(certificate.certificate_signing_request)
                if certificate.revoked:
                    with suppress(SecretNotFoundError):
                        logger.debug(
                            "Removing secret with label %s",
                            secret_label,
                        )
                        secret = self.model.get_secret(label=secret_label)
                        secret.remove_all_revisions()
                else:
                    if not self._csr_matches_request_attributes(
                        certificate.certificate_signing_request
                    ):
                        logger.debug("Certificate requested for different attributes - Skipping")
                        continue
                    try:
                        logger.debug("Setting secret with label %s", secret_label)
                        secret = self.model.get_secret(label=secret_label)
                        secret.set_content(
                            content={
                                "certificate": certificate.certificate,
                                "csr": certificate.certificate_signing_request,
                            }
                        )
                        secret.set_info(
                            expire=self._get_next_secret_expiry_time(certificate),
                        )
                    except SecretNotFoundError:
                        logger.debug("Creating new secret with label %s", secret_label)
                        secret = self.charm.unit.add_secret(
                            content={
                                "certificate": certificate.certificate,
                                "csr": certificate.certificate_signing_request,
                            },
                            label=secret_label,
                            expire=self._get_next_secret_expiry_time(certificate),
                        )
                    self.on.certificate_available.emit(
                        certificate_signing_request=certificate.certificate_signing_request,
                        certificate=certificate.certificate,
                        ca=certificate.ca,
                        chain=certificate.chain,
                    )

    def _cleanup_certificate_requests(self):
        """Clean up certificate requests.

        Remove any certificate requests that falls into one of the following categories:
        - The CSR attributes do not match any of the certificate requests defined in
        the charm's certificate_requests attribute.
        - The CSR public key does not match the private key.
        """
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if not self._csr_matches_request_attributes(requirer_csr.certificate_signing_request):
                self._remove_requirer_csr_from_relation_data(
                    requirer_csr.certificate_signing_request
                )
            elif self.private_key and not csr_matches_private_key(
                requirer_csr.certificate_signing_request, self.private_key
            ):
                self._remove_requirer_csr_from_relation_data(
                    requirer_csr.certificate_signing_request
                )

    def _get_next_secret_expiry_time(self, certificate: Certificate) -> Optional[datetime]:
        """Return the expiry time or expiry notification time.

        Extracts the expiry time from the provided certificate, calculates the
        expiry notification time and return the closest of the two, that is in
        the future.

        Args:
            certificate: Certificate object

        Returns:
            Optional[datetime]: None if the certificate expiry time cannot be read,
                                next expiry time otherwise.
        """
        cert = ProviderCertificate.from_string(certificate.certificate)
        if not cert:
            logger.warning("Could not load certificate")
            return None
        if not cert.expiry_time:
            logger.warning("Certificate has no expiry time")
            return None
        if not cert.validity_start_time:
            logger.warning("Certificate has no validity start time")
            return None
        expiry_notification_time = calculate_expiry_notification_time(
            validity_start_time=cert.validity_start_time,
            expiry_time=cert.expiry_time,
            provider_recommended_notification_time=certificate.recommended_expiry_notification_time,
        )
        if not expiry_notification_time:
            logger.warning("Could not calculate expiry notification time")
            return None
        return _get_closest_future_time(
            expiry_notification_time,
            cert.expiry_time,
        )

    def _tls_relation_created(self) -> bool:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            return False
        return True

    def _get_private_key_secret_label(self) -> str:
        if self.mode == Mode.UNIT:
            return f"{LIBID}-private-key-{self._get_unit_number()}"
        elif self.mode == Mode.APP:
            return f"{LIBID}-private-key"
        else:
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP.")

    def _get_csr_secret_label(self, csr: str) -> str:
        csr_in_sha256_hex = get_sha256_hex(csr)
        if self.mode == Mode.UNIT:
            return f"{LIBID}-certificate-{self._get_unit_number()}-{csr_in_sha256_hex}"
        elif self.mode == Mode.APP:
            return f"{LIBID}-certificate-{csr_in_sha256_hex}"
        else:
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP.")

    def _get_unit_number(self) -> str:
        return self.model.unit.name.split("/")[1]
