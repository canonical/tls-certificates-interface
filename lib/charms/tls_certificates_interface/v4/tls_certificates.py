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
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ops import BoundEvent, CharmBase, CharmEvents, SecretExpiredEvent
from ops.framework import EventBase, EventSource, Handle, Object
from ops.jujuversion import JujuVersion
from ops.model import (
    Application,
    ModelError,
    Relation,
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


class TLSCertificatesError(RuntimeError):
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
    """Enum representing the mode of the certificate request."""

    UNIT = 1
    APP = 2


@dataclass
class RequirerCSR:
    """This class represents a certificate signing request from an interface Requirer."""

    relation_id: int
    application_name: str
    csr: str
    is_ca: Optional[bool]
    unit_name: Optional[str] = None


@dataclass
class CertificateRequest:
    """This class represents a certificate request."""

    sans_dns: List[str]
    common_name: str
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
        if not self.common_name or self.common_name == "":
            return False
        return True


@dataclass
class ProviderCertificate:
    """This class represents a certificate from an interface Provider."""

    relation_id: int
    application_name: str
    csr: str
    certificate: str
    ca: str
    revoked: Optional[bool]
    expiry_time: datetime
    chain: Optional[List[str]] = None
    expiry_notification_time: Optional[datetime] = None

    def chain_as_pem(self) -> str:
        """Return full certificate chain as a PEM string."""
        if not self.chain:
            return ""
        return "\n\n".join(reversed(self.chain))

    def to_json(self) -> str:
        """Return the object as a JSON string.

        Returns:
            str: JSON representation of the object
        """
        return json.dumps(
            {
                "relation_id": self.relation_id,
                "application_name": self.application_name,
                "csr": self.csr,
                "certificate": self.certificate,
                "ca": self.ca,
                "chain": self.chain,
                "revoked": self.revoked,
                "expiry_time": self.expiry_time.isoformat(),
                "expiry_notification_time": self.expiry_notification_time.isoformat()
                if self.expiry_notification_time
                else None,
            }
        )


@dataclass
class PrivateKey:
    """This class represents a private key."""

    private_key: str
    password: str

    def to_json(self) -> str:
        """Return the object as a JSON string.

        Returns:
            str: JSON representation of the object
        """
        return json.dumps(
            {
                "private_key": self.private_key,
                "password": self.password,
            }
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


def csr_has_attributes(  # noqa: C901
    csr: str,
    common_name: str,
    sans_dns: List[str],
    organization: Optional[str],
    email_address: Optional[str],
    country_name: Optional[str],
    state_or_province_name: Optional[str],
    locality_name: Optional[str],
) -> bool:
    """Check whether CSR has the specified attributes."""
    csr_object = x509.load_pem_x509_csr(csr.encode())
    csr_common_name = csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    csr_country_name = csr_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    csr_state_or_province_name = csr_object.subject.get_attributes_for_oid(
        NameOID.STATE_OR_PROVINCE_NAME
    )
    csr_locality_name = csr_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    csr_organization_name = csr_object.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    csr_email_address = csr_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    if len(csr_common_name) == 0 and common_name:
        return False
    if csr_common_name[0].value != common_name:
        return False
    if len(csr_country_name) == 0 and country_name:
        return False
    if len(csr_country_name) != 0 and csr_country_name[0].value != country_name:
        return False
    if len(csr_state_or_province_name) == 0 and state_or_province_name:
        return False
    if (
        len(csr_state_or_province_name) != 0
        and csr_state_or_province_name[0].value != state_or_province_name
    ):
        return False
    if len(csr_locality_name) == 0 and locality_name:
        return False
    if len(csr_locality_name) != 0 and csr_locality_name[0].value != locality_name:
        return False
    if len(csr_organization_name) == 0 and organization:
        return False
    if len(csr_organization_name) != 0 and csr_organization_name[0].value != organization:
        return False
    if len(csr_email_address) == 0 and email_address:
        return False
    if len(csr_email_address) != 0 and csr_email_address[0].value != email_address:
        return False
    try:
        sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        sans = []
    if sorted([str(san.value) for san in sans]) != sorted(sans_dns):
        return False
    return True


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


def generate_ca(
    private_key: bytes,
    common_name: str,
    private_key_password: Optional[bytes] = None,
    validity: int = 365,
    country: str = "US",
) -> bytes:
    """Generate a CA Certificate.

    Args:
        private_key (bytes): Private key
        common_name (str): Common Name that can be an IP or a Full Qualified Domain Name (FQDN).
        private_key_password (bytes): Private key password
        validity (int): Certificate validity time (in days)
        country (str): Certificate Issuing country

    Returns:
        bytes: CA Certificate.
    """
    private_key_object = serialization.load_pem_private_key(
        private_key, password=private_key_password
    )
    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_cert_sign=True,
        key_agreement=False,
        content_commitment=False,
        data_encipherment=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def get_certificate_extensions(
    authority_key_identifier: bytes,
    csr: x509.CertificateSigningRequest,
    alt_names: Optional[List[str]],
    is_ca: bool,
) -> List[x509.Extension]:
    """Generate a list of certificate extensions from a CSR and other known information.

    Args:
        authority_key_identifier (bytes): Authority key identifier
        csr (x509.CertificateSigningRequest): CSR
        alt_names (list): List of alt names to put on cert - prefer putting SANs in CSR
        is_ca (bool): Whether the certificate is a CA certificate

    Returns:
        List[x509.Extension]: List of extensions
    """
    cert_extensions_list: List[x509.Extension] = [
        x509.Extension(
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=authority_key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        ),
        x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            value=x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ),
        x509.Extension(
            oid=ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=is_ca, path_length=None),
        ),
    ]

    sans: List[x509.GeneralName] = []
    san_alt_names = [x509.DNSName(name) for name in alt_names] if alt_names else []
    sans.extend(san_alt_names)
    try:
        loaded_san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans.extend(
            [x509.DNSName(name) for name in loaded_san_ext.value.get_values_for_type(x509.DNSName)]
        )
        sans.extend(
            [x509.IPAddress(ip) for ip in loaded_san_ext.value.get_values_for_type(x509.IPAddress)]
        )
        sans.extend(
            [
                x509.RegisteredID(oid)
                for oid in loaded_san_ext.value.get_values_for_type(x509.RegisteredID)
            ]
        )
    except x509.ExtensionNotFound:
        pass

    if sans:
        cert_extensions_list.append(
            x509.Extension(
                oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                critical=False,
                value=x509.SubjectAlternativeName(sans),
            )
        )

    if is_ca:
        cert_extensions_list.append(
            x509.Extension(
                ExtensionOID.KEY_USAGE,
                critical=True,
                value=x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
            )
        )

    existing_oids = {ext.oid for ext in cert_extensions_list}
    for extension in csr.extensions:
        if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            continue
        if extension.oid in existing_oids:
            logger.warning("Extension %s is managed by the TLS provider, ignoring.", extension.oid)
            continue
        cert_extensions_list.append(extension)

    return cert_extensions_list


def generate_certificate(
    csr: bytes,
    ca: bytes,
    ca_key: bytes,
    ca_key_password: Optional[bytes] = None,
    validity: int = 365,
    alt_names: Optional[List[str]] = None,
    is_ca: bool = False,
) -> bytes:
    """Generate a TLS certificate based on a CSR.

    Args:
        csr (bytes): CSR
        ca (bytes): CA Certificate
        ca_key (bytes): CA private key
        ca_key_password: CA private key password
        validity (int): Certificate validity (in days)
        alt_names (list): List of alt names to put on cert - prefer putting SANs in CSR
        is_ca (bool): Whether the certificate is a CA certificate

    Returns:
        bytes: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr)
    subject = csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
    subject_name = x509.Name([subject])
    ca_pem = x509.load_pem_x509_certificate(ca)
    issuer = ca_pem.issuer
    private_key = serialization.load_pem_private_key(ca_key, password=ca_key_password)

    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
    )
    extensions = get_certificate_extensions(
        authority_key_identifier=ca_pem.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.key_identifier,
        csr=csr_object,
        alt_names=alt_names,
        is_ca=is_ca,
    )
    for extension in extensions:
        try:
            certificate_builder = certificate_builder.add_extension(
                extval=extension.value,
                critical=extension.critical,
            )
        except ValueError as e:
            logger.warning("Failed to add extension %s: %s", extension.oid, e)

    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_private_key(
    password: Optional[bytes] = None,
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> bytes:
    """Generate a private key with the RSA algorithm.

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
        encryption_algorithm=(
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        ),
    )
    return key_bytes


def generate_csr(  # noqa: C901
    private_key: bytes,
    common_name: str,
    add_unique_id_to_subject_name: bool = True,
    organization: Optional[str] = None,
    email_address: Optional[str] = None,
    country_name: Optional[str] = None,
    state_or_province_name: Optional[str] = None,
    locality_name: Optional[str] = None,
    private_key_password: Optional[bytes] = None,
    sans: Optional[List[str]] = None,
    sans_oid: Optional[List[str]] = None,
    sans_ip: Optional[List[str]] = None,
    sans_dns: Optional[List[str]] = None,
    additional_critical_extensions: Optional[List] = None,
) -> bytes:
    """Generate a CSR using private key and subject.

    Args:
        private_key (bytes): Private key
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
        private_key_password (bytes): Private key password
        sans (list): Use sans_dns - this will be deprecated in a future release
            List of DNS subject alternative names (keeping it for now for backward compatibility)
        sans_oid (list): List of registered ID SANs
        sans_dns (list): List of DNS subject alternative names (similar to the arg: sans)
        sans_ip (list): List of IP subject alternative names
        additional_critical_extensions (list): List of critical additional extension objects.
            Object must be a x509 ExtensionType.

    Returns:
        bytes: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
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
    return signed_certificate.public_bytes(serialization.Encoding.PEM)


def get_sha256_hex(data: str) -> str:
    """Calculate the hash of the provided data and return the hexadecimal representation."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize().hex()


def csr_matches_certificate(csr: str, cert: str) -> bool:
    """Check if a CSR matches a certificate.

    Args:
        csr (str): Certificate Signing Request as a string
        cert (str): Certificate as a string
    Returns:
        bool: True/False depending on whether the CSR matches the certificate.
    """
    csr_object = x509.load_pem_x509_csr(csr.encode("utf-8"))
    cert_object = x509.load_pem_x509_certificate(cert.encode("utf-8"))

    if csr_object.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != cert_object.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        return False
    return True


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
        key_object = serialization.load_pem_private_key(key.encode("utf-8"), password=None)
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


def _relation_data_is_valid(
    relation: Relation, app_or_unit: Union[Application, Unit], databag_model
) -> bool:
    """Check whether relation data is valid based on the databag model.

    Args:
        relation (Relation): Relation object
        app_or_unit (Union[Application, Unit]): Application or unit object
        databag_model (DatabagModel): Databag model

    Returns:
        bool: Whether relation data is valid.
    """
    databag = relation.data[app_or_unit]
    try:
        databag_model.load(databag)
        return True
    except DataValidationError:
        return False


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)


class TLSCertificatesRequiresV4(Object):
    """A class to manage the TLS certificates interface for a unit.

    Use this class if your charm's certificates are managed per unit.
    """

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
        self.charm = charm
        self.relationship_name = relationship_name
        self.certificate_requests = certificate_requests
        self.mode = mode
        self.framework.observe(self.on.update_status, self._configure)
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
            raise TLSCertificatesError(
                f"Relation {self.relationship_name} does not exist - "
                f"The certificate request can't be completed"
            )
        if not self.get_requirer_csrs():
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
        """Return the application or unit object based on the mode."""
        if self.mode == Mode.UNIT:
            return self.model.unit
        elif self.mode == Mode.APP:
            return self.model.app
        raise TLSCertificatesError("Invalid mode")

    @property
    def private_key(self) -> PrivateKey | None:
        """Return the private key."""
        if not self._private_key_generated():
            return None
        secret = self.charm.model.get_secret(label=self._get_private_key_secret_label())
        private_key = secret.get_content(refresh=True)["private-key"]
        return PrivateKey(
            private_key=private_key,
            password="",
        )

    def _generate_private_key(self) -> None:
        if self._private_key_generated():
            return
        private_key = generate_private_key()
        self.charm.unit.add_secret(
            content={"private-key": private_key.decode()},
            label=self._get_private_key_secret_label(),
        )
        logger.info("private key generated for unit")

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
        secret.set_content({"private-key": generate_private_key().decode()})

    def _private_key_generated(self) -> bool:
        try:
            self.charm.model.get_secret(label=self._get_private_key_secret_label())
        except (SecretNotFoundError, KeyError):
            return False
        return True

    def _csr_matches_request_attributes(self, csr: str) -> bool:
        for certificate_request in self.certificate_requests:
            if csr_has_attributes(
                csr=csr,
                common_name=certificate_request.common_name,
                sans_dns=certificate_request.sans_dns,
                organization=certificate_request.organization,
                email_address=certificate_request.email_address,
                country_name=certificate_request.country_name,
                state_or_province_name=certificate_request.state_or_province_name,
                locality_name=certificate_request.locality_name,
            ):
                return True
        return False

    def _certificate_requested(self, certificate_request: CertificateRequest) -> bool:
        if not self.private_key:
            return False
        csr = self._certificate_requested_for_attributes(certificate_request)
        if not csr:
            return False
        if not csr_matches_private_key(csr=csr, key=self.private_key.private_key):
            return False
        return True

    def _certificate_requested_for_attributes(
        self, certificate_request: CertificateRequest
    ) -> Optional[str]:
        for requirer_csr in self.get_requirer_csrs():
            csr_str = requirer_csr.csr
            if csr_has_attributes(
                csr=csr_str,
                common_name=certificate_request.common_name,
                sans_dns=certificate_request.sans_dns,
                organization=certificate_request.organization,
                email_address=certificate_request.email_address,
                country_name=certificate_request.country_name,
                state_or_province_name=certificate_request.state_or_province_name,
                locality_name=certificate_request.locality_name,
            ):
                return csr_str
        return None

    def get_requirer_csrs(self) -> List[RequirerCSR]:
        """Return list of requirer's CSRs from relation unit data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            return []
        app_or_unit = self._get_app_or_unit()
        requirer_csrs = []
        try:
            requirer_relation_data = RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        for requirer_csr in requirer_relation_data.certificate_signing_requests:
            relation_csr = RequirerCSR(
                relation_id=relation.id,
                application_name=self.model.app.name,
                unit_name=self.model.unit.name if self.mode == Mode.UNIT else None,
                csr=requirer_csr.certificate_signing_request,
                is_ca=requirer_csr.ca,
            )
            requirer_csrs.append(relation_csr)
        return requirer_csrs

    def get_provider_certificates(self) -> List[ProviderCertificate]:
        """Return list of certificates from the provider's relation data."""
        provider_certificates: List[ProviderCertificate] = []
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
        for provider_certificate in provider_relation_data.certificates:
            try:
                certificate_object = x509.load_pem_x509_certificate(
                    data=provider_certificate.certificate.encode()
                )
            except ValueError as e:
                logger.error("Could not load certificate - Skipping: %s", e)
                continue
            validity_start_time = certificate_object.not_valid_before_utc
            expiry_notification_time = calculate_expiry_notification_time(
                validity_start_time=validity_start_time,
                expiry_time=certificate_object.not_valid_after_utc,
                provider_recommended_notification_time=provider_certificate.recommended_expiry_notification_time,
            )
            revoked = provider_certificate.revoked
            provider_certificate = ProviderCertificate(
                relation_id=relation.id,
                application_name=relation.app.name,
                csr=provider_certificate.certificate_signing_request,
                certificate=provider_certificate.certificate,
                ca=provider_certificate.ca,
                chain=provider_certificate.chain,
                revoked=revoked,
                expiry_time=certificate_object.not_valid_after_utc,
                expiry_notification_time=expiry_notification_time,
            )
            provider_certificates.append(provider_certificate)
        return provider_certificates

    def _request_certificate(self, csr: str, is_ca: bool) -> None:
        """Add CSR to relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            raise TLSCertificatesError(
                f"Relation {self.relationship_name} does not exist - "
                f"The certificate request can't be completed"
            )
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
            if not certificate_request.is_valid():
                logger.warning("Invalid certificate request - Skipping")
                continue
            if not self._certificate_requested(certificate_request):
                csr = generate_csr(
                    private_key=self.private_key.private_key.encode(),
                    sans_dns=certificate_request.sans_dns,
                    common_name=certificate_request.common_name,
                    organization=certificate_request.organization,
                    email_address=certificate_request.email_address,
                    country_name=certificate_request.country_name,
                    state_or_province_name=certificate_request.state_or_province_name,
                    locality_name=certificate_request.locality_name,
                )
                self._request_certificate(csr=csr.decode(), is_ca=certificate_request.is_ca)

    def get_assigned_certificate(
        self, certificate_request: CertificateRequest
    ) -> Tuple[ProviderCertificate | None, PrivateKey | None]:
        """Get the certificate that was assigned to the given certificate request."""
        if requirer_csr := self.get_certificate_signing_request(certificate_request):
            return self._find_certificate_in_relation_data(requirer_csr.csr), self.private_key
        return None, None

    def get_assigned_certificates(self) -> Tuple[List[ProviderCertificate], PrivateKey | None]:
        """Get a list of certificates that were assigned to this unit."""
        assigned_certificates = []
        for requirer_csr in self.get_certificate_signing_requests(fulfilled_only=True):
            if cert := self._find_certificate_in_relation_data(requirer_csr.csr):
                assigned_certificates.append(cert)
        return assigned_certificates, self.private_key

    def get_certificate_signing_request(
        self, certificate_request: CertificateRequest
    ) -> Optional[RequirerCSR]:
        """Get the CSR that was sent to the provider for the given certificate request."""
        for requirer_csr in self.get_requirer_csrs():
            if csr_has_attributes(
                csr=requirer_csr.csr,
                common_name=certificate_request.common_name,
                sans_dns=certificate_request.sans_dns,
                organization=certificate_request.organization,
                email_address=certificate_request.email_address,
                country_name=certificate_request.country_name,
                state_or_province_name=certificate_request.state_or_province_name,
                locality_name=certificate_request.locality_name,
            ):
                return requirer_csr
        return None

    def get_certificate_signing_requests(
        self,
        fulfilled_only: bool = False,
        unfulfilled_only: bool = False,
    ) -> List[RequirerCSR]:
        """Get the list of CSR's that were sent to the provider.

        You can choose to get only the CSR's that have a certificate assigned or only the CSR's
        that don't.

        Args:
            fulfilled_only (bool): This option will discard CSRs that don't have certificates yet.
            unfulfilled_only (bool): This option will discard CSRs that have certificates signed.

        Returns:
            List of RequirerCSR objects.
        """
        csrs = []
        for requirer_csr in self.get_requirer_csrs():
            cert = self._find_certificate_in_relation_data(requirer_csr.csr)
            if (unfulfilled_only and cert) or (fulfilled_only and not cert):
                continue
            csrs.append(requirer_csr)
        return csrs

    def _find_certificate_in_relation_data(self, csr: str) -> Optional[ProviderCertificate]:
        """Return the certificate that match the given CSR."""
        for provider_certificate in self.get_provider_certificates():
            if provider_certificate.csr.strip() != csr.strip():
                continue
            return provider_certificate
        return None

    def _find_available_certificates(self):
        """Find available certificates and emit events.

        This method will find certificates that are available for the requirer's CSRs.
        If a certificate is found, it will be set as a secret and an event will be emitted.
        If a certificate is revoked, the secret will be removed and an event will be emitted.
        """
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        if not relation.app:
            logger.debug("No remote app in relation: %s", self.relationship_name)
            return
        if not _relation_data_is_valid(relation, relation.app, ProviderApplicationData):
            logger.debug("Relation data did not pass JSON Schema validation")
            return
        requirer_csrs = [
            certificate_creation_request.csr
            for certificate_creation_request in self.get_requirer_csrs()
        ]
        provider_certificates = self.get_provider_certificates()
        for certificate in provider_certificates:
            if certificate.csr in requirer_csrs:
                secret_label = self._get_csr_secret_label(certificate.csr)
                if certificate.revoked:
                    with suppress(SecretNotFoundError):
                        logger.debug(
                            "Removing secret with label %s",
                            secret_label,
                        )
                        secret = self.model.get_secret(label=secret_label)
                        secret.remove_all_revisions()
                else:
                    if not self._csr_matches_request_attributes(certificate.csr):
                        logger.debug("Certificate requested for different attributes - Skipping")
                        continue
                    try:
                        logger.debug("Setting secret with label %s", secret_label)
                        secret = self.model.get_secret(label=secret_label)
                        secret.set_content(
                            content={
                                "certificate": certificate.certificate,
                                "csr": certificate.csr,
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
                                "csr": certificate.csr,
                            },
                            label=secret_label,
                            expire=self._get_next_secret_expiry_time(certificate),
                        )
                    self.on.certificate_available.emit(
                        certificate_signing_request=certificate.csr,
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
        for requirer_csr in self.get_certificate_signing_requests():
            if not self._csr_matches_request_attributes(requirer_csr.csr):
                self._remove_requirer_csr_from_relation_data(requirer_csr.csr)
            elif self.private_key and not csr_matches_private_key(
                requirer_csr.csr, self.private_key.private_key
            ):
                self._remove_requirer_csr_from_relation_data(requirer_csr.csr)

    def _get_next_secret_expiry_time(self, certificate: ProviderCertificate) -> Optional[datetime]:
        """Return the expiry time or expiry notification time.

        Extracts the expiry time from the provided certificate, calculates the
        expiry notification time and return the closest of the two, that is in
        the future.

        Args:
            certificate: ProviderCertificate object

        Returns:
            Optional[datetime]: None if the certificate expiry time cannot be read,
                                next expiry time otherwise.
        """
        if not certificate.expiry_time or not certificate.expiry_notification_time:
            return None
        return _get_closest_future_time(
            certificate.expiry_notification_time,
            certificate.expiry_time,
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
