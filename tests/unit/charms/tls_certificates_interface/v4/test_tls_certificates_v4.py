#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address

from charms.tls_certificates_interface.v4.tls_certificates import (
    PrivateKey,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    calculate_expiry_notification_time,
)
from tests.unit.charms.tls_certificates_interface.v4.certificates import (
    generate_private_key as generate_private_key_helper,
)


def validate_induced_data_from_pfx_is_equal_to_initial_data(
    pfx_file: bytes,
    password: str,
    initial_certificate: bytes,
    initial_private_key: bytes,
):
    (
        induced_private_key_object,
        induced_certificate_object,
        _,
    ) = pkcs12.load_key_and_certificates(pfx_file, password.encode())
    assert induced_private_key_object
    assert induced_certificate_object
    initial_private_key_object = load_pem_private_key(
        initial_private_key,
        password=None,
    )
    assert initial_private_key_object
    induced_private_key = induced_private_key_object.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    initial_public_key_object = initial_private_key_object.public_key()
    initial_public_key = initial_public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    induced_public_key_object = induced_private_key_object.public_key()
    induced_public_key = induced_public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    induced_certificate = induced_certificate_object.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    assert initial_public_key == induced_public_key
    assert induced_certificate == initial_certificate
    assert initial_private_key == induced_private_key


def test_given_no_password_when_generate_private_key_then_key_is_generated_and_loadable():
    private_key = generate_private_key()

    load_pem_private_key(data=str(private_key).encode(), password=None)


def test_given_key_size_provided_when_generate_private_key_then_private_key_is_generated():
    key_size = 1234

    private_key = generate_private_key(key_size=key_size)

    private_key_object = serialization.load_pem_private_key(
        str(private_key).encode(), password=None
    )
    assert isinstance(private_key_object, rsa.RSAPrivateKeyWithSerialization)
    assert private_key_object.key_size == key_size


# calculate expiry notification time


def test_given_provider_recommended_notification_time_when_calculate_expiry_notification_time_then_returns_provider_recommendation():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = 24
    expected_notification_time = expiry_time - timedelta(
        hours=provider_recommended_notification_time
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_negative_provider_recommended_notification_time_when_calculate_expiry_notification_time_then_returns_provider_recommendation():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    negative_provider_recommended_notification_time = 24
    expected_notification_time = expiry_time - timedelta(
        hours=abs(negative_provider_recommended_notification_time)
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=negative_provider_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_requirer_and_provider_recommendations_are_invalid_when_calculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = None
    calculated_hours = 80
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_negative_requirer_and_provider_recommendations_are_invalid_when_calculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = None
    calculated_hours = 80
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_validity_time_is_too_short_when_calculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 3
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = 24
    calculated_hours = 1
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


# Generate CSR


def test_given_subject_and_private_key_when_generate_csr_then_csr_is_generated_with_provided_subject():  # noqa: E501
    common_name = "whatever"
    private_key = PrivateKey(raw=generate_private_key_helper())

    csr = generate_csr(private_key=private_key, common_name=common_name)

    csr_object = x509.load_pem_x509_csr(data=str(csr).encode())
    subject_list = list(csr_object.subject)
    assert len(subject_list) == 2
    assert common_name == subject_list[0].value
    uuid.UUID(str(subject_list[1].value))


def test_given_unique_id_set_to_false_when_generate_csr_then_csr_is_generated_without_unique_id(  # noqa: E501
):
    private_key = PrivateKey(raw=generate_private_key_helper())
    common_name = "whatever subject"

    csr = generate_csr(
        private_key=private_key, common_name=common_name, add_unique_id_to_subject_name=False
    )

    csr_object = x509.load_pem_x509_csr(data=str(csr).encode())
    subject_list = list(csr_object.subject)
    assert common_name == subject_list[0].value


def test_given_localization_is_specified_when_generate_csr_then_csr_contains_localization():
    private_key = generate_private_key()

    csr = generate_csr(
        private_key=private_key,
        common_name="my.demo.server",
        sans_dns=frozenset(["my.demo.server"]),
        country_name="CA",
        state_or_province_name="Quebec",
        locality_name="Montreal",
    )

    csr_object = x509.load_pem_x509_csr(str(csr).encode())
    assert csr_object.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "CA"
    assert (
        csr_object.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value
        == "Quebec"
    )
    assert (
        csr_object.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value
        == "Montreal"
    )


def test_given_ipv6_sans_when_generate_csr_then_csr_contains_ipv6_sans():
    private_key = generate_private_key()

    csr = generate_csr(
        private_key=private_key,
        common_name="my.demo.server",
        sans_dns=frozenset(["my.demo.server"]),
        sans_ip=frozenset(["2001:db8::1", "2001:db8::2"]),
    )

    csr_object = x509.load_pem_x509_csr(str(csr).encode())
    sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    sans_ip = sans.get_values_for_type(x509.IPAddress)
    assert len(sans_ip) == 2
    assert IPv6Address("2001:db8::1") in sans_ip
    assert IPv6Address("2001:db8::2") in sans_ip


# Generate CA


def test_given_ca_certificate_attributes_when_generate_ca_then_ca_is_generated_correctly():
    private_key = PrivateKey(raw=generate_private_key_helper())

    ca_certificate = generate_ca(
        private_key=private_key,
        validity=365,
        common_name="certifier.example.com",
        sans_dns=frozenset(["certifier.example.com"]),
        sans_ip=frozenset(["1.2.3.4"]),
        email_address="banana@gmail.com",
        organization="Example",
        organizational_unit="Example Unit",
        country_name="CA",
        state_or_province_name="Quebec",
        locality_name="Montreal",
    )

    assert ca_certificate.common_name == "certifier.example.com"
    expected_expiry = datetime.now(timezone.utc) + timedelta(days=365)
    assert ca_certificate.expiry_time
    assert abs(ca_certificate.expiry_time - expected_expiry) <= timedelta(seconds=1)
    assert ca_certificate.email_address == "banana@gmail.com"
    assert ca_certificate.organization == "Example"
    assert ca_certificate.organizational_unit == "Example Unit"
    assert ca_certificate.country_name == "CA"
    assert ca_certificate.state_or_province_name == "Quebec"
    assert ca_certificate.locality_name == "Montreal"
    assert ca_certificate.sans_dns == frozenset(["certifier.example.com"])
    assert ca_certificate.sans_ip == frozenset(["1.2.3.4"])
    assert ca_certificate.sans_oid == frozenset()


# Generate Certificate

def test_given_csr_when_generate_certificate_then_certificate_generated_with_requested_attributes():  # noqa: E501
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        common_name="example.com",
        sans_dns=frozenset(["example.com"]),
        locality_name="wherever",
    )
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        validity=365,
        common_name="certifier.example.com",
        sans_dns=frozenset(["certifier.example.com"]),
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=200,
    )

    assert certificate.common_name == "example.com"
    expected_expiry = datetime.now(timezone.utc) + timedelta(days=200)
    assert certificate.expiry_time
    assert abs(certificate.expiry_time - expected_expiry) <= timedelta(seconds=1)
    assert certificate.sans_dns == frozenset(["example.com"])
    assert certificate.sans_ip == frozenset()
    assert certificate.sans_oid == frozenset()
    assert certificate.email_address is None
    assert certificate.country_name is None
    assert certificate.locality_name == "wherever"
