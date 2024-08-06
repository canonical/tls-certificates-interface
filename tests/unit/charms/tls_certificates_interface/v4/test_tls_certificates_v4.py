#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequest,
    PrivateKey,
    _generate_private_key,
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
    initial_private_key_object = load_pem_private_key(
        initial_private_key,
        password=None,
    )
    induced_private_key = induced_private_key_object.private_bytes(  # type: ignore[union-attr]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    initial_public_key_object = initial_private_key_object.public_key()
    initial_public_key = initial_public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    induced_public_key_object = induced_private_key_object.public_key()  # type: ignore[union-attr]
    induced_public_key = induced_public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    induced_certificate = induced_certificate_object.public_bytes(  # type: ignore[union-attr]
        encoding=serialization.Encoding.PEM
    )

    assert initial_public_key == induced_public_key
    assert induced_certificate == initial_certificate
    assert initial_private_key == induced_private_key


def test_given_no_password_when_generate_private_key_then_key_is_generated_and_loadable():
    private_key = _generate_private_key()

    load_pem_private_key(data=str(private_key).encode(), password=None)


def test_given_key_size_provided_when_generate_private_key_then_private_key_is_generated():
    key_size = 1234

    private_key = _generate_private_key(key_size=key_size)

    private_key_object = serialization.load_pem_private_key(
        str(private_key).encode(), password=None
    )
    assert isinstance(private_key_object, rsa.RSAPrivateKeyWithSerialization)
    assert private_key_object.key_size == key_size


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


def test_given_requirer_and_provider_recommendations_are_invalid_whencalculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
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


def test_given_negative_requirer_and_provider_recommendations_are_invalid_whencalculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
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


class TestCertificateRequest:
    def test_given_subject_and_private_key_when_generate_csr_then_csr_is_generated_with_provided_subject(  # noqa: E501
        self,
    ):
        subject = "whatever"
        private_key = PrivateKey(raw=generate_private_key_helper())

        certificate_request = CertificateRequest(common_name=subject)

        csr = certificate_request.generate_csr(private_key=private_key)

        csr_object = x509.load_pem_x509_csr(data=str(csr).encode())
        subject_list = list(csr_object.subject)
        assert len(subject_list) == 2
        assert subject == subject_list[0].value
        uuid.UUID(str(subject_list[1].value))

    def test_given_unique_id_set_to_false_when_generate_csr_then_csr_is_generated_without_unique_id(  # noqa: E501
        self,
    ):
        private_key = PrivateKey(raw=generate_private_key_helper())
        subject = "whatever subject"
        certificate_request = CertificateRequest(common_name=subject)

        csr = certificate_request.generate_csr(
            private_key=private_key, add_unique_id_to_subject_name=False
        )

        csr_object = x509.load_pem_x509_csr(data=str(csr).encode())
        subject_list = list(csr_object.subject)
        assert subject == subject_list[0].value

    def test_given_localization_is_specified_when__generate_csr_then_csr_contains_localization(
        self,
    ):
        private_key = _generate_private_key()

        certificate_request = CertificateRequest(
            common_name="my.demo.server",
            sans_dns=tuple("my.demo.server"),
            country_name="CA",
            state_or_province_name="Quebec",
            locality_name="Montreal",
        )

        csr = certificate_request.generate_csr(private_key=private_key)

        csr_object = x509.load_pem_x509_csr(str(csr).encode())
        assert (
            csr_object.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "CA"
        )
        assert (
            csr_object.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value
            == "Quebec"
        )
        assert (
            csr_object.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value
            == "Montreal"
        )

    def test_given_ipv6_sans_when__generate_csr_then_csr_contains_ipv6_sans(self):
        private_key = _generate_private_key()

        certificate_request = CertificateRequest(
            common_name="my.demo.server",
            sans_dns=tuple("my.demo.server"),
            sans_ip=("2001:db8::1", "2001:db8::2"),
        )

        csr = certificate_request.generate_csr(private_key=private_key)

        csr_object = x509.load_pem_x509_csr(str(csr).encode())
        sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans_ip = sans.get_values_for_type(x509.IPAddress)
        assert len(sans_ip) == 2
        assert IPv6Address("2001:db8::1") in sans_ip
        assert IPv6Address("2001:db8::2") in sans_ip
