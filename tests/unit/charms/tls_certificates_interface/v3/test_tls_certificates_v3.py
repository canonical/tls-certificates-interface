#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from charms.tls_certificates_interface.v3.tls_certificates import (
    csr_matches_certificate,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key, pkcs12

from lib.charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    ProviderCertificate,
    calculate_expiry_notification_time,
)
from tests.unit.charms.tls_certificates_interface.v3.certificates import (
    generate_ca as generate_ca_helper,
)
from tests.unit.charms.tls_certificates_interface.v3.certificates import (
    generate_certificate as generate_certificate_helper,
)
from tests.unit.charms.tls_certificates_interface.v3.certificates import (
    generate_csr as generate_csr_helper,
)
from tests.unit.charms.tls_certificates_interface.v3.certificates import (
    generate_ec_private_key as generate_ec_private_key_helper,
)
from tests.unit.charms.tls_certificates_interface.v3.certificates import (
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


def test_given_subject_and_private_key_when_generate_csr_then_csr_is_generated_with_provided_subject():  # noqa: E501
    subject = "whatever"
    private_key_password = b"whatever"
    private_key = generate_private_key_helper(password=private_key_password)

    csr = generate_csr(
        private_key=private_key, private_key_password=private_key_password, subject=subject
    )

    csr_object = x509.load_pem_x509_csr(data=csr)
    subject_list = list(csr_object.subject)
    assert len(subject_list) == 2
    assert subject == subject_list[0].value
    uuid.UUID(str(subject_list[1].value))


def test_given_additional_critical_extensions_when_generate_csr_then_extensions_are_added_to_csr():
    subject = "whatever"
    private_key_password = b"whatever"
    private_key = generate_private_key_helper(password=private_key_password)
    additional_critical_extension = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )

    csr = generate_csr(
        private_key=private_key,
        private_key_password=private_key_password,
        subject=subject,
        additional_critical_extensions=[additional_critical_extension],
    )

    csr_object = x509.load_pem_x509_csr(data=csr)
    assert csr_object.extensions[0].critical is True
    assert csr_object.extensions[0].value == additional_critical_extension


def test_given_no_private_key_password_when_generate_csr_then_csr_is_generated_and_loadable():
    private_key = generate_private_key_helper()
    subject = "whatever subject"

    csr = generate_csr(private_key=private_key, subject=subject)

    csr_object = x509.load_pem_x509_csr(data=csr)
    assert x509.NameAttribute(x509.NameOID.COMMON_NAME, subject) in csr_object.subject


def test_given_unique_id_set_to_false_when_generate_csr_then_csr_is_generated_without_unique_id():
    private_key = generate_private_key_helper()
    subject = "whatever subject"
    csr = generate_csr(
        private_key=private_key, subject=subject, add_unique_id_to_subject_name=False
    )

    csr_object = x509.load_pem_x509_csr(data=csr)
    subject_list = list(csr_object.subject)
    assert subject == subject_list[0].value


def test_given_no_password_when_generate_private_key_then_key_is_generated_and_loadable():
    private_key = generate_private_key()

    load_pem_private_key(data=private_key, password=None)


def test_given_password_when_generate_private_key_then_private_key_is_generated_and_loadable():
    private_key_password = b"whatever"
    private_key = generate_private_key(password=private_key_password)

    load_pem_private_key(data=private_key, password=private_key_password)


def test_given_generated_private_key_when_load_with_bad_password_then_error_is_thrown():
    private_key_password = b"whatever"
    private_key = generate_private_key(password=private_key_password)

    with pytest.raises(ValueError):
        load_pem_private_key(data=private_key, password=b"bad password")


def test_given_key_size_provided_when_generate_private_key_then_private_key_is_generated():
    key_size = 1234

    private_key = generate_private_key(key_size=key_size)

    private_key_object = serialization.load_pem_private_key(private_key, password=None)
    assert isinstance(private_key_object, rsa.RSAPrivateKeyWithSerialization)
    assert private_key_object.key_size == key_size


def test_given_private_key_and_subject_when_generate_ca_then_ca_is_generated_correctly():
    subject = "certifier.example.com"
    private_key = generate_private_key_helper()

    certifier_pem = generate_ca(private_key=private_key, subject=subject)

    cert = x509.load_pem_x509_certificate(certifier_pem)
    private_key_object = serialization.load_pem_private_key(private_key, password=None)
    certificate_public_key = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    initial_public_key = private_key_object.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )

    assert cert.issuer == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    assert cert.subject == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    assert certificate_public_key == initial_public_key
    assert (
        x509.KeyUsage(
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
        == cert.extensions.get_extension_for_class(x509.KeyUsage).value
    )
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).critical


def test_given_csr_and_ca_when_generate_certificate_then_certificate_is_generated_with_correct_subject_and_issuer():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(private_key=ca_key, common_name=ca_subject, country="US")
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        common_name=csr_subject,
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca,
        ca_key=ca_key,
    )

    certificate_object = x509.load_pem_x509_certificate(certificate)
    assert certificate_object.issuer == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, ca_subject),
        ]
    )
    assert certificate_object.subject == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, csr_subject),
        ]
    )


def test_given_csr_and_ca_when_generate_certificate_then_certificate_is_generated_with_correct_sans():  # noqa: E501
    ca_subject = "ca.subject"
    csr_subject = "csr.subject"
    sans = ["www.localhost.com", "www.test.com"]
    sans_dns = ["www.localhost.com", "www.canonical.com"]
    sans_ip = ["192.168.1.1", "127.0.0.1"]
    sans_oid = ["1.2.3.4.5.5", "1.1.1.1.1.1"]

    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr(
        private_key=csr_private_key,
        subject=csr_subject,
        sans=sans,
        sans_dns=sans_dns,
        sans_ip=sans_ip,
        sans_oid=sans_oid,
    )

    certificate = generate_certificate(csr=csr, ca=ca, ca_key=ca_key)

    cert = x509.load_pem_x509_certificate(certificate)
    result_all_sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    result_sans_dns = sorted(result_all_sans.value.get_values_for_type(x509.DNSName))
    assert result_sans_dns == sorted(set(sans + sans_dns))

    result_sans_ip = sorted(
        [str(val) for val in result_all_sans.value.get_values_for_type(x509.IPAddress)]
    )
    assert result_sans_ip == sorted(sans_ip)

    result_sans_oid = sorted(
        [val.dotted_string for val in result_all_sans.value.get_values_for_type(x509.RegisteredID)]
    )
    assert result_sans_oid == sorted(sans_oid)


def test_given_alt_names_when_generate_certificate_then_alt_names_are_correctly_populated():
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    alt_name_1 = "*.example.com"
    alt_name_2 = "*.nms.example.com"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr(
        private_key=csr_private_key,
        subject=csr_subject,
    )

    certificate = generate_certificate(
        csr=csr, ca=ca, ca_key=ca_key, alt_names=[alt_name_1, alt_name_2]
    )

    certificate_object = x509.load_pem_x509_certificate(certificate)
    alt_names = certificate_object.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )
    alt_name_strings = [alt_name.value for alt_name in alt_names.value]
    assert len(alt_name_strings) == 2
    assert alt_name_1 in alt_name_strings
    assert alt_name_2 in alt_name_strings


def test_given_sans_in_csr_and_alt_names_when_generate_certificate_then_alt_names_are_correctly_appended_to_sans():  # noqa: E501
    ca_subject = "ca.subject"
    csr_subject = "csr.subject"
    src_sans_dns = ["www.localhost.com", "www.canonical.com"]
    src_alt_names = ["*.example.com", "*.nms.example.com", "www.localhost.com"]

    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr(
        private_key=csr_private_key,
        subject=csr_subject,
        sans_dns=src_sans_dns,
    )

    certificate = generate_certificate(csr=csr, ca=ca, ca_key=ca_key, alt_names=src_alt_names)

    cert = x509.load_pem_x509_certificate(certificate)
    result_all_sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )
    result_sans_dns = sorted(result_all_sans.value.get_values_for_type(x509.DNSName))

    assert result_sans_dns == sorted(src_sans_dns + src_alt_names)


def test_given_basic_constraints_already_in_csr_when_generate_certificate_then_extension_overwritten():  # noqa: E501
    ca_subject = "ca.subject"
    csr_subject = "csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()

    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)

    csr = generate_csr(
        private_key=csr_private_key,
        subject=csr_subject,
        additional_critical_extensions=[basic_constraints],
    )

    certificate = generate_certificate(csr=csr, ca=ca, ca_key=ca_key)

    certificate_object = x509.load_pem_x509_certificate(certificate)
    basic_constraints = certificate_object.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    assert basic_constraints.value.ca is False


def test_given_basic_constraint_is_false_when_generate_ca_then_extensions_are_correctly_populated():  # noqa: E501
    subject = "whatever.ca.subject"
    private_key = generate_private_key_helper()

    ca = generate_ca(
        private_key=private_key,
        subject=subject,
    )

    certificate_object = x509.load_pem_x509_certificate(ca)
    basic_constraints = certificate_object.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    assert basic_constraints.value.ca is True


def test_given_certificate_created_when_generate_certificate_then_verify_public_key_then_doesnt_throw_exception():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        common_name=csr_subject,
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca,
        ca_key=ca_key,
    )

    certificate_object = x509.load_pem_x509_certificate(certificate)
    private_key_object = serialization.load_pem_private_key(ca_key, password=None)
    public_key = private_key_object.public_key()

    public_key.verify(  # type: ignore[call-arg, union-attr]
        certificate_object.signature,
        certificate_object.tbs_certificate_bytes,
        padding.PKCS1v15(),  # type: ignore[arg-type]
        certificate_object.signature_hash_algorithm,  # type: ignore[arg-type]
    )


def test_given_matching_cert_for_csr_when_csr_matches_certificate_then_it_returns_true():
    private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=private_key,
        common_name="same subject",
    )
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name="some subject",
    )
    certificate = generate_certificate_helper(
        csr=csr,
        ca=ca,
        ca_key=generate_private_key_helper(),
    )
    assert csr_matches_certificate(csr.decode(), certificate.decode()) is True


def test_given_matching_cert_for_csr_with_ec_key_when_csr_matches_certificate_then_it_returns_true():  # noqa: E501
    private_key = generate_ec_private_key_helper()
    csr = generate_csr_helper(
        private_key=private_key,
        common_name="same subject",
    )
    ca_key = generate_ec_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name="some subject",
    )
    certificate = generate_certificate_helper(
        csr=csr,
        ca=ca,
        ca_key=generate_ec_private_key_helper(),
    )
    assert csr_matches_certificate(csr.decode(), certificate.decode()) is True


def test_given_certificate_country_doesnt_match_with_csr_when_csr_matches_certificate_then_returns_true():  # noqa: E501
    ca_private_key = generate_private_key_helper()
    ca = generate_ca_helper(private_key=ca_private_key, common_name="ca subject", country="GB")

    server_private_key = generate_private_key_helper()
    server_csr = generate_csr_helper(
        private_key=server_private_key, common_name="server subject", country="US"
    )

    server_cert = generate_certificate_helper(
        csr=server_csr,
        ca=ca,
        ca_key=ca_private_key,
    )

    assert csr_matches_certificate(server_csr.decode(), server_cert.decode()) is True


def test_given_csr_public_key_not_matching_certificate_public_key_when_csr_matches_certificate_then_it_returns_false():  # noqa: E501
    csr_key_1 = generate_csr_helper(
        private_key=generate_private_key_helper(),
        common_name="matching subject",
    )
    csr_key_2 = generate_csr_helper(
        private_key=generate_private_key_helper(),
        common_name="matching subject",
    )
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name="matching subject",
    )
    certificate = generate_certificate_helper(
        csr=csr_key_1,
        ca=ca,
        ca_key=ca_key,
    )
    assert csr_matches_certificate(csr_key_2.decode(), certificate.decode()) is False


def test_given_ca_cert_with_subject_key_id_when_generate_certificate_then_certificate_authority_key_id_is_identical_to_ca_cert_subject_key_id():  # noqa: E501
    ca_private_key = generate_private_key()
    ca = generate_ca(
        private_key=ca_private_key,
        subject="my.demo.ca",
    )
    ca_pem = x509.load_pem_x509_certificate(ca)
    server_private_key = generate_private_key()

    server_csr = generate_csr(
        private_key=server_private_key,
        subject="10.10.10.10",
        sans_dns=[],
        sans_ip=["10.10.10.10"],
    )
    server_cert = generate_certificate(csr=server_csr, ca=ca, ca_key=ca_private_key)

    loaded_server_cert = x509.load_pem_x509_certificate(server_cert)
    assert (
        loaded_server_cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
        == ca_pem.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.key_identifier
    )


def test_given_request_is_for_ca_certificate_when_generate_certificate_then_certificate_is_generated():  # noqa: E501
    ca_private_key = generate_private_key()
    ca = generate_ca(
        private_key=ca_private_key,
        subject="my.demo.ca",
    )
    server_private_key = generate_private_key()

    server_csr = generate_csr(
        private_key=server_private_key,
        subject="10.10.10.10",
        sans_dns=[],
        sans_ip=["10.10.10.10"],
    )

    server_cert = generate_certificate(
        csr=server_csr,
        ca=ca,
        ca_key=ca_private_key,
        is_ca=True,
    )

    loaded_server_cert = x509.load_pem_x509_certificate(server_cert)

    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        is True
    )
    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
        is True
    )
    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign is True
    )


def test_given_provider_certificate_with_chain_when_chain_as_pem_then_pem_contains_full_chain():
    ca_private_key = generate_private_key()
    ca = generate_ca(
        private_key=ca_private_key,
        subject="my.demo.ca",
    )

    server_private_key = generate_private_key()
    server_csr = generate_csr(
        private_key=server_private_key,
        subject="my.demo.server",
        sans_dns=["my.demo.server"],
        sans_ip=[],
    )
    server_cert = generate_certificate(
        csr=server_csr,
        ca=ca,
        ca_key=ca_private_key,
        is_ca=False,
    )

    expiry_time = datetime.now() + timedelta(days=356)
    expiry_notification_time = expiry_time - timedelta(days=30)
    provider_cert = ProviderCertificate(
        relation_id=0,
        application_name="app",
        csr=server_csr.decode(),
        certificate=server_cert.decode(),
        ca=ca.decode(),
        chain=[ca.decode(), server_cert.decode()],
        revoked=False,
        expiry_time=expiry_time,
        expiry_notification_time=expiry_notification_time,
    )

    fullchain = provider_cert.chain_as_pem()
    loaded = x509.load_pem_x509_certificates(fullchain.encode())
    store = x509.verification.Store([x509.load_pem_x509_certificate(ca)])
    builder = x509.verification.PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(x509.DNSName("my.demo.server"))
    loaded[0].verify_directly_issued_by(loaded[1])
    chain = verifier.verify(loaded[0], loaded[1:])
    assert chain[0].public_bytes(encoding=Encoding.PEM) == server_cert


def test_given_certificate_available_with_chain_when_chain_as_pem_then_pem_contains_full_chain():
    ca_private_key = generate_private_key()
    ca = generate_ca(
        private_key=ca_private_key,
        subject="my.demo.ca",
    )

    server_private_key = generate_private_key()
    server_csr = generate_csr(
        private_key=server_private_key,
        subject="my.demo.server",
        sans_dns=["my.demo.server"],
        sans_ip=[],
    )
    server_cert = generate_certificate(
        csr=server_csr,
        ca=ca,
        ca_key=ca_private_key,
        is_ca=False,
    )

    cert_available_event = CertificateAvailableEvent(
        handle=Mock(),
        certificate_signing_request=server_csr.decode(),
        certificate=server_cert.decode(),
        ca=ca.decode(),
        chain=[ca.decode(), server_cert.decode()],
    )

    fullchain = cert_available_event.chain_as_pem()
    loaded = x509.load_pem_x509_certificates(fullchain.encode())
    store = x509.verification.Store([x509.load_pem_x509_certificate(ca)])
    builder = x509.verification.PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(x509.DNSName("my.demo.server"))
    loaded[0].verify_directly_issued_by(loaded[1])
    chain = verifier.verify(loaded[0], loaded[1:])
    assert chain[0].public_bytes(encoding=Encoding.PEM) == server_cert


def test_given_provider_recommended_notification_time_when_calculate_expiry_notification_time_then_returns_provider_recommendation():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = 24
    requirer_recommended_notification_time = 48
    expected_notification_time = (
        expiry_time - timedelta(hours=provider_recommended_notification_time)
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_negative_provider_recommended_notification_time_when_calculate_expiry_notification_time_then_returns_provider_recommendation():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    negative_provider_recommended_notification_time = 24
    requirer_recommended_notification_time = 48
    expected_notification_time = (
        expiry_time - timedelta(hours=abs(negative_provider_recommended_notification_time))
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=negative_provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_provider_recommended_notification_time_is_too_early_when_calculate_expiry_notification_time_then_returns_requirer_recommended_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = 241
    requirer_recommended_notification_time = 24
    expected_notification_time = (
        expiry_time - timedelta(hours=requirer_recommended_notification_time)
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_provider_recommended_notification_time_is_none_when_calcualte_expiry_notification_time_then_returns_requirer_recommended_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = None
    requirer_recommended_notification_time = 24
    expected_notification_time = (
        expiry_time - timedelta(hours=requirer_recommended_notification_time)
    )
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_requirer_and_provider_recommendations_are_invalid_whencalculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = None
    requirer_recommended_notification_time = 241
    calculated_hours = 80
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_negative_requirer_and_provider_recommendations_are_invalid_whencalculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 240
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = None
    negative_requirer_recommended_notification_time = -241
    calculated_hours = 80
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=negative_requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_validity_time_is_too_short_when_calculate_expiry_notification_time_then_returns_calculated_notification_time():  # noqa: E501
    expiry_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    validity_start_time_in_hours = 3
    validity_start_time = expiry_time - timedelta(hours=validity_start_time_in_hours)
    provider_recommended_notification_time = 24
    requirer_recommended_notification_time = 48
    calculated_hours = 1
    expected_notification_time = expiry_time - timedelta(hours=calculated_hours)
    notification_time = calculate_expiry_notification_time(
        expiry_time=expiry_time,
        validity_start_time=validity_start_time,
        provider_recommended_notification_time=provider_recommended_notification_time,
        requirer_recommended_notification_time=requirer_recommended_notification_time,
    )
    assert notification_time == expected_notification_time


def test_given_provider_certificate_object_when_to_json_then_json_string_is_returned():
    provider_certificate = ProviderCertificate(
        relation_id=0,
        application_name="app",
        csr="csr",
        certificate="certificate",
        ca="ca",
        chain=["ca", "certificate"],
        revoked=False,
        expiry_time=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiry_notification_time=datetime(2023, 12, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    json_string = provider_certificate.to_json()
    expected_json = json.dumps(
        {
            "relation_id": 0,
            "application_name": "app",
            "csr": "csr",
            "certificate": "certificate",
            "ca": "ca",
            "chain": ["ca", "certificate"],
            "revoked": False,
            "expiry_time": "2024-01-01T00:00:00+00:00",
            "expiry_notification_time": "2023-12-01T00:00:00+00:00",
        }
    )
    assert json_string == expected_json


def test_given_localization_is_specified_when_generate_csr_then_csr_contains_localization():
    private_key = generate_private_key()

    csr = generate_csr(
        private_key=private_key,
        subject="my.demo.server",
        sans_dns=["my.demo.server"],
        sans_ip=[],
        country_name="CA",
        state_or_province_name="Quebec",
        locality_name="Montreal",
    )

    csr_object = x509.load_pem_x509_csr(csr)
    assert csr_object.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "CA"
    assert csr_object.subject.get_attributes_for_oid(
        x509.NameOID.STATE_OR_PROVINCE_NAME
        )[0].value == "Quebec"
    assert csr_object.subject.get_attributes_for_oid(
        x509.NameOID.LOCALITY_NAME
        )[0].value == "Montreal"


def test_given_ipv6_sans_when_generate_csr_then_csr_contains_ipv6_sans():
    private_key = generate_private_key()

    csr = generate_csr(
        private_key=private_key,
        subject="my.demo.server",
        sans_dns=["my.demo.server"],
        sans_ip=["2001:db8::1", "2001:db8::2"],
    )

    csr_object = x509.load_pem_x509_csr(csr)
    sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    sans_ip = sans.get_values_for_type(x509.IPAddress)
    assert len(sans_ip) == 2
    assert sans_ip[0].compressed == "2001:db8::1"
    assert sans_ip[1].compressed == "2001:db8::2"
