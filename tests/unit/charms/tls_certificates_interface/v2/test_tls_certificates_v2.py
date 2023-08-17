#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import uuid

import pytest
from charms.tls_certificates_interface.v2.tls_certificates import (
    csr_matches_certificate,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_pfx_package,
    generate_private_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12

from tests.unit.charms.tls_certificates_interface.v2.certificates import (
    generate_ca as generate_ca_helper,
)
from tests.unit.charms.tls_certificates_interface.v2.certificates import (
    generate_certificate as generate_certificate_helper,
)
from tests.unit.charms.tls_certificates_interface.v2.certificates import (
    generate_csr as generate_csr_helper,
)
from tests.unit.charms.tls_certificates_interface.v2.certificates import (
    generate_private_key as generate_private_key_helper,
)

EXAMPLE_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCr7Or/bP3HZcsRH3vLk8rB4QXEZsLwlAfctT5h
GIvp4D1oK6TeNb/gQTH62gthGdbtR2DuMEsUC1deWdJqbbh55NtjwUqGmpj2RDX7
8ncyIROqlM6yJlMNOv25y0vqPudu62uyYVkmnimJnA0RHEwMUs3tBH2jqEHjRX/u
9SpT/yjZgb3DdngLzgzxH32VUst+Zp8Q2nDI33bfyKi5FnsI/bTkmT1MClDlHBfC
wjloF/2TL7nzPiMjv2Of/LKAxJFtG43qaO7Hs3Dg7q9py5iIlh3kljTXbnZg6OGm
zu/iKTEMrUUI45IlCip9porQuj+v+ES0H5g/L3COF0H+3j2FAgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEAfjWSRiGsEzgba0uiwHYXT8rCjeh42TruRvdUjA//Z36K
WyZmwQPIYybAfEAUAodrDOT3Z42L4SEnBkZAZfD9n2fndykdPICutDMwMTDwi1S3
McoXFQOPUC52VWyMHEGiRpD2RBmzCeyGVaTfvnGHivIkX49Z39gKcm6Csi4N+xaA
+RlNIfwQ8KIfwKUUWsR3ZRXDFgI6nf32ENcjLl1/OXAwHJEbhTZLs/SSAkbU0Oc1
RvD3wd5eWHhcl3fLJbIjkIeza+/wCduHeAfxfhpiaT5Jv3eJGcFuf7M0HXn6zw73
c8dChXlMi8iLqIUBOg4Mxcfob9josNsMFvLLqgWJgA==
-----END CERTIFICATE REQUEST-----"""


EXAMPLE_CERT = """-----BEGIN CERTIFICATE-----
MIICuDCCAaCgAwIBAgIUQxVMITHgrLwWJlCr3Adx4+SSky0wDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMwODE3MTA0MjQ2WhcNMjQw
ODE2MTA0MjQ2WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKvs6v9s/cdlyxEfe8uTysHhBcRmwvCUB9y1PmEY
i+ngPWgrpN41v+BBMfraC2EZ1u1HYO4wSxQLV15Z0mptuHnk22PBSoaamPZENfvy
dzIhE6qUzrImUw06/bnLS+o+527ra7JhWSaeKYmcDREcTAxSze0EfaOoQeNFf+71
KlP/KNmBvcN2eAvODPEffZVSy35mnxDacMjfdt/IqLkWewj9tOSZPUwKUOUcF8LC
OWgX/ZMvufM+IyO/Y5/8soDEkW0bjepo7sezcODur2nLmIiWHeSWNNdudmDo4abO
7+IpMQytRQjjkiUKKn2mitC6P6/4RLQfmD8vcI4XQf7ePYUCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAUEc2jfcS12vsSnlSbcfreOKFPDfwttYud7GJhzo46ftLz4QR
d+jDyKuonok2SuoJWZhPPguYKPOumlkWf+lS7HuoaZTaUmt2UpZU1msUTk5Y76If
tZKofTo/O/amaK3zoG3pwIhgkGHr0kXqZL//DrSGayZ/SNu/h4R11p4wj52vEbpl
Mj0IojLvil354ipa08eqtZhp8HdEKTw0YwySTdar34/xQ2swOByfBBnoMLmDMijI
sPC10bF105CbfRIfOX02whQ1FKDH5fReGgDHR+hcKiQVvgt12n6QD5IPnJn10N1L
qbNLuwLW2Nhf9xIOLFRoPMUnP7njo0t15qgMfA==
-----END CERTIFICATE-----"""


def validate_induced_data_from_pfx_is_equal_to_initial_data(
    pfx_file: bytes,
    password: str,
    initial_certificate: bytes,
    initial_private_key: bytes,
):
    (
        induced_private_key_object,
        induced_certificate_object,
        additional_certificate,
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


def test_given_csr_and_ca_when_generate_certificate_then_certificate_is_generated_with_correct_subject_and_issuer():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        subject=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        subject=csr_subject,
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
        subject=ca_subject,
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
        subject=ca_subject,
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
        x509.extensions.SubjectAlternativeName
    )
    alt_name_strings = [alt_name.value for alt_name in alt_names.value]
    assert len(alt_name_strings) == 2
    assert alt_name_1 in alt_name_strings
    assert alt_name_2 in alt_name_strings


def test_given_sans_in_csr_and_alt_names_when_generate_certificate_then_alt_names_are_correctly_appended_to_sans():
    ca_subject = "ca.subject"
    csr_subject = "csr.subject"
    src_sans_dns = ["www.localhost.com", "www.canonical.com"]
    src_alt_names = ["*.example.com", "*.nms.example.com", "www.localhost.com"]

    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        subject=ca_subject,
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
        x509.extensions.SubjectAlternativeName
    )
    result_sans_dns = sorted(result_all_sans.value.get_values_for_type(x509.DNSName))

    assert result_sans_dns == sorted(src_sans_dns + src_alt_names)


def test_given_basic_constraint_is_false_when_generate_ca_then_extensions_are_correctly_populated():  # noqa: E501
    subject = "whatever.ca.subject"
    private_key = generate_private_key_helper()

    ca = generate_ca(
        private_key=private_key,
        subject=subject,
    )

    certificate_object = x509.load_pem_x509_certificate(ca)
    basic_constraints = certificate_object.extensions.get_extension_for_class(
        x509.extensions.BasicConstraints
    )
    assert basic_constraints.value.ca is True


def test_given_certificate_created_when_generate_certificate_then_verify_public_key_then_doesnt_throw_exception():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        subject=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        subject=csr_subject,
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


def test_given_cert_and_private_key_when_generate_pfx_package_then_pfx_file_is_generated():
    password = "whatever"
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    certifier_key = generate_private_key_helper()
    certifier_pem = generate_ca_helper(
        private_key=certifier_key,
        subject=ca_subject,
    )
    admin_operator_key_pem = generate_private_key_helper()
    admin_operator_csr = generate_csr_helper(
        private_key=admin_operator_key_pem,
        subject=csr_subject,
    )
    admin_operator_pem = generate_certificate_helper(
        csr=admin_operator_csr,
        ca=certifier_pem,
        ca_key=certifier_key,
    )

    admin_operator_pfx = generate_pfx_package(
        private_key=admin_operator_key_pem,
        certificate=admin_operator_pem,
        package_password=password,
    )

    validate_induced_data_from_pfx_is_equal_to_initial_data(
        pfx_file=admin_operator_pfx,
        password=password,
        initial_certificate=admin_operator_pem,
        initial_private_key=admin_operator_key_pem,
    )


def test_given_matching_cert_for_csr_when_csr_matches_certificate_then_it_returns_true():
    csr = EXAMPLE_CSR
    certificate = EXAMPLE_CERT
    assert csr_matches_certificate(csr, certificate) is True


def test_given_non_matching_cert_for_csr_when_csr_matches_certificate_then_it_returns_false():
    csr = EXAMPLE_CSR
    certificate = "some random cert"
    assert csr_matches_certificate(csr, certificate) is False
