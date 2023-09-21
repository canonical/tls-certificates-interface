import unittest

from charms.tls_certificates_interface.v2.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from cryptography import x509


class TestCertificates(unittest.TestCase):
    def setUp(self, *unused):
        self.ca_private_key = generate_private_key()
        self.ca = generate_ca(
            private_key=self.ca_private_key,
            subject="my.demo.ca",
        )
        self.ca_pem = x509.load_pem_x509_certificate(self.ca)

        self.server_private_key = generate_private_key()
        self.server_csr = generate_csr(
            private_key=self.server_private_key,
            subject="10.10.10.10",
            sans_dns=[],
            sans_ip=["10.10.10.10"],
        )

    def test_cert_akid_matched_ca_skid(self):
        # WHEN creating a certificate signed by the CA
        server_cert = x509.load_pem_x509_certificate(
            generate_certificate(csr=self.server_csr, ca=self.ca, ca_key=self.ca_private_key)
        )

        # THEN the new certificate's AKID is identical to the CA cert's SKID
        self.assertEqual(
            server_cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value.key_identifier,
            self.ca_pem.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.key_identifier,
        )

    def test_additional_cert_extensions_override_default_extensions(self):
        # WHEN creating a certificate without passing additional extensions
        server_cert = x509.load_pem_x509_certificate(
            generate_certificate(csr=self.server_csr, ca=self.ca, ca_key=self.ca_private_key)
        )

        # THEN the new certificate has a "CA: FALSE" basic extension
        self.assertEqual(
            server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value,
            x509.BasicConstraints(ca=False, path_length=None),
        )

        # BUT WHEN a default extension is overridden
        server_cert = x509.load_pem_x509_certificate(
            generate_certificate(
                csr=self.server_csr,
                ca=self.ca,
                ca_key=self.ca_private_key,
                additional_extensions=[
                    x509.Extension(
                        x509.ExtensionOID.BASIC_CONSTRAINTS,
                        critical=False,
                        value=x509.BasicConstraints(ca=True, path_length=2),
                    )
                ],
            )
        )

        # THEN the new certificate has the overridden value
        self.assertEqual(
            server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value,
            x509.BasicConstraints(ca=True, path_length=2),
        )
