# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import unittest
from unittest.mock import PropertyMock, call, patch

from ops import testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
)
from tests.unit.charms.tls_certificates_interface.v3.dummy_provider_charm.src.charm import (
    DummyTLSCertificatesProviderCharm,
)

testing.SIMULATE_CAN_CONNECT = True

BASE_CHARM_DIR = "tests.unit.charms.tls_certificates_interface.v3.dummy_provider_charm.src.charm.DummyTLSCertificatesProviderCharm"  # noqa: E501
LIB_DIR = "lib.charms.tls_certificates_interface.v3.tls_certificates"

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


class TestTLSCertificatesProvides(unittest.TestCase):
    def setUp(self):
        self.relation_name = "certificates"
        self.remote_app = "tls-certificates-requirer"
        self.remote_unit_name = "tls-certificates-requirer/0"
        self.harness = testing.Harness(DummyTLSCertificatesProviderCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def create_certificates_relation_with_1_remote_unit(self) -> int:
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=self.remote_app
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name=self.remote_unit_name
        )
        return relation_id

    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_csr_in_relation_data_when_relation_changed_then_certificate_creation_request_is_emitted(
        self, patch_certificate_creation_request
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        csr = "whatever csr"
        key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.remote_unit_name, key_values=key_values
        )

        patch_certificate_creation_request.assert_has_calls(
            [call().emit(certificate_signing_request=csr, relation_id=relation_id, is_ca=False)]
        )

    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_no_csr_in_certificate_signing_request_when_relation_changed_then_certificate_creation_request_is_not_emitted(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "invalid key": "invalid value",
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.remote_unit_name, key_values=key_values
        )

        patch_certificate_creation_request.assert_not_called()

    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_certificate_for_csr_already_in_relation_data_when_on_relation_changed_then_certificate_creation_request_is_not_emitted(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        csr = "whatever csr"
        provider_app_data = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                        "certificate": "whatever cert",
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values=provider_app_data,
        )

        requirer_unit_data = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=requirer_unit_data,
        )

        patch_certificate_creation_request.assert_not_called()

    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_unit_not_leader_when_relation_changed_then_certificate_creation_request_is_not_emitted(
        self, patch_certificate_creation_request
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        csr = "whatever csr"
        requirer_unit_data = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                    }
                ]
            )
        }
        self.harness.set_leader(is_leader=False)
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=requirer_unit_data,
        )

        patch_certificate_creation_request.assert_not_called()

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV3.remove_certificate")
    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_revocation_request",
    )
    def test_given_unit_not_leader_when_relation_changed_then_certificate_revocation_request_is_not_emitted(
        self, patch_certificate_revocation_request, _
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        remote_unit_relation_data = {"certificate_signing_requests": "[]"}
        self.harness.set_leader(is_leader=False)
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=remote_unit_relation_data,
        )

        patch_certificate_revocation_request.emit.assert_not_called()

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV3.remove_certificate")
    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_revocation_request",
    )
    def test_given_csr_in_provider_relation_data_but_not_in_requirer_when_on_relation_changed_then_certificate_revocation_request_is_emitted(  # noqa: E501
        self, patch_certificate_revocation_request, _
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        csr = "whatever csr"
        ca = "whatever ca"
        chain = ["whatever cert 1", "whatever cert 2"]
        app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "ca": ca,
                        "chain": chain,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values=app_relation_data,
        )
        remote_unit_relation_data = {"certificate_signing_requests": "[]"}
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=remote_unit_relation_data,
        )

        patch_certificate_revocation_request.emit.assert_called_with(
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca,
            chain=chain,
        )

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV3.remove_certificate")
    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_revocation_request",
        new_callable=PropertyMock,
    )
    def test_given_csr_in_provider_relation_data_but_not_in_requirer_when_on_relation_changed_then_remove_certificate_is_called(  # noqa: E501
        self,
        _,
        patch_remove_certificate,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": "whatever csr",
                            "certificate": certificate,
                            "ca": "whatever ca",
                            "chain": ["whatever cert 1", "whatever cert 2"],
                        }
                    ]
                )
            },
        )
        remote_unit_relation_data = {"certificate_signing_requests": "[]"}
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=remote_unit_relation_data,
        )

        patch_remove_certificate.assert_called_with(certificate=certificate)

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV3.remove_certificate")
    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_revocation_request",
        new_callable=PropertyMock,
    )
    def test_given_unit_not_leader_when_relation_changed_then_remove_certificate_is_not_called(
        self,
        _,
        patch_remove_certificate,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        remote_unit_relation_data = {"certificate_signing_requests": "[]"}
        self.harness.set_leader(is_leader=False)
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=remote_unit_relation_data,
        )

        patch_remove_certificate.assert_not_called()

    def test_given_no_data_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        ca = "whatever ca"
        certificate = "whatever certificate"
        certificate_signing_request = "whatever certificate signing request"
        chain = ["whatever cert 1", "whatever cert 2"]

        self.harness.charm.certificates.set_relation_certificate(
            certificate=certificate,
            ca=ca,
            chain=chain,
            certificate_signing_request=certificate_signing_request,
            relation_id=relation_id,
        )

        expected_relation_data = {
            "certificates": [
                {
                    "certificate": certificate,
                    "certificate_signing_request": certificate_signing_request,
                    "ca": ca,
                    "chain": chain,
                }
            ]
        }

        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )

        loaded_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_some_certificates_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = ["whatever initial cert 1", "whatever initial cert 2"]
        new_ca = "whatever new ca"
        new_certificate = "whatever new certificate"
        new_certificate_signing_request = "whatever new certificate signing request"
        new_chain = ["whatever new cert 1", "whatever new cert 2"]

        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate": initial_certificate,
                        "certificate_signing_request": initial_certificate_signing_request,
                        "ca": initial_ca,
                        "chain": initial_chain,
                    }
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )

        self.harness.charm.certificates.set_relation_certificate(
            certificate=new_certificate,
            ca=new_ca,
            chain=new_chain,
            certificate_signing_request=new_certificate_signing_request,
            relation_id=relation_id,
        )

        expected_relation_data = {
            "certificates": [
                {
                    "certificate": initial_certificate,
                    "certificate_signing_request": initial_certificate_signing_request,
                    "ca": initial_ca,
                    "chain": initial_chain,
                },
                {
                    "certificate": new_certificate,
                    "certificate_signing_request": new_certificate_signing_request,
                    "ca": new_ca,
                    "chain": new_chain,
                },
            ]
        }
        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        loaded_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_identical_csr_in_relation_data_when_set_relation_certificate_then_certificate_is_replaced_in_relation_data(  # noqa: E501
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = ["whatever initial cert 1", "whatever initial cert 2"]
        new_certificate = "whatever new certificate"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": initial_certificate_signing_request,
                        "certificate": initial_certificate,
                        "ca": initial_ca,
                        "chain": initial_chain,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )

        self.harness.charm.certificates.set_relation_certificate(
            certificate=new_certificate,
            ca=initial_ca,
            chain=initial_chain,
            certificate_signing_request=initial_certificate_signing_request,
            relation_id=relation_id,
        )

        expected_relation_data = {
            "certificates": [
                {
                    "certificate": new_certificate,
                    "certificate_signing_request": initial_certificate_signing_request,
                    "ca": initial_ca,
                    "chain": initial_chain,
                },
            ]
        }
        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        loaded_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_unit_not_leader_when_set_relation_certificate_then_certificate_is_not_added_to_relation_data(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = ["whatever initial cert 1", "whatever initial cert 2"]
        new_certificate = "whatever new certificate"
        self.harness.set_leader(is_leader=False)
        self.harness.charm.certificates.set_relation_certificate(
            certificate=new_certificate,
            ca=initial_ca,
            chain=initial_chain,
            certificate_signing_request=initial_certificate_signing_request,
            relation_id=relation_id,
        )
        expected_relation_data = {}
        self.harness.set_leader(is_leader=True)
        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        loaded_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_more_than_one_remote_application_when_set_relation_certificate_then_certificate_is_added_to_correct_application_data_bag(  # noqa: E501
        self,
    ):
        remote_app_1 = "tls-requirer-1"
        remote_app_2 = "tls-requirer-2"
        remote_app_1_unit_name = "tls-requirer-1/0"
        remote_app_2_unit_name = "tls-requirer-2/0"
        self.harness.set_leader(is_leader=True)
        relation_1_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_1
        )
        relation_2_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_2
        )
        self.harness.add_relation_unit(
            relation_id=relation_1_id, remote_unit_name=remote_app_1_unit_name
        )
        self.harness.add_relation_unit(
            relation_id=relation_2_id, remote_unit_name=remote_app_2_unit_name
        )
        ca = "whatever ca"
        certificate = "whatever certificate"
        certificate_signing_request = "whatever certificate signing request"
        chain = ["whatever cert 1", "whatever cert 2"]

        self.harness.charm.certificates.set_relation_certificate(
            certificate=certificate,
            ca=ca,
            chain=chain,
            certificate_signing_request=certificate_signing_request,
            relation_id=relation_2_id,
        )

        relation_1_data = self.harness.get_relation_data(
            relation_id=relation_1_id, app_or_unit=self.harness.charm.app
        )
        relation_2_data = self.harness.get_relation_data(
            relation_id=relation_2_id, app_or_unit=self.harness.charm.app
        )

        self.assertEqual(relation_1_data, {})
        self.assertEqual(
            relation_2_data,
            {
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": certificate_signing_request,
                            "ca": ca,
                            "chain": chain,
                        }
                    ]
                )
            },
        )

    def test_given_unit_is_not_leader_when_set_relation_certificate_then_relation_data_is_not_modified(
        self,
    ):
        self.harness.set_leader(is_leader=False)
        remote_app_1 = "tls-requirer-1"
        remote_app_1_unit_name = "tls-requirer-1/0"
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_1
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name=remote_app_1_unit_name
        )
        initial_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )

        self.harness.charm.certificates.set_relation_certificate(
            certificate="whatever certificate",
            ca="whatever ca",
            chain=["whatever cert 1", "whatever cert 2"],
            certificate_signing_request="whatever certificate signing request",
            relation_id=relation_id,
        )

        final_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )

        self.assertEqual(initial_relation_data, final_relation_data)

    def test_given_certificate_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )

        self.harness.charm.certificates.remove_certificate(certificate=certificate)

        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual({"certificates": []}, provider_relation_data)

    def test_given_certificate_not_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        user_provided_certificate = "whatever cert"
        certificates_in_relation_data = [
            {
                "certificate_signing_request": "whatever csr",
                "certificate": "another certificate",
                "ca": "whatever ca",
                "chain": ["whatever cert 1", "whatever cert 2"],
            }
        ]
        key_values = {"certificates": json.dumps(certificates_in_relation_data)}
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )

        self.harness.charm.certificates.remove_certificate(certificate=user_provided_certificate)

        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(dict(provider_relation_data))
        self.assertEqual({"certificates": certificates_in_relation_data}, provider_relation_data)

    def test_given_more_than_one_remote_application_when_remove_relation_certificate_then_certificate_is_removed_from_correct_application_data_bag(  # noqa: E501
        self,
    ):
        remote_app_1 = "tls-requirer-1"
        remote_app_2 = "tls-requirer-2"
        remote_app_1_unit_name = "tls-requirer-1/0"
        remote_app_2_unit_name = "tls-requirer-2/0"
        self.harness.set_leader(is_leader=True)
        relation_1_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_1
        )
        relation_2_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_2
        )
        self.harness.add_relation_unit(
            relation_id=relation_1_id, remote_unit_name=remote_app_1_unit_name
        )
        self.harness.add_relation_unit(
            relation_id=relation_2_id, remote_unit_name=remote_app_2_unit_name
        )

        relation_1_csr = "whatever csr 1"
        relation_2_csr = "whatever csr 2"
        relation_1_certificate = "whatever cert 1"
        relation_2_certificate = "whatever cert 2"
        relation_1_ca = "whatever ca 1"
        relation_2_ca = "whatever ca 2"
        relation_1_chain = ["whatever cert 1", "whatever cert 2"]
        relation_2_chain = ["whatever cert 3", "whatever cert 4"]
        certificates_in_relation_1 = [
            {
                "certificate_signing_request": relation_1_csr,
                "certificate": relation_1_certificate,
                "ca": relation_1_ca,
                "chain": relation_1_chain,
            }
        ]
        certificates_in_relation_2 = [
            {
                "certificate_signing_request": relation_2_csr,
                "certificate": relation_2_certificate,
                "ca": relation_2_ca,
                "chain": relation_2_chain,
            }
        ]
        self.harness.update_relation_data(
            relation_id=relation_1_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"certificates": json.dumps(certificates_in_relation_1)},
        )
        self.harness.update_relation_data(
            relation_id=relation_2_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"certificates": json.dumps(certificates_in_relation_2)},
        )

        self.harness.charm.certificates.remove_certificate(certificate=relation_2_certificate)

        relation_1_data = self.harness.get_relation_data(
            relation_id=relation_1_id, app_or_unit=self.harness.charm.app
        )
        relation_2_data = self.harness.get_relation_data(
            relation_id=relation_2_id, app_or_unit=self.harness.charm.app
        )
        self.assertEqual(relation_1_data, {"certificates": json.dumps(certificates_in_relation_1)})
        self.assertEqual(relation_2_data, {"certificates": "[]"})

    @patch(f"{BASE_CHARM_DIR}._on_certificate_creation_request")
    def test_given_more_than_one_application_related_to_operator_when_csrs_are_added_to_remote_units_databag_then_certificate_creation_requests_are_triggered(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        remote_app_1 = "tls-requirer-1"
        remote_app_2 = "tls-requirer-2"
        remote_app_1_unit_name = "tls-requirer-1/0"
        remote_app_2_unit_name = "tls-requirer-2/0"
        self.harness.set_leader(is_leader=True)
        relation_1_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_1
        )
        relation_2_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=remote_app_2
        )
        self.harness.add_relation_unit(
            relation_id=relation_1_id, remote_unit_name=remote_app_1_unit_name
        )
        self.harness.add_relation_unit(
            relation_id=relation_2_id, remote_unit_name=remote_app_2_unit_name
        )
        csr_1 = "whatever csr 1"
        csr_2 = "whatever csr 2"
        requirer_app_1_unit_data = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr_1,
                    }
                ]
            )
        }
        requirer_app_2_unit_data = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr_2,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_1_id,
            app_or_unit=remote_app_1_unit_name,
            key_values=requirer_app_1_unit_data,
        )
        self.harness.update_relation_data(
            relation_id=relation_2_id,
            app_or_unit=remote_app_2_unit_name,
            key_values=requirer_app_2_unit_data,
        )

        call_args_list = patch_certificate_creation_request.call_args_list
        self.assertEqual(call_args_list[0].args[0].certificate_signing_request, csr_1)
        self.assertEqual(call_args_list[0].args[0].relation_id, relation_1_id)
        self.assertEqual(call_args_list[1].args[0].certificate_signing_request, csr_2)
        self.assertEqual(call_args_list[1].args[0].relation_id, relation_2_id)

    @patch(
        f"{LIB_DIR}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_requirer_unit_requests_ca_when_relation_changed_then_certificate_creation_request_is_emitted(
        self, patch_certificate_creation_request
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        csr = "whatever csr"
        remote_unit_relation_data = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                        "ca": True,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=remote_unit_relation_data,
        )

        patch_certificate_creation_request.assert_has_calls(
            [
                call().emit(
                    certificate_signing_request=csr,
                    is_ca=True,
                    relation_id=relation_id,
                )
            ]
        )

    def test_given_certificates_in_relation_data_when_revoke_all_certificates_then_no_certificates_are_present(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )

        self.harness.charm.certificates.revoke_all_certificates()

        expected = {
            "certificates": [
                {
                    "certificate_signing_request": "whatever csr",
                    "certificate": certificate,
                    "ca": "whatever ca",
                    "chain": ["whatever cert 1", "whatever cert 2"],
                    "revoked": True,
                }
            ]
        }
        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(provider_relation_data)
        self.assertEqual(expected, provider_relation_data)

    def test_given_unit_not_leader_and_certificates_in_relation_data_when_revoke_all_certificates_then_certificates_are_present(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )
        self.harness.set_leader(is_leader=False)
        self.harness.charm.certificates.revoke_all_certificates()

        expected = {"certificates": []}
        self.harness.set_leader(is_leader=True)
        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(provider_relation_data)
        self.assertEqual(expected, provider_relation_data)

    def test_given_no_certificates_in_relation_data_when_revoke_all_certificates_then_no_certificates_are_present(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        self.harness.charm.certificates.revoke_all_certificates()

        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(provider_relation_data)
        self.assertEqual({"certificates": []}, provider_relation_data)

    def test_given_no_certificates_in_relation_data_when_get_issued_certificates_then_returned_dict_has_empty_certificates_list(
        self,
    ):
        self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)

        certificates = self.harness.charm.certificates.get_issued_certificates()

        self.assertEqual(certificates, [])

    def test_given_one_certificate_in_relation_data_when_get_issued_certificates_then_certificate_is_returned(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )
        expected_certificate = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.remote_app,
                csr="whatever csr",
                certificate="whatever cert",
                chain=["whatever cert 1", "whatever cert 2"],
                ca="whatever ca",
                revoked=False,
            )
        ]

        certificates = self.harness.charm.certificates.get_issued_certificates()

        self.assertEqual(certificates, expected_certificate)

    def test_given_multiple_certificate_in_relation_data_when_get_issued_certificates_then_certificate_are_returned(
        self,
    ):
        relation_id_requirer_1 = self.create_certificates_relation_with_1_remote_unit()
        requirer_2_app = "tls-certificates-requirer_2"
        requirer_2_unit = "tls-certificates-requirer_2/0"
        relation_id_requirer_2 = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=requirer_2_app
        )
        self.harness.add_relation_unit(
            relation_id=relation_id_requirer_2, remote_unit_name=requirer_2_unit
        )

        self.harness.set_leader(is_leader=True)

        certificate_1 = "whatever cert 1"
        certificate_2 = "whatever cert 2"

        key_values_requirer_1 = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate_1,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        key_values_requirer_2 = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "different csr",
                        "certificate": certificate_2,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id_requirer_1,
            app_or_unit=self.harness.charm.app.name,
            key_values=key_values_requirer_1,
        )
        self.harness.update_relation_data(
            relation_id=relation_id_requirer_2,
            app_or_unit=self.harness.charm.app.name,
            key_values=key_values_requirer_2,
        )
        expected_certificates = [
            ProviderCertificate(
                relation_id=relation_id_requirer_1,
                application_name=self.remote_app,
                csr="whatever csr",
                certificate="whatever cert 1",
                chain=["whatever cert 1", "whatever cert 2"],
                ca="whatever ca",
                revoked=False,
            ),
            ProviderCertificate(
                relation_id=relation_id_requirer_2,
                application_name=requirer_2_app,
                csr="different csr",
                certificate="whatever cert 2",
                chain=["whatever cert 1", "whatever cert 2"],
                ca="whatever ca",
                revoked=False,
            ),
        ]
        certificates = self.harness.charm.certificates.get_issued_certificates()
        self.assertEqual(certificates, expected_certificates)

    def test_given_no_certificates_in_relation_data_when_get_issued_certificates_by_relation_id_then_returned_dict_has_empty_certificates_list(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)

        certificates = self.harness.charm.certificates.get_issued_certificates(relation_id)

        self.assertEqual(certificates, [])

    def test_given_certificate_in_relation_data_when_get_issued_certificates_by_relation_id_then_certificate_is_returned(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )
        expected_certificates = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.remote_app,
                csr="whatever csr",
                certificate="whatever cert",
                chain=["whatever cert 1", "whatever cert 2"],
                ca="whatever ca",
                revoked=False,
            )
        ]

        certificates = self.harness.charm.certificates.get_issued_certificates(
            relation_id=relation_id
        )

        self.assertEqual(certificates, expected_certificates)

    def test_given_unit_not_leader_when_get_issued_certificates_by_relation_id_then_returned_empty_certificates_list(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        self.harness.set_leader(is_leader=True)
        certificate = "whatever cert"
        key_values = {
            "certificates": json.dumps(
                [
                    {
                        "certificate_signing_request": "whatever csr",
                        "certificate": certificate,
                        "ca": "whatever ca",
                        "chain": ["whatever cert 1", "whatever cert 2"],
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name, key_values=key_values
        )
        self.harness.set_leader(is_leader=False)
        certificates = self.harness.charm.certificates.get_issued_certificates(
            relation_id=relation_id
        )

        self.assertEqual(certificates, [])

    def test_given_incorrect_relation_id_when_get_issued_certificates_by_relation_id_then_returned_list_is_empty(
        self,
    ):
        random_relation_id = 1234
        self.harness.set_leader(is_leader=True)
        certificates = self.harness.charm.certificates.get_issued_certificates(random_relation_id)
        self.assertEqual(certificates, [])

    def test_given_requirer_has_one_unit_and_csr_when_get_requirer_csrs_then_csr_information_is_returned(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        csr = "whatever csr"
        key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.remote_unit_name, key_values=key_values
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=csr,
                is_ca=False,
            ),
        ]

        actual_csrs_info = self.harness.charm.certificates.get_requirer_csrs()
        self.assertEqual(actual_csrs_info, expected_csrs_info)

    def test_given_requirer_has_multiple_units_and_csrs_when_get_requirer_csrs_then_csrs_information_is_returned(
        self,
    ):
        relation_id = self.create_certificates_relation_with_1_remote_unit()
        remote_unit_2 = "tls-certificates-requirer/1"
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name=remote_unit_2)
        unit_1_csr_1 = "whatever csr of unit 1"
        unit_1_csr_2 = "another csr of unit 1"
        unit_2_csr = "whatever csr of unit 2"
        unit_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": unit_1_csr_1,
                    },
                    {
                        "certificate_signing_request": unit_1_csr_2,
                    },
                ]
            )
        }
        unit_2_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": unit_2_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=unit_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=remote_unit_2, key_values=unit_2_key_values
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=unit_1_csr_1,
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=unit_1_csr_2,
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.remote_app,
                unit_name=remote_unit_2,
                csr=unit_2_csr,
                is_ca=False,
            ),
        ]
        actual_csrs_info = self.harness.charm.certificates.get_requirer_csrs()
        self.assertEqual(
            sorted(actual_csrs_info, key=lambda x: (x.relation_id, x.unit_name)),
            sorted(expected_csrs_info, key=lambda x: (x.relation_id, x.unit_name)),
        )

    def test_given_multiple_requirers_with_csrs_when_get_requirer_csrs_then_csrs_information_is_returned(
        self,
    ):
        application_1_relation_id = self.create_certificates_relation_with_1_remote_unit()
        application_2_relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="tls-certificates-requirer_2"
        )
        application_2_remote_unit_1 = "tls-certificates-requirer_2/1"
        self.harness.add_relation_unit(
            relation_id=application_2_relation_id, remote_unit_name=application_2_remote_unit_1
        )
        application_2_remote_unit_2 = "tls-certificates-requirer_2/2"
        self.harness.add_relation_unit(
            relation_id=application_2_relation_id, remote_unit_name=application_2_remote_unit_2
        )
        application_1_unit_1_csr = "whatever csr of unit 1 in application 1"
        application_2_unit_1_csr = "another csr of unit 1 in application 2"
        application_2_unit_2_csr = "whatever csr of unit 2 in application 2"
        application_1_unit_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_1_unit_1_csr,
                    }
                ]
            )
        }
        application_2_unit_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_2_unit_1_csr,
                    }
                ]
            )
        }
        application_2_unit_2_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_2_unit_2_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=application_1_relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=application_1_unit_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=application_2_relation_id,
            app_or_unit=application_2_remote_unit_1,
            key_values=application_2_unit_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=application_2_relation_id,
            app_or_unit=application_2_remote_unit_2,
            key_values=application_2_unit_2_key_values,
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=application_1_relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=application_1_unit_1_csr,
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=application_2_relation_id,
                application_name="tls-certificates-requirer_2",
                unit_name=application_2_remote_unit_1,
                csr=application_2_unit_1_csr,
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=application_2_relation_id,
                application_name="tls-certificates-requirer_2",
                unit_name=application_2_remote_unit_2,
                csr=application_2_unit_2_csr,
                is_ca=False,
            ),
        ]
        actual_csrs_info = self.harness.charm.certificates.get_requirer_csrs()
        self.assertEqual(
            sorted(actual_csrs_info, key=lambda x: (x.relation_id, x.unit_name)),
            sorted(expected_csrs_info, key=lambda x: (x.relation_id, x.unit_name)),
        )

    def test_given_multiple_requirer_applications_and_relation_id_is_specified_when_get_requirer_csrs_then_csrs_information_is_returned(
        self,
    ):
        application_1_relation_id = self.create_certificates_relation_with_1_remote_unit()
        application_2_relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="tls-certificates-requirer_2"
        )
        application_2_unit_1 = "tls-certificates-requirer_2/1"
        self.harness.add_relation_unit(
            relation_id=application_2_relation_id, remote_unit_name=application_2_unit_1
        )
        application_1_unit_1_csr = "whatever csr of unit 1 in application 1"
        application_2_unit_1_csr = "whatever csr of unit 1 in application 2"
        application_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_1_unit_1_csr,
                    }
                ]
            )
        }
        application_2_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_2_unit_1_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=application_1_relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=application_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=application_2_relation_id,
            app_or_unit=application_2_unit_1,
            key_values=application_2_key_values,
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=application_1_relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=application_1_unit_1_csr,
                is_ca=False,
            ),
        ]
        actual_csrs_info = self.harness.charm.certificates.get_requirer_csrs(
            relation_id=application_1_relation_id
        )
        self.assertEqual(actual_csrs_info, expected_csrs_info)

    def test_given_csrs_with_certs_issued_when_get_outstanding_certificate_requests_then_the_info_of_those_csrs_not_returned(
        self,
    ):
        application_1_relation_id = self.create_certificates_relation_with_1_remote_unit()
        application_2_relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="tls-certificates-requirer_2"
        )
        application_2_unit_1 = "tls-certificates-requirer_2/0"
        self.harness.add_relation_unit(
            relation_id=application_2_relation_id, remote_unit_name=application_2_unit_1
        )
        application_1_csr = "whatever csr of unit 1 in application 1"
        application_2_csr = EXAMPLE_CSR
        application_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_1_csr,
                    }
                ]
            )
        }
        application_2_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_2_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=application_1_relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=application_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=application_2_relation_id,
            app_or_unit=application_2_unit_1,
            key_values=application_2_key_values,
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=application_1_relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=application_1_csr,
                is_ca=False,
            )
        ]
        self.harness.set_leader(is_leader=True)
        ca = "whatever ca"
        certificate = EXAMPLE_CERT
        chain = ["whatever cert 1", "whatever cert 2"]
        self.harness.charm.certificates.set_relation_certificate(
            certificate=certificate,
            ca=ca,
            chain=chain,
            certificate_signing_request=application_2_csr,
            relation_id=application_2_relation_id,
        )
        actual_csrs_info = self.harness.charm.certificates.get_outstanding_certificate_requests()
        self.assertEqual(actual_csrs_info, expected_csrs_info)

    def test_given_csrs_with_no_certs_and_relation_id_specified_when_get_outstanding_certificate_requests_then_csrs_of_that_relation_are_returned(  # noqa: E501
        self,
    ):
        application_1_relation_id = self.create_certificates_relation_with_1_remote_unit()
        application_2_relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="tls-certificates-requirer_2"
        )
        application_2_unit_1 = "tls-certificates-requirer_2/0"
        self.harness.add_relation_unit(
            relation_id=application_2_relation_id, remote_unit_name=application_2_unit_1
        )
        application_1_csr = "whatever csr of unit 1 in application 1"
        application_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_1_csr,
                    }
                ]
            )
        }
        application_2_csr = "whatever csr of unit 1 in application 2"
        application_2_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": application_2_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=application_1_relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=application_1_key_values,
        )
        self.harness.update_relation_data(
            relation_id=application_2_relation_id,
            app_or_unit=application_2_unit_1,
            key_values=application_2_key_values,
        )
        expected_csrs_info = [
            RequirerCSR(
                relation_id=application_1_relation_id,
                application_name=self.remote_app,
                unit_name=self.remote_unit_name,
                csr=application_1_csr,
                is_ca=False,
            )
        ]
        actual_csrs_info = self.harness.charm.certificates.get_outstanding_certificate_requests(
            relation_id=application_1_relation_id
        )
        self.assertEqual(actual_csrs_info, expected_csrs_info)

    def test_given_no_csrs_from_requirer_when_get_requirer_crss_with_certs_then_empty_list_returned(
        self,
    ):
        self.create_certificates_relation_with_1_remote_unit()

        actual_csrs_info = self.harness.charm.certificates.get_requirer_csrs()

        self.assertEqual(actual_csrs_info, [])

    def test_given_no_csrs_from_requirer_when_get_outstanding_certificate_requests_then_empty_list_returned(
        self,
    ):
        self.create_certificates_relation_with_1_remote_unit()

        actual_csrs_info = self.harness.charm.certificates.get_outstanding_certificate_requests()
        self.assertEqual(actual_csrs_info, [])

    def test_given_one_issued_one_unissued_certificate_for_same_application_when_checking_certificate_issued_for_csr_then_correct_boolean_output_returned(
        self,
    ):
        application_1_relation_id = self.create_certificates_relation_with_1_remote_unit()
        csr1 = "fakecsr1"
        csr2 = EXAMPLE_CSR
        application_1_key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {"certificate_signing_request": csr1},
                    {"certificate_signing_request": csr2},
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=application_1_relation_id,
            app_or_unit=self.remote_unit_name,
            key_values=application_1_key_values,
        )

        self.harness.set_leader(is_leader=True)
        ca = "whatever ca"
        certificate = EXAMPLE_CERT
        chain = ["whatever cert 1", "whatever cert 2"]

        # Only issue the second certificate
        self.harness.charm.certificates.set_relation_certificate(
            certificate=certificate,
            ca=ca,
            chain=chain,
            certificate_signing_request=csr2,
            relation_id=application_1_relation_id,
        )

        self.assertFalse(
            self.harness.charm.certificates.certificate_issued_for_csr(
                self.remote_app, csr1, application_1_relation_id
            )
        )
        self.assertTrue(
            self.harness.charm.certificates.certificate_issued_for_csr(
                self.remote_app, csr2, application_1_relation_id
            )
        )
