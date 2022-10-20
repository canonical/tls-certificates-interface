# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import unittest
from unittest.mock import PropertyMock, call, patch

from ops import testing

from tests.unit.charms.tls_certificates_interface.v1.dummy_provider_charm.src.charm import (
    DummyTLSCertificatesProviderCharm,
)

testing.SIMULATE_CAN_CONNECT = True

BASE_CHARM_DIR = "tests.unit.charms.tls_certificates_interface.v1.dummy_provider_charm.src.charm.DummyTLSCertificatesProviderCharm"  # noqa: E501
LIB_DIR = "lib.charms.tls_certificates_interface.v1.tls_certificates"


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
    def test_given_csr_in_relation_data_when_relation_changed_then_certificate_creation_request_is_emitted(  # noqa: E501
        self, patch_certificate_creation_request
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

        patch_certificate_creation_request.assert_has_calls(
            [call().emit(certificate_signing_request=csr, relation_id=relation_id)]
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

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV1.remove_certificate")
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

    @patch(f"{LIB_DIR}.TLSCertificatesProvidesV1.remove_certificate")
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

    def test_given_no_data_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
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

    def test_given_certificate_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(  # noqa: E501
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

    def test_given_certificate_not_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(  # noqa: E501
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

    def test_given_certificates_in_relation_data_when_revoke_all_certificates_then_no_certificates_are_present(  # noqa: e501
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

        provider_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        provider_relation_data = _load_relation_data(provider_relation_data)
        self.assertEqual({"certificates": []}, provider_relation_data)

    def test_given_no_certificates_in_relation_data_when_revoke_all_certificates_then_no_certificates_are_present(  # noqa: e501
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
