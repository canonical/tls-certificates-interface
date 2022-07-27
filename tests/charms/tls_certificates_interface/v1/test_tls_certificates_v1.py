#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import Mock, PropertyMock, call, patch

from charms.tls_certificates_interface.v1.tls_certificates import (
    TLSCertificatesProvides,
    TLSCertificatesRequires,
)

PROVIDER_UNIT_NAME = "whatever provider unit name"
REQUIRER_UNIT_NAME = "whatever requirer unit name"
CHARM_LIB_PATH = "charms.tls_certificates_interface.v1.tls_certificates"


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


class UnitMock:
    def __init__(self, name):
        self.name = name

    @staticmethod
    def is_leader():
        return True


class TestTLSCertificatesProvides(unittest.TestCase):
    def setUp(self):
        class MockRelation:
            def relation_changed(self):
                pass

        relationship_name = "certificates"
        charm = Mock()
        charm.on = {"certificates": MockRelation()}
        self.tls_relation_provides = TLSCertificatesProvides(
            charm=charm, relationship_name=relationship_name
        )
        self.charm = charm
        self.provider_unit = UnitMock(name=PROVIDER_UNIT_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.unit = self.provider_unit

    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_request",
        new_callable=PropertyMock,
    )
    def test_given_when_relation_changed_then_certificate_request_is_emitted(  # noqa: E501
        self, patch_certificate_request
    ):
        csr = "whatever csr"
        relation_id = "whatever id"
        event = Mock()
        event.relation.data = {
            self.requirer_unit: {
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                        }
                    ]
                )
            },
            self.provider_unit: {},
        }
        event.unit = self.requirer_unit
        event.relation.id = relation_id

        self.tls_relation_provides._on_relation_changed(event)

        calls = [call().emit(certificate_signing_request=csr, relation_id=relation_id)]
        patch_certificate_request.assert_has_calls(calls, any_order=True)

    def test_given_no_data_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        class Relation:
            data: dict = {self.provider_unit: dict(), self.requirer_unit: dict()}

        ca = "whatever ca"
        chain = "whatever chain"
        certificate = "whatever certificate"
        certificate_signing_request = "whatever certificate signing request"
        relation_id = 123
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_relation_provides.set_relation_certificate(
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_unit])
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_some_certificates_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = "whatever initial chain"

        class Relation:
            data: dict = {
                self.provider_unit: {
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
                },
                self.requirer_unit: dict(),
            }

        new_ca = "whatever new ca"
        new_chain = "whatever new chain"
        new_certificate = "whatever new certificate"
        new_certificate_signing_request = "whatever new certificate signing request"
        relation_id = 123
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_relation_provides.set_relation_certificate(
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_unit])
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_identical_csr_in_relation_data_when_set_relation_certificate_then_certificate_is_replaced_in_relation_data(  # noqa: E501
        self,
    ):
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = "whatever initial chain"

        class Relation:
            data: dict = {
                self.provider_unit: {
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
                },
                self.requirer_unit: dict(),
            }

        new_certificate = "whatever new certificate"
        relation_id = 123
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_relation_provides.set_relation_certificate(
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_unit])
        self.assertEqual(expected_relation_data, loaded_relation_data)


class TestTLSCertificatesRequires(unittest.TestCase):
    def setUp(self):
        class CharmOnMock:
            certificates = Mock()

            def __getitem__(self, key):
                return getattr(self, key)

        charm = Mock()
        charm.on = CharmOnMock()
        relationship_name = "certificates"
        self.private_key = b"whatever key"
        self.private_key_password = b"whatever password"
        self.tls_certificate_requires = TLSCertificatesRequires(
            charm=charm,
            relationship_name=relationship_name,
        )
        self.charm = charm
        self.provider_unit = UnitMock(name=PROVIDER_UNIT_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.unit = self.requirer_unit

    @patch(f"{CHARM_LIB_PATH}.generate_csr")
    def test_given_common_name_when_request_certificate_then_csr_is_sent_in_relation_data(
        self, patch_generate_csr
    ):
        class Relation:
            data: dict = {self.provider_unit: dict(), self.requirer_unit: dict()}

        csr = b"whatever"
        patch_generate_csr.return_value = csr
        common_name = "whatever common name"
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate(
            common_name=common_name,
            private_key=b"whatever private key",
            private_key_password=b"whatever private key password",
        )

        self.assertIn("certificate_signing_requests", relation.data[self.requirer_unit])

        client_cert_requests = json.loads(
            relation.data[self.requirer_unit]["certificate_signing_requests"]
        )
        expected_client_cert_requests = [{"certificate_signing_request": csr.decode()}]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)

    @patch(f"{CHARM_LIB_PATH}.generate_csr")
    def test_given_relation_data_already_contains_csr_when_request_certificate_then_csr_is_not_sent_again(  # noqa: E501
        self, patch_generate_csr
    ):
        csr = b"whatever"
        patch_generate_csr.return_value = csr

        class Relation:
            data: dict = {
                self.provider_unit: dict(),
                self.requirer_unit: {
                    "certificate_signing_requests": json.dumps(
                        [{"certificate_signing_request": csr.decode()}]
                    )
                },
            }

        common_name = "whatever common name"
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate(
            common_name=common_name,
            private_key=b"whatever private key",
            private_key_password=b"whatever private key password",
        )

        self.assertIn("certificate_signing_requests", relation.data[self.requirer_unit])

        client_cert_requests = json.loads(
            relation.data[self.requirer_unit]["certificate_signing_requests"]
        )
        expected_client_cert_requests = [{"certificate_signing_request": csr.decode()}]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_available")
    def test_given_certificate_in_relation_data_when_on_relation_changed_then_certificate_available_emitted(  # noqa: E501
        self, patch_certificate_available
    ):
        ca = "whatever ca"
        chain = "whatever chain"
        certificate_signing_request = "whatever csr"
        certificate = "whatever certificate"

        class Relation:
            data: dict = {
                self.provider_unit: {
                    "certificates": json.dumps(
                        [
                            {
                                "certificate_signing_request": certificate_signing_request,
                                "certificate": certificate,
                                "ca": ca,
                                "chain": chain,
                            }
                        ]
                    ),
                },
                self.requirer_unit: dict(),
            }

        event = Mock()
        event.relation = Relation()
        event.unit = self.provider_unit

        self.tls_certificate_requires._on_relation_changed(event=event)

        patch_certificate_available.emit.assert_called_with(
            certificate=certificate,
            certificate_signing_request=certificate_signing_request,
            ca=ca,
            chain=chain,
        )
