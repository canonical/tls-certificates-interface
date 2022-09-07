#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
import uuid
from unittest.mock import Mock, PropertyMock, call, patch

import pytest
from charms.tls_certificates_interface.v1.tls_certificates import (
    TLSCertificatesProvidesV1,
    TLSCertificatesRequiresV1,
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

from tests.charms.tls_certificates_interface.v1.certificates import (
    generate_ca as generate_ca_helper,
)
from tests.charms.tls_certificates_interface.v1.certificates import (
    generate_certificate as generate_certificate_helper,
)
from tests.charms.tls_certificates_interface.v1.certificates import (
    generate_csr as generate_csr_helper,
)
from tests.charms.tls_certificates_interface.v1.certificates import (
    generate_private_key as generate_private_key_helper,
)

PROVIDER_UNIT_NAME = "whatever provider unit name"
PROVIDER_APP_NAME = "whatever provider app name"
REQUIRER_UNIT_NAME = "whatever requirer unit name"
CHARM_LIB_PATH = "charms.tls_certificates_interface.v1.tls_certificates"


class RelationMock:
    def __init__(
        self,
        provider_app,
        requirer_unit,
        relation_id: int = 123,
        provider_app_data: dict = None,
        requirer_unit_data: dict = None,
    ):
        if provider_app_data:
            self.provider_app_data = provider_app_data
        else:
            self.provider_app_data = dict()

        if requirer_unit_data:
            self.requirer_unit_data = requirer_unit_data
        else:
            self.requirer_unit_data = dict()
        self.provider_app = provider_app
        self.requirer_unit = requirer_unit
        self._relation_id = relation_id

    @property
    def data(self):
        return {
            self.provider_app: self.provider_app_data,
            self.requirer_unit: self.requirer_unit_data,
        }

    @property
    def app(self):
        return self.provider_app

    @property
    def units(self):
        return [self.requirer_unit]

    @property
    def id(self):
        return self._relation_id


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


class UnitMock:
    def __init__(self, name):
        self.name = name

    @staticmethod
    def is_leader():
        return True


class AppMock:
    def __init__(self, name):
        self.name = name


class TestTLSCertificatesProvidesV1(unittest.TestCase):
    def setUp(self):
        class MockRelationEvents:
            def relation_changed(self):
                pass

        self.relationship_name = "certificates"
        charm = Mock()
        charm.on = {"certificates": MockRelationEvents()}
        self.tls_relation_provides = TLSCertificatesProvidesV1(
            charm=charm, relationship_name=self.relationship_name
        )
        self.charm = charm
        self.provider_app = AppMock(name=PROVIDER_APP_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.app = self.provider_app

    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_csr_in_relation_data_when_relation_changed_then_certificate_creation_request_is_emitted(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        event = Mock()
        csr = "whatever csr"
        relation_id = 456
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                        }
                    ]
                )
            },
            relation_id=relation_id,
        )
        event.unit = self.requirer_unit

        self.tls_relation_provides._on_relation_changed(event)

        patch_certificate_creation_request.assert_has_calls(
            [call().emit(certificate_signing_request=csr, relation_id=relation_id)]
        )

    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_no_csr_in_certificate_signing_request_when_relation_changed_then_certificate_creation_request_is_not_emitted(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "invalid key": "invalid value",
                        }
                    ]
                )
            },
        )
        event.unit = self.requirer_unit

        self.tls_relation_provides._on_relation_changed(event)

        patch_certificate_creation_request.assert_not_called()

    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_creation_request",
        new_callable=PropertyMock,
    )
    def test_given_certificate_for_csr_already_in_relation_data_when_on_relation_changed_then_certificate_creation_request_is_not_emitted(  # noqa: E501
        self, patch_certificate_creation_request
    ):
        csr = "whatever csr"
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            requirer_unit=self.requirer_unit,
            provider_app=self.provider_app,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                        }
                    ]
                )
            },
            provider_app_data={
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
            },
        )
        event.unit = self.requirer_unit

        self.tls_relation_provides._on_relation_changed(event)

        patch_certificate_creation_request.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesProvidesV1.remove_certificate")
    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_revocation_request",
    )
    def test_given_csr_in_provider_relation_data_but_not_in_requirer_when_on_relation_changed_then_certificate_revocation_request_is_emitted(  # noqa: E501
        self, patch_certificate_revocation_request, _
    ):
        event = Mock()
        certificate = "whatever cert"
        csr = "whatever csr"
        ca = "whatever ca"
        chain = ["whatever cert 1", "whatever cert 2"]
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            requirer_unit=self.requirer_unit,
            provider_app=self.provider_app,
            requirer_unit_data={"certificate_signing_requests": json.dumps([])},
            provider_app_data={
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
            },
        )
        event.unit = self.requirer_unit

        self.tls_relation_provides._on_relation_changed(event)

        patch_certificate_revocation_request.emit.assert_called_with(
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca,
            chain=chain,
        )

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesProvidesV1.remove_certificate")
    @patch(
        f"{CHARM_LIB_PATH}.CertificatesProviderCharmEvents.certificate_revocation_request",
        new_callable=PropertyMock,
    )
    def test_given_csr_in_provider_relation_data_but_not_in_requirer_when_on_relation_changed_then_remove_certificate_is_called(  # noqa: E501
        self,
        _,
        patch_remove_certificate,
    ):
        certificate = "whatever cert"
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
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
            requirer_unit_data={"certificate_signing_requests": json.dumps([])},
        )
        event.unit = self.requirer_unit

        self.tls_relation_provides._on_relation_changed(event)

        patch_remove_certificate.assert_called_with(certificate=certificate)

    def test_given_no_data_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        ca = "whatever ca"
        certificate = "whatever certificate"
        certificate_signing_request = "whatever certificate signing request"
        chain = ["whatever cert 1", "whatever cert 2"]
        relation_id = 123
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            relation_id=relation_id,
        )
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_app])
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_some_certificates_in_relation_data_when_set_relation_certificate_then_certificate_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = ["whatever initial cert 1", "whatever initial cert 2"]
        new_ca = "whatever new ca"
        new_certificate = "whatever new certificate"
        new_certificate_signing_request = "whatever new certificate signing request"
        new_chain = ["whatever new cert 1", "whatever new cert 2"]
        relation_id = 123
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
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
        )
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_app])
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_identical_csr_in_relation_data_when_set_relation_certificate_then_certificate_is_replaced_in_relation_data(  # noqa: E501
        self,
    ):
        initial_certificate = "whatever initial cert"
        initial_certificate_signing_request = "whatever initial csr"
        initial_ca = "whatever initial ca"
        initial_chain = ["whatever initial cert 1", "whatever initial cert 2"]
        new_certificate = "whatever new certificate"
        relation_id = 123
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
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
        )
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
        loaded_relation_data = _load_relation_data(relation.data[self.provider_app])
        self.assertEqual(expected_relation_data, loaded_relation_data)

    def test_given_certificate_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(  # noqa: E501
        self,
    ):
        certificate = "whatever cert"
        self.charm.framework.model.get_relation.return_value = relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
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
        self.charm.framework.model.relations = {self.relationship_name: [relation]}

        self.tls_relation_provides.remove_certificate(certificate=certificate)

        provider_relation_data = _load_relation_data(relation.data[self.provider_app])
        self.assertEqual({"certificates": []}, provider_relation_data)

    def test_given_certificate_not_in_relation_data_when_remove_certificate_then_certificate_is_removed_from_relation(  # noqa: E501
        self,
    ):
        user_provided_certificate = "whatever cert"
        certificates_in_relation_data = [
            {
                "certificate_signing_request": "whatever csr",
                "certificate": "another certificate",
                "ca": "whatever ca",
                "chain": ["whatever cert 1", "whatever cert 2"],
            }
        ]
        self.charm.framework.model.get_relation.return_value = relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={"certificates": json.dumps(certificates_in_relation_data)},
        )
        self.charm.framework.model.relations = {self.relationship_name: [relation]}

        self.tls_relation_provides.remove_certificate(certificate=user_provided_certificate)

        provider_relation_data = _load_relation_data(relation.data[self.provider_app])
        self.assertEqual({"certificates": certificates_in_relation_data}, provider_relation_data)


class TestTLSCertificatesRequiresV1(unittest.TestCase):
    def setUp(self):
        class CharmOnMock:
            certificates = Mock()

            def update_status(self, event):
                pass

            def __getitem__(self, key):
                return getattr(self, key)

        self.charm = Mock()
        self.charm.on = CharmOnMock()
        self.relationship_name = "certificates"
        self.private_key = b"whatever key"
        self.private_key_password = b"whatever password"
        self.tls_certificate_requires = TLSCertificatesRequiresV1(
            charm=self.charm,
            relationship_name=self.relationship_name,
        )
        self.provider_app = AppMock(name=PROVIDER_APP_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.unit = self.requirer_unit

    def test_given_no_relation_when_request_certificate_creation_then_runtime_error_is_raised(
        self,
    ):
        self.charm.framework.model.get_relation.return_value = None

        with pytest.raises(RuntimeError):
            self.tls_certificate_requires.request_certificate_creation(
                certificate_signing_request=b"whatever csr"
            )

    def test_given_csr_when_request_certificate_creation_then_csr_is_sent_in_relation_data(self):
        relation = RelationMock(provider_app=self.provider_app, requirer_unit=self.requirer_unit)
        self.charm.framework.model.get_relation.return_value = relation
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            subject="whatver subject",
        )

        self.tls_certificate_requires.request_certificate_creation(certificate_signing_request=csr)

        assert json.loads(relation.data[self.requirer_unit]["certificate_signing_requests"]) == [
            {"certificate_signing_request": csr.decode().strip()}
        ]

    def test_given_relation_data_already_contains_csr_when_request_certificate_creation_then_csr_is_not_sent_again(  # noqa: E501
        self,
    ):
        common_name = "whatever common name"
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        csr = generate_csr_helper(
            private_key=private_key, private_key_password=private_key_password, subject=common_name
        )
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr.decode().strip()}]
                )
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate_creation(certificate_signing_request=csr)

        self.assertIn("certificate_signing_requests", relation.data[self.requirer_unit])

        client_cert_requests = json.loads(
            relation.data[self.requirer_unit]["certificate_signing_requests"]
        )
        expected_client_cert_requests = [{"certificate_signing_request": csr.decode().strip()}]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)

    def test_given_different_csr_in_relation_data_when_request_certificate_creation_then_new_csr_is_added(  # noqa: E501
        self,
    ):
        initial_common_name = "whatever initial common name"
        new_common_name = "whatever new common name"
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        initial_csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            subject=initial_common_name,
        )
        new_csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            subject=new_common_name,
        )
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": initial_csr.decode().strip()}]
                )
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate_creation(
            certificate_signing_request=new_csr
        )

        client_cert_requests = json.loads(
            relation.data[self.requirer_unit]["certificate_signing_requests"]
        )
        expected_client_cert_requests = [
            {"certificate_signing_request": initial_csr.decode().strip()},
            {"certificate_signing_request": new_csr.decode().strip()},
        ]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)

    def test_given_no_relation_when_request_certificate_revocation_then_runtime_error_is_raised(
        self,
    ):
        self.charm.framework.model.get_relation.return_value = None

        with pytest.raises(RuntimeError):
            self.tls_certificate_requires.request_certificate_revocation(
                certificate_signing_request=b"whatever csr"
            )

    def test_given_csr_when_request_certificate_revocation_then_csr_is_removed_from_relation_data(
        self,
    ):
        certificate_signing_request = b"whatever csr"
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": certificate_signing_request.decode()}]
                )
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate_revocation(
            certificate_signing_request=certificate_signing_request
        )

        self.assertEqual({"certificate_signing_requests": "[]"}, relation.data[self.requirer_unit])

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_available")
    def test_given_certificate_in_provider_and_but_no_csr_for_it_in_requirer_relation_data_when_on_relation_changed_then_certificate_available_not_emitted(  # noqa: E501
        self, patch_certificate_available
    ):
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            requirer_unit=self.requirer_unit,
            provider_app=self.provider_app,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": "whatever csr",
                            "certificate": "whatever certificate",
                            "ca": "whatever ca",
                            "chain": ["whatever cert 1", "whatever cert 2"],
                        }
                    ]
                ),
            },
        )
        event.app = self.provider_app

        self.tls_certificate_requires._on_relation_changed(event=event)

        patch_certificate_available.emit.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_available")
    def test_given_certificate_in_relation_data_when_on_relation_changed_then_certificate_available_emitted(  # noqa: E501
        self, patch_certificate_available
    ):
        ca = "whatever ca"
        chain = ["whatever cert 1", "whatever cert 2"]
        certificate_signing_request = "whatever csr"
        certificate = "whatever certificate"
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            requirer_unit=self.requirer_unit,
            provider_app=self.provider_app,
            provider_app_data={
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
            requirer_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": certificate_signing_request}]
                )
            },
        )
        event.app = self.provider_app

        self.tls_certificate_requires._on_relation_changed(event=event)

        patch_certificate_available.emit.assert_called_with(
            certificate=certificate,
            certificate_signing_request=certificate_signing_request,
            ca=ca,
            chain=chain,
        )

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_available")
    def test_given_relation_data_not_valid_when_on_relation_changed_then_no_certificate_event_is_emitted(  # noqa: E501
        self, patch_certificate_available
    ):
        event = Mock()
        self.charm.framework.model.get_relation.return_value = event.relation = RelationMock(
            requirer_unit=self.requirer_unit,
            provider_app=self.provider_app,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "bad key": "whatever value",
                        }
                    ]
                ),
            },
        )
        event.app = self.provider_app

        self.tls_certificate_requires._on_relation_changed(event=event)

        patch_certificate_available.assert_not_called()

    def test_given_no_csr_in_relation_data_when_request_certificate_revocation_then_nothing_is_done(
        self,
    ):
        certificate_signing_request = b"whatever csr"
        relation = RelationMock(provider_app=self.provider_app, requirer_unit=self.requirer_unit)
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires.request_certificate_revocation(
            certificate_signing_request=certificate_signing_request
        )

        self.assertEqual(dict(), relation.data[self.requirer_unit])

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expiring")
    def test_given_certificate_expires_in_shorter_amount_of_time_than_expiry_notification_time_when_update_status_then_certificate_expiring_is_emitted(  # noqa: E501
        self, certificate_expired_patch
    ):
        expiry_notification_time = 5
        certificate_expires_in_nb_hrs = 1
        tls_certificate_requires = TLSCertificatesRequiresV1(
            charm=self.charm,
            relationship_name=self.relationship_name,
            expiry_notification_time=expiry_notification_time,
        )
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key, private_key_password=private_key_password, subject="whatever"
        )
        ca_certificate = generate_ca_helper(
            private_key=ca_key, private_key_password=ca_private_key_password, subject="whatever"
        )
        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=certificate_expires_in_nb_hrs,
        )
        certificate_object = x509.load_pem_x509_certificate(data=certificate)

        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": certificate_signing_request.decode(),
                            "certificate": certificate.decode().strip(),
                            "ca": ca_certificate.decode().strip(),
                            "chain": [
                                ca_certificate.decode().strip(),
                                certificate.decode().strip(),
                            ],
                        }
                    ]
                ),
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        tls_certificate_requires._on_update_status(event=Mock())

        certificate_expired_patch.emit.assert_called_with(
            certificate=certificate.decode().strip(), expiry=certificate_object.not_valid_after
        )

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expiring")
    def test_given_certificate_expires_in_longer_amount_of_time_than_expiry_notification_time_when_update_status_then_certificate_expiring_is_not_emitted(  # noqa: E501
        self, certificate_expired_patch
    ):
        expiry_notification_time = 1
        certificate_expires_in_nb_hrs = 5
        tls_certificate_requires = TLSCertificatesRequiresV1(
            charm=self.charm,
            relationship_name=self.relationship_name,
            expiry_notification_time=expiry_notification_time,
        )
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key, private_key_password=private_key_password, subject="whatever"
        )
        ca_certificate = generate_ca_helper(
            private_key=ca_key, private_key_password=ca_private_key_password, subject="whatever"
        )
        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=certificate_expires_in_nb_hrs,
        )

        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": certificate_signing_request.decode().strip(),
                            "certificate": certificate.decode().strip(),
                            "ca": ca_certificate.decode().strip(),
                            "chain": [
                                ca_certificate.decode().strip(),
                                certificate.decode().strip(),
                            ],
                        }
                    ]
                ),
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        tls_certificate_requires._on_update_status(event=Mock())

        certificate_expired_patch.emit.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expired")
    def test_given_certificate_is_expired_when_update_status_then_certificate_expired_event_emitted(  # noqa: E501
        self, certificate_expired_patch
    ):
        hours_before_expiry = -1
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key, private_key_password=private_key_password, subject="whatever"
        )
        ca_certificate = generate_ca_helper(
            private_key=ca_key, private_key_password=ca_private_key_password, subject="whatever"
        )
        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": certificate_signing_request.decode().strip(),
                            "certificate": certificate.decode().strip(),
                            "ca": ca_certificate.decode().strip(),
                            "chain": [
                                ca_certificate.decode().strip(),
                                certificate.decode().strip(),
                            ],
                        }
                    ]
                ),
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires._on_update_status(event=Mock())

        certificate_expired_patch.emit.assert_called_with(certificate=certificate.decode().strip())

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expired")
    def test_given_certificate_is_not_expired_when_update_status_then_certificate_expired_event_is_not_emitted(  # noqa: E501
        self, certificate_expired_patch
    ):
        hours_before_expiry = 1
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key, private_key_password=private_key_password, subject="whatever"
        )
        ca_certificate = generate_ca_helper(
            private_key=ca_key, private_key_password=ca_private_key_password, subject="whatever"
        )
        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )
        relation = RelationMock(
            provider_app=self.provider_app,
            requirer_unit=self.requirer_unit,
            provider_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate_signing_request": certificate_signing_request.decode().strip(),
                            "certificate": certificate.decode().strip(),
                            "ca": ca_certificate.decode().strip(),
                            "chain": [
                                ca_certificate.decode().strip(),
                                certificate.decode().strip(),
                            ],
                        }
                    ]
                ),
            },
        )
        self.charm.framework.model.get_relation.return_value = relation

        self.tls_certificate_requires._on_update_status(event=Mock())

        certificate_expired_patch.emit.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expiring")
    @patch(f"{CHARM_LIB_PATH}.CertificatesRequirerCharmEvents.certificate_expired")
    def test_given_no_certificates_relation_when_on_update_status_then_no_certificate_event_is_emitted(
        self, patch_certificate_expired, patch_certificate_expiring
    ):
        self.charm.framework.model.get_relation.return_value = None

        self.tls_certificate_requires._on_update_status(event=Mock())

        patch_certificate_expired.assert_not_called()
        patch_certificate_expiring.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_revocation")
    def test_given_certificate_revocation_success_when_request_certificate_renewal_then_certificate_creation_is_called(  # noqa: E501
        self, _, patch_certificate_creation
    ):
        old_csr = b"whatever old csr"
        new_csr = b"whatever new csr"

        self.tls_certificate_requires.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

        patch_certificate_creation.assert_called_with(certificate_signing_request=new_csr)

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_revocation")
    def test_given_certificate_revocation_failed_when_request_certificate_renewal_then_certificate_creation_is_called_anyway(  # noqa: E501
        self, patch_certificate_revocation, patch_certificate_creation
    ):
        old_csr = b"whatever old csr"
        new_csr = b"whatever new csr"
        patch_certificate_revocation.side_effect = RuntimeError()

        self.tls_certificate_requires.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

        patch_certificate_creation.assert_called_with(certificate_signing_request=new_csr)


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
