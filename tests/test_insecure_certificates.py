import json
import unittest
from unittest.mock import Mock, PropertyMock, call, patch

from charms.tls_certificates_interface.v0.tls_certificates import (
    PROVIDER_JSON_SCHEMA,
    Cert,
    InsecureCertificatesProvides,
    InsecureCertificatesRequires,
)
from jsonschema import validate  # type: ignore[import]

PROVIDER_UNIT_NAME = "whatever provider unit name"
REQUIRER_UNIT_NAME = "whatever requirer unit name"


class UnitMock:
    def __init__(self, name):
        self.name = name

    @staticmethod
    def is_leader():
        return True


def _load_relation_data(raw_relation_data: dict) -> dict:
    certificate_data = dict()
    for key in raw_relation_data:
        try:
            certificate_data[key] = json.loads(raw_relation_data[key])
        except json.decoder.JSONDecodeError:
            certificate_data[key] = raw_relation_data[key]
    return certificate_data


class TestInsecureCertificatesProvides(unittest.TestCase):
    def setUp(self):
        class MockRelation:
            def relation_changed(self):
                pass

        relationship_name = "certificates"
        charm = Mock()
        charm.on = {"certificates": MockRelation()}
        self.insecure_relation_provides = InsecureCertificatesProvides(
            charm=charm, relationship_name=relationship_name
        )
        self.charm = charm
        self.provider_unit = UnitMock(name=PROVIDER_UNIT_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.unit = self.provider_unit

    def test_given_common_name_is_missing_from_relation_data_when_relation_changed_then_event_is_deferred(  # noqa: E501
        self,
    ):
        certificate_requests = [
            {
                "sans": json.dumps(["whatever sans"]),
            }
        ]
        event = Mock()
        event.relation.data = {
            self.requirer_unit: {"cert_requests": json.dumps(certificate_requests)},
            self.provider_unit: {},
        }
        event.unit = self.requirer_unit

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertTrue(event.defer.call_count == 1)

    def test_given_invalid_cert_requests_in_relation_data_when_relation_changed_then_event_is_deferred(  # noqa: E501
        self,
    ):
        invalid_cert_request_content = "invalid format"
        event = Mock()
        event.relation.data = {
            self.requirer_unit: {
                "common_name": "whatever common name",
                "cert_requests": invalid_cert_request_content,
            },
            self.provider_unit: {},
        }
        event.unit = self.requirer_unit

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertTrue(event.defer.call_count == 1)

    @patch(
        "charms.tls_certificates_interface.v0.tls_certificates.CertificatesProviderCharmEvents.certificate_request",  # noqa: E501
        new_callable=PropertyMock,
    )
    def test_given_cert_requests_in_relation_data_when_relation_changed_then_certificate_request_event_is_emitted_for_each_request(  # noqa: E501
        self, patch_emit
    ):
        blou = Mock()
        patch_emit.emit = blou
        relation_id = 1
        cert_request_1_common_name = "cert request 1 common name"
        cert_request_2_common_name = "cert request 2 common name"
        client_cert_request_1_common_name = "client cert request 1 common name"
        client_cert_request_2_common_name = "client cert request 2 common name"
        cert_requests = [
            {"common_name": cert_request_1_common_name},
            {"common_name": cert_request_2_common_name},
        ]
        client_cert_requests = [
            {"common_name": client_cert_request_1_common_name},
            {"common_name": client_cert_request_2_common_name},
        ]
        event = Mock()
        event.relation.data = {
            self.requirer_unit: {
                "cert_requests": json.dumps(cert_requests),
                "client_cert_requests": json.dumps(client_cert_requests),
            },
            self.provider_unit: {},
        }
        event.relation.id = relation_id
        event.unit = self.requirer_unit

        self.insecure_relation_provides._on_relation_changed(event)

        calls = [
            call().emit(
                common_name=cert_request_1_common_name,
                sans=None,
                cert_type="server",
                relation_id=relation_id,
            ),
            call().emit(
                common_name=cert_request_2_common_name,
                sans=None,
                cert_type="server",
                relation_id=relation_id,
            ),
            call().emit(
                common_name=client_cert_request_1_common_name,
                sans=None,
                cert_type="client",
                relation_id=relation_id,
            ),
            call().emit(
                common_name=client_cert_request_2_common_name,
                sans=None,
                cert_type="client",
                relation_id=relation_id,
            ),
        ]

        patch_emit.assert_has_calls(calls, any_order=True)

    def test_given_certificate_when_set_relation_certificate_then_cert_is_added_to_relation_data(
        self,
    ):
        class Relation:
            data: dict = {self.provider_unit: dict(), self.requirer_unit: dict()}
        common_name = "whatever common name"
        cert = "whatever certificate"
        private_key = "whatever private key"
        certificate = Cert(
            cert=cert,
            key=private_key,
            ca="whatever ca",
            common_name=common_name,
        )
        relation_id = 1
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_relation_provides.set_relation_certificate(
            certificate=certificate, relation_id=relation_id
        )

        relation_data = _load_relation_data(relation.data[self.provider_unit])

        expected_relation_data = {
            "cert": cert,
            "key": private_key
        }
        self.assertEqual(expected_relation_data, relation_data[common_name])

    def test_given_certificate_when_set_relation_certificate_then_ca_is_added_to_relation_data(
        self,
    ):
        class Relation:
            data: dict = {self.provider_unit: dict(), self.requirer_unit: dict()}
        common_name = "whatever common name"
        cert = "whatever certificate"
        private_key = "whatever private key"
        certificate = Cert(
            cert=cert,
            key=private_key,
            ca="whatever ca",
            common_name=common_name,
        )
        relation_id = 1
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_relation_provides.set_relation_certificate(
            certificate=certificate, relation_id=relation_id
        )

        relation_data = _load_relation_data(relation.data[self.provider_unit])

        self.assertEqual(certificate["ca"], relation_data["ca"])


class TestInsecureCertificatesRequires(unittest.TestCase):
    def setUp(self):
        class CharmOnMock:
            certificates = Mock()
            certificate_request = Mock()

            def __getitem__(self, key):
                return getattr(self, key)

        charm = Mock()
        charm.on = CharmOnMock()
        relationship_name = "certificates"
        self.insecure_certificate_requires = InsecureCertificatesRequires(
            charm=charm, relationship_name=relationship_name
        )
        self.charm = charm
        self.provider_unit = UnitMock(name=PROVIDER_UNIT_NAME)
        self.requirer_unit = UnitMock(name=REQUIRER_UNIT_NAME)
        self.charm.framework.model.unit = self.requirer_unit

    def test_given_client_when_request_certificate_then_client_cert_request_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        class Relation:
            data: dict = {self.provider_unit: dict(), self.requirer_unit: dict()}

        common_name = "whatever common name"
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_certificate_requires.request_certificate(
            cert_type="client",
            common_name=common_name,
        )

        self.assertIn("client_cert_requests", relation.data[self.requirer_unit])
        client_cert_requests = json.loads(
            relation.data[self.requirer_unit]["client_cert_requests"]
        )
        expected_client_cert_requests = [{"common_name": common_name, "sans": []}]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)

    def test_given_non_valid_relation_data_when_on_relation_changed_then_event_is_deferred(self):
        event = Mock()
        bad_relation_data = [
            {
                "common_name": "aaa",  # key, cert and ca are missing
            }
        ]
        event.relation.data = {
            self.requirer_unit: {},
            self.provider_unit: {"certificates": json.dumps(bad_relation_data)},
        }
        event.unit = self.provider_unit
        self.insecure_certificate_requires._on_relation_changed(event)

        self.assertTrue(event.defer.call_count == 1)
