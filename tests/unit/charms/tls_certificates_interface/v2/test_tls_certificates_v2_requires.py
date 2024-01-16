# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from ops import testing

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
from tests.unit.charms.tls_certificates_interface.v2.dummy_requirer_charm.src.charm import (
    DummyTLSCertificatesRequirerCharm,
)

testing.SIMULATE_CAN_CONNECT = True

BASE_CHARM_DIR = "tests.unit.charms.tls_certificates_interface.v2.dummy_requirer_charm.src.charm.DummyTLSCertificatesRequirerCharm"  # noqa: E501
LIBID = "afd8c2bccf834997afce12c2706d2ede"
LIB_DIR = "lib.charms.tls_certificates_interface.v2.tls_certificates"
SECONDS_IN_ONE_HOUR = 60 * 60


class TestJuju2(unittest.TestCase):
    def setUp(self):
        self.relation_name = "certificates"
        self.remote_app = "tls-certificates-provider"
        self.harness = testing.Harness(DummyTLSCertificatesRequirerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def create_certificates_relation(self) -> int:
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=self.remote_app
        )
        return relation_id

    def test_given_no_relation_when_request_certificate_creation_then_runtime_error_is_raised(
        self,
    ):
        with pytest.raises(RuntimeError):
            self.harness.charm.certificates.request_certificate_creation(
                certificate_signing_request=b"whatever csr"
            )

    def test_given_csr_when_request_certificate_creation_then_csr_is_sent_in_relation_data(self):
        relation_id = self.create_certificates_relation()
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatver subject",
        )

        self.harness.charm.certificates.request_certificate_creation(
            certificate_signing_request=csr
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        assert json.loads(unit_relation_data["certificate_signing_requests"]) == [
            {"certificate_signing_request": csr.decode().strip(), "ca": False}
        ]

    def test_given_relation_data_already_contains_csr_when_request_certificate_creation_then_csr_is_not_sent_again(  # noqa: E501
        self,
    ):
        relation_id = self.create_certificates_relation()
        common_name = "whatever common name"
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name=common_name,
        )
        key_values = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": csr.decode().strip(), "ca": False}]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=key_values,
        )

        self.harness.charm.certificates.request_certificate_creation(
            certificate_signing_request=csr
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        assert json.loads(unit_relation_data["certificate_signing_requests"]) == [
            {"certificate_signing_request": csr.decode().strip(), "ca": False}
        ]

    def test_given_different_csr_in_relation_data_when_request_certificate_creation_then_new_csr_is_added(  # noqa: E501
        self,
    ):
        relation_id = self.create_certificates_relation()
        initial_common_name = "whatever initial common name"
        new_common_name = "whatever new common name"
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        initial_csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name=initial_common_name,
        )
        new_csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name=new_common_name,
        )
        key_values = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": initial_csr.decode().strip(), "ca": False}]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=key_values,
        )

        self.harness.charm.certificates.request_certificate_creation(
            certificate_signing_request=new_csr
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        expected_client_cert_requests = [
            {"certificate_signing_request": initial_csr.decode().strip(), "ca": False},
            {"certificate_signing_request": new_csr.decode().strip(), "ca": False},
        ]
        self.assertEqual(
            expected_client_cert_requests,
            json.loads(unit_relation_data["certificate_signing_requests"]),
        )

    def test_given_wants_ca_when_request_certificate_creation_then_csr_and_ca_are_set_in_relation_data(
        self,
    ):
        relation_id = self.create_certificates_relation()
        private_key_password = b"whatever"
        private_key = generate_private_key_helper(password=private_key_password)
        csr = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever.com",
        )

        self.harness.charm.certificates.request_certificate_creation(
            certificate_signing_request=csr,
            is_ca=True,
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        assert json.loads(unit_relation_data["certificate_signing_requests"]) == [
            {"certificate_signing_request": csr.decode().strip(), "ca": True}
        ]

    def test_given_no_relation_when_request_certificate_revocation_then_runtime_error_is_raised(
        self,
    ):
        with pytest.raises(RuntimeError):
            self.harness.charm.certificates.request_certificate_revocation(
                certificate_signing_request=b"whatever csr"
            )

    def test_given_csr_when_request_certificate_revocation_then_csr_is_removed_from_relation_data(
        self,
    ):
        relation_id = self.create_certificates_relation()
        certificate_signing_request = b"whatever csr"
        key_values = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": certificate_signing_request.decode()}]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=key_values,
        )

        self.harness.charm.certificates.request_certificate_revocation(
            certificate_signing_request=certificate_signing_request
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        self.assertEqual({"certificate_signing_requests": "[]"}, unit_relation_data)

    def test_given_no_csr_in_relation_data_when_request_certificate_revocation_then_nothing_is_done(
        self,
    ):
        relation_id = self.create_certificates_relation()
        certificate_signing_request = b"whatever csr"

        self.harness.update_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit.name, key_values={}
        )

        self.harness.charm.certificates.request_certificate_revocation(
            certificate_signing_request=certificate_signing_request
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        self.assertEqual(dict(), unit_relation_data)

    @patch(f"{LIB_DIR}.TLSCertificatesRequiresV2.request_certificate_creation")
    @patch(f"{LIB_DIR}.TLSCertificatesRequiresV2.request_certificate_revocation")
    def test_given_certificate_revocation_success_when_request_certificate_renewal_then_certificate_creation_is_called(  # noqa: E501
        self, _, patch_certificate_creation
    ):
        old_csr = b"whatever old csr"
        new_csr = b"whatever new csr"

        self.harness.charm.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

        patch_certificate_creation.assert_called_with(certificate_signing_request=new_csr)

    @patch(f"{LIB_DIR}.TLSCertificatesRequiresV2.request_certificate_creation")
    @patch(f"{LIB_DIR}.TLSCertificatesRequiresV2.request_certificate_revocation")
    def test_given_certificate_revocation_failed_when_request_certificate_renewal_then_certificate_creation_is_called_anyway(  # noqa: E501
        self, patch_certificate_revocation, patch_certificate_creation
    ):
        old_csr = b"whatever old csr"
        new_csr = b"whatever new csr"
        patch_certificate_revocation.side_effect = RuntimeError()

        self.harness.charm.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

        patch_certificate_creation.assert_called_with(certificate_signing_request=new_csr)

    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_when_relation_changed_then_certificate_available_event_emitted(  # noqa: E501
        self, patch_on_certificate_available
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_available.assert_called()
        args, _ = patch_on_certificate_available.call_args
        certificate_available_event = args[0]
        assert certificate_available_event.certificate == certificate
        assert certificate_available_event.certificate_signing_request == csr
        assert certificate_available_event.ca == ca_certificate
        assert certificate_available_event.chain == chain

    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_no_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_when_relation_changed_then_certificate_available_event_not_emitted(  # noqa: E501
        self, patch_on_certificate_available
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_available.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_badly_formatted_when_relation_changed_then_certificate_available_event_not_emitted(  # noqa: E501
        self, patch_on_certificate_available
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate": certificate,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_available.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_expired_certificate_in_relation_data_when_update_status_then_certificate_invalidated_event_with_reason_expired_emitted(  # noqa: E501
        self, patch_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        hours_before_expiry = -1
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever",
        )

        ca_certificate = generate_ca_helper(
            private_key=ca_key,
            private_key_password=ca_private_key_password,
            common_name="whatever",
        )

        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate.decode(),
                        "chain": ["a", "b"],
                        "certificate_signing_request": certificate_signing_request.decode(),
                        "certificate": certificate.decode(),
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_invalidated.assert_called()
        args, _ = patch_certificate_invalidated.call_args
        event_data = args[0]
        assert event_data.certificate == certificate.decode()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_certificate_in_relation_data_is_not_expired_when_update_status_then_certificate_invalidated_event_with_reason_expired_not_emitted(  # noqa: E501
        self, patch_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        hours_before_expiry = 100
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever",
        )

        ca_certificate = generate_ca_helper(
            private_key=ca_key,
            private_key_password=ca_private_key_password,
            common_name="whatever",
        )

        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate.decode(),
                        "chain": ["a", "b"],
                        "certificate_signing_request": certificate_signing_request.decode(),
                        "certificate": certificate.decode(),
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_invalidated.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    def test_given_certificate_expires_in_shorter_amount_of_time_than_expiry_notification_time_when_update_status_then_certificate_expiring_is_emitted(  # noqa: E501
        self, patch_certificate_expiring
    ):
        relation_id = self.create_certificates_relation()
        hours_before_expiry = 8
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever",
        )

        ca_certificate = generate_ca_helper(
            private_key=ca_key,
            private_key_password=ca_private_key_password,
            common_name="whatever",
        )

        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate.decode(),
                        "chain": ["a", "b"],
                        "certificate_signing_request": certificate_signing_request.decode(),
                        "certificate": certificate.decode(),
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_expiring.assert_called()
        args, _ = patch_certificate_expiring.call_args
        event_data = args[0]
        assert event_data.certificate == certificate.decode()
        time_difference = datetime.fromisoformat(event_data.expiry) - datetime.utcnow()
        assert (
            (hours_before_expiry * SECONDS_IN_ONE_HOUR) - 60
            <= time_difference.seconds
            <= hours_before_expiry * SECONDS_IN_ONE_HOUR
        )

    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    def test_given_certificate_expires_in_longer_amount_of_time_than_expiry_notification_time_when_update_status_then_certificate_expiring_is_not_emitted(  # noqa: E501
        self, patch_certificate_expiring
    ):
        relation_id = self.create_certificates_relation()
        hours_before_expiry = 200
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever",
        )

        ca_certificate = generate_ca_helper(
            private_key=ca_key,
            private_key_password=ca_private_key_password,
            common_name="whatever",
        )

        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate.decode(),
                        "chain": ["a", "b"],
                        "certificate_signing_request": certificate_signing_request.decode(),
                        "certificate": certificate.decode(),
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_expiring.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_no_certificate_in_relation_data_when_update_status_then_no_event_emitted(  # noqa: E501
        self, patch_certificate_invalidated, patch_certificate_expiring
    ):
        relation_id = self.create_certificates_relation()
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values={},
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_invalidated.assert_not_called()
        patch_certificate_expiring.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_csr_in_unit_relation_data_and_certificate_revoked_in_remote_relation_data_when_relation_changed_then_certificate_invalidated_event_with_reason_revoked_emitted(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": True,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_invalidated.assert_called()
        args, _ = patch_on_certificate_invalidated.call_args
        certificate_invalidated_event = args[0]
        assert certificate_invalidated_event.certificate == certificate
        assert certificate_invalidated_event.certificate_signing_request == csr
        assert certificate_invalidated_event.ca == ca_certificate
        assert certificate_invalidated_event.chain == chain

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_no_csr_in_unit_relation_data_and_certificate_revoked_in_remote_relation_data_when_relation_changed_then_certificate_invalidated_event_not_emitted(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": True,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_invalidated.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_csr_in_unit_relation_data_and_certificate_revoked_in_remote_relation_data_badly_formatted_when_relation_changed_then_certificate_invalidated_event_not_emitted(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate": certificate,
                        "revoked": True,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_invalidated.assert_not_called()

    @patch(f"{BASE_CHARM_DIR}._on_all_certificates_invalidated")
    def test_given_certificate_in_relation_data_when_relation_broken_then_all_certificates_invalidated_event_is_emitted(  # noqa: E501
        self, patch_on_all_certificates_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": False,
                    }
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        self.harness.remove_relation(relation_id)

        patch_on_all_certificates_invalidated.assert_called()

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_certificate_in_relation_data_when_certificate_invalidated_event_with_no_certificate_emitted_then_type_error_is_raised(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": False,
                    }
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        with pytest.raises(TypeError):
            self.harness.charm.certificates.on.certificate_invalidated.emit(
                reason="expired", certificate_signing_request=csr, ca=ca_certificate, chain=chain
            )

    @patch(f"{BASE_CHARM_DIR}._on_all_certificates_invalidated")
    def test_given_no_certificates_in_relation_data_when_relation_broken_then_all_certificates_invalidated_event_emitted(  # noqa: E501
        self, patch_on_all_certificates_invalidated
    ):
        relation_id = self.create_certificates_relation()

        self.harness.remove_relation(relation_id)

        patch_on_all_certificates_invalidated.assert_called()


class FakeJujuVersion:
    @classmethod
    def from_environ(cls):
        return cls()

    @property
    def has_secrets(self):
        return True


@patch(f"{LIB_DIR}.JujuVersion", new=FakeJujuVersion)
class TestJuju3(unittest.TestCase):
    # The following patch is required because the one on the class will
    # only apply to test cases.
    # See: https://docs.python.org/3/library/unittest.mock.html#patch
    @patch(f"{LIB_DIR}.JujuVersion", new=FakeJujuVersion)
    def setUp(self):
        self.relation_name = "certificates"
        self.remote_app = "tls-certificates-provider"
        self.harness = testing.Harness(DummyTLSCertificatesRequirerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def create_certificates_relation(self) -> int:
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=self.remote_app
        )
        return relation_id

    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    def test_given_certificate_expires_in_shorter_amount_of_time_than_expiry_notification_time_and_juju_secrets_are_available_when_update_status_then_certificate_expiring_is_not_emitted(  # noqa: E501
        self, patch_certificate_expiring
    ):
        relation_id = self.create_certificates_relation()
        hours_before_expiry = 8
        private_key_password = b"whatever1"
        ca_private_key_password = b"whatever2"
        private_key = generate_private_key_helper(password=private_key_password)
        ca_key = generate_private_key_helper(password=ca_private_key_password)
        certificate_signing_request = generate_csr_helper(
            private_key=private_key,
            private_key_password=private_key_password,
            common_name="whatever",
        )

        ca_certificate = generate_ca_helper(
            private_key=ca_key,
            private_key_password=ca_private_key_password,
            common_name="whatever",
        )

        certificate = generate_certificate_helper(
            ca=ca_certificate,
            ca_key=ca_key,
            csr=certificate_signing_request,
            ca_key_password=ca_private_key_password,
            validity=hours_before_expiry,
        )

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate.decode(),
                        "chain": ["a", "b"],
                        "certificate_signing_request": certificate_signing_request.decode(),
                        "certificate": certificate.decode(),
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        self.harness.charm.on.update_status.emit()

        patch_certificate_expiring.assert_not_called()

    def test_given_csr_when_request_certificate_revocation_then_csr_is_removed_from_relation_data(
        self,
    ):
        relation_id = self.create_certificates_relation()
        certificate_signing_request = b"whatever csr"
        key_values = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": certificate_signing_request.decode()}]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=key_values,
        )

        self.harness.charm.certificates.request_certificate_revocation(
            certificate_signing_request=certificate_signing_request
        )

        unit_relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )

        self.assertEqual({"certificate_signing_requests": "[]"}, unit_relation_data)

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_csr_in_unit_relation_data_and_certificate_revoked_in_remote_relation_data_and_secret_exists_when_relation_changed_then_secret_revisions_are_removed(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": True,
                    }
                ]
            )
        }
        secret_id = self.harness.add_model_secret(
            owner=self.harness.model.unit.name, content={"certificate": "old data"}
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=f"{LIBID}-{csr}")

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        with pytest.raises(RuntimeError):
            self.harness.get_secret_revisions(secret_id)

    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_csr_in_unit_relation_data_and_certificate_revoked_in_remote_relation_data_when_relation_changed_then_certificate_invalidated_event_with_reason_revoked_emitted(  # noqa: E501
        self, patch_on_certificate_invalidated
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                        "revoked": True,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_invalidated.assert_called()
        args, _ = patch_on_certificate_invalidated.call_args
        certificate_invalidated_event = args[0]
        assert certificate_invalidated_event.certificate == certificate
        assert certificate_invalidated_event.certificate_signing_request == csr
        assert certificate_invalidated_event.ca == ca_certificate
        assert certificate_invalidated_event.chain == chain

    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_when_relation_changed_then_certificate_available_event_emitted(  # noqa: E501
        self, patch_on_certificate_available
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    }
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        patch_on_certificate_available.assert_called()
        args, _ = patch_on_certificate_available.call_args
        certificate_available_event = args[0]
        assert certificate_available_event.certificate == certificate
        assert certificate_available_event.certificate_signing_request == csr
        assert certificate_available_event.ca == ca_certificate
        assert certificate_available_event.chain == chain

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_when_relation_changed_then_secret_is_added(  # noqa: E501
        self, patch_on_certificate_available, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    }
                ]
            )
        }
        expiry_time = datetime.utcnow() + timedelta(days=30)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")
        assert secret.get_content()["certificate"] == certificate
        assert secret.get_info().expires == expiry_time - timedelta(hours=168)

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_available")
    def test_given_csr_in_unit_relation_data_and_certificate_in_remote_relation_data_and_secret_already_exists_when_relation_changed_then_secret_is_updated(  # noqa: E501
        self, patch_on_certificate_available, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    }
                ]
            )
        }
        secret_id = self.harness.add_model_secret(
            owner=self.harness.model.unit.name, content={"certificate": "old data"}
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=f"{LIBID}-{csr}")
        expiry_time = datetime.utcnow() + timedelta(days=30)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")
        assert secret.get_content(refresh=True)["certificate"] == certificate
        assert secret.get_info().expires == expiry_time - timedelta(hours=168)

    def test_given_certificates_available_when_get_assigned_certificates_then_unit_certificates_returned_only(
        self,
    ):  # noqa: E501
        relation_id = self.create_certificates_relation()

        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": "csr1"}])
        }

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert2",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        assert len(self.harness.charm.certificates.get_assigned_certificates()) == 1

    def test_given_certificates_available_when_get_assigned_certificates_with_no_csrs_then_no_certificates_returned(
        self,
    ):  # noqa: E501
        relation_id = self.create_certificates_relation()

        unit_relation_data = {"certificate_signing_requests": json.dumps([])}

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert2",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        assert len(self.harness.charm.certificates.get_assigned_certificates()) == 0

    def test_given_csrs_created_when_get_certificate_signing_requests_then_all_csrs_returned(self):
        relation_id = self.create_certificates_relation()

        unit_relation_data = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": "csr1"}, {"certificate_signing_request": "csr3"}]
            )
        }

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert1",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        assert len(self.harness.charm.certificates.get_certificate_signing_requests()) == 2

    def test_given_csrs_created_when_get_fulfilled_csrs_only_then_correct_csrs_returned(self):
        relation_id = self.create_certificates_relation()

        unit_relation_data = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": "csr1"}, {"certificate_signing_request": "csr3"}]
            )
        }

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert1",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        output = self.harness.charm.certificates.get_certificate_signing_requests(
            fulfilled_only=True
        )
        assert len(output) == 1
        assert output[0]["certificate_signing_request"] == "csr1"

    def test_given_csrs_created_when_get_unfulfilled_csrs_only_then_correct_csrs_returned(self):
        relation_id = self.create_certificates_relation()

        unit_relation_data = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": "csr1"}, {"certificate_signing_request": "csr3"}]
            )
        }

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert1",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        output = self.harness.charm.certificates.get_certificate_signing_requests(
            unfulfilled_only=True
        )
        assert len(output) == 1
        assert output[0]["certificate_signing_request"] == "csr3"

    def test_given_csrs_created_when_get_unfulfilled_and_fulfilled_csrs_only_then_no_csrs_returned(
        self,
    ):
        relation_id = self.create_certificates_relation()

        unit_relation_data = {
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": "csr1"}, {"certificate_signing_request": "csr3"}]
            )
        }

        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": "cacert1",
                        "chain": ["cert1"],
                        "certificate_signing_request": "csr1",
                        "certificate": "cert1",
                    },
                    {
                        "ca": "cacert1",
                        "chain": ["cert2"],
                        "certificate_signing_request": "csr2",
                        "certificate": "cert2",
                    },
                ]
            )
        }

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )

        output = self.harness.charm.certificates.get_certificate_signing_requests(
            fulfilled_only=True, unfulfilled_only=True
        )
        assert len(output) == 0

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_expired_certificate_in_relation_data_when_secret_expired_then_certificate_invalidated_event_with_reason_expired_emitted(  # noqa: E501
        self, patch_certificate_invalidated, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        expiry_time = datetime.utcnow() - timedelta(seconds=10)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")

        self.harness.trigger_secret_expiration(secret.get_info().id, 0)

        patch_certificate_invalidated.assert_called()
        args, _ = patch_certificate_invalidated.call_args
        event_data = args[0]
        assert event_data.certificate == certificate

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_expired_certificate_and_other_certificates_in_relation_data_when_secret_expired_then_certificate_invalidated_event_with_reason_expired_emitted_once(  # noqa: E501
        self, patch_certificate_invalidated, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": f"{csr}2",
                        "certificate": certificate,
                    },
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        expiry_time = datetime.utcnow() - timedelta(seconds=10)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")

        self.harness.trigger_secret_expiration(secret.get_info().id, 0)

        patch_certificate_invalidated.assert_called_once()
        args, _ = patch_certificate_invalidated.call_args
        event_data = args[0]
        assert event_data.certificate == certificate

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_invalidated")
    def test_given_expired_certificate_in_relation_data_when_secret_expired_then_secret_revisions_are_removed(  # noqa: E501
        self, patch_certificate_invalidated, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        expiry_time = datetime.utcnow() - timedelta(seconds=10)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")
        secret_id = secret.get_info().id

        self.harness.trigger_secret_expiration(secret_id, 0)

        with pytest.raises(RuntimeError):
            self.harness.get_secret_revisions(secret_id)

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    def test_given_almost_expiring_certificate_in_relation_data_when_secret_expired_then_certificate_expiring_event_emitted(  # noqa: E501
        self, patch_certificate_expiring, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        expiry_time = datetime.utcnow() + timedelta(days=8)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")

        self.harness.trigger_secret_expiration(secret.get_info().id, 0)

        patch_certificate_expiring.assert_called()
        args, _ = patch_certificate_expiring.call_args
        event_data = args[0]
        assert event_data.certificate == certificate

    @patch(f"{LIB_DIR}._get_certificate_expiry_time")
    @patch(f"{BASE_CHARM_DIR}._on_certificate_expiring")
    def test_given_almost_expiring_certificate_in_relation_data_when_secret_expired_then_secret_expiry_is_set_to_certificate_expiry(  # noqa: E501
        self, patch_certificate_expiring, patch_get_expiry_time
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        expiry_time = datetime.utcnow() + timedelta(days=8)
        patch_get_expiry_time.return_value = expiry_time
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret = self.harness.model.get_secret(label=f"{LIBID}-{csr}")

        self.harness.trigger_secret_expiration(secret.get_info().id, 0)

        assert secret.get_info().expires == expiry_time

    def test_given_secret_not_owner_by_lib_when_secret_expired_then_secret_revisions_are_not_removed(  # noqa: E501
        self,
    ):
        secret_id = self.harness.add_model_secret(
            owner=self.harness.charm.unit.name, content={"meal": "brisket"}
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label="not our stuff")

        self.harness.trigger_secret_expiration(secret_id, 0)

        assert self.harness.get_secret_revisions(secret_id)

    def test_given_certificate_not_found_in_relation_data_when_secret_expired_then_secret_revisions_are_removed(  # noqa: E501
        self,
    ):
        secret_id = self.harness.add_model_secret(
            owner=self.harness.charm.unit.name, content={"certificate": "brisket"}
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=f"{LIBID}-brisket")
        secret_id = secret.get_info().id

        self.harness.trigger_secret_expiration(secret_id, 0)

        with pytest.raises(RuntimeError):
            self.harness.get_secret_revisions(secret_id)

    def test_given_certificate_invalid_in_relation_data_when_secret_expired_then_secret_revisions_are_removed(  # noqa: E501
        self,
    ):
        relation_id = self.create_certificates_relation()
        ca_certificate = "whatever certificate"
        chain = ["certificate 1", "certiicate 2", "certificate 3"]
        csr = "whatever csr"
        certificate = "whatever certificate"
        unit_relation_data = {
            "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values=unit_relation_data,
        )
        remote_app_relation_data = {
            "certificates": json.dumps(
                [
                    {
                        "ca": ca_certificate,
                        "chain": chain,
                        "certificate_signing_request": csr,
                        "certificate": certificate,
                    },
                ]
            )
        }
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.remote_app,
            key_values=remote_app_relation_data,
        )
        secret_id = self.harness.add_model_secret(
            owner=self.harness.charm.unit.name, content={"certificate": certificate}
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=f"{LIBID}-{csr}")
        secret_id = secret.get_info().id

        self.harness.trigger_secret_expiration(secret_id, 0)

        with pytest.raises(RuntimeError):
            self.harness.get_secret_revisions(secret_id)
