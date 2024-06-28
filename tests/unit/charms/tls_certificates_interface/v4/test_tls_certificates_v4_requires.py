# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import json
from unittest.mock import patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    get_sha256_hex as get_sha256_hex,
)
from ops import testing

from tests.unit.charms.tls_certificates_interface.v4.certificates import (
    csrs_match,
    generate_csr,
    generate_private_key,
    private_key_is_valid,
)
from tests.unit.charms.tls_certificates_interface.v4.dummy_requirer_charm.src.charm import (
    DummyTLSCertificatesRequirerCharm,
)

LIB_DIR = "lib.charms.tls_certificates_interface.v4.tls_certificates"
LIBID = "afd8c2bccf834997afce12c2706d2ede"


class TestTLSCertificatesRequiresV4:
    patcher_generate_csr = patch(LIB_DIR + ".generate_csr")

    @pytest.fixture()
    def setup(self):
        self.mock_generate_csr = TestTLSCertificatesRequiresV4.patcher_generate_csr.start()
        self.private_key = generate_private_key()
        self.csr = generate_csr(
            private_key=self.private_key,
            common_name="example.com",
        )
        self.mock_generate_csr.return_value = self.csr
        self.relation_name = "certificates"
        self.remote_app = "tls-certificates-provider"

    @pytest.fixture(autouse=True)
    def harnesser(self, setup, request):
        self.harness = testing.Harness(DummyTLSCertificatesRequirerCharm)

    def create_certificates_relation(self) -> int:
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app=self.remote_app
        )
        self.harness.add_relation_unit(relation_id, "tls-certificates-provider/0")
        return relation_id

    def test_given_private_key_not_created_when_certificates_relation_created_then_private_key_is_generated(  # noqa: E501
        self,
    ):
        self.harness.begin()

        self.create_certificates_relation()

        private_key_secret = self.harness.model.get_secret(label=f"{LIBID}-private-key-0")
        private_key_secret_content = private_key_secret.get_content()
        private_key = private_key_secret_content["private-key"]
        assert private_key_is_valid(private_key.encode())

    def test_given_certificate_requested_when_relation_joined_then_certificate_request_is_added_to_databag(  # noqa: E501
        self,
    ):
        self.harness.update_config(key_values={"common_name": "example.com"})
        self.harness.begin()

        relation_id = self.create_certificates_relation()

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.unit
        )
        requests = json.loads(relation_data["certificate_signing_requests"])
        assert len(requests) == 1
        assert not requests[0]["ca"]
        assert csrs_match(self.csr, requests[0]["certificate_signing_request"].encode())

    def test_given_certificate_in_provider_relation_data_when_relation_changed_then_certificate_available_event_is_emitted(  # noqa: E501
        self,
    ):
        pass

    def test_given_certificate_not_requested_when_relation_changed_then_certificate_is_removed_from_databag(  # noqa: E501
        self,
    ):
        pass
