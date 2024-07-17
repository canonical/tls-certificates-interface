# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest
import scenario
import yaml
from scenario.state import Secret

from lib.charms.tls_certificates_interface.v4.tls_certificates import CertificateAvailableEvent
from tests.unit.charms.tls_certificates_interface.v4.certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from tests.unit.charms.tls_certificates_interface.v4.dummy_requirer_charm.src.charm import (
    DummyTLSCertificatesRequirerCharm,
)

BASE_CHARM_DIR = "tests.unit.charms.tls_certificates_interface.v4.dummy_requirer_charm.src.charm.DummyTLSCertificatesRequirerCharm"  # noqa: E501
LIB_DIR = "lib.charms.tls_certificates_interface.v4.tls_certificates"
LIBID = "afd8c2bccf834997afce12c2706d2ede"
METADATA = yaml.safe_load(
    Path(
        "tests/unit/charms/tls_certificates_interface/v4/dummy_requirer_charm/charmcraft.yaml"  # noqa: E501
    ).read_text()
)


class TestTLSCertificatesRequiresV4:
    def private_key_secret_exists(self, secrets: List[Secret]) -> bool:
        return any(secret.label == f"{LIBID}-private-key-0" for secret in secrets)

    def certificate_secret_exists(self, secrets: List[Secret]) -> bool:
        return any(
            secret.label.startswith(f"{LIBID}-certificate") for secret in secrets if secret.label
        )

    def get_private_key_secret(self, secrets: List[Secret]) -> Secret:
        return next(secret for secret in secrets if secret.label == f"{LIBID}-private-key-0")

    def get_certificate_secret(self, secrets: List[Secret]) -> Secret:
        return next(
            secret
            for secret in secrets
            if secret.label and secret.label.startswith(f"{LIBID}-certificate")
        )

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=DummyTLSCertificatesRequirerCharm,
            meta=METADATA,
            config=METADATA["config"],
            actions=METADATA["actions"],
        )

    def test_given_private_key_not_created_when_certificates_relation_created_then_private_key_is_generated(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )
        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        state_out = self.ctx.run(certificates_relation.created_event, state_in)

        assert self.private_key_secret_exists(state_out.secrets)

    @patch(LIB_DIR + ".generate_csr")
    def test_given_certificate_requested_when_relation_joined_then_certificate_request_is_added_to_databag(  # noqa: E501
        self, patch_generate_csr
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        patch_generate_csr.return_value = csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )
        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
            secrets=[
                Secret(
                    id="1",
                    revision=0,
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                    contents={0: {"private-key": private_key.decode()}},
                )
            ],
        )

        state_out = self.ctx.run(certificates_relation.changed_event, state_in)

        assert state_out.relations == [
            scenario.Relation(
                relation_id=certificates_relation.relation_id,
                endpoint="certificates",
                interface="tls-certificates",
                remote_app_name="certificate-requirer",
                local_unit_data={
                    "certificate_signing_requests": json.dumps(
                        [
                            {
                                "certificate_signing_request": csr.decode().strip(),
                                "ca": False,
                            }
                        ]
                    )
                },
            ),
        ]

    def test_given_certificate_in_provider_relation_data_when_relation_changed_then_certificate_available_event_is_emitted(  # noqa: E501
        self,
    ):
        requirer_private_key = generate_private_key()
        csr = generate_csr(
            private_key=requirer_private_key,
            common_name="example.com",
        )
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=csr,
            ca=provider_ca_certificate,
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate.decode().strip(),
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": provider_ca_certificate.decode().strip(),
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        self.ctx.run(certificates_relation.changed_event, state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], CertificateAvailableEvent)
        assert self.ctx.emitted_events[1].certificate == certificate.decode().strip()
        assert self.ctx.emitted_events[1].ca == provider_ca_certificate.decode().strip()
        assert self.ctx.emitted_events[1].certificate_signing_request == csr.decode().strip()

    def test_given_no_request_and_certificate_in_provider_relation_data_when_relation_changed_then_certificate_available_event_is_not_emitted(  # noqa: E501
        self,
    ):
        requirer_private_key = generate_private_key()
        csr = generate_csr(
            private_key=requirer_private_key,
            common_name="example.com",
        )
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            ca=provider_ca_certificate,
            csr=csr,
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate.decode().strip(),
                            "ca": provider_ca_certificate.decode().strip(),
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        self.ctx.run(certificates_relation.changed_event, state_in)

        assert len(self.ctx.emitted_events) == 1

    def test_given_certificate_not_requested_when_relation_changed_then_certificate_request_is_removed_from_databag(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={},  # Note that there is no `common_name` in the config here
        )

        state_out = self.ctx.run(certificates_relation.changed_event, state_in)

        assert state_out.relations == [
            scenario.Relation(
                relation_id=certificates_relation.relation_id,
                endpoint="certificates",
                interface="tls-certificates",
                remote_app_name="certificate-requirer",
                local_unit_data={"certificate_signing_requests": "[]"},
            ),
        ]

    @patch(LIB_DIR + ".generate_csr")
    def test_given_private_key_does_not_match_with_certificate_requests_when_relation_changed_then_certificate_request_is_replaced_in_databag(  # noqa: E501
        self, patch_generate_csr
    ):
        initial_private_key = generate_private_key()
        csr = generate_csr(
            private_key=initial_private_key,
            common_name="example.com",
        )

        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
        )

        new_private_key = generate_private_key()

        new_csr = generate_csr(
            private_key=new_private_key,
            common_name="example.com",
        )
        patch_generate_csr.return_value = new_csr

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
            secrets=[
                Secret(
                    id="1",
                    revision=0,
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                    contents={0: {"private-key": new_private_key.decode()}},
                )
            ],
        )

        state_out = self.ctx.run(certificates_relation.changed_event, state_in)

        assert state_out.relations == [
            scenario.Relation(
                relation_id=certificates_relation.relation_id,
                endpoint="certificates",
                interface="tls-certificates",
                remote_app_name="certificate-requirer",
                local_unit_data={
                    "certificate_signing_requests": json.dumps(
                        [
                            {
                                "certificate_signing_request": new_csr.decode().strip(),
                                "ca": False,
                            }
                        ]
                    )
                },
            ),
        ]

    @patch(LIB_DIR + ".generate_csr")
    def test_given_certificate_request_changed_when_relation_changed_then_new_certificate_is_requested(  # noqa: E501
        self, patch_generate_csr
    ):
        private_key = generate_private_key()
        csr_in_relation_data = generate_csr(
            private_key=private_key,
            common_name="old.example.com",
        )
        new_csr = generate_csr(
            private_key=private_key,
            common_name="new.example.com",
        )
        patch_generate_csr.return_value = new_csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr_in_relation_data.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "new.example.com"},
            secrets=[
                Secret(
                    id="1",
                    revision=0,
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                    contents={0: {"private-key": private_key.decode()}},
                )
            ],
        )

        state_out = self.ctx.run(certificates_relation.changed_event, state_in)

        assert state_out.relations == [
            scenario.Relation(
                relation_id=certificates_relation.relation_id,
                endpoint="certificates",
                interface="tls-certificates",
                remote_app_name="certificate-requirer",
                local_unit_data={
                    "certificate_signing_requests": json.dumps(
                        [
                            {
                                "certificate_signing_request": new_csr.decode().strip(),
                                "ca": False,
                            }
                        ]
                    )
                },
            ),
        ]

    def test_given_private_key_generated_when_regenerate_private_key_then_new_private_key_is_generated(  # noqa: E501
        self,
    ):
        initial_private_key = "whatever the initial private key is"
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
            secrets=[
                Secret(
                    id="1",
                    revision=0,
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                    contents={0: {"private-key": initial_private_key}},
                )
            ],
        )

        action_output = self.ctx.run_action("regenerate-private-key", state_in)

        assert action_output.success is True
        secret = self.get_private_key_secret(action_output.state.secrets)
        assert secret.contents[1]["private-key"] != initial_private_key

    def test_given_certificate_requested_when_get_certificate_requests_then_certificate_request_is_returned(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
        )
        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        action_output = self.ctx.run_action("get-certificate-request", state_in)

        assert action_output.success is True
        assert action_output.results == {
            "csr": csr.decode().strip(),
            "is-ca": False,
        }

    def test_given_certificate_is_provided_when_get_certificate_then_certificate_is_returned(self):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=csr,
            ca=provider_ca_certificate,
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate.decode().strip(),
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": provider_ca_certificate.decode().strip(),
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        action_output = self.ctx.run_action("get-certificate", state_in)

        assert action_output.success is True
        assert action_output.results == {
            "certificate": certificate.decode().strip(),
            "ca": provider_ca_certificate.decode().strip(),
            "csr": csr.decode().strip(),
        }

    def test_given_certificate_is_provided_when_relation_changed_then_certificate_secret_is_created(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=csr,
            ca=provider_ca_certificate,
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate.decode().strip(),
                            "certificate_signing_request": csr.decode().strip(),
                            "ca": provider_ca_certificate.decode().strip(),
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations=[certificates_relation],
            config={"common_name": "example.com"},
        )

        state_out = self.ctx.run(certificates_relation.changed_event, state_in)

        assert self.certificate_secret_exists(state_out.secrets)

    def test_given_certificate_when_certificate_secret_expires_then_new_certificate_is_requested(  # noqa: E501
        self,
    ):
        # This test was not implemented because of this issue in the scenario library:
        # https://github.com/canonical/ops-scenario/issues/157
        pass
