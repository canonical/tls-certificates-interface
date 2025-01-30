# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime
import json
from pathlib import Path
from typing import Iterable
from unittest.mock import MagicMock, patch

import ops
import pytest
import scenario
import yaml
from cryptography.hazmat.primitives import hashes
from scenario import Secret

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateAvailableEvent,
    CertificateSigningRequest,
    Mode,
)
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


def get_sha256_hex(data: str) -> str:
    """Calculate the hash of the provided data and return the hexadecimal representation."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize().hex()


class TestTLSCertificatesRequiresV4:
    def private_key_secret_exists(self, secrets: Iterable[Secret]) -> bool:
        return any(secret.label == f"{LIBID}-private-key-0" for secret in secrets)

    def certificate_secret_exists(self, secrets: Iterable[Secret]) -> bool:
        return any(
            secret.label.startswith(f"{LIBID}-certificate") for secret in secrets if secret.label
        )

    def get_certificate_secret(self, secrets: Iterable[Secret]) -> Secret:
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
            relations={certificates_relation},
            config={"common_name": "example.com"},
        )

        state_out = self.ctx.run(self.ctx.on.relation_created(certificates_relation), state_in)

        assert self.private_key_secret_exists(state_out.secrets)

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_certificate_requested_when_relation_joined_then_certificate_request_is_added_to_unit_databag(  # noqa: E501
        self, mock_generate_csr: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        mock_generate_csr.return_value = csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )
        state_in = scenario.State(
            relations={certificates_relation},
            config={
                "common_name": "example.com",
                "is_ca": False,
            },
            secrets=[
                Secret(
                    {"private-key": private_key},
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                )
            ],
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                ),
            }
        )

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    @patch(BASE_CHARM_DIR + "._app_or_unit", MagicMock(return_value=Mode.APP))
    def test_given_certificate_requested_in_app_mode_when_relation_joined_then_certificate_request_is_added_to_app_databag(  # noqa: E501
        self, mock_generate_csr: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        mock_generate_csr.return_value = csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )
        state_in = scenario.State(
            leader=True,
            relations={certificates_relation},
            config={
                "common_name": "example.com",
                "is_ca": False,
            },
            secrets=[
                Secret(
                    {"private-key": private_key},
                    label=f"{LIBID}-private-key",
                    owner="unit",
                )
            ],
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)
        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_app_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                ),
            }
        )

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_ca_certificate_requested_when_relation_joined_then_certificate_request_is_added_to_databag(  # noqa: E501
        self, mock_generate_csr: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        mock_generate_csr.return_value = csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )
        state_in = scenario.State(
            relations={certificates_relation},
            config={
                "common_name": "example.com",
                "is_ca": True,
            },
            secrets={
                Secret(
                    {"private-key": private_key},
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                )
            },
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": csr,
                                    "ca": True,
                                }
                            ]
                        )
                    },
                ),
            }
        )

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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": requirer_private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )
        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret},
        )

        self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], CertificateAvailableEvent)
        assert self.ctx.emitted_events[1].certificate == Certificate.from_string(certificate)
        assert self.ctx.emitted_events[1].ca == Certificate.from_string(provider_ca_certificate)
        assert self.ctx.emitted_events[
            1
        ].certificate_signing_request == CertificateSigningRequest.from_string(csr)

    def test_given_ca_certificate_in_provider_relation_data_when_relation_changed_then_certificate_available_event_is_emitted(  # noqa: E501
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
            is_ca=True,
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                            "ca": True,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": requirer_private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )
        state_in = scenario.State(
            relations=[certificates_relation],
            config={
                "common_name": "example.com",
                "is_ca": True,
            },
            secrets={private_key_secret},
        )

        self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], CertificateAvailableEvent)
        assert self.ctx.emitted_events[1].certificate == Certificate.from_string(certificate)
        assert self.ctx.emitted_events[1].ca == Certificate.from_string(provider_ca_certificate)
        assert self.ctx.emitted_events[
            1
        ].certificate_signing_request == CertificateSigningRequest.from_string(csr)

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
                            "certificate": certificate,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
        )

        self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={},  # Note that there is no `common_name` in the config here
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={},
                ),
            }
        )

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_private_key_does_not_match_with_certificate_requests_when_relation_changed_then_certificate_request_is_replaced_in_databag(  # noqa: E501
        self, mock_generate_csr: MagicMock
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
                            "certificate_signing_request": csr,
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
        mock_generate_csr.return_value = new_csr

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={
                Secret(
                    {"private-key": new_private_key},
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                ),
            },
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": new_csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                ),
            }
        )

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_certificate_request_changed_when_relation_changed_then_new_certificate_is_requested(  # noqa: E501
        self, mock_generate_csr: MagicMock
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
        mock_generate_csr.return_value = new_csr
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr_in_relation_data,
                            "ca": False,
                        }
                    ]
                )
            },
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "new.example.com"},
            secrets={
                Secret(
                    {"private-key": private_key},
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                )
            },
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": new_csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                ),
            }
        )

    def test_given_revoked_certificate_when_relation_changed_then_certificate_secret_is_removed(
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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                            "revoked": True,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": requirer_private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        certificate_secret = Secret(
            {
                "certificate": certificate,
                "csr": csr,
            },
            label=f"{LIBID}-certificate-0-{get_sha256_hex(csr)}",
            owner="unit",
        )
        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={
                private_key_secret,
                certificate_secret,
            },
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert state_out.secrets == frozenset(
            {
                private_key_secret,
            }
        )

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
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={
                Secret(
                    {"private-key": initial_private_key},
                    label=f"{LIBID}-private-key-0",
                    owner="unit",
                )
            },
        )

        state_out = self.ctx.run(self.ctx.on.action("regenerate-private-key"), state_in)

        secret = state_out.get_secret(label=f"{LIBID}-private-key-0")
        assert secret.latest_content is not None
        assert secret.latest_content["private-key"] != initial_private_key

    def test_given_certificate_is_provided_when_get_certificate_then_certificate_is_returned(self):
        private_key = generate_private_key()
        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )
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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret},
        )

        self.ctx.run(self.ctx.on.action("get-certificate"), state_in)

        assert self.ctx.action_results == {
            "certificate": certificate,
            "ca": provider_ca_certificate,
            "csr": csr,
        }

    def test_given_provided_certificate_does_not_match_private_key_when_get_certificate_then_certificate_is_not_returned(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        bad_private_key = generate_private_key()
        bad_csr = generate_csr(
            private_key=bad_private_key,
            common_name="example.com",
        )
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        bad_certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=bad_csr,
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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": bad_certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret},
        )

        with pytest.raises(ops._private.harness.ActionFailed):  # type: ignore[reportAttributeAccessIssue]
            self.ctx.run(self.ctx.on.action("get-certificate"), state_in)

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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret},
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert self.certificate_secret_exists(state_out.secrets)

    def test_given_certificate_secret_exists_and_certificate_is_provided_when_relation_changed_then_certificate_secret_is_updated(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )

        initial_certificate_secret = Secret(
            {
                "certificate": "initial certificate",
                "csr": csr,
            },
            label=f"{LIBID}-certificate-0-{get_sha256_hex(csr)}",
            owner="unit",
        )

        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        new_certificate = generate_certificate(
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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": new_certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret, initial_certificate_secret},
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert self.certificate_secret_exists(state_out.secrets)

        certificate_secret = self.get_certificate_secret(state_out.secrets)

        assert certificate_secret.latest_content == {
            "certificate": new_certificate,
            "csr": csr,
        }

    def test_given_certificate_secret_exists_and_certificate_unchanged_when_relation_changed_then_certificate_secret_is_not_updated(  # noqa: E501
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
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        certificate_secret = Secret(
            {
                "certificate": certificate,
                "csr": csr,
            },
            label=f"{LIBID}-certificate-0-{get_sha256_hex(csr)}",
            owner="unit",
        )
        state_in = scenario.State(
            relations={certificates_relation},
            config={"common_name": "example.com"},
            secrets={private_key_secret, certificate_secret},
        )

        state_out = self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

        assert self.certificate_secret_exists(state_out.secrets)

        certificate_secret = self.get_certificate_secret(state_out.secrets)

        assert certificate_secret._latest_revision == 1

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_certificate_when_certificate_secret_expires_then_new_certificate_is_requested(  # noqa: E501
        self, mock_generate_csr: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        csr_in_sha256_hex = get_sha256_hex(csr)
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=csr,
            ca=provider_ca_certificate,
            validity=datetime.timedelta(hours=1),
        )

        new_csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        assert csr != new_csr
        mock_generate_csr.return_value = new_csr

        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        certificate_secret = Secret(
            {
                "certificate": certificate,
                "csr": csr,
            },
            label=f"{LIBID}-certificate-0-{csr_in_sha256_hex}",
            owner="unit",
            expire=datetime.datetime.now() - datetime.timedelta(minutes=1),
        )

        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            config={"common_name": "example.com"},
            relations={certificates_relation},
            secrets={
                private_key_secret,
                certificate_secret,
            },
        )

        state_out = self.ctx.run(
            self.ctx.on.secret_expired(certificate_secret, revision=1), state_in
        )

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": new_csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                    remote_app_data={
                        "certificates": json.dumps(
                            [
                                {
                                    "certificate": certificate,
                                    "certificate_signing_request": csr,
                                    "ca": provider_ca_certificate,
                                }
                            ]
                        ),
                    },
                )
            }
        )

    @patch(LIB_DIR + ".CertificateRequestAttributes.generate_csr")
    def test_given_certificate_when_renew_certificate_then_new_certificate_is_requested(
        self, mock_generate_csr: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        csr_in_sha256_hex = get_sha256_hex(csr)
        provider_private_key = generate_private_key()
        provider_ca_certificate = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        certificate = generate_certificate(
            ca_key=provider_private_key,
            csr=csr,
            ca=provider_ca_certificate,
            validity=datetime.timedelta(hours=1),
        )

        new_csr = generate_csr(
            private_key=private_key,
            common_name="example.com",
        )
        assert csr != new_csr
        mock_generate_csr.return_value = new_csr

        private_key_secret = Secret(
            {"private-key": private_key},
            label=f"{LIBID}-private-key-0",
            owner="unit",
        )

        certificate_secret = Secret(
            {
                "certificate": certificate,
                "csr": csr,
            },
            label=f"{LIBID}-certificate-0-{csr_in_sha256_hex}",
            owner="unit",
            expire=datetime.datetime.now() - datetime.timedelta(minutes=1),
        )

        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [
                        {
                            "certificate_signing_request": csr,
                            "ca": False,
                        }
                    ]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": provider_ca_certificate,
                        }
                    ]
                ),
            },
        )

        state_in = scenario.State(
            config={"common_name": "example.com"},
            relations={certificates_relation},
            secrets={
                private_key_secret,
                certificate_secret,
            },
        )

        state_out = self.ctx.run(self.ctx.on.action("renew-certificates"), state_in)

        assert state_out.relations == frozenset(
            {
                scenario.Relation(
                    id=certificates_relation.id,
                    endpoint="certificates",
                    interface="tls-certificates",
                    remote_app_name="certificate-requirer",
                    local_unit_data={
                        "certificate_signing_requests": json.dumps(
                            [
                                {
                                    "certificate_signing_request": new_csr,
                                    "ca": False,
                                }
                            ]
                        )
                    },
                    remote_app_data={
                        "certificates": json.dumps(
                            [
                                {
                                    "certificate": certificate,
                                    "certificate_signing_request": csr,
                                    "ca": provider_ca_certificate,
                                }
                            ]
                        ),
                    },
                )
            }
        )
