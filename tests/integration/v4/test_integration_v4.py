#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import shutil
import time

from certificates import Certificate

logger = logging.getLogger(__name__)

LIB_DIR_V3 = "lib/charms/tls_certificates_interface/v3/tls_certificates.py"
LIB_DIR_V4 = "lib/charms/tls_certificates_interface/v4/tls_certificates.py"
REQUIRER_CHARM_DIR = "tests/integration/v4/requirer_charm"
PROVIDER_CHARM_DIR = "tests/integration/v4/provider_charm"
TLS_CERTIFICATES_PROVIDER_APP_NAME = "tls-certificates-provider"
TLS_CERTIFICATES_REQUIRER_APP_NAME = "tls-certificates-requirer"


def copy_lib_content() -> None:
    shutil.copyfile(src=LIB_DIR_V4, dst=f"{REQUIRER_CHARM_DIR}/{LIB_DIR_V4}")
    shutil.copyfile(src=LIB_DIR_V3, dst=f"{PROVIDER_CHARM_DIR}/{LIB_DIR_V3}")


class TestIntegration:
    requirer_charm = None
    provider_charm = None

    async def test_given_charms_packed_when_deploy_charm_then_status_is_blocked(self, ops_test):
        copy_lib_content()
        TestIntegration.requirer_charm = await ops_test.build_charm(f"{REQUIRER_CHARM_DIR}/")
        TestIntegration.provider_charm = await ops_test.build_charm(f"{PROVIDER_CHARM_DIR}/")
        await ops_test.model.deploy(
            TestIntegration.requirer_charm,
            application_name=TLS_CERTIFICATES_REQUIRER_APP_NAME,
            series="jammy",
        )
        await ops_test.model.deploy(
            TestIntegration.provider_charm,
            application_name=TLS_CERTIFICATES_PROVIDER_APP_NAME,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(
            apps=[TLS_CERTIFICATES_REQUIRER_APP_NAME, TLS_CERTIFICATES_PROVIDER_APP_NAME],
            status="blocked",
            timeout=1000,
        )

    async def test_given_charms_deployed_when_relate_then_status_is_active(self, ops_test):
        await ops_test.model.add_relation(
            relation1=TLS_CERTIFICATES_REQUIRER_APP_NAME,
            relation2=TLS_CERTIFICATES_PROVIDER_APP_NAME,
        )

        await ops_test.model.wait_for_idle(
            apps=[TLS_CERTIFICATES_REQUIRER_APP_NAME, TLS_CERTIFICATES_PROVIDER_APP_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_charms_deployed_when_relate_then_requirer_received_certs(self, ops_test):
        requirer_unit = ops_test.model.units[f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0"]

        action = await requirer_unit.run_action(action_name="get-certificate")

        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id, wait=60
        )
        assert action_output["return-code"] == 0
        assert "ca" in action_output and action_output["ca"] is not None
        assert "certificate" in action_output and action_output["certificate"] is not None
        assert "chain" in action_output and action_output["chain"] is not None

    async def test_given_additional_requirer_charm_deployed_when_relate_then_requirer_received_certs(  # noqa: E501
        self, ops_test
    ):
        new_requirer_app_name = "new-tls-requirer"
        await ops_test.model.deploy(
            TestIntegration.requirer_charm, application_name=new_requirer_app_name, series="jammy"
        )
        await ops_test.model.add_relation(
            relation1=new_requirer_app_name,
            relation2=TLS_CERTIFICATES_PROVIDER_APP_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[
                TLS_CERTIFICATES_PROVIDER_APP_NAME,
                new_requirer_app_name,
            ],
            status="active",
            timeout=1000,
        )
        requirer_unit = ops_test.model.units[f"{new_requirer_app_name}/0"]

        action = await requirer_unit.run_action(action_name="get-certificate")

        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id, wait=60
        )
        assert action_output["return-code"] == 0
        assert "ca" in action_output and action_output["ca"] is not None
        assert "certificate" in action_output and action_output["certificate"] is not None
        assert "chain" in action_output and action_output["chain"] is not None

    async def test_given_4_min_certificate_validity_when_certificate_expires_then_certificate_is_automatically_renewed(  # noqa: E501
        self, ops_test
    ):
        requirer_unit = ops_test.model.units[f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0"]

        action = await requirer_unit.run_action(action_name="get-certificate")

        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id, wait=60
        )

        assert "certificate" in action_output and action_output["certificate"] is not None
        initial_certificate = Certificate(action_output["certificate"])

        time.sleep(300)  # Wait 5 minutes for certificate to expire

        action = await requirer_unit.run_action(action_name="get-certificate")

        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id, wait=60
        )

        assert "certificate" in action_output and action_output["certificate"] is not None
        renewed_certificate = Certificate(action_output["certificate"])

        assert initial_certificate.expiry != renewed_certificate.expiry
