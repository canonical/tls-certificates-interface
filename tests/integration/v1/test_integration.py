#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import shutil

import pytest

logger = logging.getLogger(__name__)
LIB_DIR = "lib/charms/tls_certificates_interface/v1/tls_certificates.py"
REQUIRER_CHARM_DIR = "tests/integration/v1/requirer_charm"
PROVIDER_CHARM_DIR = "tests/integration/v1/provider_charm"
TLS_CERTIFICATES_PROVIDER_APP_NAME = "tls-certificates-provider"
TLS_CERTIFICATES_REQUIRER_APP_NAME = "tls-certificates-requirer"


def copy_lib_content() -> None:
    shutil.copyfile(src=LIB_DIR, dst=f"{REQUIRER_CHARM_DIR}/{LIB_DIR}")
    shutil.copyfile(src=LIB_DIR, dst=f"{PROVIDER_CHARM_DIR}/{LIB_DIR}")


class TestIntegration:
    @pytest.mark.abort_on_fail
    async def build_and_deploy_requirer_charm(self, ops_test):
        charm = await ops_test.build_charm(f"{REQUIRER_CHARM_DIR}/")
        await ops_test.model.deploy(charm, application_name=TLS_CERTIFICATES_REQUIRER_APP_NAME)

    @pytest.mark.abort_on_fail
    async def build_and_deploy_provider_charm(self, ops_test):
        charm = await ops_test.build_charm(f"{PROVIDER_CHARM_DIR}/")
        await ops_test.model.deploy(charm, application_name=TLS_CERTIFICATES_PROVIDER_APP_NAME)

    async def test_given_charms_packed_when_deploy_charm_then_status_is_blocked(self, ops_test):
        copy_lib_content()
        await self.build_and_deploy_requirer_charm(ops_test)
        await self.build_and_deploy_provider_charm(ops_test)

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
