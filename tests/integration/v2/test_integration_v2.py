#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import shutil
import subprocess
from pathlib import Path

import jubilant
import pytest

logger = logging.getLogger(__name__)

LIB_DIR = "lib/charms/tls_certificates_interface/v2/tls_certificates.py"
REQUIRER_CHARM_DIR = "tests/integration/v2/requirer_charm"
PROVIDER_CHARM_DIR = "tests/integration/v2/provider_charm"
TLS_CERTIFICATES_PROVIDER_APP_NAME = "tls-certificates-provider"
TLS_CERTIFICATES_REQUIRER_APP_NAME = "tls-certificates-requirer"


def build_charm(path: Path) -> Path:
    shutil.copyfile(src=LIB_DIR, dst=path / Path(LIB_DIR))
    _ = subprocess.run(
        ["charmcraft", "pack", "--verbose"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=path,
    )
    return next(path.glob("*.charm"))


@pytest.fixture(scope="module")
def requirer_charm():
    charm_path = build_charm(Path(f"{REQUIRER_CHARM_DIR}/").absolute())
    yield charm_path


@pytest.fixture(scope="module")
def provider_charm():
    charm_path = build_charm(Path(f"{PROVIDER_CHARM_DIR}/").absolute())
    yield charm_path


@pytest.fixture(scope="module")
def juju():
    with jubilant.temp_model() as juju:
        juju.wait_timeout = 1000
        yield juju


@pytest.fixture(scope="module")
def is_juju_29(juju: jubilant.Juju):
    yield juju.cli("version", include_model=False).startswith("2.9")


def test_given_charms_packed_when_deploy_charm_then_status_is_blocked(
    juju: jubilant.Juju,
    requirer_charm: Path,
    provider_charm: Path,
):
    juju.deploy(requirer_charm, app=TLS_CERTIFICATES_REQUIRER_APP_NAME)
    juju.deploy(provider_charm, app=TLS_CERTIFICATES_PROVIDER_APP_NAME)
    status = juju.wait(
        lambda status: (
            status.apps[TLS_CERTIFICATES_REQUIRER_APP_NAME]
            .units[f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0"]
            .is_blocked
            and status.apps[TLS_CERTIFICATES_PROVIDER_APP_NAME]
            .units[f"{TLS_CERTIFICATES_PROVIDER_APP_NAME}/0"]
            .is_blocked
        ),
        error=jubilant.any_error,
    )
    assert status.apps[TLS_CERTIFICATES_REQUIRER_APP_NAME].scale == 1
    assert status.apps[TLS_CERTIFICATES_PROVIDER_APP_NAME].scale == 1


def test_given_charms_deployed_when_relate_then_status_is_active(
    juju: jubilant.Juju,
):
    # Directly calling the CLI because `integrate` is not available on Juju 2
    juju.cli("relate", TLS_CERTIFICATES_REQUIRER_APP_NAME, TLS_CERTIFICATES_PROVIDER_APP_NAME)

    _ = juju.wait(jubilant.all_active)


def test_given_charms_deployed_when_relate_then_requirer_received_certs(
    juju: jubilant.Juju,
    is_juju_29: bool,
):
    if is_juju_29:
        result = json.loads(
            juju.cli(
                "run-action",
                f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0",
                "get-certificate",
                "--wait",
                "--format",
                "json",
            )
        )[f"unit-{TLS_CERTIFICATES_REQUIRER_APP_NAME}-0"]["results"]
    else:
        result = juju.run(
            unit=f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0",
            action="get-certificate",
        ).results

    assert "ca" in result and result["ca"] is not None
    assert "certificate" in result and result["certificate"] is not None
    assert "chain" in result and result["chain"] is not None


def test_given_additional_requirer_charm_deployed_when_relate_then_requirer_received_certs(
    juju: jubilant.Juju,
    is_juju_29: bool,
    requirer_charm: Path,
):
    new_requirer_app_name = "new-tls-requirer"
    juju.deploy(requirer_charm, app=new_requirer_app_name)
    # Directly calling the CLI because `integrate` is not available on Juju 2
    juju.cli("relate", new_requirer_app_name, TLS_CERTIFICATES_PROVIDER_APP_NAME)
    _ = juju.wait(jubilant.all_active)

    if is_juju_29:
        result = json.loads(
            juju.cli(
                "run-action",
                f"{new_requirer_app_name}/0",
                "get-certificate",
                "--wait",
                "--format",
                "json",
            )
        )[f"unit-{new_requirer_app_name}-0"]["results"]
    else:
        result = juju.run(
            unit=f"{new_requirer_app_name}/0",
            action="get-certificate",
        ).results

    assert "ca" in result and result["ca"] is not None
    assert "certificate" in result and result["certificate"] is not None
    assert "chain" in result and result["chain"] is not None


def test_given_enough_time_passed_then_certificate_expired(
    juju: jubilant.Juju,
):
    juju.wait(
        lambda status: (
            status.apps[TLS_CERTIFICATES_REQUIRER_APP_NAME]
            .units[f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0"]
            .is_blocked
            and status.apps[TLS_CERTIFICATES_PROVIDER_APP_NAME]
            .units[f"{TLS_CERTIFICATES_PROVIDER_APP_NAME}/0"]
            .is_active
        ),
        error=jubilant.any_error,
    )

    status = juju.status()
    assert (
        status.apps[TLS_CERTIFICATES_REQUIRER_APP_NAME]
        .units[f"{TLS_CERTIFICATES_REQUIRER_APP_NAME}/0"]
        .workload_status.message
        == "Told you, now your certificate expired"
    )
