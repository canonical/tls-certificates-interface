from __future__ import annotations

from typing import Any

import jubilant
import pytest


@pytest.fixture(scope="session", autouse=True)
def patched_jubilant():
    """Patch Jubilant AppStatusRelation for Juju 2.9 support.

    Jubilant does not support Juju 2.9, and this workaround is required
    as the JSON format of the CLI is not the same for the relation field.
    In Juju >=3, the field is a dictionary, but in Juju 2.9 it is a string.

    This patch prevents a crash in Jubilant on the Juju 2.9 format.

    A fix was proposed upstream but not accepted:
    https://github.com/canonical/jubilant/pull/101
    """
    _old_from_dict = jubilant.statustypes.AppStatusRelation._from_dict

    def _new_from_dict(d: dict[str, Any] | str):
        if isinstance(d, str):
            return jubilant.statustypes.AppStatusRelation(related_app=d)
        return _old_from_dict(d)

    jubilant.statustypes.AppStatusRelation._from_dict = _new_from_dict
