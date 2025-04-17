from __future__ import annotations

from typing import Any

import jubilant
import pytest


@pytest.fixture(scope="session", autouse=True)
def patched_jubilant():
    _old_from_dict = jubilant.statustypes.AppStatusRelation._from_dict

    def _new_from_dict(d: dict[str, Any] | str):
        if isinstance(d, str):
            return jubilant.statustypes.AppStatusRelation(related_app=d)
        return _old_from_dict(d)

    jubilant.statustypes.AppStatusRelation._from_dict = _new_from_dict
