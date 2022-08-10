#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Placeholder charm."""

from ops.charm import CharmBase
from ops.main import main


class PlaceholderCharm(CharmBase):
    """Placeholder charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event):
        pass


if __name__ == "__main__":
    main(PlaceholderCharm)
