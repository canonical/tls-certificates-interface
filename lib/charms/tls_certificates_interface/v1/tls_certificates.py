# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for the tls-certificates relation.

Warning: This version of the `tls-certificates` library is deprecated.
Please use the latest version.

"""


import logging

from ops.charm import CharmBase
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 15


logger = logging.getLogger(__name__)


class TLSCertificatesProvidesV1(Object):
    """TLS certificates provider class to be instantiated by TLS certificates providers."""

    def __init__(self, charm: CharmBase, relationship_name: str):
        super().__init__(charm, relationship_name)
        logger.warning(
            "This version of the `tls-certificates` library is deprecated. "
            "Please use the latest version."
        )
        self.charm = charm
        self.relationship_name = relationship_name


class TLSCertificatesRequiresV1(Object):
    """TLS certificates requirer class to be instantiated by TLS certificates requirers."""

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
    ):
        """Generates/use private key and observes relation changed event.

        Args:
            charm: Charm object
            relationship_name: Juju relation name
        """
        super().__init__(charm, relationship_name)
        self.relationship_name = relationship_name
        self.charm = charm
