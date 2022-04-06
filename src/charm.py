#!/usr/bin/env python3

import logging
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus

log = logging.getLogger(__name__)


class KubeOvnCharm(CharmBase):
    stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        log.info("GKK: __init__")
        self.framework.observe(self.on.config_changed, self.on_config_changed)

    def on_config_changed(self, _):
        log.info("GKK: config_changed")


if __name__ == "__main__":
    main(KubeOvnCharm)
