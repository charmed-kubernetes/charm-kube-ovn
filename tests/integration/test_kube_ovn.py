from pathlib import Path
from pytest_operator.plugin import OpsTest

import shlex
import pytest
import logging

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    log.info("Build charm...")
    charm = await ops_test.build_charm(".")

    plugin_path = Path.cwd() / "plugins/kubectl-ko"

    overlays = [
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
    ]

    log.info("Rendering overlays...")
    bundle, *overlays = await ops_test.async_render_bundles(
        *overlays, charm=charm, plugin=plugin_path
    )

    log.info("Deploy charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} " + " ".join(
        f"--overlay={f}" for f in overlays
    )

    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    await ops_test.model.block_until(
        lambda: "kube-ovn" in ops_test.model.applications, timeout=60
    )

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_kubectl_ko_plugin(ops_test: OpsTest):
    units = ops_test.model.applications["kube-ovn"].units
    machines = [u.machine.entity_id for u in units]

    for m in machines:
        cmd = f"juju ssh {m} kubectl ko nbctl show"
        rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
        assert (
            rc == 0
        ), f"Failed to execute kubectl-ko on machine:{m} {(stderr or stdout).strip()}"
