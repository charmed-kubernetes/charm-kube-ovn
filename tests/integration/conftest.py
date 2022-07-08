import logging
from pathlib import Path

import pytest
from lightkube import Client, codecs, KubeConfig

log = logging.getLogger(__name__)


@pytest.fixture()
async def kubeconfig(ops_test):
    kubeconfig_path = ops_test.tmp_path / "kubeconfig"
    rc, stdout, stderr = await ops_test.run(
        "juju",
        "scp",
        "kubernetes-control-plane/leader:/home/ubuntu/config",
        kubeconfig_path,
    )
    if rc != 0:
        log.error(f"retcode: {rc}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to copy kubeconfig from kubernetes-control-plane")
    assert Path(kubeconfig_path).stat().st_size, "kubeconfig file is 0 bytes"
    yield kubeconfig_path


@pytest.fixture()
async def client(kubeconfig):
    config = KubeConfig.from_file(kubeconfig)
    client = Client(
        config=config.get(context_name="juju-context"),
        trust_env=False,
    )
    yield client


@pytest.fixture()
def iperf3_yaml_path(client):
    path = Path.cwd() / "tests/data/iperf3_daemonset.yaml"
    yield path
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(
                type(obj), obj.metadata.name, namespace=obj.metadata.namespace
            )
