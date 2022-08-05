import time
import os
import juju.utils
from juju.tag import untag
import asyncio
import subprocess
import json
import pytest
import pytest_asyncio
import logging

from pathlib import Path
import yaml
import shlex
from lightkube import Client, codecs, KubeConfig
from lightkube.resources.apps_v1 import DaemonSet
from lightkube.resources.core_v1 import Pod
from lightkube.resources.core_v1 import Namespace
from lightkube.resources.core_v1 import Node
from lightkube.generic_resource import create_global_resource
from random import choices
from string import ascii_lowercase, digits

log = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption(
        "--k8s-cloud",
        action="store",
        help="Juju kubernetes cloud to reuse; if not provided, will generate a new cloud",
    )


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
async def client(kubeconfig):
    config = KubeConfig.from_file(kubeconfig)
    client = Client(
        config=config.get(context_name="juju-context"),
        trust_env=False,
    )
    yield client


@pytest.fixture(scope="module")
def subnet_resource(client):
    return create_global_resource("kubeovn.io", "v1", "Subnet", "subnets")


@pytest.fixture(scope="module")
def worker_node(client):
    # Returns a worker node
    for node in client.list(Node):
        if node.metadata.labels["juju-application"] == "kubernetes-worker":
            return node


@pytest.fixture(scope="module")
async def gateway_server(ops_test):
    cmd = "run --unit ubuntu/0 -- sudo apt install -y iperf3"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to install iperf3: {(stdout or stderr).strip()}"

    iperf3_cmd = "iperf3 -s --daemon"
    cmd = f"juju run --unit ubuntu/0 -- {iperf3_cmd}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run iperf3 server: {(stdout or stderr).strip()}"

    cmd = "juju show-unit ubuntu/0"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to get ubuntu/0 unit data: {(stdout or stderr).strip()}"

    unit_data = yaml.safe_load(stdout)
    return unit_data["ubuntu/0"]["public-address"]


@pytest.fixture()
def gateway_client_pod(client, worker_node, subnet_resource):
    log.info("Creating gateway QoS-related resources ...")
    path = Path("tests/data/gateway_qos.yaml")
    for obj in codecs.load_all_yaml(path.read_text()):
        if obj.kind == "Subnet":
            obj.spec["gatewayNode"] = worker_node.metadata.name
        if obj.kind == "Namespace":
            namespace = obj.metadata.name
        if obj.kind == "Pod":
            pod_name = obj.metadata.name
        client.create(obj)

    client_pod = client.get(Pod, name=pod_name, namespace=namespace)
    # wait for pod to come up
    client.wait(
        Pod,
        client_pod.metadata.name,
        for_conditions=["Ready"],
        namespace=namespace,
    )

    yield client_pod

    log.info("Deleting gateway QoS-related resources ...")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.delete(type(obj), obj.metadata.name, namespace=obj.metadata.namespace)


@pytest.fixture()
def iperf3_pods(client):
    log.info("Creating iperf3 resources ...")
    path = Path.cwd() / "tests/data/iperf3_daemonset.yaml"
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            if obj.kind == "Namespace":
                namespace = obj.metadata.name
            if obj.kind == "DaemonSet":
                ds = obj.metadata.name
            client.create(obj)

    wait_daemonset(client, namespace, ds, 3)
    pods = list(client.list(Pod, namespace=namespace))

    yield pods

    log.info("Deleting iperf3 resources ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(
                type(obj), obj.metadata.name, namespace=obj.metadata.namespace
            )

    # wait for pods to be deleted
    remaining_pods = list(client.list(Pod, namespace=namespace))
    while len(remaining_pods) != 0:
        log.info("iperf3 pods still in existence, waiting ...")
        remaining_pods = list(client.list(Pod, namespace=namespace))
        time.sleep(5)

    while namespace in list(client.list(Namespace)):
        log.info("iperf3 namespace still in existence, waiting ...")
        time.sleep(5)

    log.info("iperf3 cleanup finished")


@pytest.fixture(scope="module")
def kubectl(kubeconfig):
    async def f(*args):
        cmd = ["kubectl", "--kubeconfig", str(kubeconfig)] + list(args)
        process = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE)
        output, _ = await process.communicate()
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                returncode=process.returncode, cmd=cmd, output=output
            )
        return output

    return f


@pytest.fixture(scope="module")
async def k8s_storage(kubectl):
    await kubectl("apply", "-f", "tests/data/vsphere-storageclass.yaml")


@pytest.fixture(scope="module")
def module_name(request):
    return request.module.__name__.replace("_", "-")


@pytest.fixture(scope="module")
async def k8s_cloud(k8s_storage, kubeconfig, module_name, ops_test, request):
    """Use an existing k8s-cloud or create a k8s-cloud
    for deploying a new k8s model into"""
    cloud_name = request.config.option.k8s_cloud or f"{module_name}-k8s-cloud"
    controller = await ops_test.model.get_controller()
    try:
        current_clouds = await controller.clouds()
        if f"cloud-{cloud_name}" in current_clouds.clouds:
            yield cloud_name
            return
    finally:
        await controller.disconnect()

    with ops_test.model_context("main"):
        log.info(f"Adding cloud '{cloud_name}'...")
        os.environ["KUBECONFIG"] = str(kubeconfig)
        await ops_test.juju(
            "add-k8s",
            cloud_name,
            f"--controller={ops_test.controller_name}",
            "--client",
            check=True,
            fail_msg=f"Failed to add-k8s {cloud_name}",
        )
    yield cloud_name

    with ops_test.model_context("main"):
        log.info(f"Removing cloud '{cloud_name}'...")
        await ops_test.juju(
            "remove-cloud",
            cloud_name,
            "--controller",
            ops_test.controller_name,
            "--client",
            check=True,
        )


@pytest.fixture(scope="module")
async def k8s_model(k8s_cloud, ops_test):
    model_alias = "k8s-model"
    log.info("Creating k8s model ...")
    # Create model with Juju CLI to work around a python-libjuju bug
    # https://github.com/juju/python-libjuju/issues/603
    model_name = "test-kube-ovn-" + "".join(choices(ascii_lowercase + digits, k=4))
    await ops_test.juju(
        "add-model",
        f"--controller={ops_test.controller_name}",
        model_name,
        k8s_cloud,
        "--no-switch",
    )
    model = await ops_test.track_model(
        model_alias,
        model_name=model_name,
        cloud_name=k8s_cloud,
        credential_name=k8s_cloud,
        keep=False,
    )
    model_uuid = model.info.uuid
    yield model, model_alias
    timeout = 5 * 60
    await ops_test.forget_model(model_alias, timeout=timeout, allow_failure=False)

    async def model_removed():
        _, stdout, stderr = await ops_test.juju("models", "--format", "yaml")
        if _ != 0:
            return False
        model_list = yaml.safe_load(stdout)["models"]
        which = [m for m in model_list if m["model-uuid"] == model_uuid]
        return len(which) == 0

    log.info("Removing k8s model")
    await juju.utils.block_until_with_coroutine(model_removed, timeout=timeout)
    # Update client's model cache
    await ops_test.juju("models")
    log.info("k8s model removed")


@pytest.fixture(scope="module")
async def multus_installed(ops_test, k8s_model):
    _, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias) as model:
        await model.deploy(entity_url="multus", channel="edge")
        await model.block_until(lambda: "multus" in model.applications, timeout=60)
        await model.wait_for_idle(status="active", timeout=60 * 60)

    # need to wait until all kubernetes-worker units have multus CNI config installed
    deadline = time.time() + 600
    for unit in ops_test.model.applications["kubernetes-worker"].units:
        log.info("waiting for Multus config on unit %s" % unit.name)
        while time.time() < deadline:
            rc, _, _ = await ops_test.juju(
                "ssh",
                "-m",
                ops_test.model_full_name,
                unit.name,
                "--",
                "sudo",
                "ls",
                "/etc/cni/net.d",
                "|",
                "grep",
                "multus",
            )
            if rc == 0:
                break
            await asyncio.sleep(1)
        else:
            pytest.fail("timed out waiting for Multus config on unit %s" % unit.name)

    yield

    with ops_test.model_context(k8s_alias) as m:
        log.info("Removing multus application ...")
        cmd = "remove-application multus --destroy-storage --force"
        rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
        log.info(stdout)
        log.info(stderr)
        assert rc == 0
        await m.block_until(lambda: "multus" not in m.applications, timeout=60 * 10)


def wait_daemonset(client: Client, namespace, name, pods_ready):
    for _, obj in client.watch(
        DaemonSet, namespace=namespace, fields={"metadata.name": name}
    ):
        if obj.status is None:
            continue
        status = obj.status.to_dict()
        if status["numberReady"] == pods_ready:
            return


@pytest_asyncio.fixture(scope="module")
async def grafana_app(ops_test, k8s_model):
    grafana_model_obj, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias) as m:
        log.info("Deploying grafana-k8s ...")
        await m.deploy(entity_url="grafana-k8s", trust=True, channel="edge")

        await m.block_until(lambda: "grafana-k8s" in m.applications, timeout=60)
        await m.wait_for_idle(status="active")

    yield "grafana-k8s"

    with ops_test.model_context(k8s_alias) as m:
        log.info("Removing grafana-k8s application ...")
        cmd = "remove-application grafana-k8s --destroy-storage --force"
        rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
        log.info(stdout)
        log.info(stderr)
        assert rc == 0
        await m.block_until(
            lambda: "grafana-k8s" not in m.applications, timeout=60 * 10
        )


@pytest_asyncio.fixture(scope="module")
async def related_grafana(ops_test, grafana_app, k8s_model):
    grafana_model_obj, k8s_alias = k8s_model
    app_name = grafana_app
    machine_model_name = ops_test.model_name
    model_owner = untag("user-", grafana_model_obj.info.owner_tag)
    with ops_test.model_context(k8s_alias) as m:
        offer, saas = None, None
        log.info("Creating CMR offer for Grafana")
        offer = await m.create_offer(f"{app_name}:grafana-dashboard")
        grafana_model_name = ops_test.model_name

    log.info("Consuming Grafana CMR offer")
    log.info(
        f"{machine_model_name} consuming Grafana CMR offer from {grafana_model_name}"
    )
    saas = await ops_test.model.consume(
        f"{model_owner}/{grafana_model_name}.{app_name}"
    )
    log.info("Relating grafana and kube-ovn...")
    await ops_test.model.add_relation("kube-ovn", f"{app_name}:grafana-dashboard")
    with ops_test.model_context(k8s_alias) as gf_model:
        await gf_model.wait_for_idle(status="active")
    await ops_test.model.wait_for_idle(status="active")
    yield
    with ops_test.model_context(k8s_alias) as m:
        keep = ops_test.keep_model
    if not keep:
        try:
            if saas:
                log.info("Removing Grafana CMR consumer")
                await ops_test.model.remove_saas(app_name)
            if offer:
                log.info("Removing Grafana CMR offer and relations")
                await grafana_model_obj.remove_offer(
                    f"{grafana_model_name}.{app_name}", force=True
                )
        except Exception:
            log.exception("Error performing cleanup")


@pytest_asyncio.fixture(scope="module")
async def grafana_password(ops_test, related_grafana, k8s_model, grafana_app):
    grafana_model_obj, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias):
        action = (
            await ops_test.model.applications[grafana_app]
            .units[0]
            .run_action("get-admin-password")
        )
        action = await action.wait()
    return action.results["admin-password"]


@pytest_asyncio.fixture(scope="module")
async def grafana_service(ops_test, client, related_grafana, k8s_model, grafana_app):
    _, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias):
        grafana_model_name = ops_test.model_name

    log.info("Creating Grafana service ...")
    path = Path("tests/data/grafana_service.yaml")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj, namespace=grafana_model_name)

    yield

    log.info("Deleting Grafana service ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(type(obj), obj.metadata.name, namespace=grafana_model_name)


@pytest_asyncio.fixture(scope="module")
async def grafana_host(
    ops_test, grafana_service, worker_node, related_grafana, k8s_model, grafana_app
):
    worker_ip = None
    for address in worker_node.status.addresses:
        if address.type == "ExternalIP":
            worker_ip = address.address
    return worker_ip


@pytest_asyncio.fixture(scope="module")
async def expected_dashboard_titles():
    grafana_dir = Path("src/grafana_dashboards")
    grafana_files = [
        p for p in grafana_dir.iterdir() if p.is_file() and p.name.endswith(".json")
    ]
    titles = []
    for path in grafana_files:
        dashboard = json.loads(path.read_text())
        titles.append(dashboard["title"])
    return titles


@pytest_asyncio.fixture(scope="module")
async def prometheus_app(ops_test, k8s_model):
    _, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias) as m:
        log.info("Deploying prometheus-k8s ...")
        await m.deploy(entity_url="prometheus-k8s", trust=True, channel="beta")

        await m.block_until(lambda: "prometheus-k8s" in m.applications, timeout=60 * 3)
        await m.wait_for_idle(
            apps=["prometheus-k8s"],
            status="active",
            timeout=60 * 3,
            raise_on_error=False,
        )

    yield "prometheus-k8s"

    with ops_test.model_context(k8s_alias) as m:
        log.info("Removing prometheus-k8s application ...")
        cmd = "remove-application prometheus-k8s --destroy-storage --force"
        rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
        log.info(stdout)
        log.info(stderr)
        assert rc == 0
        await m.block_until(
            lambda: "prometheus-k8s" not in m.applications, timeout=60 * 10
        )


@pytest_asyncio.fixture(scope="module")
async def related_prometheus(ops_test, prometheus_app, k8s_model):
    prometheus_model_obj, k8s_alias = k8s_model
    app_name = prometheus_app
    machine_model_name = ops_test.model_name
    model_owner = untag("user-", prometheus_model_obj.info.owner_tag)
    with ops_test.model_context(k8s_alias) as m:
        offer, saas = None, None
        log.info("Creating CMR offer for Prometheus")
        offer = await m.create_offer(f"{app_name}:receive-remote-write")
        prom_model_name = ops_test.model_name

    log.info("Consuming Prometheus CMR offer")
    log.info(
        f"{machine_model_name} consuming Prometheus CMR offer from {prom_model_name}"
    )
    saas = await ops_test.model.consume(f"{model_owner}/{prom_model_name}.{app_name}")
    log.info("Relating Prometheus and kube-ovn...")
    await ops_test.model.add_relation("kube-ovn", f"{app_name}:receive-remote-write")
    with ops_test.model_context(k8s_alias) as prom_model:
        await prom_model.wait_for_idle(status="active")
    await ops_test.model.wait_for_idle(status="active")
    yield
    with ops_test.model_context(k8s_alias) as m:
        keep = ops_test.keep_model
    if not keep:
        try:
            if saas:
                log.info("Removing Prometheus CMR consumer")
                await ops_test.model.remove_saas(app_name)
            if offer:
                log.info("Removing Prometheus CMR offer and relations")
                await prometheus_model_obj.remove_offer(
                    f"{prom_model_name}.{app_name}", force=True
                )
        except Exception:
            log.exception("Error performing cleanup")


@pytest_asyncio.fixture(scope="module")
async def prometheus_service(
    ops_test, client, related_prometheus, k8s_model, prometheus_app
):
    _, k8s_alias = k8s_model
    with ops_test.model_context(k8s_alias):
        prometheus_model_name = ops_test.model_name

    log.info("Creating Prometheus service ...")
    path = Path("tests/data/prometheus_service.yaml")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj, namespace=prometheus_model_name)

    yield

    log.info("Deleting Prometheus service ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(type(obj), obj.metadata.name, namespace=prometheus_model_name)


@pytest_asyncio.fixture(scope="module")
async def prometheus_host(
    ops_test,
    prometheus_service,
    worker_node,
    related_prometheus,
    k8s_model,
    prometheus_app,
):
    worker_ip = None
    for address in worker_node.status.addresses:
        if address.type == "ExternalIP":
            worker_ip = address.address
    return worker_ip


@pytest_asyncio.fixture(scope="module")
async def expected_prometheus_metrics():
    metrics_path = Path("tests/data/prometheus_metrics.json")
    with open(metrics_path, "r") as file:
        metrics = json.load(file)["data"]

    return metrics
