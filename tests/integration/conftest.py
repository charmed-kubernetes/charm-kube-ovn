import time
import os
import asyncio
import json
import pytest
import pytest_asyncio
import logging

from pathlib import Path
import yaml
import shlex
from lightkube import Client, codecs, KubeConfig
from lightkube.core.exceptions import ApiError, ObjectDeleted
from lightkube.resources.apps_v1 import DaemonSet, Deployment
from lightkube.resources.core_v1 import Namespace, Node, Pod, Service
from lightkube.generic_resource import create_global_resource
from lightkube.types import PatchType
from random import choices
from string import ascii_lowercase, digits
from typing import Union, Tuple
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_delay,
    wait_fixed,
)


log = logging.getLogger(__name__)
GRAFANA = "grafana-k8s"


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
        "juju", "ssh", "kubernetes-control-plane/leader", "--", "cat", "config"
    )
    if rc != 0:
        log.error(f"retcode: {rc}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to copy kubeconfig from kubernetes-control-plane")
    assert stdout, "kubeconfig file is 0 bytes"
    kubeconfig_path.write_text(stdout)
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
    cmd = "exec --unit ubuntu/0 -- sudo apt install -y iperf3"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to install iperf3: {(stdout or stderr).strip()}"

    iperf3_cmd = "iperf3 -s --daemon"
    cmd = f"juju exec --unit ubuntu/0 -- {iperf3_cmd}"
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


async def wait_pod_ips(client, pods):
    """Returns a list of pods which have an ip address assigned."""

    log.info("Waiting for pods...")
    ready = []

    for pod in pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )
        for _, obj in client.watch(
            Pod,
            namespace=pod.metadata.namespace,
            fields={"metadata.name": pod.metadata.name},
        ):
            if obj.status.podIP:
                ready.append(obj)
                break

    return ready


@pytest.fixture()
async def isolated_subnet(client, subnet_resource):
    log.info("Creating isolated subnet resources ...")
    path = Path("tests/data/isolated-subnet.yaml")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.create(obj)
    subnets = [
        client.get(subnet_resource, name="isolated-subnet"),
        client.get(subnet_resource, name="allowed-subnet"),
    ]
    log.info("Waiting for subnets...")
    for sn in subnets:
        client.wait(subnet_resource, sn.metadata.name, for_conditions=["Ready"])

    watch = [
        client.get(Pod, name="isolated-pod", namespace="isolated"),
        client.get(Pod, name="allowed-pod", namespace="allowed"),
    ]

    pods = await wait_pod_ips(client, watch)

    yield tuple(pods)

    log.info("Deleting isolated subnet resources ...")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.delete(type(obj), obj.metadata.name, namespace=obj.metadata.namespace)

    await wait_for_removal(client, pods)


async def wait_for_removal(client, pods):
    """Waits until listed pods are no longer present in the cluster."""
    for pod in pods:
        namespace = pod.metadata.namespace
        remaining_pods = list(client.list(Pod, namespace=namespace))
        while len(remaining_pods) != 0:
            log.info("Pods still in existence, waiting ...")
            remaining_pods = list(client.list(Pod, namespace=namespace))
            await asyncio.sleep(5)

    for pod in pods:
        namespace = pod.metadata.namespace
        while namespace in list(client.list(Namespace)):
            log.info(f"{namespace} namespace still in existence, waiting ...")
            await asyncio.sleep(5)


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
def kubectl(ops_test, kubeconfig):
    """Supports running kubectl exec commands."""

    KubeCtl = Union[str, Tuple[int, str, str]]

    async def f(*args, **kwargs) -> KubeCtl:
        """Actual callable returned by the fixture.

        :returns: if kwargs[check] is True or undefined, stdout is returned
                  if kwargs[check] is False, Tuple[rc, stdout, stderr] is returned
        """
        cmd = ["kubectl", "--kubeconfig", str(kubeconfig)] + list(args)
        check = kwargs["check"] = kwargs.get("check", True)
        rc, stdout, stderr = await ops_test.run(*cmd, **kwargs)
        if not check:
            return rc, stdout, stderr
        return stdout

    return f


@pytest.fixture(scope="module")
def kubectl_exec(kubectl):
    async def f(name: str, namespace: str, cmd: str, **kwds):
        shcmd = f'exec {name} -n {namespace} -- sh -c "{cmd}"'
        return await kubectl(*shlex.split(shcmd), **kwds)

    return f


@pytest.fixture(scope="module")
def kubectl_get(kubectl):
    async def f(*args, **kwargs):
        args = ["get", "-o", "json"] + list(args)
        output = await kubectl(*args, **kwargs)
        return json.loads(output)

    return f


@pytest.fixture(scope="module")
def module_name(request):
    return request.module.__name__.replace("_", "-")


@pytest.fixture(scope="module")
async def k8s_cloud(kubeconfig, module_name, ops_test, request):
    """Use an existing k8s-cloud or create a k8s-cloud
    for deploying a new k8s model into"""
    cloud_name = request.config.option.k8s_cloud or f"{module_name}-k8s-cloud"
    controller = await ops_test.model.get_controller()
    current_clouds = await controller.clouds()
    if f"cloud-{cloud_name}" in current_clouds.clouds:
        yield cloud_name
        return

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


@retry(
    retry=retry_if_exception_type(AssertionError),
    stop=stop_after_delay(60 * 10),
    wait=wait_fixed(1),
)
async def confirm_multus_installed(ops_test):
    model = ops_test.model
    model_name = ops_test.model_full_name
    for unit in model.applications["kubernetes-worker"].units:
        log.info(f"Confirming multus config on unit {unit.name}")
        multus_match = "sudo ls /etc/cni/net.d | grep multus"
        ssh_cmd = f"ssh -m {model_name} {unit.name} -- {multus_match}"
        rc, *_ = await ops_test.juju(*shlex.split(ssh_cmd))
        assert rc == 0, f"Multus not yet on {unit.name}"
    log.info("Multus Installed")


async def confirm_multus_removed(ops_test):
    model = ops_test.model
    model_name = ops_test.model_full_name
    for unit in model.applications["kubernetes-worker"].units:
        commands = (
            "sudo rm -rf /etc/cni/net.d/multus.d",
            "sudo rm -rf /etc/cni/net.d/00-multus.conf",
        )
        for command in commands:
            ssh_cmd = f"ssh -m {model_name} {unit.name} -- {command}"
            await ops_test.juju(*shlex.split(ssh_cmd))
    log.info("Multus Removed")


@pytest.fixture(scope="module")
async def k8s_model(k8s_cloud, ops_test, client: Client):
    model_alias = "k8s-model"
    model_name = "test-kube-ovn-" + "".join(choices(ascii_lowercase + digits, k=4))
    log.info(f"Creating k8s model {model_name}...")
    machine_model = ops_test.model
    await confirm_multus_removed(ops_test)
    await ops_test.track_model(
        model_alias,
        model_name=model_name,
        cloud_name=k8s_cloud,
        credential_name=k8s_cloud,
        keep=False,
    )

    saases = []
    try:
        with ops_test.model_context(model_alias) as k8s_model:
            await asyncio.gather(
                *(
                    k8s_model.deploy(app, trust=True, channel="edge")
                    for app in ("multus", GRAFANA, "prometheus-k8s")
                )
            )
            saas_model = f"{k8s_model.info.users[0].display_name}/{model_name}"
            await k8s_model.create_offer(f"{GRAFANA}:grafana-dashboard")
            await k8s_model.create_offer("prometheus-k8s:receive-remote-write")
            saases.append(await machine_model.consume(f"{saas_model}.{GRAFANA}"))
            saases.append(await machine_model.consume(f"{saas_model}.prometheus-k8s"))

            async with ops_test.fast_forward():
                # The o11y charms like to error occasionally -- just wait for stable
                await k8s_model.wait_for_idle(
                    status="active", timeout=60 * 10, raise_on_error=False
                )

            # the o11y charms seems to not evaluate their relations until after the units are active/idle
            await machine_model.relate("kube-ovn:grafana-dashboard", GRAFANA)
            await machine_model.relate("kube-ovn:send-remote-write", "prometheus-k8s")
            async with ops_test.fast_forward():
                await k8s_model.wait_for_idle(
                    status="active", timeout=60 * 5, raise_on_error=False
                )

        await confirm_multus_installed(ops_test)
        async with ops_test.fast_forward():
            await machine_model.wait_for_idle(status="active", timeout=60 * 10)

        log.info("K8s model Ready")

        yield model_alias
    finally:
        log.info("Removing k8s model")
        for saas in saases:
            log.info(f"Removing {saas} CMR consumer and offers")
            await machine_model.remove_saas(saas)
            await k8s_model.remove_offer(f"{model_name}.{saas}", force=True)

        await ops_test.forget_model(model_alias, timeout=5 * 60, allow_failure=False)
        await confirm_multus_removed(ops_test)

    log.info("Confirming k8s model is delete...")
    try:
        client.get(Namespace, model_name)
        client.wait(Namespace, model_name, for_conditions=[])
    except (ObjectDeleted, ApiError):
        log.info("Confirmed...")

    async with ops_test.fast_forward():
        log.info("Confirming machine model is stable...")
        await machine_model.wait_for_idle(status="active", timeout=60 * 10)


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
async def grafana_password(ops_test, k8s_model):
    with ops_test.model_context(k8s_model):
        action = (
            await ops_test.model.applications[GRAFANA]
            .units[0]
            .run_action("get-admin-password")
        )
        action = await action.wait()
    return action.results["admin-password"]


@pytest_asyncio.fixture(scope="module")
async def grafana_host(ops_test, client, k8s_model, worker_node):
    with ops_test.model_context(k8s_model):
        grafana_model_name = ops_test.model_name

    log.info("Creating Grafana service ...")
    path = Path("tests/data/grafana_service.yaml")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj, namespace=grafana_model_name)

    worker_ip = None
    for address in worker_node.status.addresses:
        if address.type == "ExternalIP":
            worker_ip = address.address

    yield worker_ip

    log.info("Deleting Grafana service ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(type(obj), obj.metadata.name, namespace=grafana_model_name)


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
async def prometheus_host(ops_test, client, k8s_model, worker_node):
    with ops_test.model_context(k8s_model):
        prometheus_model_name = ops_test.model_name

    log.info("Creating Prometheus service ...")
    path = Path("tests/data/prometheus_service.yaml")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj, namespace=prometheus_model_name)

    worker_ip = None
    for address in worker_node.status.addresses:
        if address.type == "ExternalIP":
            worker_ip = address.address

    yield worker_ip
    log.info("Deleting Prometheus service ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(type(obj), obj.metadata.name, namespace=prometheus_model_name)


@pytest_asyncio.fixture(scope="module")
async def expected_prometheus_metrics():
    metrics_path = Path("tests/data/prometheus_metrics.json")
    with open(metrics_path, "r") as file:
        metrics = json.load(file)["data"]

    return metrics


@pytest_asyncio.fixture(scope="module")
async def nginx(client):
    log.info("Creating Nginx deployment and service ...")
    path = Path("tests/data/nginx.yaml")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj, namespace="default")

    log.info("Waiting for Nginx deployment to be available ...")
    client.wait(Deployment, "nginx", for_conditions=["Available"])
    log.info("Nginx deployment is now available")
    yield

    log.info("Deleting Nginx deployment and service ...")
    with open(path) as f:
        for obj in codecs.load_all_yaml(f):
            client.delete(type(obj), obj.metadata.name)


@pytest_asyncio.fixture(scope="module")
async def nginx_cluster_ip(client, nginx):
    log.info("Getting Nginx service IP ...")
    svc = client.get(Service, name="nginx", namespace="default")
    return svc.spec.clusterIP


@pytest_asyncio.fixture(scope="module")
async def nginx_pods(client, nginx):
    def f():
        pods = client.list(Pod, namespace="default", labels={"app": "nginx"})
        return pods

    return f


@pytest.fixture()
def default_subnet(client, subnet_resource):
    def f():
        subnet = client.get(subnet_resource, name="ovn-default")
        return subnet

    return f


@pytest_asyncio.fixture(scope="module")
async def bird(ops_test):
    await ops_test.model.deploy(entity_url="bird", channel="stable", num_units=3)
    await ops_test.model.block_until(
        lambda: "bird" in ops_test.model.applications, timeout=60
    )
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)
    log.info("Bird deployment complete")

    bird_app = ops_test.model.applications["bird"]
    kube_ovn_app = ops_test.model.applications["kube-ovn"]
    worker_app = ops_test.model.applications["kubernetes-worker"]

    log.info("Configuring Kube-OVN to peer with Bird")
    await kube_ovn_app.set_config(
        {
            "bgp-speakers": yaml.dump(
                [
                    {
                        "name": f'test-speaker-{bird_unit.name.replace("/", "-")}',
                        "node-selector": f"kubernetes.io/hostname={worker_unit.machine.hostname}",
                        "neighbor-address": bird_unit.public_address,
                        "neighbor-as": 64512,
                        "cluster-as": 64512,
                        "announce-cluster-ip": True,
                        "log-level": 5,
                    }
                    for (bird_unit, worker_unit) in zip(
                        bird_app.units, worker_app.units
                    )
                ]
            )
        }
    )
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)

    log.info("Configuring Bird to peer with Kube-OVN")
    await bird_app.set_config(
        {
            "bgp-peers": yaml.dump(
                [
                    {"address": unit.public_address, "as-number": 64512}
                    for unit in worker_app.units
                ]
            )
        }
    )
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)

    yield

    log.info("Setting empty bgp-speakers config ...")
    await kube_ovn_app.set_config(
        {
            "bgp-speakers": "",
        }
    )
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)

    cmd = "remove-application bird --force"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    log.info(stdout)
    log.info(stderr)
    assert rc == 0
    await ops_test.model.block_until(
        lambda: "bird" not in ops_test.model.applications, timeout=60 * 10
    )


@pytest_asyncio.fixture(scope="module")
async def bird_container_ip(ops_test, bird):
    bird_app = ops_test.model.applications["bird"]
    bird_unit = bird_app.units[0]

    cmd = f"exec --unit {bird_unit.name} -- sudo sysctl -w net.ipv4.ip_forward=1"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to enable IP forwarding: {(stdout or stderr).strip()}"

    cmd = f"exec --unit {bird_unit.name} -- sudo apt install -y jq"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to install jq: {(stdout or stderr).strip()}"

    log.info(f"Creating ubuntu container on bird unit {bird_unit.name}")
    cmd = f"exec --unit {bird_unit.name} -- sudo lxd init --auto"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to initialize lxd: {(stdout or stderr).strip()}"

    cmd = f"exec --unit {bird_unit.name} -- sudo lxc launch images:ubuntu/22.04 ubuntu-container"
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to launch ubuntu container: {(stdout or stderr).strip()}"

    cmd = f'exec --unit {bird_unit.name} -- sudo lxc list --format=json ubuntu-container | jq -r ".[].state.network.eth0.addresses | .[0].address"'
    rc, stdout, stderr = await ops_test.juju(*shlex.split(cmd))
    assert rc == 0, f"Failed to get container IP: {(stdout or stderr).strip()}"

    container_ip = stdout
    log.info(f"Ubuntu container IP {container_ip}")
    return container_ip


@pytest_asyncio.fixture(scope="module")
async def external_gateway_pod(ops_test, client, subnet_resource):
    bird_app = ops_test.model.applications["bird"]
    bird_unit = bird_app.units[0]
    log.info(f"Getting IP for bird unit {bird_unit.name}")
    cmd = f"juju show-unit {bird_unit.name}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert (
        rc == 0
    ), f"Failed to get {bird_unit.name} unit data: {(stdout or stderr).strip()}"

    unit_data = yaml.safe_load(stdout)
    bird_unit_ip = unit_data[bird_unit.name]["public-address"]

    # Create subnet, namespace, and pod for external gateway
    log.info("Creating subnet, namespace, and pod for external gateway testing ...")
    path = Path("tests/data/external-gateway.yaml")
    for obj in codecs.load_all_yaml(path.read_text()):
        if obj.kind == "Subnet":
            obj.spec["externalEgressGateway"] = bird_unit_ip
        if obj.kind == "Namespace":
            namespace = obj.metadata.name
        if obj.kind == "Pod":
            pod_name = obj.metadata.name
        client.create(obj)

    external_pod = client.get(Pod, name=pod_name, namespace=namespace)
    # wait for pod to come up
    client.wait(
        Pod,
        external_pod.metadata.name,
        for_conditions=["Ready"],
        namespace=namespace,
    )
    yield external_pod

    log.info("Deleting external-gateway related resources ...")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.delete(type(obj), obj.metadata.name, namespace=obj.metadata.namespace)


@pytest.fixture(scope="module")
def annotate(client, ops_test):
    def f(obj, annotation_dict, patch_type=PatchType.STRATEGIC):
        log.info(
            f"Annotating {type(obj)} {obj.metadata.name} with {annotation_dict} ..."
        )
        obj.metadata.annotations = annotation_dict
        client.patch(
            type(obj),
            obj.metadata.name,
            obj,
            namespace=obj.metadata.namespace,
            patch_type=patch_type,
        )

    return f


@pytest.fixture()
async def network_policies(client):
    log.info("Creating network policy resources ...")
    path = Path("tests/data/network-policies.yaml")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.create(obj)

    watch = [
        client.get(Pod, name="blocked-pod", namespace="netpolicy"),
        client.get(Pod, name="allowed-pod", namespace="netpolicy"),
    ]

    pods = await wait_pod_ips(client, watch)

    yield tuple(pods)

    log.info("Deleting network policy resources ...")
    for obj in codecs.load_all_yaml(path.read_text()):
        client.delete(type(obj), obj.metadata.name, namespace=obj.metadata.namespace)

    await wait_for_removal(client, pods)
