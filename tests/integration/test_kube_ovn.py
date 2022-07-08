from math import isclose
from pathlib import Path
from lightkube import Client, codecs
from lightkube.resources.core_v1 import Pod
from lightkube.resources.apps_v1 import DaemonSet
from pytest_operator.plugin import OpsTest

import shlex
import pytest
import logging
import re
import subprocess

log = logging.getLogger(__name__)

LOW_PRIORITY_HTB = "300"
NEW_PRIORITY_HTB = "50"


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


async def test_pod_network_limits(ops_test, kubeconfig, client, iperf3_yaml_path):
    with open(iperf3_yaml_path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj)

    wait_daemonset(client, "ls1", "perf", 3)

    pods = list(client.list(Pod, namespace="ls1"))

    for pod in pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    server, test_pod, _ = pods
    namespace = server.metadata.namespace

    log.info("Annotate test pod with rate limit values...")
    rate_values = (
        'ovn.kubernetes.io/ingress_rate="10" ovn.kubernetes.io/egress_rate="5"'
    )
    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        "annotate --overwrite "
        f"pod {test_pod.metadata.name} "
        f"-n {namespace} {rate_values}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    log.info("Test ingress bandwidth...")
    ingress_bw = await run_bandwidth_test(
        ops_test, server, test_pod, namespace, kubeconfig
    )
    assert isclose(ingress_bw, 5.0, abs_tol=0.5)

    log.info("Test egress bandwidth...")
    egress_bw = await run_bandwidth_test(
        ops_test, test_pod, server, namespace, kubeconfig
    )
    assert isclose(egress_bw, 10.0, abs_tol=0.5)


@pytest.mark.skip
async def test_linux_htb_performance(ops_test, kubeconfig, client, iperf3_yaml_path):
    """
    TODO: This test is not working as intended
    and must be fixed.
    """
    with open(iperf3_yaml_path) as f:
        for obj in codecs.load_all_yaml(f):
            client.create(obj)

    wait_daemonset(client, "ls1", "perf", 3)
    pods = list(client.list(Pod, namespace="ls1"))

    for pod in pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    server, pod_prior, pod_non_prior = pods
    namespace = server.metadata.namespace
    server_ip = server.status.podIP

    log.info("Setup iperf3 servers...")
    iperf3_cmd = 'sh -c "iperf3 -s -p 5101 --daemon && iperf3 -s -p 5102 --daemon"'
    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {server.metadata.name} -n {namespace} "
        f"-- {iperf3_cmd}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to setup iperf3 servers: {(stderr or stdout).strip()}"

    log.info("Annotate client pods with QoS priority values...")
    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"annotate --overwrite pod {pod_prior.metadata.name} "
        f"-n {namespace} ovn.kubernetes.io/priority={NEW_PRIORITY_HTB}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"annotate --overwrite pod {pod_non_prior.metadata.name}"
        f"-n {namespace} ovn.kubernetes.io/priority={LOW_PRIORITY_HTB}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = []
    cmd.append(
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {pod_prior.metadata.name} "
        f"-n {namespace} "
        f'-- sh -c "iperf3 -c {server_ip} -p 5101 | tail -3"'
    )
    cmd.append(
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {pod_non_prior.metadata.name} "
        f"-n {namespace} "
        f'-- sh -c "iperf3 -c {server_ip} -p 5102 | tail -3"'
    )

    processes = []
    for c in cmd:
        p = subprocess.Popen(shlex.split(c), stdout=subprocess.PIPE)
        processes.append(p)

    results = []
    for p in processes:
        p.wait()
        out, _ = p.communicate()
        results.append(out.decode("utf-8"))

    prior_bw = parse_iperf_result(results[0])
    non_prior_bw = parse_iperf_result(results[1])

    assert prior_bw > non_prior_bw


def parse_iperf_result(output):
    # First line contains test result
    line = output.split("\n")[0]
    # Sixth value contains the average bandwidth value
    return float(re.sub(" +", " ", line).split(" ")[6])


async def run_bandwidth_test(ops_test, server, client, namespace, kubeconfig):
    server_ip = server.status.podIP

    log.info("Setup iperf3 server...")
    iperf3_cmd = "iperf3 -s -p 5101 --daemon"
    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {server.metadata.name} "
        f"-n {namespace} -- {iperf3_cmd}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to setup iperf3 server: {(stderr or stdout).strip()}"

    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {client.metadata.name} "
        f"-n {namespace} "
        f'-- sh -c "iperf3 -c {server_ip} -p 5101 | tail -3"'
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run iperf3 test: {(stdout or stderr).strip()}"

    return parse_iperf_result(stdout)


def wait_daemonset(client: Client, namespace, name, pods_ready):
    for _, obj in client.watch(
        DaemonSet, namespace=namespace, fields={"metadata.name": name}
    ):
        if obj.status is None:
            continue
        status = obj.status.to_dict()
        if status["numberReady"] == pods_ready:
            return
