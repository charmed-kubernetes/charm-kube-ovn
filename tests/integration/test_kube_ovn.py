from math import isclose
from pathlib import Path
from lightkube.resources.core_v1 import Pod
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


async def test_pod_network_limits(ops_test, kubeconfig, client, iperf3_pods):

    for pod in iperf3_pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    server, test_pod, _ = iperf3_pods
    namespace = server.metadata.namespace

    rate_values = (
        'ovn.kubernetes.io/ingress_rate="10" ovn.kubernetes.io/egress_rate="5"'
    )
    annotate_pod(ops_test, kubeconfig, test_pod, namespace, rate_values)

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
async def test_linux_htb_performance(ops_test, kubeconfig, client, iperf3_pods):
    """
    TODO: This test is not working as intended
    and must be fixed.
    """

    for pod in iperf3_pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    server, pod_prior, pod_non_prior = iperf3_pods
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

    new_priority_annotation = f'ovn.kubernetes.io/priority="{NEW_PRIORITY_HTB}"'
    annotate_pod(ops_test, kubeconfig, pod_prior, namespace, new_priority_annotation)

    low_priority_annotation = f'ovn.kubernetes.io/priority="{LOW_PRIORITY_HTB}"'
    annotate_pod(
        ops_test, kubeconfig, pod_non_prior, namespace, low_priority_annotation
    )

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


async def test_pod_netem_latency(ops_test, kubeconfig, client, iperf3_pods):
    for pod in iperf3_pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    # latency is in ms
    latency = 1000
    latency_annotation = f'ovn.kubernetes.io/latency="{latency}"'
    annotate_pod(ops_test, kubeconfig, pinger, namespace, latency_annotation)

    log.info("Testing ping latency ...")
    stdout = await ping(ops_test, pinger, pingee, namespace, kubeconfig)
    average_latency = parse_ping_delay(stdout)
    assert isclose(average_latency, latency, rel_tol=0.05)


async def test_pod_netem_loss(ops_test, kubeconfig, client, iperf3_pods):
    for pod in iperf3_pods:
        client.wait(
            Pod,
            pod.metadata.name,
            for_conditions=["Ready"],
            namespace=pod.metadata.namespace,
        )

    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    # Test loss before applying the annotation
    log.info("Testing ping loss ...")
    stdout = await ping(ops_test, pinger, pingee, namespace, kubeconfig)
    actual_loss = parse_ping_loss(stdout)
    assert actual_loss == 0

    # Annotate and test again
    expected_loss = 100
    loss_annotation = f'ovn.kubernetes.io/loss="{expected_loss}"'
    annotate_pod(ops_test, kubeconfig, pinger, namespace, loss_annotation)

    log.info("Testing ping loss ...")
    stdout = await ping(ops_test, pinger, pingee, namespace, kubeconfig)
    actual_loss = parse_ping_loss(stdout)
    assert actual_loss == expected_loss


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


async def ping(ops_test, pinger, pingee, namespace, kubeconfig):
    pingee_ip = pingee.status.podIP

    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        f"exec {pinger.metadata.name} "
        f"-n {namespace} "
        f'-- sh -c "ping {pingee_ip} -w 5"'
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run iperf3 test: {(stdout or stderr).strip()}"

    return stdout


def parse_ping_delay(stdout):
    lines = stdout.splitlines()
    delay_line = lines[-1]
    delay_stats = delay_line.split("=")[-1]
    average_delay = delay_stats.split("/")[1]
    return average_delay


def parse_ping_loss(stdout):
    lines = stdout.splitlines()
    loss_line = lines[-2]
    loss_stats = loss_line.split(",")[2]
    loss_percentage = loss_stats.split("%")[0]
    return loss_percentage


async def annotate_pod(ops_test, kubeconfig, pod, namespace, annotation):
    log.info(f"Annotating pod {pod.metadata.name} with {annotation} ...")
    cmd = (
        f"kubectl --kubeconfig {kubeconfig} "
        "annotate --overwrite "
        f"pod {pod.metadata.name} "
        f"-n {namespace} {annotation}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"
