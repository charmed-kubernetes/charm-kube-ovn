from pathlib import Path
from lightkube import Client
from lightkube.resources.core_v1 import Pod
from pytest_operator.plugin import OpsTest

import shlex
import os
import pytest
import logging
import re
import subprocess
import time

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


async def test_pod_network_limits(ops_test, kubeconfig, kubernetes):
    os.environ["KUBECONFIG"] = str(kubeconfig)
    resources = Path.cwd() / "tests/data/qos_daemonset.yaml"
    cmd = f"kubectl apply -f {resources}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to deploy resources: {(stderr or stdout).strip()}"

    # Sleep to wait for resources to become available
    time.sleep(60)

    server, test_pod, _ = list(kubernetes.list(Pod, namespace="ls1"))
    namespace = server.metadata.namespace

    log.info("Annotate test pod with rate limit values...")
    rate_values = (
        'ovn.kubernetes.io/ingress_rate="10" ovn.kubernetes.io/egress_rate="5"'
    )
    cmd = (
        "kubectl annotate --overwrite "
        f"pod {test_pod.metadata.name} "
        f"-n {namespace} {rate_values}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    log.info("Test ingress bandwidth...")
    ingress_bw = await run_bandwidth_test(
        ops_test, server, test_pod, namespace, kubeconfig
    )
    assert 5.0 <= ingress_bw <= 5.50

    log.info("Test egress bandwidth...")
    egress_bw = await run_bandwidth_test(
        ops_test, test_pod, server, namespace, kubeconfig
    )
    assert 10.0 <= egress_bw <= 10.50

    log.info("Clean up resources...")
    cmd = f"kubectl delete -f {resources}"
    await ops_test.run(*shlex.split(cmd))


@pytest.mark.skip
async def test_linux_htb_performance(
    ops_test: OpsTest, kubeconfig: Path, kubernetes: Client
):
    os.environ["KUBECONFIG"] = str(kubeconfig)
    resources = Path.cwd() / "tests/data/qos_daemonset.yaml"
    cmd = f"kubectl apply -f {resources}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to deploy resources: {(stderr or stdout).strip()}"

    # Sleep to wait for resources to become available
    time.sleep(60)

    server, pod_prior, pod_non_prior = list(kubernetes.list(Pod, namespace="ls1"))
    namespace = server.metadata.namespace
    server_ip = server.status.podIP

    log.info("Setup iperf3 servers...")
    iperf3_cmd = 'sh -c "iperf3 -s -p 5101 --daemon && iperf3 -s -p 5102 --daemon"'
    cmd = f"kubectl exec {server.metadata.name} -n {namespace} -- {iperf3_cmd}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to setup iperf3 servers: {(stderr or stdout).strip()}"

    log.info("Annotate client pods with QoS priority values...")
    cmd = (
        f"kubectl annotate --overwrite "
        f"pod {pod_prior.metadata.name} "
        f"-n {namespace} ovn.kubernetes.io/priority={NEW_PRIORITY_HTB}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = (
        "kubectl annotate --overwrite "
        f"pod {pod_non_prior.metadata.name}"
        f"-n {namespace} ovn.kubernetes.io/priority={LOW_PRIORITY_HTB}"
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = []
    cmd.append(
        f"kubectl exec {pod_prior.metadata.name} "
        f"-n {namespace} "
        f'-- sh -c "iperf3 -c {server_ip} -p 5101 | tail -3"'
    )
    cmd.append(
        f"kubectl exec {pod_non_prior.metadata.name} "
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

    log.info("Clean up resources...")
    cmd = f"kubectl delete -f {resources}"
    await ops_test.run(*shlex.split(cmd))

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
