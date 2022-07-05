from pathlib import Path
from lightkube import Client
from lightkube.resources.core_v1 import Pod
from pytest_operator.plugin import OpsTest

import json
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
    time.sleep(10)

    server, test_pod, _ = list(kubernetes.list(Pod, namespace="ls1"))
    namespace = server.metadata.namespace

    log.info("Annotate test pod with rate limit values...")
    rate_values = (
        'ovn.kubernetes.io/ingress_rate="10" ovn.kubernetes.io/egress_rate="5"'
    )
    cmd = f"kubectl annotate --overwrite pod {test_pod.metadata.name} -n {namespace} {rate_values}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    log.info("Test ingress bandwidth...")
    ingress_bw = await run_bandwidth_test(ops_test, server, test_pod, namespace)
    assert 5.0 <= ingress_bw <= 5.50

    log.info("Test egress bandwidth...")
    egress_bw = await run_bandwidth_test(ops_test, test_pod, server, namespace)
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
    time.sleep(10)

    server, pod_prior, pod_non_prior = list(kubernetes.list(Pod, namespace="ls1"))
    namespace = server.metadata.namespace
    server_ip = server.status.podIP

    log.info("Setup iperf3 servers...")
    iperf3_cmd = 'sh -c "iperf3 -s -p 5101 --daemon && iperf3 -s -p 5102 --daemon"'
    cmd = f"kubectl exec {server.metadata.name} -n {namespace} -- {iperf3_cmd}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to setup iperf3 servers: {(stderr or stdout).strip()}"

    log.info("Annotate client pods with QoS priority values...")
    cmd = f"kubectl annotate --overwrite pod {pod_prior.metadata.name} -n {namespace} ovn.kubernetes.io/priority={NEW_PRIORITY_HTB}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = f"kubectl annotate --overwrite pod {pod_non_prior.metadata.name} -n {namespace} ovn.kubernetes.io/priority={LOW_PRIORITY_HTB}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to annotate pod: {(stdout or stderr).strip()}"

    cmd = []
    cmd.append(
        f'kubectl exec {pod_prior.metadata.name} -n {namespace} -- sh -c "iperf3 -c {server_ip} -p 5101 | tail -3"'
    )
    cmd.append(
        f'kubectl exec {pod_non_prior.metadata.name} -n {namespace} -- sh -c "iperf3 -c {server_ip} -p 5102 | tail -3"'
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


async def test_linux_htb_qos(ops_test, kubeconfig, kubernetes):
    os.environ["KUBECONFIG"] = str(kubeconfig)

    log.info("Deploy linux-htb test resources...")
    resources = Path.cwd() / "tests/data/htb_subnet.yaml"

    cmd = f"kubectl apply -f {resources}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert (
        rc == 0
    ), f"Failed to deploy linux-htb test resources {(stderr or stdout).strip()}"

    pods = kubernetes.list(Pod, namespace="test-htb-ns", labels={"app": "perf"})
    nodes = {p.spec.nodeName for p in pods}

    log.info("Check pods inherit the QoS value of the subnet...")
    await check_pod_htb_qos(ops_test, nodes, "prior", LOW_PRIORITY_HTB)

    log.info("Annotate pods with new priority value...")
    cmd = f"kubectl annotate --overwrite pod -n test-htb-ns -l app=perf ovn.kubernetes.io/priority={NEW_PRIORITY_HTB}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    log.info("Check pods change QoS value...")
    await check_pod_htb_qos(ops_test, nodes, "prior", NEW_PRIORITY_HTB)

    log.info("Clean up linux-htb resources...")
    cmd = f"kubectl delete -f {resources}"
    await ops_test.run(*shlex.split(cmd))


async def check_pod_htb_qos(ops_test, nodes, pod_name, priority):
    for node in nodes:
        cmd = f"kubectl ko vsctl {node} -f json list queue"
        rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
        assert rc == 0
        pods = parse_vsctl_json(stdout)
        for pod, pod_priority in pods.items():
            if pod_name in pod:
                assert pod_priority == priority


def parse_iperf_result(output):
    # First line contains test result
    line = output.split("\n")[0]
    # Sixth value contains the average bandwidth value
    return float(re.sub(" +", " ", line).split(" ")[6])


def parse_vsctl_json(raw_json):
    # vsctl returns a JSON with two fields (data and headings)
    # "data" holds the queue information.
    parsed = json.loads(raw_json)["data"]
    pods = {}

    for queue in parsed:
        # This index contains the name
        pod = queue[2][1][1][1]
        # This index contains the linux-htb QoS value
        qos_value = queue[3][1][0][1]
        pods[pod] = qos_value
    return pods


async def run_bandwidth_test(ops_test, server, client, namespace):
    server_ip = server.status.podIP

    log.info("Setup iperf3 server...")
    iperf3_cmd = "iperf3 -s -p 5101 --daemon"
    cmd = f"kubectl exec {server.metadata.name} -n {namespace} -- {iperf3_cmd}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    assert rc == 0, f"Failed to setup iperf3 server: {(stderr or stdout).strip()}"

    cmd = f'kubectl exec {client.metadata.name} -n {namespace} -- sh -c "iperf3 -c {server_ip} -p 5101 | tail -3"'
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run iperf3 test: {(stdout or stderr).strip()}"

    return parse_iperf_result(stdout)
