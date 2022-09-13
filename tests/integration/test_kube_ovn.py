from math import isclose
from pathlib import Path
from pytest_operator.plugin import OpsTest
from grafana import Grafana
from prometheus import Prometheus
import asyncio
import shlex
import pytest
import logging
import time
import json
import re

from ipaddress import ip_address, ip_network
from retry import async_retry


log = logging.getLogger(__name__)

LOW_PRIORITY_HTB = "300"
NEW_PRIORITY_HTB = "50"
PING_LATENCY_RE = re.compile(r"(?:(\d+.\d+)\/?)")
PING_LOSS_RE = re.compile(r"(?:([\d\.]+)% packet loss)")


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest):
    log.info("Build charm...")
    charm = await ops_test.build_charm(".")

    plugin_path = Path.cwd() / "plugins/kubectl-ko"

    overlays = [
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
        Path("tests/data/vsphere-overlay.yaml"),
    ]

    log.info("Rendering overlays...")
    bundle, *overlays = await ops_test.async_render_bundles(
        *overlays, charm=charm, plugin=plugin_path
    )

    log.info("Deploy charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} --trust " + " ".join(
        f"--overlay={f}" for f in overlays
    )

    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    await ops_test.model.block_until(
        lambda: "kube-ovn" in ops_test.model.applications, timeout=60
    )

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_kubectl_ko_plugin(ops_test):
    units = ops_test.model.applications["kube-ovn"].units
    machines = [u.machine.entity_id for u in units]
    for m in machines:
        cmd = f"juju ssh {m} -- kubectl ko nbctl show"
        await ops_test.run(
            *shlex.split(cmd),
            check=True,
            fail_msg=f"Failed to execute kubectl-ko on machine:{m}",
        )


async def test_pod_network_limits(kubectl_exec, client, iperf3_pods):
    server, test_pod, _ = iperf3_pods
    namespace = server.metadata.namespace

    rate_values = {
        "ovn.kubernetes.io/ingress_rate": "10",
        "ovn.kubernetes.io/egress_rate": "5",
    }
    await annotate_obj(client, test_pod, rate_values)

    log.info("Test ingress bandwidth...")
    ingress_bw = await run_bandwidth_test(kubectl_exec, server, test_pod, namespace)
    assert isclose(ingress_bw, 5.0, abs_tol=0.5)

    log.info("Test egress bandwidth...")
    egress_bw = await run_bandwidth_test(
        kubectl_exec, server, test_pod, namespace, reverse=True
    )
    assert isclose(egress_bw, 10.0, abs_tol=0.5)


@pytest.mark.skip
async def test_linux_htb_performance(kubectl_exec, client, iperf3_pods):
    """
    TODO: This test is not working as intended
    and must be fixed.
    """

    server, pod_prior, pod_non_prior = iperf3_pods
    namespace = server.metadata.namespace
    server_ip = server.status.podIP

    log.info("Setup iperf3 servers...")
    iperf3_cmd = "iperf3 -s -p 5101 --daemon && iperf3 -s -p 5102 --daemon"
    rc, stdout, stderr = await kubectl_exec(server.metadata.name, namespace, iperf3_cmd)
    assert rc == 0, f"Failed to setup iperf3 servers: {(stderr or stdout).strip()}"

    new_priority_annotation = {"ovn.kubernetes.io/priority": f"{NEW_PRIORITY_HTB}"}
    await annotate_obj(client, pod_prior, new_priority_annotation)

    low_priority_annotation = {"ovn.kubernetes.io/priority": f"{LOW_PRIORITY_HTB}"}
    await annotate_obj(client, pod_non_prior, low_priority_annotation)

    results = await asyncio.gather(
        kubectl_exec(
            pod_prior.metadata.name, namespace, f"iperf3 -c {server_ip} -p 5101 -JZ"
        ),
        kubectl_exec(
            pod_non_prior.metadata.name, namespace, f"iperf3 -c {server_ip} -p 5102 -JZ"
        ),
    )

    _, prior_bw = parse_iperf_result(results[0])
    _, non_prior_bw = parse_iperf_result(results[1])

    assert prior_bw > non_prior_bw


async def test_pod_netem_latency(kubectl_exec, client, iperf3_pods):
    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    # ping once before the test, as the first ping delay takes a bit,
    # but subsequent pings work as expected
    # https://wiki.linuxfoundation.org/networking/netem#how_come_first_ping_takes_longer
    stdout = await ping(kubectl_exec, pinger, pingee, namespace)

    # latency is in ms
    latency = 1000
    latency_annotation = {"ovn.kubernetes.io/latency": f"{latency}"}
    await annotate_obj(client, pinger, latency_annotation)

    log.info("Testing ping latency ...")
    stdout = await ping(kubectl_exec, pinger, pingee, namespace)
    average_latency = avg_ping_delay(stdout)
    assert isclose(average_latency, latency, rel_tol=0.05)


async def test_pod_netem_loss(kubectl_exec, client, iperf3_pods):
    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    # Test loss before applying the annotation
    log.info("Testing ping loss ...")
    stdout = await ping(kubectl_exec, pinger, pingee, namespace)
    actual_loss = ping_loss(stdout)
    assert actual_loss == 0

    # Annotate and test again
    expected_loss = 100
    loss_annotation = {"ovn.kubernetes.io/loss": f"{expected_loss}"}
    await annotate_obj(client, pinger, loss_annotation)

    log.info("Testing ping loss ...")
    stdout = await ping(kubectl_exec, pinger, pingee, namespace)
    actual_loss = ping_loss(stdout)
    assert actual_loss == expected_loss


async def test_pod_netem_limit(ops_test, client, iperf3_pods):
    expected_limit = 100
    for pod in iperf3_pods:
        # Annotate all the pods so we dont have to worry about
        # which worker node we pick to check the qdisk
        limit_annotation = {"ovn.kubernetes.io/limit": f"{expected_limit}"}
        await annotate_obj(client, pod, limit_annotation)

    log.info("Looking for kubernetes-worker/0 netem interface ...")
    cmd = "juju run --unit kubernetes-worker/0 -- ip link"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run ip link: {(stdout or stderr).strip()}"

    interface = parse_ip_link(stdout)
    log.info(f"Checking qdisk on interface {interface} for correct limit ...")
    cmd = f"juju run --unit kubernetes-worker/0 -- tc qdisc show dev {interface}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Failed to run tc qdisc show: {(stdout or stderr).strip()}"
    actual_limit = parse_tc_show(stdout)
    assert actual_limit == expected_limit


async def test_gateway_qos(
    kubectl_exec, client, gateway_server, gateway_client_pod, worker_node
):
    namespace = gateway_client_pod.metadata.namespace

    rate_annotations = {
        "ovn.kubernetes.io/ingress_rate": "60",
        "ovn.kubernetes.io/egress_rate": "30",
    }

    await annotate_obj(client, worker_node, rate_annotations)

    # We need to wait a little bit for OVN to do its thing
    # after applying the annotations
    await asyncio.sleep(60)

    log.info("Testing node-level ingress bandwidth...")
    ingress_bw = await run_external_bandwidth_test(
        kubectl_exec,
        gateway_server,
        gateway_client_pod,
        namespace,
        reverse=True,
    )
    assert isclose(ingress_bw, 60, rel_tol=0.10)

    log.info("Testing node-level egress bandwidth...")
    egress_bw = await run_external_bandwidth_test(
        kubectl_exec, gateway_server, gateway_client_pod, namespace
    )
    assert isclose(egress_bw, 30, rel_tol=0.10)


async def test_grafana(
    ops_test, grafana_host, grafana_password, expected_dashboard_titles
):
    # port is defined in grafana_service.yaml
    grafana = Grafana(ops_test, host=grafana_host, port=30123, pw=grafana_password)
    while not await grafana.is_ready():
        log.info("Waiting for Grafana to be ready ...")
        await asyncio.sleep(5)
    dashboards = await grafana.dashboards_all()
    actual_dashboard_titles = []
    for dashboard in dashboards:
        actual_dashboard_titles.append(dashboard["title"])

    assert set(expected_dashboard_titles) == set(actual_dashboard_titles)


async def test_prometheus(ops_test, prometheus_host, expected_prometheus_metrics):
    prometheus = Prometheus(ops_test, host=prometheus_host, port=31337)
    while not await prometheus.is_ready():
        log.info("Waiting for Prometheus to be ready...")
        await asyncio.sleep(5)
    log.info("Waiting for metrics...")
    await asyncio.sleep(60)
    metrics = await prometheus.metrics_all()

    assert set(expected_prometheus_metrics).issubset(set(metrics))


@pytest.fixture()
async def multi_nic_ipam(kubectl, kubectl_exec):
    manifest_path = "tests/data/test-multi-nic-ipam.yaml"
    await kubectl("apply", "-f", manifest_path)

    @async_retry(exceptions=AssertionError, delay=1, max_seconds=600)
    async def pod_ip_addr():
        pod = "test-multi-nic-ipam"
        await kubectl_exec(pod, "default", "apt-get update")
        await kubectl_exec(pod, "default", "apt-get install -y iproute2")
        return await kubectl_exec(pod, "default", "ip -j addr")

    ip_addr_output = await pod_ip_addr()

    try:
        yield ip_addr_output
    finally:
        await kubectl("delete", "-f", manifest_path)


@pytest.mark.usefixtures("multus_installed")
async def test_multi_nic_ipam(multi_nic_ipam):
    ifaces = json.loads(multi_nic_ipam)
    iface_addrs = {
        iface["ifname"]: [
            addr for addr in iface["addr_info"] if addr["family"] == "inet"
        ]
        for iface in ifaces
    }

    assert set(iface_addrs) == set(["lo", "eth0", "net1"])

    assert len(iface_addrs["lo"]) == 1
    assert iface_addrs["lo"][0]["prefixlen"] == 8
    assert iface_addrs["lo"][0]["local"] == "127.0.0.1"

    assert len(iface_addrs["eth0"]) == 1
    assert iface_addrs["eth0"][0]["prefixlen"] == 16
    assert ip_address(iface_addrs["eth0"][0]["local"]) in ip_network("192.168.0.0/16")

    assert len(iface_addrs["net1"]) == 1
    assert iface_addrs["net1"][0]["prefixlen"] == 24
    assert ip_address(iface_addrs["net1"][0]["local"]) in ip_network("10.123.123.0/24")



class iPerfError(Exception):
    pass


def parse_iperf_result(output: str):
    """Parse output from iperf3, raise iPerfError when the data isn't valid."""
    # iperf3 output looks like this:
    # {
    #   start: {...},
    #   intervals: {...},
    #   end: {
    #     sum_sent: {
    #       streams: {...},
    #       sum_sent: {
    #         ...,
    #         bits_per_second: xxx.xxx,
    #         ...
    #       },
    #       sum_received: {...},
    #     }
    #   },
    # }

    try:
        result = json.loads(output)
    except json.decoder.JSONDecodeError as ex:
        raise iPerfError(f"Cannot parse iperf3 json results: '{output}'") from ex
    # Extract the average values in bps and convert into mbps.
    iperf_error = result.get("error")
    if iperf_error:
        raise iPerfError(f"iperf3 encountered a runtime error: {iperf_error}")

    try:
        sum_sent = float(result["end"]["sum_sent"]["bits_per_second"]) / 1e6
        sum_received = float(result["end"]["sum_received"]["bits_per_second"]) / 1e6
    except KeyError as ke:
        raise iPerfError(f"failed to find bps in result {result}") from ke

    return sum_sent, sum_received


@async_retry(exceptions=iPerfError, tries=3, logger=log)
async def run_bandwidth_test(kubectl_exec, server, client, namespace, reverse=False):
    server_ip = server.status.podIP

    log.info("Setup iperf3 internal bw test...")
    iperf3_cmd = "iperf3 -s -p 5101 --daemon"
    args = server.metadata.name, namespace, iperf3_cmd
    stdout = await kubectl_exec(*args, fail_msg="Failed to setup iperf3 server")

    reverse_flag = "-R" if reverse else ""
    iperf3_cmd = f"iperf3 -c {server_ip} {reverse_flag} -p 5101 -JZ"
    args = client.metadata.name, namespace, iperf3_cmd
    stdout = await kubectl_exec(*args, fail_msg="Failed to run iperf3 test")

    _, sum_received = parse_iperf_result(stdout)
    return sum_received


@async_retry(exceptions=iPerfError, tries=3, logger=log)
async def run_external_bandwidth_test(
    kubectl_exec, server, client, namespace, reverse=False
):
    log.info("Setup iperf3 external bw test...")
    reverse_flag = "-R" if reverse else ""
    iperf3_cmd = f"iperf3 -c {server} {reverse_flag} -JZ"
    args = client.metadata.name, namespace, iperf3_cmd
    stdout = await kubectl_exec(*args, fail_msg="Failed to run iperf3 test")
    _, sum_received = parse_iperf_result(stdout)
    return sum_received


async def ping(kubectl_exec, pinger, pingee, namespace):
    pingee_ip = pingee.status.podIP
    ping_cmd = f"ping {pingee_ip} -w 5"
    args = pinger.metadata.name, namespace, ping_cmd
    return await kubectl_exec(*args, fail_msg=f"Failed to ping {pingee_ip}")


def _ping_parse(stdout: str, line_filter: str, regex: re.Pattern, idx: int):
    # ping output looks like this:
    # PING google.com(dfw28s31-in-x0e.1e100.net (2607:f8b0:4000:818::200e))
    # 56 data bytes
    # 64 bytes from dfw28s31-in-x0e.1e100.net (2607:f8b0:4000:818::200e):
    # icmp_seq=1 ttl=115 time=518 ms
    # 64 bytes from dfw28s31-in-x0e.1e100.net (2607:f8b0:4000:818::200e):
    # icmp_seq=2 ttl=115 time=50.9 ms
    #
    # --- google.com ping statistics ---
    # 2 packets transmitted, 2 received, 0% packet loss, time 1001ms
    # rtt min/avg/max/mdev = 50.860/284.419/517.978/233.559 ms
    lines = [line for line in stdout.splitlines() if line_filter in line]
    assert len(lines) == 1, f"'{line_filter}' not found in ping response: {stdout}"
    matches = regex.findall(lines[0])
    assert (
        len(matches) > idx
    ), f"'{line_filter}' not parsable in ping response: {stdout}"
    return matches[idx]


def avg_ping_delay(stdout: str) -> float:
    return float(_ping_parse(stdout, "min/avg/max", PING_LATENCY_RE, 1))


def ping_loss(stdout: str) -> float:
    return float(_ping_parse(stdout, "packet loss", PING_LOSS_RE, 0))


def parse_ip_link(stdout):
    # ip link output looks like this:
    # 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode
    # DEFAULT group default qlen 1000
    # link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    # 2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode
    # DEFAULT group default qlen 1000
    # link/ether 00:50:56:00:fc:8c brd ff:ff:ff:ff:ff:ff

    lines = stdout.splitlines()
    netem_line = [line for line in lines if "netem" in line][0]
    # Split on @, take left side, split on :, take right side, and trim spaces
    interface = netem_line.split("@", 1)[0].split(":")[1].strip()
    return interface


def parse_tc_show(stdout):
    # tc show output looks similar to this:
    # qdisc netem 1: root refcnt 2 limit 5 delay 1.0s
    # there could be multiple lines if multiple qdiscs are present

    lines = stdout.splitlines()
    netem_line = [line for line in lines if "netem" in line][0]
    netem_split = netem_line.split(" ")
    limit_index = netem_split.index("limit")
    # Limit value directly follows the string limit
    limit_value = netem_split[limit_index + 1]
    return int(limit_value)


async def annotate_obj(client, obj, annotation_dict):
    log.info(f"Annotating {type(obj)} {obj.metadata.name} with {annotation_dict} ...")
    obj.metadata.annotations = annotation_dict
    client.patch(
        type(obj), obj.metadata.name, obj, namespace=obj.metadata.namespace, force=True
    )
