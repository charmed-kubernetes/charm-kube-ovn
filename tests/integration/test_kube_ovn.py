from math import isclose
from pathlib import Path
from pytest_operator.plugin import OpsTest
from grafana import Grafana
from prometheus import Prometheus
import asyncio
import shlex
import shutil
import pytest
import logging
import json
import re
import time
from contextlib import suppress

from ipaddress import ip_address, ip_network
from lightkube.types import PatchType
from lightkube.codecs import load_all_yaml
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
    before_log,
)


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

    # Juju 3.x CLI doesn't have read access to
    # /opt/github-runner/_work/charm-kube-ovn/charm-kube-ovn/plugins/kubectl-ko
    # on GH runners. Copy it into ops_test.tmp_path which should be readable
    plugin_src = Path.cwd() / "plugins/kubectl-ko"
    plugin_path = ops_test.tmp_path / "kubectl-ko"
    shutil.copy(str(plugin_src), str(plugin_path))

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
    juju_cmd = f"deploy -m {model} {bundle} --trust " + " ".join(
        f"--overlay={f}" for f in overlays
    )

    await ops_test.juju(
        *shlex.split(juju_cmd), check=True, fail_msg="Bundle deploy failed"
    )
    await ops_test.model.block_until(
        lambda: "kube-ovn" in ops_test.model.applications, timeout=60
    )

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_kubectl_ko_plugin(ops_test):
    units = ops_test.model.applications["kube-ovn"].units
    machines = [u.machine.entity_id for u in units]
    for m in machines:
        juju_cmd = f"ssh {m} -- kubectl ko nbctl show"
        await ops_test.juju(
            *shlex.split(juju_cmd),
            check=True,
            fail_msg=f"Failed to execute kubectl-ko on machine:{m}",
        )


async def test_pod_network_limits(kubectl_exec, client, iperf3_pods, annotate):
    server, test_pod, _ = iperf3_pods
    namespace = server.metadata.namespace

    rate_values = {
        "ovn.kubernetes.io/ingress_rate": "10",
        "ovn.kubernetes.io/egress_rate": "5",
    }
    annotate(test_pod, rate_values)

    log.info("Test ingress bandwidth...")
    ingress_bw = await run_bandwidth_test(kubectl_exec, server, test_pod, namespace)
    assert isclose(ingress_bw, 5.0, abs_tol=0.5)

    log.info("Test egress bandwidth...")
    egress_bw = await run_bandwidth_test(
        kubectl_exec, server, test_pod, namespace, reverse=True
    )
    assert isclose(egress_bw, 10.0, abs_tol=0.5)


@pytest.mark.skip
async def test_linux_htb_performance(kubectl_exec, client, iperf3_pods, annotate):
    """
    TODO: This test is not working as intended
    and must be fixed.
    """

    server, pod_prior, pod_non_prior = iperf3_pods
    namespace = server.metadata.namespace
    server_ip = server.status.podIP

    log.info("Setup iperf3 servers...")
    iperf3_cmd = "iperf3 -s -p 5101 --daemon && iperf3 -s -p 5102 --daemon"
    args = server.metadata.name, namespace, iperf3_cmd
    await kubectl_exec(*args, fail_msg="Failed to setup iperf3 servers")

    new_priority_annotation = {"ovn.kubernetes.io/priority": f"{NEW_PRIORITY_HTB}"}
    annotate(pod_prior, new_priority_annotation)

    low_priority_annotation = {"ovn.kubernetes.io/priority": f"{LOW_PRIORITY_HTB}"}
    annotate(pod_non_prior, low_priority_annotation)

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


async def test_pod_netem_latency(kubectl_exec, client, iperf3_pods, annotate):
    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
        before=before_log(log, logging.INFO),
    )
    async def ping_for_latency(latency):
        log.info(f"Testing that ping latency == {latency} ...")
        stdout = await ping(kubectl_exec, pinger, pingee, namespace)
        average_latency = avg_ping_delay(stdout)
        assert isclose(average_latency, latency, rel_tol=0.05)

    # ping once before the test, as the first ping delay takes a bit,
    # but subsequent pings work as expected
    # https://wiki.linuxfoundation.org/networking/netem#how_come_first_ping_takes_longer
    await ping(kubectl_exec, pinger, pingee, namespace)

    # latency is in ms
    expected_latency = 1000
    latency_annotation = {"ovn.kubernetes.io/latency": f"{expected_latency}"}

    annotate(pinger, latency_annotation)

    await ping_for_latency(expected_latency)


async def test_pod_netem_loss(kubectl_exec, client, iperf3_pods, annotate):
    pinger, pingee, _ = iperf3_pods
    namespace = pinger.metadata.namespace

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
        before=before_log(log, logging.INFO),
    )
    async def ping_for_loss(loss):
        log.info(f"Testing that ping loss == {loss} ...")
        stdout = await ping(kubectl_exec, pinger, pingee, namespace)
        actual_loss = ping_loss(stdout)
        assert actual_loss == loss

    # Test loss before applying the annotation
    await ping_for_loss(0)

    # Annotate and test again
    expected_loss = 100
    loss_annotation = {"ovn.kubernetes.io/loss": f"{expected_loss}"}
    annotate(pinger, loss_annotation)

    await ping_for_loss(expected_loss)


async def test_acl_subnet(kubectl_exec, isolated_subnet, client, subnet_resource):
    isolated_pod, allowed_pod = isolated_subnet

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
        before=before_log(log, logging.INFO),
    )
    async def check_ping(loss):
        log.info(f"Pinging pod. Loss == {loss}")
        stdout = await ping(
            kubectl_exec, allowed_pod, isolated_pod, allowed_pod.metadata.namespace
        )
        actual_loss = ping_loss(stdout)
        assert actual_loss == loss

    await check_ping(100)

    log.info("Patching subnet with ACL rules ...")
    subnet = client.get(subnet_resource, "isolated-subnet")
    subnet.spec["acls"] = [
        {
            "action": "allow",
            "direction": "to-lport",
            "match": f"ip4.src=={allowed_pod.status.podIP} && ip4.dst=={isolated_pod.status.podIP}",
            "priority": 2222,
        }
    ]
    client.patch(
        subnet_resource,
        "isolated-subnet",
        obj=subnet,
        patch_type=PatchType.MERGE,
        force=True,
    )

    # Ping to update the ARP cache
    _ = await ping(
        kubectl_exec, allowed_pod, isolated_pod, allowed_pod.metadata.namespace
    )

    await check_ping(0)


async def test_pod_netem_limit(ops_test, client, iperf3_pods, annotate):
    expected_limit = 100
    for pod in iperf3_pods:
        # Annotate all the pods so we dont have to worry about
        # which worker node we pick to check the qdisk
        limit_annotation = {"ovn.kubernetes.io/limit": f"{expected_limit}"}
        annotate(pod, limit_annotation)

    log.info("Looking for kubernetes-worker/0 netem interface ...")
    juju_cmd = "exec --unit kubernetes-worker/0 -- ip link"
    _, stdout, __ = await ops_test.juju(
        *shlex.split(juju_cmd), fail_msg="Failed to run ip link"
    )

    interface = parse_ip_link(stdout)
    log.info(f"Checking qdisk on interface {interface} for correct limit ...")
    juju_cmd = f"exec --unit kubernetes-worker/0 -- tc qdisc show dev {interface}"
    _, stdout, __ = await ops_test.juju(
        *shlex.split(juju_cmd), fail_msg="Failed to run tc qdisc show"
    )
    actual_limit = parse_tc_show(stdout)
    assert actual_limit == expected_limit


async def test_gateway_qos(
    kubectl_exec, client, gateway_server, gateway_client_pod, worker_node, annotate
):
    namespace = gateway_client_pod.metadata.namespace

    rate_annotations = {
        "ovn.kubernetes.io/ingress_rate": "60",
        "ovn.kubernetes.io/egress_rate": "30",
    }

    annotate(worker_node, rate_annotations)

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


async def test_isolated_subnet(kubectl_exec, isolated_subnet, client, subnet_resource):
    isolated_pod, allowed_pod = isolated_subnet

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
        before=before_log(log, logging.INFO),
    )
    async def check_ping(loss):
        log.info(f"Pinging pod. Loss == {loss}")
        stdout = await ping(
            kubectl_exec, allowed_pod, isolated_pod, allowed_pod.metadata.namespace
        )
        actual_loss = ping_loss(stdout)
        assert actual_loss == loss

    await check_ping(100)

    log.info("Patching Subnet (allow 10.17.0.0/16 subnet)...")
    subnet = client.get(subnet_resource, "isolated-subnet")
    subnet.spec["allowSubnets"] = ["10.17.0.0/16"]
    client.patch(
        subnet_resource,
        "isolated-subnet",
        obj=subnet,
        patch_type=PatchType.MERGE,
        force=True,
    )

    # Ping to update the ARP cache
    _ = await ping(
        kubectl_exec, allowed_pod, isolated_pod, allowed_pod.metadata.namespace
    )

    await check_ping(0)


@pytest.fixture()
async def multi_nic_ipam(kubectl, kubectl_exec):
    manifest_path = "tests/data/test-multi-nic-ipam.yaml"
    await kubectl("apply", "-f", manifest_path)

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
    )
    async def pod_ip_addr():
        pod = "test-multi-nic-ipam"
        await kubectl_exec(pod, "default", "apt-get update")
        await kubectl_exec(pod, "default", "apt-get install -y iproute2")
        return await kubectl_exec(pod, "default", "ip -j addr")

    ip_addr_output = await pod_ip_addr()

    try:
        yield ip_addr_output
    finally:
        # net-attach-def needs to be deleted last since kube-ovn-controller
        # depends on it to properly clean up the pod and subnet
        await kubectl("delete", "pod", "test-multi-nic-ipam")
        await kubectl("delete", "subnet", "test-multi-nic-ipam")
        await kubectl("delete", "net-attach-def", "test-multi-nic-ipam")


class TCPDumpError(Exception):
    pass


@retry(
    retry=retry_if_exception_type(TCPDumpError),
    stop=stop_after_delay(60 * 10),
    wait=wait_fixed(1),
    before=before_log(log, logging.INFO),
)
async def run_tcpdump_test(ops_test, unit, interface, capture_comparator, filter=""):
    juju_cmd = f"ssh --pty=false {unit.name} -- sudo timeout 5 tcpdump -ni {interface} {filter}"
    retcode, stdout, stderr = await ops_test.juju(
        *shlex.split(juju_cmd),
        check=False,
    )

    # In GH actions, the output is in stderr and stdout is empty
    output = stdout + stderr
    # Timeout return code is 124 when command times out
    if retcode == 124:
        # Last 3 lines of stdout look like this:
        # 0 packets captured
        # 0 packets received by filter
        # 0 packets dropped by kernel
        for line in output.split("\n"):
            if "packets captured" in line:
                captured = int(line.split(" ")[0])
                if capture_comparator(captured):
                    log.info(
                        f"Comparison succeeded. Number of packets captured: {captured}"
                    )
                    return True
                else:
                    msg = f"Comparison failed. Number of packets captured: {captured}"
                    log.info(msg)
                    raise TCPDumpError(msg)

        msg = "output did not contain the number of packets captured"
        log.info(msg)
        log.info(f"stdout:\n{stdout}")
        log.info(f"stderr:\n{stderr}")
        raise TCPDumpError(msg)
    else:
        msg = f"Failed to execute sudo timeout tcpdump -ni {interface} on {unit.name}"
        log.info(msg)
        raise TCPDumpError(msg)


async def test_global_mirror(ops_test):
    kube_ovn_app = ops_test.model.applications["kube-ovn"]
    worker_app = ops_test.model.applications["kubernetes-worker"]
    worker_unit = worker_app.units[0]
    mirror_iface = "mirror0"
    # Test once before configuring the mirror, 0 packets should be captured
    assert await run_tcpdump_test(ops_test, worker_unit, mirror_iface, lambda x: x == 0)

    # Configure and test that traffic is being captured (more than 0 captured)
    # Note this will be retried a few times, as it takes a bit of time for the newly configured
    # daemonset to get restarted
    log.info("Enabling global mirror ...")
    await kube_ovn_app.set_config(
        {
            "enable-global-mirror": "true",
            "mirror-iface": mirror_iface,
        }
    )
    try:
        await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)
        assert await run_tcpdump_test(
            ops_test, worker_unit, mirror_iface, lambda x: x > 0
        )
    finally:
        log.info("Disabling global mirror ...")
        await kube_ovn_app.set_config(
            {
                "enable-global-mirror": "false",
                "mirror-iface": mirror_iface,
            }
        )
        await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)


async def test_pod_mirror(ops_test, nginx_pods, annotate):
    async def repeated_curl(unit, ip_to_curl, wait_time):
        while True:
            log.info(f"Curling {ip_to_curl} from {unit.name}")
            retcode, stdout, stderr = await curl_from_unit(ops_test, unit, ip_to_curl)
            if retcode != 0:
                log.info(f"failed to reach {ip_to_curl} from {unit.name}")
                log.info(f"stdout: {stdout}")
                log.info(f"stderr: {stderr}")
            await asyncio.sleep(wait_time)

    kube_ovn_app = ops_test.model.applications["kube-ovn"]
    worker_app = ops_test.model.applications["kubernetes-worker"]
    mirror_iface = "mirror0"

    # For pod level mirroring, mirror-face must be set, and enable-global-mirror must be false
    # This is the default config, so resetting after the test is not necessary
    log.info("Configuring pod level mirroring ...")
    await kube_ovn_app.set_config(
        {
            "enable-global-mirror": "false",
            "mirror-iface": mirror_iface,
        }
    )
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)

    # Unlike the global test, the pod level test must check the interface of the worker unit
    # that the pod is running on.
    for pod in nginx_pods():
        host_ip = pod.status.hostIP
        pod_ip = pod.status.podIP
        # Find unit with corresponding IP
        for unit in worker_app.units:
            if await unit.get_public_address() == host_ip:
                # Need to repeatedly start curling now
                task = asyncio.ensure_future(repeated_curl(unit, pod_ip, 1))
                assert await run_tcpdump_test(
                    ops_test,
                    unit,
                    mirror_iface,
                    lambda x: x == 0,
                    filter=f"dst {pod_ip} and port 80",
                )
                annotate(pod, {"ovn.kubernetes.io/mirror": "true"})

                # Need to stop curling for at least 11 seconds to allow existing
                # flows to expire. Otherwise, the traffic may never start to
                # mirror. See https://github.com/kubeovn/kube-ovn/issues/2801
                log.warning(
                    "Working around https://github.com/kubeovn/kube-ovn/issues/2801"
                )
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
                await asyncio.sleep(20)
                task = asyncio.ensure_future(repeated_curl(unit, pod_ip, 1))

                assert await run_tcpdump_test(
                    ops_test,
                    unit,
                    mirror_iface,
                    lambda x: x > 0,
                    filter=f"dst {pod_ip} and port 80",
                )
                # stop curling
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task


class BGPError(Exception):
    pass


@retry(
    retry=retry_if_exception_type(BGPError),
    stop=stop_after_delay(60 * 10),
    wait=wait_fixed(1),
    before=before_log(log, logging.INFO),
)
async def run_bird_curl_test(ops_test, unit, ip_to_curl):
    retcode, stdout, stderr = await curl_from_unit(ops_test, unit, ip_to_curl)
    if retcode == 0:
        return True
    else:
        raise BGPError(f"failed to reach {ip_to_curl} from {unit.name}")


@pytest.mark.usefixtures("bird")
@pytest.mark.parametrize("scope", ["pod", "subnet"])
async def test_bgp(ops_test, kubectl, kubectl_get, scope):
    template_path = Path.cwd() / "tests/data/test-bgp.yaml"
    template = template_path.read_text()
    manifest = ops_test.tmp_path / "test-bgp.yaml"
    manifest_data = template.format(
        pod_annotations='annotations: {ovn.kubernetes.io/bgp: "true"}'
        if scope == "pod"
        else "",
        subnet_annotations='annotations: {ovn.kubernetes.io/bgp: "true"}'
        if scope == "subnet"
        else "",
    )
    manifest.write_text(manifest_data)

    async def cleanup():
        await kubectl("delete", "--ignore-not-found", "-f", manifest)

    await cleanup()

    await kubectl("apply", "-f", manifest)
    ips_to_curl = []
    deadline = time.time() + 600

    while time.time() < deadline:
        pod = await kubectl_get("po", "-n", "test-bgp", "nginx")
        pod_ip = pod.get("status", {}).get("podIP")
        if pod_ip:
            ips_to_curl.append(pod_ip)
            break
        log.info("Waiting for nginx pod IP")
        await asyncio.sleep(1)

    while time.time() < deadline:
        svc = await kubectl_get("svc", "-n", "test-bgp", "nginx")
        svc_ip = svc.get("spec", {}).get("clusterIP")
        if svc_ip:
            ips_to_curl.append(svc_ip)
            break
        log.info("Waiting for nginx svc IP")
        await asyncio.sleep(1)

    log.info("Verifying the following IPs are reachable from bird units ...")
    log.info(ips_to_curl)
    bird_app = ops_test.model.applications["bird"]
    for unit in bird_app.units:
        for ip in ips_to_curl:
            assert await run_bird_curl_test(ops_test, unit, ip)

    await cleanup()


async def test_network_policies(ops_test, client, kubectl_exec, network_policies):
    blocked_pod, allowed_pod = network_policies

    @retry(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(600),
        wait=wait_fixed(1),
        before=before_log(log, logging.INFO),
    )
    async def check_wget(url, client, msg):
        stdout = await wget(kubectl_exec, client, url)
        assert msg in stdout

    log.info("Checking pods connectivity...")
    for pod in network_policies:
        await check_wget("nginx.netpolicy", pod, "'index.html' saved")

    log.info("Applying NetworkPolicy...")
    path = Path("tests/data/net-policy.yaml")
    policies = load_all_yaml(path.read_text())
    for obj in policies:
        client.create(obj)

    try:
        log.info("Checking NetworkPolicy...")
        await check_wget("nginx.netpolicy", allowed_pod, "'index.html' saved")
        await check_wget("nginx.netpolicy", blocked_pod, "wget: download timed out")
    finally:
        log.info("Removing NetworkPolicy...")
        for obj in policies:
            client.delete(
                type(obj), obj.metadata.name, namespace=obj.metadata.namespace
            )


class ExternalPingError(Exception):
    pass


@retry(
    retry=retry_if_exception_type(ExternalPingError),
    stop=stop_after_delay(60 * 10),
    wait=wait_fixed(1),
    before=before_log(log, logging.INFO),
)
async def run_external_ping_test(kubectl_exec, external_gateway_pod, bird_container_ip):
    ping_cmd = f"ping -w 5 {bird_container_ip}"
    args = (
        external_gateway_pod.metadata.name,
        external_gateway_pod.metadata.namespace,
        ping_cmd,
    )
    rc, stdout, stderr = await kubectl_exec(*args, check=False)
    if rc == 0:
        return True
    else:
        raise ExternalPingError(
            f"Failed to ping {bird_container_ip} from pod {external_gateway_pod.metadata.name}"
        )


async def test_external_gateway(bird_container_ip, external_gateway_pod, kubectl_exec):
    # This tests that a pod in a subnet configured with an external gateway can reach
    # an LXD container running on a BIRD unit
    # The subnet has the IP of the bird unit configured as the external gateway IP
    # A perf pod is deployed in the subnet, and the pod pings the IP of the LXD container directly.
    # KubeOVN has no knowledge of this LXD container IP (via BGP or otherwise)
    # KubeOVN sees that the IP trying to be reached is external to its subnet, so sends the traffic to the configured
    # gateway (the bird unit)
    # Bird unit receives the traffic, and then routes it to the LXD container via the bridge network
    # Response traffic from the LXD container is then routed back to the pod via BGP (this is necessary as the subnet
    # has natOutgoing set to false, so BGP is what enables response traffic to get back to the pod)

    log.info(
        f"Pinging {bird_container_ip} from within pod {external_gateway_pod.metadata.name} in namespace "
        f"{external_gateway_pod.metadata.namespace}"
    )
    assert await run_external_ping_test(
        kubectl_exec, external_gateway_pod, bird_container_ip
    )


async def test_grafana(
    ops_test, grafana_host, grafana_password, expected_dashboard_titles
):
    # port is defined in grafana_service.yaml
    grafana = Grafana(ops_test, host=grafana_host, port=30123, pw=grafana_password)
    while not await grafana.is_ready():
        log.info("Waiting for Grafana to be ready ...")
        await asyncio.sleep(5)
    dashboards = await grafana.dashboards_all()
    actual_dashboard_titles = [dashboard["title"] for dashboard in dashboards]

    assert set(expected_dashboard_titles) == set(actual_dashboard_titles)


async def test_prometheus(ops_test, prometheus_host, expected_prometheus_metrics):
    prometheus = Prometheus(ops_test, host=prometheus_host, port=31337)

    while not await prometheus.is_ready():
        log.info("Waiting for Prometheus to be ready...")
        await asyncio.sleep(5)

    @retry(
        retry=retry_if_exception_type(AssertionError),
        wait=wait_fixed(30),
        stop=stop_after_attempt(2),
    )
    async def gather_metrics():
        metrics = await prometheus.metrics_all()
        assert set(expected_prometheus_metrics).issubset(set(metrics))

    await gather_metrics()


@pytest.mark.usefixtures("k8s_model")
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


@retry(
    retry=retry_if_exception_type(iPerfError),
    stop=stop_after_attempt(3),
    wait=wait_fixed(1),
)
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


@retry(
    retry=retry_if_exception_type(iPerfError),
    stop=stop_after_attempt(3),
    wait=wait_fixed(1),
)
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
    _, stdout, __ = await kubectl_exec(*args, check=False)
    return stdout


async def wget(kubectl_exec, client, url):
    wget_cmd = f"wget {url} -T 10"
    args = client.metadata.name, client.metadata.namespace, wget_cmd
    rc, stdout, stderr = await kubectl_exec(*args, check=False)
    if rc == 0:
        rm_cmd = "rm index.html"
        args = client.metadata.name, client.metadata.namespace, rm_cmd
        await kubectl_exec(*args, check=False)
    return stdout + stderr


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


async def curl_from_unit(ops_test, unit, ip_to_curl):
    cmd = (
        f"ssh --pty=false -m {ops_test.model_full_name} {unit.name} -- "
        f"curl --connect-timeout 5 {ip_to_curl}"
    )
    return await ops_test.juju(
        *shlex.split(cmd),
    )
