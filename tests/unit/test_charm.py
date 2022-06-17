# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest.mock as mock
from pathlib import Path

import pytest
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus
import ops.testing

from charm import KubeOvnCharm

ops.testing.SIMULATE_CAN_CONNECT = True


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubeOvnCharm)
    try:
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture
def charm(harness):
    harness.begin_with_initial_hooks()
    yield harness.charm


def test_launch_initial_hooks(charm):
    assert charm.stored.kube_ovn_configured is False, "Unexpected Stored Default"
    assert charm.stored.pod_restart_needed is False, "Unexpected Stored Default"
    assert charm.unit.status == WaitingStatus("Waiting to retry configuring Kube-OVN")


@pytest.mark.skip_kubectl_mock
@pytest.mark.usefixtures
@mock.patch("charm.check_output", autospec=True)
def test_kubectl(mock_check_output, charm):
    charm.kubectl("arg1", "arg2")
    mock_check_output.assert_called_with(
        ["kubectl", "--kubeconfig", "/root/.kube/config", "arg1", "arg2"]
    )


def test_apply_crds(charm, kubectl):
    charm.apply_crds()
    assert charm.unit.status == MaintenanceStatus("Applying CRDs")
    kubectl.assert_called_once_with(charm, "apply", "-f", "templates/crd.yaml")


def test_restart_pods(charm, kubectl):
    charm.stored.pod_restart_needed = True
    kubectl.side_effect = [
        '{"items": [{"metadata": {"name": "kube-system"}}]}',
        '{"items": [{"metadata": {"name": "restartable-pod"},'
        ' "spec": {"hostNetwork": false}}]}',
        "",
    ]

    charm.restart_pods()
    assert charm.unit.status == MaintenanceStatus("Restarting pods")
    assert charm.stored.pod_restart_needed is False
    kubectl.assert_has_calls(
        [
            mock.call(charm, "get", "ns", "-o", "json"),
            mock.call(
                charm,
                "get",
                "po",
                "-n",
                "kube-system",
                "--field-selector",
                "spec.restartPolicy=Always",
                "-o",
                "json",
            ),
            mock.call(
                charm,
                "delete",
                "po",
                "-n",
                "kube-system",
                "restartable-pod",
                "--ignore-not-found",
            ),
        ]
    )


def test_replace_node_selector(harness, charm):
    harness.disable_hooks()
    config_dict = {"control-plane-node-label": "juju-charm=kubernetes-control-plane"}
    harness.update_config(config_dict)
    resource = dict(
        spec=dict(template=dict(spec=dict(nodeSelector={"kube-ovn/role": "deleteMe"})))
    )
    charm.replace_node_selector(resource)
    assert "juju-charm" in resource["spec"]["template"]["spec"]["nodeSelector"]
    assert "kube-ovn/role" not in resource["spec"]["template"]["spec"]["nodeSelector"]


def test_replace_images(harness, charm):
    harness.disable_hooks()
    config_dict = {"registry": "rocks.canonical.com:443/cdk"}
    harness.update_config(config_dict)
    resources = [
        dict(
            kind="Deployment",
            spec=dict(
                template=dict(
                    spec=dict(
                        containers=[dict(image="mcr.microsoft.com/cool/image:latest")],
                        initContainers=[
                            dict(image="mcr.microsoft.com/cooler/image:latest")
                        ],
                    )
                )
            ),
        )
    ]
    charm.replace_images(resources)
    pod_spec = resources[0]["spec"]["template"]["spec"]
    assert (
        pod_spec["containers"][0]["image"]
        == "rocks.canonical.com:443/cdk/cool/image:latest"
    )
    assert (
        pod_spec["initContainers"][0]["image"]
        == "rocks.canonical.com:443/cdk/cooler/image:latest"
    )


def test_replace_container_env_vars(charm):
    container = dict(env=[dict(name="MY_ENV", value=2)])
    env_vars = dict(MY_ENV=0)
    charm.replace_container_env_vars(container, env_vars)
    assert container["env"][0]["value"] == 0


def test_replace_container_args(charm):
    containers = [
        dict(args=["--v", "--value-arg=values"]),
        dict(command=["sleep", "--v", "--value-arg=values"]),
    ]
    args = {
        "--v": None,
        "--value-arg": "empty",
    }
    charm.replace_container_args(containers[0], args)
    charm.replace_container_args(containers[1], args)
    assert containers[0]["args"] == ["--v", "--value-arg=empty"]
    assert containers[1]["command"] == ["sleep", "--v", "--value-arg=empty"]


def test_get_container_resource(charm):
    needle = "right-container"
    haystack = dict(
        kind="Deployment",
        spec=dict(
            template=dict(
                spec=dict(
                    containers=[
                        dict(name=needle),
                        dict(name="wrong-container"),
                    ],
                )
            )
        ),
    )
    result = charm.get_container_resource(haystack, needle)
    assert result["name"] == needle


def test_get_resource(charm):
    kind = "Deployment"
    needle = "right-container"
    haystack = [
        dict(kind=kind, metadata=dict(name=needle)),
        dict(kind=kind, metadata=dict(name="wrong-resource")),
        dict(kind="DaemonSet", metadata=dict(name=needle)),
    ]
    result = charm.get_resource(haystack, kind, needle)
    assert result["kind"] == kind and result["metadata"]["name"] == needle


def test_is_kubeconfig_available(harness, charm):
    harness.disable_hooks()
    rel_id = harness.add_relation("cni", "kubernetes-control-plane")
    harness.add_relation_unit(rel_id, "kubernetes-control-plane/0")
    assert not charm.is_kubeconfig_available()

    harness.update_relation_data(
        rel_id, "kubernetes-control-plane/0", {"kubeconfig-hash": 1234}
    )
    assert charm.is_kubeconfig_available()


def test_load_manifest(charm):
    with pytest.raises(FileNotFoundError):
        charm.load_manifest("bogus.yaml")
    assert charm.load_manifest("crd.yaml")
    assert charm.load_manifest("kube-ovn.yaml")
    assert charm.load_manifest("ovn.yaml")


def test_render_manifest(charm):
    destination = Path(charm.render_manifest({}, "out.yaml"))
    assert destination.exists()
    destination.unlink()
    destination.parent.rmdir()


def test_get_ovn_node_ips(harness, charm, kubectl):
    harness.disable_hooks()
    config_dict = {"control-plane-node-label": "juju-charm=kubernetes-control-plane"}
    harness.update_config(config_dict)
    kubectl.side_effect = [
        '{"items": [{"status":{"addresses":'
        '[{"type":"InternalIP","address":"192.168.0.1"}]}}]}',
    ]
    result = charm.get_ovn_node_ips()
    assert result == ["192.168.0.1"]
    kubectl.assert_called_once_with(
        charm, "get", "node", "-l", "juju-charm=kubernetes-control-plane", "-o", "json"
    )


@pytest.mark.parametrize(
    "name, resource",
    [
        ("kube-ovn-cni", "daemonset"),
        ("kube-ovn-controller", "deployment"),
        ("ovn-central", "deployment"),
    ],
)
def test_wait_for(kubectl, charm, name, resource):
    method_name = f"wait_for_{name.replace('-','_')}"
    wait_method = getattr(charm, method_name)
    wait_method()
    assert charm.unit.status == WaitingStatus(f"Waiting for {name}")
    resource_name = f"{resource}/{name}"
    kubectl.assert_called_once_with(
        charm,
        "rollout",
        "status",
        "-n",
        "kube-system",
        resource_name,
        "--timeout",
        "300s",
    )


def test_apply_manifest(charm, kubectl):
    with mock.patch("charm.KubeOvnCharm.render_manifest") as render_manifest:
        charm.apply_manifest("any-manifest", "any-name")
    render_manifest.assert_called_once_with("any-manifest", "any-name")
    kubectl.assert_called_once_with(charm, "apply", "-f", render_manifest.return_value)


def test_check_if_pod_restart_will_be_needed(charm, kubectl):
    kubectl.return_value = ""
    assert charm.stored.pod_restart_needed is False

    charm.check_if_pod_restart_will_be_needed()
    kubectl.assert_called_once()
    assert charm.stored.pod_restart_needed is True


def test_configure_cni_relation(harness, charm):
    harness.disable_hooks()
    config_dict = {"default-cidr": "172.22.0.0/16"}
    harness.update_config(config_dict)
    rel_id = harness.add_relation("cni", "kubernetes-control-plane")
    harness.add_relation_unit(rel_id, "kubernetes-control-plane/0")

    charm.configure_cni_relation()
    assert charm.unit.status == MaintenanceStatus("Configuring CNI relation")
    assert len(harness.model.relations["cni"]) == 1
    relation = harness.model.relations["cni"][0]
    assert relation.data[charm.unit] == {
        "cidr": "172.22.0.0/16",
        "cni-conf-file": "01-kube-ovn.conflist",
    }


@mock.patch("charm.KubeOvnCharm.configure_cni_relation")
@mock.patch("charm.KubeOvnCharm.set_active_status")
def test_join_cni_relation(set_active_status, configure_cni_relation, harness, charm):
    rel_id = harness.add_relation("cni", "kubernetes-control-plane")
    harness.add_relation_unit(rel_id, "kubernetes-control-plane/0")
    set_active_status.assert_called_once_with()
    configure_cni_relation.assert_called_once_with()


@pytest.mark.parametrize("kubconfig_ready", (True, False))
@mock.patch("charm.KubeOvnCharm.configure_cni_relation", mock.MagicMock())
@mock.patch("charm.KubeOvnCharm.configure_kube_ovn")
def test_change_cni_relation(configure_kube_ovn, kubconfig_ready, harness, charm):
    rel_id = harness.add_relation("cni", "kubernetes-control-plane")
    harness.add_relation_unit(rel_id, "kubernetes-control-plane/0")
    configure_kube_ovn.return_value = kubconfig_ready
    charm.stored.kube_ovn_configured = kubconfig_ready
    harness.update_relation_data(rel_id, "kubernetes-control-plane/0", {"key": "val"})

    configure_kube_ovn.assert_called_once_with()

    if kubconfig_ready:
        assert charm.unit.status == ActiveStatus()
    else:
        assert charm.unit.status == WaitingStatus(
            "Waiting to retry configuring Kube-OVN"
        )


@mock.patch("charm.KubeOvnCharm.load_manifest")
@mock.patch("charm.KubeOvnCharm.get_ovn_node_ips")
@mock.patch("charm.KubeOvnCharm.get_resource")
@mock.patch("charm.KubeOvnCharm.get_container_resource")
@mock.patch("charm.KubeOvnCharm.replace_images")
@mock.patch("charm.KubeOvnCharm.replace_node_selector")
@mock.patch("charm.KubeOvnCharm.replace_container_args")
@mock.patch("charm.KubeOvnCharm.apply_manifest")
@mock.patch("charm.KubeOvnCharm.wait_for_kube_ovn_controller")
@mock.patch("charm.KubeOvnCharm.wait_for_kube_ovn_cni")
def test_apply_kube_ovn(
    wait_for_kube_ovn_cni,
    wait_for_kube_ovn_controller,
    apply_manifest,
    replace_container_args,
    replace_node_selector,
    replace_images,
    get_container_resource,
    get_resource,
    get_ovn_node_ips,
    load_manifest,
    charm,
    harness,
):
    # Setup
    harness.disable_hooks()
    config_dict = {
        "default-cidr": "172.22.0.0/16",
        "default-gateway": "172.22.0.1",
        "service-cidr": "10.152.183.0/24",
        "pinger-external-address": "10.152.183.1",
        "pinger-external-dns": "1.1.1.1",
    }
    harness.update_config(config_dict)
    node_ips = get_ovn_node_ips.return_value = ["1.1.1.1"]
    (
        kube_ovn_controller,
        kube_ovn_cni,
        kube_ovn_pinger,
        kube_ovn_monitor,
    ) = get_resource.side_effect = [
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
        dict(spec=dict(replicas=None)),
    ]

    (
        kube_ovn_controller_container,
        cni_server_container,
        pinger_container,
    ) = get_container_resource.side_effect = [
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
    ]

    # Test Method
    charm.apply_kube_ovn()  # Heavy mocking here suggests perhaps a refactor.

    # Assert Correct Behavior
    assert charm.unit.status == MaintenanceStatus("Applying Kube-OVN resources")

    load_manifest.assert_called_once_with("kube-ovn.yaml")
    resources = load_manifest.return_value

    get_ovn_node_ips.assert_called_once_with()

    replace_images.assert_called_once_with(resources)
    get_resource.assert_has_calls(
        [
            mock.call(resources, kind="Deployment", name="kube-ovn-controller"),
            mock.call(resources, kind="DaemonSet", name="kube-ovn-cni"),
            mock.call(resources, kind="DaemonSet", name="kube-ovn-pinger"),
            mock.call(resources, kind="Deployment", name="kube-ovn-monitor"),
        ]
    )

    get_container_resource.assert_has_calls(
        [
            mock.call(kube_ovn_controller, container_name="kube-ovn-controller"),
            mock.call(kube_ovn_cni, container_name="cni-server"),
            mock.call(kube_ovn_pinger, container_name="pinger"),
        ]
    )

    replace_container_args.assert_has_calls(
        [
            mock.call(
                kube_ovn_controller_container,
                args={
                    "--default-cidr": config_dict["default-cidr"],
                    "--default-gateway": config_dict["default-gateway"],
                    "--service-cluster-ip-range": config_dict["service-cidr"],
                },
            ),
            mock.call(
                cni_server_container,
                args={"--service-cluster-ip-range": config_dict["service-cidr"]},
            ),
            mock.call(
                pinger_container,
                args={
                    "--external-address": config_dict["pinger-external-address"],
                    "--external-dns": config_dict["pinger-external-dns"],
                },
            ),
        ]
    )

    replace_node_selector.assert_called_once_with(kube_ovn_monitor)
    assert kube_ovn_monitor["spec"]["replicas"] == len(node_ips)

    apply_manifest.assert_called_once_with(resources, "kube-ovn.yaml")
    wait_for_kube_ovn_controller.assert_called_once_with()
    wait_for_kube_ovn_cni.assert_called_once_with()


@mock.patch("charm.KubeOvnCharm.load_manifest")
@mock.patch("charm.KubeOvnCharm.get_ovn_node_ips")
@mock.patch("charm.KubeOvnCharm.get_resource")
@mock.patch("charm.KubeOvnCharm.get_container_resource")
@mock.patch("charm.KubeOvnCharm.replace_images")
@mock.patch("charm.KubeOvnCharm.replace_node_selector")
@mock.patch("charm.KubeOvnCharm.replace_container_env_vars")
@mock.patch("charm.KubeOvnCharm.apply_manifest")
@mock.patch("charm.KubeOvnCharm.wait_for_ovn_central")
def test_apply_ovn(
    wait_for_ovn_central,
    apply_manifest,
    replace_container_env_vars,
    replace_node_selector,
    replace_images,
    get_container_resource,
    get_resource,
    get_ovn_node_ips,
    load_manifest,
    charm,
):
    node_ips = get_ovn_node_ips.return_value = ["1.1.1.1"]
    ovn_central = get_resource.return_value = dict(spec=dict(replicas=None))
    charm.apply_ovn()  # Heavy mocking here suggests perhaps a refactor.

    assert charm.unit.status == MaintenanceStatus("Applying OVN resources")
    load_manifest.assert_called_once_with("ovn.yaml")
    resources = load_manifest.return_value

    get_ovn_node_ips.assert_called_once_with()

    replace_images.assert_called_once_with(resources)
    get_resource.assert_called_once_with(
        resources, kind="Deployment", name="ovn-central"
    )

    replace_node_selector.assert_called_once_with(ovn_central)
    assert ovn_central["spec"]["replicas"] == len(node_ips)

    get_container_resource.assert_called_once_with(
        ovn_central, container_name="ovn-central"
    )
    ovn_central_container = get_container_resource.return_value

    replace_container_env_vars.assert_called_once_with(
        ovn_central_container, env_vars={"NODE_IPS": ",".join(node_ips)}
    )
    apply_manifest.assert_called_once_with(resources, "ovn.yaml")
    wait_for_ovn_central.assert_called_once_with()
