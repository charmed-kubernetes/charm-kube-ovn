# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing
import logging
from ipaddress import IPv4Address
from pydantic import ValidationError
from subprocess import CalledProcessError
import unittest.mock as mock
from pathlib import Path
from contextlib import ExitStack as does_not_raise
import json
import pytest
from ops.model import (
    ActiveStatus,
    MaintenanceStatus,
    WaitingStatus,
    BlockedStatus,
    ModelError,
)
import ops.testing
import ops.framework

from charm import KubeOvnCharm
from charm import SpeakerConfig

ops.testing.SIMULATE_CAN_CONNECT = True
DEFAULT_SERVICE_CIDR = "10.152.183.0/24"
DEFAULT_IMAGE_REGISTRY = "rocks.canonical.com:443/cdk"


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
    harness.disable_hooks()
    harness.set_leader(True)
    harness.enable_hooks()
    yield harness.charm


def test_launch_initial_hooks(charm):
    assert charm.stored.kube_ovn_configured is False, "Unexpected Stored Default"
    assert charm.stored.pod_restart_needed is False, "Unexpected Stored Default"
    assert charm.unit.status == WaitingStatus("Waiting for CNI relation")


@pytest.mark.skip_kubectl_mock
@pytest.mark.usefixtures
@mock.patch("charm.check_output", autospec=True)
def test_kubectl(mock_check_output, charm):
    charm.kubectl("arg1", "arg2")
    mock_check_output.assert_called_with(
        ["kubectl", "--kubeconfig", "/root/.kube/config", "arg1", "arg2"]
    )


@mock.patch("charm.KubeOvnCharm.configure_cni_relation")
@mock.patch("charm.KubeOvnCharm.configure_kube_ovn")
def test_config_change(configure_kube_ovn, configure_cni_relation, charm, harness):
    configure_kube_ovn.return_value = True
    charm.stored.kube_ovn_configured = True
    config_dict = {"control-plane-node-label": "juju-charm=kubernetes-control-plane"}
    harness.update_config(config_dict)
    configure_cni_relation.assert_called_once()
    configure_kube_ovn.assert_called_once()
    assert charm.unit.status == ActiveStatus()


def test_apply_crds(charm, kubectl):
    charm.apply_crds()
    assert charm.unit.status == MaintenanceStatus("Applying CRDs")
    kubectl.assert_called_once_with(
        charm, "apply", "-f", "templates/kube-ovn/kube-ovn-crd.yaml"
    )


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


def test_set_node_selector(harness, charm):
    config_dict = {"control-plane-node-label": "juju-charm=kubernetes-control-plane"}
    resource = dict(
        spec=dict(template=dict(spec=dict(nodeSelector={"kube-ovn/role": "deleteMe"})))
    )
    charm.set_node_selector(
        resource, config_dict["control-plane-node-label"], replace="kube-ovn/role"
    )
    assert "juju-charm" in resource["spec"]["template"]["spec"]["nodeSelector"]
    assert "kube-ovn/role" not in resource["spec"]["template"]["spec"]["nodeSelector"]


def test_replace_images(harness, charm):
    harness.disable_hooks()
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
    charm.replace_images(resources, DEFAULT_IMAGE_REGISTRY)
    pod_spec = resources[0]["spec"]["template"]["spec"]
    assert (
        pod_spec["containers"][0]["image"]
        == "rocks.canonical.com:443/cdk/cool/image:latest"
    )
    assert (
        pod_spec["initContainers"][0]["image"]
        == "rocks.canonical.com:443/cdk/cooler/image:latest"
    )


def test_replace_name(charm):
    resource = dict(metadata={"name": "replace-me"})
    charm.replace_name(resource, "new-name")
    assert "new-name" in resource["metadata"]["name"]
    assert "replace-me" not in resource["metadata"]["name"]


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
        rel_id, "kubernetes-control-plane/0", {"kubeconfig-hash": "1234"}
    )
    assert charm.is_kubeconfig_available()


def test_get_service_cidr(harness, charm):
    harness.disable_hooks()
    rel_id = harness.add_relation("kube-ovn", "kube-ovn")
    harness.add_relation_unit(rel_id, "kube-ovn/0")
    assert not charm.kube_ovn_peer_data("service-cidr")

    harness.update_relation_data(
        rel_id,
        "kube-ovn/0",
        {"service-cidr": DEFAULT_SERVICE_CIDR},
    )
    assert charm.kube_ovn_peer_data("service-cidr") == DEFAULT_SERVICE_CIDR

    harness.add_relation_unit(rel_id, "kube-ovn/1")
    harness.update_relation_data(
        rel_id,
        "kube-ovn/1",
        {"service-cidr": "unspeakable-horror"},
    )
    assert charm.kube_ovn_peer_data("service-cidr") is None


def test_get_registry(harness, charm):
    harness.disable_hooks()
    config_dict = {"image-registry": ""}
    harness.update_config(config_dict)
    rel_id = harness.add_relation("kube-ovn", "kube-ovn")
    harness.add_relation_unit(rel_id, "kube-ovn/0")
    assert not charm.get_registry()

    harness.update_relation_data(
        rel_id,
        "kube-ovn/0",
        {"image-registry": DEFAULT_IMAGE_REGISTRY},
    )
    assert charm.get_registry() == DEFAULT_IMAGE_REGISTRY

    harness.add_relation_unit(rel_id, "kube-ovn/1")
    harness.update_relation_data(
        rel_id,
        "kube-ovn/1",
        {"image-registry": "unspeakable-horror"},
    )
    assert charm.get_registry() is None

    config_dict = {"image-registry": "some.registry.com:443/cdk"}
    harness.update_config(config_dict)
    assert charm.get_registry() == "some.registry.com:443/cdk"


def test_load_manifests(charm):
    with pytest.raises(FileNotFoundError):
        charm.load_manifests("bogus.yaml")
    assert charm.load_manifests("kube-ovn/kube-ovn.yaml")
    assert charm.load_manifests("kube-ovn/ovn.yaml")


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
    method_name = f"wait_for_{name.replace('-', '_')}"
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
        "1s",
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
    harness.update_relation_data(
        rel_id,
        "kubernetes-control-plane/0",
        {"key": "val", "service-cidr": DEFAULT_SERVICE_CIDR},
    )

    configure_kube_ovn.assert_called_once_with()

    if kubconfig_ready:
        assert charm.unit.status == ActiveStatus()
    else:
        assert charm.unit.status == WaitingStatus("Waiting for CNI relation")


@pytest.mark.parametrize("kubconfig_ready", (True, False))
@mock.patch("charm.KubeOvnCharm.configure_kube_ovn")
def test_change_kube_ovn_relation(configure_kube_ovn, kubconfig_ready, harness, charm):
    rel_id = harness.add_relation("kube-ovn", "kube-ovn/1")
    harness.add_relation_unit(rel_id, "kube-ovn/1")
    configure_kube_ovn.return_value = kubconfig_ready
    charm.stored.kube_ovn_configured = kubconfig_ready
    harness.update_relation_data(rel_id, "kube-ovn/1", {"key": "val"})

    configure_kube_ovn.assert_called_once_with()

    if kubconfig_ready:
        assert charm.unit.status == ActiveStatus()
    else:
        assert charm.unit.status == WaitingStatus("Waiting for CNI relation")


@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available")
@mock.patch("charm.KubeOvnCharm.get_registry")
@mock.patch("charm.KubeOvnCharm.kube_ovn_peer_data")
@mock.patch("charm.KubeOvnCharm.check_if_pod_restart_will_be_needed")
@mock.patch("charm.KubeOvnCharm.apply_crds")
@mock.patch("charm.KubeOvnCharm.apply_ovn")
@mock.patch("charm.KubeOvnCharm.apply_kube_ovn")
@mock.patch("charm.KubeOvnCharm.wait_for_ovn_central")
@mock.patch("charm.KubeOvnCharm.wait_for_kube_ovn_controller")
@mock.patch("charm.KubeOvnCharm.wait_for_kube_ovn_cni")
@mock.patch("charm.KubeOvnCharm.restart_pods")
def test_configure_kube_ovn(
    restart_pods,
    wait_for_kube_ovn_cni,
    wait_for_kube_ovn_controller,
    wait_for_ovn_central,
    apply_kube_ovn,
    apply_ovn,
    apply_crds,
    check_if_pod_restart_will_be_needed,
    kube_ovn_peer_data,
    get_registry,
    is_kubeconfig_available,
    charm,
):
    charm.stored.pod_restart_needed = True
    is_kubeconfig_available.return_value = True
    kube_ovn_peer_data.return_value = DEFAULT_SERVICE_CIDR
    get_registry.return_value = DEFAULT_IMAGE_REGISTRY
    assert not charm.stored.kube_ovn_configured

    charm.configure_kube_ovn()

    check_if_pod_restart_will_be_needed.assert_called_once_with()
    apply_crds.assert_called_once_with()
    apply_ovn.assert_called_once_with(DEFAULT_IMAGE_REGISTRY)
    apply_kube_ovn.assert_called_once_with(DEFAULT_SERVICE_CIDR, DEFAULT_IMAGE_REGISTRY)
    wait_for_ovn_central.assert_called_once_with()
    wait_for_kube_ovn_controller.assert_called_once_with()
    wait_for_kube_ovn_cni.assert_called_once_with()
    restart_pods.assert_called_once_with()
    assert charm.stored.kube_ovn_configured

    apply_crds.side_effect = CalledProcessError(1, "kubectl", stderr="kubectl failure")
    charm.configure_kube_ovn()
    assert not charm.stored.kube_ovn_configured


def test_add_container_args(charm):
    containers = [
        dict(args=["--arg0=val0"]),
        dict(command=["command", "-a"]),
    ]
    args = {
        "--arg1": "val1",
        "--arg2": "val2",
    }
    charm.add_container_args(containers[0], args)
    charm.add_container_args(containers[1], args, True)
    assert containers[0]["args"] == ["--arg0=val0", "--arg1=val1", "--arg2=val2"]
    assert containers[1]["command"] == ["command", "-a", "--arg1=val1", "--arg2=val2"]


@mock.patch("charm.KubeOvnCharm.get_ovn_node_ips")
@mock.patch("charm.KubeOvnCharm.apply_manifest")
def test_apply_kube_ovn(
    apply_manifest,
    get_ovn_node_ips,
    charm,
    harness,
):
    get_ovn_node_ips.return_value = ["1.1.1.1"]

    charm.apply_kube_ovn("10.152.183.0/24", DEFAULT_IMAGE_REGISTRY)

    assert charm.unit.status == MaintenanceStatus("Applying Kube-OVN resources")

    apply_manifest.assert_called_once()
    resources = apply_manifest.call_args.args[0]
    assert len(apply_manifest.call_args.args) == 2
    assert apply_manifest.call_args.args[1] == "kube-ovn.yaml"

    for resource in resources:
        if resource["kind"] in ["Deployment", "DaemonSet", "StatefulSet"]:
            pod_spec = resource["spec"]["template"]["spec"]
            containers = pod_spec["containers"]
            init_containers = pod_spec.get("initContainers", [])
            for container in containers + init_containers:
                assert container["image"].startswith(DEFAULT_IMAGE_REGISTRY)

    controller = charm.get_resource(
        resources, kind="Deployment", name="kube-ovn-controller"
    )
    controller_container = charm.get_container_resource(
        controller, "kube-ovn-controller"
    )
    controller_args = controller_container["args"]
    controller_env = {
        var["name"]: var["value"]
        for var in controller_container["env"]
        if "value" in var
    }
    cni = charm.get_resource(resources, kind="DaemonSet", name="kube-ovn-cni")
    cni_container = charm.get_container_resource(cni, "cni-server")
    cni_args = cni_container["args"]
    pinger = charm.get_resource(resources, kind="DaemonSet", name="kube-ovn-pinger")
    pinger_container = charm.get_container_resource(pinger, "pinger")
    pinger_args = pinger_container["args"]
    monitor = charm.get_resource(resources, kind="Deployment", name="kube-ovn-monitor")

    assert controller["spec"]["replicas"] == 1
    assert (
        controller["spec"]["template"]["spec"]["nodeSelector"]["juju-application"]
        == "kubernetes-control-plane"
    )
    assert "--default-cidr=192.168.0.0/16" in controller_args
    assert "--default-gateway=192.168.0.1" in controller_args
    assert "--service-cluster-ip-range=10.152.183.0/24" in controller_args
    assert "--node-switch-cidr=100.64.0.0/16" in controller_args
    assert "--node-switch-gateway=100.64.0.1" in controller_args
    assert controller_env["OVN_DB_IPS"] == "1.1.1.1"
    assert "--service-cluster-ip-range=10.152.183.0/24" in cni_args
    assert "--enable-mirror=false" in cni_args
    assert "--external-address=8.8.8.8" in pinger_args
    assert "--external-dns=google.com" in pinger_args
    assert monitor["spec"]["replicas"] == 1
    assert (
        monitor["spec"]["template"]["spec"]["nodeSelector"]["juju-application"]
        == "kubernetes-control-plane"
    )


@mock.patch("charm.KubeOvnCharm.get_ovn_node_ips")
@mock.patch("charm.KubeOvnCharm.apply_manifest")
def test_apply_ovn(
    apply_manifest,
    get_ovn_node_ips,
    charm,
    harness,
):
    get_ovn_node_ips.return_value = ["1.1.1.1"]

    charm.apply_ovn(DEFAULT_IMAGE_REGISTRY)

    assert charm.unit.status == MaintenanceStatus("Applying OVN resources")

    apply_manifest.assert_called_once()
    resources = apply_manifest.call_args.args[0]
    assert len(apply_manifest.call_args.args) == 2
    assert apply_manifest.call_args.args[1] == "ovn.yaml"

    for resource in resources:
        if resource["kind"] in ["Deployment", "DaemonSet", "StatefulSet"]:
            pod_spec = resource["spec"]["template"]["spec"]
            containers = pod_spec["containers"]
            init_containers = pod_spec.get("initContainers", [])
            for container in containers + init_containers:
                assert container["image"].startswith(DEFAULT_IMAGE_REGISTRY)

    ovn_central = charm.get_resource(resources, kind="Deployment", name="ovn-central")
    ovn_central_container = charm.get_container_resource(ovn_central, "ovn-central")
    ovn_central_container_env = {
        var["name"]: var["value"]
        for var in ovn_central_container["env"]
        if "value" in var
    }
    ovs_ovn = charm.get_resource(resources, kind="DaemonSet", name="ovs-ovn")
    openvswitch_container = charm.get_container_resource(ovs_ovn, "openvswitch")
    openvswitch_container_env = {
        var["name"]: var["value"]
        for var in openvswitch_container["env"]
        if "value" in var
    }

    assert ovn_central["spec"]["replicas"] == 1
    assert (
        ovn_central["spec"]["template"]["spec"]["nodeSelector"]["juju-application"]
        == "kubernetes-control-plane"
    )
    assert ovn_central_container_env["NODE_IPS"] == "1.1.1.1"
    assert openvswitch_container_env["OVN_DB_IPS"] == "1.1.1.1"


@pytest.mark.parametrize(
    "resource_name,content,expected_resource,exception",
    [
        pytest.param(
            "kubectl-ko",
            "Some content",
            "kubectl-ko",
            does_not_raise(),
            id="Resource found",
        ),
        pytest.param(
            "kubectl-ko",
            "Some content",
            "another-resource",
            pytest.raises(NameError),
            id="Resource not found",
        ),
    ],
)
def test_get_charm_resource_path(
    charm,
    harness,
    resource_name,
    expected_resource,
    content,
    exception,
):
    harness.add_resource(resource_name, content)
    with exception:
        charm.get_charm_resource_path(expected_resource)


@mock.patch("charm.KubeOvnCharm.model")
def test_get_charm_resource_path_model_error(mock_model, charm):
    mock_model.resources.fetch.side_effect = ModelError()
    with pytest.raises(ModelError):
        charm.get_charm_resource_path("kubectl-ko")


@mock.patch("charm.KubeOvnCharm.get_charm_resource_path")
@mock.patch("charm.KubeOvnCharm.get_registry")
@mock.patch("charm.os.chmod")
@mock.patch("charm.Path")
def test_install_kubectl_plugin(
    mock_path, mock_chmod, mock_get_registry, mock_get_resource, charm
):
    plugin_name = "test_plugin"
    mock_get_registry.return_value = "rocks.canonical.com:443/cdk"
    mock_get_resource.return_value.read_text.return_value = 'REGISTRY="kubeovn"'
    mock_plugin_path = mock_path("/usr/local/bin") / plugin_name

    charm.install_kubectl_plugin(plugin_name)

    mock_plugin_path.write_text.assert_called_once_with(
        'REGISTRY="rocks.canonical.com:443/cdk/kubeovn"'
    )
    mock_chmod.assert_called_once_with(mock_plugin_path, 0o755)


@pytest.mark.parametrize(
    "path,exception,log_message",
    [
        pytest.param(
            None, ModelError, "Failed to install plugin", id="Resource not available"
        ),
        pytest.param(
            None, NameError, "Failed to install plugin", id="Resource not found"
        ),
        pytest.param(
            "/home/test/plugin",
            OSError,
            "Failed to copy plugin",
            id="Failed to access location",
        ),
    ],
)
@mock.patch("charm.KubeOvnCharm.get_charm_resource_path")
@mock.patch("charm.KubeOvnCharm.get_registry")
@mock.patch("charm.os.chmod", mock.MagicMock())
def test_install_kubectl_plugin_raises(
    mock_get_registry, mock_get_resource, path, exception, log_message, charm, caplog
):
    mock_get_registry.return_value = "rocks.canonical.com:443/cdk"
    mock_get_resource.side_effect = exception
    mock_get_resource.return_value = path

    charm.install_kubectl_plugin("test_plugin")

    assert log_message in caplog.text


@mock.patch("charm.os.remove")
def test_remove_kubectl_plugin(mock_remove, charm):
    plugin_name = "test_plugin"
    path = Path("/usr/local/bin") / plugin_name

    charm.remove_kubectl_plugin(plugin_name)

    mock_remove.assert_called_once_with(path)


@mock.patch("charm.os.remove")
def test_remove_kubectl_plugin_raises(mock_remove, charm, caplog):
    mock_remove.side_effect = OSError
    charm.remove_kubectl_plugin("test_plugin")

    assert "Failed to remove plugin" in caplog.text


@mock.patch("charm.KubeOvnCharm.remove_kubectl_plugin")
def test_on_remove(mock_remove, charm, harness):
    charm.on_remove("mock_event")
    mock_remove.assert_called_once_with("kubectl-ko")


@pytest.mark.parametrize("kube_ovn_configured", [False, True])
@mock.patch("charm.KubeOvnCharm.configure_kube_ovn")
@mock.patch("charm.KubeOvnCharm.set_active_status")
def test_on_update_status(
    set_active_status, configure_kube_ovn, charm, harness, kube_ovn_configured
):
    charm.stored.kube_ovn_configured = kube_ovn_configured
    charm.on_update_status("mock_event")
    if kube_ovn_configured:
        configure_kube_ovn.assert_not_called()
    else:
        configure_kube_ovn.assert_called_once_with()
    set_active_status.assert_called_once_with()


@pytest.mark.parametrize("agent_configured", [False, True])
@mock.patch("charm.KubeOvnCharm.patch_prometheus_resources")
@mock.patch("charm.KubeOvnCharm.render_template")
def test_apply_grafana_agent(
    mock_render, mock_patch, kubectl, harness, agent_configured
):
    patch_res = [
        {"kind": "deployment", "name": "kube-ovn-monitor", "port": 10661},
        {"kind": "daemonset", "name": "kube-ovn-pinger", "port": 8080},
        {"kind": "deployment", "name": "kube-ovn-controller", "port": 10660},
        {"kind": "daemonset", "name": "kube-ovn-cni", "port": 10665},
    ]
    mock_render.return_value = "templates/test.yaml"
    harness.disable_hooks()
    harness.begin()
    harness.set_leader(True)
    harness.charm.stored = ops.framework.StoredState()
    harness.charm.stored.prometheus_patched = (
        harness.charm.stored.grafana_agent_configured
    ) = agent_configured
    harness.charm.stored.grafana_namespace = "kube-ovn-grafana-agent"

    harness.charm.apply_grafana_agent("prometheus.local/api/v1")

    kubectl_calls = []
    if agent_configured:
        mock_patch.assert_not_called()
        kubectl_calls.append(
            mock.call(harness.charm, "delete", "-f", mock_render.return_value)
        )
    else:
        mock_patch.assert_called_once_with(patch_res, "kube-system")
        kubectl_calls.append(
            mock.call(harness.charm, "create", "namespace", "kube-ovn-grafana-agent")
        )
    kubectl_calls.append(
        mock.call(harness.charm, "apply", "-f", mock_render.return_value)
    )
    kubectl_calls.append(
        mock.call(harness.charm, "apply", "-f", mock_render.return_value),
    )
    kubectl.assert_has_calls(kubectl_calls)


@mock.patch("charm.KubeOvnCharm.install_kubectl_plugin")
def test_on_upgrade(mock_install, charm, harness):
    charm.on_upgrade_charm("mock_event")
    mock_install.assert_called_once_with("kubectl-ko")


@mock.patch("charm.KubeOvnCharm.install_kubectl_plugin", mock.MagicMock())
def test_grafana_dashboards(harness):
    # Test that the files in src/grafana_dashboards are being passed as relation data
    harness.set_leader(True)
    harness.begin_with_initial_hooks()
    relation_id = harness.add_relation("grafana-dashboard", "grafana-k8s")
    data = harness.get_relation_data(relation_id, "kube-ovn")
    dashboards_json = data["dashboards"]
    dashboards = json.loads(dashboards_json)
    templates = dashboards["templates"]
    grafana_dir = Path("src/grafana_dashboards")
    grafana_files = [p.name for p in grafana_dir.iterdir() if p.is_file()]
    expected_keys = []
    for file_with_extension in grafana_files:
        if file_with_extension.endswith(".json"):
            name_only = file_with_extension[:-5]
            key = "file:" + name_only
            expected_keys.append(key)

    assert set(expected_keys) == set(templates.keys())


@pytest.mark.parametrize("leader", [True, False])
@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", return_value=True)
@mock.patch("charm.KubeOvnCharm.apply_grafana_agent")
def test_remote_write_consumer_changed(
    apply_grafana_agent, mock_kubeconfig, harness, leader
):
    harness.set_leader(leader)
    rel_id = harness.add_relation("send-remote-write", "prometheus-k8s")
    harness.add_relation_unit(rel_id, "prometheus/0")
    remote_write_data = {"url": "prometheus.local:8080/api/v1"}
    harness.update_relation_data(
        rel_id,
        "prometheus/0",
        {"remote_write": json.dumps(remote_write_data)},
    )

    harness.begin_with_initial_hooks()

    assert harness.charm.remote_write_consumer.endpoints == [remote_write_data]
    if leader:
        apply_grafana_agent.assert_has_calls(
            [
                mock.call([remote_write_data]),
                mock.call([remote_write_data]),
            ]
        )
    else:
        apply_grafana_agent.assert_not_called()


@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", return_value=False)
@mock.patch("charm.KubeOvnCharm.apply_grafana_agent")
def test_remote_write_consumer_changed_kubeconfig_unavailable(
    apply_grafana_agent,
    mock_kubeconfig,
    harness,
):
    harness.set_leader(True)
    harness.disable_hooks()
    harness.begin()
    rel_id = harness.add_relation("send-remote-write", "prometheus-k8s")
    harness.add_relation_unit(rel_id, "prometheus/0")
    remote_write_data = {"url": "prometheus.local:8080/api/v1"}
    harness.update_relation_data(
        rel_id,
        "prometheus/0",
        {"remote_write": json.dumps(remote_write_data)},
    )
    mock_event = mock.MagicMock()

    charm = harness.charm
    charm.remote_write_consumer_changed(mock_event)

    assert harness.charm.remote_write_consumer.endpoints == [remote_write_data]

    apply_grafana_agent.assert_not_called()
    mock_event.defer.assert_called_once()


@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", return_value=True)
@mock.patch("charm.KubeOvnCharm.apply_grafana_agent")
def test_remote_write_consumer_changed_exception(
    apply_grafana_agent,
    mock_kubeconfig,
    harness,
):
    harness.set_leader(True)
    harness.disable_hooks()
    harness.begin()
    rel_id = harness.add_relation("send-remote-write", "prometheus-k8s")
    harness.add_relation_unit(rel_id, "prometheus/0")
    remote_write_data = {"url": "prometheus.local:8080/api/v1"}
    harness.update_relation_data(
        rel_id,
        "prometheus/0",
        {"remote_write": json.dumps(remote_write_data)},
    )
    mock_event = mock.MagicMock()

    charm = harness.charm
    apply_grafana_agent.side_effect = CalledProcessError(1, "foo")
    charm.remote_write_consumer_changed(mock_event)

    assert harness.charm.remote_write_consumer.endpoints == [remote_write_data]

    mock_event.defer.assert_called_once()


@pytest.mark.parametrize("leader", [True, False])
@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", mock.Mock(return_value=True))
@mock.patch("charm.KubeOvnCharm.set_active_status")
@mock.patch("charm.KubeOvnCharm.remove_grafana_agent")
def test_on_send_remote_write_departed(
    remove_grafana_agent, set_active_status, harness, leader
):
    harness.begin()
    harness.disable_hooks()
    harness.set_leader(leader)
    harness.charm.stored = ops.framework.StoredState()
    harness.charm.stored.grafana_agent_configured = True
    mock_event = mock.MagicMock()
    harness.charm.on_send_remote_write_departed(mock_event)

    if leader:
        remove_grafana_agent.assert_called_once_with()
        set_active_status.assert_called_once_with()
    else:
        remove_grafana_agent.assert_not_called()


@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", return_value=False)
@mock.patch("charm.KubeOvnCharm.remove_grafana_agent")
def test_on_send_remote_write_departed_kubeconfig_unavailable(
    mock_remove,
    mock_kubeconfig,
    harness,
):
    harness.set_leader(True)
    harness.begin_with_initial_hooks()
    harness.charm.stored = ops.framework.StoredState()
    harness.charm.stored.grafana_agent_configured = True
    mock_event = mock.MagicMock()
    harness.charm.on_send_remote_write_departed(mock_event)

    mock_event.defer.assert_called_once()
    mock_remove.assert_not_called()


@mock.patch("charm.KubeOvnCharm.is_kubeconfig_available", return_value=True)
@mock.patch("charm.KubeOvnCharm.remove_grafana_agent")
def test_on_send_remote_write_departed_exception(
    mock_remove,
    mock_kubeconfig,
    harness,
):
    harness.set_leader(True)
    harness.begin_with_initial_hooks()
    harness.charm.stored = ops.framework.StoredState()
    harness.charm.stored.grafana_agent_configured = True
    mock_event = mock.MagicMock()
    mock_remove.side_effect = CalledProcessError(1, "cmd")
    harness.charm.on_send_remote_write_departed(mock_event)

    mock_event.defer.assert_called_once()
    mock_remove.assert_called_once()


@mock.patch("charm.KubeOvnCharm.patch_prometheus_resources")
def test_remove_grafana_agent(mock_patch, charm, kubectl):
    patched_resources = [
        {"kind": "deployment", "name": "kube-ovn-monitor", "port": 10661},
        {"kind": "daemonset", "name": "kube-ovn-pinger", "port": 8080},
        {"kind": "deployment", "name": "kube-ovn-controller", "port": 10660},
        {"kind": "daemonset", "name": "kube-ovn-cni", "port": 10665},
    ]
    charm.remove_grafana_agent()
    mock_patch.assert_called_once_with(patched_resources, "kube-system", remove=True)
    kubectl.assert_called_once_with(
        charm, "delete", "namespace", "kube-ovn-grafana-agent"
    )


def test_render_template(charm):
    destination = Path(charm.render_template("patch-prometheus.yaml"))
    assert destination.exists()
    destination.unlink()
    destination.parent.rmdir()


@pytest.mark.parametrize(
    "side_effect,exception",
    [
        pytest.param(
            None,
            does_not_raise(),
            id="Namespace found",
        ),
        pytest.param(
            CalledProcessError(
                "1",
                "kubectl"
                "Error from server (NotFound): namespaces grafana-agent not found",
            ),
            pytest.raises(CalledProcessError),
            id="Namespace not found",
        ),
    ],
)
def test_on_leader_elected(harness, kubectl, side_effect, exception):
    harness.set_leader(True)
    harness.begin()
    kubectl.side_effect = side_effect
    harness.charm.on_leader_elected("mock_event")
    if side_effect:
        assert harness.charm.stored.grafana_agent_configured is False


@pytest.mark.parametrize("remove", [True, False])
@mock.patch("charm.KubeOvnCharm.render_template")
def test_patch_prometheus_resources(mock_render, charm, kubectl, remove):
    mock_render.return_value = "templates/rendered/patch-prometheus_rendered.yaml"
    test_resources = [
        {"kind": "deployment", "name": "test-deployment1", "port": 8080},
        {"kind": "daemonset", "name": "test-daemon-set", "port": 8081},
    ]
    charm.patch_prometheus_resources(test_resources, "kube-system", remove=remove)
    if remove:
        mock_render_calls = [
            mock.call("patch-prometheus.yaml", scrape="null", port="null", remove=True)
        ]
    else:
        mock_render_calls = [
            mock.call(
                "patch-prometheus.yaml", scrape=True, port=res["port"], remove=False
            )
            for res in test_resources
        ]
    mock_render.assert_has_calls(mock_render_calls)

    kubectl_calls = [
        mock.call(
            charm,
            "patch",
            res["kind"],
            "-n",
            "kube-system",
            res["name"],
            "--patch-file",
            mock_render.return_value,
        )
        for res in test_resources
    ]
    kubectl.assert_has_calls(kubectl_calls)


@mock.patch("charm.KubeOvnCharm.load_manifests")
@mock.patch("charm.KubeOvnCharm.get_resource")
@mock.patch("charm.KubeOvnCharm.get_container_resource")
@mock.patch("charm.KubeOvnCharm.replace_images")
@mock.patch("charm.KubeOvnCharm.set_node_selector")
@mock.patch("charm.KubeOvnCharm.replace_name")
@mock.patch("charm.KubeOvnCharm.add_container_args")
@mock.patch("charm.KubeOvnCharm.replace_container_args")
@mock.patch("charm.KubeOvnCharm.apply_manifest")
def test_apply_speaker(
    apply_manifest,
    replace_container_args,
    add_container_args,
    replace_name,
    set_node_selector,
    replace_images,
    get_container_resource,
    get_resource,
    load_manifests,
    charm,
):
    # Setup
    speaker_dict = {
        "name": "my-speaker",
        "node-selector": "juju-application=kubernetes-worker",
        "neighbor-address": "10.32.32.1",
        "neighbor-as": 65030,
        "cluster-as": 65000,
        "announce-cluster-ip": True,
        "log-level": 5,
    }

    parsed_speaker_config = SpeakerConfig(**speaker_dict)
    (kube_ovn_speaker,) = get_resource.side_effect = [
        mock.MagicMock(),
    ]

    (kube_ovn_speaker_container,) = get_container_resource.side_effect = [
        mock.MagicMock(),
    ]

    # Test Method
    charm.apply_speaker(DEFAULT_IMAGE_REGISTRY, parsed_speaker_config)

    # Assert Correct Behavior
    assert charm.unit.status == MaintenanceStatus("Applying Speaker resource")

    load_manifests.assert_called_once_with("kube-ovn/speaker.yaml")
    resources = load_manifests.return_value
    replace_images.assert_called_once_with(resources, DEFAULT_IMAGE_REGISTRY)
    get_resource.assert_called_once_with(
        resources, kind="DaemonSet", name="kube-ovn-speaker"
    )

    get_container_resource.assert_called_once_with(
        kube_ovn_speaker, container_name="kube-ovn-speaker"
    )

    replace_container_args.assert_called_once_with(
        kube_ovn_speaker_container,
        args={
            "--neighbor-address": IPv4Address("10.32.32.1"),
            "--neighbor-as": 65030,
            "--cluster-as": 65000,
        },
    )

    add_container_args.assert_called_once_with(
        kube_ovn_speaker_container,
        args={
            "--announce-cluster-ip": True,
            "--v": 5,
        },
    )

    set_node_selector.assert_called_once_with(
        kube_ovn_speaker,
        "juju-application=kubernetes-worker",
        replace="ovn.kubernetes.io/bgp",
    )
    replace_name.assert_called_once_with(kube_ovn_speaker, "my-speaker")
    apply_manifest.assert_called_once_with(resources, "my-speaker.speaker.yaml")

    # Also try with a config that does not provide the announce-cluster-ip or log-level keys
    (kube_ovn_speaker,) = get_resource.side_effect = [
        mock.MagicMock(),
    ]

    (kube_ovn_speaker_container,) = get_container_resource.side_effect = [
        mock.MagicMock(),
    ]
    add_container_args.reset_mock()
    speaker_dict = {
        "name": "my-speaker",
        "node-selector": "juju-application=kubernetes-worker",
        "neighbor-address": "10.32.32.1",
        "neighbor-as": 65030,
        "cluster-as": 65000,
    }

    parsed_speaker_config = SpeakerConfig(**speaker_dict)
    charm.apply_speaker(DEFAULT_IMAGE_REGISTRY, parsed_speaker_config)
    add_container_args.assert_called_once_with(
        kube_ovn_speaker_container,
        args={
            "--announce-cluster-ip": False,
            "--v": 2,
        },
    )


@pytest.mark.parametrize(
    "test_input, expected_msgs",
    [
        (
            {"name": ""},
            [
                "name\n  string does not match regex",
            ],
        ),
        ({"neighbor-as": 0}, ["neighbor-as\n  ensure this value is greater than 0"]),
        ({"cluster-as": 0}, ["cluster-as\n  ensure this value is greater than 0"]),
        (
            {"neighbor-as": 65536},
            ["neighbor-as\n  ensure this value is less than 65536"],
        ),
        ({"cluster-as": 65536}, ["cluster-as\n  ensure this value is less than 65536"]),
        (
            {"neighbor-address": "invalidIP"},
            ["neighbor-address\n  value is not a valid IPv4 or IPv6 address"],
        ),
        (
            {},
            [
                "name\n  field required",
                "node-selector\n  field required",
                "neighbor-address\n  field required",
                "neighbor-as\n  field required",
                "cluster-as\n  field required",
            ],
        ),
        (
            {"node-selector": "key value"},
            ["node-selector\n  string does not match regex"],
        ),
        (
            {"log-level": "-1"},
            ["log-level\n  ensure this value is greater than -1"],
        ),
    ],
)
def test_speaker_config_validation(test_input, expected_msgs):
    with pytest.raises(ValidationError) as excinfo:
        SpeakerConfig(**test_input)
    for msg in expected_msgs:
        assert msg in str(excinfo.value)


@mock.patch("charm.KubeOvnCharm.apply_speaker")
@mock.patch("charm.KubeOvnCharm.remove_speakers")
def test_apply_speakers(remove_speakers, apply_speaker, harness, charm, caplog):
    # Setup
    harness.disable_hooks()
    config_dict = {
        "bgp-speakers": """- name: my-speaker
  node-selector: juju-application=kubernetes-worker
  neighbor-address: '10.32.32.1'
  neighbor-as: 65030
  cluster-as: 65000
  announce-cluster-ip: true
  log-level: 5""",
    }
    harness.update_config(config_dict)
    charm.apply_speakers(DEFAULT_IMAGE_REGISTRY)
    remove_speakers.assert_called_once()
    apply_speaker(
        DEFAULT_IMAGE_REGISTRY,
        SpeakerConfig.construct(
            name="my-speaker",
            node_selector="juju-application=kubernetes-worker",
            neighbor_address=IPv4Address("10.32.32.1"),
            neighbor_as=65030,
            cluster_as=65000,
            announce_cluster_ip=True,
            log_level=5,
        ),
    )

    # Try with empty config option
    apply_speaker.reset_mock()
    config_dict = {
        "bgp-speakers": "",
    }
    harness.update_config(config_dict)
    charm.apply_speakers(DEFAULT_IMAGE_REGISTRY)
    apply_speaker.assert_not_called()

    # Try with an invalid config option
    apply_speaker.reset_mock()
    config_dict = {
        "bgp-speakers": """- name:
  node-selector: juju-application=kubernetes-worker
  neighbor-address: '10.32.32.1'
  neighbor-as: -2
  cluster-as: -2
  announce-cluster-ip: true
  log-level: -2""",
    }
    harness.update_config(config_dict)
    with caplog.at_level(logging.ERROR):
        charm.apply_speakers(DEFAULT_IMAGE_REGISTRY)
    apply_speaker.assert_not_called()
    assert "Error validating bgp-speakers config:" in caplog.text
    assert charm.unit.status == BlockedStatus("Error validating bgp-speakers config")


@pytest.mark.parametrize("leader", [True, False])
@mock.patch("charm.os.path.isdir")
@mock.patch("charm.os.listdir")
@mock.patch("charm.os.remove")
def test_remove_speakers(remove, listdir, isdir, kubectl, harness, leader, caplog):
    harness.set_leader(leader)
    harness.begin()
    listdir.return_value = [
        "somefile.yaml",
        "one.speaker.yaml",
        "two.speaker.yaml",
        "otherfile.yaml",
    ]
    isdir.return_value = True
    harness.charm.remove_speakers()
    if leader:
        assert len(kubectl.call_args_list) == 2
        kubectl.assert_has_calls(
            [
                mock.call(
                    harness.charm, "delete", "-f", "templates/rendered/one.speaker.yaml"
                ),
                mock.call(
                    harness.charm, "delete", "-f", "templates/rendered/two.speaker.yaml"
                ),
            ]
        )
    else:
        kubectl.assert_not_called()

    remove.assert_has_calls(
        [
            mock.call("templates/rendered/one.speaker.yaml"),
            mock.call("templates/rendered/two.speaker.yaml"),
        ]
    )

    # Test the kubectl failure path
    if leader:
        kubectl.side_effect = CalledProcessError(1, "error")
        with caplog.at_level(logging.INFO):
            harness.charm.remove_speakers()
        assert "Error removing speaker daemonset" in caplog.text

    # Test the os.remove failure path
    remove.side_effect = FileNotFoundError("error")
    with caplog.at_level(logging.INFO):
        harness.charm.remove_speakers()
    assert "Error deleting rendered yaml" in caplog.text
