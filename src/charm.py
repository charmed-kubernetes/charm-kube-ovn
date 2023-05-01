#!/usr/bin/env python3

import json
import logging
import os
import traceback
import yaml
from jinja2 import Environment, FileSystemLoader

from pathlib import Path
from subprocess import CalledProcessError, check_output
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    WaitingStatus,
    BlockedStatus,
    MaintenanceStatus,
    ModelError,
)
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.prometheus_k8s.v0.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)

from pydantic import (
    BaseModel,
    IPvAnyAddress,
    ValidationError,
    Field,
)

log = logging.getLogger(__name__)

PLUGINS_PATH = "/usr/local/bin"
TMP_RENDER_PATH = "/tmp/templates/rendered"
PROMETHEUS_RESOURCES = [
    {"kind": "deployment", "name": "kube-ovn-monitor", "port": 10661},
    {"kind": "daemonset", "name": "kube-ovn-pinger", "port": 8080},
    {"kind": "deployment", "name": "kube-ovn-controller", "port": 10660},
    {"kind": "daemonset", "name": "kube-ovn-cni", "port": 10665},
]


class SpeakerConfig(BaseModel):
    name: str = Field(
        ...,
        regex="^[a-z0-9.-]+$",
    )
    node_selector: str = Field(
        ...,
        alias="node-selector",
        regex=r"^[\w./-]+=[\w.-]+$",
    )
    neighbor_address: IPvAnyAddress = Field(..., alias="neighbor-address")
    neighbor_as: int = Field(..., alias="neighbor-as", gt=0, lt=65536)
    cluster_as: int = Field(..., alias="cluster-as", gt=0, lt=65536)
    announce_cluster_ip: bool = Field(False, alias="announce-cluster-ip")
    log_level: int = Field(2, alias="log-level", gt=-1)


class KubeOvnCharm(CharmBase):
    stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.grafana_dashboard_provider = GrafanaDashboardProvider(self)
        self.remote_write_consumer = PrometheusRemoteWriteConsumer(self)
        self.jinja2_environment = Environment(loader=FileSystemLoader("templates/"))
        self.stored.set_default(kube_ovn_configured=False)
        self.stored.set_default(pod_restart_needed=False)
        self.stored.set_default(grafana_agent_configured=False)
        self.stored.set_default(prometheus_patched=False)
        self.stored.set_default(
            grafana_namespace=self.model.config["default-grafana-namespace"]
        )
        self.framework.observe(
            self.on.cni_relation_changed, self.on_cni_relation_changed
        )
        self.framework.observe(self.on.cni_relation_joined, self.on_cni_relation_joined)
        self.framework.observe(
            self.on.kube_ovn_relation_changed, self.on_kube_ovn_relation_changed
        )
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.remove, self.on_remove)
        self.framework.observe(self.on.update_status, self.on_update_status)
        self.framework.observe(self.on.upgrade_charm, self.on_upgrade_charm)
        self.framework.observe(
            self.remote_write_consumer.on.endpoints_changed,
            self.remote_write_consumer_changed,
        )
        self.framework.observe(
            self.on.send_remote_write_relation_departed,
            self.on_send_remote_write_departed,
        )
        self.framework.observe(self.on.leader_elected, self.on_leader_elected)

    def add_container_args(self, container, args, command=False):
        key = "command" if command else "args"
        container_args = container.setdefault(key, [])
        for k, v in args.items():
            container_args.append(k + "=" + str(v))

    def apply_crds(self):
        self.unit.status = MaintenanceStatus("Applying CRDs")
        self.kubectl("apply", "-f", "templates/kube-ovn/kube-ovn-crd.yaml")

    def apply_grafana_agent(self, remote_endpoints):
        namespace = self.stored.grafana_namespace
        if not self.stored.prometheus_patched:
            self.patch_prometheus_resources(PROMETHEUS_RESOURCES, "kube-system")
            self.stored.prometheus_patched = True

        agent_config = self.render_template(
            "grafana-configmap.yaml",
            juju_model=self.model.name,
            juju_model_uuid=self.model.uuid,
            juju_app=self.model.app.name,
            remote_endpoints=remote_endpoints,
            namespace=namespace,
        )
        grafana_manifest = self.render_template(
            "grafana-agent.yaml", juju_app=self.model.app.name, namespace=namespace
        )
        if self.stored.grafana_agent_configured:
            self.kubectl("delete", "-f", grafana_manifest)
        else:
            self.kubectl("create", "namespace", namespace)

        self.kubectl("apply", "-f", agent_config)
        self.kubectl("apply", "-f", grafana_manifest)

        self.stored.grafana_agent_configured = True

    def apply_kube_ovn(self, service_cidr, registry):
        self.unit.status = MaintenanceStatus("Applying Kube-OVN resources")
        resources = self.load_manifest("kube-ovn/kube-ovn.yaml")
        control_plane_node_label = self.model.config["control-plane-node-label"]
        cidr = self.model.config["default-cidr"]
        gateway = self.model.config["default-gateway"]
        pinger_address = self.model.config["pinger-external-address"]
        pinger_dns = self.model.config["pinger-external-dns"]
        node_switch_cidr = self.model.config["node-switch-cidr"]
        node_switch_gateway = self.model.config["node-switch-gateway"]
        node_ips = self.get_ovn_node_ips()
        enable_global_mirror = self.model.config["enable-global-mirror"]
        mirror_iface = self.model.config["mirror-iface"]

        self.replace_images(resources, registry)

        kube_ovn_controller = self.get_resource(
            resources, kind="Deployment", name="kube-ovn-controller"
        )
        self.set_replicas(kube_ovn_controller, len(node_ips))
        self.set_node_selector(
            kube_ovn_controller, control_plane_node_label, replace="kube-ovn/role"
        )

        kube_ovn_controller_container = self.get_container_resource(
            kube_ovn_controller, container_name="kube-ovn-controller"
        )
        self.replace_container_args(
            kube_ovn_controller_container,
            args={
                "--default-cidr": cidr,
                "--default-gateway": gateway,
                "--service-cluster-ip-range": service_cidr,
                "--node-switch-cidr": node_switch_cidr,
            },
        )
        self.replace_container_env_vars(
            kube_ovn_controller_container, env_vars={"OVN_DB_IPS": ",".join(node_ips)}
        )

        self.add_container_args(
            kube_ovn_controller_container,
            args={"--node-switch-gateway": node_switch_gateway},
        )

        kube_ovn_cni = self.get_resource(
            resources, kind="DaemonSet", name="kube-ovn-cni"
        )
        cni_server_container = self.get_container_resource(
            kube_ovn_cni, container_name="cni-server"
        )

        cni_args_to_replace = {"--service-cluster-ip-range": service_cidr}
        if enable_global_mirror and not mirror_iface:
            log.error("If enable-global-mirror is true, mirror-iface must be set")
            self.unit.status = BlockedStatus(
                "If enable-global-mirror is true, mirror-iface must be set"
            )
        else:
            # Only enable the mirror if a mirror interface is also provided
            cni_args_to_replace["--enable-mirror"] = str(enable_global_mirror).lower()
        self.replace_container_args(cni_server_container, args=cni_args_to_replace)

        cni_args_to_add = {}
        if mirror_iface:
            # The mirror interface can be enabled without enabling the global mirror above.
            cni_args_to_add["--mirror-iface"] = mirror_iface
            self.add_container_args(
                cni_server_container,
                args=cni_args_to_add,
            )

        kube_ovn_pinger = self.get_resource(
            resources, kind="DaemonSet", name="kube-ovn-pinger"
        )
        pinger_container = self.get_container_resource(
            kube_ovn_pinger, container_name="pinger"
        )
        self.replace_container_args(
            pinger_container,
            args={"--external-address": pinger_address, "--external-dns": pinger_dns},
        )

        kube_ovn_monitor = self.get_resource(
            resources, kind="Deployment", name="kube-ovn-monitor"
        )
        self.set_node_selector(
            kube_ovn_monitor,
            control_plane_node_label,
            replace="kube-ovn/role",
        )
        self.set_replicas(kube_ovn_monitor, len(node_ips))

        self.apply_manifest(resources, "kube-ovn.yaml")

    def apply_manifest(self, manifest, name):
        destination = self.render_manifest(manifest, name)
        self.kubectl("apply", "-f", destination)

    def apply_ovn(self, registry):
        self.unit.status = MaintenanceStatus("Applying OVN resources")
        resources = self.load_manifest("kube-ovn/ovn.yaml")
        node_ips = self.get_ovn_node_ips()
        self.replace_images(resources, registry)

        ovn_central = self.get_resource(
            resources, kind="Deployment", name="ovn-central"
        )
        self.set_node_selector(
            ovn_central,
            self.model.config["control-plane-node-label"],
            replace="kube-ovn/role",
        )
        self.set_replicas(ovn_central, len(node_ips))

        ovn_central_container = self.get_container_resource(
            ovn_central, container_name="ovn-central"
        )
        self.replace_container_env_vars(
            ovn_central_container, env_vars={"NODE_IPS": ",".join(node_ips)}
        )

        ovs_ovn = self.get_resource(resources, kind="DaemonSet", name="ovs-ovn")
        openvswitch_container = self.get_container_resource(
            ovs_ovn, container_name="openvswitch"
        )
        self.replace_container_env_vars(
            openvswitch_container, env_vars={"OVN_DB_IPS": ",".join(node_ips)}
        )

        self.apply_manifest(resources, "ovn.yaml")

    def apply_speaker(self, registry, speaker_config: SpeakerConfig):
        self.unit.status = MaintenanceStatus("Applying Speaker resource")
        resources = self.load_manifest("kube-ovn/speaker.yaml")
        speaker = self.get_resource(
            resources, kind="DaemonSet", name="kube-ovn-speaker"
        )
        speaker_container = self.get_container_resource(
            speaker, container_name="kube-ovn-speaker"
        )
        self.replace_container_args(
            speaker_container,
            args={
                "--neighbor-address": speaker_config.neighbor_address,
                "--neighbor-as": speaker_config.neighbor_as,
                "--cluster-as": speaker_config.cluster_as,
            },
        )
        self.add_container_args(
            speaker_container,
            args={
                "--announce-cluster-ip": speaker_config.announce_cluster_ip,
                "--v": speaker_config.log_level,
            },
        )
        self.replace_images(resources, registry)
        self.set_node_selector(
            speaker, speaker_config.node_selector, replace="ovn.kubernetes.io/bgp"
        )
        self.replace_name(speaker, speaker_config.name)
        self.apply_manifest(resources, f"{speaker_config.name}.speaker.yaml")

    def remove_speakers(self):
        log.info("Cleaning up any existing speakers ...")
        rendered_dir = "templates/rendered/"
        if os.path.isdir(rendered_dir):
            for file in os.listdir(rendered_dir):
                if file.endswith(".speaker.yaml"):
                    filepath = os.path.join(rendered_dir, file)
                    log.info(f"Removing {filepath}")
                    if self.unit.is_leader():
                        # Only need to delete the daemonset once, let the leader do it
                        try:
                            self.kubectl("delete", "-f", filepath)
                        except CalledProcessError as e:
                            log.error(
                                f"Error removing speaker daemonset defined in {filepath}: {e}"
                            )
                    try:
                        os.remove(filepath)
                    except FileNotFoundError as e:
                        log.error(f"Error deleting rendered yaml {filepath}: {e}")

    def check_if_pod_restart_will_be_needed(self):
        output = self.kubectl(
            "get",
            "deployment",
            "-n",
            "kube-system",
            "kube-ovn-controller",
            "--ignore-not-found",
            "-o",
            "json",
        )
        if not output:
            # kube-ovn-controller doesn't exist, so this is a first time deployment
            self.stored.pod_restart_needed = True

    def configure_cni_relation(self):
        self.unit.status = MaintenanceStatus("Configuring CNI relation")
        cidr = self.model.config["default-cidr"]
        for relation in self.model.relations["cni"]:
            relation.data[self.unit]["cidr"] = cidr
            relation.data[self.unit]["cni-conf-file"] = "01-kube-ovn.conflist"

    def configure_kube_ovn(self):
        self.stored.kube_ovn_configured = False

        service_cidr = self.kube_ovn_peer_data("service-cidr")
        registry = self.get_registry()
        if not self.is_kubeconfig_available() or not service_cidr or not registry:
            self.unit.status = WaitingStatus("Waiting for CNI relation")
            return

        try:
            self.check_if_pod_restart_will_be_needed()

            self.apply_crds()
            self.apply_ovn(registry)
            self.apply_kube_ovn(service_cidr, registry)

            if self.stored.pod_restart_needed:
                self.wait_for_ovn_central()
                self.wait_for_kube_ovn_controller()
                self.wait_for_kube_ovn_cni()
                self.restart_pods()

            self.apply_speakers(registry)

        except CalledProcessError:
            # Likely the Kubernetes API is unavailable. Log the exception in
            # case it is something else, and let the caller know we failed.
            log.error(traceback.format_exc())
            self.unit.status = WaitingStatus("Waiting to retry configuring Kube-OVN")
            return

        self.stored.kube_ovn_configured = True

    def apply_speakers(self, registry):
        self.remove_speakers()
        if self.model.config["bgp-speakers"]:
            raw_speaker_config_list = list(
                yaml.safe_load(self.model.config["bgp-speakers"])
            )
            try:
                parsed_speaker_config_list = [
                    SpeakerConfig(**d) for d in raw_speaker_config_list
                ]
                for speaker_config in parsed_speaker_config_list:
                    self.apply_speaker(registry, speaker_config)
            except ValidationError as e:
                log.error(f"Error validating bgp-speakers config: {e}")
                self.unit.status = BlockedStatus("Error validating bgp-speakers config")

    def get_registry(self):
        registry = self.model.config["image-registry"]
        if not registry:
            registry = self.kube_ovn_peer_data("image-registry")
        return registry

    def get_charm_resource_path(self, resource_name):
        try:
            return self.model.resources.fetch(resource_name)
        except ModelError as e:
            log.error(
                f"Something went wrong when claiming the {resource_name} resource."
            )
            raise e
        except NameError as e:
            log.error(f"Resource {resource_name} not found on the charm")
            raise e

    def get_container_resource(self, resource, container_name):
        return next(
            filter(
                lambda c: c["name"] == container_name,
                resource["spec"]["template"]["spec"]["containers"],
            )
        )

    def get_resource(self, resources, kind, name):
        return next(
            filter(
                lambda c: c["kind"] == kind and c["metadata"]["name"] == name,
                resources,
            )
        )

    def get_ovn_node_ips(self):
        label = self.model.config["control-plane-node-label"]

        nodes = json.loads(self.kubectl("get", "node", "-l", label, "-o", "json"))[
            "items"
        ]
        node_ips = [
            address["address"]
            for node in nodes
            for address in node["status"]["addresses"]
            if address["type"] == "InternalIP"
        ]
        return node_ips

    def install_kubectl_plugin(self, plugin_name):
        registry = self.get_registry()
        if not registry:
            log.info("Waiting for registry to install kubectl plugin")
            return
        try:
            resource_path = self.get_charm_resource_path(plugin_name)
            plugin_path = Path(PLUGINS_PATH) / plugin_name
            plugin = resource_path.read_text()
            plugin = plugin.replace(
                'REGISTRY="kubeovn"', f'REGISTRY="{registry}/kubeovn"'
            )
            plugin_path.write_text(plugin)
            os.chmod(plugin_path, 0o755)
        except (ModelError, NameError) as e:
            log.error(f"Failed to install plugin {plugin_name}")
            log.error(e)
        except OSError as e:
            log.error(f"Failed to copy plugin {plugin_name}")
            log.error(e)

    def is_kubeconfig_available(self):
        for relation in self.model.relations["cni"]:
            for unit in relation.units:
                if relation.data[unit].get("kubeconfig-hash"):
                    return True
        return False

    def cni_to_kube_ovn(self, event):
        """Repeat received CNI relation data to each kube-ovn unit.

        CNI relation data is received over the cni relation only from
        kubernetes-control-plane units.  the kube-ovn peer relation
        shares the value around to each kube-ovn unit.
        """
        for key in ["service-cidr", "image-registry"]:
            cni_data = event.relation.data[event.unit].get(key)
            if not cni_data:
                continue
            for relation in self.model.relations["kube-ovn"]:
                relation.data[self.unit][key] = cni_data

    def kubectl(self, *args):
        cmd = ["kubectl", "--kubeconfig", "/root/.kube/config"] + list(args)
        return check_output(cmd)

    def load_manifest(self, name):
        with open("templates/" + name) as f:
            return list(yaml.safe_load_all(f))

    def on_cni_relation_joined(self, event):
        self.configure_cni_relation()
        self.set_active_status()

    def on_cni_relation_changed(self, event):
        self.cni_to_kube_ovn(event)
        self.configure_kube_ovn()
        self.install_kubectl_plugin("kubectl-ko")

        self.set_active_status()

    def on_kube_ovn_relation_changed(self, event):
        self.configure_kube_ovn()
        self.install_kubectl_plugin("kubectl-ko")
        self.set_active_status()

    def on_config_changed(self, event):
        self.configure_cni_relation()
        self.configure_kube_ovn()
        self.install_kubectl_plugin("kubectl-ko")
        self.set_active_status()

    def on_leader_elected(self, _):
        if self.unit.is_leader():
            try:
                self.kubectl("get", "namespace", self.stored.grafana_namespace)
                self.stored.grafana_agent_configured = (
                    self.stored.prometheus_patched
                ) = True
            except CalledProcessError:
                self.stored.grafana_agent_configured = (
                    self.stored.prometheus_patched
                ) = False

    def on_remove(self, _):
        self.remove_kubectl_plugin("kubectl-ko")

    def on_send_remote_write_departed(self, event):
        if self.stored.grafana_agent_configured and self.unit.is_leader():
            self.remove_grafana_agent()

    def on_update_status(self, _):
        if not self.stored.kube_ovn_configured:
            self.configure_kube_ovn()
        self.set_active_status()

    def on_upgrade_charm(self, _):
        self.install_kubectl_plugin("kubectl-ko")

    def patch_prometheus_resources(self, resources, namespace, remove=False):
        for res in resources:
            patch_file = self.render_template(
                "patch-prometheus.yaml",
                scrape="null" if remove else True,
                port="null" if remove else res["port"],
                remove=remove,
            )
            self.kubectl(
                "patch",
                res["kind"],
                "-n",
                namespace,
                res["name"],
                "--patch-file",
                patch_file,
            )

    def remote_write_consumer_changed(self, _):
        if self.remote_write_consumer.endpoints and self.unit.is_leader():
            # Get the last available endpoint reported in the relation data.
            self.apply_grafana_agent(self.remote_write_consumer.endpoints)

    def remove_grafana_agent(self):
        self.patch_prometheus_resources(
            PROMETHEUS_RESOURCES, "kube-system", remove=True
        )
        self.stored.prometheus_patched = False

        self.kubectl("delete", "namespace", self.stored.grafana_namespace)
        self.stored.grafana_agent_configured = False

    def remove_kubectl_plugin(self, plugin_name):
        try:
            plugin_path = Path(PLUGINS_PATH) / plugin_name
            os.remove(plugin_path)
        except OSError as e:
            log.error(f"Failed to remove plugin: {plugin_name}")
            log.error(e)

    def render_manifest(self, manifest, name):
        os.makedirs("templates/rendered", exist_ok=True)
        destination = "templates/rendered/" + name
        with open(destination, "w") as f:
            yaml.safe_dump_all(manifest, f)
        return destination

    def render_template(self, filename, **kwargs):
        os.makedirs(TMP_RENDER_PATH, exist_ok=True)
        destination = f"{TMP_RENDER_PATH}/{filename}_rendered.yaml"
        template = self.jinja2_environment.get_template(filename)
        template.stream(**kwargs).dump(destination)
        return destination

    def replace_container_args(self, container, args):
        # Args can appear either in the "command" field or in the "args" field,
        # we need to go through both.
        container_command = container.get("command", [])
        container_args = container.get("args", [])
        for i, arg in enumerate(container_command):
            if i == 0:
                continue
            key = arg.split("=")[0]
            value = args.get(key)
            if value is not None:  # allow for non-truthy values
                container_command[i] = key + "=" + str(value)
        for i, arg in enumerate(container_args):
            key = arg.split("=")[0]
            value = args.get(key)
            if value is not None:  # allow for non-truthy values
                container_args[i] = key + "=" + str(value)

    def replace_container_env_vars(self, container, env_vars):
        for env_var in container["env"]:
            key = env_var["name"]
            value = env_vars.get(key)
            if value is not None:  # allow for non-truthy values
                env_var["value"] = value

    def replace_images(self, resources, registry):
        for resource in resources:
            if resource["kind"] in ["Deployment", "DaemonSet", "StatefulSet"]:
                pod_spec = resource["spec"]["template"]["spec"]
                for container_type in ["containers", "initContainers"]:
                    for container in pod_spec.get(container_type, []):
                        container["image"] = "/".join(
                            [registry] + container["image"].split("/")[-2:]
                        )

    def replace_name(self, resource, new_name):
        resource["metadata"]["name"] = new_name

    def restart_pods(self):
        self.unit.status = MaintenanceStatus("Restarting pods")
        namespaces = [
            resource["metadata"]["name"]
            for resource in json.loads(self.kubectl("get", "ns", "-o", "json"))["items"]
        ]
        for namespace in namespaces:
            pods = [
                resource["metadata"]["name"]
                for resource in json.loads(
                    self.kubectl(
                        "get",
                        "po",
                        "-n",
                        namespace,
                        "--field-selector",
                        "spec.restartPolicy=Always",
                        "-o",
                        "json",
                    )
                )["items"]
                if not resource["spec"].get("hostNetwork")
            ]
            for pod in pods:
                log.info(f"Deleting pod {pod} in namespace {namespace}")
                self.kubectl("delete", "po", "-n", namespace, pod, "--ignore-not-found")
        self.stored.pod_restart_needed = False

    def set_active_status(self):
        if self.stored.kube_ovn_configured:
            self.unit.status = ActiveStatus()

    def set_node_selector(self, resource, new_label, replace=None):
        label_key, label_value = new_label.split("=")

        node_selector = resource["spec"]["template"]["spec"]["nodeSelector"]
        if replace and replace in node_selector:
            del node_selector[replace]
        node_selector[label_key] = label_value

    def set_replicas(self, resource, replicas):
        resource["spec"]["replicas"] = replicas

    def wait_for_kube_ovn_cni(self):
        self.unit.status = WaitingStatus("Waiting for kube-ovn-cni")
        self.wait_for_rollout("daemonset/kube-ovn-cni")

    def wait_for_kube_ovn_controller(self):
        self.unit.status = WaitingStatus("Waiting for kube-ovn-controller")
        self.wait_for_rollout("deployment/kube-ovn-controller")

    def wait_for_ovn_central(self):
        self.unit.status = WaitingStatus("Waiting for ovn-central")
        self.wait_for_rollout("deployment/ovn-central")

    def wait_for_rollout(self, name, namespace="kube-system", timeout=1):
        self.kubectl(
            "rollout", "status", "-n", namespace, name, "--timeout", str(timeout) + "s"
        )

    def kube_ovn_peer_data(self, key):
        """Return the agreed data associated with the key
        from each kube-ovn unit including self.
        If there isn't unity in the relation, return None
        """
        joined_data = set()
        for relation in self.model.relations["kube-ovn"]:
            for unit in relation.units | {self.unit}:
                data = relation.data[unit].get(key)
                joined_data.add(data)
        filtered = set(filter(bool, joined_data))
        return filtered.pop() if len(filtered) == 1 else None


if __name__ == "__main__":
    main(KubeOvnCharm)  # pragma: no cover
