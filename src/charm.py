#!/usr/bin/env python3

import json
import logging
import os
import traceback
import yaml
from subprocess import CalledProcessError, check_output
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus, MaintenanceStatus

log = logging.getLogger(__name__)


class KubeOvnCharm(CharmBase):
    stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.stored.set_default(kube_ovn_configured=False)
        self.stored.set_default(pod_restart_needed=False)
        self.framework.observe(
            self.on.cni_relation_changed, self.on_cni_relation_changed
        )
        self.framework.observe(self.on.cni_relation_joined, self.on_cni_relation_joined)
        self.framework.observe(self.on.config_changed, self.on_config_changed)

    def apply_crds(self):
        self.unit.status = MaintenanceStatus("Applying CRDs")
        self.kubectl("apply", "-f", "templates/crd.yaml")

    def apply_kube_ovn(self):
        self.unit.status = MaintenanceStatus("Applying Kube-OVN resources")
        resources = self.load_manifest("kube-ovn.yaml")
        cidr = self.model.config["default-cidr"]
        gateway = self.model.config["default-gateway"]
        service_cidr = self.model.config["service-cidr"]
        pinger_address = self.model.config["pinger-external-address"]
        pinger_dns = self.model.config["pinger-external-dns"]
        node_ips = self.get_ovn_node_ips()

        self.replace_images(resources)

        kube_ovn_controller = self.get_resource(
            resources, kind="Deployment", name="kube-ovn-controller"
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
            },
        )

        kube_ovn_cni = self.get_resource(
            resources, kind="DaemonSet", name="kube-ovn-cni"
        )
        cni_server_container = self.get_container_resource(
            kube_ovn_cni, container_name="cni-server"
        )
        self.replace_container_args(
            cni_server_container, args={"--service-cluster-ip-range": service_cidr}
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
        self.replace_node_selector(kube_ovn_monitor)
        self.set_replicas(kube_ovn_monitor, len(node_ips))

        self.apply_manifest(resources, "kube-ovn.yaml")
        self.wait_for_kube_ovn_controller()
        self.wait_for_kube_ovn_cni()

    def apply_manifest(self, manifest, name):
        destination = self.render_manifest(manifest, name)
        self.kubectl("apply", "-f", destination)

    def apply_ovn(self):
        self.unit.status = MaintenanceStatus("Applying OVN resources")
        resources = self.load_manifest("ovn.yaml")
        node_ips = self.get_ovn_node_ips()

        self.replace_images(resources)

        ovn_central = self.get_resource(
            resources, kind="Deployment", name="ovn-central"
        )
        self.replace_node_selector(ovn_central)
        self.set_replicas(ovn_central, len(node_ips))

        ovn_central_container = self.get_container_resource(
            ovn_central, container_name="ovn-central"
        )
        self.replace_container_env_vars(
            ovn_central_container, env_vars={"NODE_IPS": ",".join(node_ips)}
        )

        self.apply_manifest(resources, "ovn.yaml")
        self.wait_for_ovn_central()

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
        if not self.is_kubeconfig_available():
            self.unit.status = WaitingStatus("Waiting for Kubernetes API")
            return

        try:
            self.check_if_pod_restart_will_be_needed()

            self.apply_crds()
            self.apply_ovn()
            self.apply_kube_ovn()

            if self.stored.pod_restart_needed:
                self.restart_pods()
        except CalledProcessError:
            # Likely the Kubernetes API is unavailable. Log the exception in
            # case it it something else, and let the caller know we failed.
            log.error(traceback.format_exc())
            return False

        self.stored.kube_ovn_configured = True
        return True

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

    def is_kubeconfig_available(self):
        for relation in self.model.relations["cni"]:
            for unit in relation.units:
                if relation.data[unit].get("kubeconfig-hash"):
                    return True
        return False

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
        if not self.configure_kube_ovn():
            self.schedule_event_retry(event, "Waiting to retry configuring Kube-OVN")
            return

        self.set_active_status()

    def on_config_changed(self, event):
        self.configure_cni_relation()

        if not self.configure_kube_ovn():
            self.schedule_event_retry(event, "Waiting to retry configuring Kube-OVN")
            return

        self.set_active_status()

    def render_manifest(self, manifest, name):
        os.makedirs("templates/rendered", exist_ok=True)
        destination = "templates/rendered/" + name
        with open(destination, "w") as f:
            yaml.safe_dump_all(manifest, f)
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
                container_command[i] = key + "=" + value
        for i, arg in enumerate(container_args):
            key = arg.split("=")[0]
            value = args.get(key)
            if value is not None:  # allow for non-truthy values
                container_args[i] = key + "=" + value

    def replace_container_env_vars(self, container, env_vars):
        for env_var in container["env"]:
            key = env_var["name"]
            value = env_vars.get(key)
            if value is not None:  # allow for non-truthy values
                env_var["value"] = value

    def replace_images(self, resources):
        registry = self.model.config["registry"]
        for resource in resources:
            if resource["kind"] in ["Deployment", "DaemonSet", "StatefulSet"]:
                pod_spec = resource["spec"]["template"]["spec"]
                for container_type in ["containers", "initContainers"]:
                    for container in pod_spec.get(container_type, []):
                        container["image"] = "/".join(
                            [registry] + container["image"].split("/")[-2:]
                        )

    def replace_node_selector(self, resource):
        label = self.model.config["control-plane-node-label"]
        label_key, label_value = label.split("=")

        node_selector = resource["spec"]["template"]["spec"]["nodeSelector"]
        del node_selector["kube-ovn/role"]
        node_selector[label_key] = label_value

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

    def schedule_event_retry(self, event, message):
        self.unit.status = WaitingStatus(message)
        event.defer()

    def set_active_status(self):
        if self.stored.kube_ovn_configured:
            self.unit.status = ActiveStatus()

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

    def wait_for_rollout(self, name, namespace="kube-system", timeout=300):
        self.kubectl(
            "rollout", "status", "-n", namespace, name, "--timeout", str(timeout) + "s"
        )


if __name__ == "__main__":
    main(KubeOvnCharm)  # pragma: no cover
