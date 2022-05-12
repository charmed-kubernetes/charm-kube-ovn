# Kube-OVN charm

This is an experimental proof-of-concept charm for using Kube-OVN with
Charmed Kubernetes. This is a subordinate machine charm that relates to
kubernetes-control-plane and kubernetes-worker via the kubernetes-cni
interface.

## Building

To build the Kube-OVN charm:

```
charmcraft pack
```

## Deploying

After you've built the Kube-OVN charm, you can deploy Charmed Kubernetes with
Kube-OVN by running:

```
juju deploy charmed-kubernetes --overlay overlay.yaml
```
