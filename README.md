# Kube-OVN Charm

[Kube-OVN][] is a CNI implementation based on OVN that provides a rich
set of networking features for advanced enterprise applications.

This charm will deploy Kube-OVN as a background service, and configure CNI for
use with Kube-OVN, on any principal charm that implements the [kubernetes-cni][]
interface.

This charm is a component of Charmed Kubernetes. For full information,
please visit the [official Charmed Kubernetes docs](https://www.ubuntu.com/kubernetes/docs/charm-kube-ovn).

[kube-ovn]: https://kubeovn.github.io/docs/v1.10.x/en/
[kubernetes-cni]: https://github.com/juju-solutions/interface-kubernetes-cni

# Developers

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
