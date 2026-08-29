# Configure Cilium

The `cilium` package is a configuration contributor, not a competing host
daemon. Install it alongside exactly one k3s role and enable its own typed
root:

```nix
{
  aos.apm.desiredPackages = ["k3s-combined" "cilium"];

  k3s = {
    enable = true;
    token.ref = "system-credential:k3s-token";
    server.clusterInit = true;
  };

  cilium = {
    enable = true;
    kubeProxyReplacement = true;
    operatorReplicas = 2;
  };
}
```

The signed Cilium module can contribute only
`k3s.integrations.cni.cilium` and
`k3s.integrations.resources.cilium`. It disables the conflicting built-in CNI
features and contributes a version-pinned Cilium `HelmChart` resource. It
cannot set `k3s.enable`, cluster identity, credentials, or networking ranges.
The k3s server owns resource staging and reconciliation.

The Helm controller retrieves the exact chart version declared by the signed
resource. Operators must ensure the configured chart repository and container
registry are admitted by their network and image-verification policy.
