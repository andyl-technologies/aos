# Configure Longhorn

`longhorn-manager` is the Longhorn integration package. Its authenticated
configuration metadata retains the matching `longhorn-engine` and
`longhorn-instance-manager` payloads and contributes only to the k3s CSI and
resource surfaces:

```nix
{
  aos.apm.desiredPackages = ["k3s-combined" "longhorn-manager"];

  k3s = {
    enable = true;
    token.ref = "system-credential:k3s-token";
    server.clusterInit = true;
  };

  longhorn = {
    enable = true;
    defaultReplicaCount = 3;
  };
}
```

The module contributes the package-owned Longhorn node label and a
version-pinned `HelmChart` resource. It cannot enable k3s or alter owner-only
cluster policy. The k3s server stages the signed resource bundle and its Helm
controller performs Kubernetes reconciliation. Chart and container retrieval
must comply with the operator's network and image-verification policy.
