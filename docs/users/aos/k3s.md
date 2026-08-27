# Configure k3s

AOS provides three mutually exclusive packages implementing the shared
`k3s.*` configuration interface:

- `k3s-worker` runs only the agent.
- `k3s-control-plane` runs a server with the agent disabled.
- `k3s-combined` runs a server and agent together.

Select exactly one package and enable the service in operator policy. The
cluster token is always an opaque credential reference; plaintext token bytes
must not appear in a Nix module or the Nix store.

```nix
{
  aos.apm.desiredPackages = ["k3s-worker"];

  k3s = {
    enable = true;
    serverUrl = "https://control.example:6443";
    token.ref = "system-credential:k3s-token";

    node = {
      name = "worker-1";
      labels."node-role.kubernetes.io/worker" = "true";
    };
  };
}
```

The evaluator renders non-secret settings to the package-owned
`/etc/aos/packages/k3s-worker/k3s.env` artifact. Activation resolves the token
reference into the `token` systemd credential. The launcher passes only the
credential file path to k3s through `K3S_TOKEN_FILE`.

Initialize a new combined cluster with:

```nix
{
  aos.apm.desiredPackages = ["k3s-combined"];

  k3s = {
    enable = true;
    token.ref = "tpm2-credstore:k3s-token";
    server.clusterInit = true;
    server.tlsSans = ["api.example.test"];
  };
}
```

`server.clusterInit` and `serverUrl` are mutually exclusive. Workers require a
`serverUrl`; every enabled role requires a token reference.

## CNI and CSI composition

The owner of `k3s.*` exposes only `integrations.cni.*` and
`integrations.csi.*` as package-contributable paths. A CNI meta-package can,
for example, request replacement of Flannel, network policy, and kube-proxy:

```nix
{
  k3s.integrations.cni.cilium = {
    disableFlannel = true;
    disableNetworkPolicy = true;
    disableKubeProxy = true;
  };
}
```

A CSI package may contribute node-selection labels beneath its own integration
name. Integration packages cannot enable k3s or change server credentials,
node identity, cluster addressing, or other owner-only settings. The operator
continues to select and enable every package explicitly.
