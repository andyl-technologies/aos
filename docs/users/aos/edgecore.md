# KubeEdge EdgeCore runtime configuration

The `edgecore` package owns the strict `edgecore.*` runtime interface for a
pre-provisioned edge node. TLS material is delivered as opaque credentials and
never embedded in its generated YAML configuration.

```nix
{
  edgecore = {
    enable = true;
    nodeName = "factory-edge-01";
    cloudHub = {
      httpServer = "https://192.0.2.20:10002";
      server = "192.0.2.20:10000";
    };
    tls = {
      caCertificate.ref = "system-credential:kubeedge-ca";
      clientCertificate.ref = "system-credential:factory-edge-01-cert";
      clientPrivateKey.ref = "system-credential:factory-edge-01-key";
    };
  };
}
```

EdgeCore incorporates an edge kubelet and therefore has an explicit
root-equivalent expose contract: host networking, cgroup delegation, CRI
socket access, kernel networking modules, pod logs, and the bounded privileged
capabilities required to manage workloads. Selecting the package never enables
it; only an operator runtime module can do so.
