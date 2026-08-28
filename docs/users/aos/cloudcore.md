# KubeEdge CloudCore runtime configuration

The `cloudcore` package owns the strict `cloudcore.*` runtime interface. The
service is disabled unless an operator selects it and supplies a Kubernetes
kubeconfig plus the complete CloudHub certificate chain through opaque
credential references.

```nix
{
  cloudcore = {
    enable = true;
    advertiseAddresses = ["192.0.2.20"];
    kubeApi.kubeconfig.ref = "system-credential:cloudcore-kubeconfig";
    tls = {
      caCertificate.ref = "system-credential:kubeedge-ca";
      caPrivateKey.ref = "system-credential:kubeedge-ca-key";
      serverCertificate.ref = "system-credential:kubeedge-server";
      serverPrivateKey.ref = "system-credential:kubeedge-server-key";
    };
  };
}
```

CloudCore runs without host user or network administration privileges. The
signed package exposes only its CloudHub listeners, persistent Unix socket,
managed logs, and exact read-only configuration and credential projections.
