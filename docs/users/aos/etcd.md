# Configure etcd

Install `etcd`, then configure its package-owned `etcd.*` interface from
`host.nix` or a supplemental runtime module:

```nix
{
  aos.apm.desiredPackages = ["etcd"];

  etcd = {
    enable = true;
    name = "control-1";
    client = {
      listenUrls = ["https://0.0.0.0:2379"];
      advertiseUrls = ["https://control-1.internal:2379"];
      tls = {
        enable = true;
        certificate.ref = "system-credential:etcd-client-certificate";
        privateKey.ref = "system-credential:etcd-client-private-key";
        trustedCa.ref = "system-credential:etcd-client-ca";
        clientCertificateAuth = true;
      };
    };
    peer = {
      listenUrls = ["https://0.0.0.0:2380"];
      advertiseUrls = ["https://control-1.internal:2380"];
      tls = {
        enable = true;
        certificate.ref = "system-credential:etcd-peer-certificate";
        privateKey.ref = "system-credential:etcd-peer-private-key";
        trustedCa.ref = "system-credential:etcd-peer-ca";
        clientCertificateAuth = true;
      };
    };
    cluster.members.control-1.peerUrls = ["https://control-1.internal:2380"];
  };
}
```

The module renders `/etc/aos/packages/etcd/etcd.json`. The package owns
`/var/lib/aos-pkg-etcd`, and configuration changes restart `etcd.service` while
retaining its database. The local member must appear in `cluster.members`, and
its declared peer URLs must exactly match `peer.advertiseUrls`. Endpoint lists
must be unique and use HTTPS whenever their transport enables TLS.

For a multi-member cluster, declare every member with stable advertised peer
URLs and use the same non-secret `cluster.token` on every host. Set
`cluster.state = "existing"` only when joining an already-created cluster.
Changing the initial topology does not migrate live membership; use `etcdctl`
member operations before applying the matching declarative topology.

Client and peer certificates, private keys, and CA bundles are opaque AOS
credential references. Their bytes are resolved after evaluation and delivered
only through `/run/credentials/etcd.service`; they never enter the generated
JSON or Nix store. Binding beyond loopback also requires an explicit host
firewall policy.

