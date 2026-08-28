# Configure Garage

Install `garage`, then configure its package-owned `garage.*` interface from
`host.nix` or a supplemental runtime module. The shared RPC key is always an
opaque credential reference:

```nix
{
  aos.apm.desiredPackages = ["garage"];

  garage = {
    enable = true;
    replicationFactor = 1;
    rpc.secret.ref = "system-credential:garage-rpc-secret";
    s3 = {
      bindAddress = "0.0.0.0:3900";
      region = "garage";
      rootDomain = ".s3.example.internal";
    };
  };
}
```

The package writes `/etc/aos/packages/garage/garage.toml`. Metadata and object
data remain in `/var/lib/aos-pkg-garage`; the runtime and log directories are
managed by systemd. Garage performs compatible metadata migrations while the
daemon starts, after the package's state-preparation unit and before its APIs
become ready. Configuration changes restart the daemon safely rather than
pretending that Garage can reload its TOML in place.

## Cluster and administration credentials

The RPC secret must contain Garage's 32-byte cluster key as 64 hexadecimal
characters. Enabling the administration API also requires separate opaque
administrator and metrics tokens:

```nix
{
  garage = {
    enable = true;
    replicationFactor = 3;
    rpc = {
      bindAddress = "0.0.0.0:3901";
      publicAddress = "garage-a.example.internal:3901";
      bootstrapPeers = [
        "0123456789abcdef@garage-b.example.internal:3901"
        "fedcba9876543210@garage-c.example.internal:3901"
      ];
      secret.ref = "tpm2-credstore:garage-rpc-secret";
    };
    admin = {
      enable = true;
      bindAddress = "127.0.0.1:3903";
      token.ref = "system-credential:garage-admin-token";
      metrics.token.ref = "system-credential:garage-metrics-token";
    };
  };
}
```

Secret bytes are projected into the service credential directory and passed to
Garage through its `*_FILE` interfaces. They never appear in TOML, Nix store
paths, environment values, or command-line arguments. Restrict externally bound
RPC and API listeners with `aos.firewall`.
