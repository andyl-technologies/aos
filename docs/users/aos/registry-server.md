# Run an AOS registry server

Install the signed package system-wide, then configure it with a supplemental
runtime module:

```console
apm install aos-registry-server --system --yes
apm config add 30-registry-server.nix
apm config apply
```

```nix
{
  "aos-registry-server" = {
    enable = true;

    git = {
      listenAddress = "0.0.0.0";
      port = 9418;
      basePath = "/var/lib/aos-registry-server/registries";
    };

    cache = {
      listenAddress = "0.0.0.0";
      port = 15000;
      anonymousRead = true;
      maxConcurrentBuilds = 4;
    };
  };
}
```

The package owns `aos-registry-server.*`. It projects separate enablement
artifacts for the Git and cache workloads plus the structured `serve.toml` used
by `aos serve`. Installing the package does not enable either workload; setting
the package-level `enable` option and at least one workload enable is required.

Repository, cache, and nested Nix-store state remains under
`/var/lib/aos-registry-server`. The bootstrap socket remains under the volatile
`/run/aos-registry-server` namespace. Paths outside those package-owned roots
are rejected by the typed interface.

The signed package metadata opens the default Git and cache ports. If an
operator selects different ports, the host firewall must explicitly admit
them; runtime values never silently expand signed network authority.
