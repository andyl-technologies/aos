# Run standalone containerd

The `containerd` package can run a host container runtime independently of
k3s. Installing it is intentionally inert; enable the daemon through a typed
supplemental runtime module:

```console
apm install containerd --system --yes
apm config add 30-containerd.nix
apm config apply
```

```nix
{
  containerd = {
    enable = true;
    grpcAddress = "/run/containerd/containerd.sock";
    snapshotter = "overlayfs";
    systemdCgroup = true;
    metricsAddress = "127.0.0.1:1338";
    registryConfigPath = "/etc/containerd/certs.d";
  };
}
```

The package owns `containerd.*` and projects a version-3 `config.toml` plus a
separate enablement artifact. It declares the privileged kernel, cgroup, state,
and runtime access required by a container runtime. Because this is an explicit
root-equivalent workload, review its signed permissions before installation.

State is retained beneath `/var/lib/containerd`; volatile sockets and process
state live beneath `/run/containerd`. Host-specific registry `hosts.toml` files
may be provisioned under the selected `registryConfigPath`. Do not embed registry
passwords in runtime Nix modules: use the registry's external credential helper
or a platform-managed file whose bytes never enter evaluation.

The k3s role packages use containerd binaries as subordinate payloads and do
not enable this standalone service. Do not enable both runtimes against the same
state or socket paths.
