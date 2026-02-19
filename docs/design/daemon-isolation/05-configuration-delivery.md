# Configuration Delivery

> Part of the [Daemon Isolation Architecture](README.md)

This document describes how the daemon isolation containers are configured --
what is baked into the system image at build time, what is delivered per-machine
via Ignition at first boot, and how configuration can be updated at runtime.
It covers the AOS module design for the fetch proxy and the extensions needed
to the existing nix-daemon module.

> **AOS context:** AOS uses its own module system (`lib.evalModules`) and
> package set -- not NixOS modules from nixpkgs. All module paths below refer
> to AOS modules under `modules/`. System variants compose these modules in
> `systems/`.

---

## 1. AOS System Model

AOS machines have a layered filesystem model designed for immutability with
controlled mutability where needed:

| Layer | Mount | Properties |
|-------|-------|------------|
| Root filesystem | `/` | Read-only squashfs (baked at build time) |
| `/etc` overlay | `/etc` | OverlayFS -- lower layer from squashfs, upper layer on ZFS `aos-pool/etc-overlay` |
| `/var` | `/var` | Writable ZFS dataset (`aos-pool/var`) |
| `/var/lib/machines` | `/var/lib/machines` | ZFS dataset for container rootfs images |

The read-only root contains the system image produced by `system.build.toplevel`
-- all packages, systemd units, and default configuration files. The writable
`/etc` overlay allows Ignition to write per-machine configuration at first boot
and operators to make runtime changes. The writable `/var` holds all mutable
state.

Configuration reaches the system through three phases:

```
BUILD TIME                 FIRST BOOT                 RUNTIME
(immutable image)          (Ignition, once)            (operator changes)

Nix modules evaluate  -->  Per-machine config    -->  Edit files on /etc overlay
system.build.toplevel      written to /etc overlay    systemd .path watches reload
```

---

## 2. Configuration Inventory

### 2.1 Build-time configuration (baked into the image)

These artifacts are produced by the AOS module system and included in the
read-only root filesystem. They are the same on every machine running a given
system variant.

| Artifact | Path | Source module |
|----------|------|---------------|
| Container rootfs (nix-daemon) | `/var/lib/machines/nix-daemon/` | `modules/services/nix-daemon.nix` |
| Container rootfs (fetch-proxy) | `/var/lib/machines/fetch-proxy/` | `modules/services/fetch-proxy.nix` |
| nspawn config (nix-daemon) | `/etc/systemd/nspawn/nix-daemon.nspawn` | `modules/services/nix-daemon.nix` |
| nspawn config (fetch-proxy) | `/etc/systemd/nspawn/fetch-proxy.nspawn` | `modules/services/fetch-proxy.nix` |
| systemd units | `/etc/systemd/system/` | Both modules |
| Default domain allowlist | `/etc/squid/domains.txt` | `modules/services/fetch-proxy.nix` |
| nix.conf with proxy settings | `/etc/nix/nix.conf` | `modules/services/nix-daemon.nix` |
| networkd `.network` files | `/etc/systemd/network/` | Both modules |
| squid.conf | `/etc/squid/squid.conf` | `modules/services/fetch-proxy.nix` |
| nftables rules | `/etc/nftables.conf` (or drop-in) | `modules/services/fetch-proxy.nix` |

### 2.2 First-boot configuration (per-machine via Ignition)

Delivered by CoreOS Ignition (spec v3.4) and written to the `/etc` overlay
during the initrd phase. See `modules/services/ignition.nix` for the Ignition
service implementation.

| Artifact | Path | Purpose |
|----------|------|---------|
| Domain allowlist overrides | `/etc/squid/domains.txt` | Machine- or tenant-specific upstream sources |
| Network interface mapping | `/etc/systemd/network/*.network` | Which NIC is internet vs. intranet |
| TLS certificates | `/etc/squid/tls/` | MITM proxy CA (if applicable) |
| Machine hostname | `/etc/hostname` | Per-machine identity |
| SSH authorized keys | `/etc/ssh/authorized_keys.d/` | Operator access |
| nix.conf overrides | `/etc/nix/nix.conf.d/` | Per-machine Nix settings |

### 2.3 Ignition file entry example

An Ignition config (JSON, spec v3.4) that replaces the default domain
allowlist with a tenant-specific one:

```json
{
  "ignition": { "version": "3.4.0" },
  "storage": {
    "files": [
      {
        "path": "/etc/squid/domains.txt",
        "overwrite": true,
        "contents": {
          "inline": "github.com\nraw.githubusercontent.com\nftp.gnu.org\nftpmirror.gnu.org\nkernel.org\ncdn.kernel.org\nexample-tenant.internal\nartifacts.example-tenant.com\n"
        },
        "mode": 420
      },
      {
        "path": "/etc/hostname",
        "overwrite": true,
        "contents": { "inline": "seed-zone-a-01" },
        "mode": 420
      }
    ]
  }
}
```

Because the `/etc` overlay is writable, Ignition's `overwrite: true` replaces
the default file from the read-only lower layer with the per-machine version
in the upper layer. The original default remains intact in the squashfs -- a
factory reset is possible by clearing the overlay upper directory.

---

## 3. AOS Module Design: `modules/services/fetch-proxy.nix`

The fetch proxy is expressed as an AOS module following the same patterns as
`modules/services/nix-daemon.nix`, `modules/services/nginx.nix`, and
`modules/services/seed.nix`. The module declares options, generates
configuration files, and wires up systemd units.

### 3.1 Module options

```nix
# modules/services/fetch-proxy.nix — Squid forward proxy in systemd-nspawn
#
# Runs a Squid forward proxy inside a systemd-nspawn container. The proxy
# mediates all source fetches for the nix-daemon container, enforcing a
# domain allowlist and caching HTTP traffic. See daemon-isolation design.

{ config, pkgs, lib, ... }:

let cfg = config.aos.services.fetchProxy; in
{
  options.aos.services.fetchProxy = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the Squid forward proxy container for Nix fetch isolation.";
    };

    allowedDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        # Source hosting
        "github.com"
        "raw.githubusercontent.com"
        "codeload.github.com"

        # GNU mirrors
        "ftp.gnu.org"
        "ftpmirror.gnu.org"

        # Kernel.org
        "kernel.org"
        "cdn.kernel.org"
        "mirrors.edge.kernel.org"

        # Common source hosts
        "sourceforge.net"
        "downloads.sourceforge.net"
        "cpan.metacpan.org"
        "pypi.org"
        "files.pythonhosted.org"

        # Rust ecosystem
        "static.rust-lang.org"
        "crates.io"
        "static.crates.io"
      ];
      description = ''
        Domain allowlist for the forward proxy. Only HTTPS CONNECT and HTTP
        requests to these domains are permitted. All other traffic is blocked.
      '';
    };

    cacheSize = lib.mkOption {
      type = lib.types.str;
      default = "10000";
      description = "Squid disk cache size in MB.";
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 3128;
      description = "Port the Squid proxy listens on inside the container.";
    };

    internetInterface = lib.mkOption {
      type = lib.types.str;
      default = "eth0";
      description = "Host network interface with internet access (used for macvlan).";
    };

    proxySubnet = lib.mkOption {
      type = lib.types.str;
      default = "172.30.0.0/30";
      description = "Subnet for the veth pair between proxy and nix-daemon containers.";
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "512M";
      description = "Memory limit for the fetch-proxy container (systemd MemoryMax=).";
    };
  };

  config = lib.mkIf cfg.enable {
    # ... (see section 3.2 for generated configuration)
  };
}
```

### 3.2 Generated configuration

The `config` block generates all the files and units described in section 2.1.
The key generation logic:

**Domain allowlist** -- one domain per line, consumed by `squid.conf` ACL:

```nix
environment.etc."squid/domains.txt" = {
  text = builtins.concatStringsSep "\n" cfg.allowedDomains + "\n";
};
```

**squid.conf** -- generated from module options, references the domain file:

```nix
environment.etc."squid/squid.conf" = {
  text = ''
    # /etc/squid/squid.conf — generated by modules/services/fetch-proxy.nix

    http_port ${toString cfg.listenPort}

    # Domain allowlist ACL
    acl allowed_domains dstdomain "/etc/squid/domains.txt"
    acl CONNECT method CONNECT

    http_access allow CONNECT allowed_domains
    http_access allow allowed_domains
    http_access deny all

    # Cache settings
    cache_dir ufs /var/spool/squid ${cfg.cacheSize} 16 256
    maximum_object_size 512 MB
    cache_mem 128 MB

    # Logging
    access_log daemon:/var/log/squid/access.log
    cache_log /var/log/squid/cache.log
  '';
};
```

**systemd-nspawn configuration** (`.nspawn` file):

```nix
environment.etc."systemd/nspawn/fetch-proxy.nspawn" = {
  text = ''
    [Exec]
    Boot=yes
    Capability=CAP_NET_ADMIN CAP_NET_RAW

    [Network]
    VirtualEthernet=yes
    MACVLAN=${cfg.internetInterface}

    [Files]
    Bind=/etc/squid/squid.conf:/etc/squid/squid.conf
    Bind=/etc/squid/domains.txt:/etc/squid/domains.txt
  '';
};
```

**systemd service unit**:

```nix
systemd.services."fetch-proxy" = {
  description = "Squid Forward Proxy Container";
  wantedBy = [ "multi-user.target" ];
  before = [ "nix-daemon-container.service" ];
  after = [ "network-online.target" "local-fs.target" ];
  wants = [ "network-online.target" ];
  serviceConfig = {
    Type = "notify";
    ExecStart = "/usr/bin/systemd-nspawn --machine=fetch-proxy --boot --directory=/var/lib/machines/fetch-proxy";
    Restart = "on-failure";
    RestartSec = "5s";
    MemoryMax = cfg.memoryMax;
    KillMode = "mixed";
  };
};
```

**networkd configuration** for the veth interface:

```nix
environment.etc."systemd/network/80-veth-proxy.network" = {
  text = ''
    [Match]
    Name=veth-proxy

    [Network]
    Address=172.30.0.1/30
  '';
};
```

**Domain allowlist reload** -- a path unit watches for changes:

```nix
systemd.services."fetch-proxy-reload" = {
  description = "Reload Squid Configuration";
  serviceConfig = {
    Type = "oneshot";
    ExecStart = "/usr/bin/machinectl shell fetch-proxy /usr/sbin/squid -k reconfigure";
  };
};

systemd.services."fetch-proxy-reload-watcher" = {
  description = "Watch for domain allowlist changes";
  wantedBy = [ "multi-user.target" ];
  pathConfig = {
    PathModified = "/etc/squid/domains.txt";
    Unit = "fetch-proxy-reload.service";
  };
};
```

---

## 4. Extending the Nix Daemon Module

The existing `modules/services/nix-daemon.nix` needs extensions to support
running inside a systemd-nspawn container and routing fetches through the
proxy. The changes are additive -- when `fetchProxy.enable` is false, the
module behaves exactly as it does today.

### 4.1 Container mode

When the fetch proxy is enabled, the nix-daemon runs inside an nspawn
container instead of directly on the host:

```nix
# In modules/services/nix-daemon.nix, within the config block:

# When fetch proxy is enabled, replace the direct daemon service
# with a containerised version.
systemd.services."nix-daemon" = lib.mkIf config.aos.services.fetchProxy.enable {
  description = "Nix Daemon Container";
  wantedBy = [ "multi-user.target" ];
  after = [
    "fetch-proxy.service"
    "network-online.target"
    "local-fs.target"
  ];
  wants = [ "fetch-proxy.service" ];
  serviceConfig = {
    Type = "notify";
    ExecStart = builtins.concatStringsSep " " [
      "/usr/bin/systemd-nspawn"
      "--machine=nix-daemon"
      "--boot"
      "--directory=/var/lib/machines/nix-daemon"
      "--private-network"
      "--bind=/nix/store"
      "--bind=/nix/var"
      "--bind=/run/nix"
    ];
    Restart = "on-failure";
    RestartSec = "5s";
    KillMode = "mixed";
  };
};
```

### 4.2 Proxy environment variables

When `fetchProxy.enable` is true, the module injects proxy variables into both
the daemon's environment and `nix.conf`:

```nix
# Proxy address derived from fetch-proxy module options.
proxyUrl =
  let fp = config.aos.services.fetchProxy;
  in "http://172.30.0.1:${toString fp.listenPort}";

# Added to the nix-daemon systemd unit's Environment=
nixDaemonEnv = lib.optionalAttrs config.aos.services.fetchProxy.enable {
  http_proxy = proxyUrl;
  https_proxy = proxyUrl;
  no_proxy = "localhost,127.0.0.1";
};

# Added to nix.conf extraConfig
proxyNixConf = lib.optionalString config.aos.services.fetchProxy.enable ''
  # Proxy for fetchgit sandboxed builds
  experimental-features = configurable-impure-env
  impure-env = http_proxy=${proxyUrl} https_proxy=${proxyUrl} no_proxy=localhost,127.0.0.1
'';
```

### 4.3 nspawn configuration for the daemon container

```nix
environment.etc."systemd/nspawn/nix-daemon.nspawn" =
  lib.mkIf config.aos.services.fetchProxy.enable {
    text = ''
      [Exec]
      Boot=yes
      Capability=CAP_NET_ADMIN CAP_SYS_ADMIN

      [Network]
      Private=yes
      VirtualEthernet=yes

      [Files]
      Bind=/nix/store:/nix/store
      Bind=/nix/var:/nix/var
      Bind=/run/nix/daemon-socket:/run/nix/daemon-socket
      Bind=/etc/nix/nix.conf:/etc/nix/nix.conf:ro
    '';
  };
```

### 4.4 Socket forwarding

The Nix daemon socket must be accessible from the host (so `nix-build` and
`aos build` can connect). The container bind-mounts
`/run/nix/daemon-socket` back to the host:

```nix
# Bind mount in .nspawn [Files] section (see 4.3 above)
Bind=/run/nix/daemon-socket:/run/nix/daemon-socket
```

Host processes connect to `/run/nix/daemon-socket/socket` as before. The
socket is created by the daemon inside the container but is visible on the
host filesystem via the bind mount.

---

## 5. Configuration Flow

The complete flow from module evaluation through runtime operation:

```
BUILD TIME                              FIRST BOOT (Ignition)              RUNTIME
──────────                              ─────────────────────              ───────

modules/services/fetch-proxy.nix ──┐
modules/services/nix-daemon.nix  ──┤
systems/seed.nix                 ──┘
        │
        ▼
  lib.evalModules
        │
        ▼
  system.build.toplevel
  ├── /etc/squid/squid.conf              (generated from options)
  ├── /etc/squid/domains.txt             (default allowlist)
  ├── /etc/nix/nix.conf                  (with proxy settings)
  ├── /etc/systemd/nspawn/*.nspawn       (container configs)
  ├── /etc/systemd/system/*.service      (container units)
  ├── /etc/systemd/network/*.network     (veth configs)
  ├── /var/lib/machines/nix-daemon/      (container rootfs)
  └── /var/lib/machines/fetch-proxy/     (container rootfs)
        │
        ▼
  system.build.image ──────────────► Squashfs / raw image
                                           │
                                           ▼
                               Ignition config (per-machine JSON)
                               ├── /etc/hostname
                               ├── /etc/squid/domains.txt     (overwrite: true)
                               ├── /etc/squid/tls/proxy-ca.pem
                               ├── /etc/systemd/network/       (interface mapping)
                               └── /etc/ssh/authorized_keys.d/
                                           │
                                           ▼
                               ZFS datasets created (aos-pool)
                               /etc overlay mounted (upper on ZFS)
                               Per-machine files written to upper
                                           │
                                           ▼
                               systemd starts
                               ├── fetch-proxy.service  (starts first)
                               │   └── squid reads /etc/squid/domains.txt
                               └── nix-daemon.service   (starts after proxy)
                                   └── daemon env has http_proxy=...
                                                        │
                                                        ▼
                                                   RUNTIME UPDATES
                                                   ├── Edit /etc/squid/domains.txt
                                                   │   └── .path unit triggers reload
                                                   ├── Edit /etc/nix/nix.conf
                                                   │   └── restart nix-daemon
                                                   └── TLS cert rotation
                                                       └── LoadCredential= reload
```

### 5.1 Startup ordering

The systemd dependency chain ensures correct startup:

```
local-fs.target
    │
    ▼
network-online.target
    │
    ├──────────────────────────────┐
    ▼                              ▼
fetch-proxy.service          (networkd configures veth)
    │
    ▼
nix-daemon.service (container)
    │
    ▼
aos-build-images.service (if seed variant)
```

The `fetch-proxy.service` has `Before=nix-daemon.service` and the daemon
has `After=fetch-proxy.service` + `Wants=fetch-proxy.service`. This ensures
the proxy is running and the veth network is up before the daemon attempts
any source fetches.

---

## 6. Runtime Configuration Updates

Because `/etc` is writable via OverlayFS, all generated configuration files
can be modified at runtime without rebuilding the image.

### 6.1 Domain allowlist changes

```
Operator edits /etc/squid/domains.txt
        │
        ▼
systemd path unit (fetch-proxy-reload-watcher) detects modification
        │
        ▼
fetch-proxy-reload.service runs:
  machinectl shell fetch-proxy /usr/sbin/squid -k reconfigure
        │
        ▼
Squid re-reads domains.txt, applies new ACLs
(no downtime, no container restart)
```

This is a zero-downtime operation. Squid's `-k reconfigure` signal causes it
to re-read its configuration files and apply changes to new connections. Active
downloads are not interrupted.

### 6.2 Nix configuration changes

Modifying `/etc/nix/nix.conf` requires a daemon restart because Nix reads its
configuration at startup:

```sh
# Edit nix.conf (e.g., change max-jobs or add a substituter)
vi /etc/nix/nix.conf
systemctl restart nix-daemon.service
```

In-flight builds will be terminated by the restart. Completed store paths are
not affected.

### 6.3 Full configuration reset

To revert all runtime changes and return to the build-time defaults, clear
the OverlayFS upper directory:

```sh
# Clear per-machine /etc changes (requires reboot)
rm -rf /var/lib/aos/etc-overlay/upper/etc/squid
rm -rf /var/lib/aos/etc-overlay/upper/etc/nix
reboot
```

After reboot, the OverlayFS falls through to the squashfs lower layer,
restoring the original generated files.

---

## 7. Secrets Management

The isolation architecture requires several categories of secrets. AOS
uses systemd's credential infrastructure as the primary mechanism.

### 7.1 `LoadCredential=` (preferred)

systemd's `LoadCredential=` directive loads secrets from files into a
per-service credential directory (`$CREDENTIALS_DIRECTORY`) at service
start. The source files are not accessible to the running service after
loading, and the credential directory is private to the unit.

```nix
# In the fetch-proxy service unit
systemd.services."fetch-proxy" = {
  serviceConfig = {
    LoadCredential = [
      "proxy-ca.pem:/etc/squid/tls/proxy-ca.pem"
      "proxy-cert.pem:/etc/squid/tls/proxy-cert.pem"
      "proxy-key.pem:/etc/squid/tls/proxy-key.pem"
    ];
  };
};
```

| Secret | Delivery | Rotation |
|--------|----------|----------|
| Proxy TLS CA certificate | Ignition (first boot) or `LoadCredential=` | Replace file + restart service |
| Proxy TLS server cert/key | Ignition or `LoadCredential=` | Replace file + restart service |
| Nix signing key | `LoadCredential=` | Replace file + restart nix-daemon |
| SSH host keys | Ignition (first boot) | Manual replacement |

### 7.2 Ignition inline secrets

For static secrets that do not rotate, Ignition can deliver them inline in
the first-boot config. This is acceptable when the Ignition config is
delivered over an authenticated HTTPS channel:

```json
{
  "path": "/etc/squid/tls/proxy-ca.pem",
  "contents": { "inline": "-----BEGIN CERTIFICATE-----\n..." },
  "mode": 384
}
```

`mode: 384` is octal `0600` (owner read/write only).

### 7.3 Vault Agent (future)

For environments requiring automatic certificate rotation, a Vault Agent
sidecar can template secrets and signal services to reload:

```
Vault Agent (host)
    ├── renders /etc/squid/tls/proxy-cert.pem
    ├── renders /etc/squid/tls/proxy-key.pem
    └── signals fetch-proxy-reload.service
```

This is not part of the initial implementation but the architecture supports
it -- the path unit already watches for file changes, and `LoadCredential=`
re-reads files on service restart.

---

## 8. Multi-Tenant Configuration

Different machines receive different domain allowlists based on their role
or tenant assignment. The mechanism is straightforward: the base image
contains a default allowlist, and per-machine Ignition configs override it.

### 8.1 Default and override model

```
Squashfs (lower layer)              Ignition (upper layer)
───────────────────────             ──────────────────────
/etc/squid/domains.txt              /etc/squid/domains.txt
  github.com                          github.com
  ftp.gnu.org                         ftp.gnu.org
  kernel.org                          kernel.org
  ...                                 tenant-repo.example.com    ← added
                                      artifacts.tenant.internal  ← added
```

The OverlayFS upper layer file completely replaces the lower layer file --
there is no merge. Tenants that need additional domains must include the
full list (base + additions) in their Ignition config.

### 8.2 Per-variant defaults

Different system variants can have different default allowlists by setting
`fetchProxy.allowedDomains` in their system definition:

```nix
# systems/seed.nix
{
  imports = [
    ./server.nix
    ../modules/services/fetch-proxy.nix
    ../modules/services/nix-daemon.nix
    ../modules/services/seed.nix
  ];

  aos.services.fetchProxy.enable = true;
  aos.services.fetchProxy.allowedDomains = [
    "github.com"
    "raw.githubusercontent.com"
    "codeload.github.com"
    "ftp.gnu.org"
    "ftpmirror.gnu.org"
    "kernel.org"
    "cdn.kernel.org"
    "mirrors.edge.kernel.org"
    "static.rust-lang.org"
    "crates.io"
    "static.crates.io"
  ];

  aos.services.nix.enable = true;
  aos.services.seed.enable = true;
}
```

A more restricted variant (e.g., a build worker that only builds from cached
sources) could set a minimal allowlist or even an empty one, forcing all
fetches to hit a local `aos serve` substituter.

### 8.3 Fleet-wide allowlist management

For fleets of machines, the Ignition config is typically generated by an
orchestrator (e.g., a seed server or a provisioning API). The orchestrator
maintains a per-tenant domain list and injects it into each machine's
Ignition config at provisioning time:

```
Provisioning API
    │
    ├── tenant "platform-team"
    │   └── domains: [github.com, kernel.org, ...]
    │
    ├── tenant "ml-team"
    │   └── domains: [github.com, huggingface.co, ...]
    │
    └── generates Ignition JSON per machine
        └── /etc/squid/domains.txt with tenant-specific domains
```

---

## 9. ZFS Dataset for Container State

Container root filesystems and runtime state live on a dedicated ZFS dataset
with compression and no access-time tracking:

```nix
# In modules/services/fetch-proxy.nix (or nix-daemon.nix)
aos.filesystems.zfs.datasets."var/lib/machines" = {
  mountpoint = "/var/lib/machines";
  compression = "zstd-3";
  atime = "off";
};
```

This dataset is created by Ignition at first boot (see
`modules/services/ignition.nix` -- the unified `aos.filesystems.zfs.datasets`
option is read by the Ignition module's `ignition-zfs-datasets` service).

Additional datasets for container-specific state:

```nix
# Squid cache (separate dataset for independent snapshots/quotas)
aos.filesystems.zfs.datasets."var/lib/machines/fetch-proxy/var/spool/squid" = {
  mountpoint = "/var/lib/machines/fetch-proxy/var/spool/squid";
  compression = "zstd-3";
  atime = "off";
  recordsize = "128K";
};
```

The ZFS dataset hierarchy:

```
aos-pool
├── etc-overlay          ← /etc OverlayFS upper layer
├── var                  ← /var (writable state)
├── var/lib/machines     ← container rootfs images
│   ├── nix-daemon/      ← nix-daemon container root
│   └── fetch-proxy/     ← fetch-proxy container root
└── var/lib/nix          ← /nix (Nix store + state)
```

---

## 10. Integration Summary

The configuration delivery model follows AOS's existing patterns -- modules
declare options, generate files, and define systemd units. The three-phase
delivery (build, first-boot, runtime) aligns with the immutable root +
writable overlay architecture.

| Concern | Mechanism | Restart required? |
|---------|-----------|-------------------|
| Default domain allowlist | Build-time module option | N/A (baked in) |
| Per-machine domain overrides | Ignition `overwrite: true` | No (first boot) |
| Runtime domain changes | Edit file + path unit reload | No (hot reload) |
| Proxy environment for daemon | Module generates systemd `Environment=` | N/A (baked in) |
| `impure-env` for fetchgit | Module generates `nix.conf` | N/A (baked in) |
| TLS certificates | Ignition or `LoadCredential=` | Service restart |
| Container rootfs | Build-time, stored on ZFS | Container restart |
| Network interface mapping | Ignition per-machine | No (first boot) |

The fetch-proxy module cross-references the nix-daemon module: when
`fetchProxy.enable` is true, the nix-daemon module switches to container
mode, injects proxy environment variables, and adds `After=fetch-proxy.service`
ordering. This keeps the coupling explicit and visible in the module system
rather than hidden in ad-hoc scripts.
