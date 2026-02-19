# Container Isolation

> Part of the [Daemon Isolation Architecture](README.md)

Two systemd-nspawn containers enforce the principle of least privilege for the
Nix daemon and its network path. The **nix-daemon container** runs the Nix
daemon with no direct network access and exclusive write access to the AOS
store. The **fetch-proxy container** runs a Squid forward proxy with internet
access via macvlan and provides the only network path for source fetches.

---

## 1. Container Overview

| Property | nix-daemon | fetch-proxy |
|---|---|---|
| Purpose | Runs `nix-daemon`, performs builds | Runs Squid forward proxy + dnsmasq |
| Network | `--private-network` -- no host interfaces | macvlan on internet-facing NIC |
| Store access | Bind-mount `/var/lib/aos/store` (rw) | None |
| Internet | None -- all fetches go through `http_proxy` | Direct via macvlan |
| Boot mode | `--boot` (full systemd init) | `--boot` (full systemd init) |
| Image path | `/var/lib/machines/nix-daemon/` | `/var/lib/machines/fetch-proxy/` |

---

## 2. Boot Mode: `--boot` vs `--as-pid2`

Both containers use `--boot` (`Boot=yes` in the `.nspawn` file), which runs a
full systemd init tree inside the container. This is required because both
containers depend on systemd service management features that `--as-pid2`
cannot provide.

### Why nix-daemon needs `--boot`

The Nix daemon's sandbox creates isolated build environments that require
multiple Linux namespace and process management features:

- **Build users (nixbld1-32)** -- systemd manages the `nix-daemon.service` unit
  that spawns the daemon, which `setuid`s to per-build users. Proper user
  session tracking requires init.
- **Mount/PID/network namespaces** -- the Nix sandbox calls `unshare(2)` to
  create per-build namespaces. This requires `/proc`, `/sys`, and `/dev` to be
  properly mounted by init, not minimally stub-mounted by `--as-pid2`.
- **Cgroup delegation** -- the container's systemd must own its cgroup subtree
  to manage resource limits on build processes. Without init, there is no cgroup
  manager.
- **Proper `/proc` `/sys` `/dev`** -- `--boot` mounts a full procfs, sysfs, and
  devtmpfs. The Nix sandbox bind-mounts a subset of `/dev` into each build
  chroot and needs `/proc/self/mountinfo` to track mount state.

### Why fetch-proxy needs `--boot`

- **systemd-networkd** -- handles interface configuration for the macvlan and
  veth interfaces. `--as-pid2` does not start networkd.
- **Service management** -- squid and dnsmasq run as separate systemd units with
  dependency ordering, restart policies, and journal logging.
- **Journal logging** -- `journalctl` inside the container provides unified
  logging for proxy access logs, DNS queries, and service lifecycle events.

### Why not `--as-pid2`

`--as-pid2` is lighter (no full init, the specified binary runs as PID 2 under
a minimal systemd stub) but it does not support:

- `systemd-networkd` or any socket-activated services
- `systemctl` / service management
- Proper cgroup delegation
- Multi-service supervision

For single-process, network-free containers, `--as-pid2` is appropriate. These
containers are not that.

---

## 3. Capabilities

systemd-nspawn's default capability set for `--boot` containers includes:

```
CAP_AUDIT_CONTROL   CAP_AUDIT_WRITE    CAP_CHOWN          CAP_DAC_OVERRIDE
CAP_DAC_READ_SEARCH CAP_FOWNER         CAP_FSETID         CAP_IPC_OWNER
CAP_KILL            CAP_LEASE          CAP_LINUX_IMMUTABLE CAP_MKNOD
CAP_NET_ADMIN       CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_RAW
CAP_SETFCAP         CAP_SETGID         CAP_SETPCAP        CAP_SETUID
CAP_SYS_ADMIN       CAP_SYS_BOOT       CAP_SYS_CHROOT    CAP_SYS_NICE
CAP_SYS_PTRACE      CAP_SYS_RESOURCE   CAP_SYS_TTY_CONFIG
```

### nix-daemon capabilities

The Nix daemon's sandbox requires a substantial capability set. All required
capabilities are included in the default set -- no extra `--capability=` flags
are needed.

| Capability | Reason |
|---|---|
| `CAP_SYS_ADMIN` | Creating mount namespaces, bind mounts inside sandbox chroot |
| `CAP_SYS_CHROOT` | `chroot()` for build sandbox isolation |
| `CAP_SETUID` / `CAP_SETGID` | Switching to nixbld build users (nixbld1-32) |
| `CAP_DAC_OVERRIDE` | Accessing store paths during builds regardless of ownership |
| `CAP_FOWNER` | Setting ownership on store paths after builds complete |
| `CAP_MKNOD` | Creating device nodes (`/dev/null`, `/dev/zero`, etc.) in sandbox `/dev` |
| `CAP_NET_ADMIN` | Creating network namespaces for sandboxed builds (non-fixed-output) |

### fetch-proxy capabilities

The proxy container has a smaller attack surface. It needs only:

| Capability | Reason |
|---|---|
| `CAP_NET_BIND_SERVICE` | Squid may bind to port 3128 (>1024, but needed if reconfigured to 80/443) |
| `CAP_NET_RAW` | Raw socket access for ICMP health checks and dnsmasq |
| `CAP_NET_ADMIN` | Configuring the macvlan and veth interfaces via networkd |

The fetch-proxy should drop all other capabilities via `--drop-capability=` in
the `.nspawn` file. In practice, the default set is acceptable since the
container has no store access, but defense-in-depth argues for dropping
`CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, etc.

---

## 4. Bind Mounts

The nix-daemon container needs read-write access to the AOS store and Nix state
directories. The fetch-proxy container has **no bind mounts to the store** --
it cannot read or write store paths.

```
Container       Host Path                              Container Path                         Mode
-----------     -----------------------------------    -----------------------------------    ----
nix-daemon      /var/lib/aos/store                     /var/lib/aos/store                     rw
nix-daemon      /var/lib/aos/var/nix                   /var/lib/aos/var/nix                   rw
nix-daemon      /var/lib/aos/var/nix/daemon-socket     /var/lib/aos/var/nix/daemon-socket     rw
nix-daemon      /etc/nix/nix.conf                      /etc/nix/nix.conf                      ro
fetch-proxy     (none -- no store access)
```

### Why bind-mount the socket directory, not the socket file

The Nix daemon creates its Unix domain socket at startup. If you bind-mount the
socket file itself, the mount is established before the daemon starts -- but the
daemon calls `unlink()` + `bind()` on the path, which replaces the inode. The
bind-mount then points to a stale inode, and the host sees the old (deleted)
socket.

By bind-mounting the **directory** (`/var/lib/aos/var/nix/daemon-socket/`), the
directory is mounted before the container's init starts. When the daemon creates
the socket inside the directory, the new inode is visible on the host
immediately because the directory mount shares the underlying filesystem. The
host process (`aos serve`) connects to
`/var/lib/aos/var/nix/daemon-socket/socket` and reaches the daemon inside the
container.

### Store path semantics

The bind-mount uses the same path inside and outside the container
(`/var/lib/aos/store`). This is critical because:

1. Nix is compiled with `--store-dir=/var/lib/aos/store` -- the path is a
   compile-time constant baked into the daemon binary.
2. Store paths are self-referencing (the hash includes the path prefix). If
   paths were mounted at a different location inside the container, all hash
   computations would break.
3. The daemon's SQLite database (`/var/lib/aos/var/nix/db/db.sqlite`) records
   absolute store paths. These must match the actual mount location.

---

## 5. Socket Forwarding

The host needs to communicate with the Nix daemon running inside the container.
Three options were evaluated:

### Option A: Bind-mount the socket directory (recommended)

The daemon-socket directory is bind-mounted into the container (see section 4).
The daemon creates the socket inside the mounted directory, and it appears on
the host automatically. No additional forwarding infrastructure is needed.

```
Host process                   Container
    │                              │
    ├── connect() ────────────────►│ /var/lib/aos/var/nix/daemon-socket/socket
    │   (Unix domain socket)       │ (same inode via bind-mount)
    │                              │
```

This is the simplest approach and avoids any additional daemons or
configuration. The socket supports the full Nix daemon protocol (it is the
real socket, not a proxy).

### Option B: `/run/host/unix-export/`

The [systemd Container Interface][container-interface] specification defines
`/run/host/unix-export/` as a directory where the container can place Unix
domain sockets that should be accessible from the host. systemd-nspawn
automatically bind-mounts this directory bidirectionally.

This is more "correct" from a systemd perspective but adds an unnecessary layer
of indirection. The daemon would need to be configured to create its socket at
a non-default path inside `/run/host/unix-export/`, which complicates the Nix
configuration.

[container-interface]: https://systemd.io/CONTAINER_INTERFACE/

### Option C: `systemd-socket-proxyd`

A socket-activation proxy that listens on the host and forwards connections
into the container. This provides socket-activation semantics (the proxy
socket exists before the container starts) and is useful when the daemon
should only start on first connection.

```
[Socket]
ListenStream=/var/lib/aos/var/nix/daemon-socket/socket

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd \
    --exit-idle-time=30s \
    /run/systemd/nspawn/nix-daemon/socket
```

This adds complexity (an extra service unit, an extra process in the data
path) with no meaningful benefit for a daemon that should always be running.
Appropriate only if lazy-start semantics are desired.

**Decision**: Option A. Bind-mount the directory. Zero moving parts.

---

## 6. `machinectl` and Template Units

systemd-nspawn containers integrate with `machinectl` through the
`systemd-nspawn@.service` template unit. The instance name after `@` identifies
the machine.

### Machine management

```
machinectl enable nix-daemon        # Enable at boot
machinectl start nix-daemon         # Start the container
machinectl status nix-daemon        # Show status, PID, IP, OS info
machinectl shell nix-daemon         # Open a shell inside the container
machinectl poweroff nix-daemon      # Graceful shutdown (sends SIGRTMIN+4)
machinectl list                     # List running machines
```

### File layout

```
/var/lib/machines/
├── nix-daemon/                     # Container rootfs (directory tree)
│   ├── etc/
│   ├── usr/
│   └── var/
└── fetch-proxy/                    # Container rootfs (directory tree)
    ├── etc/
    ├── usr/
    └── var/

/etc/systemd/nspawn/
├── nix-daemon.nspawn               # Override defaults for nix-daemon container
└── fetch-proxy.nspawn              # Override defaults for fetch-proxy container
```

The `.nspawn` files in `/etc/systemd/nspawn/` override the defaults from the
`systemd-nspawn@.service` template. They are matched by filename to the machine
name (e.g. `nix-daemon.nspawn` applies to the `nix-daemon` machine).

### Template unit

The `systemd-nspawn@.service` template unit shipped by systemd calls
`systemd-nspawn --quiet --keep-unit --boot --link-journal=try-guest
--network-veth -U --settings=override --machine=%i`. The `.nspawn` files
override specific settings (network mode, bind mounts, capabilities). Settings
in the `.nspawn` file take precedence because of `--settings=override`.

---

## 7. Cgroup Delegation

The container's systemd init needs full control over its cgroup subtree to
manage services, resource limits, and the Nix daemon's per-build cgroups.

### Default delegation

The `systemd-nspawn@.service` template unit ships with `Delegate=yes` in its
`[Service]` section. This tells the host's systemd to delegate the entire
cgroup subtree to the container, meaning:

- The container's systemd (PID 1 inside) becomes the cgroup manager for all
  processes in its subtree.
- The container can create child cgroups freely (e.g. for each systemd service,
  for each Nix build sandbox).
- The host does not interfere with cgroup operations inside the container.

### Resource control overrides

If resource limits are needed on the containers themselves, override the
delegation to specify which controllers are delegated:

```ini
# /etc/systemd/system/systemd-nspawn@nix-daemon.service.d/resources.conf
[Service]
Delegate=cpu cpuset io memory pids

# Limit the nix-daemon container to 75% of CPU and 32G RAM
CPUQuota=75%
MemoryMax=32G
TasksMax=4096
```

For the fetch-proxy container, tighter limits are appropriate since it only
runs Squid and dnsmasq:

```ini
# /etc/systemd/system/systemd-nspawn@fetch-proxy.service.d/resources.conf
[Service]
CPUQuota=10%
MemoryMax=2G
TasksMax=256
```

### Nix sandbox cgroups

Inside the nix-daemon container, the Nix daemon creates per-build cgroups under
its own cgroup subtree. This requires that the container's systemd has delegated
the cgroup controllers to the `nix-daemon.service` unit inside the container.
The container's `nix-daemon.service` unit should include:

```ini
[Service]
Delegate=yes
```

This creates a three-level delegation chain:

```
host systemd
  └── systemd-nspawn@nix-daemon.service  (Delegate=yes)
        └── container systemd
              └── nix-daemon.service     (Delegate=yes)
                    ├── build-sandbox-1  (per-build cgroup)
                    ├── build-sandbox-2
                    └── ...
```

---

## 8. Container Rootfs

Each container needs a minimal root filesystem under `/var/lib/machines/<name>/`.
These rootfs images are built as Nix derivations from AOS packages -- hermetic,
reproducible, no nixpkgs. The derivation assembles a directory tree suitable for
booting under `systemd-nspawn --boot`.

### nix-daemon rootfs

The nix-daemon rootfs must contain everything the daemon needs to operate:

```
/var/lib/machines/nix-daemon/
├── etc/
│   ├── passwd                      # root + nixbld1-32 users
│   ├── group                       # root + nixbld group
│   ├── shadow                      # locked passwords
│   ├── nix/nix.conf                # (overridden by bind-mount)
│   ├── systemd/system/
│   │   └── nix-daemon.service      # systemd unit for the daemon
│   └── os-release                  # required by machinectl
├── usr/
│   ├── bin/
│   │   ├── nix-daemon              # the daemon binary
│   │   └── nix                     # CLI (for nix-store operations)
│   └── lib/
│       ├── libc.so.6               # glibc
│       ├── libsqlite3.so           # SQLite (Nix dependency)
│       ├── libcurl.so              # libcurl (for builtin:fetchurl)
│       ├── libssl.so               # OpenSSL (for HTTPS fetches)
│       └── ...                     # other Nix runtime dependencies
├── var/
│   └── lib/aos/                    # (bind-mounted from host)
│       ├── store/
│       ├── var/nix/
│       └── var/nix/daemon-socket/
└── tmp/                            # build sandbox tmpdir
```

The `/etc/passwd` must include build users:

```
root:x:0:0:root:/root:/bin/sh
nixbld1:x:30001:30000:Nix build user 1:/var/empty:/usr/sbin/nologin
nixbld2:x:30002:30000:Nix build user 2:/var/empty:/usr/sbin/nologin
...
nixbld32:x:30032:30000:Nix build user 32:/var/empty:/usr/sbin/nologin
```

And `/etc/group`:

```
root:x:0:
nixbld:x:30000:nixbld1,nixbld2,...,nixbld32
```

### fetch-proxy rootfs

The fetch-proxy rootfs is smaller -- it only needs the proxy and DNS services:

```
/var/lib/machines/fetch-proxy/
├── etc/
│   ├── passwd                      # root + squid user
│   ├── group                       # root + squid group
│   ├── squid/
│   │   └── squid.conf              # forward proxy config with domain ACLs
│   ├── dnsmasq.conf                # DNS forwarder config
│   ├── systemd/system/
│   │   ├── squid.service
│   │   └── dnsmasq.service
│   ├── systemd/network/
│   │   ├── 10-mv-eth0.network      # macvlan interface config
│   │   └── 20-veth-proxy.network   # veth interface config (172.30.0.1/30)
│   └── os-release
├── usr/
│   ├── bin/
│   │   ├── squid
│   │   └── dnsmasq
│   └── lib/
│       ├── libc.so.6
│       └── ...
└── var/
    ├── spool/squid/                # Squid cache directory
    └── log/squid/                  # Squid access/cache logs
```

### Building the rootfs as a Nix derivation

Each rootfs should be assembled by a Nix derivation that copies the required
AOS packages into a directory tree:

```nix
# Pseudocode -- actual implementation will be an AOS mkDerivation
{ mkDerivation, nix, glibc, openssl, curl, sqlite, systemd, ... }:
mkDerivation {
  pname = "nix-daemon-rootfs";
  version = "1.0.0";

  buildDeps = [ ];
  runtimeDeps = [ ];

  phases = [
    ''
      mkdir -p $out/{etc,usr/bin,usr/lib,var/lib/aos,tmp}

      # Copy nix binaries
      cp ${nix}/bin/nix-daemon $out/usr/bin/
      cp ${nix}/bin/nix $out/usr/bin/

      # Copy runtime libraries
      for lib in ${glibc}/lib/libc.so.6 ${sqlite}/lib/libsqlite3.so ...; do
        cp "$lib" $out/usr/lib/
      done

      # Generate /etc/passwd, /etc/group, systemd units, etc.
      ...
    ''
  ];
}
```

The rootfs derivation is a pure Nix build -- reproducible and hermetic. No
runtime state is included. The store and Nix state directories are empty in the
rootfs and populated at runtime via bind mounts.

---

## 9. `.nspawn` Configuration Files

### `/etc/systemd/nspawn/nix-daemon.nspawn`

```ini
[Exec]
Boot=yes
# Full systemd init for build user management, namespace creation, cgroups

[Files]
# AOS store -- read-write, same path inside and outside
Bind=/var/lib/aos/store
# Nix state (DB, GC roots, logs)
Bind=/var/lib/aos/var/nix
# Daemon socket directory -- host processes connect here
Bind=/var/lib/aos/var/nix/daemon-socket
# Nix configuration -- read-only, host controls the config
BindReadOnly=/etc/nix/nix.conf

[Network]
# No host network interfaces -- completely isolated
Private=yes
# veth pair to fetch-proxy is configured via systemd-networkd
# inside the container and host-side nspawn network setup
VirtualEthernet=no
```

The `Private=yes` setting creates a private network namespace with only a
loopback interface. The veth pair connecting to the fetch-proxy container is
created externally (see [Network Architecture](03-network-architecture.md))
and moved into the container's network namespace.

### `/etc/systemd/nspawn/fetch-proxy.nspawn`

```ini
[Exec]
Boot=yes
# Full systemd init for networkd, squid, dnsmasq

[Files]
# No store access -- the proxy cannot read or write store paths

[Network]
# macvlan on the internet-facing interface for upstream connectivity
MACVLAN=eth0
# Private network namespace -- macvlan is the only external interface
Private=yes
VirtualEthernet=no
```

The `MACVLAN=eth0` setting creates a macvlan interface inside the container
attached to the host's internet-facing NIC. The container sees this as
`mv-eth0` and configures it via systemd-networkd. The veth pair to the
nix-daemon container is created externally and moved into the namespace.

### Overriding the template unit

Some settings cannot be expressed in `.nspawn` files and require drop-in
overrides on the `systemd-nspawn@.service` template:

```ini
# /etc/systemd/system/systemd-nspawn@nix-daemon.service.d/override.conf
[Service]
# Ensure cgroup delegation for nested sandboxing
Delegate=yes
# Increase timeout for clean shutdown (daemon may be mid-build)
TimeoutStopSec=120
```

---

## 10. Prerequisite: systemd `-Dmachined=true`

The container infrastructure depends on `systemd-machined.service`, which
provides the `machinectl` command, the `systemd-nspawn@.service` template unit,
and the machine registration D-Bus API. This is currently **disabled** in the
AOS systemd package.

**Current state** (`pkgs/init/systemd.nix`, line 164):

```
-Dmachined=false
```

This must be changed to:

```
-Dmachined=true
```

### What `-Dmachined=true` enables

| Component | Binary | Purpose |
|---|---|---|
| `systemd-machined.service` | `systemd-machined` | D-Bus service that tracks running containers/VMs |
| `machinectl` | `machinectl` | CLI for managing machines (start, stop, shell, status) |
| `systemd-nspawn@.service` | `systemd-nspawn` | Template unit for container instances |
| `systemd-nspawn` | `systemd-nspawn` | The container runtime itself |
| `nss-mymachines` | `libnss_mymachines.so` | NSS module for resolving container hostnames |

### Build implications

Enabling machined does not introduce new external dependencies. `systemd-nspawn`
and `systemd-machined` are part of the systemd source tree and are built from
the same source tarball. The meson flag controls whether these components are
compiled and installed. The only additional build-time cost is compiling a few
extra source files -- there are no new library dependencies beyond what systemd
already requires.

### Additional meson flags to consider

Alongside `-Dmachined=true`, the following related flags should be evaluated:

| Flag | Current | Recommended | Reason |
|---|---|---|---|
| `-Dmachined=` | `false` | `true` | Required for container management |
| `-Dimportd=` | (check) | `true` | `systemd-importd` for pulling container images (optional) |
| `-Dnspawn=` | (check) | `true` | Explicit enable for `systemd-nspawn` binary |

The `-Dnspawn=` flag may be implicitly enabled by `-Dmachined=true` depending
on the systemd version, but setting it explicitly ensures the binary is built.
