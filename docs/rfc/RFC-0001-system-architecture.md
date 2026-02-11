# RFC-0001: ANDYL OS System Architecture

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS is an immutable, server-oriented Linux distribution built entirely from source using GNU Guix as the build system. This RFC defines the overall architecture: an immutable root filesystem with overlay strategies for `/etc` and `/var`, systemd as PID 1 (replacing Guix's default Shepherd), no Guix daemon at runtime on deployed machines, and content-addressed store paths providing deterministic, reproducible system images.

## Motivation

Traditional Linux distributions suffer from configuration drift, non-reproducible builds, and mutable system state that complicates auditing and rollback. ANDYL OS addresses these problems by treating the entire operating system as an immutable artifact produced by a deterministic build pipeline. The Guix build system provides content-addressed store paths and functional package management, while systemd provides battle-tested service management and hardware integration. By separating the build-time infrastructure (Guix daemon, compilers, build tools) from the deployed system (read-only store, systemd, minimal userspace), we achieve a minimal attack surface with maximum auditability.

## Design

### 1. Immutable OS Philosophy

ANDYL OS treats the deployed operating system as a sealed, read-only artifact. All system binaries, libraries, configuration templates, and kernel modules are built at image-creation time and deployed as a single atomic unit called a "generation." No package installation, compilation, or system modification occurs on deployed machines.

The core invariants are:

- `/gnu/store` is read-only at runtime. All packages, libraries, and system profiles live here.
- `/usr`, `/bin`, `/sbin`, `/lib` are either symlinks into `/gnu/store` or part of the read-only root filesystem.
- Only `/var`, `/etc` (via overlay), `/tmp`, and `/run` are writable.
- Updates are delivered as pre-built NAR archives containing new store paths. Switching to a new generation is an atomic symlink swap.

### 2. Relationship Between Guix Build System and Deployed System

Guix serves two distinct roles in ANDYL OS, and these roles are strictly separated:

**Build-time role (on CI/build infrastructure):**

- `guix-daemon` runs inside Docker containers on macOS or Linux build machines.
- The daemon executes builds in isolated namespaces, producing content-addressed outputs in `/gnu/store`.
- Package definitions, system configurations, and image assembly scripts are written in Guile Scheme.
- `guix system image` produces bootable disk images containing the complete system closure.
- `guix publish` serves pre-built packages as signed NAR archives for the binary cache.

**Runtime role (on deployed machines):**

- The Guix daemon does NOT run. There is no `guix-daemon` process, no build users, no build infrastructure.
- The `guix` CLI tool is not installed (except optionally for debugging).
- `/gnu/store` is bind-mounted or ZFS-mounted read-only.
- Updates arrive as pre-built NAR archives verified against the project signing key.
- An update agent (`andyl-os-agent`) handles receiving, verifying, unpacking, and registering new generations.

This separation eliminates build-time dependencies (compilers, build tools) from deployed machines, reduces the attack surface, and prevents non-determinism from building on heterogeneous hardware.

### 3. Content-Addressed Store Layout

Every artifact in the system lives under `/gnu/store` with a path of the form:

```
/gnu/store/<hash>-<name>-<version>
```

The hash is computed from all build inputs: source code, build scripts, dependencies (recursively), environment variables, and build system type. Changing any input produces a different hash.

A system profile is a store path containing a directory tree of symlinks:

```
/gnu/store/xyz789...-andyl-os-system/
  bin/                       -> symlinks to package binaries
  etc/                       -> system configuration templates
  lib/                       -> libraries and kernel modules
  boot/
    vmlinuz                  -> kernel image
    initrd                   -> initial ramdisk
  manifest                   -> JSON manifest of all paths
```

Generations are numbered symlinks pointing to system profiles:

```
/var/guix/profiles/
  system            -> system-42          (current generation)
  system-42         -> /gnu/store/xyz789...-andyl-os-system
  system-41         -> /gnu/store/ghi789...-andyl-os-system
```

### 4. Overlay Strategy for /etc

`/etc` requires special handling because many programs expect to both read and write to it. ANDYL OS uses OverlayFS to merge the immutable base `/etc` from the system profile with a writable upper layer:

```
                       +---------------+
                       |  merged /etc  |  <- processes see this
                       +-------+-------+
                               |
               +---------------+---------------+
               |               |               |
       +-------+-------+ +----+----+ +--------+--------+
       | lower (ro)     | | upper   | | work dir        |
       | /sysroot/etc   | | /var/   | | /var/            |
       | from profile   | | etc-    | | etc-overlay-     |
       |                | | overlay | | work             |
       +----------------+ +---------+ +-----------------+
```

The lower layer comes from the current generation's system profile and is read-only. The upper layer persists on `/var/etc-overlay` (a writable ZFS dataset or ext4 partition). Ignition writes machine-specific configuration (hostname, network, certificates) into the upper layer on first boot.

The overlay is mounted via a systemd mount unit:

```ini
[Mount]
What=overlay
Where=/etc
Type=overlay
Options=lowerdir=/sysroot/etc,upperdir=/var/etc-overlay,workdir=/var/etc-overlay-work
```

This approach preserves the full base `/etc` from the image while allowing targeted modifications. The upper layer captures only delta changes, making it easy to audit what has been modified from the base.

### 5. /var as the Writable Persistent Area

`/var` is the primary writable, persistent area. Its structure:

```
/var/
  lib/                    Persistent application state
    containers/           Container storage (containerd)
    kubelet/              Kubernetes node state
    systemd/              systemd persistent state
    extensions/           systemd-sysext images
    etcd/                 etcd data (control plane nodes)
  log/                    Persistent logs
    journal/              systemd journal
  cache/                  Caches (can be tmpfs)
  spool/                  Mail, cron (if needed)
  tmp/                    Persistent temp (30-day cleanup via tmpfiles.d)
  etc-overlay/            Upper layer for /etc overlay
  etc-overlay-work/       Work directory for /etc overlay
  guix/
    profiles/             Generation symlinks
```

On ZFS-based layouts, `/var` subtrees are separate datasets with appropriate properties:

```bash
zfs create -o mountpoint=/var/lib -o compression=zstd datapool/var-lib
zfs create -o mountpoint=/var/log -o compression=zstd datapool/var-log
```

### 6. systemd as PID 1

ANDYL OS uses systemd instead of Guix's default Shepherd init system. This is a significant departure from standard Guix System but provides access to the full systemd ecosystem.

**Why systemd over Shepherd:**

- systemd has first-class support for immutable/read-only root filesystems (`ProtectSystem=strict`, `systemd.volatile=overlay`).
- systemd-boot integration for generational boot management and boot counting.
- systemd-networkd, systemd-resolved, systemd-timesyncd provide integrated network management.
- systemd-tmpfiles and systemd-sysusers handle volatile state creation on boot.
- systemd-sysext enables role-based system extensions.
- systemd-journald provides structured logging.
- Broad ecosystem compatibility (Kubernetes, container runtimes, monitoring tools).

**Implications:**

- We cannot use Guix's `(service ...)` abstractions, which target Shepherd.
- systemd unit files are packaged as Guix packages and installed into the system profile.
- The system profile's `lib/systemd/system/` directory is linked into `/usr/lib/systemd/system/` at boot.

Key systemd components used:

| Component | Purpose |
|-----------|---------|
| journald | Structured binary logging in `/var/log/journal/` |
| networkd | Predictable server network management |
| resolved | DNS with DNSSEC and DNS-over-TLS support |
| timesyncd | Lightweight NTP (or chrony for high accuracy) |
| tmpfiles.d | Creates volatile directories and files on every boot |
| sysusers.d | Ensures system users/groups exist on boot |
| systemd-boot | UEFI boot manager with generation entries |
| systemd-sysext | Overlays role-specific extensions onto `/usr` |
| systemd-oomd | PSI-based OOM management |

### 7. No Guix Daemon at Runtime

This is a critical design decision. Deployed ANDYL OS machines:

- Do not run `guix-daemon`.
- Do not have `guix` CLI tools installed (except optionally for emergency debugging).
- Have a read-only `/gnu/store`.
- Receive updates as pre-built NAR archives, not as derivations to build.
- Do not have compilers, build tools, or development headers.

This eliminates:

- Build-time dependencies on deployed machines.
- The attack surface of a build daemon running as root.
- Resource consumption from local builds.
- Non-determinism from building on heterogeneous hardware.

The `andyl-os-agent` handles all update operations without requiring the Guix daemon.

### 8. Filesystem Layout

```
/                           Read-only root (ZFS readonly=on or bind-mount ro)
  /gnu/store/               Content-addressed store (read-only)
  /usr/                     Part of root (read-only); systemd-sysext can overlay
  /etc/                     OverlayFS (lower=profile /etc, upper=/var/etc-overlay)
  /var/                     Writable, persistent (ZFS or ext4)
    /var/lib/               Application state (containers, databases, kubelet)
    /var/log/               Persistent logs (systemd journal)
    /var/tmp/               Persistent temp with 30-day cleanup
    /var/guix/profiles/     Generation symlinks
  /tmp/                     tmpfs (volatile)
  /run/                     tmpfs (volatile)
  /boot/                    ESP mount point (FAT32)
    /boot/loader/entries/   systemd-boot generation entries
```

### 9. Boot Flow

```
UEFI firmware
  -> systemd-boot (from ESP)
    -> Selects generation entry (boot counting: tries left > 0)
      -> Load UKI or kernel + initrd + cmdline
        -> Linux kernel boots
          -> CPU microcode applied
          -> systemd in initrd (PID 1)
            -> udevd starts, devices enumerated
            -> ZFS module loaded, rpool imported
            -> Root dataset mounted on /sysroot
            -> Ignition runs (first boot only)
              -> switch-root to /sysroot
                -> systemd on real root (PID 1)
                  -> Mounts: /var (ZFS), /etc (overlay), /tmp (tmpfs), /run (tmpfs)
                  -> tmpfiles.d creates volatile dirs/files
                  -> sysusers.d ensures system users exist
                  -> networkd configures networking
                  -> systemd-sysext merges extensions into /usr
                  -> multi-user.target reached
                  -> systemd-bless-boot marks boot as good
                    -> System ready
```

## Alternatives Considered

**Guix System with Shepherd (default Guix approach):** Rejected because Shepherd lacks the ecosystem integration we need (boot counting, sysext, networkd, comprehensive container runtime support). Shepherd would require reimplementing significant infrastructure that systemd provides out of the box.

**NixOS:** Provides a similar immutable/generational model but uses Nix rather than Guix. Guix was chosen for its Scheme-based configuration language, full-source bootstrap capability, and the ability to define every package in our own channel without upstream dependencies.

**Flatcar Container Linux / Fedora CoreOS:** These are mature immutable OSes but do not provide the same level of build-from-source auditability. They rely on upstream binary packages. ANDYL OS builds everything through a verified bootstrap chain.

**Traditional distribution with configuration management (Ansible/Puppet):** Rejected because configuration management on mutable systems cannot guarantee reproducibility or provide atomic rollback. Configuration drift remains a fundamental problem.

## Security Considerations

- **Read-only root filesystem** prevents runtime modification of system binaries and libraries.
- **No Guix daemon at runtime** eliminates the attack surface of a privileged build daemon.
- **Content-addressed store paths** enable verification that deployed artifacts match their build derivations.
- **Signed updates** ensure that only authorized build infrastructure can produce deployable artifacts.
- **OverlayFS for /etc** makes it auditable which files have been modified from the base image by inspecting the upper layer.
- **Minimal userspace** (no compilers, no build tools) reduces available attack tools if the system is compromised.
- **systemd service hardening** (`ProtectSystem=strict`, `PrivateTmp=yes`, `ReadWritePaths=`) restricts each service to its required resources.

## Compatibility

- **Guix build infrastructure:** This design uses Guix as a build tool only. All Guix modules (`(guix packages)`, `(guix build-system gnu)`, etc.) are used at build time. The Guix version used for building is pinned and treated as a build-time dependency.
- **systemd ecosystem:** Full compatibility with systemd-based tooling, including container runtimes (containerd), Kubernetes (kubelet), and monitoring systems.
- **UEFI systems:** Requires UEFI firmware with systemd-boot. Legacy BIOS boot is not supported.
- **Container runtimes:** containerd and runc are fully supported. All mutable state lives on `/var`.

## Open Questions

1. **Guix tool versioning:** The Guix installation itself (providing the build DSL and daemon) is a build-time dependency. Should we pin its version explicitly, vendor the Guix Scheme modules, or accept it as an external dependency?
2. **systemd-sysext adoption timing:** Should role-specific software be delivered as system extensions from day one, or should we start with everything in the base image and split later?
3. **Secure Boot:** Should we sign UKIs for UEFI Secure Boot? This requires key management infrastructure but hardens the boot chain.
4. **Guix service layer:** How much of Guix's service abstraction do we replicate for systemd? Full declarative model generating unit files, or manually package unit files?

## References

- GNU Guix Manual: https://guix.gnu.org/manual/
- systemd documentation: https://systemd.io/
- Boot Loader Specification: https://systemd.io/BOOT_LOADER_SPECIFICATION/
- systemd-sysext: https://www.freedesktop.org/software/systemd/man/systemd-sysext.html
- OverlayFS documentation: https://docs.kernel.org/filesystems/overlayfs.html
- Fedora CoreOS design: https://docs.fedoraproject.org/en-US/fedora-coreos/
