# RFC-0001: ANDYL OS System Architecture

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS is an immutable, server-oriented Linux distribution built entirely from source using a custom Nix infrastructure. This RFC defines the overall architecture: an immutable root filesystem with overlay strategies for `/etc` and `/var`, systemd as PID 1, no Nix daemon at runtime on deployed machines, and content-addressed store paths providing deterministic, reproducible system images. The build system uses stable Nix features exclusively (no flakes, no experimental features), with a custom Rust CLI (`aos`) providing the user interface.

## Motivation

Traditional Linux distributions suffer from configuration drift, non-reproducible builds, and mutable system state that complicates auditing and rollback. ANDYL OS addresses these problems by treating the entire operating system as an immutable artifact produced by a deterministic build pipeline. The Nix build system provides content-addressed store paths and functional package management, while systemd provides battle-tested service management and hardware integration. By separating the build-time infrastructure (Nix daemon, compilers, build tools) from the deployed system (read-only store, systemd, minimal userspace), we achieve a minimal attack surface with maximum auditability.

## Design

### 1. Immutable OS Philosophy

ANDYL OS treats the deployed operating system as a sealed, read-only artifact. All system binaries, libraries, configuration templates, and kernel modules are built at image-creation time and deployed as a single atomic unit called a "generation." No package installation, compilation, or system modification occurs on deployed machines.

The core invariants are:

- `/nix/store` is read-only at runtime. All packages, libraries, and system profiles live here.
- `/usr`, `/bin`, `/sbin`, `/lib` are either symlinks into `/nix/store` or part of the read-only root filesystem.
- Only `/var`, `/etc` (via overlay), `/tmp`, and `/run` are writable.
- Updates are delivered as compressed store path archives containing new store paths. Switching to a new generation is an atomic symlink swap.

### 2. Relationship Between Nix Build System and Deployed System

Nix serves two distinct roles in ANDYL OS, and these roles are strictly separated:

**Build-time role (on CI/build infrastructure):**

- `nix-daemon` runs on Linux build machines. No Docker is required -- builds happen natively.
- The daemon executes builds in isolated sandboxes, producing content-addressed outputs in `/nix/store`.
- Package definitions, system configurations, and image assembly scripts are written in the Nix language.
- `nix-build default.nix -A images.<variant>` produces bootable disk images containing the complete system closure.

**Runtime role (on deployed machines):**

- The Nix daemon does NOT run. There is no `nix-daemon` process, no build users, no build infrastructure.
- The `nix` CLI tools are not installed (except optionally for debugging).
- `/nix/store` is mounted read-only.
- Updates arrive as pre-built, signed store path archives verified against the project signing key.
- An update agent (`aos-update`) handles receiving, verifying, unpacking, and registering new generations.

This separation eliminates build-time dependencies (compilers, build tools) from deployed machines, reduces the attack surface, and prevents non-determinism from building on heterogeneous hardware.

### 3. No Flakes: Custom CLI Instead

ANDYL OS does not use Nix flakes or any experimental Nix features. Instead, it provides a custom Rust CLI called `aos` that wraps standard `nix-build` and `nix-instantiate` commands.

**Why not flakes:**

- Still marked "experimental" after years of use.
- Copies the entire repository into `/nix/store` on every evaluation.
- Complex lock file format with surprising behaviors.
- Conflates too many concerns (versioning, composability, CLI UX, evaluation hermeticity).

**The `aos` CLI provides:**

```
aos build <package>            Build a package from source
aos system build <variant>     Build a system closure
aos system image <variant>     Build a bootable disk image
aos system eval <variant>      Show evaluated system configuration
aos show <package>             Show package metadata
aos test [layer] [suite]       Run tests (eval, build, vm, fleet)
aos gc                         Garbage-collect old store paths
```

Each `aos` subcommand is a transparent wrapper around stable `nix-build` or `nix-instantiate` invocations against the single `default.nix` entry point. The CLI adds colored output, progress indicators, `--json` mode for scripting, and shell completions.

**Reproducibility without flakes:** The `default.nix` file is the single entry point. It has no external inputs -- every source URL and hash is pinned in `pkgs/sources.nix`. The entire build is determined by the Git commit of this repository. No lock file is needed because there are no floating inputs to lock.

### 4. Content-Addressed Store Layout

Every artifact in the system lives under `/nix/store` with a path of the form:

```
/nix/store/<hash>-<name>-<version>
```

The hash is computed from all build inputs: source code, build scripts, dependencies (recursively), environment variables, and build system type. Changing any input produces a different hash.

A system profile is a store path containing a directory tree of symlinks:

```
/nix/store/xyz789...-aos-system/
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
/var/lib/aos/generations/
  system            -> system-42          (current generation)
  system-42         -> /nix/store/xyz789...-aos-system
  system-41         -> /nix/store/ghi789...-aos-system
```

### 5. Overlay Strategy for /etc

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

The lower layer comes from the current generation's system profile and is read-only. The upper layer persists on `/var/etc-overlay` (a writable ZFS dataset). Ignition writes machine-specific configuration (hostname, network, certificates) into the upper layer on first boot.

The overlay is mounted via a systemd mount unit:

```ini
[Mount]
What=overlay
Where=/etc
Type=overlay
Options=lowerdir=/sysroot/etc,upperdir=/var/etc-overlay,workdir=/var/etc-overlay-work
```

This approach preserves the full base `/etc` from the image while allowing targeted modifications. The upper layer captures only delta changes, making it easy to audit what has been modified from the base.

### 6. /var as the Writable Persistent Area

`/var` is the primary writable, persistent area. Its structure:

```
/var/
  lib/                    Persistent application state
    containers/           Container storage (containerd)
    kubelet/              Kubernetes node state
    systemd/              systemd persistent state
    etcd/                 etcd data (control plane nodes)
    aos/                  AOS state (generations, updates)
  log/                    Persistent logs
    journal/              systemd journal
  cache/                  Caches (can be tmpfs)
  spool/                  Mail, cron (if needed)
  tmp/                    Persistent temp (30-day cleanup via tmpfiles.d)
  etc-overlay/            Upper layer for /etc overlay
  etc-overlay-work/       Work directory for /etc overlay
```

On ZFS-based layouts, `/var` subtrees are separate datasets with appropriate properties:

```bash
zfs create -o mountpoint=/var/lib -o compression=zstd datapool/var-lib
zfs create -o mountpoint=/var/log -o compression=zstd datapool/var-log
```

### 7. systemd as PID 1

ANDYL OS uses systemd as the init system. systemd unit files are generated by the NixOS-inspired module system and installed into the system profile.

**Why systemd:**

- systemd has first-class support for immutable/read-only root filesystems (`ProtectSystem=strict`, `systemd.volatile=overlay`).
- systemd-boot integration for generational boot management and boot counting.
- systemd-networkd, systemd-resolved, systemd-timesyncd provide integrated network management.
- systemd-tmpfiles and systemd-sysusers handle volatile state creation on boot.
- systemd-journald provides structured logging.
- Broad ecosystem compatibility (Kubernetes, container runtimes, monitoring tools).

**Module-generated systemd units:** The AOS module system (see `modules/`) generates systemd unit files declaratively. Each module defines options with typed defaults, and when enabled, emits the corresponding systemd services, timers, and configuration files. This replaces both NixOS's activation scripts and manual unit file packaging.

Key systemd components used:

| Component | Purpose |
|-----------|---------|
| journald | Structured binary logging in `/var/log/journal/` |
| networkd | Predictable server network management |
| resolved | DNS with DNSSEC and DNS-over-TLS support |
| tmpfiles.d | Creates volatile directories and files on every boot |
| sysusers.d | Ensures system users/groups exist on boot |
| systemd-boot | UEFI boot manager with generation entries |
| systemd-oomd | PSI-based OOM management |

### 8. No Nix Daemon at Runtime

This is a critical design decision. Deployed ANDYL OS machines:

- Do not run `nix-daemon`.
- Do not have `nix` CLI tools installed (except optionally for emergency debugging).
- Have a read-only `/nix/store`.
- Receive updates as pre-built, signed store path archives, not as derivations to build.
- Do not have compilers, build tools, or development headers.

This eliminates:

- Build-time dependencies on deployed machines.
- The attack surface of a build daemon running as root.
- Resource consumption from local builds.
- Non-determinism from building on heterogeneous hardware.

The `aos-update` agent handles all update operations without requiring the Nix daemon.

### 9. Filesystem Layout

```
/                           Read-only root (ext4 mounted read-only)
  /nix/store/               Content-addressed store (read-only)
  /usr/                     Part of root (read-only)
  /etc/                     OverlayFS (lower=profile /etc, upper=/var/etc-overlay)
  /var/                     Writable, persistent (ZFS)
    /var/lib/               Application state (containers, databases, kubelet)
    /var/log/               Persistent logs (systemd journal)
    /var/tmp/               Persistent temp with 30-day cleanup
    /var/lib/aos/           AOS state (generations, update staging)
  /tmp/                     tmpfs (volatile)
  /run/                     tmpfs (volatile)
  /boot/                    ESP mount point (FAT32)
    /boot/loader/entries/   systemd-boot generation entries
```

### 10. Boot Flow

```
UEFI firmware
  -> systemd-boot (from ESP)
    -> Selects generation entry (boot counting: tries left > 0)
      -> Load kernel + initrd + cmdline
        -> Linux kernel boots
          -> CPU microcode applied
          -> systemd in initrd (PID 1)
            -> udevd starts, devices enumerated
            -> ZFS module loaded, pool imported
            -> Root partition mounted on /sysroot
            -> Ignition runs (first boot only)
              -> switch-root to /sysroot
                -> systemd on real root (PID 1)
                  -> Mounts: /var (ZFS), /etc (overlay), /tmp (tmpfs), /run (tmpfs)
                  -> tmpfiles.d creates volatile dirs/files
                  -> sysusers.d ensures system users exist
                  -> networkd configures networking
                  -> multi-user.target reached
                  -> systemd-bless-boot marks boot as good
                    -> System ready
```

### 11. Module System Design

ANDYL OS uses a custom NixOS-inspired module system (`lib/modules.nix`, ~300 lines) with improvements over the NixOS module system:

**No priority numbers.** NixOS uses `mkDefault` (priority 1000), `mkForce` (priority 50), and `mkOverride N` -- confusing numeric priorities. AOS uses named layers with fixed evaluation order: module defaults, then base system, then variant, then site-specific overrides. Later modules simply override earlier ones using standard Nix attrset merge (`//`).

**No activation scripts.** NixOS runs imperative Bash "activation scripts" at switch-time. AOS is fully declarative -- systemd units handle all runtime state, and the system image contains the complete filesystem.

**Explicit module list.** Modules are listed in `modules/module-list.nix` rather than auto-discovered, for fast evaluation.

**~20 modules vs NixOS's ~1500.** The module set is minimal and purpose-built.

### 12. Package System Design

Packages are Nix derivations using a custom `mkDerivation` from `lib/derivations.nix` with improvements over nixpkgs:

**Clean dependency names:**

```nix
mkDerivation {
  buildDeps = [ gcc pkg-config ];      # Build-time only (nativeBuildInputs)
  runtimeDeps = [ glibc openssl ];     # Runtime (buildInputs)
  propagatedDeps = [ linux-headers ];  # Propagated to dependents
}
```

**Structured build phases:**

```nix
phases = [
  { name = "unpack"; script = "tar xf $src"; }
  { name = "configure"; script = "./configure --prefix=$out"; }
  { name = "build"; script = "make -j$NIX_BUILD_CORES"; }
  { name = "install"; script = "make install"; }
];
```

Phases can be replaced, inserted, or removed by name using `lib.replacePhase`, `lib.addPhaseAfter`, etc.

**Single override mechanism:** One `.override` function instead of nixpkgs's three (`.override`, `.overrideAttrs`, `.overrideDerivation`).

**Separated sources:** All source URLs and hashes live in `pkgs/sources.nix`. All versions live in `pkgs/versions.nix`. Package definitions reference them by name, keeping build logic free of URL and hash noise.

## Alternatives Considered

**NixOS with nixpkgs:** Provides a similar immutable/generational model but bundles ~80,000 packages with known design issues (priority numbers, activation scripts, confusing dependency names). AOS builds only what it needs from scratch with corrections to these issues.

**Flatcar Container Linux / Fedora CoreOS:** These are mature immutable OSes but do not provide the same level of build-from-source auditability. They rely on upstream binary packages. ANDYL OS builds everything through a verified bootstrap chain.

**Traditional distribution with configuration management (Ansible/Puppet):** Rejected because configuration management on mutable systems cannot guarantee reproducibility or provide atomic rollback. Configuration drift remains a fundamental problem.

**Nix flakes:** Rejected due to experimental status, repo-copy-to-store overhead, complex lock file format, and conflation of concerns. The `aos` CLI wrapping stable `nix-build` provides equivalent functionality with better design.

## Security Considerations

- **Read-only root filesystem** prevents runtime modification of system binaries and libraries.
- **No Nix daemon at runtime** eliminates the attack surface of a privileged build daemon.
- **Content-addressed store paths** enable verification that deployed artifacts match their build derivations.
- **Signed updates** ensure that only authorized build infrastructure can produce deployable artifacts.
- **OverlayFS for /etc** makes it auditable which files have been modified from the base image by inspecting the upper layer.
- **Minimal userspace** (no compilers, no build tools) reduces available attack tools if the system is compromised.
- **systemd service hardening** (`ProtectSystem=strict`, `PrivateTmp=yes`, `ReadWritePaths=`) restricts each service to its required resources.

## Compatibility

- **Nix build infrastructure:** This design uses Nix as a build tool only. Standard `nix-build` and `nix-instantiate` are used at build time. Only stable Nix features are required -- no experimental features, no flakes.
- **systemd ecosystem:** Full compatibility with systemd-based tooling, including container runtimes (containerd), Kubernetes (kubelet), and monitoring systems.
- **UEFI systems:** Requires UEFI firmware with systemd-boot. Legacy BIOS boot is not supported.
- **Container runtimes:** containerd and runc are fully supported. All mutable state lives on `/var`.

## Open Questions

1. **Secure Boot:** Should we sign boot artifacts for UEFI Secure Boot? This requires key management infrastructure but hardens the boot chain.
2. **Store path configurability:** The store path (`/nix/store`) is parameterized via `storeDir` in `lib/derivations.nix` -- when should we exercise this?

## References

- Nix Manual: https://nix.dev/manual/nix/stable/
- systemd documentation: https://systemd.io/
- Boot Loader Specification: https://systemd.io/BOOT_LOADER_SPECIFICATION/
- OverlayFS documentation: https://docs.kernel.org/filesystems/overlayfs.html
- Fedora CoreOS design: https://docs.fedoraproject.org/en-US/fedora-coreos/
