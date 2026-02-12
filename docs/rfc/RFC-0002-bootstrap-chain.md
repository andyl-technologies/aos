# RFC-0002: Bootstrap Chain

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS bootstraps a complete Linux toolchain from a minimal (~357-byte) auditable binary seed using Nix derivations. All packages are defined in a custom package set with no dependency on nixpkgs. The entire build pipeline runs natively on Linux using standard `nix-build` -- no Docker containers are required.

## Motivation

Supply chain security requires knowing the provenance of every binary in the system. Most Linux distributions rely on pre-compiled binaries from upstream maintainers, creating an opaque chain of trust. By bootstrapping from a minimal auditable seed (the "trusting trust" problem solution), ANDYL OS can trace the lineage of every binary back to human-auditable source code. The custom package set ensures that every package definition is under our control, with no silent dependency on upstream nixpkgs packages or binary substitutes.

## Design

### 1. Native Nix Build Environment

ANDYL OS builds natively on Linux using standard Nix tools. Docker is not involved in the build pipeline.

**Build invocation:**

```bash
# Build the full bootstrap chain
aos build bootstrap.glibc

# Which wraps:
nix-build default.nix -A pkgs.bootstrap.glibc
```

The Nix daemon provides build isolation via Linux namespaces (mount, PID, network, user, IPC, UTS). Each build runs in an isolated sandbox with only its declared inputs visible.

**Resource requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 64 GB | 128 GB |

### 2. The Bootstrap Chain (Stages 0-6)

The full-source bootstrap starts from a ~357-byte auditable binary seed and builds up to a modern GCC toolchain entirely from source. Each stage is implemented as a Nix derivation in `stdenv/bootstrap/`.

```
Stage 0: bootstrap-seeds (~357 bytes x86 asm)        stdenv/bootstrap/seeds.nix
  hex0 - reads hex pairs, writes raw bytes
  kaem - minimal script executor
    |
Stage 1: mescc-tools                                  stdenv/bootstrap/stage1-mescc-tools.nix
  hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem
    |
Stage 2: Mes + TinyCC                                 stdenv/bootstrap/stage2-mes.nix
  M2-Planet compiles GNU Mes (Scheme interpreter + MesCC)   stdenv/bootstrap/stage3-tinycc.nix
  MesCC compiles TinyCC (small C compiler)
    |
Stage 3: GCC 4.6.4                                    stdenv/bootstrap/stage4-gcc46.nix
  TinyCC compiles GCC 4.6.4 (first "real" compiler)
    |
Stage 4: GCC 7.5.0                                    stdenv/bootstrap/stage5-gcc75.nix
  GCC 4.6.4 -> GCC 7.5.0 (C + C++)
    |
Stage 5: glibc 2.39                                   stdenv/bootstrap/stage6-glibc.nix
  GCC 7.5.0 builds production glibc with server hardening flags
    |
Stage 6: Full toolchain                               stdenv/default.nix
  GCC 13.3.0 + glibc 2.39 + binutils 2.42
  coreutils, bash, findutils, gawk, grep, sed,
  tar, gzip/xz, diffutils, patch, pkg-config
```

**Stage 0 details:**

The bootstrap seeds contain `hex0` (~357 bytes of x86 assembly) and `kaem` (a minimal script runner). These are the ONLY pre-compiled binaries in the entire chain and are small enough to audit by hand. They are sourced from https://github.com/oriansj/bootstrap-seeds.

```nix
# stdenv/bootstrap/seeds.nix (simplified)
{ fetchurl, sources, versions }:

builtins.derivation {
  name = "bootstrap-seeds-${versions.bootstrap.mescc-tools}";
  system = "x86_64-linux";
  builder = "builtin:fetchurl";
  url = sources.bootstrap-seeds.url;
  outputHash = sources.bootstrap-seeds.hash;
  outputHashMode = "flat";
  outputHashAlgo = "sha256";
}
```

**Stage 2 details (Mes + TinyCC):**

GNU Mes provides `mescc`, a C compiler written in Scheme. MesCC compiles TinyCC, which is the bridge from "toy" compilers to "real" compilers. TinyCC can compile GCC with some patches.

**Stage 5 details (glibc):**

glibc appears twice in the bootstrap: a minimal version sufficient to build modern GCC, and a final production build with server-oriented hardening flags:

```
--enable-kernel=5.15          Minimum kernel version (current LTS)
--enable-stack-protector=strong  Buffer overflow detection
--enable-bind-now             Full RELRO (GOT overwrite prevention)
--enable-static-nss           Static NSS for container compatibility
--enable-cet                  Intel Control-flow Enforcement Technology
```

Because the bootstrap derivations are bootstrapping the stdenv itself, they use `builtins.derivation` directly rather than the `mkDerivation` helper (which does not yet exist at that point in the chain).

### 3. Package Set Design

The AOS package set is defined in `pkgs/` with a single entry point at `pkgs/default.nix`. It has NO dependency on upstream nixpkgs for packages.

**Package set structure:**

```
pkgs/
  default.nix              Package set composition (entry point)
  versions.nix             Single source of truth for all package versions
  sources.nix              All source URLs and hashes
  toolchain/
    gcc.nix                GCC 13.3.0
    binutils.nix           Binutils 2.42
    linux-headers.nix      Linux headers 6.12.11
  core/                    Base utilities (coreutils, bash, grep, etc.)
  compression/             zlib, zstd, lz4
  tls/                     OpenSSL 3.3.2
  init/                    systemd, dbus, util-linux, kmod
  kernel/                  Linux kernel, firmware
  security/                SELinux stack, audit
  networking/              iproute2, nftables, curl, openssh, chrony
  containers/              containerd, runc
  kubernetes/              kubelet, kubeadm, kubectl, CNI, helm
  monitoring/              node-exporter
  boot/                    dracut, ignition, butane
  tools/                   minisign, sbsigntools, update-tool
```

The explicit absence of a nixpkgs dependency means:

- No upstream package enters our system.
- Every package definition is ours to audit and control.
- Updating one package never silently updates others.
- Every change is an explicit commit to our repository.

### 4. Version Pinning Strategy

Three layers of version pinning ensure reproducibility:

1. **Source hashes:** Every source in `pkgs/sources.nix` includes a SHA-256 hash. Nix refuses to use source that does not match.

2. **Centralized versions:** All package versions are defined in `pkgs/versions.nix`:
   ```nix
   {
     toolchain = { gcc = "13.3.0"; glibc = "2.39"; binutils = "2.42"; ... };
     core = { make = "4.4.1"; coreutils = "9.5"; bash = "5.2.32"; ... };
     kernel = { linux = "6.12.11"; firmware = "20241210"; };
     # ...
   }
   ```

3. **Git commit pinning:** The entire build is determined by the Git commit of the AOS repository. `default.nix` has no external inputs. No lock file is needed because there are no floating inputs to lock.

No transitive updates occur because there is no upstream package dependency. Every change is an explicit commit.

### 5. Build Isolation

The Nix daemon uses Linux namespaces for build isolation:

| Namespace | Purpose |
|-----------|---------|
| Mount | Chroot into store; only declared inputs visible |
| PID | Isolated process tree; build cannot see other processes |
| Network | No network access during build; prevents downloads |
| User | Builder runs as unprivileged build user |
| IPC | No shared memory with host |
| UTS | Deterministic hostname |

This is standard Nix sandbox behavior -- no additional containerization is needed.

### 6. Substitutes: Disabled for External Sources

All upstream binary substitutes are disabled. We trust only our own builds.

```bash
# At daemon level
nix-daemon --option substitute false

# Via aos CLI
aos build --no-substitutes zlib
```

Reasons:

- **Trust:** Upstream substitutes are signed by nixpkgs infrastructure, not by us.
- **Customization:** Our packages have different build flags and configurations.
- **Auditability:** Every build is traceable through our bootstrap chain.
- **Supply chain security:** No external binary enters our system beyond the auditable bootstrap seeds.

### 7. Build Tool Integration

All build operations are invoked through the `aos` CLI or the `justfile`:

```bash
# Run the full bootstrap
aos build bootstrap.glibc

# Build a specific package
aos build openssl

# Build all packages
aos build --all

# Via justfile
just build openssl
```

The `aos` CLI wraps `nix-build default.nix -A pkgs.<package>` with colored output, progress indicators, and error context.

## Alternatives Considered

**Using upstream nixpkgs packages directly:** Rejected because it creates an implicit trust dependency on upstream maintainers and binary substitutes. We cannot audit what we do not control.

**GNU Guix instead of Nix:** Guix provides similar content-addressing and has a more mature full-source bootstrap. However, Guix's ecosystem is too immature for production server use. The Nix language and tooling are more stable and widely tested. The same bootstrap chain (hex0 through GCC) is preserved in our Nix implementation.

**Using upstream binary substitutes with signature verification:** Even with signature verification, using upstream substitutes means trusting that the upstream build infrastructure has not been compromised. Building from source through our own bootstrap chain provides stronger guarantees.

**Docker-based builds:** Rejected. Docker adds unnecessary complexity and indirection. Nix already provides build isolation via Linux namespaces. Native builds are faster and simpler.

## Security Considerations

- The **bootstrap seeds** (~357 bytes) are the root of trust and are small enough to audit by hand.
- **Build isolation** via Linux namespaces prevents builds from accessing the network or host system.
- **Disabled substitutes** ensure no external binary enters the system.
- **Source hash verification** ensures downloaded source code matches expected content.
- The **signing key** for build artifacts must be protected. Store it in a hardware security module or secrets manager. Only CI infrastructure should have access.

## Compatibility

- **Nix version:** Standard stable Nix (no experimental features required). The Nix version used for building is pinned as a build-time dependency.
- **Linux kernel:** Requires a Linux kernel with user namespace support for Nix sandbox.
- **Package ecosystem:** All packages are self-contained Nix derivations using our `mkDerivation` from `lib/derivations.nix`.

## Open Questions

1. **Bootstrap verification:** Should we mandate that the full bootstrap chain is rebuilt and verified periodically (e.g., quarterly), or only when bootstrap-stage packages change?
2. **Package update workflow:** When OpenSSL has a CVE, the process is: update version + hash in `pkgs/sources.nix` and `pkgs/versions.nix`, commit, CI builds, cache populates, redeploy. What is the target SLA for this pipeline?

## References

- GNU Mes (Maxwell Equations of Software): https://www.gnu.org/software/mes/
- Bootstrap Seeds: https://github.com/oriansj/bootstrap-seeds
- MesCC-Tools: https://github.com/oriansj/mescc-tools
- TinyCC: https://bellard.org/tcc/
- NAR Archive Format: https://nixos.org/guides/nix-pills/nix-store-paths.html
- Nix Manual: https://nix.dev/manual/nix/stable/
