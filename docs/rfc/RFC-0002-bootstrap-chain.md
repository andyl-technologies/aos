# RFC-0002: Guix Bootstrap Chain

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS bootstraps a complete Linux toolchain from a minimal (~357-byte) auditable binary seed using GNU Guix's build infrastructure. All packages are defined in a custom ANDYL channel with no upstream Guix package dependencies. The entire build pipeline runs inside Docker containers on macOS, with a persistent content-addressed store.

## Motivation

Supply chain security requires knowing the provenance of every binary in the system. Most Linux distributions rely on pre-compiled binaries from upstream maintainers, creating an opaque chain of trust. By bootstrapping from a minimal auditable seed (the "trusting trust" problem solution), ANDYL OS can trace the lineage of every binary back to human-auditable source code. The ANDYL channel ensures that every package definition is under our control, with no silent dependency on upstream Guix packages or binary substitutes.

## Design

### 1. Docker-Based Build Environment on macOS

Guix requires a Linux kernel with user namespaces, cgroups, and a functioning `/gnu/store`. macOS provides none of these. Docker Desktop for Mac runs a lightweight Linux VM (via Apple's Virtualization.framework on Apple Silicon or HyperKit on Intel), providing the required Linux environment.

**Dockerfile structure (multi-stage hex0 bootstrap from `scratch`):**

The Dockerfile runs the complete bootstrap chain inside Docker, starting from
the ~357-byte hex0 seed. Each major compilation step is a separate Docker
stage for layer caching. The final clean image starts `FROM scratch` and
contains only the bootstrapped `/gnu` and `/var/guix` trees. A runtime stage
layers on minimal Debian dependencies for `guix-daemon`.

```dockerfile
# Stage 1: Obtain bootstrap seeds (hex0, kaem)
FROM debian:bookworm-slim@sha256:<pinned-digest> AS hex0-seeds
# ... wget to fetch bootstrap-seeds archive ...

# Stage 2: mescc-tools (hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet)
FROM hex0-seeds AS mescc-tools
# Each step is a separate RUN for Docker layer caching

# Stage 3-4: GNU Mes + TinyCC
FROM mescc-tools AS mes-build / tinycc-build

# Stage 5-7: GCC 4.6.4 -> GCC 7.x -> GCC 13.x
FROM tinycc-build AS gcc4-build / gcc7-build / gcc13-build

# Stage 8: glibc (compiled by modern GCC)
FROM gcc13-build AS glibc-build

# Stage 9: Build Guix itself from source
FROM glibc-build AS guix-from-source

# Stage 10: FROM scratch -- only bootstrapped artifacts survive
FROM scratch AS guix-clean
COPY --from=guix-from-source /gnu /gnu
COPY --from=guix-from-source /var/guix /var/guix

# Stage 11: Runtime environment with guix-daemon
FROM debian:bookworm-slim@sha256:<pinned-digest> AS guix-builder
COPY --from=guix-clean /gnu /gnu
COPY --from=guix-clean /var/guix /var/guix
# ... runtime deps, build users, locale setup ...
ENV GUIX_DAEMON_OPTS="--no-substitutes --max-jobs=4 --cores=0"
```

There is no binary tarball download. The only pre-compiled binary is the
~357-byte hex0 seed, which is small enough to audit by hand.

**Resource requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 64 GB | 128 GB |

**Docker volume strategy:**

| Volume | Mount Point | Type | Purpose |
|--------|-------------|------|---------|
| `gnu-store` | `/gnu/store` | Named volume | Content-addressed build outputs. Must use named volume (not bind mount) for native ext4 I/O performance. |
| `guix-var` | `/var/guix` | Named volume | Guix database and profiles. Must stay consistent with `/gnu/store`. |
| Channel repo | `/andyl-channel` | Bind mount (ro) | Package definitions from host. Read-only since Guix copies what it needs. |

**Apple Silicon considerations:**

On ARM64 hosts targeting x86_64 servers, use `--platform linux/amd64` with QEMU emulation (5-10x slower) or a remote x86_64 build machine via `guix build --offload`. Guix natively supports aarch64-linux for ARM server targets.

### 2. The Bootstrap Chain (Stages 0-6)

The full-source bootstrap starts from a ~357-byte auditable binary seed and builds up to a modern GCC toolchain entirely from source.

```
Stage 0: bootstrap-seeds (~357 bytes x86 asm)
  hex0 - reads hex pairs, writes raw bytes
  kaem - minimal script executor
    |
Stage 1: mescc-tools
  hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem
    |
Stage 2: Mes + TinyCC
  M2-Planet compiles GNU Mes (Scheme interpreter + MesCC)
  MesCC compiles TinyCC (small C compiler)
    |
Stage 3: GCC 4.6.4
  TinyCC compiles GCC 4.6.4 (first "real" compiler)
    |
Stage 4: Modern GCC (13.x)
  GCC 4.6.4 -> GCC 7.x -> GCC 10.x/13.x
    |
Stage 5: glibc 2.39
  Modern GCC builds production glibc with server hardening flags
    |
Stage 6: Full toolchain
  binutils, make, coreutils, bash, findutils, gawk, grep, sed,
  tar, gzip/xz, diffutils, patch, pkg-config
```

**Stage 0 details:**

The bootstrap seeds contain `hex0` (~357 bytes of x86 assembly) and `kaem` (a minimal script runner). These are the ONLY pre-compiled binaries in the entire chain and are small enough to audit by hand. They are sourced from https://github.com/oriansj/bootstrap-seeds.

```scheme
;; channel/andyl/packages/bootstrap.scm
(define-public andyl-bootstrap-seeds
  (package
    (name "andyl-bootstrap-seeds")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/"
                    version ".tar.gz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    ;; ... installs architecture-specific seeds ...
    ))
```

**Stage 2 details (Mes + TinyCC):**

GNU Mes provides `mescc`, a C compiler written in Scheme. MesCC compiles TinyCC, which is the bridge from "toy" compilers to "real" compilers. TinyCC can compile GCC with some patches.

**Stage 5 details (glibc):**

glibc appears twice in the bootstrap: a minimal `glibc-mesboot` sufficient to build modern GCC, and a final production `andyl-glibc` with server-oriented hardening flags:

```
--enable-kernel=5.15          Minimum kernel version (current LTS)
--enable-stack-protector=strong  Buffer overflow detection
--enable-bind-now             Full RELRO (GOT overwrite prevention)
--enable-static-nss           Static NSS for container compatibility
--enable-cet                  Intel Control-flow Enforcement Technology
```

### 3. ANDYL Channel Design

The ANDYL channel is a Git repository containing Guile Scheme modules that define every package in the system. It has NO dependency on the upstream `guix` channel for packages.

**Channel structure:**

```
channel/
  .guix-channel              Channel metadata
  .guix-authorizations       Authorized committers (OpenPGP)
  andyl/
    packages/
      bootstrap.scm          Stage 0: seeds
      commencement.scm        Stages 1-6: bootstrap chain
      base.scm               coreutils, bash, etc.
      gcc.scm                GCC (post-bootstrap)
      glibc.scm              glibc (post-bootstrap)
      linux.scm              kernel, headers
      networking.scm          curl, openssl, etc.
      services.scm           nginx, postgresql, etc.
      tls.scm                TLS libraries
      python.scm             Python ecosystem
      compression.scm        zlib, xz, zstd, etc.
    system/
      base.scm               Base operating-system config
      server.scm             Server-specific config
      services.scm           System service definitions
```

**`.guix-channel` file:**

```scheme
(channel
  (version 0)
  (url "https://git.andyl.dev/andyl-channel")
  (directory ".")
  (dependencies '()))    ;; NO dependency on upstream 'guix' channel
```

The explicit absence of a dependency on the upstream `guix` channel means:

- No upstream Guix package enters our system.
- Every package definition is ours to audit and control.
- Updating one package never silently updates others.
- Every change is an explicit, signed commit to our channel.

### 4. Channel Authentication

Every commit to the ANDYL channel must be signed by an authorized OpenPGP key. Guix verifies the chain of signatures on `guix pull`.

```scheme
;; channel/.guix-authorizations
(authorizations
  (version 0)
  (("FINGERPRINT_OF_ANDYL_SIGNING_KEY_1"
    (name "andyl-builder"))
   ("FINGERPRINT_OF_ANDYL_SIGNING_KEY_2"
    (name "andyl-admin"))))
```

**Workflow:**

```bash
# Generate signing key (RSA 4096, no expiry for build keys)
gpg --full-gen-key

# Configure Git to sign all commits
git config commit.gpgsign true
git config user.signingkey FINGERPRINT

# Guix verifies signatures on pull
guix pull --channels=channels.scm
# If any commit is unsigned or signed by an unauthorized key, pull fails.
```

### 5. Version Pinning Strategy

Three layers of version pinning ensure reproducibility:

1. **Source hashes:** Every `origin` includes a `sha256` hash. Guix refuses to use source that does not match.

2. **Channel commit pinning:** Pin the channel to a specific commit:
   ```scheme
   (channel
     (name 'andyl)
     (url "file:///andyl-channel")
     (commit "abc123def456..."))
   ```

3. **Time machine:** `guix time-machine` builds against any historical channel commit:
   ```bash
   guix time-machine --commit=abc123 -- build andyl-nginx
   ```

No transitive updates occur because there is no upstream channel dependency. Every change is an explicit commit.

### 6. Build Isolation

The `guix-daemon` uses Linux namespaces for build isolation:

| Namespace | Purpose |
|-----------|---------|
| Mount | Chroot into `/gnu/store`; only declared inputs visible |
| PID | Isolated process tree; build cannot see other processes |
| Network | No network access during build; prevents downloads |
| User | Builder runs as unprivileged `guixbuilderNN` user |
| IPC | No shared memory with host |
| UTS | Deterministic hostname |

Docker provides an outer layer of namespace isolation. The guix-daemon creates inner namespaces within the container. This double isolation is safe and intentional.

**Docker capability requirement:** The container needs `SYS_ADMIN` to allow the daemon to create inner namespaces, or `seccomp:unconfined`.

### 7. Substitutes: Disabled for External Sources

All upstream binary substitutes are disabled. We trust only our own builds.

```bash
# At daemon level
guix-daemon --no-substitutes

# At client level (belt and suspenders)
guix build --no-substitutes andyl-zlib
```

Reasons:

- **Trust:** Upstream substitutes are signed by Guix infrastructure, not by us.
- **Customization:** Our packages have different build flags and configurations.
- **Auditability:** Every build is traceable through our bootstrap chain.
- **Supply chain security:** No external binary enters our system beyond the auditable bootstrap seeds.

### 8. Grafts: Disabled

Grafts are Guix's mechanism for applying security updates by rewriting store references without full rebuilds. We disable grafts because:

- Every binary should match its derivation exactly.
- We have our own CI/binary cache, making full rebuilds acceptable.
- Grafted binaries have been post-processed, making their store path not match the build derivation.

```bash
guix build --no-grafts andyl-nginx
```

### 9. Binary Cache for CI

After initial bootstrap, built packages are cached to avoid repeated builds:

```
CI Worker 1 ---+
CI Worker 2 ---+---> guix publish ---> NAR Cache (S3 or local)
CI Worker 3 ---+     (substitute         |
                      server)            v
                                    Signs NARs with ANDYL key
                                         |
Dev Machines --------pull----------------+
Deployment   --------pull----------------+
```

NAR (Nix ARchive) is a deterministic archive format: same contents always produce identical bytes. Each narinfo file contains a cryptographic signature for authenticity.

```bash
# Start the substitute server
guix publish --port=8080 --compression=zstd:6 \
  --cache=/var/cache/guix/publish --ttl=30d

# Generate signing keys
guix archive --generate-key
# Creates /etc/guix/signing-key.sec (private) and .pub (public)
```

### 10. justfile Integration

All build operations are orchestrated through a `justfile` that wraps Docker and Guix commands:

```makefile
# Run the full bootstrap (Stage 0 through Stage 6)
bootstrap: docker-build
    docker compose run --rm guix-builder \
        guix build --no-substitutes \
            andyl-bootstrap-seeds andyl-mescc-tools andyl-mes \
            andyl-tinycc-mescc andyl-gcc-core-mesboot andyl-gcc \
            andyl-glibc andyl-binutils andyl-make andyl-coreutils

# Build a specific package
build PACKAGE:
    docker compose run --rm guix-builder \
        guix build --no-substitutes "{{PACKAGE}}"
```

## Alternatives Considered

**Using upstream Guix packages directly:** Rejected because it creates an implicit trust dependency on upstream maintainers and binary substitutes. We cannot audit what we do not control.

**Nix instead of Guix:** Nix provides similar content-addressing but uses a custom DSL (Nix language) rather than a general-purpose language (Guile Scheme). Guix's full-source bootstrap is more mature and the Scheme-based configuration is more expressive.

**Using upstream binary substitutes with signature verification:** Even with signature verification, using upstream substitutes means trusting that the upstream build infrastructure has not been compromised. Building from source through our own bootstrap chain provides stronger guarantees.

**Building natively on Linux instead of Docker on macOS:** Development happens on macOS. Docker provides the required Linux environment with acceptable performance. Remote Linux build machines are used for production CI.

## Security Considerations

- The **bootstrap seeds** (~357 bytes) are the root of trust and are small enough to audit by hand.
- **Channel authentication** via OpenPGP signatures prevents unauthorized package modifications.
- **Build isolation** via Linux namespaces prevents builds from accessing the network or host system.
- **Disabled substitutes** ensure no external binary enters the system.
- **Source hash verification** ensures downloaded source code matches expected content.
- The **signing key** for the binary cache must be protected. Store it in a hardware security module or secrets manager. Only CI infrastructure should have access.

## Compatibility

- **Guix version:** Guix (daemon + CLI) is built from source as part of the hex0 bootstrap chain inside Docker. The version is determined by the bootstrap chain's source inputs, which are pinned by hash.
- **Docker:** Requires Docker Desktop for Mac or OrbStack with VirtioFS for acceptable I/O performance. Docker layer caching is critical since the full bootstrap takes many hours on first run.
- **Apple Silicon:** Cross-architecture builds require QEMU emulation or remote x86_64 build machines.
- **Package ecosystem:** Our channel can reference Guix build system modules (`(guix build-system gnu)`, etc.) from the bootstrapped Guix installation.

## Open Questions

1. **Guix module vendoring:** Our package definitions use modules like `(guix packages)` from the Guix installation. Should we vendor these modules or accept the Guix version as a build-time dependency?
2. **Multi-architecture support:** If we need both x86_64 and aarch64 server images, we need separate bootstrap chains and store paths for each architecture. When should we introduce aarch64 support?
3. **Bootstrap verification:** Should we mandate that the full bootstrap chain is rebuilt and verified periodically (e.g., quarterly), or only when bootstrap-stage packages change?
4. **Package update workflow:** When OpenSSL has a CVE, the process is: update version + hash in channel, commit (signed), CI builds, cache populates, redeploy. What is the target SLA for this pipeline?

## References

- GNU Mes (Maxwell Equations of Software): https://www.gnu.org/software/mes/
- Bootstrap Seeds: https://github.com/oriansj/bootstrap-seeds
- Guix Full-Source Bootstrap: https://guix.gnu.org/blog/2023/the-full-source-bootstrap/
- GNU Guix Channels: https://guix.gnu.org/manual/en/html_node/Channels.html
- MesCC-Tools: https://github.com/oriansj/mescc-tools
- TinyCC: https://bellard.org/tcc/
- NAR Archive Format: https://nixos.org/guides/nix-pills/nix-store-paths.html
