# 01 - Guix Bootstrap: From Zero to Full Toolchain

## Overview

This document describes how ANDYL OS bootstraps a complete Linux distribution
using GNU Guix's build infrastructure, without relying on any upstream Guix
packages or binary substitutes. Everything is built from source through our own
Guix channel, using a Guix build environment installed via the standard binary
tarball.

The hex0 full-source bootstrap chain is documented in Section 2 as a
theoretical/educational reference. The actual Docker build environment uses
the Guix binary tarball for a fast, practical setup.

We develop on macOS, so the entire build pipeline runs inside Docker containers
with a persistent `/gnu/store`.

```
 +-------------------------------------------------------------------+
 |                        macOS Host (Dev Machine)                    |
 |                                                                    |
 |  justfile                                                          |
 |    |                                                               |
 |    v                                                               |
 |  Docker Desktop                                                    |
 |    |                                                               |
 |    v                                                               |
 |  +-------------------------------------------------------------+  |
 |  |  Guix Build Container (binary tarball installation)           |  |
 |  |                                                              |  |
 |  |  guix-daemon  <--- builds derivations                        |  |
 |  |    |                                                         |  |
 |  |    v                                                         |  |
 |  |  /gnu/store/  <--- content-addressed build outputs           |  |
 |  |    |                (Docker volume, persists across builds)   |  |
 |  |    v                                                         |  |
 |  |  ANDYL Channel  <--- our package definitions                 |  |
 |  |    |                                                         |  |
 |  |    v                                                         |  |
 |  |  Golden Image  <--- final server image output                |  |
 |  +-------------------------------------------------------------+  |
 +-------------------------------------------------------------------+
```

---

## 1. Docker-based Guix Bootstrap on macOS

### 1.1 Why Docker?

Guix requires a Linux kernel with user namespaces, cgroups, and a functioning
`/gnu/store`. macOS provides none of these. Docker Desktop for Mac runs a
lightweight Linux VM (via Apple's Virtualization.framework on Apple Silicon, or
HyperKit on Intel), giving us a real Linux kernel.

### 1.2 macOS-Specific Considerations

**Docker Desktop resource allocation:**

- Guix builds are CPU and memory intensive, especially for GCC bootstrap stages
- Recommended minimums: 8 CPU cores, 16 GB RAM, 100 GB disk
- Apple Silicon (ARM64) note: Guix supports aarch64-linux natively. If the
  target is x86_64 servers, we need `--platform linux/amd64` which uses QEMU
  emulation and is significantly slower. Prefer native aarch64-linux builds when
  possible, or use a remote x86_64 build machine.

**Filesystem performance:**

- Docker Desktop uses virtiofs (macOS 12.5+) for bind mounts, which is fast
  but still slower than native Linux I/O
- The `/gnu/store` should live on a Docker named volume (not a bind mount) for
  best I/O performance, since named volumes use the VM's native ext4 filesystem
- Bind mounts are acceptable for source code (the channel repo) since reads are
  infrequent relative to store writes

**Docker context and BuildKit:**

```shell
# Ensure Docker Desktop is running and configured
docker info --format '{{.OSType}}'  # Should output: linux

# Check available resources
docker info --format 'CPUs: {{.NCPU}}, Memory: {{.MemTotal}}'
```

### 1.3 Dockerfile: Guix Binary Tarball Installation

The Dockerfile installs GNU Guix using the standard binary tarball from
`ftp.gnu.org/gnu/guix/`. This provides a pre-built `/gnu/store` and
`/var/guix` with a working `guix-daemon` and CLI tool.

> **Note:** The full hex0 source bootstrap chain (hex0 -> hex1 -> hex2 -> M0 ->
> M1 -> M2-Planet -> Mes -> MesCC -> TinyCC -> GCC -> glibc -> Guix) is
> documented in Section 2 below as a theoretical/educational reference. It is
> not implemented in the Docker build due to its multi-hour build time (4-8+
> hours). The binary tarball approach provides a working Guix environment in
> minutes.

```dockerfile
# =============================================================================
# docker/Dockerfile
# ANDYL OS -- Guix build environment via binary tarball installation
# =============================================================================

FROM debian:bookworm-slim@sha256:<pinned-digest> AS guix-builder

# Pin the Guix binary tarball version
ARG GUIX_VERSION=1.4.0
ARG GUIX_ARCH=x86_64-linux

# Install runtime dependencies for guix-daemon
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates coreutils curl git gnupg \
    less locales nscd wget xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Generate a UTF-8 locale (Guix needs this)
RUN sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Download and extract the Guix binary tarball
RUN cd /tmp \
    && wget -q "https://ftp.gnu.org/gnu/guix/guix-binary-${GUIX_VERSION}.${GUIX_ARCH}.tar.xz" \
        -O guix-binary.tar.xz \
    && tar --warning=no-timestamp -xf guix-binary.tar.xz -C / \
    && rm guix-binary.tar.xz

# Create guix profile symlinks
RUN mkdir -p ~root/.config/guix \
    && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix \
        /usr/local/bin/guix \
    && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix-daemon \
        /usr/local/bin/guix-daemon

# Create build users (guix-daemon runs builds as these unprivileged users)
RUN groupadd --system guixbuild && \
    for i in $(seq -w 1 10); do \
        useradd -g guixbuild -G guixbuild \
                -d /var/empty -s /usr/sbin/nologin \
                -c "Guix build user $i" \
                "guixbuilder$i"; \
    done

# Ensure the store and var directories have correct permissions
RUN mkdir -p /gnu/store /var/guix/db \
    && chmod 1775 /gnu/store

# IMPORTANT: We do NOT authorize the upstream Guix substitute server key.
# We explicitly refuse upstream substitutes.
ENV GUIX_DAEMON_OPTS="--no-substitutes --max-jobs=4 --cores=0"

# Copy entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["guix", "repl"]
```

**Build the image:**

```bash
docker build -f docker/Dockerfile -t andyl-os/guix-builder .
```

**justfile target:**

```makefile
# Build the Guix build container
docker-build:
    docker compose -f docker/docker-compose.yml build
```

### 1.4 Entrypoint Script

```bash
#!/bin/bash
# docker/entrypoint.sh
#
# Start guix-daemon in the background, then exec the requested command.

set -euo pipefail

echo "Starting guix-daemon..."
# --no-substitutes: refuse all upstream binary caches
# --max-jobs: number of parallel build jobs
# --cores: cores per build (0 = use all available)
guix-daemon --build-users-group=guixbuild \
            --no-substitutes \
            --max-jobs="${GUIX_MAX_JOBS:-4}" \
            --cores="${GUIX_CORES:-0}" &

DAEMON_PID=$!

# Wait for daemon socket to appear
for i in $(seq 1 30); do
    if guix describe >/dev/null 2>&1; then
        echo "guix-daemon is ready."
        break
    fi
    sleep 1
done

# If the channel repo is mounted, add it
if [ -d /andyl-channel ]; then
    echo "Configuring ANDYL channel..."
    mkdir -p ~/.config/guix
    cat > ~/.config/guix/channels.scm << 'CHANNELS'
(list
  (channel
    (name 'andyl)
    (url "file:///andyl-channel")
    (branch "main")))
CHANNELS
    guix pull --channels=/root/.config/guix/channels.scm
fi

# Execute the provided command
exec "$@"
```

### 1.5 Docker Volume Strategy

```
 Docker Volumes
 ==============

 gnu-store (named volume)         <--- /gnu/store
   |
   |  Contains ALL build outputs. Content-addressed.
   |  Persists across container restarts.
   |  Can grow to 50-100 GB during full bootstrap.
   |
 guix-var (named volume)          <--- /var/guix
   |
   |  Guix database, profiles, gcroots.
   |  Must stay consistent with /gnu/store.
   |
 andyl-channel (bind mount)       <--- ./channel:/andyl-channel (read-only)
   |
   |  Our package definitions. Mounted from host.
   |  Read-only since Guix copies what it needs into the store.
```

Docker Compose configuration:

```yaml
# docker/docker-compose.yml
version: "3.8"

services:
  guix-builder:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    volumes:
      - gnu-store:/gnu/store
      - guix-var:/var/guix
      - ../channel:/andyl-channel:ro
    environment:
      - GUIX_MAX_JOBS=4
      - GUIX_CORES=0
    # Guix needs these capabilities for build isolation
    cap_add:
      - SYS_ADMIN
    security_opt:
      - seccomp:unconfined
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: "8"
          memory: 16G

volumes:
  gnu-store:
    driver: local
  guix-var:
    driver: local
```

### 1.5.1 OverlayFS Bind-Mount for /gnu/store with Shared Volume

For production and CI use cases, we want the image's base `/gnu/store` to
remain **read-only** while new packages built inside the container are written
to a **shared Docker volume** (the overlay upper layer). This is accomplished
with an OverlayFS overlay mount on `/gnu/store` at container startup.

**How it works:**

```
 OverlayFS Layers for /gnu/store
 ================================

 +-------------------------------------------------+
 |  Merged View:  /gnu/store  (seen by guix-daemon) |
 +-------------------------------------------------+
       |                          |
       v                          v
 +------------------+    +-------------------+
 | Upper Layer      |    | Lower Layer       |
 | (Docker volume)  |    | (Image's built-in |
 | Read-Write       |    |  /gnu/store)      |
 | New packages go  |    | Read-Only         |
 | here             |    |                   |
 +------------------+    +-------------------+
 | store-upper:/    |    | Baked into the    |
 | gnu/store-upper  |    | Docker image at   |
 |                  |    | build time        |
 | Persists across  |    |                   |
 | container runs   |    |                   |
 | via named volume |    |                   |
 +------------------+    +-------------------+
```

**Entrypoint overlay setup:**

Add the following to `docker/entrypoint.sh` before starting `guix-daemon`:

```bash
# --- OverlayFS setup for /gnu/store ---
# If GUIX_STORE_OVERLAY=1, mount an overlay on /gnu/store so that:
#   - The image's /gnu/store is the read-only lower layer
#   - A Docker volume provides the read-write upper layer
#   - New builds are written to the upper layer (persisted via volume)
#   - The merged view at /gnu/store shows both layers

if [ "${GUIX_STORE_OVERLAY:-0}" = "1" ]; then
    echo "Setting up OverlayFS overlay on /gnu/store..."

    OVERLAY_UPPER="/gnu/store-upper/upper"
    OVERLAY_WORK="/gnu/store-upper/work"
    OVERLAY_LOWER="/gnu/store"

    # The upper and work directories live on the Docker volume
    # mounted at /gnu/store-upper
    mkdir -p "${OVERLAY_UPPER}" "${OVERLAY_WORK}"

    # Copy the original /gnu/store to a temporary lower dir
    # (overlay cannot use the same path as both lower and merged)
    cp -a /gnu/store /gnu/store-lower

    mount -t overlay overlay \
        -o "lowerdir=/gnu/store-lower,upperdir=${OVERLAY_UPPER},workdir=${OVERLAY_WORK}" \
        /gnu/store

    echo "OverlayFS mounted on /gnu/store (lower=image, upper=volume)"
fi
```

**Docker run invocation with overlay:**

```bash
# Run with overlay-backed /gnu/store
# - store-upper: named volume persisting the overlay upper layer
# - SYS_ADMIN capability is required for the mount(2) syscall
docker run --rm -it \
    --cap-add SYS_ADMIN \
    --security-opt seccomp=unconfined \
    -e GUIX_STORE_OVERLAY=1 \
    -v store-upper:/gnu/store-upper \
    -v guix-var:/var/guix \
    -v "$(pwd)/channel:/andyl-channel:ro" \
    andyl-os/guix-builder \
    bash

# The named volume 'store-upper' persists across container runs.
# On the first run it is empty; as packages are built, their outputs
# appear in the upper layer and survive container restarts.
```

**Docker Compose with overlay:**

```yaml
# docker/docker-compose.overlay.yml
version: "3.8"

services:
  guix-builder:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    volumes:
      - store-upper:/gnu/store-upper
      - guix-var:/var/guix
      - ../channel:/andyl-channel:ro
    environment:
      - GUIX_MAX_JOBS=4
      - GUIX_CORES=0
      - GUIX_STORE_OVERLAY=1
    cap_add:
      - SYS_ADMIN
    security_opt:
      - seccomp:unconfined
    deploy:
      resources:
        limits:
          cpus: "8"
          memory: 16G

volumes:
  store-upper:
    driver: local
  guix-var:
    driver: local
```

**How the volume persists build artifacts:**

1. On first `docker run`, the `store-upper` volume is empty. The merged
   `/gnu/store` shows only the image's built-in store paths (lower layer).
2. When `guix-daemon` builds a new package, the output is written to
   `/gnu/store/<hash>-<name>`. OverlayFS directs this write to the upper
   layer (`store-upper` volume).
3. On subsequent `docker run` invocations with the same `store-upper` volume,
   previously built packages are immediately visible -- no rebuild required.
4. The base image can be updated independently; the upper layer volume
   carries forward. If a store path exists in both layers, the upper layer
   wins (copy-up semantics).
5. To reset the cache, simply remove the volume: `docker volume rm store-upper`.

**justfile targets:**

```makefile
# Run with overlay-backed /gnu/store
docker-shell-overlay:
    docker compose -f docker/docker-compose.overlay.yml run --rm guix-builder bash

# Show what the overlay upper layer contains (newly built packages)
store-overlay-diff:
    docker run --rm -v store-upper:/mnt busybox \
        sh -c 'echo "Upper layer contents:" && ls /mnt/upper/ | head -20'

# Reset the overlay upper layer (discard all cached builds)
store-overlay-reset:
    docker volume rm store-upper
```

### 1.6 Deterministic Docker Layers and Caching Strategy

Docker layer caching is not content-addressed in the Guix sense, but we can
maximize determinism and leverage Docker's layer cache to avoid redundant work:

1. **Pin the base image digest:**
   ```dockerfile
   FROM debian:bookworm-slim@sha256:<specific-digest>
   ```

2. **Pin the Guix binary tarball version** via `ARG GUIX_VERSION`

3. **The real determinism comes from Guix itself:** Once guix-daemon is running,
   every build output is content-addressed. Two builds of the same derivation
   with the same inputs will produce byte-identical outputs. The Docker
   container is just the host for the daemon; reproducibility lives in the Guix
   store.

Since the Dockerfile uses a single-stage binary tarball installation, Docker
layer caching is straightforward: the tarball download and extraction are
cached as long as `GUIX_VERSION` and the base image digest remain unchanged.
Rebuilds complete in seconds.

To verify layer caching is working:

```bash
# Build with --progress=plain to see cache hit/miss for each step
docker build -f docker/Dockerfile --progress=plain .

# Lines starting with "CACHED" indicate a cache hit
```

---

## 2. The Bootstrap Chain

### 2.1 Why Bootstrap Matters

The "trusting trust" problem: every compiler is compiled by a previous compiler.
Where does the chain start? Guix solves this with a "full source bootstrap"
that starts from a tiny (~357 bytes) auditable binary seed and builds up to a
modern GCC toolchain entirely from source.

For ANDYL OS, we follow the same bootstrap chain. We use Guix's bootstrap
infrastructure (the `(gnu packages commencement)` module patterns) but through
our own channel definitions. This means we define every package ourselves but
follow the same DAG of build dependencies.

### 2.2 Bootstrap Stages

```
 Stage 0           Stage 1             Stage 2          Stage 3
 --------          -----------         -----------      -----------
 bootstrap-       hex0 (hex           tinycc           gcc-core
 seeds              assembler)          (from            (4.x)
 (~357 bytes         |                  mescc            (from
  x86 asm)       M1 macro              output)          tinycc)
    |             assembler                |
    v                |                     v              Stage 4
   mes            M2-Planet           builds enough      -----------
   (Minimal         |                 of coreutils       gcc (modern
    Extensible   mescc-tools          to bootstrap       10.x/13.x)
    Scheme)      (hex2, M1,           more                  |
    |             kaem)                                     v
    v                |                                   Stage 5
   mescc             v                                   -----------
   (mes C         simple C                               glibc
    compiler)     compiler                               (built with
                  (from M2-Planet)                        modern gcc)
                                                            |
                                                            v
                                                         Stage 6
                                                         -----------
                                                         Full toolchain:
                                                         binutils, gcc,
                                                         glibc, make,
                                                         coreutils, etc.
```

### 2.3 Stage 0: The Binary Seeds

The Guix full-source bootstrap starts with `bootstrap-seeds`, a package
containing a minimal set of auditable binaries:

- **hex0**: A ~357-byte x86 binary that reads hex pairs from stdin and writes
  raw bytes to stdout. This is the absolute root of trust.
- **kaem**: A minimal script executor (built from hex0).

These are defined in `(gnu packages bootstrap)` and are the ONLY pre-compiled
binaries in the entire chain. They're small enough to audit by hand.

```scheme
;; channel/andyl/packages/bootstrap.scm
;;
;; Our bootstrap seeds - mirrors Guix's bootstrap-seeds but defined in
;; our channel.

(define-module (andyl packages bootstrap)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system trivial)
  #:use-module (guix licenses))

;; The bootstrap seeds: hex0, kaem
;; These are the only non-source-built artifacts in the entire chain.
;; Source: https://github.com/oriansj/bootstrap-seeds
(define-public andyl-bootstrap-seeds
  (package
    (name "andyl-bootstrap-seeds")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/"
                    version ".tar.gz"))
              (sha256
               (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    (arguments
     `(#:builder
       (begin
         ;; Extract and install the seed binaries for our target architecture
         (use-modules (guix build utils))
         (let ((out (assoc-ref %outputs "out"))
               (source (assoc-ref %build-inputs "source")))
           (mkdir-p (string-append out "/bin"))
           ;; Copy architecture-specific seeds
           (copy-recursively
            (string-append source "/NATIVE/x86")
            (string-append out "/bin"))))))
    (home-page "https://github.com/oriansj/bootstrap-seeds")
    (synopsis "Minimal binary seeds for bootstrapping")
    (description "Tiny auditable binaries that serve as the root of the
bootstrap chain.  Contains hex0 (~357 bytes of x86 assembly) and kaem.")
    (license gpl3+)))
```

### 2.4 Stage 1: MesCC-Tools (Hex Assembler to Macro Assembler)

From `hex0`, we build progressively more capable assemblers:

1. **hex0** reads hex, writes bytes
2. **hex1** adds single-character labels and relative jumps
3. **hex2** adds absolute addresses and multi-character labels
4. **M0** is a simple macro assembler
5. **M1** is a full macro assembler with support for architectures
6. **M2-Planet** is a simple C compiler written in M1 assembly
7. **kaem** (also called "kaem-optional") is a shell-like script runner

These are collectively the `mescc-tools` and `mescc-tools-extra` packages.

```scheme
;; The build DAG for Stage 1 (simplified):
;;
;; hex0 --builds--> hex1 --builds--> hex2
;;                                     |
;;                                     v
;;                                    M0 --builds--> M1
;;                                                    |
;;                                                    v
;;                                                 M2-Planet
;;                                                    |
;;                                                    v
;;                                                  kaem
```

Each step is a derivation. Guix's `(gnu packages commencement)` defines these
as a carefully ordered chain. In our channel, we mirror this structure:

```scheme
;; channel/andyl/packages/commencement.scm
;;
;; The commencement module: from seeds to full toolchain.
;; This is the most critical module in the entire channel.

(define-module (andyl packages commencement)
  #:use-module (guix packages)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (andyl packages bootstrap))

;; Stage 1: mescc-tools
;; Built using only the bootstrap seeds (hex0, kaem)
(define-public andyl-mescc-tools
  (package
    (name "andyl-mescc-tools")
    (version "1.5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/mescc-tools/archive/refs/tags/Release_"
                    version ".tar.gz"))
              (sha256
               (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-bootstrap-seeds))
    (arguments
     `(#:builder
       (begin
         ;; Use hex0 and kaem from seeds to build the tools chain
         ;; kaem.run script drives the build
         ;; Each tool is built using only the previously-built tools
         #t)))
    (home-page "https://github.com/oriansj/mescc-tools")
    (synopsis "Tools for bootstrapping from hex to macro assembly")
    (description "Provides hex2 linker, M1 macro assembler, and kaem
shell, all bootstrapped from the ~357-byte hex0 seed.")
    (license gpl3+)))
```

### 2.5 Stage 2: Mes and TinyCC Bootstrap

**GNU Mes** (Maxwell Equations of Software) is a Scheme interpreter and C
compiler written in a mutually self-hosting style. The C compiler (MesCC) can
compile a subset of C sufficient to build TinyCC.

```scheme
;; Mes: Scheme interpreter + C compiler
;; Built with mescc-tools (M2-Planet compiles it)
(define-public andyl-mes
  (package
    (name "andyl-mes")
    (version "0.27")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://ftp.gnu.org/gnu/mes/mes-"
                                  version ".tar.gz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    (native-inputs (list andyl-mescc-tools))
    (arguments
     `(#:builder
       (begin
         ;; M2-Planet (from mescc-tools) compiles mes.c
         ;; Then mes can interpret Scheme and compile C via mescc
         #t)))
    (synopsis "GNU Mes - Scheme interpreter and C compiler")
    (description "Mes provides mescc, a C compiler written in Scheme,
which is used to bootstrap TinyCC.")
    (license gpl3+)
    (home-page "https://www.gnu.org/software/mes/")))
```

**TinyCC (tcc)** is then built using MesCC. TinyCC is a small, fast C compiler
that can compile GCC (with some patches):

```scheme
;; TinyCC: Small C compiler, bootstrapped from mescc
;; This is the bridge from "toy" compilers to "real" compilers
(define-public andyl-tinycc-mescc
  (package
    (name "andyl-tinycc-mescc")
    (version "0.9.27")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://download.savannah.gnu.org/releases/tinycc/tcc-"
                    version ".tar.bz2"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    (native-inputs (list andyl-mes))
    (arguments
     `(#:builder
       (begin
         ;; mescc compiles tcc
         ;; The resulting tcc is limited but can compile more C
         #t)))
    (synopsis "TinyCC bootstrapped from MesCC")
    (description "A bootstrap TinyCC compiled using GNU Mes's C compiler.
This TinyCC can then compile GCC.")
    (license lgpl2.1+)
    (home-page "https://bellard.org/tcc/")))
```

### 2.6 Stage 3: GCC 4.x from TinyCC

TinyCC compiles an early GCC (version 4.6.4 is typical). This GCC is limited
but functional enough to compile a modern GCC:

```scheme
;; GCC 4.6.4: First "real" compiler in the chain
;; Built with TinyCC (which was built with MesCC, which was built with
;; M2-Planet, which was built with hex0)
(define-public andyl-gcc-core-mesboot
  (package
    (name "andyl-gcc-core-mesboot")
    (version "4.6.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-core-" version ".tar.gz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-tinycc-mescc
           andyl-mescc-tools      ;; for as, ld
           andyl-bootstrap-glibc  ;; minimal libc
           ))
    (arguments
     `(#:builder
       (begin
         ;; TinyCC compiles GCC 4.6.4
         ;; This is a minimal C-only GCC (no C++, no Fortran, etc.)
         ;; It's enough to bootstrap a modern GCC
         #t)))
    (synopsis "GCC 4.6.4 bootstrapped from TinyCC")
    (description "A minimal GCC compiled using bootstrap TinyCC.")
    (license gpl3+)
    (home-page "https://gcc.gnu.org/")))
```

### 2.7 Stage 4: Modern GCC

GCC 4.6.4 compiles GCC 7.x, which compiles GCC 10.x or 13.x:

```scheme
;; GCC 10.x or 13.x: The production compiler
;; This is what we'll use to build all remaining packages
(define-public andyl-gcc
  (package
    (name "andyl-gcc")
    (version "13.3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-" version ".tar.xz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc-intermediate))  ;; GCC 7.x built from GCC 4.6.4
    (arguments
     '(#:configure-flags
       (list "--enable-languages=c,c++"
             "--disable-multilib"
             "--disable-bootstrap"  ;; We did our own bootstrap
             "--with-system-zlib")
       ;; Phases adjusted for bootstrap environment
       #:phases
       (modify-phases %standard-phases
         ;; Custom phase modifications as needed
         )))
    (synopsis "GCC compiled through the full bootstrap chain")
    (description "Modern GCC built through the complete bootstrap path
from hex0 seeds.")
    (license gpl3+)
    (home-page "https://gcc.gnu.org/")))
```

### 2.8 Stage 5: glibc (covered in detail in Section 4)

### 2.9 Stage 6: Full Toolchain

Once we have modern GCC + glibc, we build the complete toolchain:

```
 Full Toolchain Components
 =========================
 binutils     - as, ld, ar, nm, objdump, etc.
 gcc          - C/C++ compiler (already built)
 glibc        - C library (already built)
 make         - GNU Make
 coreutils    - basic shell utilities
 bash         - shell
 findutils    - find, xargs
 gawk         - text processing
 grep         - pattern matching
 sed          - stream editor
 tar          - archiving
 gzip/xz      - compression
 diffutils    - diff, cmp
 patch        - apply diffs
 pkg-config   - build configuration
```

This set of packages becomes the "toolchain" that all subsequent packages use
as implicit inputs. In Guix, this is what `gnu-build-system` provides
automatically as the `%default-inputs`.

### 2.10 How `(gnu packages commencement)` Implements This

In upstream Guix, the `(gnu packages commencement)` module contains hundreds of
carefully-ordered package definitions that implement this bootstrap chain. Key
packages include:

| Guix Package Name | Stage | Description |
|---|---|---|
| `bootstrap-seeds` | 0 | hex0, kaem |
| `mescc-tools` | 1 | hex2, M1, M2-Planet |
| `mes` | 2 | Scheme interpreter + MesCC |
| `tinycc-mesboot` | 2 | TinyCC from MesCC |
| `gcc-core-mesboot` | 3 | GCC 4.6.4 from TinyCC |
| `gcc-mesboot` | 3-4 | GCC 7.5 from GCC 4.6.4 |
| `glibc-mesboot` | 5 | glibc from bootstrap GCC |
| `gcc-boot0` | 4 | Near-final GCC |
| `binutils-boot0` | 6 | Bootstrap binutils |
| `glibc-final` | 5-6 | Production glibc |
| `gcc-final` | 4-6 | Production GCC |
| `%boot0-inputs` ... `%final-inputs` | 0-6 | Input sets for each stage |

Our ANDYL channel replicates this structure but with our own package names,
versions, and configurations. We can study and reference `commencement.scm`
but every package definition in our channel is ours.

---

## 3. Custom Guix Channel (ANDYL Channel)

### 3.1 Channel Definition

A Guix channel is a Git repository containing Guile Scheme modules that define
packages. The channel is identified by a `.guix-channel` file at the repo root.

```
 channel/
 +-- .guix-channel              <-- channel metadata
 +-- .guix-authorizations       <-- authorized committers (OpenPGP)
 +-- andyl/
     +-- packages/
     |   +-- bootstrap.scm      <-- Stage 0: seeds
     |   +-- commencement.scm   <-- Stages 1-6: bootstrap chain
     |   +-- base.scm           <-- coreutils, bash, etc.
     |   +-- gcc.scm            <-- GCC (post-bootstrap)
     |   +-- glibc.scm          <-- glibc (post-bootstrap)
     |   +-- linux.scm          <-- kernel, headers
     |   +-- networking.scm     <-- curl, openssl, etc.
     |   +-- services.scm       <-- nginx, postgresql, etc.
     |   +-- tls.scm            <-- TLS libraries
     |   +-- python.scm         <-- Python ecosystem
     |   +-- compression.scm    <-- zlib, xz, zstd, etc.
     |   +-- ...
     +-- system/
     |   +-- base.scm           <-- base operating-system config
     |   +-- server.scm         <-- server-specific config
     |   +-- services.scm       <-- system service definitions
     +-- build/
         +-- andyl-build-system.scm  <-- (optional) custom build system
```

### 3.2 `.guix-channel` File

```scheme
;; channel/.guix-channel
(channel
  (version 0)
  (url "https://git.andyl.dev/andyl-channel")
  (directory ".")                       ;; package modules are at repo root
  (dependencies '())                    ;; no dependencies on other channels
  ;; NOTE: We explicitly have NO dependency on the upstream 'guix' channel.
  ;; We define everything ourselves.
  )
```

### 3.3 Channel Authentication

Guix channels support commit authentication via OpenPGP signatures. Every
commit must be signed by an authorized key.

```scheme
;; channel/.guix-authorizations
;; This file lists OpenPGP fingerprints authorized to commit to the channel.
;; Guix verifies that every commit in the channel is signed by one of these keys.
(authorizations
  (version 0)
  (("FINGERPRINT_OF_ANDYL_SIGNING_KEY_1"
    (name "andyl-builder"))
   ("FINGERPRINT_OF_ANDYL_SIGNING_KEY_2"
    (name "andyl-admin"))))
```

Workflow for signed commits:

```bash
# Generate a signing key (once)
gpg --full-gen-key  # RSA 4096, no expiry for build keys

# Configure Git to sign commits
git config commit.gpgsign true
git config user.signingkey FINGERPRINT

# Every commit to the channel is now signed
git commit -m "Add andyl-openssl package"
# GPG will prompt for passphrase

# Guix verifies the chain of signatures on `guix pull`
guix pull --channels=channels.scm
# If any commit is unsigned or signed by an unauthorized key, pull fails.
```

### 3.4 Package Definition Structure

Every package in Guix is a Scheme record with these fields:

```scheme
(define-public andyl-zlib
  (package
    (name "andyl-zlib")                  ;; package name
    (version "1.3.1")                    ;; version string
    (source                              ;; where to get the source
      (origin
        (method url-fetch)               ;; download method
        (uri (string-append
              "https://zlib.net/zlib-"
              version ".tar.gz"))
        (sha256                          ;; hash for integrity verification
         (base32 "0kp5w2bz4z3gm5vjqpc6..."))))
    (build-system gnu-build-system)      ;; how to build (./configure, make, make install)
    (arguments                           ;; build customization
     '(#:phases
       (modify-phases %standard-phases
         ;; zlib doesn't use a standard autoconf configure
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (invoke "./configure"
                       (string-append "--prefix=" out)
                       "--shared")))))))
    (home-page "https://zlib.net/")
    (synopsis "Compression library")
    (description "zlib is a general-purpose lossless data compression library.")
    (license license:zlib)))
```

### 3.5 Input Types

Guix distinguishes three types of package inputs:

```
 +-------------------------------------------------------------------+
 |  INPUT TYPE          | AT BUILD TIME?  | AT RUN TIME?  | PROPAGATED?  |
 +-------------------------------------------------------------------+
 |  inputs              | Yes (on PATH)   | Yes (in RUNPATH) | No        |
 |  native-inputs       | Yes (on PATH)   | No               | No        |
 |  propagated-inputs   | Yes (on PATH)   | Yes              | Yes*      |
 +-------------------------------------------------------------------+

 * propagated-inputs are automatically added to the inputs of any package
   that uses this package as an input.
```

**inputs**: Libraries and tools needed both at build and run time. The build
output will contain references to these store paths in RUNPATH/RPATH entries.

```scheme
;; curl needs openssl at both build and run time
(inputs (list andyl-openssl andyl-zlib))
```

**native-inputs**: Tools needed only at build time (compilers, code generators,
test frameworks). These are NOT needed at run time and won't be referenced
from the build output.

```scheme
;; pkg-config is only needed during ./configure, not at runtime
(native-inputs (list andyl-pkg-config andyl-perl))  ;; perl for test scripts
```

**propagated-inputs**: Like inputs, but "infectious" -- any package that depends
on this package automatically gets these as inputs too. Used for header-only
libraries and libraries that expose types from their dependencies in their
public API.

```scheme
;; glib propagates libffi because glib's headers include libffi types
(propagated-inputs (list andyl-libffi andyl-pcre2))
```

### 3.6 Build Systems

Guix provides several build systems. Each one automates a particular build
pattern:

| Build System | Pattern | Phases |
|---|---|---|
| `gnu-build-system` | `./configure && make && make install` | unpack, patch, configure, build, check, install |
| `cmake-build-system` | `cmake .. && make && make install` | (similar, uses cmake) |
| `meson-build-system` | `meson setup && ninja && ninja install` | (similar, uses meson/ninja) |
| `trivial-build-system` | Custom builder Scheme code | (just runs your #:builder) |
| `copy-build-system` | Copy files to output | (simple file installation) |
| `python-build-system` | `python setup.py install` or pip | (Python-specific phases) |

For ANDYL OS server packages, we'll primarily use `gnu-build-system` and
`cmake-build-system`. The `trivial-build-system` is crucial for bootstrap
stages where the standard build phases don't apply.

### 3.7 Version Pinning Strategy

Since we control every package, version pinning is straightforward:

1. **Source hashes**: Every `origin` includes a `sha256` hash. Guix refuses to
   use source that doesn't match.

2. **Channel commit pinning**: Pin the channel to a specific commit:
   ```scheme
   (channel
     (name 'andyl)
     (url "file:///andyl-channel")
     (commit "abc123def456..."))  ;; exact commit
   ```

3. **No transitive updates**: Because we have no upstream channel dependency,
   updating one package never silently updates others. Every change is an
   explicit commit to our channel.

4. **Reproducible environments**: `guix time-machine` lets us build against
   any historical channel commit:
   ```bash
   guix time-machine --commit=abc123 -- build andyl-nginx
   ```

---

## 4. glibc Build Details

### 4.1 glibc in the Bootstrap Chain

glibc appears twice in the bootstrap:

1. **Bootstrap glibc (glibc-mesboot)**: A minimal glibc built with the
   bootstrap GCC. Just enough to build a modern GCC.

2. **Final glibc (andyl-glibc)**: The production glibc built with the final
   GCC. This is what all user-space packages link against.

### 4.2 Building glibc from Source

```scheme
;; channel/andyl/packages/glibc.scm

(define-module (andyl packages glibc)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages linux))

(define-public andyl-glibc
  (package
    (name "andyl-glibc")
    (version "2.39")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/glibc/glibc-"
                                  version ".tar.xz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system gnu-build-system)

    ;; glibc must be built out-of-tree
    (arguments
     `(#:out-of-source? #t

       ;; glibc's test suite is extensive but slow; enable in CI
       #:tests? #f

       #:configure-flags
       (list
        ;; Install prefix
        (string-append "--prefix=" (assoc-ref %outputs "out"))

        ;; Kernel headers location
        (string-append "--with-headers="
                       (assoc-ref %build-inputs "linux-headers")
                       "/include")

        ;; Server-oriented flags
        "--enable-kernel=5.15"      ;; minimum kernel version
        "--enable-stack-protector=strong"
        "--enable-bind-now"         ;; full RELRO
        "--enable-static-nss"       ;; static NSS for containers
        "--enable-cet"              ;; Control-flow Enforcement (x86)
        "--disable-werror"          ;; warnings shouldn't fail the build

        ;; Architecture tuning for servers
        "--enable-lock-elision"     ;; hardware lock elision (if available)

        ;; Locale and charset
        "--enable-add-ons"
        "--with-default-link"

        ;; Paths
        "--sysconfdir=/etc"
        "--localstatedir=/var")

       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'set-shell
           (lambda _
             ;; glibc configure needs a shell
             (setenv "SHELL" (which "bash"))
             (setenv "CONFIG_SHELL" (which "bash"))))

         (add-after 'install 'install-utf8-locales
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Generate essential UTF-8 locales
             (let ((out (assoc-ref outputs "out")))
               (invoke "make" "localedata/install-locales"
                       (string-append "DESTDIR=" out)))))

         (add-after 'install 'remove-static-libs
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Keep libc.a and libpthread.a for static linking
             ;; Remove other static libraries to save space
             (let ((lib (string-append (assoc-ref outputs "out") "/lib")))
               (for-each delete-file
                 (filter (lambda (f)
                           (and (string-suffix? ".a" f)
                                (not (member (basename f)
                                             '("libc.a" "libpthread.a"
                                               "libm.a" "libdl.a"
                                               "librt.a")))))
                         (find-files lib "\\.a$")))))))))

    (native-inputs
     (list andyl-gcc
           andyl-binutils
           andyl-make
           andyl-perl           ;; needed for glibc build scripts
           andyl-python-boot    ;; needed for some glibc build tools
           andyl-bison
           andyl-texinfo))

    ;; glibc has no runtime inputs — it IS the base runtime
    (inputs '())

    ;; linux-headers are needed at build time for syscall definitions
    ;; and at "run time" in the sense that other packages need the
    ;; headers to build against glibc
    (propagated-inputs
     (list andyl-linux-headers))

    (home-page "https://www.gnu.org/software/libc/")
    (synopsis "The GNU C Library")
    (description "glibc is the GNU C Library, providing the core libraries
for the GNU system and GNU/Linux systems.  Built with server-oriented
hardening flags.")
    (license license:lgpl2.1+)))
```

### 4.3 Kernel Headers

glibc needs Linux kernel headers at build time. These define syscall numbers,
ioctl constants, and kernel data structures:

```scheme
(define-public andyl-linux-headers
  (package
    (name "andyl-linux-headers")
    (version "6.6.70")  ;; LTS kernel
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-"
                    version ".tar.xz"))
              (sha256 (base32 "HASH_HERE"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _
             ;; No configure step for headers
             #t))
         (replace 'build
           (lambda _
             ;; "make headers" extracts the user-space API headers
             (invoke "make" "headers"
                     (string-append "ARCH="
                       (match (or (getenv "TARGET_ARCH") "x86_64")
                         ("x86_64" "x86")
                         ("aarch64" "arm64")
                         (arch arch))))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               ;; Install sanitized headers
               (invoke "make" "headers_install"
                       (string-append "INSTALL_HDR_PATH=" out)
                       "ARCH=x86")
               ;; Remove non-header files
               (for-each delete-file
                 (find-files (string-append out "/include")
                             "\\.install$"))))))
       #:tests? #f))  ;; No tests for headers
    (home-page "https://kernel.org/")
    (synopsis "Linux kernel headers for glibc")
    (description "Sanitized Linux kernel headers providing the user-space
API for system calls and kernel interfaces.")
    (license license:gpl2)))
```

### 4.4 Server-Specific Build Flags Explained

| Flag | Purpose |
|---|---|
| `--enable-kernel=5.15` | Assume minimum kernel 5.15 (current LTS). Enables syscalls not available on older kernels. |
| `--enable-stack-protector=strong` | Buffer overflow detection via stack canaries. "strong" protects functions with local arrays or address-taken variables. |
| `--enable-bind-now` | Full RELRO: all PLT entries resolved at load time. Prevents GOT overwrite attacks. |
| `--enable-static-nss` | Statically link NSS modules. Useful for containers/static binaries. |
| `--enable-cet` | Intel Control-flow Enforcement Technology. Hardware-enforced return address protection. |

### 4.5 Locale Handling

For servers, we generate a minimal set of locales:

```
 Essential locales for servers:
 - en_US.UTF-8     (default)
 - C.UTF-8         (POSIX with UTF-8)
 - POSIX           (always available, built-in)
```

The `install-utf8-locales` phase above handles this. Additional locales can be
generated at deployment time if needed, but keeping the base image minimal is
preferred.

### 4.6 NSS (Name Service Switch) Considerations

glibc's NSS modules control how name resolution works (users, groups, hosts,
etc.). For server environments:

- **files**: Always available, reads `/etc/passwd`, `/etc/hosts`, etc.
- **dns**: DNS resolution via `/etc/resolv.conf`.
- **We do NOT include**: NIS, LDAP, or other network name services in the base
  glibc build. If needed, these can be separate packages.

The `--enable-static-nss` flag allows static linking of NSS modules, which is
useful for containerized deployments where dynamic NSS plugin loading is
problematic.

---

## 5. Guix Build System Internals

### 5.1 Derivations (.drv Files)

A derivation is Guix's unit of build. It's a deterministic description of
how to build something. Derivations are stored as `.drv` files in `/gnu/store/`.

```
 Derivation structure:
 ====================

 /gnu/store/abc123...-andyl-zlib-1.3.1.drv
   |
   +-- outputs:     [("out", "/gnu/store/xyz789...-andyl-zlib-1.3.1")]
   +-- inputs:      [("/gnu/store/...-gcc-13.3.0.drv", ["out"]),
   |                 ("/gnu/store/...-make-4.4.1.drv", ["out"]),
   |                 ("/gnu/store/...-source-zlib-1.3.1.tar.gz", ["out"])]
   +-- system:      "x86_64-linux"
   +-- builder:     "/gnu/store/...-guile-3.0.9/bin/guile"
   +-- args:        ["--no-auto-compile", "-e", "(@ (guix build gnu-build-system) builder)"]
   +-- environment: [("PATH", "/gnu/store/...-gcc-.../bin:..."),
                     ("C_INCLUDE_PATH", "..."),
                     ("LIBRARY_PATH", "...")]
```

Key properties of derivations:

1. **Content-addressed**: The `.drv` file path is the hash of its contents.
   If any input changes, the derivation hash changes.

2. **Deterministic**: Same derivation always produces the same output
   (bit-for-bit, assuming the build is reproducible).

3. **Self-contained**: All dependencies are explicit. No implicit dependencies
   on the host system.

Inspect derivations:

```bash
# Show the derivation for a package
guix build --derivations andyl-zlib
# => /gnu/store/abc123...-andyl-zlib-1.3.1.drv

# Pretty-print a derivation
guix show --derivation /gnu/store/abc123...-andyl-zlib-1.3.1.drv

# Show the build graph
guix graph andyl-zlib | dot -Tpng > zlib-graph.png
```

### 5.2 Content-Addressed Store Paths

Every item in `/gnu/store/` has a path of the form:

```
/gnu/store/<hash>-<name>-<version>
```

The hash is computed from:
- All input derivations (recursively)
- The build script
- All environment variables
- The build system type

This means:
- Changing ANY input (even a single header file) changes the output hash
- Two builds with identical inputs produce identical output paths
- Outputs can be verified: recompute the hash and compare

```
 Example store paths:
 /gnu/store/abc123...-andyl-gcc-13.3.0/
   +-- bin/gcc
   +-- lib/libgcc_s.so
   +-- include/...
   +-- ...

 /gnu/store/def456...-andyl-glibc-2.39/
   +-- lib/libc.so.6
   +-- lib/ld-linux-x86-64.so.2
   +-- include/stdio.h
   +-- ...
```

### 5.3 The Build Daemon (guix-daemon)

`guix-daemon` is the privileged process that actually executes builds. It runs
as root and performs builds as unprivileged "build users":

```
 Build Isolation:
 ================

 guix-daemon (root)
   |
   +-- Build Request: "build /gnu/store/abc...-zlib.drv"
   |
   +-- Creates isolated build environment:
   |     - New mount namespace (chroot into /gnu/store/...)
   |     - New PID namespace (builder sees only its own processes)
   |     - New network namespace (no network access by default)
   |     - New user namespace (builder runs as nobody)
   |     - /tmp is a private tmpfs
   |     - Only declared inputs are visible
   |     - No access to /home, /etc, or host system
   |
   +-- Runs build as guixbuilder01 (unprivileged)
   |     - ./configure && make && make install
   |     - Output goes to /gnu/store/<hash>-<name>/
   |
   +-- Verifies output and registers in database
```

Build isolation guarantees:
- **No network**: Builds cannot download anything. All sources must be
  pre-fetched as inputs.
- **No host contamination**: The build can't see `/usr/lib` or any host files.
- **Deterministic environment**: Same user, same tmpdir, same everything.
- **Time**: Some builds see a fixed timestamp (for reproducibility).

### 5.4 Substitutes and Why We Disable Them

Substitutes are pre-built binaries served by a build farm. Upstream Guix uses
`ci.guix.gnu.org` as the default substitute server. When you `guix build foo`,
Guix checks if a substitute exists and downloads it instead of building locally.

**We disable ALL upstream substitutes.** Reasons:

1. **Trust**: We trust only our own builds. Upstream substitutes are signed by
   Guix infrastructure, not by us.

2. **Customization**: Our packages have different build flags, patches, and
   configurations than upstream.

3. **Auditability**: We can verify every build from source through our own
   bootstrap chain.

4. **Supply chain security**: No binary from outside our build infrastructure
   enters our system (except the auditable bootstrap seeds).

Disabling substitutes:

```bash
# At daemon level (in Dockerfile / entrypoint)
guix-daemon --no-substitutes

# At client level (belt and suspenders)
guix build --no-substitutes andyl-zlib

# In Guix configuration
(guix-configuration
  (use-substitutes? #f)
  (authorized-keys '()))  ;; empty = trust nobody
```

### 5.5 Grafts

Grafts are Guix's mechanism for applying security updates without rebuilding
the entire dependency graph. When a leaf package (like openssl) has a security
fix, Guix can "graft" the new version into packages that depend on it by
rewriting store references at install time.

```
 Without grafts:                    With grafts:
 ==============                    =============
 openssl 1.1.1t                    openssl 1.1.1t (fixed)
   |                                 |
   v                                 v
 nginx (rebuilt)                   nginx (original build,
   |                                      references rewritten
   v                                      to point to fixed openssl)
 30 other packages (rebuilt)       30 other packages (not rebuilt,
                                         grafted at profile time)
```

For ANDYL OS, we need to decide:

- **Enable grafts** (default): Faster security updates, but the running binary
  has been post-processed. Store path doesn't match the build derivation
  exactly.

- **Disable grafts**: Every security update triggers a full rebuild of all
  dependents. Slower but every binary matches its derivation exactly.

Recommendation for ANDYL OS: **Disable grafts.** We have our own CI/binary
cache, and full rebuilds are acceptable for the level of auditability we want.

```bash
# Disable grafts
guix build --no-grafts andyl-nginx
```

```scheme
;; Or in system configuration
(operating-system
  ...
  ;; Custom guix service config that disables grafts
  )
```

### 5.6 Build Isolation Details

The build daemon uses Linux namespaces for isolation:

| Namespace | Purpose | ANDYL Relevance |
|---|---|---|
| Mount | Chroot: only declared inputs visible | Ensures no host contamination |
| PID | Isolated process tree | Build can't see/signal other processes |
| Network | No network by default | Prevents downloads during build |
| User | Maps builder to nobody | Principle of least privilege |
| IPC | Isolated IPC | No shared memory with host |
| UTS | Isolated hostname | Deterministic hostname |

Docker already provides a layer of namespace isolation. The guix-daemon adds a
second layer inside the container. This double isolation is fine -- the inner
namespaces operate within the outer Docker namespaces.

**Docker capability requirements**: The container needs `SYS_ADMIN` to allow
the daemon to create inner namespaces. Alternatively, use `--privileged` (less
secure) or configure specific seccomp profiles.

---

## 6. Binary Caching for CI

### 6.1 Architecture

```
 +-------------------------------------------------------------------+
 |                     Binary Cache Architecture                      |
 |                                                                    |
 |  CI Worker 1 ----+                                                 |
 |  CI Worker 2 ----+----> guix publish ----> NAR Cache Storage       |
 |  CI Worker 3 ----+      (substitute         (S3, local disk,       |
 |                          server)              or GCS)              |
 |                             |                                      |
 |                             v                                      |
 |                    Signs NARs with ANDYL key                       |
 |                             |                                      |
 |  Dev Machines ----pull------+                                      |
 |  Deployment   ----pull------+                                      |
 +-------------------------------------------------------------------+
```

### 6.2 Setting Up `guix publish`

`guix publish` serves pre-built packages over HTTP. It's Guix's built-in
substitute server:

```bash
# Generate a signing key pair for the ANDYL cache
guix archive --generate-key

# This creates:
#   /etc/guix/signing-key.sec  (private key, PROTECT THIS)
#   /etc/guix/signing-key.pub  (public key, distribute to consumers)

# Start the substitute server
guix publish \
  --port=8080 \
  --user=guix-publish \
  --compression=zstd:6 \        # zstd is fast and compresses well
  --cache=/var/cache/guix/publish \  # pre-compress and cache NARs
  --ttl=30d                     # narinfo cache TTL
```

### 6.3 NAR Archive Format

NAR (Nix ARchive) is a deterministic archive format used by both Nix and Guix.
Unlike tar, NAR is canonicalized:

- Files are sorted lexicographically
- No timestamps, no user/group info
- No filesystem metadata that could vary between machines
- This makes NAR archives reproducible: same contents = same NAR bytes

A narinfo file accompanies each NAR and contains metadata:

```
StorePath: /gnu/store/abc123...-andyl-zlib-1.3.1
URL: nar/zstd/abc123...-andyl-zlib-1.3.1
Compression: zstd
NarHash: sha256:def456...
NarSize: 245760
References: /gnu/store/xyz789...-andyl-glibc-2.39
FileSize: 98304
Signature: 1;andyl-cache;ABCDEF123456...
```

### 6.4 Signing and Verification

Every narinfo must be signed with our private key. Consumers verify with our
public key:

```bash
# On the cache server: sign everything automatically
# (guix publish does this automatically using /etc/guix/signing-key.sec)

# On consumer machines: authorize our cache
guix archive --authorize < /path/to/andyl-cache-public-key.pub

# Configure the consumer to use our cache (and ONLY our cache)
# In ~/.config/guix/channels.scm or system config:
```

```scheme
;; Consumer guix-daemon configuration (in system config or CLI)
(guix-configuration
  (use-substitutes? #t)  ;; Yes, but ONLY from our own server
  (substitute-urls '("https://cache.andyl.dev"))
  (authorized-keys
    (list (local-file "/path/to/andyl-cache-public-key.pub"))))
```

### 6.5 Cache Storage Backends

**Option A: Local disk**

```bash
guix publish --cache=/var/cache/guix/publish
# Simple, fast, but doesn't scale to multiple servers
```

**Option B: S3-compatible object storage**

```bash
# Use a reverse proxy (nginx) in front of guix publish
# that caches NARs to S3

# Or use guix publish with a local cache directory that's synced to S3:
guix publish --cache=/var/cache/guix/publish &
# Sync to S3 periodically:
aws s3 sync /var/cache/guix/publish/ s3://andyl-guix-cache/
```

**Option C: Dedicated cache service**

For larger deployments, run a dedicated narinfo/NAR server that reads from
object storage. The `guix publish` protocol is simple HTTP:

```
GET /nix-cache-info           -> cache metadata
GET /<hash>.narinfo           -> narinfo for store path
GET /nar/zstd/<hash>-<name>   -> compressed NAR archive
```

### 6.6 CI Integration with Docker Builds

```
 CI Pipeline:
 ============

 1. CI triggers on channel commit
 2. Spin up Docker container with Guix build environment
 3. Mount /gnu/store from Docker volume (warm cache from last build)
 4. guix pull to update channel
 5. guix build <changed-packages> --no-substitutes
    - Builds only what changed (Guix tracks derivation DAG)
 6. guix publish serves the built packages
 7. Other CI stages pull substitutes from our cache
 8. Golden image build pulls all packages from cache (fast)

 +----------+     +-------------+     +-----------+     +-----------+
 | Channel  |---->| CI: Build   |---->| CI: Cache |---->| CI: Image |
 | Commit   |     | packages    |     | (publish) |     | assembly  |
 +----------+     +-------------+     +-----------+     +-----------+
                       |                    ^                 |
                       v                    |                 v
                  /gnu/store          guix publish       Golden .img
                  (Docker vol)        port 8080          artifact
```

### 6.7 Cache Invalidation Strategy

Guix's content-addressing handles most cache invalidation naturally:

1. **Package source changes**: New source hash = new derivation hash = new
   store path. Old cache entry is simply never requested again.

2. **Build flag changes**: Different flags = different derivation = different
   cache entry.

3. **Transitive invalidation**: Changing glibc invalidates all packages that
   depend on it (different input hash = different derivation hash).

What needs manual management:

- **Garbage collection**: Old cache entries pile up. Run `guix gc` periodically
  to remove unreferenced store paths, then clean the publish cache.
  ```bash
  # Keep last 3 generations, delete everything else
  guix gc --delete-generations=3m
  # Clean publish cache of store paths that no longer exist
  guix publish --cache=/var/cache/guix/publish --cache-bypass-threshold=0
  ```

- **Full rebuilds**: When the bootstrap chain changes, everything rebuilds.
  This is rare but the cache will grow significantly. Plan for it.

---

## 7. justfile Integration

### 7.1 Key Build Targets

```makefile
# justfile
#
# ANDYL OS build orchestration
# All builds happen inside Docker containers.

# Default recipe: show help
default:
    @just --list

# ===========================================================================
# Docker Environment
# ===========================================================================

# Build the Guix build container image
docker-build:
    docker compose -f docker/docker-compose.yml build

# Start the Guix build environment (interactive)
docker-shell:
    docker compose -f docker/docker-compose.yml run --rm guix-builder bash

# Start the Guix build environment with daemon (detached)
docker-up:
    docker compose -f docker/docker-compose.yml up -d guix-builder

# Stop the build environment
docker-down:
    docker compose -f docker/docker-compose.yml down

# Show Docker volume sizes
docker-volumes:
    docker system df -v | grep -E 'gnu-store|guix-var'

# ===========================================================================
# Bootstrap
# ===========================================================================

# Run the full bootstrap (Stage 0 through Stage 6)
# WARNING: This takes many hours on first run. Subsequent runs use the store.
bootstrap: docker-build
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes \
            andyl-bootstrap-seeds \
            andyl-mescc-tools \
            andyl-mes \
            andyl-tinycc-mescc \
            andyl-gcc-core-mesboot \
            andyl-gcc \
            andyl-glibc \
            andyl-binutils \
            andyl-make \
            andyl-coreutils

# Bootstrap just the toolchain (assumes seeds + mescc-tools are cached)
bootstrap-toolchain:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes andyl-gcc andyl-glibc andyl-binutils

# ===========================================================================
# Package Building
# ===========================================================================

# Build a specific package
build PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes "{{PACKAGE}}"

# Build all server packages
build-all:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes \
            andyl-linux \
            andyl-nginx \
            andyl-openssl \
            andyl-postgresql \
            andyl-python

# Show the dependency graph for a package
graph PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix graph "{{PACKAGE}}" > "/tmp/{{PACKAGE}}-graph.dot"
    @echo "Graph written to /tmp/{{PACKAGE}}-graph.dot"
    @echo "Render with: dot -Tpng /tmp/{{PACKAGE}}-graph.dot > graph.png"

# ===========================================================================
# System Image
# ===========================================================================

# Build the server system image
build-image:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix system image --image-type=raw \
            --no-substitutes \
            /andyl-channel/andyl/system/server.scm

# Build a VM image for testing
build-vm:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix system vm \
            --no-substitutes \
            /andyl-channel/andyl/system/server.scm

# ===========================================================================
# Binary Cache
# ===========================================================================

# Start the substitute server
cache-serve:
    docker compose -f docker/docker-compose.yml run --rm \
        -p 8080:8080 guix-builder \
        guix publish --port=8080 --compression=zstd:6 \
            --cache=/var/cache/guix/publish

# Generate signing keys (first-time setup)
cache-keygen:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix archive --generate-key

# Export a package as a NAR archive
cache-export PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix archive --export "{{PACKAGE}}"

# ===========================================================================
# Channel Management
# ===========================================================================

# Update the channel (pull latest definitions)
channel-pull:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix pull --channels=/root/.config/guix/channels.scm

# Lint a package definition
lint PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix lint "{{PACKAGE}}"

# Show package details
show PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix show "{{PACKAGE}}"

# ===========================================================================
# Store Management
# ===========================================================================

# Run garbage collection (remove unreferenced store items)
gc:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix gc --free-space=10G

# Show store size
store-size:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        du -sh /gnu/store/

# Verify store integrity
store-verify:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix gc --verify=contents

# ===========================================================================
# Development
# ===========================================================================

# Open a Guix REPL for interactive development
repl:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix repl

# Run the test suite for our packages
test:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes --check andyl-zlib andyl-openssl

# ===========================================================================
# Environment Variables (set via .env or export)
# ===========================================================================

# GUIX_MAX_JOBS: Number of parallel build jobs (default: 4)
# GUIX_CORES: Cores per build, 0 = all (default: 0)
```

### 7.2 Environment Variable Management

```bash
# .env (loaded by docker-compose automatically)
GUIX_MAX_JOBS=4
GUIX_CORES=0
COMPOSE_PROJECT_NAME=andyl-os
```

### 7.3 Build Artifact Management

Build outputs live in the Docker volume `/gnu/store`. To extract artifacts:

```bash
# Copy a built package out of the container
docker compose -f docker/docker-compose.yml run --rm guix-builder \
    guix build --no-substitutes andyl-nginx
# Output: /gnu/store/abc123...-andyl-nginx-1.25.4

# Copy it to host
docker cp <container_id>:/gnu/store/abc123...-andyl-nginx-1.25.4 ./artifacts/

# Or use guix archive to create a portable NAR
docker compose -f docker/docker-compose.yml run --rm guix-builder \
    guix archive --export andyl-nginx > artifacts/andyl-nginx.nar

# Or use guix pack to create a relocatable tarball
docker compose -f docker/docker-compose.yml run --rm guix-builder \
    guix pack --no-substitutes --compression=zstd \
        andyl-nginx andyl-openssl
```

---

## 8. Edge Cases and Considerations

### 8.1 Cross-Compilation

If developing on Apple Silicon (aarch64) but targeting x86_64 servers:

```bash
# Option 1: QEMU emulation via Docker
docker run --platform linux/amd64 ...
# Slow (5-10x), but works for all packages

# Option 2: Guix cross-compilation
guix build --target=x86_64-linux-gnu andyl-nginx
# Fast, but not all packages support cross-compilation cleanly

# Option 3: Remote build machine
guix build --no-substitutes andyl-nginx \
    --offload --offload-machine=x86-builder.andyl.dev
# Requires an x86_64 Linux machine running guix-daemon
```

### 8.2 Build Reproducibility Verification

```bash
# Build a package twice and compare
guix build --no-substitutes --check andyl-zlib
# If the build is reproducible, this succeeds silently
# If not, it shows which output files differ

# For more detail
guix challenge andyl-zlib
# Compares your local build against known-good builds
```

### 8.3 Handling Network-Dependent Builds

Some packages need network access during build (e.g., Rust crates, Go modules).
Guix handles this by pre-fetching all sources:

```scheme
;; For packages with many source dependencies (like Go):
(source (origin
          (method git-fetch)
          (uri (git-reference
                (url "https://github.com/example/tool")
                (commit (string-append "v" version))))
          (sha256 (base32 "HASH"))))

;; Vendored dependencies: include them in the source
;; Or define each dependency as a separate origin
```

### 8.4 Build Time Estimates

**Docker image build** (binary tarball installation): 2-5 minutes. This
downloads and extracts the pre-built Guix tarball. Subsequent rebuilds with
Docker layer caching complete in seconds.

**Package builds** inside the container depend on the package complexity.
Initial builds of large packages (GCC, glibc) take 1-2 hours each.
Subsequent builds only rebuild what changed. The store caches everything.

> **Note:** The full hex0 source bootstrap (Stage 0 through Stage 6) described
> in Section 2 takes 4-8 hours on a modern machine. This is documented as a
> theoretical reference but is not part of the Docker build.

### 8.5 Store Size Management

A full bootstrap produces a large store:

```
 /gnu/store/ breakdown (approximate):
 ===================================
 Bootstrap stages (seeds through gcc-mesboot):  ~5 GB
 Final toolchain (gcc, glibc, binutils, etc.):  ~3 GB
 Server packages (nginx, postgresql, etc.):     ~2 GB
 Intermediate build artifacts:                  ~10 GB
 Source tarballs:                                ~2 GB
 ---------------------------------------------------
 Total before gc:                               ~22 GB
 After gc (keeping only final outputs):         ~8 GB
```

Regular garbage collection is essential:

```bash
# Keep only live references (current profiles)
just gc

# More aggressive: remove everything not in current profile
guix gc --delete-generations
guix gc
```

### 8.6 Debugging Failed Builds

```bash
# Keep the build directory on failure
guix build --keep-failed andyl-problematic-package
# Build directory preserved at /tmp/guix-build-andyl-problematic-package-1.0.drv-0/

# Build with verbose output
guix build --verbosity=3 andyl-problematic-package

# Enter the build environment interactively
guix shell --container --development andyl-problematic-package
# This drops you into a shell with all build inputs available
# You can then run ./configure, make, etc. manually

# View build logs
guix build --log-file andyl-problematic-package
# Returns the path to the build log in /var/log/guix/
```

---

## 9. Summary: What We Build vs. What We Borrow

```
 +-------------------------------------------------------------------+
 |                     FROM GUIX (borrowed)                           |
 +-------------------------------------------------------------------+
 |  - guix-daemon binary (installed via binary tarball)               |
 |  - guix CLI tool                                                   |
 |  - Build system infrastructure (gnu-build-system, etc.)            |
 |  - Package DSL (define-public, package record, etc.)               |
 |  - Store management, derivation engine, content-addressing         |
 |  - NAR archive format, guix publish, guix archive                  |
 |  - Namespace-based build isolation                                 |
 +-------------------------------------------------------------------+

 +-------------------------------------------------------------------+
 |                     FROM US (built from scratch)                    |
 +-------------------------------------------------------------------+
 |  - Every package definition (our own Scheme files)                 |
 |  - Channel (our own .guix-channel, authenticated)                  |
 |  - Binary cache (our own signing key, our own server)              |
 |  - Build flags, patches, configurations                            |
 |  - System configuration (operating-system, services)               |
 |  - Docker build environment (our Dockerfile)                       |
 |  - CI pipeline                                                     |
 |  - Golden image                                                    |
 +-------------------------------------------------------------------+
```

The distinction is: we use Guix as a **build tool** (like using `make` or
`cmake`), but we provide ALL the **build definitions** ourselves. The Guix
daemon and CLI are installed via the standard binary tarball. No upstream Guix
package definitions or binary substitutes are used -- all packages are built
from source through our own channel.

---

## 10. Open Questions for Further Investigation

1. **Channel dependency on Guix modules**: Even though we don't depend on the
   upstream `guix` channel for packages, our package definitions use modules
   like `(guix packages)`, `(guix build-system gnu)`, etc. These come from the
   Guix installation itself (the `current-guix` profile). We need to decide:
   - Pin the Guix version we use as a build tool?
   - Vendor the Guix Scheme modules into our repo?
   - Accept that the Guix tool version is a build-time dependency?

2. **Kernel**: We need to build the Linux kernel itself. This is separate from
   kernel headers. Kernel configuration for servers (minimal drivers, no
   desktop, hardened options) deserves its own brainstorm document.

3. **Init system**: Guix uses GNU Shepherd as init (PID 1). We need to either
   use Shepherd or build an alternative (systemd, runit, etc.). Shepherd
   integrates tightly with Guix's service model.

4. **Firmware**: Server hardware may need firmware blobs (NIC firmware, RAID
   controller firmware). These are non-free and conflict with Guix's free
   software policy. We need a strategy.

5. **Package update workflow**: When OpenSSL has a CVE, what's the process?
   Update the version + hash in our channel, commit (signed), CI builds, cache
   populates, redeploy. How fast can this pipeline be?

6. **Multi-architecture support**: If we need both x86_64 and aarch64 server
   images, we need separate bootstrap chains and store paths for each
   architecture.
