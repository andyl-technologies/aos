# Cross-Cutting Integration Checks

Cross-cutting checks validate that packages work **together** across dependency
boundaries. While toolchain checks verify compilers, library checks verify
ABI/API surfaces, and tool/service checks verify individual binaries, cross-cutting
checks exercise the full dependency chains that define AOS system functionality.

The core insight: AOS controls the entire build from source. Every interaction
point between packages is a testable surface. Cross-cutting checks test the
**edges** in the dependency graph -- not just the nodes.

This document specifies:

1. End-to-end integration scenarios that exercise critical dependency chains
2. ABI/API regression detection for shared library upgrades
3. System-level integration checks (boot, RPATH, config validity, filesystem)
4. The upgrade impact matrix: which tests gate which package upgrades
5. Test priority tiers for release gating
6. CI/CD integration strategy
7. Implementation notes for the existing test framework

---

## 1. End-to-End Integration Scenarios

Each scenario traces a complete functional path through the AOS package graph.
A scenario fails if any package in the chain is incompatible with its neighbors,
even if every individual package passes its own tests in isolation.

Scenarios are classified by execution environment:

- **build-sandbox**: Runs as a Nix derivation. No VM, no init system. Tests
  compile, link, and execute small programs against AOS package outputs.
- **VM test**: Boots a full AOS image in QEMU. Required when tests need
  systemd, networking, or kernel facilities.

---

### 1.1 TLS Stack (openssl as hub)

**Goal**: Verify that every TLS consumer in the system uses a consistent, working
openssl, and that TLS operations succeed end-to-end.

**Dependency chain exercised**:
```
openssl
 +-- zlib (compression within TLS)
 +-- curl --> libssh2 --> openssl (circular)
 |        --> nghttp2 (HTTP/2)
 |        --> zlib
 +-- nginx --> pcre2 (URL matching)
 |         --> zlib (gzip)
 +-- openssh --> zlib
 +-- nix --> curl --> openssl
 |       --> libgit2 --> openssl, libssh2
 +-- systemd --> (resolved TLS, journal remote)
```

**Test steps**:

1. nginx serves an HTTPS page with a self-signed certificate (validates:
   nginx + openssl + pcre2 + zlib)
2. curl fetches the page over HTTPS (validates: curl + openssl + nghttp2 + zlib)
3. curl fetches the same page over HTTP/2 (validates: nghttp2 integration)
4. openssh connects to sshd using key-based auth (validates: openssh + openssl
   key exchange)
5. nix downloads a NAR from a local HTTP cache served by nginx (validates:
   nix + curl + openssl + libarchive + zlib)
6. Verify all TLS consumers report the same openssl version at runtime

**Environment**: VM test (needs nginx, sshd, nix-daemon as running services)

**Packages exercised**: openssl, curl, nginx, openssh, nix, zlib, libssh2,
nghttp2, pcre2, libarchive

**Failure modes caught**:
- openssl SONAME change breaks one consumer but not another
- TLS 1.3 default change causes handshake failure in older consumers
- Certificate verification behavior differs between curl and nix
- zlib compression mismatch between nginx gzip and curl inflate

---

### 1.2 C Compilation Pipeline (gcc/binutils as hub)

**Goal**: Verify the entire C/C++ toolchain is coherent -- from source code to
running ELF binary -- including the ccWrapper, RPATH injection, and dynamic linker.

**Dependency chain exercised**:
```
gcc (bootstrap)
 +-- binutils (as, ld, readelf)
 +-- glibc (libc, ld-linux)
 +-- ccWrapper (AOS-specific flag injection)
     +-- -isystem (header search)
     +-- -L (library search)
     +-- -Wl,-rpath (runtime library path)
     +-- -Wl,-dynamic-linker (ELF interpreter)
```

**Test steps**:

1. Preprocess a C file with `cpp` -- verify include paths resolve AOS headers
   (validates: ccWrapper `-isystem` injection)
2. Compile C source to object file with `gcc -c` (validates: gcc + glibc
   headers)
3. Assemble `.s` file with `as` (validates: binutils assembler)
4. Link object file with `ld` / `gcc` into a shared library (validates:
   linker + ccWrapper `-L` flags)
5. Link a program against the shared library (validates: `-Wl,-rpath` injection)
6. Run `readelf -d` on the binary -- verify RPATH points to AOS store paths,
   not `/usr/lib` or empty (validates: RPATH correctness)
7. Run the binary -- verify it executes and exits 0 (validates: dynamic linker,
   glibc runtime)
8. Compile and link a C++ program using `g++` -- verify `libstdc++` resolves
   (validates: C++ runtime integration)
9. Compile a program that links against openssl and zlib simultaneously --
   verify no symbol conflicts (validates: multi-library linking)

**Environment**: build-sandbox

**Packages exercised**: gcc, binutils, glibc, ccWrapper (from `pkgs/default.nix`),
openssl, zlib

**Failure modes caught**:
- ccWrapper injects wrong `-isystem` path after a glibc update
- RPATH missing for a new library added to runtimeDeps
- `ld` cannot find `crt1.o` / `crti.o` (glibc startfiles)
- C++ `#include_next` failure from mismatched libstdc++ headers
- Symbol version conflict between two libraries compiled against different
  glibc versions

---

### 1.3 Go Application Stack (go as hub)

**Goal**: Verify the Go compiler produces correct binaries for both pure Go and
CGO programs, and that the entire Kubernetes stack built with Go functions
correctly.

**Dependency chain exercised**:
```
go (compiler)
 +-- gcc/glibc (CGO)
 +-- openssl (CGO FFI)
 +-- zlib (CGO FFI)
 +-- containerd --> libseccomp (CGO)
 +-- runc --> libseccomp (CGO)
 +-- kubelet
 +-- kubectl
 +-- kubeadm
 +-- cni-plugins
 +-- helm
 +-- crictl
 +-- nerdctl
 +-- node-exporter
```

**Test steps** (build-sandbox):

1. Build a pure Go "hello world" binary (validates: Go compiler, linker)
2. Run the binary (validates: Go runtime, system call interface)
3. Build a CGO binary that calls a C function (validates: CGO + gcc integration)
4. Build a CGO binary linking openssl via `crypto/tls` replacement or
   direct FFI (validates: CGO + openssl linking)
5. Build a CGO binary linking zlib (validates: CGO + zlib linking)
6. Verify all Kubernetes Go binaries have correct RPATH / are statically linked
   as expected

**Test steps** (VM test):

7. Start containerd (validates: containerd + libseccomp + runc integration)
8. Start kubelet pointing at containerd (validates: kubelet + containerd CRI)
9. Verify kubelet health endpoint responds (validates: kubelet HTTP stack)
10. Run `kubectl version --client` (validates: kubectl binary)
11. Run `helm version` (validates: helm binary)
12. Run `crictl version` (validates: crictl + containerd CRI socket)

**Environment**: build-sandbox (steps 1-6), VM test with k8s-worker variant
(steps 7-12)

**Packages exercised**: go, gcc, glibc, openssl, zlib, libseccomp, containerd,
runc, kubelet, kubectl, kubeadm, helm, cni-plugins, crictl, nerdctl,
node-exporter

**Failure modes caught**:
- Go upgrade changes CGO calling convention
- libseccomp API change breaks containerd/runc seccomp filter loading
- Statically linked Go binary embeds wrong glibc NSS stubs
- Kubernetes component version skew from partial Go rebuild

---

### 1.4 Rust Application Stack (rust/llvm as hub)

**Goal**: Verify Rust compiler and LLVM produce correct binaries, including
FFI linkage against C libraries.

**Dependency chain exercised**:
```
rust-bootstrap --> rust (compiled from source)
 +-- llvm (backend)
 +-- gcc/glibc (linker, libc)
 +-- openssl (via openssl-sys FFI)
 +-- libgit2 (via libgit2-sys FFI)
 +-- zlib (transitive via libgit2, openssl)
```

**Test steps**:

1. Build a Rust "hello world" with `rustc` (validates: Rust compiler + LLVM
   backend)
2. Run the binary (validates: Rust runtime, dynamic linking)
3. Build a Rust program using `openssl-sys` crate pattern -- compile C FFI
   that calls `OpenSSL_version()` (validates: Rust FFI + openssl linkage)
4. Build a Rust program using `libgit2-sys` crate pattern -- compile C FFI
   that calls `git_libgit2_version()` (validates: Rust FFI + libgit2 linkage)
5. Verify the nix binary (which has Rust components) executes correctly
   (validates: real-world Rust + FFI integration)

**Environment**: build-sandbox

**Packages exercised**: rust, rust-bootstrap, llvm, gcc, glibc, openssl,
libgit2, zlib

**Failure modes caught**:
- LLVM upgrade changes code generation in ways that break Rust's assumptions
- Rust FFI bindings generate wrong ABI for updated C library
- `openssl-sys` build script finds wrong openssl headers
- Link-time optimization across Rust/C boundary produces incorrect code

---

### 1.5 Python Build System Chain (python3 as hub)

**Goal**: Verify python3 works as both a runtime and a build-time dependency for
critical packages that use Python-based build systems.

**Dependency chain exercised**:
```
python3
 +-- sqlite (python3 _sqlite3 module)
 +-- ncurses (python3 curses module)
 +-- readline (python3 readline module)
 +-- zlib (python3 zlib module)
 +-- meson --> systemd (PID 1)
 |         --> dbus (IPC)
 +-- llvm (uses python for tablegen, lit)
 +-- setools --> libselinux, libsepol (policy analysis)
 +-- audit (python bindings)
```

**Test steps**:

1. `python3 -c "import sys; print(sys.version)"` -- interpreter starts
   (validates: python3 core)
2. `python3 -c "import sqlite3; sqlite3.connect(':memory:').execute('SELECT 1')"` --
   sqlite module works (validates: python3 + sqlite linkage)
3. `python3 -c "import zlib; zlib.compress(b'test')"` -- zlib module works
   (validates: python3 + zlib linkage)
4. `python3 -c "import readline"` -- readline module loads
   (validates: python3 + readline + ncurses linkage)
5. `meson --version` -- meson runs under python3 (validates: meson + python3)
6. Use meson to configure a trivial project that uses pkg-config to find
   openssl (validates: meson + pkg-config + python3 integration)
7. Verify systemd was built by meson -- check `systemctl --version` output
   (validates: meson built systemd successfully)
8. Run `seinfo --version` (validates: setools + python3 + libselinux)

**Environment**: build-sandbox (steps 1-6, 8), VM test for step 7 (needs
running systemd)

**Packages exercised**: python3, sqlite, ncurses, readline, zlib, meson,
ninja, systemd, dbus, llvm, setools, audit

**Failure modes caught**:
- python3 upgrade breaks `_sqlite3` module ABI
- meson upgrade changes build file semantics, breaking systemd configuration
- python3 zlib module compiled against wrong zlib headers
- setools imports fail due to python3 minor version change

---

### 1.6 SELinux Security Stack (libsepol as root)

**Goal**: Verify the entire SELinux chain from policy compilation through
enforcement, including systemd integration.

**Dependency chain exercised**:
```
libsepol
 +-- libselinux --> pcre2 (regex for contexts)
 |    +-- libsemanage
 |    |    +-- policycoreutils (sestatus, semodule, restorecon, etc.)
 |    +-- setools --> python3, sqlite (policy analysis)
 |    +-- checkpolicy (policy compiler)
 |    |    +-- refpolicy (reference policy)
 |    +-- systemd (SELinux-aware init)
 |    +-- container-selinux (container policy modules)
 +-- semodule-utils (semodule_package, semodule_link, etc.)
```

**Test steps**:

1. Compile a minimal policy module from source using `checkpolicy`
   (validates: checkpolicy + libsepol)
2. Package it with `semodule_package` (validates: semodule-utils + libsepol)
3. Verify `sestatus` reports SELinux status (validates: policycoreutils +
   libselinux)
4. Load a policy module with `semodule -i` (validates: libsemanage + libsepol +
   libselinux)
5. Query the loaded policy with `sesearch` (validates: setools + libselinux +
   python3 + sqlite)
6. Verify systemd booted with SELinux awareness -- check that systemd set
   security contexts on units (validates: systemd + libselinux integration)
7. Verify `restorecon` can relabel a test file (validates: policycoreutils +
   libselinux + file context database)
8. Load container-selinux policy module (validates: container-selinux +
   libsemanage + libsepol)

**Environment**: VM test (needs systemd with SELinux enabled, policy loaded at
boot)

**Packages exercised**: libsepol, libselinux, libsemanage, policycoreutils,
setools, checkpolicy, semodule-utils, refpolicy, audit, systemd,
container-selinux, pcre2, python3, sqlite

**Failure modes caught**:
- libsepol internal format change breaks all downstream policy tools
- libselinux ABI change breaks systemd's SELinux initialization
- pcre2 upgrade changes regex behavior for file context matching
- python3 binding mismatch in setools after libselinux upgrade

---

### 1.7 Nix Package Manager Stack (nix as sink)

**Goal**: Verify the nix package manager -- the package with the most
dependencies in AOS -- functions correctly with all of its runtime
dependencies.

**Dependency chain exercised**:
```
nix
 +-- boost (C++ libraries: filesystem, algorithm, etc.)
 +-- sqlite (local store database)
 +-- curl --> openssl, zlib, libssh2, nghttp2
 +-- libgit2 --> openssl, zlib, libssh2
 +-- libarchive --> zlib, zstd, lz4
 +-- libsodium (NAR signing/verification)
 +-- editline (nix repl input)
 +-- lowdown (markdown rendering for docs)
 +-- openssl (direct dependency)
 +-- zlib (direct dependency)
```

**Test steps**:

1. `nix --version` -- binary starts (validates: dynamic linking of all 10+
   runtime deps)
2. `nix-store --init` -- store database initializes (validates: nix + sqlite)
3. `nix-instantiate --eval -E '1 + 1'` -- evaluator works (validates: nix
   core + boost)
4. `nix-build -E 'derivation { name = "test"; builder = "/bin/sh"; args = ["-c" "echo ok > $out"]; system = "x86_64-linux"; }'` --
   can build a trivial derivation (validates: nix daemon + store + builder
   integration)
5. Start nix-daemon, perform a store operation over the daemon socket
   (validates: nix daemon protocol + sqlite)
6. Download a NAR from a local nginx-served cache (validates: nix + curl +
   openssl + libarchive + zlib for decompression)
7. Verify NAR signature verification (validates: nix + libsodium)
8. `nix repl` sends a command and receives output (validates: nix + editline)

**Environment**: VM test (needs nix-daemon, nginx for cache serving)

**Packages exercised**: nix, boost, sqlite, curl, openssl, zlib, libssh2,
nghttp2, libgit2, libarchive, zstd, lz4, libsodium, editline, lowdown

**Failure modes caught**:
- boost upgrade changes `filesystem` API semantics
- sqlite schema change breaks nix store database
- libarchive cannot decompress NARs compressed with updated zstd
- libsodium signature format change breaks NAR verification
- curl HTTP/2 negotiation fails with updated nghttp2

---

### 1.8 Network/Firewall Stack

**Goal**: Verify networking packages interoperate correctly for firewall
management, connection tracking, and name resolution.

**Dependency chain exercised**:
```
libmnl
 +-- libnftnl --> nftables --> jansson (JSON output)
 +-- libnetfilter_conntrack --> conntrack-tools
 +-- iptables (legacy compat via nftables backend)
libnl
 +-- iproute2
libnfnetlink
 +-- libnetfilter_conntrack
 +-- libnetfilter_queue

systemd-networkd (interface management)
systemd-resolved (DNS resolution)
chrony (NTP time synchronization)
```

**Test steps**:

1. `ip link show` lists interfaces (validates: iproute2 + libnl)
2. Load nftables rules from a config file (validates: nftables + libnftnl +
   libmnl + jansson)
3. `nft list ruleset` shows the loaded rules (validates: nftables JSON/text
   output)
4. `iptables -L` reads rules via nftables backend (validates: iptables +
   nftables compat layer)
5. Generate traffic and verify `conntrack -L` shows tracked connections
   (validates: conntrack-tools + libnetfilter_conntrack + libmnl +
   libnfnetlink)
6. Verify systemd-networkd configured an interface (validates: systemd
   networking + iproute2 interop)
7. Verify systemd-resolved resolves a hostname (validates: systemd-resolved)
8. Verify chrony synchronized time (validates: chrony + libcap + network stack)

**Environment**: VM test (needs kernel networking, systemd services)

**Packages exercised**: iproute2, nftables, iptables, conntrack-tools,
chrony, systemd, libnl, libmnl, libnftnl, libnfnetlink, libnetfilter_conntrack,
libnetfilter_queue, jansson, libcap

**Failure modes caught**:
- libmnl netlink protocol change breaks nftables communication with kernel
- iptables-nft translation layer incompatible with new nftables version
- libnl upgrade changes attribute parsing for iproute2
- conntrack-tools linked against wrong libnetfilter_conntrack SONAME

---

### 1.9 Build Tooling Chain

**Goal**: Verify all build systems in AOS can discover and use AOS packages
correctly -- that `pkg-config`, `cmake --find-package`, and `meson`
dependency resolution all work with AOS store paths.

**Dependency chain exercised**:
```
m4 --> autoconf --> automake
pkg-config (dependency discovery)
cmake (CMake-based builds)
meson + ninja + python3 (Meson-based builds)
gcc + binutils (underlying compiler)
```

**Test steps**:

1. `m4` processes a macro file (validates: m4 works)
2. `autoconf` generates a `configure` script from `configure.ac` (validates:
   autoconf + m4)
3. `automake` generates `Makefile.in` from `Makefile.am` (validates: automake +
   autoconf)
4. `./configure` detects an AOS package (e.g., openssl) via `pkg-config`
   (validates: configure + pkg-config + AOS store paths)
5. `make` builds the project (validates: make + gcc + pkg-config flags)
6. A CMake project uses `find_package(OpenSSL)` to locate AOS openssl, builds,
   and links (validates: cmake + AOS package discovery)
7. A Meson project uses `dependency('openssl')` to locate AOS openssl, builds,
   and links (validates: meson + ninja + python3 + pkg-config)
8. Verify the resulting binaries from all three build systems have correct
   RPATH pointing to AOS store paths

**Environment**: build-sandbox

**Packages exercised**: m4, autoconf, automake, make, pkg-config, cmake,
meson, ninja, python3, gcc, binutils, openssl (as the dependency target)

**Failure modes caught**:
- autoconf upgrade generates configure scripts incompatible with AOS paths
- pkg-config cannot find `.pc` files in AOS store paths
- cmake `find_package` ignores `CMAKE_PREFIX_PATH` for AOS packages
- meson `dependency()` fails to use pkg-config in AOS environment
- RPATH not injected through cmake/meson build systems

---

### 1.10 Container/Kubernetes Full Stack

**Goal**: Verify the complete Kubernetes worker node stack from container
runtime through orchestration.

**Dependency chain exercised**:
```
containerd --> runc --> libseccomp
           --> cni-plugins
kubelet --> containerd (CRI)
kubeadm (cluster bootstrap)
kubectl (CLI)
helm (package management)
crictl (CRI debugging)
nerdctl (container CLI)
node-exporter (monitoring)
```

**Test steps**:

1. containerd starts and its health endpoint responds (validates: containerd +
   libseccomp + runc availability)
2. `runc --version` (validates: runc binary)
3. CNI plugins are present in expected path (validates: cni-plugins install)
4. kubelet starts with containerd as CRI runtime (validates: kubelet +
   containerd CRI protocol)
5. kubelet health endpoint (`/healthz`) responds (validates: kubelet HTTP
   server)
6. `kubectl version --client` (validates: kubectl binary)
7. `helm version` (validates: helm binary)
8. `crictl version` connects to containerd socket (validates: crictl +
   containerd CRI compatibility)
9. `nerdctl version` (validates: nerdctl binary)
10. node-exporter metrics endpoint responds (validates: node-exporter +
    HTTP serving)

**Environment**: VM test (k8s-worker variant)

**Packages exercised**: containerd, runc, cni-plugins, kubelet, kubectl,
kubeadm, helm, crictl, nerdctl, node-exporter, libseccomp

**Failure modes caught**:
- containerd CRI API version mismatch with kubelet
- runc OCI runtime spec version incompatible with containerd
- CNI plugin binary not found at expected path
- libseccomp filter syntax change breaks containerd seccomp profiles
- Go version skew across Kubernetes components causes protocol incompatibility

---

### 1.11 Compression Stack (zlib/zstd/lz4 interop)

**Goal**: Verify that data compressed by one tool or library can be decompressed
by another, and that all compression consumers link against consistent library
versions.

**Dependency chain exercised**:
```
zlib
 +-- gzip (CLI)
 +-- curl (HTTP content-encoding)
 +-- nginx (gzip response compression)
 +-- libarchive (tar.gz, .zip)
 +-- python3 (zlib, gzip modules)
 +-- nix (NAR compression)
 +-- openssl, libssh2, libgit2 (transitive)

zstd
 +-- libarchive (tar.zst)
 +-- systemd (journal compression)

lz4
 +-- libarchive (tar.lz4)
 +-- systemd (journal compression)
```

**Test steps** (build-sandbox):

1. Compress a test payload with `gzip`, decompress with a C program calling
   `inflate()` from zlib (validates: gzip CLI + zlib API produce compatible
   output)
2. Compress with the zlib C API (`deflate()`), decompress with `gzip -d`
   (validates: reverse direction)
3. Compress with `zstd` CLI, decompress with a C program calling
   `ZSTD_decompress()` (validates: zstd CLI + library interop)
4. Compress with `lz4` CLI, decompress with a C program calling
   `LZ4_decompress_safe()` (validates: lz4 CLI + library interop)
5. Create a `.tar.gz` archive with `tar`, extract with libarchive C API
   (validates: tar + zlib + libarchive interop)
6. Create a `.tar.zst` archive with `tar`, extract with libarchive C API
   (validates: tar + zstd + libarchive interop)
7. Python: `zlib.compress()` a payload, decompress with C `inflate()`
   (validates: python3 zlib module + system zlib are the same library)
8. Verify all compression libraries report matching header/runtime versions

**Test steps** (VM test):

9. nginx compresses a response with gzip, curl receives and decompresses it
   (validates: nginx zlib + curl zlib interop)
10. journalctl reads journal entries compressed with zstd and lz4 by journald
    (validates: systemd compression round-trip)

**Environment**: build-sandbox (steps 1-8), VM test (steps 9-10)

**Packages exercised**: zlib, zstd, lz4, libarchive, tar, python3, nginx,
curl, systemd, nix

**Failure modes caught**:
- zlib upgrade changes default compression level or window bits
- zstd frame format version incompatibility between CLI and library
- libarchive decompressor compiled against different zlib/zstd than compressor
- python3 zlib module links against system zlib SONAME that changed
- nginx and curl using different zlib versions (header/runtime mismatch)

---

## 2. ABI/API Regression Tests

These tests detect incompatibilities introduced by shared library upgrades.
They run as build-sandbox derivations (no VM required) and are designed to
be attached to any package rebuild.

### 2.1 Shared Object Version Tracking

For every `.so` file in the system image, record and diff against a baseline:

**What to record per shared object**:

| Field | Source | Purpose |
|-------|--------|---------|
| SONAME | `readelf -d \| grep SONAME` | Detect ABI version bumps |
| Exported symbol count | `nm -D --defined-only \| wc -l` | Detect removed symbols |
| Exported symbol list | `nm -D --defined-only` | Identify specific removals |
| Required shared libs | `readelf -d \| grep NEEDED` | Detect new transitive deps |

**Regression rules**:

- SONAME changed: **FAIL** -- all consumers must be rebuilt and retested
- Exported symbol removed: **FAIL** -- consumers may call removed symbols
- Exported symbol added: **PASS** -- backwards compatible
- New NEEDED entry: **WARN** -- may increase closure size

**Implementation**: A derivation that walks all `.so` files in the image closure,
runs `readelf` and `nm` on each, and diffs against a checked-in baseline file.
The baseline is updated explicitly when upgrades are intentional.

```
checks.integration.soname-tracking
  inputs: all .so files from the image closure
  outputs: diff report, pass/fail status
  baseline: tests/baselines/soname-baseline.json
```

### 2.2 Header/Runtime Version Consistency

For key libraries, verify that the header version (compiled against) matches
the runtime version (linked at execution). This catches the case where a
package was built against headers from version N but runs against `.so` from
version N+1.

**Libraries to check**:

| Library | Header version macro | Runtime version function |
|---------|---------------------|------------------------|
| openssl | `OPENSSL_VERSION_TEXT` | `OpenSSL_version(OPENSSL_VERSION)` |
| zlib | `ZLIB_VERSION` | `zlibVersion()` |
| zstd | `ZSTD_VERSION_STRING` | `ZSTD_versionString()` |
| lz4 | `LZ4_VERSION_STRING` | `LZ4_versionString()` |
| pcre2 | `PCRE2_MAJOR`, `PCRE2_MINOR` | `pcre2_config(PCRE2_CONFIG_VERSION, ...)` |
| sqlite | `SQLITE_VERSION` | `sqlite3_libversion()` |
| curl | `LIBCURL_VERSION` | `curl_version()` |
| libarchive | `ARCHIVE_VERSION_STRING` | `archive_version_string()` |
| libsodium | `SODIUM_VERSION_STRING` | `sodium_version_string()` |

**Test implementation**: For each library, compile and run a C program:

```c
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *header = OPENSSL_VERSION_TEXT;
    const char *runtime = OpenSSL_version(OPENSSL_VERSION);
    if (strcmp(header, runtime) != 0) {
        fprintf(stderr, "MISMATCH: header=%s runtime=%s\n", header, runtime);
        return 1;
    }
    printf("MATCH: %s\n", runtime);
    return 0;
}
```

A mismatch indicates that the binary was compiled against headers from one
version but is loading a `.so` from a different version. In a hermetic build
system this should never happen -- but it can occur if RPATH is misconfigured
or if a package caches compiled objects across version bumps.

**Environment**: build-sandbox (one derivation per library)

### 2.3 pkg-config Consistency

For every package that installs a `.pc` file, verify three properties:

1. **Version match**: `pkg-config --modversion <name>` returns the expected
   version string.

2. **Linkability**: `pkg-config --libs <name>` produces flags that
   successfully link a trivial program:
   ```sh
   echo 'int main(){}' > test.c
   gcc test.c $(pkg-config --libs openssl) -o test
   ```

3. **Header findability**: `pkg-config --cflags <name>` produces flags that
   find the library's headers:
   ```sh
   echo '#include <openssl/ssl.h>' > test.c
   echo 'int main(){}' >> test.c
   gcc test.c $(pkg-config --cflags openssl) -c -o test.o
   ```

**Packages with .pc files to verify** (non-exhaustive):

openssl, zlib, zstd, lz4, pcre2, libcap, libseccomp, libarchive, sqlite3,
libcurl, libssh2, libgit2, libsodium, libnl, libmnl, libnftnl, jansson,
oniguruma, editline, ncurses, readline, dbus, audit, libselinux, libsepol,
libsemanage, popt, libtirpc, libpcap

**Environment**: build-sandbox (one derivation that checks all `.pc` files)

**Failure modes caught**:
- `.pc` file has absolute path to wrong store path
- `Libs:` field references a library that was moved or renamed
- `Cflags:` field points to headers from a different version
- `Requires:` field names a package whose `.pc` file is missing

---

## 3. System-Level Integration Checks

These checks verify system-wide invariants that span all packages. They do not
test any single dependency chain but instead validate properties that emerge
from the composition of the entire package set into a bootable image.

### 3.1 Boot-to-Login

**Goal**: Verify the system boots to multi-user target with no failed units.

**Test steps** (VM test):

1. Boot the system image (validates: kernel + initramfs + systemd PID 1)
2. Wait for `multi-user.target` to be reached (validates: systemd dependency
   ordering across all enabled units)
3. Query `systemctl --failed` -- assert zero failed units (validates: every
   service's dependency chain is satisfied)
4. Verify `/etc/os-release` contains expected values (validates: toplevel
   assembly)
5. Verify `hostname` matches expected value (validates: hostname config
   propagation)

**Environment**: VM test (all system variants -- base, server, k8s-worker,
k8s-control-plane, seed)

**What it catches**: Any package whose service unit fails to start due to
missing dependencies, broken symlinks, or misconfigured paths. This is the
single most valuable cross-cutting test because it exercises every enabled
systemd unit in the image simultaneously.

### 3.2 Package Closure Integrity (RPATH validation)

**Goal**: Every ELF binary and shared library in the image has a valid RPATH
and no missing `.so` dependencies at runtime.

**Test steps** (build-sandbox):

1. Walk every ELF file in the image closure
2. For each file, run `readelf -d` to extract RPATH and NEEDED entries
3. For each NEEDED entry, verify the `.so` exists at one of the RPATH paths
   or in the standard search paths
4. Fail if any NEEDED `.so` cannot be resolved

**Implementation**: A derivation that takes the image closure as input and
runs validation on every ELF file. This is equivalent to running `ldd` on
every binary but without requiring a running system.

```
checks.integration.rpath
  inputs: all ELF files from system closure
  outputs: list of missing .so dependencies (empty = pass)
```

**What it catches**: Missing `runtimeDeps` declarations, broken ccWrapper
RPATH injection, libraries that installed to `lib64/` instead of `lib/`.

### 3.3 Configuration Validity

**Goal**: All configuration files in `/etc` are syntactically valid before
the image boots.

**Test steps** (build-sandbox or VM test):

| Config file | Validation command | Package |
|-------------|-------------------|---------|
| `/etc/ssh/sshd_config` | `sshd -t -f <config>` | openssh |
| `/etc/nginx/nginx.conf` | `nginx -t -c <config>` | nginx |
| nftables ruleset | `nft -c -f <rules>` | nftables |
| systemd units | `systemd-analyze verify <unit>` | systemd |
| `/etc/chrony/chrony.conf` | `chronyd -p <config>` | chrony |

For build-sandbox tests, the validation commands run against the config files
extracted from the toplevel derivation's `/etc` directory. For VM tests, the
commands run inside the guest after boot.

**What it catches**: Module-generated config files with syntax errors,
missing paths in config files (e.g., referencing a binary that was moved),
incompatible config directives after a package upgrade.

### 3.4 Filesystem Layout

**Goal**: The assembled system image has the expected directory structure,
permissions, and symlinks.

**Test steps** (VM test):

1. Verify required directories exist: `/nix/store`, `/etc`, `/run`, `/var`,
   `/tmp`, `/proc`, `/sys`, `/dev`
2. Verify `/sbin/init` is a symlink to systemd
3. Verify `/bin/sh` is a symlink to bash
4. Verify `/run/current-system` points to the toplevel derivation
5. Verify `/lib/systemd` symlinks resolve to the systemd package in
   `/nix/store`
6. Verify all symlinks in `/usr/bin` and `/usr/sbin` resolve to valid targets
   (no dangling symlinks)
7. Verify `/etc/passwd`, `/etc/group`, `/etc/shadow` exist with correct
   permissions (shadow must be 640)
8. Verify no world-writable files outside `/tmp` and `/var/tmp`

**What it catches**: Broken toplevel assembly, missing symlinks from system
packages, incorrect permissions from module configuration, dangling symlinks
from removed packages.

---

## 4. Upgrade Impact Matrix

When a package is upgraded, the following matrix specifies the **minimum set
of tests** that must pass before the upgrade is accepted. This is the
authoritative reference for CI test selection on package-change PRs.

### 4.1 Matrix: Package to Required Test Suites

| Package Upgraded | Required Test Suites |
|-----------------|---------------------|
| **openssl** | TLS stack scenario (1.1); all library link tests for openssl consumers (curl, nginx, openssh, systemd, nix, rsync, libssh2, libgit2); header/runtime version consistency (2.2); pkg-config consistency (2.3); SONAME tracking (2.1) |
| **zlib** | TLS stack scenario (1.1) (exercises zlib transitively); all zlib consumer link tests; header/runtime version consistency; nix NAR decompression (1.7 step 6); python3 zlib module (1.5 step 3); SONAME tracking |
| **gcc** | C compilation pipeline (1.2); ALL compile+link tests (everything rebuilds); Go CGO tests (1.3 steps 3-5); Rust FFI tests (1.4 steps 3-4); SONAME tracking for all `.so` files |
| **go** | Go application stack (1.3); all Go-built binary version checks (containerd, kubelet, kubectl, helm, crictl, nerdctl, node-exporter, cni-plugins, kubeadm); container/k8s full stack (1.10) |
| **python3** | Python build chain (1.5); meson builds systemd successfully; setools runs; nix build (if Python-dependent steps exist); header/runtime version consistency for python3 extension modules |
| **systemd** | VM boot-to-login; all systemd service tests (systemd-basics, chrony, ssh, firewall, containerd, kubelet); SELinux integration; journald; networkd; resolved; tmpfiles |
| **linux** | Full VM boot; all VM tests; all fleet tests |
| **rust** | Rust application stack (1.4); nix rebuild and smoke test (1.7) |
| **llvm** | LLVM compile tests; Rust application stack (1.4, since Rust uses LLVM) |
| **curl** | TLS stack scenario (1.1) (curl-specific steps); nix download test (1.7 step 6); header/runtime version consistency; pkg-config consistency |
| **nginx** | TLS stack scenario (1.1) (nginx-specific steps); nix cache serving (1.7 step 6); nginx service startup; HTTPS serving with real certificate |
| **containerd** | Container/k8s full stack (1.10); Go application stack (1.3 steps 7-12) |
| **kubelet** | Container/k8s full stack (1.10) |
| **libselinux** | SELinux stack (1.6); systemd rebuild + VM boot; pkg-config consistency |
| **libsepol** | SELinux stack (1.6); all downstream rebuilds (libselinux, checkpolicy, semodule-utils) |
| **sqlite** | nix store operations (1.7 steps 2-5); python3 sqlite module (1.5 step 2); header/runtime version consistency |
| **boost** | nix rebuild and smoke test (1.7) |
| **libarchive** | nix NAR handling (1.7 step 6); compression format tests (zstd, lz4, zlib via libarchive) |
| **libmnl** | Network/firewall stack (1.8); all netfilter library rebuilds; nftables + iptables rule tests |
| **pcre2** | nginx regex tests; libselinux file context matching; pkg-config consistency |
| **ncurses** | readline rebuild; bash interactive test; python3 curses module |
| **meson** | Python build chain (1.5 steps 5-7); systemd rebuild + VM boot |
| **cmake** | Build tooling chain (1.9 step 6); all cmake-built package rebuilds (llvm, curl, libarchive, libgit2, libssh2, nghttp2) |
| **libseccomp** | containerd seccomp filter test; runc seccomp test; container stack (1.10) |
| **libgit2** | nix git operations; Rust FFI test (1.4 step 4); pkg-config consistency |
| **zstd** | Compression stack (1.11); libarchive tests; systemd journal compression; header/runtime version consistency; SONAME tracking |
| **lz4** | Compression stack (1.11); libarchive tests; systemd journal compression; header/runtime version consistency; SONAME tracking |
| **libssh2** | curl SSH protocol tests; libgit2 SSH transport; pkg-config consistency |

### 4.2 Deriving Tests from the Dependency Graph

The matrix above is derived from two rules:

1. **Direct consumer rule**: For every direct runtime dependent of the upgraded
   package, run that dependent's integration tests.

2. **Transitive critical path rule**: If the upgraded package is on a critical
   chain (see dependency-graph.md Section 3), run the full scenario test for
   that chain.

When a package not listed above is upgraded, apply these rules against the
dependency graph data in `dependency-graph.md` Section 2 to determine the
required tests.

---

## 5. Test Priority Tiers

Tests are classified into priority tiers that determine when they run and
whether they block releases.

### P0 -- Blocks Release

Must pass for any image to ship. Failure at P0 means the system cannot boot
or is fundamentally broken.

| Test | What it validates |
|------|-------------------|
| Boot-to-login | Kernel + systemd + glibc + bash: the system reaches a login prompt |
| No failed systemd units | Every enabled unit reaches `active` or `inactive` (no `failed`) |
| Binary RPATH validity | Every ELF binary in the image has valid RPATH (no missing `.so` at runtime) |
| Critical package builds | linux, systemd, glibc, gcc, bash, coreutils all build without error |
| C compilation pipeline (1.2) | The fundamental toolchain works: compile, link, run |

### P1 -- Blocks Deployment

Must pass before any production image is deployed. P1 failures indicate that
a core system function is broken.

| Test | What it validates |
|------|-------------------|
| TLS stack scenario (1.1) | All TLS consumers work with the same openssl |
| All library compile+link tests (2.2, 2.3) | No ABI/API breaks in shared libraries |
| All service startup tests | nginx, containerd, kubelet, sshd, chronyd, nix-daemon start |
| All CLI tool smoke tests | curl, jq, tar, rsync, openssh, nftables, etc. run and produce output |
| C/Go/Rust compilation pipelines (1.2, 1.3, 1.4) | All language toolchains produce working binaries |
| SELinux policy load (1.6 steps 1-3) | Basic SELinux functionality works |
| Nix package manager (1.7 steps 1-5) | nix can evaluate, build, and manage the store |

### P2 -- Should Pass

Important for system quality. Failures should be investigated and fixed
promptly but do not block a release if the failure is understood and
contained.

| Test | What it validates |
|------|-------------------|
| Full cross-cutting scenarios (1.1-1.10) | Deep multi-package integration |
| SONAME tracking (2.1) | No unexpected ABI version changes |
| Header/runtime version consistency (2.2) | No linkage mismatches |
| pkg-config consistency (2.3) | Build system integration works |
| Build tooling chain (1.9) | autoconf/cmake/meson all work with AOS packages |
| Network/firewall stack (1.8) | Firewall and networking tools interoperate |
| Full SELinux stack (1.6) | Policy compilation, module management, enforcement |

### P3 -- Informational

Nice to have. Provides early warning signals and tracks system health trends
over time.

| Test | What it tracks |
|------|----------------|
| Exported symbol counts per `.so` | API surface stability |
| Closure size trends | Dependency bloat |
| Build time benchmarks | Build system performance |
| SONAME baseline updates | Intentional ABI version progression |

---

## 6. CI/CD Integration

### 6.1 Pipeline Stages

Tests integrate into the CI pipeline at four stages, each gating the next:

```
PR opened
  |
  v
Stage 1: Eval (seconds)
  - nix-build -A checks.eval
  - All module graphs resolve
  - Gate: any eval failure blocks merge
  |
  v
Stage 2: Build (minutes)
  - nix-build -A checks.build
  - Critical packages compile
  - Closure sizes within bounds
  - Gate: any build failure blocks merge
  |
  v
Stage 2.5: Integration (minutes)
  - Determine changed packages from PR diff
  - Consult upgrade impact matrix (Section 3) to select tests
  - Run: SONAME tracking, header/runtime checks, pkg-config checks
  - Run: scenario tests for affected dependency chains
  - Gate: any P0/P1 test failure blocks merge
  |
  v
Stage 3: VM tests (10-30 minutes, post-merge on main)
  - Boot all system variants
  - Run VM-requiring scenarios (TLS stack, SELinux, k8s, nix-daemon)
  - Gate: P0/P1 failures trigger revert consideration
  |
  v
Stage 4: Fleet tests (30-60 minutes, post-merge on main)
  - Multi-VM cluster formation
  - Rolling update verification
  - Gate: P0/P1 failures block release
```

### 6.2 Changed-Package Detection

Stage 2.5 must determine which packages changed in a PR to select the right
tests. The detection algorithm:

1. Parse `git diff` for modified files under `pkgs/`.
2. Map each modified file to its package name.
3. Look up the package in the upgrade impact matrix (Section 3.1).
4. Union all required test suites for all changed packages.
5. Add the SONAME tracking test if any package with `.so` outputs changed.
6. Add the pkg-config consistency test if any package with `.pc` files changed.

For changes outside `pkgs/` (e.g., `modules/`, `systems/`, `lib/`), run
the full P0 + P1 test suite as a conservative default.

### 6.3 Test Selection Example

A PR upgrades openssl from 3.3.2 to 3.4.0:

```
Changed files: pkgs/tls/openssl.nix
Package: openssl
Matrix lookup (Section 3.1):
  - TLS stack scenario (1.1)
  - Library link tests: curl, nginx, openssh, systemd, nix, rsync, libssh2, libgit2
  - Header/runtime version consistency (2.2) for openssl
  - pkg-config consistency (2.3) for openssl
  - SONAME tracking (2.1)

Stage 2.5 runs these tests.
Stage 3 (post-merge) runs the full TLS stack VM scenario.
```

A PR upgrades both zlib and openssl:

```
Changed files: pkgs/tls/openssl.nix, pkgs/compression/zlib.nix
Packages: openssl, zlib
Matrix lookup: union of openssl tests and zlib tests
  - TLS stack scenario (full, since both are involved)
  - All consumer link tests for both packages
  - Header/runtime version consistency for both
  - pkg-config consistency for both
  - SONAME tracking
  - nix NAR decompression test
  - python3 zlib module test
```

### 6.4 Release Gate

A release candidate must pass:

- All P0 tests (mandatory, no exceptions)
- All P1 tests (mandatory, no exceptions)
- All P2 tests (advisory; failures require written justification to ship)
- P3 tests are informational and do not gate releases

The release gate is a single derivation that depends on all P0 and P1 test
derivations:

```
checks.release-gate
  buildDeps = [
    checks.vm.boot          # P0: boot-to-login
    checks.build             # P0: critical packages build
    checks.integration.rpath # P0: binary RPATH validity
    checks.integration.tls   # P1: TLS stack
    checks.integration.abi   # P1: ABI consistency
    ...
  ];
```

---

## 7. Scenario Summary

| # | Scenario | Hub Package | Environment | Key Failure Class |
|---|----------|-------------|-------------|-------------------|
| 1.1 | TLS Stack | openssl | VM | TLS interop, certificate handling |
| 1.2 | C Compilation Pipeline | gcc/binutils | build-sandbox | Toolchain coherence, RPATH |
| 1.3 | Go Application Stack | go | both | CGO linking, k8s component compat |
| 1.4 | Rust Application Stack | rust/llvm | build-sandbox | FFI linking, LLVM codegen |
| 1.5 | Python Build System | python3 | both | Extension modules, meson compat |
| 1.6 | SELinux Security Stack | libsepol | VM | Policy chain, systemd integration |
| 1.7 | Nix Package Manager | nix | VM | Multi-dep linking, store operations |
| 1.8 | Network/Firewall Stack | libmnl | VM | Netlink protocol, rule compat |
| 1.9 | Build Tooling Chain | pkg-config | build-sandbox | Package discovery, RPATH |
| 1.10 | Container/Kubernetes | containerd | VM | CRI protocol, seccomp, k8s |
| 1.11 | Compression Stack | zlib/zstd/lz4 | both | Format interop, round-trip |

Total packages covered across all scenarios: ~65 of ~162 (the high-fanout
and high-risk packages). Remaining packages are leaf nodes tested by their
individual tool/service checks.

---

## 8. Implementation Notes

This section describes how cross-cutting checks map to the existing AOS test
framework defined in `lib/testing/`.

### 8.1 Framework Primitives

The AOS test infrastructure provides these primitives (from `lib/testing/`):

| Primitive | Defined in | Purpose |
|-----------|-----------|---------|
| `mkDerivation` | `pkgs/default.nix` | Build-sandbox tests: compile, link, run programs |
| `mkVMTest` | `lib/testing/vm.nix` | VM tests: boot QEMU, run checks via guest agent |
| `mkCheck` | `lib/testing/checks.nix` | Single named check (shell script fragment) |
| `mkCheckGroup` | `lib/testing/checks.nix` | Group checks under a common prefix |
| `composeChecks` | `lib/testing/checks.nix` | Flatten + wrap checks with banners |
| `validateChecks` | `lib/testing/checks.nix` | Pre-flight syntax validation (no QEMU) |
| `mkFleetTest` | `lib/testing/fleet.nix` | Multi-VM orchestration tests |

### 8.2 Build-Sandbox Scenarios as Derivations

Scenarios that run in the build sandbox (1.2, 1.4, 1.9, 1.11 steps 1-8, and
all of Section 2) are implemented as `mkDerivation` derivations. Each
derivation takes the relevant packages as `buildDeps`, compiles and runs
test programs in its `phases`, and writes `PASS` to `$out/result` on success.

Example structure for a header/runtime version consistency check (2.2):

```nix
# tests/integration/version-consistency.nix
{ pkgs }:
pkgs.mkDerivation {
  pname = "check-version-consistency-openssl";
  version = "0";
  src = null;

  buildDeps = [ pkgs.openssl ];

  phases = [
    {
      name = "check";
      script = ''
        cat > test.c << 'EOF'
        #include <openssl/opensslv.h>
        #include <openssl/crypto.h>
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            const char *h = OPENSSL_VERSION_TEXT;
            const char *r = OpenSSL_version(OPENSSL_VERSION);
            if (strcmp(h, r) != 0) {
                fprintf(stderr, "MISMATCH: header=%s runtime=%s\n", h, r);
                return 1;
            }
            printf("MATCH: %s\n", r);
            return 0;
        }
        EOF
        gcc test.c -lssl -lcrypto -o test
        ./test
        echo "PASS: openssl header/runtime version match"
        mkdir -p $out
        echo "PASS" > $out/result
      '';
    }
  ];
}
```

The RPATH validation check (3.2) follows the same pattern but walks all
ELF files in the image closure:

```nix
# tests/integration/rpath-check.nix
{ pkgs, system }:
pkgs.mkDerivation {
  pname = "check-rpath-validity";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.binutils  # readelf
    system.config.system.build.toplevel
  ];

  phases = [
    {
      name = "check";
      script = ''
        FAIL=0
        # Walk all ELF files in the toplevel closure
        find ${builtins.toString system.config.system.build.toplevel} \
          -type f \( -name '*.so*' -o -executable \) | while read -r f; do
          # Check if it is an ELF file
          if readelf -h "$f" > /dev/null 2>&1; then
            # Extract NEEDED entries and RPATH
            NEEDED=$(readelf -d "$f" 2>/dev/null | grep NEEDED | \
                     sed 's/.*\[\(.*\)\]/\1/')
            RPATH=$(readelf -d "$f" 2>/dev/null | grep RPATH | \
                    sed 's/.*\[\(.*\)\]/\1/' | tr ':' '\n')
            for lib in $NEEDED; do
              FOUND=0
              for dir in $RPATH; do
                if [ -f "$dir/$lib" ]; then
                  FOUND=1
                  break
                fi
              done
              if [ "$FOUND" -eq 0 ]; then
                echo "MISSING: $f needs $lib (RPATH: $RPATH)"
                FAIL=1
              fi
            done
          fi
        done
        if [ "$FAIL" -eq 1 ]; then
          echo "FAIL: some libraries could not be resolved"
          exit 1
        fi
        echo "PASS: all RPATH dependencies resolved"
        mkdir -p $out
        echo "PASS" > $out/result
      '';
    }
  ];
}
```

### 8.3 VM Scenarios as mkCheck/mkCheckGroup

VM-based cross-cutting scenarios (1.1, 1.3 steps 7-12, 1.6, 1.7, 1.8, 1.10,
1.11 steps 9-10, 3.1, 3.4) are implemented using the `mkCheck`/`mkCheckGroup`
system. Check scripts run on the **host** and communicate with the guest via
`run_in_guest`, `assert_success`, and `assert_output_contains` helpers from
`lib/testing/assertions.nix`.

Example structure for the TLS stack scenario (1.1) as a check group:

```nix
# tests/vm/checks/tls-stack.nix
{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "tls-stack";
  description = "TLS stack cross-cutting integration";
  checks = [
    (mkCheck {
      name = "nginx-https-serves";
      description = "nginx serves HTTPS with self-signed cert";
      script = ''
        assert_success "curl -sk https://localhost/" \
          "curl can fetch HTTPS from nginx"
      '';
    })
    (mkCheck {
      name = "curl-http2";
      description = "curl negotiates HTTP/2 with nginx";
      script = ''
        assert_output_contains "curl -sk --http2 -o /dev/null -w '%{http_version}' https://localhost/" \
          "2" \
          "curl negotiates HTTP/2"
      '';
    })
    (mkCheck {
      name = "ssh-key-exchange";
      description = "openssh key exchange succeeds";
      script = ''
        assert_success "ssh -o StrictHostKeyChecking=no -o BatchMode=yes localhost true" \
          "SSH key-based authentication works"
      '';
    })
    (mkCheck {
      name = "openssl-version-consistent";
      description = "All TLS consumers report same openssl version";
      script = ''
        assert_success "openssl version" \
          "openssl CLI reports version"
        # Verify curl links the same openssl
        assert_output_contains "curl --version" "OpenSSL" \
          "curl reports OpenSSL in version string"
      '';
    })
  ];
}
```

These check groups are composed into VM tests via `mkVMTest`:

```nix
# tests/vm/cross-cutting.nix (hypothetical)
{ pkgs, lib, systems, testTools }:
let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };
  mkC = { inherit (harness) mkCheck mkCheckGroup; };
in
harness.mkVMTest {
  name = "cross-cutting";
  system = systems.seed;  # has nginx + nix-daemon + sshd
  checks = [
    (import ./checks/tls-stack.nix mkC)
    (import ./checks/nix-stack.nix mkC)
    (import ./checks/compression-vm.nix mkC)
  ];
}
```

### 8.4 Integration into checks Attribute Set

Cross-cutting checks are exposed under `checks.integration` alongside the
existing `checks.eval`, `checks.build`, `checks.vm`, and `checks.fleet`:

```nix
# tests/default.nix additions (planned)
{
  # Existing:
  eval = ...;
  build = ...;
  vm = ...;
  fleet = ...;

  # New:
  integration = {
    # Build-sandbox checks (Section 2, 3.2)
    version-consistency = import ./integration/version-consistency.nix { inherit pkgs; };
    pkg-config = import ./integration/pkg-config.nix { inherit pkgs; };
    soname-tracking = import ./integration/soname-tracking.nix { inherit pkgs; };
    rpath = import ./integration/rpath-check.nix { inherit pkgs; system = systems.base; };
    c-pipeline = import ./integration/c-pipeline.nix { inherit pkgs; };
    compression = import ./integration/compression.nix { inherit pkgs; };
    build-tooling = import ./integration/build-tooling.nix { inherit pkgs; };

    # VM-based cross-cutting checks (Section 1 VM scenarios)
    tls-stack = import ./vm/cross-cutting-tls.nix { ... };
    selinux-stack = import ./vm/cross-cutting-selinux.nix { ... };
    nix-stack = import ./vm/cross-cutting-nix.nix { ... };
    network-stack = import ./vm/cross-cutting-network.nix { ... };
    k8s-stack = import ./vm/cross-cutting-k8s.nix { ... };
  };
}
```

### 8.5 Baseline Management

The SONAME tracking test (2.1) requires a baseline file checked into the
repository. The workflow:

1. Run `nix-build -A checks.integration.soname-tracking` to generate the
   current baseline.
2. Review the diff: new symbols are expected, removed symbols require
   investigation.
3. Update `tests/baselines/soname-baseline.json` and commit.

The baseline file is a JSON object mapping each `.so` path (relative to the
store) to its SONAME and exported symbol list. The test derivation compares
the current state against this baseline and fails on regressions.

### 8.6 Guest Agent Constraints

VM-based cross-cutting checks must respect the guest agent environment
(documented in `lib/testing/vm.nix`):

- The guest has: bash, coreutils, systemd tools (systemctl, journalctl)
- The guest does **not** have: grep, sed, ip, sysctl, mount, lsmod
- Use file-based checks (`test -f`, `cat /proc/...`) instead of text
  processing tools
- `assert_output_contains` runs `grep` on the **host**, not the guest
- JSON escaping in the agent uses bash `${s//pattern/replacement}` builtins
- Commands sent via `run_in_guest` execute with `eval` and redirect stdout
  to a file

For cross-cutting checks that need tools like `curl`, `nginx`, `nft`, or
`nix` in the guest, those packages must be included in the system variant's
`environment.systemPackages`. The seed variant already includes nginx and
nix; the k8s-worker variant includes Kubernetes components; the server
variant includes networking tools.
