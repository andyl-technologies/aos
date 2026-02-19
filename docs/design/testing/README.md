# AOS Integration Testing Strategy

AOS builds ~130 packages from source in a single repository. Every shared library,
CLI tool, and system service is compiled against the same toolchain and linked against
the same dependency tree. This monorepo structure creates an opportunity that
traditional distributions miss: verifying cross-package compatibility at build time
rather than discovering it in production.

This document describes the testing philosophy and architecture for comprehensive
package integration testing in AOS.

## Problem statement

### The compatibility gap in Linux distributions

Traditional distributions (Debian, Fedora) package software independently. Each
package maintainer tests their own build and publishes it to a shared repository.
Cross-package compatibility is verified implicitly: if curl and openssl both build
against the same distro's headers and libraries, they are assumed to work together.
When they don't -- ABI changes, symbol version mismatches, behavioral regressions --
users discover it in production.

NixOS improves on this with reproducible builds and pinned dependency graphs, but
the testing model is the same: packages are tested in isolation by their maintainers.
The `nixpkgs` CI runs `nix-build` on individual packages. If openssl 3.4 introduces
a deprecation that breaks curl's TLS handshake at runtime but not at compile time,
nothing catches it until a user reports the failure.

### The cost of late discovery

An ABI incompatibility found in production means:

- **Downtime** while the broken package is rolled back or patched
- **Debugging time** to identify which of dozens of recent upgrades caused the regression
- **Blast radius** across every service that depends on the broken library
- **Erosion of trust** in the upgrade process, leading teams to defer upgrades and
  accumulate security debt

For a distribution that builds everything from source, the information to catch these
failures early already exists in the build graph. The missing piece is systematic
testing of the dependency edges.

### What AOS can do differently

AOS controls the entire package set. When openssl is upgraded, the build system
already rebuilds every package that depends on it. The question is whether those
rebuilt packages actually work. Adding integration checks to this rebuild pipeline
turns the monorepo from a build system into a verification system: every version
change is validated against all its consumers before it reaches any machine.

## Testing philosophy

### Test the edges, not just the nodes

A package that builds successfully is a necessary but insufficient condition. The
interesting failures happen at dependency boundaries:

- A library compiles but changed its symbol versions (ABI break)
- A library compiles but changed default behavior (API semantic break)
- Two libraries both build but are incompatible when linked into the same binary
- A CLI tool builds but fails when invoked with real data from its dependencies

AOS integration tests focus on these edges. For every dependency relationship
`A -> B`, there should be a test that exercises A's use of B. Each test runs
in its own Firecracker microVM to validate against the actual AOS kernel.

### Monorepo advantage

Because AOS builds every package in a single Nix evaluation:

1. **Dependency graph is known statically.** Nix evaluation produces the complete
   DAG. We know exactly which packages consume openssl, which link against zlib,
   which use the Go toolchain.

2. **Reverse dependencies rebuild automatically.** Upgrading a leaf library triggers
   rebuilds of everything above it. Integration tests attached to those rebuilds
   run automatically.

3. **Test closures share the build cache.** Integration test derivations that depend
   on `pkgs.curl` and `pkgs.openssl` reuse the same store paths. No redundant builds.

4. **Failures are attributable.** When a test fails, the Nix dependency graph tells
   you exactly which version change caused it. There is no ambiguity about which
   combination of upgrades produced the regression.

### Everything runs against the real kernel

A subtle but critical decision: all tests -- even simple compile+link checks --
run inside Firecracker microVMs booting the AOS kernel. This means every test
validates the complete stack: the AOS kernel, glibc, dynamic linker,
`/proc`/`/sys` layout, and syscall behavior. A library that works on the
builder's host kernel but fails on the AOS kernel will be caught. This
eliminates an entire class of "works on the builder, fails on the target" bugs.

To achieve sub-minute execution despite running everything in VMs, each
integration test spawns its own Firecracker microVM (~150ms boot) and the host
Nix daemon schedules them in parallel via `--max-jobs`. No manual sharding, no
guest Nix daemon -- each microVM boots, runs one test, and exits. Nix's
content-addressed caching means unchanged tests never spawn a VM at all.

## Test layer architecture

AOS organizes tests into four layers, ordered by cost and scope. A critical design
decision: **all tests run inside Firecracker microVMs booting the actual AOS
kernel**. This ensures every test validates against the real kernel, dynamic
linker, and userspace that ships in the OS image -- not the builder's host kernel.

```
Layer 1: Eval          ~0s    Pure Nix evaluation. Module graphs resolve.
Layer 2: Build        ~min    Packages compile. Closure sizes bounded.
Layer 3: VM          <90s     All integration + system tests in per-test microVMs.
Layer 4: Fleet        ~min    Multi-VM orchestration: k8s cluster, rolling update.
```

**Performance target:** All tests (Layers 1-3) complete in under 90 seconds
per-commit. Integration tests alone complete in ~10-15 seconds.

### Why all tests run in VMs

Build-sandbox tests (running on the builder host) validate against the builder's
kernel, not the AOS kernel. This misses an entire class of failures:

- Kernel syscall behavior differences between builder and target
- Kernel module availability (netfilter, overlay, cgroup v2)
- `/proc` and `/sys` layout differences
- Signal handling, seccomp filter, and capability semantics
- Dynamic linker behavior under the actual kernel + glibc combination

By running every test -- including compile-and-link checks, CLI smoke tests, and
library ABI verification -- inside Firecracker microVMs booting the AOS kernel,
we validate the complete stack from kernel through userspace.

### Why Firecracker instead of QEMU

QEMU provides a full-featured hardware emulator: PCI bus, ACPI tables, BIOS/UEFI,
dozens of device models. AOS tests need none of this. What they need is fast boot,
minimal overhead, and the ability to run hundreds of concurrent VMs.

Firecracker is a purpose-built microVM monitor (VMM) created by AWS for Lambda
and Fargate. It provides exactly what AOS tests need:

| Aspect | QEMU | Firecracker |
|--------|------|-------------|
| Boot to userspace | ~1-2s | ~125ms |
| Device model | Full (q35, PCI, ACPI) | Minimal (virtio-blk, virtio-net, vsock) |
| Memory overhead per VM | ~50-100MB | ~5-10MB |
| Guest communication | virtio-serial | vsock |
| Concurrent VMs (32GB RAM) | ~50-100 | ~500+ |
| Binary size | ~50MB | ~5MB |
| Security model | Process isolation | jailer + seccomp + cgroup isolation |

The ~125ms boot time is the key enabler: it makes per-test VMs practical. Instead
of amortizing boot cost across a shard of tests, each test gets its own isolated
microVM. This eliminates shard load-balancing entirely and lets the host Nix
daemon's `--max-jobs` handle all scheduling.

### Per-test microVM architecture

Each integration test (compile+link, tool smoke test) is a Nix derivation whose
build phase launches a Firecracker microVM. The VM boots the AOS kernel, runs the
test as its init process, and exits. No systemd. No guest Nix daemon. No agent
protocol. The init script IS the test.

```
nix-build -A checks.integration.all
              |
   Nix daemon evaluates ~200 derivations
   Schedules builds via --max-jobs=N
              |
   +------+------+------+------+---...   (N concurrent)
   |      |      |      |      |
  FC VM  FC VM  FC VM  FC VM  FC VM
  150ms  150ms  150ms  150ms  150ms
  boot   boot   boot   boot   boot
   |      |      |      |      |
  test   test   test   test   test
  ~1s    ~0.5s  ~2s    ~0.2s  ~0.5s
   |      |      |      |      |
  exit   exit   exit   exit   exit
```

Nix's content-addressed store means unchanged tests never build at all -- the
output already exists. On a typical commit touching one package, only ~10-20
tests actually spawn VMs. The rest are instant cache hits.

System tests (service startup, security hardening, boot verification) still
boot a full system variant with systemd, but use Firecracker instead of QEMU.
These communicate with the host over vsock instead of virtio-serial. There is
one system test VM per system variant (base, server, k8s-worker,
k8s-control-plane, seed), running in parallel.

### Layer 1: Eval

Pure Nix evaluation with no builds and no VMs. The `checks.eval` derivation forces
`builtins.toJSON` on every system variant's configuration, which evaluates the
entire module graph. Any module type error, missing option, or infinite recursion
causes an instantiation failure.

**What it catches:** Module definition errors, option type mismatches, circular
imports, missing required options.

**Cost:** Instantaneous. Runs in the Nix evaluator with no builder invocation.

**Entry point:** `nix-build -A checks.eval`

### Layer 2: Build

Verifies that critical packages compile and that closure sizes stay within bounds.
The `checks.build` derivation lists critical packages (linux, systemd, containerd,
kubelet, coreutils, bash, openssl) as build dependencies and runs `nix-store --query
--size` to enforce closure size limits.

**What it catches:** Compilation failures, linker errors, missing headers, closure
bloat from accidental dependency inclusion.

**Cost:** Minutes. Bounded by the slowest critical package build (typically the
kernel or Go packages). Cached builds make subsequent runs fast.

**Entry point:** `nix-build -A checks.build`

### Layer 3: VM (Integration + System Tests)

All package integration and system tests run inside Firecracker microVMs booting
the AOS kernel with direct kernel boot.

**Integration tests (per-test microVMs):**

Each integration test is a standalone Nix derivation that spawns its own
Firecracker microVM. The test script runs as PID 1 (no systemd). The host Nix
daemon schedules up to `--max-jobs` VMs concurrently.

| Category | Tests | Boot overhead | Per-test time |
|----------|-------|---------------|---------------|
| Toolchain (gcc, g++, Go, Rust) | ~50 | 150ms | 1-3s |
| Library ABI (compile+link+run) | ~80 | 150ms | 0.5-2s |
| CLI tool smoke tests | ~40 | 150ms | 0.2-1s |
| Cross-cutting scenarios | ~10 | 150ms | 1-5s |

**System tests (per-variant VMs with systemd):**

System tests boot a full system variant with systemd and run checks via the
vsock guest agent. One VM per system variant, all in parallel.

| System Variant | What it tests |
|---------------|---------------|
| base | Boot fundamentals, filesystem, kernel |
| server | Hardening, SELinux, audit, firewall, SSH, chrony, nginx |
| k8s-worker | containerd, kubelet, CNI, networking |
| k8s-control-plane | etcd, kube-apiserver, kubeadm |
| seed | nginx cache server, nix-daemon, build orchestration |

**What it catches:** ABI breaks, API changes, kernel-userspace incompatibilities,
service failures, security policy enforcement, cross-package runtime issues.

**Cost:** Under 90 seconds total. Integration tests complete in ~10-15s (200
tests at ~1s each, 32 concurrent). System tests complete in ~60s (5 variants
in parallel, ~60s each for boot + checks).

**Entry points:**
- `nix-build -A checks.integration.all` -- All integration tests (per-test VMs)
- `nix-build -A checks.integration.toolchain` -- Toolchain subset
- `nix-build -A checks.integration.libraries` -- Library ABI subset
- `nix-build -A checks.vm.boot` -- Boot smoke test
- `nix-build -A checks.vm.security` -- Kernel hardening
- `nix-build -A checks.vm.services` -- systemd, chrony, SSH, nginx
- `nix-build -A checks.vm.kubernetes` -- containerd, kubelet, CNI
- `nix-build -A checks.vm.seed` -- Seed server infrastructure

### Layer 4: Fleet

Multi-VM orchestration tests that boot several Firecracker instances connected
via tap networking. These verify distributed system behavior that cannot be
tested on a single node.

**What it catches:** Cluster formation failures, node join/leave issues, rolling
update regressions, cross-node network connectivity, distributed consensus problems.

**Cost:** Slowest layer. Multiple VMs must boot and coordinate.

**Entry points:**
- `nix-build -A checks.fleet.k8s-cluster` -- Control plane + worker join
- `nix-build -A checks.fleet.rolling-update` -- Rolling update with health checks

## Test categories

The package integration layer is detailed across four companion documents, each
covering a category of cross-package validation:

### Toolchain checks

Validates that the AOS compiler toolchain (gcc, g++, bootstrap linker) and language
runtimes (Go, Rust, Python, Perl) produce correct, runnable binaries. Tests compile
small programs, verify dynamic linking, check runtime behavior, and confirm that
language-specific package managers (cargo, go modules) work with AOS-built
dependencies.

See: [toolchain-checks.md](toolchain-checks.md)

### Library checks

Validates ABI and API compatibility for shared libraries. For each "hub" library
(openssl, zlib, zstd, pcre2, libcap, elfutils, etc.), tests compile and run a
program that exercises the library's public API, then verify that every consumer
package links correctly. Checks include symbol version verification, pkg-config
correctness, and header/library path consistency.

See: [library-checks.md](library-checks.md)

### Tool and service checks

Smoke tests for CLI tools (jq, curl, tar, rsync, openssh, nftables, etc.) and
startup tests for system services (systemd, sshd, nginx, chrony, containerd,
kubelet, nix-daemon). Each test invokes the tool or service with minimal but
realistic inputs and verifies expected output.

See: [tool-service-checks.md](tool-service-checks.md)

### Cross-cutting checks

Multi-package integration scenarios that span dependency boundaries. Tests cover
upgrade regression detection (what breaks when openssl goes from 3.3 to 3.4),
TLS stack coherence (all TLS consumers use the same openssl and ca-certificates),
compression interop (archives created by one tool are readable by another), and
full-stack scenarios (nix-daemon -> libarchive -> zstd -> zlib chain).

See: [cross-cutting-checks.md](cross-cutting-checks.md)

## Coverage goals

The target is to verify every dependency edge that crosses a package boundary in the
AOS build graph. Concretely:

**Shared libraries:** Every `.so` that is consumed by more than one package has an
ABI test that compiles and links a program against it, runs it, and verifies the
expected symbols are present at the expected versions.

**CLI tools:** Every user-facing CLI tool has a smoke test that invokes it with
representative arguments and checks the exit code and output.

**System services:** Every systemd service defined in AOS modules has a startup test
that verifies the unit reaches `active` state and responds to basic health checks.

**Toolchain outputs:** Programs compiled with each AOS-built compiler (gcc, g++, go,
rustc) are verified to link correctly, find the dynamic linker, and execute on the
target system.

**Dependency chains:** For high-fan-out packages (openssl, zlib, glibc, systemd),
tests verify that all direct dependents still function after an upgrade.

**Quantitative targets:**

| Metric | Target |
|--------|--------|
| Hub library ABI coverage (>5 dependents) | 100% |
| CLI tool smoke test coverage | 100% |
| Service startup test coverage | 100% |
| Toolchain output verification | All 4 languages (C, C++, Go, Rust) |
| Cross-package integration scenarios | All identified critical paths |

## Implementation

The implementation plan describes how these tests are expressed as Nix derivations,
integrated into the existing `checks` attribute set, and executed on the remote
builder.

See: [implementation.md](implementation.md)

## Table of contents

| # | Document | Description |
|---|----------|-------------|
| -- | [README.md](README.md) | Overview, philosophy, test layer architecture (this file) |
| 01 | [dependency-graph.md](dependency-graph.md) | Full dependency analysis, hub packages, risk assessment |
| 02 | [toolchain-checks.md](toolchain-checks.md) | Compiler and language runtime integration tests |
| 03 | [library-checks.md](library-checks.md) | Shared library ABI/API compile-link-run tests |
| 04 | [tool-service-checks.md](tool-service-checks.md) | CLI smoke tests and service startup tests |
| 05 | [cross-cutting-checks.md](cross-cutting-checks.md) | Multi-package compatibility and upgrade regression tests |
| 06 | [implementation.md](implementation.md) | Nix derivation patterns, CI integration, execution strategy |
