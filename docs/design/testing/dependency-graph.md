# Dependency Graph Analysis

This document analyzes the dependency graph of the AOS package set to derive
test priorities, upgrade impact assessments, and risk levels for each layer
of the system.

## 1. Dependency Graph Overview

AOS builds ~162 packages hermetically from source. The dependency graph forms
a layered DAG (directed acyclic graph) rooted at the bootstrap toolchain.
Every package declares three dependency types:

| Dependency Type   | Meaning                                   | Propagation  |
|-------------------|-------------------------------------------|--------------|
| `buildDeps`       | Tools needed only at build time            | Not inherited |
| `runtimeDeps`     | Libraries/tools needed at runtime          | Direct only   |
| `propagatedDeps`  | Deps that propagate to downstream consumers| Transitive    |

The graph has a characteristic **hourglass shape**: a small set of foundation
packages fans out through shared libraries and build tools, then converges
into leaf applications and services.

```
                    ┌─────────────────┐
                    │   Bootstrap     │
                    │ gcc glibc make  │
                    │ bash coreutils  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
        │  Shared   │ │ Language  │ │  Build    │
        │  Libs     │ │ Runtimes  │ │  Systems  │
        │ openssl   │ │ python3   │ │ cmake     │
        │ zlib pcre │ │ go rust   │ │ meson     │
        │ libcap    │ │ perl      │ │ autoconf  │
        └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
  ┌─────┴─────┐  ┌──────────┴──────────┐  ┌─────┴─────┐
  │ Networking│  │ Security / SELinux  │  │  System   │
  │ curl ssh  │  │ libsepol libselinux │  │ systemd   │
  │ nginx     │  │ audit libseccomp   │  │ dbus      │
  └─────┬─────┘  └──────────┬──────────┘  └─────┬─────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
        │  Nix      │ │ Kubernetes│ │  Leaf     │
        │  Package  │ │ Stack     │ │  Tools    │
        │  Manager  │ │ kubelet   │ │ chrony    │
        │           │ │ containerd│ │ ethtool   │
        └───────────┘ └───────────┘ └───────────┘
```

---

## 2. Hub Package Analysis

Hub packages have high fanout -- many other packages depend on them. A bug
in a hub package has a blast radius proportional to its dependent count.

### Tier 1 -- Foundation

These are bootstrap-provided. Everything depends on them. They are not
individually upgradeable (they change only with a full bootstrap rebuild).

| Package    | Role                        | Direct Dependents | Risk |
|------------|-----------------------------|-------------------|------|
| gcc/glibc  | C/C++ compiler and libc     | All C/C++ pkgs    | Total|
| make       | Build system                | ~120 packages     | Total|
| coreutils  | POSIX utilities             | All packages      | Total|
| bash       | Build shell ($CONFIG_SHELL) | All packages      | Total|

Since Tier 1 is bootstrap-provided, it changes infrequently. When it does
change, the **entire package set** must be rebuilt and retested.

### Tier 2 -- Critical Shared Libraries

| Package    | Direct Runtime Dependents                                       | Count | Risk     |
|------------|-----------------------------------------------------------------|-------|----------|
| openssl    | curl, openssh, nginx, systemd, rsync, nix, libssh2, libgit2    | 8+    | Critical |
| zlib       | curl, openssh, openssl, nginx, systemd, rust, libarchive,       | 10+   | Critical |
|            | libgit2, libssh2, nix, python3                                 |       |          |
| zstd       | systemd, libarchive                                             | 2     | High     |
| lz4        | systemd                                                         | 1     | Medium   |
| pcre2      | nginx, libselinux, systemd                                      | 3     | High     |
| libcap     | systemd, chrony, containerd (indirect)                          | 3     | High     |
| libxcrypt  | systemd, nginx, openssh                                         | 3     | High     |

### Tier 3 -- Language Runtimes

| Package | Packages Built With It                                                  | Count | Risk     |
|---------|-------------------------------------------------------------------------|-------|----------|
| python3 | systemd, meson, llvm, setools, audit, libgit2, refpolicy, nix          | 8+    | Critical |
| perl    | openssl, autoconf, texinfo, audit                                       | 4     | High     |
| go      | containerd, runc, kubelet, kubectl, kubeadm, helm, cni-plugins,        | 13+   | Critical |
|         | crictl, nerdctl, node-exporter, butane, nginx-acme, ignition,           |       |          |
|         | conntrack-tools (partial), ipvsadm (partial)                            |       |          |
| rust    | nix (components), sbsigntools                                           | 2     | Medium   |

### Tier 4 -- Build Systems

| Package          | Used By                                                       | Count | Risk   |
|------------------|---------------------------------------------------------------|-------|--------|
| cmake            | llvm, curl, libarchive, libgit2, nlohmann-json, libssh2, nghttp2 | 7  | High   |
| meson + ninja    | systemd, dbus                                                 | 2     | High   |
| autoconf + automake | Multiple GNU packages                                      | 5+    | Medium |
| pkg-config       | Many packages (dep discovery)                                 | 20+   | High   |
| flex             | libsepol, libselinux                                          | 2     | Medium |
| bison            | iproute2, nftables, iptables                                  | 3     | Medium |
| gperf            | systemd, libseccomp                                           | 2     | Medium |

### Tier 5 -- Networking Libraries

| Package    | Direct Dependents                                               | Count | Risk   |
|------------|-----------------------------------------------------------------|-------|--------|
| libmnl     | libnftnl, libnetfilter_*, conntrack-tools, nftables, iptables   | 6+    | High   |
| libnfnetlink | libnetfilter_conntrack, libnetfilter_queue, conntrack-tools   | 3     | Medium |
| libnl      | iproute2, nftables                                              | 2     | Medium |
| curl       | nix, libgit2, cmake (download mode)                             | 3     | High   |
| libssh2    | curl, libgit2                                                   | 2     | Medium |
| nghttp2    | curl                                                            | 1     | Medium |

### Tier 6 -- Security / SELinux

| Package      | Direct Dependents                                            | Count | Risk   |
|--------------|--------------------------------------------------------------|-------|--------|
| libsepol     | libselinux, checkpolicy, semodule-utils                      | 3     | High   |
| libselinux   | libsemanage, policycoreutils, setools, systemd, container-selinux | 5 | High   |
| libsemanage  | policycoreutils                                              | 1     | Medium |
| audit        | systemd, setools                                             | 2     | Medium |
| libseccomp   | containerd, runc                                             | 2     | Medium |

### Tier 7 -- Data / Utility Libraries

| Package     | Direct Dependents          | Count | Risk |
|-------------|----------------------------|-------|------|
| ncurses     | readline, bash, python3    | 3     | High |
| readline    | bash, python3              | 2     | Medium |
| sqlite      | nix, python3               | 2     | Medium |
| boost       | nix                        | 1     | Medium |
| libarchive  | nix, cmake                 | 2     | Medium |
| libgit2     | nix                        | 1     | Low  |
| oniguruma   | jq                         | 1     | Low  |
| jansson     | nftables                   | 1     | Low  |
| gmp         | mpfr                       | 1     | Low  |
| mpfr        | libmpc                     | 1     | Low  |
| libmpc      | gcc                        | 1     | Low  |

---

## 3. Critical Dependency Chains

These are the longest and most consequential paths through the dependency
graph. A failure at any point in the chain breaks everything downstream.

### 3.1 OpenSSL Chain

OpenSSL is the most critical shared library. It underpins TLS for every
network-facing service.

```
openssl
├──> curl ──> nix (package manager)
│         ──> libgit2 ──> nix
│         ──> cmake (download mode)
├──> openssh (remote access)
├──> nginx (web serving / reverse proxy)
├──> systemd (journald, resolved, networkd TLS)
├──> rsync (file transfer)
├──> libssh2 ──> curl (circular buildDep path via linking)
│             ──> libgit2 ──> nix
└──> rust ──> nix (components)
         ──> sbsigntools
```

**Transitive impact**: An openssl bug can break the package manager (nix),
remote access (openssh), the init system's networking (systemd), web services
(nginx), and the build system's download capability (cmake via curl).

### 3.2 Go / Kubernetes Chain

The entire container orchestration stack is built with Go. A Go compiler
bug can break every component.

```
go
├──> containerd ──> (container runtime)
├──> runc ──> (OCI runtime, used by containerd)
├──> kubelet ──> (node agent)
├──> kubectl ──> (CLI)
├──> kubeadm ──> (cluster bootstrap)
├──> helm ──> (package manager)
├──> cni-plugins ──> (pod networking)
├──> crictl ──> (CRI debugging)
├──> nerdctl ──> (container CLI)
├──> node-exporter ──> (monitoring)
├──> butane ──> (Ignition config transpiler)
├──> nginx-acme ──> (TLS certificate automation)
├──> ignition ──> (first-boot provisioning)
├──> conntrack-tools (Go portion)
└──> ipvsadm (Go portion)
```

**Transitive impact**: A Go upgrade rebuilds the entire Kubernetes stack,
all container tooling, and cluster provisioning. All 13+ packages must be
retested.

### 3.3 Python / Systemd Chain

Python3 is a build-time dependency of the init system through meson.

```
python3
├──> meson ──> systemd (init system, PID 1)
│           ──> dbus (IPC bus)
├──> llvm (compiler infrastructure)
├──> setools (SELinux policy analysis)
├──> audit (kernel audit framework)
├──> libgit2 (build-time Python scripts)
├──> refpolicy (SELinux reference policy)
└──> nix (some build components)
```

**Transitive impact**: A python3 build failure prevents building systemd.
Without systemd, no system variant can boot.

### 3.4 SELinux Chain

SELinux forms a linear dependency chain where each layer builds on the last.

```
libsepol
└──> libselinux
     ├──> libsemanage
     │    └──> policycoreutils (sestatus, semodule, restorecon, etc.)
     ├──> setools (policy analysis, depends on libselinux + python3)
     ├──> systemd (SELinux-aware init)
     ├──> container-selinux (container policy)
     └──> checkpolicy (policy compiler)
          └──> refpolicy (reference policy build)
```

**Transitive impact**: A libsepol bug breaks the entire SELinux stack.
Since systemd is SELinux-aware, this can affect boot if policy loading fails.

### 3.5 Nix Package Manager Chain

Nix has the most dependencies of any single package in the system -- it
requires 9 direct runtime/build dependencies beyond the basics.

```
nix
├── boost (C++ libraries)
├── sqlite (local database)
├── curl ──> openssl, zlib, libssh2, nghttp2
├── libgit2 ──> openssl, zlib, libssh2
├── libarchive ──> zlib, zstd, lz4
├── libsodium (cryptographic signing)
├── editline (REPL input)
├── lowdown (markdown rendering)
└── rust (some components)
```

**Transitive impact**: Nix is the package manager itself. If nix cannot
build, no further system maintenance is possible on a deployed node (though
the system still runs with existing packages).

### 3.6 Netfilter Chain

The firewall stack has a deep library chain.

```
libmnl
├──> libnftnl ──> nftables (modern firewall)
├──> libnetfilter_conntrack ──> conntrack-tools
├──> libnetfilter_queue ──> (packet queuing)
├──> libnetfilter_cthelper ──> conntrack-tools
├──> libnetfilter_cttimeout ──> conntrack-tools
└──> iptables (legacy firewall)

libnfnetlink
├──> libnetfilter_conntrack
├──> libnetfilter_queue
└──> conntrack-tools
```

---

## 4. Risk Assessment Matrix

| Tier | Scope of Failure | Example Packages | Impact Description |
|------|------------------|------------------|--------------------|
| 1 - Foundation | **Nothing builds** | gcc, glibc, make, bash, coreutils | Complete rebuild required. No package in the tree can compile. Equivalent to a bootstrap failure. |
| 2 - Shared Libs | **Core services fail at runtime** | openssl, zlib, pcre2, libcap | TLS breaks (openssl), compression breaks (zlib), pattern matching breaks (pcre2). Services segfault or fail to start. |
| 3 - Runtimes | **Entire language ecosystem breaks** | python3, go, rust, perl | All packages built with that runtime are broken. Python3 bug: no systemd. Go bug: no Kubernetes. |
| 4 - Build Systems | **Subset of packages fail to build** | cmake, meson, autoconf, pkg-config | Only packages using that build system are affected. cmake bug: no curl, no libarchive. meson bug: no systemd. |
| 5 - Networking | **Firewall and network tooling breaks** | libmnl, curl, libssh2 | Firewalls stop working (libmnl), downloads fail (curl), SSH tunnels break (libssh2). |
| 6 - Security | **SELinux policy stack breaks** | libsepol, libselinux, libseccomp | Policy cannot be loaded or enforced. Containers lose seccomp filtering. System may boot in permissive mode. |
| 7 - Data/Utility | **Individual packages affected** | ncurses, sqlite, boost, readline | Limited blast radius. ncurses bug affects readline and bash. sqlite bug affects nix and python3. |

### Severity Ranking

When two packages are both candidates for testing resources, prioritize the
one with the higher tier number (lower in the table = lower priority), unless
the lower-tier package is on a critical chain (Section 3).

---

## 5. Test Priority Derivation

The dependency graph directly determines which packages warrant the most
testing effort. The principle: **test investment should be proportional to
the number of packages that break if a given package is buggy.**

### Priority Levels

**P0 -- Must not regress (gate all releases):**
- openssl, zlib (highest fanout shared libraries)
- python3, go (highest fanout runtimes)
- systemd (init system -- if it breaks, nothing boots)
- Entire bootstrap toolchain (gcc, glibc, make, bash)

**P1 -- Must pass before deployment:**
- curl, openssh, nginx (network-facing services)
- nix (package manager -- needed for ongoing maintenance)
- kubelet, containerd, runc (container orchestration)
- libselinux, libsepol (security enforcement)
- cmake, meson (build systems with many consumers)

**P2 -- Should pass, tested in CI:**
- pcre2, libcap, libxcrypt, zstd, lz4 (shared libraries, limited fanout)
- perl, rust (runtimes with fewer consumers)
- autoconf, automake, pkg-config, bison, flex, gperf (build tools)
- libmnl, libnftnl, nftables, iptables (firewall stack)
- dbus, audit, libseccomp (system infrastructure)

**P3 -- Tested on change only:**
- Leaf packages: dosfstools, ethtool, bc, diffutils, gawk, patch, texinfo,
  minisign, chrony, node-exporter, helm, nerdctl, crictl, setools, firmware,
  zfs
- Single-consumer libraries: oniguruma, jansson, editline, lowdown, boost,
  gmp, mpfr, libmpc

### Hub Package Testing Requirements

Hub packages (Tier 2-3) need more than unit-level verification. They need
**compatibility testing with every direct consumer**:

| Hub Package | Required Compatibility Tests |
|-------------|----------------------------|
| openssl     | curl TLS handshake, nginx HTTPS serving, openssh connection, systemd-resolved DNS-over-TLS, nix binary cache fetch |
| zlib        | curl compressed transfer, nginx gzip, nix NAR decompression, python3 zlib module |
| python3     | systemd builds successfully, meson can configure, setools runs |
| go          | All 13+ Go packages build and pass their test suites |
| libselinux  | systemd boots with SELinux, policycoreutils works, container-selinux policy loads |

---

## 6. Upgrade Impact Analysis

When a package is upgraded, the following table defines the **test blast
radius** -- the minimum set of tests that must pass before the upgrade is
accepted.

### Blast Radius by Package

#### openssl upgrade
```
Must rebuild: curl, openssh, nginx, systemd, rsync, nix, libssh2, libgit2, rust
Must test:
  - curl: HTTPS fetch, client certificate auth
  - openssh: SSH connection, key exchange
  - nginx: HTTPS serving, TLS 1.3, certificate loading
  - systemd: resolved DNS-over-TLS, journald remote
  - nix: binary cache fetch over HTTPS
  - VM boot test (systemd integration)
  - Kubernetes API server TLS (if applicable)
```

#### zlib upgrade
```
Must rebuild: curl, openssh, openssl, nginx, systemd, rust, libarchive,
              libgit2, libssh2, nix, python3
Must test:
  - curl: compressed HTTP responses
  - nginx: gzip compression/decompression
  - nix: NAR handling
  - python3: import zlib, gzip module
  - VM boot test
```

#### python3 upgrade
```
Must rebuild: systemd, meson, llvm, setools, audit, libgit2, refpolicy, nix
Must test:
  - meson: can configure and build systemd
  - systemd: full build + VM boot test
  - setools: policy analysis functions
  - nix: any Python-dependent build steps
```

#### go upgrade
```
Must rebuild: containerd, runc, kubelet, kubectl, kubeadm, helm,
              cni-plugins, crictl, nerdctl, node-exporter, butane,
              nginx-acme, ignition, conntrack-tools (partial), ipvsadm (partial)
Must test:
  - containerd: container lifecycle (create, start, stop, delete)
  - runc: OCI runtime spec compliance
  - kubelet: node registration, pod lifecycle
  - cni-plugins: pod network connectivity
  - helm: chart install/upgrade
  - ignition: first-boot provisioning
```

#### systemd upgrade
```
Must rebuild: (few direct dependents -- systemd is mostly a leaf consumer)
Must test:
  - VM boot test (critical -- systemd is PID 1)
  - Service management: start, stop, restart, enable, disable
  - journald: log collection and querying
  - networkd: interface configuration, DHCP
  - resolved: DNS resolution
  - tmpfiles: /tmp cleanup, /run setup
  - SELinux integration: policy loading at boot
```

#### libselinux upgrade
```
Must rebuild: libsemanage, policycoreutils, setools, systemd, container-selinux
Must test:
  - systemd: boots with SELinux enforcing
  - policycoreutils: sestatus, semodule, restorecon
  - setools: sesearch, seinfo
  - container-selinux: container policy loads correctly
```

#### curl upgrade
```
Must rebuild: nix, libgit2
Must test:
  - HTTPS fetch (various TLS versions)
  - HTTP/2 (via nghttp2)
  - Redirect handling
  - nix: binary cache substitution
  - libgit2: HTTPS clone
```

#### libmnl upgrade
```
Must rebuild: libnftnl, libnetfilter_conntrack, libnetfilter_queue,
              libnetfilter_cthelper, libnetfilter_cttimeout, nftables, iptables
Must test:
  - nftables: rule add/delete/list
  - iptables: basic rule operations
  - conntrack-tools: connection tracking
```

#### ncurses upgrade
```
Must rebuild: readline, bash, python3
Must test:
  - bash: interactive terminal, line editing
  - readline: input handling
  - python3: curses module, then cascade python3 tests
```

### Minimal Test Matrix

For CI efficiency, the following matrix covers the highest-value tests for
the most commonly upgraded packages:

| Test                          | openssl | zlib | python3 | go | systemd | curl | libselinux |
|-------------------------------|---------|------|---------|----|---------|------|------------|
| Eval check (all pkgs parse)   | X       | X    | X       | X  | X       | X    | X          |
| VM boot                       | X       | X    | X       |    | X       |      | X          |
| curl HTTPS fetch              | X       | X    |         |    |         | X    |            |
| nginx HTTPS serve             | X       |      |         |    |         |      |            |
| openssh connection            | X       |      |         |    |         |      |            |
| nix substitution              | X       | X    |         |    |         | X    |            |
| Go packages build             |         |      |         | X  |         |      |            |
| K8s pod lifecycle             |         |      |         | X  |         |      |            |
| SELinux policy load           |         |      |         |    | X       |      | X          |
| systemd service management    |         |      |         |    | X       |      |            |
| meson configures systemd      |         |      | X       |    |         |      |            |
| Firewall rules (nftables)     |         |      |         |    |         |      |            |

---

## 7. Dependency Graph Invariants

These invariants should be enforced by CI to prevent accidental introduction
of problematic dependency patterns:

1. **No circular runtime dependencies.** The runtime dependency graph must
   be a DAG. Build-time cycles (e.g., openssl needs perl to build, perl
   needs openssl at runtime) are acceptable as staged bootstrap.

2. **Leaf packages must not become hub packages.** If a package currently
   has 0-1 dependents and a change would add 3+ dependents, flag for review.

3. **No nixpkgs imports.** The only nixpkgs dependency is QEMU for VM tests.
   All other packages must be built from source using AOS packages.

4. **Propagated deps must be minimal.** Each `propagatedDeps` entry adds
   transitive weight to every consumer. Prefer `runtimeDeps` unless
   consumers genuinely need the transitive dependency in their own builds.

5. **Hub package upgrades require explicit test plans.** Any upgrade to a
   Tier 2 or Tier 3 package must include a test plan referencing the blast
   radius tables in Section 6.
