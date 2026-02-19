# Implementation Plan

> Part of the [Daemon Isolation Architecture](README.md)

This document describes the prerequisites, phased implementation plan, testing
strategy, and risk assessment for adding nspawn-based daemon isolation to AOS.
All changes follow AOS hermetic build principles -- new packages are built from
source using bootstrap tools, and no nixpkgs packages are introduced.

---

## 1. Prerequisites

Each prerequisite is a discrete unit of work that can be reviewed and merged
independently. The table lists them in dependency order -- later items may
depend on earlier ones.

| # | Change | File(s) | Complexity | Notes |
|---|--------|---------|-----------|-------|
| 1 | Enable machined in systemd | `pkgs/init/systemd.nix` | Low | Change `-Dmachined=false` to `-Dmachined=true` (line ~164). Also consider `-Dimportd=enabled` for container image import support. |
| 2 | Build Squid from source | `pkgs/web/squid.nix` (new) | Medium | Dependencies: openssl, libxml2. Follow AOS hermetic build patterns -- both deps are already AOS packages. |
| 3 | Build dnsmasq from source | `pkgs/networking/dnsmasq.nix` (new) | Low | Minimal dependencies, straightforward Makefile build. No autoconf. |
| 4 | Create fetch-proxy module | `modules/services/fetch-proxy.nix` (new) | High | Generates `squid.conf`, `.nspawn` files, systemd units, networkd config, nftables rules. |
| 5 | Extend nix-daemon module | `modules/services/nix-daemon.nix` | High | Add container mode, proxy env vars, store bind mounts, socket forwarding. |
| 6 | Extend firewall module | `modules/security/firewall.nix` | Medium | Add container isolation chain for the FORWARD path, per-namespace nftables injection. |
| 7 | Build container rootfs derivations | `modules/services/fetch-proxy.nix` or separate | High | Minimal rootfs from AOS packages for each container. |
| 8 | Wire into seed system variant | `systems/seed.nix` | Low | Import fetch-proxy module, enable it. |

### Dependency graph

```
  1  Enable machined
  │
  ├──► 4  Create fetch-proxy module ◄── 2  Build Squid
  │    │                              ◄── 3  Build dnsmasq
  │    │
  │    ├──► 7  Build container rootfs
  │    │
  │    └──► 5  Extend nix-daemon module
  │         │
  │         └──► 8  Wire into seed variant
  │
  └──► 6  Extend firewall module ──► 8
```

Prerequisites 1, 2, and 3 have no dependencies on each other and can be
implemented in parallel. Prerequisites 4-7 form the core implementation and
depend on the packages from 1-3. Prerequisite 8 is the final integration step.

---

## 2. Implementation Phases

### Phase 1: Foundation (prerequisites 1-3)

**Goal:** Build all required packages from source and verify that
`machinectl`/`systemd-nspawn` work on an AOS system.

- Enable the `machined` meson option in `pkgs/init/systemd.nix`. This compiles
  `systemd-machined`, `machinectl`, and the `systemd-nspawn` container runtime
  into the existing systemd package. No new package is needed -- these are
  built-in systemd components gated by a meson flag.

- Build Squid as a new AOS package at `pkgs/web/squid.nix`:

  ```nix
  { mkDerivation, fetchurl, make, openssl, libxml2, perl }:
  let version = "6.12"; in
  mkDerivation {
    pname = "squid";
    inherit version;
    src = fetchurl {
      urls = [
        "https://www.squid-cache.org/Versions/v6/squid-${version}.tar.xz"
      ];
      hash = "sha256-...";
    };
    buildDeps = [ make perl ];
    runtimeDeps = [ openssl libxml2 ];
    phases = [ ... ];
  }
  ```

- Build dnsmasq as a new AOS package at `pkgs/networking/dnsmasq.nix`. dnsmasq
  has no autoconf -- it uses a plain Makefile with `PREFIX=` and `DESTDIR=`:

  ```nix
  { mkDerivation, fetchurl, make }:
  let version = "2.90"; in
  mkDerivation {
    pname = "dnsmasq";
    inherit version;
    src = fetchurl {
      urls = [
        "https://thekelleys.org.uk/dnsmasq/dnsmasq-${version}.tar.xz"
      ];
      hash = "sha256-...";
    };
    buildDeps = [ make ];
    runtimeDeps = [];
    phases = [ ... ];
  }
  ```

- Verify basic `systemd-nspawn` operation by booting a minimal rootfs on an AOS
  system. Estimated work: 2-3 new packages to build from source.

### Phase 2: Container infrastructure (prerequisites 4, 5, 7)

**Goal:** Create the module infrastructure for running the Nix daemon and fetch
proxy inside nspawn containers.

- Create `modules/services/fetch-proxy.nix` with options for:
  - Domain allowlist (`services.fetchProxy.allowedDomains`)
  - Proxy port and listen address
  - DNS forwarder upstream servers
  - Cache size and retention policy
  - nspawn container configuration (capabilities, bind mounts)

- Extend `modules/services/nix-daemon.nix` with a container mode:
  - Generate an `.nspawn` unit for the daemon container
  - Bind-mount `/var/lib/aos/store` (read-write) into the container
  - Bind-mount the daemon socket out to the host
  - Inject `http_proxy`/`https_proxy` environment variables into the daemon's
    systemd unit
  - Configure `impure-env` in `nix.conf` for `fetchgit` proxy support

- Build container rootfs derivations. Each container needs a minimal rootfs
  built as a Nix derivation from AOS packages:

  ```
  fetch-proxy rootfs:
    squid, dnsmasq, coreutils, bash, systemd (init)

  nix-daemon rootfs:
    nix, coreutils, bash, systemd (init), cacert
  ```

  These are pure derivations -- no runtime downloads, no external images.

- Test basic container startup and verify socket forwarding works.

### Phase 3: Network isolation (prerequisite 6)

**Goal:** Implement the veth network topology and nftables firewall rules that
enforce the isolation boundary.

- Implement veth pair creation between the fetch-proxy and nix-daemon
  containers. The pair uses a `/30` subnet (`172.30.0.0/30`) with static
  addresses:
  - `172.30.0.1` -- fetch-proxy container (Squid + dnsmasq)
  - `172.30.0.2` -- nix-daemon container

- Configure nftables rules for container isolation:
  - FORWARD chain: allow traffic between the two containers on the veth pair
  - FORWARD chain: block all other container-to-host and container-to-intranet
    traffic
  - INPUT chain on nix-daemon container: allow only proxy and DNS from
    `172.30.0.1`
  - Per-namespace nftables injection for defense-in-depth

- Test domain allowlist enforcement: verify that Squid blocks requests to
  domains not in the allowlist and returns HTTP 403.

- Test multi-homed interface isolation: verify that the nix-daemon container
  cannot reach the host's intranet interface (e.g. `eth1` / `10.0.0.0/24`).

### Phase 4: Integration (prerequisite 8)

**Goal:** Wire the isolation architecture into the seed system variant and
validate end-to-end.

- Import the fetch-proxy module in `systems/seed.nix` and enable it:

  ```nix
  {
    imports = [
      ../modules/services/fetch-proxy.nix
    ];

    services.fetchProxy = {
      enable = true;
      allowedDomains = [
        ".kernel.org"
        ".gnu.org"
        ".github.com"
        ".githubusercontent.com"
        # ... per-machine allowlist from Ignition
      ];
    };
  }
  ```

- End-to-end testing: build an AOS package through the isolated daemon and
  verify the full pipeline (daemon -> proxy -> upstream -> hash verification).

- Verify GC root integrity across the store bind mount -- roots created inside
  the container must be visible to the host's garbage collector.

- Performance benchmarking: measure fetch latency and build throughput compared
  to the direct (non-containerized) daemon to quantify overhead.

---

## 3. Open Questions and Trade-offs

| Question | Options | Recommendation |
|----------|---------|----------------|
| Store path: AOS custom vs. `/nix` | Container could map `/var/lib/aos/store` to either path | Use the AOS custom path (`/var/lib/aos/store`) consistently in both host and container. The Nix binary is compiled with this store dir -- no remapping needed. |
| Container rootfs: build-time vs. first-boot | Build-time: baked into the system image. First-boot: fetched as a tarball. | Build-time (preferred). The rootfs is a Nix derivation rebuilt automatically when inputs change. No network access is needed at first boot. |
| DNS in nix-daemon container | dnsmasq on proxy vs. Squid's internal resolver vs. none | dnsmasq on the proxy at `172.30.0.1:53` (belt-and-suspenders). Squid's internal resolver is adequate for HTTP, but `fetchgit` needs system-level DNS resolution via `/etc/resolv.conf`. |
| Proxy for `fetchgit` | `impureEnvVars` in derivation vs. `impure-env` in `nix.conf` | `impure-env` in `nix.conf` with the `configurable-impure-env` experimental feature. This is configuration-only and does not require changes to derivation definitions. See [01-nix-daemon-internals.md](01-nix-daemon-internals.md) section 3. |
| Network zone approach | `--network-zone=` (bridge) vs. manual veth pair | Manual veth pair. Precise control over routing, no unintended NAT rules, no dependency on systemd's bridge auto-creation. |

---

## 4. Testing Strategy

Testing follows the existing AOS test infrastructure described in `tests/`.

### 4.1 Eval test

Verify that the module system evaluates correctly when the fetch-proxy module is
enabled. This catches type errors, missing option definitions, and invalid
systemd unit generation without booting a VM.

```bash
nix-build -A checks.eval
```

### 4.2 VM test

Boot a seed system variant with `services.fetchProxy.enable = true` and verify
the isolation architecture end-to-end. The VM test uses QEMU direct kernel boot
(as documented in `tests/vm/lib.nix`).

Test cases:

| # | Test | Assertion |
|---|------|-----------|
| 1 | Containers start | `machinectl list` shows both `fetch-proxy` and `nix-daemon` containers running |
| 2 | Inter-container communication | `nix-daemon` container can reach `172.30.0.1:3128` (Squid) and `172.30.0.1:53` (dnsmasq) |
| 3 | Domain allowlist blocks | Fetch from a domain NOT in the allowlist returns HTTP 403 / connection refused |
| 4 | Allowed domains pass | Fetch from an allowed domain (e.g. `kernel.org`) succeeds through the proxy |
| 5 | `nix-build` works | A fixed-output derivation (`builtin:fetchurl`) successfully downloads through the proxy |
| 6 | Intranet isolation | The nix-daemon container cannot reach the host's intranet interface (`10.0.0.0/24`) |
| 7 | Socket forwarding | Host processes can connect to the daemon socket and run `nix-store --version` |
| 8 | GC root visibility | A GC root created inside the container is visible from the host |

### 4.3 Integration test

Full build of an AOS package through the isolated daemon. This test exercises
the complete pipeline: `nix-build` on the host connects to the daemon socket,
the daemon fetches sources through the proxy, builds the package, and the output
is available in the host's store.

```bash
# Inside the VM test harness:
nix-build -A pkgs.hello --store /var/lib/aos/store
```

---

## 5. Dependency on AOS Cache Server

This isolation architecture is designed to work with the `aos serve` cache
server documented in [docs/design/aos-cache/](../aos-cache/README.md). The
relationship between the two systems:

```
                    Host
                     │
  ┌──────────────────┼──────────────────────┐
  │                  │                      │
  │  aos serve       │   daemon socket      │
  │  (HTTP cache)    │   (Unix socket)      │
  │  listens on      │   bind-mounted       │
  │  :5000           │   from container     │
  │       │          │          │            │
  │       │          │          │            │
  │       └──────────┼──────────┘            │
  │         connects via                     │
  │         standard Nix                     │
  │         daemon protocol                  │
  └──────────────────┼──────────────────────┘
                     │
              nix-daemon container
```

The `aos serve` process runs on the **host** and connects to the daemon via the
bind-mounted Unix socket. The isolation is transparent to `aos serve` -- it sees
the same Unix socket API regardless of whether the daemon runs directly on the
host or inside an nspawn container.

When `aos serve` is configured as a substituter for the daemon (see
[01-nix-daemon-internals.md](01-nix-daemon-internals.md) section 5), the daemon
fetches narinfo and NAR files from the cache using its in-process libcurl. These
requests go through the proxy unless `no_proxy` is configured to bypass it for
local addresses.

---

## 6. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| systemd machined adds build complexity | Medium | Low | machined is already part of systemd -- enabling it requires only a meson flag change. The additional compiled binaries (`machinectl`, `systemd-nspawn`) are well-tested upstream components. |
| Squid is a large dependency chain | Medium | Low | Most dependencies (openssl, libxml2) are already AOS packages. Squid's build system is autoconf-based, which AOS handles routinely. The perl build dependency is only needed at build time. |
| Nested namespaces fail inside nspawn | High | Medium | The Nix sandbox creates network namespaces (`CLONE_NEWNET`) for regular (non-fixed-output) builds. This requires `CAP_NET_ADMIN` inside the nspawn container. Test early with a minimal nspawn configuration. Fallback: `sandbox = relaxed` in `nix.conf` if nested namespaces are unsupported. |
| Performance overhead of proxy + veth | Low | Low | veth overhead is negligible (~microseconds per packet). Squid adds ~1ms per HTTP request for ACL evaluation and connection setup. Source tarballs are megabytes -- the per-request overhead is lost in download time. |
| Container rootfs maintenance burden | Medium | Low | The rootfs is a Nix derivation built from AOS packages. When a dependency changes (e.g. a Squid security update), the rootfs is rebuilt automatically as part of the normal `nix-build` pipeline. No manual image management. |
| Store corruption from concurrent access | High | Low | Only one nix-daemon instance has write access to the store. The socket bind mount ensures all clients go through the single daemon. The host never writes to `/var/lib/aos/store` directly. |
| Ignition delivery of per-machine allowlists | Medium | Medium | The allowlist is a flat list of domain patterns. Ignition already supports writing arbitrary files to `/etc/`. If Ignition is unavailable, the module falls back to a compiled-in default allowlist. |

---

## 7. File Change Summary

A complete list of files that will be created or modified:

```
pkgs/init/systemd.nix                   (modify — enable machined)
pkgs/web/squid.nix                      (create — new package)
pkgs/networking/dnsmasq.nix             (create — new package)
modules/services/fetch-proxy.nix        (create — new module)
modules/services/nix-daemon.nix         (modify — container mode)
modules/security/firewall.nix           (modify — container chains)
systems/seed.nix                        (modify — import fetch-proxy)
tests/default.nix                       (modify — add new test)
tests/vm/checks/fetch-proxy.nix         (create — VM test)
```

All new packages follow the standard AOS package structure documented in
`CLAUDE.md` -- each is a single Nix file that takes `{ mkDerivation, fetchurl,
... }` and returns a derivation built hermetically from source.
