# Nix Daemon Isolation Architecture

The Nix daemon runs inside a systemd-nspawn container with no direct network
access. A second container runs a Squid forward proxy that mediates all source
fetches, enforcing a domain allowlist and caching HTTP traffic. The two
containers communicate over a veth pair in a private network namespace.

## Goals

1. **Zero direct network access** for the Nix daemon -- all fetches are proxied
2. **Domain allowlisting** -- only approved upstream sources are reachable
3. **Multi-homed isolation** -- intranet interfaces are invisible to the daemon
4. **Store exclusivity** -- only the daemon container has write access to the store
5. **Configuration via Ignition** -- per-machine allowlists delivered at first boot

## Architecture

```
 ┌─ HOST ─────────────────────────────────────────────────────────────┐
 │                                                                     │
 │  eth0 (internet)              eth1 (intranet)                       │
 │  203.0.113.0/24               10.0.0.0/24                           │
 │       │                            │                                │
 │       │                            │   nftables: no container       │
 │       │                            │   traffic allowed here         │
 │  ┌────┼────────────────────────────┼──────────────────────────────┐ │
 │  │    │  macvlan                   │                              │ │
 │  │    │                            │                              │ │
 │  │  ┌─┴────────────────────────┐   │   ┌───────────────────────┐ │ │
 │  │  │ fetch-proxy container    │   │   │ nix-daemon container  │ │ │
 │  │  │                          │   │   │                       │ │ │
 │  │  │ mv-eth0: internet access │   │   │  --private-network    │ │ │
 │  │  │                          │   │   │  no host interface    │ │ │
 │  │  │ veth-proxy: 172.30.0.1/30├───────┤ veth-nixd:172.30.0.2 │ │ │
 │  │  │                          │   │   │                       │ │ │
 │  │  │ ┌──────────────────────┐ │   │   │ http_proxy=           │ │ │
 │  │  │ │ squid :3128          │ │   │   │  http://172.30.0.1:   │ │ │
 │  │  │ │  forward proxy       │ │   │   │  3128                 │ │ │
 │  │  │ │  domain ACLs         │ │   │   │                       │ │ │
 │  │  │ │  CONNECT for HTTPS   │ │   │   │ ┌───────────────────┐ │ │ │
 │  │  │ └──────────────────────┘ │   │   │ │ nix-daemon        │ │ │ │
 │  │  │                          │   │   │ │  builds from src  │ │ │ │
 │  │  │ ┌──────────────────────┐ │   │   │ │  fetches via proxy│ │ │ │
 │  │  │ │ dnsmasq :53          │ │   │   │ └───────────────────┘ │ │ │
 │  │  │ │  forwards to 1.1.1.1 │ │   │   │                       │ │ │
 │  │  │ └──────────────────────┘ │   │   │ DNS → 172.30.0.1:53  │ │ │
 │  │  └──────────────────────────┘   │   └───────────────────────┘ │ │
 │  └─────────────────────────────────┴──────────────────────────────┘ │
 │                                                                     │
 │  /var/lib/aos/store  ──bind-mount (rw)──►  nix-daemon container     │
 │  daemon socket       ◄──bind-mount──────  nix-daemon container      │
 └─────────────────────────────────────────────────────────────────────┘
```

## Table of contents

| # | Section | Description |
|---|---------|-------------|
| 01 | [Nix daemon internals](01-nix-daemon-internals.md) | How `builtin:fetchurl` works, proxy env vars, `impureEnvVars`, libcurl |
| 02 | [Container isolation](02-container-isolation.md) | systemd-nspawn configuration, capabilities, cgroup delegation, rootfs |
| 03 | [Network architecture](03-network-architecture.md) | veth pairs, macvlan, nftables, static routing, startup ordering |
| 04 | [Forward proxy](04-forward-proxy.md) | Why Squid (not Varnish), domain ACLs, HTTPS CONNECT, caching |
| 05 | [Configuration delivery](05-configuration-delivery.md) | Ignition integration, AOS module design, runtime updates |
| 06 | [Implementation plan](06-implementation-plan.md) | Prerequisites, AOS codebase changes, build order |

## Key design decisions

- **Squid, not Varnish.** Varnish is a reverse proxy that cannot handle the
  HTTP CONNECT method needed for HTTPS tunneling. Squid natively supports
  forward proxying with CONNECT and domain-based ACLs.

- **`builtin:fetchurl` simplifies proxy routing.** AOS uses `builtin:fetchurl`,
  which performs HTTP calls in the daemon process itself (via libcurl), not in
  a sandboxed builder. Proxy env vars in the daemon's systemd unit are
  sufficient -- no `impureEnvVars` needed for source downloads.

- **Manual veth pair, not `--network-zone=`.** A manually created veth pair
  between containers gives precise control over routing without relying on
  systemd's bridge auto-creation. The nix-daemon container has exactly one
  interface with a single route to the proxy.

- **macvlan for multi-homed isolation.** The proxy container gets internet
  access via `--network-macvlan=eth0`, which creates a virtual interface on
  the internet-facing NIC only. The intranet interface (eth1) is never
  exposed to either container.

- **`CAP_NET_ADMIN` for nested sandboxing.** The Nix sandbox creates network
  namespaces for regular (non-fixed-output) builds. This requires
  `CAP_NET_ADMIN` inside the nspawn container.
