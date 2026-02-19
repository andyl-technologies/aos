# Forward Proxy Selection and Configuration

> Part of the [Nix Daemon Isolation Architecture](README.md). This document
> covers forward proxy selection (why Squid, not Varnish), domain allowlist
> management, HTTPS CONNECT tunneling, caching analysis, and performance tuning.

## 4.1 Reverse Proxy vs. Forward Proxy

The fetch-proxy container sits between the Nix daemon and the internet. It must
act as a **forward proxy** -- the daemon explicitly sends requests through it
via `http_proxy` / `https_proxy` environment variables. This is fundamentally
different from a reverse proxy, which sits in front of known backend servers.

| Aspect | Reverse Proxy | Forward Proxy |
|--------|---------------|---------------|
| Client awareness | Client doesn't know about proxy | Client explicitly uses proxy |
| Backend set | Fixed, known backends | Arbitrary, client-specified |
| VCL `backend` | Pre-declared | Must be dynamic (`vmod_dynamic`) |
| CONNECT method | Not needed | **Required for HTTPS** |

The critical distinction is that the daemon fetches from arbitrary upstream
domains (kernel.org, github.com, gnu.org, etc.), and most of these use HTTPS.
The proxy must support the HTTP CONNECT method to establish tunnels for TLS
connections.

## 4.2 Why NOT Varnish

Varnish is a reverse proxy designed to sit in front of origin servers. It
has three critical limitations for forward proxy use:

1. **No CONNECT support.** Varnish operates at the HTTP layer -- it parses
   requests, applies VCL rules, and serves cached responses. The HTTP CONNECT
   method establishes a raw TCP tunnel (opaque byte stream) that Varnish has no
   mechanism to relay. This is a hard architectural limitation, not a missing
   feature.

2. **Static backend declarations.** VCL requires backends to be declared at
   compile time. A forward proxy must connect to whatever domain the client
   requests. The `vmod_dynamic` module works around this, but it is an
   afterthought bolted onto a reverse proxy architecture.

3. **Split-proxy complexity.** If Varnish were used, a second process
   (tinyproxy, stunnel, or similar) would be needed to handle HTTPS CONNECT
   tunnels. This means two daemons, two configurations, two ACL systems, and
   a routing layer to split HTTP vs. HTTPS traffic. Since most modern source
   mirrors use HTTPS, the Varnish side would handle the minority of traffic.

**The dealbreaker is CONNECT.** Without it, the proxy cannot mediate HTTPS
fetches at all. Since AOS builds fetch from HTTPS sources (GitHub releases,
kernel.org, python.org, etc.), a proxy that cannot handle CONNECT is unusable
as the sole network gateway for the daemon.

## 4.3 Why Squid

Squid is purpose-built as a forward proxy and satisfies every requirement:

| Requirement | Squid Capability |
|-------------|-----------------|
| HTTP CONNECT for HTTPS | Native support -- `acl CONNECT method CONNECT` |
| Domain-based ACLs | `acl dstdomain` with subdomain matching |
| HTTP response caching | Built-in, configurable cache directory |
| Single process | Handles both HTTP caching and HTTPS tunneling |
| Maturity | Decades of production use, widely deployed |
| Graceful reload | `squid -k reconfigure` applies config changes without restart |
| Logging | Per-request access log for auditing allowed and denied fetches |

A single Squid process replaces what would otherwise require two daemons (cache
+ CONNECT relay) with separate configurations and ACL systems.

## 4.4 Squid Configuration

Full `/etc/squid/squid.conf` for the AOS fetch proxy:

```
# AOS Fetch Proxy -- Squid forward proxy with domain allowlist

http_port 3128

# Domain allowlist
acl allowed_domains dstdomain .github.com
acl allowed_domains dstdomain .githubusercontent.com
acl allowed_domains dstdomain .kernel.org
acl allowed_domains dstdomain .gnu.org
acl allowed_domains dstdomain .gnupg.org
acl allowed_domains dstdomain .sourceforge.net
acl allowed_domains dstdomain .python.org
acl allowed_domains dstdomain .cpan.org
acl allowed_domains dstdomain .rust-lang.org
acl allowed_domains dstdomain .crates.io
acl allowed_domains dstdomain .releases.nixos.org
acl allowed_domains dstdomain .openssl.org
acl allowed_domains dstdomain .zlib.net
acl allowed_domains dstdomain .tukaani.org
acl allowed_domains dstdomain .curl.se
acl allowed_domains dstdomain .llvm.org
acl allowed_domains dstdomain .savannah.gnu.org
acl allowed_domains dstdomain .sourceware.org

# HTTPS CONNECT ports
acl SSL_ports port 443
acl CONNECT method CONNECT

# Access control
http_access allow CONNECT SSL_ports allowed_domains
http_access allow allowed_domains
http_access deny all

# Cache settings -- cache tarballs aggressively
maximum_object_size 512 MB
cache_dir ufs /var/spool/squid 10000 16 256

# Logging
access_log daemon:/var/log/squid/access.log squid

# Security
forwarded_for delete
via off
```

### Configuration breakdown

**Domain allowlist.** Each `acl allowed_domains dstdomain` line adds a domain
to the allowlist. The leading `.` enables subdomain matching -- `.github.com`
matches `github.com`, `codeload.github.com`, `objects.githubusercontent.com`,
etc.

**Access rules.** Two `http_access allow` rules:
- `CONNECT SSL_ports allowed_domains` -- allows HTTPS tunnels to port 443 on
  allowed domains only.
- `allowed_domains` -- allows plain HTTP requests to allowed domains.
- `deny all` -- default deny. Any request to an unlisted domain gets a 403.

**Security hardening.** `forwarded_for delete` strips the `X-Forwarded-For`
header (no need to reveal the daemon container's internal IP). `via off`
suppresses the `Via` header that would advertise the proxy's presence.

## 4.5 Domain Allowlist Management

### Syntax

Domains use `.domain.com` prefix syntax for subdomain matching:

```
acl allowed_domains dstdomain .kernel.org
```

This matches `kernel.org`, `cdn.kernel.org`, `mirrors.kernel.org`, etc. One
`acl` line per domain keeps the configuration clear and auditable.

### Adding a domain

1. Add an `acl allowed_domains dstdomain .newdomain.org` line to `squid.conf`.
2. Run `squid -k reconfigure` for a graceful reload (no connection drops).
3. The change takes effect immediately for new connections.

### Denied request behavior

- The client (libcurl in the Nix daemon) receives an HTTP 403 response.
- The Squid error page includes the denied domain name.
- The access log records both allowed and denied requests, providing a full
  audit trail of all fetch attempts.

### Auditing

The access log at `/var/log/squid/access.log` records every request:

```
1706000000.000    200 TCP_MISS/200 52428800 GET http://ftp.gnu.org/gnu/gcc/gcc-14.1.0/gcc-14.1.0.tar.xz -
1706000001.000    200 TCP_TUNNEL/200 0 CONNECT github.com:443 -
1706000002.000    403 TCP_DENIED/403 0 CONNECT evil.example.com:443 -
```

The `TCP_DENIED` entry shows blocked requests. Monitoring this log reveals
both legitimate fetches and any unexpected outbound connection attempts from
the daemon.

## 4.6 TLS/HTTPS Handling

### CONNECT tunneling (recommended)

When the Nix daemon fetches an HTTPS URL through the proxy:

```
1. libcurl sends:  CONNECT github.com:443 HTTP/1.1
2. Squid checks:   Is github.com in allowed_domains?
3. Squid checks:   Is port 443 in SSL_ports?
4. If allowed:     Squid opens a TCP connection to github.com:443
                   and relays bytes bidirectionally (raw tunnel)
5. libcurl:        Performs TLS handshake through the tunnel
6. Traffic:        Encrypted end-to-end (libcurl <-> github.com)
```

**Properties of CONNECT tunneling:**
- The proxy sees only the destination hostname and port -- not the URL path,
  headers, or response body.
- TLS is end-to-end between libcurl (in the Nix daemon) and the upstream
  server. No MITM, no CA management, no certificate injection.
- Domain allowlist enforcement happens at the CONNECT stage, before the TLS
  handshake.
- Hash verification still works -- Nix checks the content hash after download
  regardless of transport.

### TLS MITM (not recommended)

Squid supports `ssl_bump` to intercept HTTPS connections via a MITM CA. This
would theoretically allow caching of HTTPS content, but it introduces
significant problems:

| Concern | Impact |
|---------|--------|
| CA management | Must generate a MITM CA and inject it via `NIX_SSL_CERT_FILE` |
| Certificate pinning | Some clients reject MITM certificates |
| HSTS | Strict transport security headers may break |
| Complexity | Substantial additional configuration and key management |
| Benefit | Minimal -- Nix store already deduplicates content |

TLS MITM is not recommended for the AOS fetch proxy. CONNECT tunneling
provides domain-level access control, which is the primary security goal.
Content caching is a secondary benefit that does not justify the complexity
and fragility of TLS interception.

## 4.7 Caching Analysis

### Cache benefit matrix

| Factor | Without Proxy Cache | With Proxy Cache |
|--------|---------------------|------------------|
| First fetch | ~2-30s (network) | ~2-30s (network) |
| Re-fetch after GC | ~2-30s (network) | <10ms (local) |
| Bandwidth (repeat) | Full re-download | Zero |
| Upstream load | 1 req per build | 1 req total |
| Concurrent dedup | No | Yes |
| Offline builds | Impossible | Possible (stale) |

### Why caching matters despite content-addressing

Nix content-addresses store paths, so a given source tarball always produces
the same store path. However, the store path is the *output* of fetching --
the fetch itself still hits the network. Caching is valuable because:

1. **GC + rebuild cycles.** After garbage collection, rebuilding a package
   re-fetches the same source tarball. The proxy cache serves it locally.
2. **Concurrent builds.** Multiple simultaneous builds of different packages
   may share source dependencies. The proxy deduplicates upstream requests.
3. **Network resilience.** Squid's grace/stale serving can return cached
   content when the upstream is temporarily unreachable.

### HTTPS caching limitation

Caching only works for HTTP traffic. HTTPS traffic via CONNECT is tunneled
opaquely -- the proxy cannot see or cache the response content. Since most
modern source mirrors use HTTPS, the caching benefit is limited to HTTP-only
mirrors (some GNU mirrors, kernel.org legacy endpoints).

This is an acceptable trade-off. The primary value of the proxy is **domain
allowlisting and network isolation**, not caching. Caching is a bonus for the
HTTP traffic that does flow through.

## 4.8 Performance Tuning

```
# Squid tuning for build server workload
maximum_object_size 512 MB       # Large source tarballs
cache_mem 256 MB                 # In-memory hot cache
cache_dir ufs /var/spool/squid 10000 16 256  # 10GB disk cache
refresh_pattern . 43200 100% 43200  # Cache everything for 30 days
quick_abort_min -1               # Never abort partial downloads
connect_timeout 30 seconds
read_timeout 600 seconds         # Large tarballs take time
```

### Parameter rationale

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `maximum_object_size` | 512 MB | Source tarballs (GCC, LLVM, Rust) can be 100-200 MB |
| `cache_mem` | 256 MB | Keeps recently fetched tarballs in RAM for concurrent builds |
| `cache_dir` | 10 GB | Sufficient for ~50-100 large source tarballs on disk |
| `refresh_pattern` | 30 days | Source tarballs are immutable -- aggressive caching is safe |
| `quick_abort_min` | -1 | Never abort a fetch midway; always complete the download |
| `connect_timeout` | 30s | Generous timeout for upstream connection establishment |
| `read_timeout` | 600s | 10 minutes for large tarball downloads over slow links |

The `refresh_pattern . 43200 100% 43200` line tells Squid to consider any
cached object fresh for 30 days (43200 minutes), regardless of upstream cache
headers. This is appropriate because source tarballs at versioned URLs are
immutable -- `gcc-14.1.0.tar.xz` will never change content at the same URL.

## 4.9 DNS Resolution

Squid needs DNS to resolve upstream domain names. The fetch-proxy container
runs dnsmasq alongside Squid to provide DNS for both itself and the nix-daemon
container:

```
┌─ fetch-proxy container ────────────────────────┐
│                                                 │
│  dnsmasq :53 ──── forwards to ──── 1.1.1.1     │
│     ▲                                8.8.8.8   │
│     │                                           │
│  Squid (internal resolver → 127.0.0.1:53)       │
│                                                 │
│  veth-proxy: 172.30.0.1/30                      │
│     ▲                                           │
└─────┼───────────────────────────────────────────┘
      │
      │ DNS queries from nix-daemon container
      │
┌─────┼───────────────────────────────────────────┐
│     ▼                                           │
│  /etc/resolv.conf: nameserver 172.30.0.1        │
│                                                 │
│  nix-daemon container (--private-network)       │
└─────────────────────────────────────────────────┘
```

The nix-daemon container's `/etc/resolv.conf` points at `172.30.0.1:53`
(the proxy container's veth address). This ensures all DNS resolution flows
through the proxy container, which has controlled internet access via its
macvlan interface. The nix-daemon container has no direct path to any external
DNS server.

Using dnsmasq rather than Squid's internal DNS resolver provides:
- DNS caching (reduces upstream lookups for repeated fetches)
- Explicit control over upstream forwarders
- A single DNS service for both Squid and the nix-daemon container

## 4.10 AOS Prerequisite: Building Squid

Squid must be built as an AOS package from source (`pkgs/web/squid.nix`),
following AOS's hermetic build requirements. No host tools, no upstream
nixpkgs.

### Dependency chain

```
squid
├── openssl      (TLS support for CONNECT tunneling)
├── libxml2      (error page generation, optional but standard)
└── libtool      (build system requirement)
    └── ...      (existing AOS packages)
```

OpenSSL is already built as an AOS package (`pkgs/tls/openssl.nix`). The
`libxml2` and `libtool` dependencies may need to be added if not already
present.

### Package skeleton

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
    hash = "sha256-FIXME";
  };
  buildDeps = [ make perl ];
  runtimeDeps = [ openssl libxml2 ];
  phases = [
    ''
      ./configure \
        --prefix=$out \
        --with-openssl=${openssl} \
        --enable-ssl-crtd=no \
        --disable-arch-native
      make -j$NIX_BUILD_CORES
      make install
    ''
  ];
}
```

The `--enable-ssl-crtd=no` flag disables the TLS MITM certificate generator
(not needed for CONNECT tunneling). `--disable-arch-native` ensures the binary
is portable across machines with different CPU microarchitectures.
