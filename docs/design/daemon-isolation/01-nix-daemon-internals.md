# Nix Daemon Internals

> Part of the [Daemon Isolation Architecture](README.md)

This document describes how the Nix daemon fetches sources, how proxy
configuration propagates to each fetch code path, and what this means for the
AOS isolation design. Understanding these internals is a prerequisite for the
container and proxy architecture described in later sections.

> **AOS context:** AOS compiles Nix with `/var/lib/aos` as its store root
> (`--store-dir=/var/lib/aos/store`, `--state-dir=/var/lib/aos/var/nix`). The
> `/nix` directory does not exist on an AOS system. All paths below use
> `/var/lib/aos` accordingly.

---

## 1. Three Fetch Code Paths

Nix has three distinct mechanisms for downloading source code. They differ in
*who* makes the HTTP call, *where* the call happens, and *how* proxy
configuration reaches the HTTP client.

### 1.1 `builtin:fetchurl` (used by AOS)

AOS's `fetchurl` in `lib/derivations.nix` creates a fixed-output derivation
with `builder = "builtin:fetchurl"`:

```nix
# lib/derivations.nix (simplified)
builtins.derivation {
  builder = "builtin:fetchurl";
  url = builtins.head resolvedUrls;

  outputHash = sha256;
  outputHashMode = "flat";
  outputHashAlgo = "sha256";

  preferLocalBuild = true;
}
```

When the daemon realises this derivation, it does **not** spawn an external
process. Instead, a forked child of the daemon performs the download in-process
using Nix's `FileTransfer` class, which is backed by **libcurl** (compiled into
the Nix binary). The call chain is:

```
nix-daemon
  └─ DerivationGoal::tryBuildHook()
       └─ builtinFetchurl()
            └─ fileTransfer->download(url)
                 └─ libcurl (CURLOPT_URL, respects proxy env vars)
```

Key properties:

- The HTTP call happens **inside the daemon process** (in a forked child), not
  in a build sandbox.
- libcurl automatically honours `http_proxy`, `https_proxy`, `no_proxy`, and
  `all_proxy` environment variables without any explicit `CURLOPT_PROXY`
  configuration.
- The daemon tries hashed mirrors first (if `hashed-mirrors` is configured in
  `nix.conf`), then falls back to the primary URL.
- If the derivation sets `unpack = true`, the daemon decompresses (`.xz`,
  `.gz`, `.bz2`) after download.
- The output hash is verified after download -- a proxy (even a MITM proxy)
  cannot tamper with the content without detection.

### 1.2 `builtins.fetchurl` (evaluation-time fetch)

This is a Nix language builtin that downloads a URL during **expression
evaluation**, not during the build phase. It runs in the evaluator (which is
either `nix-build` or the `nix-daemon` process when remote building). The
download uses the same in-process `FileTransfer`/libcurl code path and respects
the same proxy environment variables.

Downloads are cached in the evaluator's tarball cache with a TTL controlled by
`tarball-ttl` in `nix.conf`. **AOS does not use this mechanism** -- all source
fetches go through `builtin:fetchurl` derivations with explicit output hashes.

### 1.3 nixpkgs-style `fetchurl` (shell builder)

The upstream nixpkgs `fetchurl` function creates a derivation that runs a shell
script invoking an external `curl` binary inside the build sandbox:

```bash
# Simplified nixpkgs fetchurl builder
/run/current-system/sw/bin/curl --fail --location "$url" -o "$out"
```

This is a fundamentally different execution model: the HTTP call is made by a
separate process (`curl`) running inside Nix's build sandbox. Proxy
configuration must be explicitly injected into the sandbox environment via
`impureEnvVars` (see section 3 below).

**AOS does not use this mechanism.** All AOS source downloads use
`builtin:fetchurl` (section 1.1). However, AOS's `fetchgit` (section 1.4)
does use an in-sandbox builder pattern.

### 1.4 AOS `fetchgit` (in-sandbox git clone)

AOS's `fetchgit` in `lib/derivations.nix` creates a fixed-output derivation
that runs `git clone` inside the build sandbox:

```nix
# lib/derivations.nix (simplified)
builtins.derivation {
  builder = "/bin/sh";
  args = [ "-c" ''
    export PATH="${storeDir}/git-minimal/bin:$PATH"
    export GIT_SSL_CAINFO="${storeDir}/cacert/etc/ssl/certs/ca-bundle.crt"
    git clone --depth 1 "${url}" "$out"
    cd "$out"
    git checkout "${rev}"
  '' ];

  outputHash = sha256;
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
}
```

Because this is a fixed-output derivation, it has network access (see section 2),
but the `git` process runs inside the sandbox and does **not** automatically
inherit the daemon's environment. Proxy variables must reach the sandbox via
`impureEnvVars` (see section 3).

---

## 2. Fixed-Output Derivations and the Sandbox

Nix's build sandbox uses Linux namespaces to isolate build processes:

```c
// Nix sandbox namespace flags (regular builds)
CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET
```

**Fixed-output derivations** (those with an `outputHash` attribute) are treated
specially. The `isSandboxed()` function returns `false` for these derivations,
which means:

| Property | Regular derivation | Fixed-output derivation |
|----------|-------------------|------------------------|
| Network namespace | Private (`CLONE_NEWNET`) -- loopback only | **Host network** -- inherits daemon's namespace |
| DNS | No `/etc/resolv.conf` | `/etc/resolv.conf` bind-mounted from host |
| Outbound connections | Blocked | **Allowed** |
| Output verification | By build log determinism | **By content hash** |

This is why `builtin:fetchurl` and `fetchgit` can make network connections: they
are both fixed-output derivations. The daemon's network namespace (which, in the
AOS isolation architecture, is the nspawn container's namespace) is inherited by
the build sandbox for these derivations.

```
Host network namespace
  └─ nix-daemon container namespace (veth to proxy)
       ├─ builtin:fetchurl     ← runs in daemon process, uses container network
       ├─ fetchgit sandbox     ← inherits container network (fixed-output)
       └─ regular build sandbox ← private network (loopback only)
```

---

## 3. The `impureEnvVars` Mechanism

For fixed-output derivations, Nix provides a mechanism to pass specific
environment variables from the daemon's environment into the build sandbox.

### How it works

A derivation can declare `impureEnvVars`:

```nix
builtins.derivation {
  # ...
  impureEnvVars = [ "http_proxy" "https_proxy" "no_proxy" ];
}
```

When the daemon sets up the sandbox environment for this derivation, it looks up
each listed variable in:

1. **`impure-env`** in `nix.conf` (requires the `configurable-impure-env`
   experimental feature)
2. **`getEnv()`** -- the daemon's own process environment (fallback)

The resolved values are injected into the sandbox environment alongside the
standard build variables (`PATH`, `HOME`, `NIX_STORE`, etc.).

### When is it needed?

| Fetch mechanism | Runs where | Needs `impureEnvVars`? | Why |
|-----------------|-----------|----------------------|-----|
| `builtin:fetchurl` | Daemon process | **No** | libcurl reads proxy vars from daemon env directly |
| `builtins.fetchurl` | Evaluator process | **No** | Same in-process libcurl |
| nixpkgs `fetchurl` | Build sandbox (`curl`) | **Yes** | Sandbox env is clean; proxy vars must be injected |
| AOS `fetchgit` | Build sandbox (`git`) | **Yes** | Same as above -- `git` needs proxy vars in its env |
| Substituter fetches | Daemon process | **No** | In-process libcurl, same as `builtin:fetchurl` |

**For AOS, `impureEnvVars` is only needed for `fetchgit`.** All `fetchurl`
downloads go through the daemon's in-process libcurl, which reads proxy
variables directly from the daemon's environment.

### Configuration via `nix.conf`

The `impure-env` setting provides an alternative to relying on the daemon's
process environment:

```ini
# /etc/aos/nix.conf
experimental-features = configurable-impure-env

impure-env = http_proxy=http://172.30.0.1:3128 https_proxy=http://172.30.0.1:3128 no_proxy=localhost,127.0.0.1
```

This is more explicit than relying on `getEnv()` and survives daemon restarts
that might change the process environment.

---

## 4. Where to Set Proxy Environment Variables

There is **no `proxy` setting in `nix.conf`**. Nix relies entirely on
environment variables for proxy configuration. The correct place to set them
depends on which fetch code path is in use.

### 4.1 Daemon process environment (covers `builtin:fetchurl` + substituters)

Set `http_proxy`, `https_proxy`, and `no_proxy` in the daemon's systemd unit.
These are picked up by libcurl for all in-process HTTP calls:

```ini
# /etc/systemd/system/nix-daemon.service.d/proxy.conf
[Service]
Environment=http_proxy=http://172.30.0.1:3128
Environment=https_proxy=http://172.30.0.1:3128
Environment=no_proxy=localhost,127.0.0.1
```

This covers:
- All `builtin:fetchurl` downloads (AOS source fetches)
- All substituter fetches (narinfo + NAR downloads from `aos serve` or other caches)
- Evaluation-time `builtins.fetchurl` (not used by AOS, but covered anyway)

### 4.2 Sandbox environment (covers `fetchgit`)

For `fetchgit` and any other fixed-output derivation that runs an external
process in the sandbox, configure `impure-env` in `nix.conf`:

```ini
# /etc/aos/nix.conf
experimental-features = configurable-impure-env

impure-env = http_proxy=http://172.30.0.1:3128 https_proxy=http://172.30.0.1:3128 no_proxy=localhost,127.0.0.1
```

Alternatively, if `configurable-impure-env` is not available, the daemon's
process environment serves as a fallback -- `getEnv()` is called for each
variable listed in the derivation's `impureEnvVars`. Since the systemd unit
already sets proxy variables (section 4.1), this fallback works without
additional configuration.

### 4.3 Summary: what covers what

```
Daemon systemd Environment=
  │
  ├──► libcurl (in-process)
  │      ├── builtin:fetchurl     ✓ covered
  │      ├── builtins.fetchurl    ✓ covered
  │      └── substituter fetches  ✓ covered
  │
  └──► getEnv() fallback for impureEnvVars
         └── fetchgit sandbox     ✓ covered (if impureEnvVars declared)

nix.conf impure-env
  │
  └──► explicit sandbox injection
         └── fetchgit sandbox     ✓ covered (preferred over getEnv fallback)
```

---

## 5. Substituter Interaction

When `aos serve` (or any Nix binary cache) is configured as a substituter, the
daemon makes HTTP requests to fetch `.narinfo` metadata and `.nar` archive files.
These requests use the same in-process `FileTransfer`/libcurl code path as
`builtin:fetchurl`.

```ini
# /etc/aos/nix.conf
substituters = http://cache.internal:5000/prod
trusted-public-keys = cache.internal:abc123...
```

The daemon's proxy environment variables apply to substituter fetches. For a
local substituter (e.g., on the same veth network), use `no_proxy` to avoid
routing local traffic through the forward proxy:

```ini
# /etc/systemd/system/nix-daemon.service.d/proxy.conf
[Service]
Environment=no_proxy=localhost,127.0.0.1,172.30.0.1,cache.internal
```

---

## 6. Certificate Handling

### 6.1 CA bundle for daemon HTTPS

The daemon's libcurl uses a CA certificate bundle for TLS verification. This is
configured via:

| Setting | Source | Scope |
|---------|--------|-------|
| `ssl-cert-file` in `nix.conf` | Configuration file | All daemon HTTPS (fetches, substituters) |
| `NIX_SSL_CERT_FILE` env var | Daemon environment | Overrides `ssl-cert-file` |
| System default (e.g. `/etc/ssl/certs/ca-certificates.crt`) | Fallback | Used if neither above is set |

### 6.2 MITM proxy certificates

When using a MITM proxy (as opposed to a CONNECT tunnel), the proxy terminates
TLS and re-encrypts with its own certificate. The proxy's CA certificate must be
trusted by the daemon's libcurl. **Append the proxy CA to the daemon's CA
bundle**:

```bash
cat /etc/ssl/certs/ca-certificates.crt /etc/aos/proxy-ca.pem > /etc/aos/ca-bundle.pem
```

```ini
# /etc/aos/nix.conf
ssl-cert-file = /etc/aos/ca-bundle.pem
```

Hash verification still works correctly with a MITM proxy: the output hash is
computed on the downloaded content *after* TLS decryption. The proxy sees the
plaintext HTTP traffic, but it cannot alter the content without causing a hash
mismatch.

### 6.3 `fetchgit` certificates

AOS's `fetchgit` sets `GIT_SSL_CAINFO` explicitly in the build script:

```nix
export GIT_SSL_CAINFO="${storeDir}/cacert/etc/ssl/certs/ca-bundle.crt"
```

This points to an AOS-built CA bundle in the store. For MITM proxy support,
this bundle would need to include the proxy CA. In the isolation architecture,
the proxy uses HTTPS CONNECT tunneling (not MITM), so the standard CA bundle
is sufficient.

---

## 7. Summary Table

| Fetch mechanism | Who makes HTTP call | Where it runs | Proxy source | AOS usage |
|-----------------|-------------------|---------------|-------------|-----------|
| `builtin:fetchurl` | nix-daemon (forked child, in-process libcurl) | Daemon process | Daemon env vars | **Primary** -- all source tarballs |
| `builtins.fetchurl` | nix evaluator (in-process libcurl) | Daemon or nix-build process | Process env vars | Not used |
| nixpkgs `fetchurl` | `/bin/curl` binary | Build sandbox | `impureEnvVars` | Not used (AOS does not use nixpkgs) |
| AOS `fetchgit` | `git` binary | Build sandbox (with network) | `impureEnvVars` / `impure-env` | Used for git-sourced packages |
| Substituter fetches | nix-daemon (in-process libcurl) | Daemon process | Daemon env vars | `aos serve` cache lookups |

---

## 8. Complete Configuration Example

Below is a complete configuration for the AOS nix-daemon running inside the
isolation container, with all fetch paths proxied through the Squid forward
proxy at `172.30.0.1:3128`.

### 8.1 systemd unit override

```ini
# /etc/systemd/system/nix-daemon.service.d/proxy.conf
[Service]
# Proxy for all in-process libcurl calls (builtin:fetchurl, substituters)
Environment=http_proxy=http://172.30.0.1:3128
Environment=https_proxy=http://172.30.0.1:3128
Environment=no_proxy=localhost,127.0.0.1

# CA bundle (if using MITM proxy; omit if using CONNECT tunneling)
# Environment=NIX_SSL_CERT_FILE=/etc/aos/ca-bundle.pem
```

### 8.2 nix.conf

```ini
# /etc/aos/nix.conf

# Store configuration (compiled in, but also set here for clarity)
store = /var/lib/aos/store
state = /var/lib/aos/var/nix

# Sandbox settings
sandbox = true
sandbox-fallback = false

# Build settings
max-jobs = 4
cores = 0

# Substituter (local cache, bypasses proxy via no_proxy)
substituters = http://172.30.0.1:5000/prod
trusted-public-keys = aos-cache:abc123def456...

# Pass proxy env vars into fixed-output build sandboxes (for fetchgit)
experimental-features = configurable-impure-env
impure-env = http_proxy=http://172.30.0.1:3128 https_proxy=http://172.30.0.1:3128 no_proxy=localhost,127.0.0.1

# TLS certificate bundle
# ssl-cert-file = /etc/aos/ca-bundle.pem   # uncomment for MITM proxy
```

### 8.3 Verification

To confirm proxy configuration is working:

```bash
# Check daemon environment
systemctl show nix-daemon.service -p Environment

# Test builtin:fetchurl (daemon in-process fetch)
nix-store --realise /var/lib/aos/store/$(nix-instantiate --expr \
  'builtins.derivation {
    name = "test-fetch";
    system = "x86_64-linux";
    builder = "builtin:fetchurl";
    url = "https://httpbin.org/get";
    outputHash = "";
    outputHashAlgo = "sha256";
    outputHashMode = "flat";
  }')
# Will fail with hash mismatch, but the download attempt confirms proxy works.
# Check Squid access.log for the request.

# Verify nix.conf impure-env
nix show-config | grep impure-env
```

---

## 9. Implications for the Isolation Architecture

The key insight is that **AOS's primary fetch path (`builtin:fetchurl`) is
trivial to proxy** because the HTTP call happens inside the daemon process
itself. Setting three environment variables in the daemon's systemd unit covers
all source tarball downloads and substituter fetches with zero changes to
derivation definitions.

The only complication is `fetchgit`, which runs `git` inside the build sandbox.
This requires `impureEnvVars` in the derivation definition and corresponding
`impure-env` configuration in `nix.conf`. Since AOS controls all derivation
definitions in `lib/derivations.nix`, adding `impureEnvVars` to `fetchgit` is
straightforward.

The subsequent sections of this design cover the container topology
([02-container-isolation](02-container-isolation.md)), network plumbing
([03-network-architecture](03-network-architecture.md)), and proxy configuration
([04-forward-proxy](04-forward-proxy.md)) that implement this proxied fetch
architecture.
