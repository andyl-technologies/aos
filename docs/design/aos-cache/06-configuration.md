# Configuration

### 7.1 AOS Root Path (Compile-Time)

The AOS state root (`/var/lib/aos` by default) is a **compile-time constant**
baked into the `aos` binary. Nix itself is compiled with
`--store-dir=/var/lib/aos/store` and `--state-dir=/var/lib/aos/var/nix`, so
`/var/lib/aos` is the root for BOTH Nix and AOS state — `/nix` does not exist.
The AOS-specific directories (`gcroots/`, `meta/`, `views/`) live alongside
Nix's own (`store/`, `var/`). The `aosRoot` in the Nix expression is used both
for `AOS_ROOT` and to configure Nix's store/state dirs. The path is set by the
Nix expression that builds the `aos` CLI package:

```nix
{ mkDerivation, fetchurl, rustc, ... }:
let
  aosRoot = "/var/lib/aos";
in mkDerivation {
  pname = "aos";
  phases = [
    ''
      export AOS_ROOT="${aosRoot}"
      export AOS_STORE_DIR="${aosRoot}/store"
      cargo build --release
    ''
  ];
}
```

The Rust binary reads this at compile time:

```rust
/// AOS state root — set at compile time by the Nix build harness.
/// Analogous to Nix's compiled-in store path.
pub const AOS_ROOT: &str = env!("AOS_ROOT");
```

All data directories are derived from `AOS_ROOT`:

| Directory | Purpose |
|-----------|---------|
| `{AOS_ROOT}/store/` | Nix store (content-addressed) |
| `{AOS_ROOT}/var/nix/db/` | Nix metadata DB |
| `{AOS_ROOT}/var/nix/gcroots/` | Nix GC roots |
| `{AOS_ROOT}/gcroots/{view}/bin/` | Per-view GC roots for build outputs |
| `{AOS_ROOT}/gcroots/{view}/src/` | Per-view GC roots for source tarballs |
| `{AOS_ROOT}/meta/{view}/bin/` | Binary output metadata JSON |
| `{AOS_ROOT}/meta/{view}/src/` | Source tarball metadata JSON |
| `{AOS_ROOT}/meta/tokens.db` | Provisioning token database |
| `{AOS_ROOT}/views/{view}/builds/` | In-flight build state |

System variants can override the root — e.g., an embedded image might use
`/data/aos` instead of `/var/lib/aos`. Since the path is compiled in, the
binary always knows its state directory without per-invocation configuration.

### 7.2 Server Configuration

Single TOML file at `/etc/aos/serve.toml` (or `--config` flag):

```toml
[server]
listen = "127.0.0.1:5000"
# listen = "[::]:5000"          # IPv6
# listen = "/run/aos/http.sock" # Unix socket (for reverse proxy)

[build]
# The Nix daemon builds and signs. These control build behavior:
max_jobs = 4                        # parallel build jobs (--max-jobs)
cores_per_build = 0                 # cores per build (0 = all)
# extra_platforms = ["aarch64-linux"]  # requires binfmt/QEMU on host

[signing]
# The Nix daemon's signing key is used for outputs it builds.
# This key is for narinfo re-signing (if different from daemon key):
# secret_key_file = "/etc/aos/secret.pem"
# If unset, narinfo is served with the daemon's signatures as-is.

[compression]
# Default compression for NAR responses
algorithm = "zstd"    # zstd | xz | none
level = 3             # zstd level (1-19)

[[views]]
name = "ci"
ttl = "7d"                          # binary output TTL
source_ttl = "90d"                  # source tarball TTL (longer)
source_mirror = true                # retain source inputs (default: true)
anonymous_read = false
max_concurrent_builds = 4
max_store_size = "200G"
max_paths = 50000

[[views]]
name = "prod"
ttl = "none"
source_ttl = "none"                 # keep sources forever alongside binaries
anonymous_read = true
max_concurrent_builds = 2
max_store_size = "500G"

[[views]]
name = "dev"
ttl = "24h"
source_ttl = "7d"                   # keep sources a week even for dev
anonymous_read = false
max_concurrent_builds = 2
max_store_size = "50G"

[oauth2]
access_token_ttl = 3600               # 1 hour JWT expiry
jwt_secret_file = "/etc/aos/jwt.secret"

[bootstrap]
socket = "/run/aos/bootstrap.sock"
socket_group = "aos-admins"            # Unix group allowed to create tokens

# Tokens are NOT in this file — they're created via `aos token create`
# and stored in /var/lib/aos/meta/tokens.db (SQLite).
# See 04-authentication.md for the provisioning token model.
```
