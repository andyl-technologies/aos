# APM Security Model

## Threat Model

`apm` must protect against:

1. **Tampered registry** — An attacker modifies TOML files to point to
   malicious NARs
2. **Tampered NAR** — An attacker substitutes a NAR on a mirror with a
   backdoored version
3. **Mirror compromise** — A mirror operator serves malicious content
4. **Downgrade attack** — An attacker replays an old registry state with
   known-vulnerable packages
5. **Man-in-the-middle** — An attacker intercepts registry or NAR downloads

## Defense Layers

### Layer 1: Transport Security (TLS)

Registry fetches and NAR downloads use TLS by default. Plain HTTP (`http://`)
is supported but not recommended -- it bypasses transport encryption. Integrity
is still guaranteed by Layers 2-5 regardless of transport. TLS prevents passive
eavesdropping and active MITM attacks at the network level.

### Layer 2: Git Integrity (Transport-Independent)

The git object model provides cryptographic integrity for registry content
regardless of transport. Whether objects arrive via HTTP bundles or native
git, the same Merkle tree is verified:

- Every TOML file (git blob) has a SHA hash
- Every directory (git tree) has a SHA hash over its children
- Every commit has a SHA hash over its tree, parent, and metadata
- Changing any file changes the commit hash

Git bundles contain the same pack format as `git fetch` — identical object
SHAs, tree structure, and commit signatures. A bundle is a pre-packed fetch
response served as a static file.

This means: if you trust the commit hash, you trust every file in the
repository — regardless of how the objects were delivered.

### Layer 2a: Bundle Integrity (HTTP Transport)

For HTTP bundle transport, an additional verification layer applies before
git object verification:

1. Each bundle file has a SHA-256 hash in the `bundle-list.toml` manifest
2. The client verifies the downloaded bundle against this hash
3. `git bundle verify` checks pack integrity and prerequisite consistency
4. Only then are objects imported into the local git repository

The SHA-256 hashes in `bundle-list.toml` detect transport corruption but do
not authenticate the manifest itself. Authentication comes from Layers 2 and
3 -- the git objects inside the bundle carry their own integrity (Layer 2) and
the commit signatures provide authentication (Layer 3). Bundle mirrors are
**untrusted by design**; a compromised mirror can deny service but cannot forge
valid git objects or signatures. This is the same trust model as NAR mirrors.

### Layer 3: Commit Signing (Optional but Recommended)

Registry maintainers sign commits using git's SSH signing support with
Ed25519 keys. Commit signatures are embedded in the commit object itself and
survive bundle transport -- they are verified after import regardless of how
the objects arrived:

```toml
# registry.toml
[signing]
required = true
public_key = "aos-core:Ed25519:base64key=="
```

When `signing.required = true`, `apm update` will reject unsigned or
incorrectly signed commits. This prevents an attacker who compromises
the bundle mirror or git host from serving unsigned malicious commits.

### Layer 4: NAR Hash Verification

Each package TOML contains two hashes:

1. `download_hash` — SHA-256 of the compressed NAR file as served by mirrors
2. `nar_hash` — SHA-256 of the decompressed NAR content

After downloading a NAR:

```
1. Compute SHA-256(compressed file) → compare with download_hash
2. Decompress
3. Compute SHA-256(decompressed NAR) → compare with nar_hash
```

Both must match. Since the hashes come from the git-verified TOML file,
a compromised mirror cannot serve a tampered NAR without detection.

### Layer 5: Store Path Verification

The Nix store path is derived from the NAR content hash. After `nix-store
--import`, the resulting store path must match `store_path` from the TOML.
This is a third independent verification that the imported content is correct.

### Layer 6: Source Derivation Audit

The `source_drv` field enables anyone to rebuild the package from source and
verify the output matches. This is the ultimate verification — it proves the
binary was built from the claimed source code using the claimed build process.

```
apm source --verify openssl
```

## Trust Chain Summary

```
Registry maintainer signs commit
         |
         v
Bundle downloaded over HTTPS and verified (SHA-256 + git bundle verify)
  OR git fetch over HTTPS/SSH
         |
         v
Git commit signature verified by apm
         |
         v
Fast-forward check against last_commit (downgrade protection)
         |
         v
TOML file integrity guaranteed by git object hashes
         |
         v
NAR download_hash in TOML verified against downloaded file
         |
         v
NAR nar_hash in TOML verified against decompressed content
         |
         v
Store path matches after nix-store --import
         |
         v
(Optional) Source derivation rebuild produces same store path
```

Each layer is independent and transport-independent. Even if TLS is
compromised, git hashes protect the registry. Even if a bundle mirror is
compromised, git object hashes detect any modification — the mirror can only
deny service, not serve tampered content. Even if the git host is compromised,
commit signatures protect against unauthorized changes. Even if a NAR mirror
is compromised, NAR hashes prevent tampered binaries from being installed.

## Downgrade Protection

### Registry Pinning

Users can pin a registry to a specific tag:

```toml
pin = "v2026.02"
```

This prevents rollback to an older registry state. `apm update` will only
advance to the pinned tag (or its patch releases), not beyond it.

### Monotonic Version Tracking

`apm` records the latest seen registry commit and bundle creation token in
the per-registry state. The state file location depends on the operation scope:

- **User operations** (default): `~/.config/apm/registries.d/aos-core.toml`
- **System operations** (`--system`): `/var/lib/apm/registries.d/aos-core.toml`

```toml
# managed by apm, not user-edited
[registry.state]
last_commit = "abc123def456..."
last_creation_token = 2026020002
last_update = "2026-02-13T10:00:00Z"
```

System-level registry state at `/var/lib/apm/registries.d/` is writable and
managed by apm when run as root. This is separate from:

- `/etc/apm/registries.d/` -- immutable system config (cloud-init provisioned)
- `~/.config/apm/registries.d/` -- user-level config and state

After every update (bundle or git), the client checks that the new HEAD
commit is a descendant of `last_commit` (fast-forward only). If the new
HEAD is an ancestor of `last_commit` (i.e., a rollback), `apm` warns and
refuses to downgrade unless `--allow-downgrade` is explicitly passed.

For HTTP bundle transport, the `creation_token` provides an additional
monotonic check -- the client refuses to apply bundles with tokens lower
than or equal to the stored token. This catches stale bundles served by
a compromised mirror.

### Attack Scenarios

**Stale snapshot bundle:** An attacker controlling a mirror serves an old
full-snapshot bundle. Defense: the `last_commit` fast-forward check detects
that the bundle's HEAD is an ancestor of the stored commit and rejects it.

**Missing deltas:** An attacker returns 404 for delta bundles, hoping to
force the client to accept a stale snapshot. Defense: the client applies the
same `last_commit` check to any bundle it imports. A snapshot older than the
current state is rejected.

**Delta ordering manipulation:** An attacker serves deltas out of order or
skips intermediate patches. Defense: `git bundle verify` checks that all
prerequisite commits exist locally. Out-of-order or gapped deltas fail
verification.

## Key Management

### Registry Signing Keys

Signing keys are distributed via two channels:

1. **In the registry itself (TOFU)** — `registry.toml` contains the public
   key. When `apm registry add` is called:
   - The registry's signing key is fetched from `registry.toml`
   - The key fingerprint is displayed to the user
   - The user must explicitly confirm trust (interactive prompt)
   - The key is stored in `~/.config/apm/trusted-keys.d/` for user
     registries, or `/etc/apm/trusted-keys.d/` for system registries
     (`--system`)
   - Subsequent `apm update` calls verify commits against the stored key

2. **Out of band** — Keys can be pre-installed in the system config at
   `/etc/apm/trusted-keys.d/` (provisioned via cloud-init) or per-user at
   `~/.config/apm/trusted-keys.d/`. Both locations are checked. Pre-installed
   keys skip the TOFU prompt -- the registry is trusted immediately on first
   `apm registry add`.

### Key Rotation

When a registry rotates its signing key, the old key signs a commit that
introduces the new key. `apm` follows this chain:

1. Old key signs commit containing `registry.toml` with new key
2. Subsequent commits are signed with new key
3. `apm update` verifies the transition commit with old key, then trusts new key

## File Permissions

APM installs to two targets: a user profile (default, non-root) and a system
profile (requires root). The Nix store itself is managed by `nix-daemon`,
which handles privileged store operations on behalf of unprivileged users
via its Unix socket.

### System paths (immutable at runtime, configured via cloud-init)

| Path | Owner | Purpose |
|------|-------|---------|
| `/etc/apm/apm.conf` | root | System-wide config defaults |
| `/etc/apm/registries.d/` | root | Default registries (inherited by all users) |
| `/etc/apm/trusted-keys.d/` | root | Pre-trusted signing keys |
| `/var/lib/apm/` | root | System-level apm state (registry tracking) |

### Per-user paths (owned by `$USER`)

| Path | Purpose |
|------|---------|
| `~/.config/apm/apm.conf` | User config overrides |
| `~/.config/apm/registries.d/` | User-added or overridden registries |
| `~/.config/apm/trusted-keys.d/` | Per-user trusted signing keys |
| `~/.local/share/apm/remote/` | Registry metadata caches (populated via bundles or git) |
| `~/.cache/apm/` | Downloaded NAR cache |

### Profile paths

| Path | Owner | Purpose |
|------|-------|---------|
| `/var/lib/profiles/system/` | root | System profile (generations, metadata, GC roots) |
| `/var/lib/profiles/per-user/$USER/` | `$USER` | User profile (generations, metadata, GC roots) |

### Shared paths (managed by nix-daemon)

| Path | Owner | Purpose |
|------|-------|---------|
| `/var/lib/store/` | nix-daemon | Shared Nix store (content-addressed, deduplicated) |

### System profile cache isolation

When running `apm install --system` or other system-scoped operations, apm uses
`/var/lib/apm/remote/` for registry metadata cache instead of the invoking
user's `~/.local/share/apm/remote/`. This prevents privilege escalation where
a non-root user manipulates their local cache before running `sudo apm install
--system`. System operations always read from system-owned paths.

### Config lookup order

When operating on the **user profile** (default), `apm` reads user config
first and falls back to system config. When operating on the **system profile**
(`--system`), `apm` reads only `/etc/apm/`. A user-level registry file with
the same `name` as a system-level one overrides it entirely.
