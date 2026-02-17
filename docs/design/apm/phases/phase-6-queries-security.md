# Phase 6: Queries, Security, & Polish

## Goal

Implement all query/info commands (search, show, list, depends, policy, files),
the security subsystem (TOFU, signing verification, downgrade protection), and
system profile support. After this phase, APM is feature-complete.

## Prerequisites

- Phase 5 complete (all core commands)

## Design References

- [cli.md](../cli.md) — Query command specs, output formats
- [examples.md](../examples.md) — Expected output for all query commands
- [security.md](../security.md) — TOFU, signing, key management
- [integration.md](../integration.md) — System profiles, PATH, man pages
- [store.md](../store.md) — Verification flow

---

## Chunk 6A: Search, Show, List

### Files to Create

**`src/package/query.rs`** (~300 lines)

Package information and search commands.

```rust
/// Run `apm search <pattern>`.
///
/// Search package names and descriptions across all registries.
/// Output format: name/registry version - description
pub async fn search(
    config: &ApmConfig,
    pattern: &str,
    names_only: bool,
    installed_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()>;

/// Run `apm show <package>`.
///
/// Display detailed package information.
/// Dependencies are derived from `references` via the registry hash index.
///
/// Output format (human):
///   Package: curl
///   Version: 8.5.0
///   Registry: aos-core
///   Description: ...
///   ...
///   Dependencies: openssl, zlib, nghttp2, cacert
///
/// Output format (--json): full JSON object.
pub async fn show(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm list`.
///
/// List packages (all, installed, upgradable, held).
/// Output format: name/registry version [status]
pub async fn list(
    config: &ApmConfig,
    installed: bool,
    upgradable: bool,
    held: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()>;

/// Derive human-readable dependency names from store path hashes.
///
/// For each hash in `references`, look it up in the same registry
/// via the hash index. Return named packages. Unnamed store paths
/// (bootstrap deps not in the registry) are shown as raw hashes.
fn resolve_dependency_names(
    registry: &Registry,
    references: &[String],
) -> Vec<String>;

/// Format package for search output: "name/registry version - description"
fn format_search_line(meta: &PackageMeta, registry_name: &str) -> String;

/// Format package for list output: "name/registry version [status]"
fn format_list_line(
    meta: &InstalledMeta,
    shadow_info: Option<&str>,
) -> String;
```

### Tests

- Search by name pattern matches partial names.
- Search by description matches description text.
- `--names-only` skips description matching.
- `--installed` filters to installed packages only.
- Show displays all fields for a known package.
- Show `--json` outputs valid JSON matching the schema.
- Dependencies derived from references show named packages.
- References not in the registry show as raw hashes.
- List `--installed` shows only installed packages.
- List `--upgradable` shows packages with available updates.
- List `--held` shows only held packages.

### Acceptance Criteria

- Search output matches examples.md format: `name/registry version - description`.
- Show output matches cli.md format with all fields.
- Show `--json` produces the exact JSON structure from examples.md.
- List uses slash-delimited format: `name/registry version [status]`.
- All commands respect `--registry` filter.

---

## Chunk 6B: Depends, Rdepends, Policy, Files

### Files to Create

**`src/package/deps.rs`** (~250 lines)

Dependency tree, reverse dependency, policy, and file listing commands.

```rust
/// Run `apm depends <package>`.
///
/// Walk the store reference graph and display as a tree.
/// Package names are resolved via the registry hash index.
pub async fn depends(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm rdepends <package>`.
///
/// Scan installed packages for closures that include this package.
pub async fn rdepends(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm policy <package>`.
///
/// Show available versions across all registries.
/// Mark installed version with ***.
pub async fn policy(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm files <package>`.
///
/// List files in the package's store path.
pub async fn files(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Build a dependency tree structure for display.
///
/// Recursively walks references, resolving names from the registry.
/// Handles cycles by tracking visited hashes.
fn build_dep_tree(
    registry: &Registry,
    root_hash: &str,
    visited: &mut HashSet<String>,
) -> DepNode;

pub struct DepNode {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub children: Vec<DepNode>,
}

/// Format a dependency tree for display.
/// Uses box-drawing characters: ├──, └──, │
fn format_tree(node: &DepNode, prefix: &str, is_last: bool) -> String;
```

### Tests

- `depends curl` shows tree: curl -> openssl -> zlib, curl -> nghttp2, etc.
- Tree handles diamond dependencies (zlib referenced by multiple packages).
- `rdepends openssl` shows curl, nginx if both are installed.
- `policy openssl` shows versions from all registries with priorities.
- `***` marker on installed version in policy output.
- `files curl` lists `bin/curl`, `lib/libcurl.so`, etc.
- Tree formatting uses correct box-drawing characters.

### Acceptance Criteria

- `apm depends` output matches examples.md tree format.
- `apm rdepends` lists all installed reverse dependencies.
- `apm policy` output matches cli.md format (no parenthetical annotations).
- `apm files` lists actual files from the store path.
- All commands support `--json` output.

---

## Chunk 6C: Security — TOFU, Signing, Downgrade Protection

### Files to Create

**`src/package/security.rs`** (~300 lines)

Key management, TOFU, and commit signature verification.

```rust
/// Trusted key storage.
///
/// Keys are stored as individual files in trusted-keys.d/:
///   ~/.config/apm/trusted-keys.d/ (user scope)
///   /etc/apm/trusted-keys.d/ (system scope, cloud-init provisioned)
///   /var/lib/apm/trusted-keys.d/ (system scope, runtime)
pub struct KeyStore {
    dirs: Vec<PathBuf>,       // search order
}

impl KeyStore {
    /// Load keys from all configured directories.
    pub fn load(scope: ProfileScope) -> Result<Self>;

    /// Check if a key is trusted.
    pub fn is_trusted(&self, key_id: &str) -> bool;

    /// Add a key to the user's trusted keys.
    pub fn trust_key(&self, key_id: &str, public_key: &str) -> Result<()>;

    /// Remove a key from the user's trusted keys.
    pub fn untrust_key(&self, key_id: &str) -> Result<()>;

    /// List all trusted keys.
    pub fn list_keys(&self) -> Result<Vec<TrustedKey>>;
}

pub struct TrustedKey {
    pub key_id: String,
    pub algorithm: String,     // "Ed25519"
    pub public_key: String,    // base64
    pub source: String,        // "system", "user", or "runtime"
}

/// TOFU (Trust On First Use) flow for `apm registry add`.
///
/// 1. Fetch registry.toml from the registry URL
/// 2. Extract signing key
/// 3. Check if key is already trusted
/// 4. If not: display fingerprint, prompt user for confirmation
/// 5. If confirmed: store key in trusted-keys.d/
/// 6. If rejected: abort registry add
pub async fn tofu_check(
    registry_url: &str,
    signing: &SigningConfig,
    key_store: &mut KeyStore,
    printer: &Printer,
    assume_yes: bool,
) -> Result<()>;

/// Verify a git commit signature against trusted keys.
///
/// Uses `git verify-commit` with the trusted key.
pub fn verify_commit_signature(
    repo_dir: &Path,
    commit: &str,
    key_store: &KeyStore,
) -> Result<()>;

/// Full downgrade protection check.
///
/// 1. Fast-forward: new_commit must descend from last_commit
/// 2. Monotonic: new_creation_token >= last_creation_token
pub fn check_downgrade(
    repo_dir: &Path,
    state: &RegistryState,
    new_commit: &str,
    new_token: u64,
) -> Result<()>;
```

### Tests

- TOFU flow with a new key prompts for confirmation.
- TOFU with already-trusted key skips prompt.
- TOFU with `-y` flag auto-trusts.
- Key store reads from multiple directories.
- System keys cannot be modified by non-root.
- Commit signature verification with valid Ed25519 key.
- Commit signature verification fails with wrong key.
- Downgrade protection rejects old creation_token.
- Downgrade protection rejects non-fast-forward commit.

### Acceptance Criteria

- `apm registry add` triggers TOFU flow.
- Key fingerprints are displayed clearly.
- Signature verification is integrated into `apm update` flow.
- Downgrade protection is enforced on every registry sync.
- System scope uses `/var/lib/apm/trusted-keys.d/` (writable at runtime).

---

## Chunk 6D: System Profiles, Verify, Source, Registry Commands

### Files to Modify

**`src/package/mod.rs`** — Wire remaining commands.

### Files to Create

**`src/package/source.rs`** (~150 lines)

```rust
/// Run `apm verify <package>`.
///
/// 1. Look up package in registry to get expected nar_hash
/// 2. Run `nix-store --dump <store_path>` to get current NAR
/// 3. Compute SHA-256 of NAR
/// 4. Compare against nar_hash
pub async fn verify(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm source <package>`.
///
/// --show-drv: print source derivation path
/// --fetch: download source derivation and inputs
/// --verify: rebuild from source and compare hash
pub async fn source(
    config: &ApmConfig,
    package: &str,
    fetch: bool,
    verify: bool,
    printer: &Printer,
) -> Result<()>;
```

### Registry Commands

Wire `apm registry add/remove/list`:

```rust
/// Run `apm registry add <url> [--priority=N]`.
///
/// 1. Fetch registry.toml from URL
/// 2. Extract registry name and signing key
/// 3. TOFU check
/// 4. Write config file to registries.d/
/// 5. Run initial sync (apm update for this registry)
pub async fn registry_add(
    config: &ApmConfig,
    url: &str,
    priority: u32,
    printer: &Printer,
) -> Result<()>;

/// Run `apm registry remove <name>`.
///
/// 1. Check if any installed packages are from this registry
/// 2. If yes: refuse with error listing the packages
/// 3. If no: delete config file and cached metadata
pub async fn registry_remove(
    config: &ApmConfig,
    name: &str,
    printer: &Printer,
) -> Result<()>;

/// Run `apm registry list`.
pub async fn registry_list(config: &ApmConfig, printer: &Printer) -> Result<()>;
```

### System Profile Support

Ensure all commands respect `--system` flag:

- Profile path: `/var/lib/profiles/system/`
- Config: `/etc/apm/` only (no user fallback)
- Registry cache: `/var/lib/apm/remote/`
- Registry state: `/var/lib/apm/registries.d/`
- Trusted keys: `/etc/apm/trusted-keys.d/` + `/var/lib/apm/trusted-keys.d/`
- Requires root (check euid at command start)

### Tests

- `apm verify curl` checks NAR hash against registry.
- Verify detects corrupted store path.
- Registry add writes config file and triggers TOFU.
- Registry remove refuses when packages are installed.
- Registry remove succeeds when no packages are installed.
- Registry list shows all configured registries.
- System scope commands check for root privileges.
- System scope uses correct paths (`/var/lib/apm/`).

### Acceptance Criteria

- `apm verify` validates installed packages against registry hashes.
- `apm source --verify` rebuilds from source and compares.
- `apm registry add` includes TOFU key verification.
- `apm registry remove` enforces clean uninstall requirement.
- `--system` correctly routes to system profile with isolated state.
- All commands support `--json` output where applicable.

---

## Integration Notes

After Phase 6 is complete:
- APM is feature-complete
- All 23 subcommands are implemented
- Security model is enforced (TOFU, signing, downgrade protection)
- System and user profiles both work
- `apm` alias works via argv[0] detection
- Full test coverage for all commands

## Post-Implementation Checklist

- [ ] All exit codes from cli.md are implemented
- [ ] `--json` output works for all query commands
- [ ] `--quiet` suppresses non-error output
- [ ] Man page for `apm` (can be auto-generated from clap)
- [ ] Integration tests: full install → upgrade → remove → gc cycle
- [ ] Nix package: create `apm` symlink alongside `aos` binary
