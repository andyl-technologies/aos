# Phase 2: Registry Sync

## Goal

Implement `apm update` — the registry synchronization system. After this phase,
`apm` can fetch registry metadata via HTTP bundles (default) or native git,
verify bundle and commit integrity, enforce downgrade protection, and populate
the local registry cache.

## Prerequisites

- Phase 1 complete (types, config, CLI scaffolding, TOML parsing)

## Design References

- [registry.md](../registry.md) — Bundle distribution, transport rules, versioning
- [security.md](../security.md) — Layers 1-3, downgrade protection, TOFU
- [cli.md](../cli.md) — `apm update` behavior

---

## Chunk 2A: HTTP Bundle Transport

### Files to Create

**`src/package/registry/bundle.rs`** (~350 lines)

HTTP bundle download, verification, and unbundling.

```rust
/// Bundle manifest entry from bundle-list.toml.
pub struct BundleEntry {
    pub uri: String,
    pub creation_token: u64,
    pub sha256: String,
    pub size: u64,
    pub bundle_type: BundleType,   // snapshot, sequential-delta, skip-delta
    pub base_tag: Option<String>,
    pub target_tag: String,
}

pub enum BundleType {
    Snapshot,
    SequentialDelta,
    SkipDelta,
}

/// Parsed bundle-list.toml manifest.
pub struct BundleManifest {
    pub version: u32,
    pub entries: Vec<BundleEntry>,
}

impl BundleManifest {
    /// Fetch and parse bundle-list.toml from a mirror URL.
    pub async fn fetch(client: &reqwest::Client, base_url: &str) -> Result<Self>;

    /// Filter entries newer than the given creation_token.
    pub fn entries_since(&self, token: u64) -> Vec<&BundleEntry>;

    /// Find the latest snapshot bundle.
    pub fn latest_snapshot(&self) -> Option<&BundleEntry>;

    /// Find the skip-ahead delta from a given minor base to latest.
    pub fn skip_delta_from(&self, base_tag: &str) -> Option<&BundleEntry>;
}

/// Download a bundle file, verify SHA-256 against manifest.
pub async fn download_bundle(
    client: &reqwest::Client,
    entry: &BundleEntry,
    base_url: &str,
    dest: &Path,
    printer: &Printer,
) -> Result<()>;

/// Verify a downloaded bundle file:
/// 1. SHA-256 matches manifest
/// 2. `git bundle verify` passes
pub fn verify_bundle(path: &Path, expected_sha256: &str) -> Result<()>;

/// Unbundle into the local registry git cache.
/// Runs `git bundle unbundle <path>` in the cache repo.
pub fn unbundle(bundle_path: &Path, repo_dir: &Path) -> Result<()>;
```

### External Commands Used

- `git bundle verify <path>` — check pack integrity
- `git bundle unbundle <path>` — import objects into local repo
- `git init --bare` — initialize local cache repo (first time)
- `sha256sum` / Rust `sha2` crate — hash verification

### Tests

- Parse a well-formed `bundle-list.toml` with snapshot and delta entries.
- `entries_since(token)` correctly filters by creation_token.
- `latest_snapshot()` returns the most recent snapshot.
- `skip_delta_from("v2026.02")` finds the right delta.
- SHA-256 verification catches corrupted downloads.
- `git bundle verify` integration test with a real bundle (create one in test setup).

### Acceptance Criteria

- Can download and verify a bundle from an HTTP mirror.
- SHA-256 mismatch produces `AosError::HashMismatch`.
- `git bundle verify` failure produces a clear error with recovery suggestion.
- Progress bar shown during download via `Printer`.

---

## Chunk 2B: Git Transport

### Files to Create

**`src/package/registry/git.rs`** (~200 lines)

Native git transport for development/advanced use.

```rust
/// Sync a git-transport registry.
///
/// Supports:
/// - Tag pinning: fetch specific tag
/// - Branch tracking: fetch HEAD of branch
/// - SHA pinning: verify specific commit
pub async fn sync_git(
    config: &RegistryConfig,
    cache_dir: &Path,
    state: &mut RegistryState,
    printer: &Printer,
) -> Result<SyncResult>;

pub struct SyncResult {
    pub new_commit: String,
    pub packages_added: usize,
    pub packages_updated: usize,
    pub packages_removed: usize,
}

/// Initialize or open a bare git repo for registry cache.
fn ensure_repo(cache_dir: &Path, url: &str) -> Result<PathBuf>;

/// Run `git fetch` with the appropriate refspec.
fn fetch_refs(repo_dir: &Path, url: &str, config: &RegistryConfig) -> Result<()>;

/// Verify commit signature if signing.required = true.
fn verify_commit_signature(
    repo_dir: &Path,
    commit: &str,
    signing: &SigningConfig,
) -> Result<()>;

/// Enforce fast-forward: new commit must be a descendant of last_commit.
fn enforce_fast_forward(
    repo_dir: &Path,
    old_commit: &str,
    new_commit: &str,
) -> Result<()>;

/// Extract package TOML files from the git tree into the parsed cache.
fn extract_packages(
    repo_dir: &Path,
    commit: &str,
    output_dir: &Path,
) -> Result<()>;
```

### External Commands Used

- `git fetch`, `git init --bare`
- `git log --verify-signatures` or `git verify-commit`
- `git merge-base --is-ancestor` (fast-forward check)
- `git archive` or `git show` (extract TOML files)

### Tests

- Sync from a local bare repo (create in test setup).
- Tag pinning fetches only the pinned tag.
- Branch tracking fetches HEAD of branch.
- Fast-forward violation is rejected.
- Signature verification with a test Ed25519 key.
- `SyncResult` correctly counts added/updated/removed packages.

### Acceptance Criteria

- `git+https://` and `git://` URLs trigger git transport.
- Fast-forward check prevents downgrade attacks.
- Commit signature verification works with Ed25519 SSH keys.
- Git transport does not use bundles; bundle transport does not use git fetch.

---

## Chunk 2C: Registry State & Update Orchestration

### Files to Create

**`src/package/registry/state.rs`** (~150 lines)

Update state tracking and downgrade protection.

```rust
/// Load the [registry.state] section from a registry config file.
pub fn load_state(config_path: &Path) -> Result<RegistryState>;

/// Save the [registry.state] section back to a registry config file.
/// Appends or replaces the section without modifying user-edited fields.
pub fn save_state(config_path: &Path, state: &RegistryState) -> Result<()>;

/// Check monotonic creation_token ordering.
pub fn check_monotonic(old_token: u64, new_token: u64) -> Result<()>;

/// Encode a version tag as a creation_token.
/// "v2026.02.3" -> 2026020003
pub fn version_to_token(tag: &str) -> Result<u64>;

/// Decode a creation_token to a version string.
/// 2026020003 -> "v2026.02.3"
pub fn token_to_version(token: u64) -> String;
```

### Files to Modify

**`src/package/mod.rs`** — Wire up `PackageCommand::Update`.

```rust
PackageCommand::Update { registry } => {
    update::run(&config, registry.as_deref(), &printer).await
}
```

### Files to Create

**`src/package/update.rs`** (~200 lines)

`apm update` implementation — orchestrates registry sync.

```rust
/// Run `apm update` — sync all (or one) registry.
pub async fn run(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    // For each enabled registry (or just the filtered one):
    // 1. Determine transport from URL scheme
    // 2. Dispatch to bundle::sync_bundle() or git::sync_git()
    // 3. Update [registry.state] in config file
    // 4. Re-parse TOML package files into cache
    // 5. Report results
}

/// Sync a single registry via HTTP bundles.
///
/// Client update algorithm (from registry.md):
/// 1. Fetch bundle-list.toml
/// 2. Compare creation_token against local state
/// 3. Download required bundles (snapshot or deltas)
/// 4. Verify SHA-256, git bundle verify
/// 5. Commit signature verification (if signing.required)
/// 6. Fast-forward check
/// 7. Extract package TOML files
/// 8. Update local state
pub async fn sync_bundle(
    config: &RegistryConfig,
    cache_dir: &Path,
    state: &mut RegistryState,
    printer: &Printer,
) -> Result<SyncResult>;
```

### Tests

- `version_to_token("v2026.02.3")` → `2026020003`.
- `token_to_version(2026020003)` → `"v2026.02.3"`.
- Monotonic check rejects old token.
- State round-trips through save/load without corrupting user config fields.
- Full update flow with a mock HTTP server (bundle-list.toml + bundle files).

### Acceptance Criteria

- `apm update` syncs all enabled registries.
- `apm update --registry=aos-core` syncs only that registry.
- Bundle transport: downloads only bundles newer than `last_creation_token`.
- First-time bootstrap downloads the latest snapshot.
- Downgrade protection enforced via `creation_token` monotonic check + git
  fast-forward.
- Output matches examples.md format:
  ```
  Fetching registry 'aos-core' ... done (143 packages, 5 updated)
  ```

---

## Integration Notes

After Phase 2 is complete:
- `apm update` is fully functional
- Local registry caches are populated with parsed TOML package files
- Both HTTP bundle and git transports work
- Downgrade protection is enforced
- Registry state is persisted in config files
- `RegistrySet` can be loaded from the cache for resolution (used in Phase 5)
