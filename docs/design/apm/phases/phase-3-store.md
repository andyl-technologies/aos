# Phase 3: Store Operations

## Goal

Implement the NAR download, hash verification, and store import pipeline. After
this phase, APM can download compressed NARs from HTTPS mirrors, verify them
through the full hash chain, import them into the Nix store, and create GC
roots.

## Prerequisites

- Phase 1 complete (types, config, registry TOML parsing)

## Design References

- [store.md](../store.md) — NAR operations, hash verification, GC roots
- [security.md](../security.md) — Layers 4-5, hash chain
- [packages.md](../packages.md) — `nar_hash`, `download_hash` fields
- [convergence.md](../convergence.md) — `usr/{hash}`, `src/{hash}` root layout

---

## Chunk 3A: NAR Download Engine

### Files to Create

**`src/package/download.rs`** (~300 lines)

Parallel HTTPS NAR download with progress reporting.

```rust
/// A NAR to download.
pub struct DownloadRequest {
    pub store_path: String,
    pub nar_hash: String,         // used in URL: <mirror>/<nar_hash>.nar.zst
    pub download_hash: String,    // SHA-256 of compressed file
    pub download_size: u64,
    pub mirror_url: String,
}

/// Result of a successful download.
pub struct DownloadResult {
    pub store_path: String,
    pub local_path: PathBuf,      // path to downloaded .nar.zst in cache
    pub download_hash: String,
    pub nar_hash: String,
}

/// Download multiple NARs in parallel.
///
/// - Uses `config.settings.parallel_downloads` concurrency limit.
/// - Shows per-file progress bars via Printer.
/// - Downloads to ~/.cache/apm/ (user) or /var/lib/apm/cache/ (system).
/// - Retries each download up to 3 times on network error.
pub async fn download_nars(
    client: &reqwest::Client,
    requests: &[DownloadRequest],
    cache_dir: &Path,
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<DownloadResult>>;

/// Download a single NAR file.
async fn download_one(
    client: &reqwest::Client,
    req: &DownloadRequest,
    dest: &Path,
    printer: &Printer,
) -> Result<DownloadResult>;

/// Construct the download URL for a NAR.
/// <mirror_url>/<nar_hash>.nar.zst
pub fn nar_url(mirror_url: &str, nar_hash: &str) -> String;

/// Determine the mirror URL for a package.
/// Uses the first available mirror from the registry config, falling back
/// to the registry URL + "/nar/".
pub fn resolve_mirror(registry: &RegistryConfig, package: &PackageMeta) -> String;
```

### Tests

- `nar_url("https://cache.aos.dev/nar", "sha256:abc123")` produces correct URL.
- Parallel download with 2 concurrent fetches and a mock HTTP server.
- Retry on transient HTTP error (503).
- Abort on 404 with `AosError::DownloadError`.
- Progress bars update correctly during download.
- Downloaded files land in the expected cache directory.

### Acceptance Criteria

- Downloads NARs in parallel with configurable concurrency.
- Each download shows a progress bar with filename, size, and speed.
- Retries transient errors up to 3 times with backoff.
- Cache directory is created if it doesn't exist.
- Clean error messages on network failure.

---

## Chunk 3B: Hash Verification Chain

### Files to Create

**`src/package/verify.rs`** (~200 lines)

Three-layer hash verification matching security.md Layers 4-5.

```rust
/// Verify a downloaded NAR file through the full hash chain.
///
/// Layer 4a: SHA-256 of compressed file matches download_hash.
/// Layer 4b: Decompress and SHA-256 of raw NAR matches nar_hash.
/// Layer 5:  After store import, resulting store path matches expected.
pub struct VerifyResult {
    pub download_hash_ok: bool,
    pub nar_hash_ok: bool,
    pub store_path_ok: bool,
}

/// Verify the compressed NAR download hash (Layer 4a).
///
/// Computes SHA-256 of the file at `path` and compares against `expected`.
pub fn verify_download_hash(path: &Path, expected: &str) -> Result<()>;

/// Verify the decompressed NAR hash (Layer 4b).
///
/// Decompresses the .nar.zst file and computes SHA-256 of the raw NAR
/// content. Compares against `expected`.
///
/// Uses streaming decompression to avoid loading the full NAR into memory.
pub fn verify_nar_hash(path: &Path, expected: &str) -> Result<()>;

/// Verify the store path after import (Layer 5).
///
/// Checks that the path returned by `nix-store --import` matches the
/// expected store_path from the package TOML.
pub fn verify_store_path(actual: &str, expected: &str) -> Result<()>;

/// Compute SHA-256 of a file, returning "sha256:<hex>" format.
pub fn sha256_file(path: &Path) -> Result<String>;

/// Compute SHA-256 of a stream, returning "sha256:<hex>" format.
pub fn sha256_stream(reader: impl Read) -> Result<String>;

/// Verify an installed package against registry metadata.
/// Used by `apm verify <pkg>`.
///
/// 1. Look up the package in the registry to get expected nar_hash.
/// 2. Run `nix-store --dump <store_path>` to get the current NAR.
/// 3. Compute SHA-256 of the NAR.
/// 4. Compare against nar_hash from registry.
pub async fn verify_installed(
    store_path: &str,
    expected_nar_hash: &str,
) -> Result<()>;
```

### Tests

- `verify_download_hash` succeeds for matching hash.
- `verify_download_hash` fails with `HashMismatch` for wrong hash.
- `verify_nar_hash` correctly decompresses zstd and computes hash.
- `verify_store_path` catches path mismatch.
- `sha256_file` produces correct hex digest for known content.
- Streaming SHA-256 produces same result as whole-file.
- `verify_installed` runs `nix-store --dump` and checks hash.

### Acceptance Criteria

- All three verification layers are independent functions.
- Hash format is `"sha256:<hex>"` throughout (matching packages.md).
- Verification errors include both expected and actual hashes.
- Streaming verification handles large NARs without OOM.

---

## Chunk 3C: Store Import & GC Root Management

### Files to Create

**`src/package/store.rs`** (~250 lines)

Import NARs into the Nix store and create GC roots in profiles.

```rust
/// Import a verified NAR into the Nix store.
///
/// 1. Decompress .nar.zst
/// 2. Run `nix-store --import < <nar>`
/// 3. Verify resulting store path (Layer 5)
/// 4. Return the store path
pub async fn import_nar(
    nar_path: &Path,
    expected_store_path: &str,
) -> Result<String>;

/// Check which store paths from a closure are already present locally.
///
/// Uses NixStore::is_valid_path() from server/store.rs.
pub fn filter_missing(
    nix_store: &NixStore,
    store_paths: &[String],
) -> Vec<String>;

/// Create GC roots for a set of store paths in a profile generation.
///
/// For each path, creates:
///   gen-N/usr/{hash} -> /var/lib/store/{hash}-pkg-version
///
/// For packages with source_drv, also creates:
///   gen-N/src/{hash} -> /var/lib/store/{hash}-pkg-version.drv
///
/// Uses atomic symlink creation (temp file + rename).
pub fn create_gc_roots(
    gen_dir: &Path,
    packages: &[PackageMeta],
) -> Result<()>;

/// Remove GC roots for a set of store paths from a profile generation.
pub fn remove_gc_roots(
    gen_dir: &Path,
    hashes: &[String],
) -> Result<()>;

/// Walk the store reference graph for a store path.
///
/// Runs `nix-store -qR <path>` to get the full closure.
/// Returns all transitive references.
pub async fn closure_paths(store_path: &str) -> Result<Vec<String>>;

/// Query references of a single store path.
///
/// Runs `nix-store -q --references <path>`.
pub async fn direct_references(store_path: &str) -> Result<Vec<String>>;
```

### Reuse from Existing Code

- `server::store::NixStore` — `is_valid_path()`, `path_info()`
- `server::views::ViewManager` — `store_path_hash()` utility function
  (extract or duplicate into `package/types.rs`)

### Tests

- `import_nar` with a real .nar.zst file (create in test setup using
  `nix-store --dump | zstd`).
- `filter_missing` correctly identifies present vs absent paths.
- `create_gc_roots` creates correct symlinks with expected targets.
- `remove_gc_roots` cleans up symlinks.
- `closure_paths` returns transitive closure for a known store path.
- Atomic symlink creation doesn't leave partial state on error.

### Acceptance Criteria

- NAR import pipeline: decompress → import → verify store path.
- GC root symlinks follow the `usr/{hash}` naming convention.
- Source derivation roots use `src/{hash}` naming.
- `filter_missing` allows skipping already-cached paths.
- All file operations use atomic write (temp + rename).

---

## Integration Notes

After Phase 3 is complete:
- NARs can be downloaded from HTTPS mirrors in parallel
- Full hash verification chain (download_hash → nar_hash → store_path)
- NARs can be imported into the Nix store
- GC roots can be created/removed in profile generation directories
- Store reference graph can be queried
- Combined with Phase 2, the registry-to-store pipeline is complete
  (resolution + download + verify + import + roots)
