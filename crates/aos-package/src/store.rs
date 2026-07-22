//! Nix store interactions: NAR import, validity checks, and GC roots.
//!
//! This module is apm's boundary with the Nix store, shelling out to
//! `nix-store` (with [`aos_nix_env`] so `AOS_ROOT`-relative stores work):
//!
//! - [`import_nar`] turns a downloaded `.nar.zst` plus its narinfo metadata
//!   into a valid store path via `nix-store --import`, synthesizing the
//!   export-format trailer (path, references, deriver) the import expects.
//! - [`filter_missing`] checks which closure members still need downloading
//!   (`nix-store --check-validity`).
//! - [`create_gc_roots`] / [`remove_gc_roots`] maintain the per-generation
//!   symlink farms (`gen-N/usr/<hash>` for package outputs, `gen-N/src/<hash>`
//!   for source derivations) that keep installed paths alive across GC.
//! - [`closure_paths`] / [`direct_references`] query the on-disk reference
//!   graph for removal and dependency commands.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use aos_core::nar::export::ExportTrailer;
use aos_core::nix::aos_nix_env;

use super::registry::store_path_hash;
use super::types::PackageMeta;
use super::verify::verify_store_path;

// ---------------------------------------------------------------------------
// NAR import
// ---------------------------------------------------------------------------

/// Import a compressed NAR (`.nar.zst`) into the Nix store.
///
/// The cache serves a *plain* NAR (`nix-store --dump` output), but
/// `nix-store --import` consumes the *export* format — a NAR followed by a
/// metadata trailer (store path, references, deriver). We reconstruct that
/// trailer from the narinfo metadata and stream NAR + trailer into the
/// import process.
///
/// Steps:
///   1. Decompress the `.nar.zst` file via `zstd -d` to a temporary `.nar`.
///   2. Stream the NAR plus a synthesized `ExportTrailer` into
///      `nix-store --import`.
///   3. Verify the resulting store path matches `expected_store_path`.
///   4. Clean up the temporary decompressed file.
///
/// `references` and `deriver` come from the narinfo. `references` may be
/// store-path basenames or full paths; bare basenames are resolved against
/// the active store directory.
///
/// Returns the imported store path on success.
///
/// # Errors
///
/// Returns an error if zstd decompression fails, the decompressed NAR
/// cannot be read, `nix-store --import` fails or produces unparseable
/// output, or the imported path differs from `expected_store_path`
/// ([`AosError::HashMismatch`](aos_core::error::AosError::HashMismatch)).
pub async fn import_nar(
    nar_path: &Path,
    expected_store_path: &str,
    references: &[String],
    deriver: Option<&str>,
) -> Result<String> {
    // Decompress .nar.zst -> .nar alongside the original file.
    let decompressed = nar_path.with_extension("");
    let zstd_output = Command::new("zstd")
        .args([
            "-d",
            "-f",
            &nar_path.display().to_string(),
            "-o",
            &decompressed.display().to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("running zstd decompression")?;

    if !zstd_output.status.success() {
        let stderr = String::from_utf8_lossy(&zstd_output.stderr);
        bail!(
            "zstd decompression failed for {}: {}",
            nar_path.display(),
            stderr.trim()
        );
    }

    let nar_data = tokio::fs::read(&decompressed)
        .await
        .with_context(|| format!("reading decompressed NAR {}", decompressed.display()))?;

    // Clean up the decompressed file now that it's in memory.
    let _ = tokio::fs::remove_file(&decompressed).await;

    // Resolve the store directory references are rooted under, so bare
    // basenames from the narinfo become full paths in the export trailer.
    let store_dir = store_dir_of(expected_store_path);
    let full_refs: Vec<String> = references
        .iter()
        .map(|r| resolve_store_path(r, &store_dir))
        .collect();
    let full_deriver = deriver.map(|d| resolve_store_path(d, &store_dir));

    let trailer = ExportTrailer::new(expected_store_path, full_refs, full_deriver);

    // Stream NAR + trailer into `nix-store --import`. aos_nix_env() routes
    // the import at AOS_ROOT's store when that env var is set.
    let import_output = tokio::task::spawn_blocking(move || -> Result<std::process::Output> {
        let mut child = std::process::Command::new("nix-store")
            .envs(aos_nix_env())
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning nix-store --import")?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .context("no stdin for nix-store --import")?;
            trailer
                .write_import_stream(stdin, &nar_data)
                .context("writing export stream")?;
        }
        child
            .wait_with_output()
            .context("waiting for nix-store --import")
    })
    .await
    .context("import task panicked")??;

    if !import_output.status.success() {
        let stderr = String::from_utf8_lossy(&import_output.stderr);
        bail!(
            "nix-store --import failed for {}: {}",
            nar_path.display(),
            stderr.trim()
        );
    }

    // Parse the imported store path from stdout (one path per line; take the
    // last non-empty line which is the top-level path).
    let stdout = String::from_utf8_lossy(&import_output.stdout);
    let imported_path = parse_import_output(&stdout)?;

    // Verify it matches what we expected.
    verify_store_path(&imported_path, expected_store_path)?;

    Ok(imported_path)
}

/// Derive the store directory from a full store path.
///
/// `"/var/lib/aos/store/abc-foo-1.0"` → `"/var/lib/aos/store"`.
/// Falls back to `/nix/store` when the path has no parent.
fn store_dir_of(store_path: &str) -> String {
    Path::new(store_path)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/nix/store".to_string())
}

/// Resolve a narinfo reference (bare basename or full path) to a full path
/// rooted under `store_dir`.
fn resolve_store_path(reference: &str, store_dir: &str) -> String {
    if reference.starts_with('/') {
        reference.to_string()
    } else {
        format!("{store_dir}/{reference}")
    }
}

/// Extract the imported store path from `nix-store --import` stdout.
///
/// The output may contain multiple lines (one per imported path).  The last
/// non-empty line is the top-level path we care about.
fn parse_import_output(stdout: &str) -> Result<String> {
    let path = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string());

    match path {
        Some(p) if p.starts_with('/') => Ok(p),
        Some(p) => bail!("unexpected nix-store --import output: {p}"),
        None => bail!("nix-store --import produced no output"),
    }
}

// ---------------------------------------------------------------------------
// Store path validity checking
// ---------------------------------------------------------------------------

/// Check which store paths from a list are missing (not yet in the store).
///
/// For each path, runs `nix-store --check-validity <path>` which exits 0
/// if valid, non-zero if missing. Returns only the missing paths.
///
/// This does NOT use `server::store::NixStore` since that is a different
/// abstraction for the cache server. Instead it runs `nix-store` directly.
///
/// # Errors
///
/// Returns an error if `nix-store` cannot be spawned. A non-zero exit for a
/// path is not an error -- it marks the path as missing.
pub async fn filter_missing(store_paths: &[String]) -> Result<Vec<String>> {
    let mut missing = Vec::new();

    for path in store_paths {
        let status = Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--check-validity", path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .with_context(|| format!("running nix-store --check-validity {path}"))?;

        if !status.success() {
            missing.push(path.clone());
        }
    }

    Ok(missing)
}

// ---------------------------------------------------------------------------
// GC root management
// ---------------------------------------------------------------------------

/// Create GC roots for installed packages in a profile generation directory.
///
/// For each package:
///   `gen_dir/usr/{hash}` -> `{store_path}`
///
/// For packages with a non-empty `source_drv`:
///   `gen_dir/src/{drv_hash}` -> `{source_drv}`
///
/// Uses `std::os::unix::fs::symlink` for atomic symlink creation.
///
/// # Errors
///
/// Returns an error if the `usr/`/`src/` directories cannot be created or a
/// symlink cannot be created or renamed into place.
pub fn create_gc_roots(gen_dir: &Path, packages: &[PackageMeta]) -> Result<()> {
    let usr_dir = gen_dir.join("usr");
    let src_dir = gen_dir.join("src");

    std::fs::create_dir_all(&usr_dir).with_context(|| format!("creating {}", usr_dir.display()))?;
    std::fs::create_dir_all(&src_dir).with_context(|| format!("creating {}", src_dir.display()))?;

    for meta in packages {
        // Create usr/{hash} -> store_path
        let hash = store_path_hash(&meta.store_path);
        let usr_link = usr_dir.join(hash);
        atomic_symlink(&meta.store_path, &usr_link).with_context(|| {
            format!(
                "creating GC root {} -> {}",
                usr_link.display(),
                meta.store_path
            )
        })?;

        // Create src/{drv_hash} -> source_drv (if source_drv is non-empty)
        if !meta.source_drv.is_empty() {
            let drv_hash = store_path_hash(&meta.source_drv);
            let src_link = src_dir.join(drv_hash);
            atomic_symlink(&meta.source_drv, &src_link).with_context(|| {
                format!(
                    "creating GC root {} -> {}",
                    src_link.display(),
                    meta.source_drv
                )
            })?;
        }
    }

    Ok(())
}

/// Creates the configuration-generation GC roots: `cfg/` (manifest outputs)
/// and `cfgsrc/` (config-module source closure + `host.nix`).
///
/// Extends the per-generation symlink farm written by [`create_gc_roots`] with
/// the two roots the on-host config evaluator needs (build-spec §2). Each is a
/// directory of `<hash> -> <store path>` symlinks `nix-store --gc` honors:
///
/// - `gen_dir/cfg/<hash>` pins the realized **manifest outputs** — rendered
///   `/etc` trees, unit files, job-script texts, the toplevel — so a same-ABI
///   rollback is a pure pointer switch (the output is already on disk).
/// - `gen_dir/cfgsrc/<hash>` pins the eval **inputs**: the config-module
///   *source* closure and the `host.nix` store path. This is the load-bearing
///   addition (review M-gc-inputs): `cfg/` pins outputs, which reference
///   package *runtime* closures, **not** the config-module source NARs nor
///   `host.nix`; without `cfgsrc/` a plain `apm gc` would collect the inputs
///   and break cross-ABI re-eval.
///
/// Both `cfg_outputs` and `cfgsrc_inputs` are absolute store paths. The two
/// directories live inside `gen_dir`, so [`crate::profile::Profile::prune_generations`]
/// (which removes the whole `gen-N/` directory) drops them together with the
/// generation.
///
/// # Errors
///
/// Returns an error if either directory cannot be created or a symlink cannot
/// be created or renamed into place.
pub fn create_config_gc_roots(
    gen_dir: &Path,
    cfg_outputs: &[String],
    cfgsrc_inputs: &[String],
) -> Result<()> {
    write_store_path_roots(&gen_dir.join("cfg"), cfg_outputs)?;
    write_store_path_roots(&gen_dir.join("cfgsrc"), cfgsrc_inputs)?;
    Ok(())
}

/// Create the image-scoped `image-gen-N/baselib/<module_abi>` GC root
/// retained by the active configuration generations.
///
/// Pins **only** the base-lib + evaluator closure of one image-generation —
/// not the kernel/initrd/whole UKI — keyed by the image's `module_abi`. This is
/// the per-image-gen retention root that keeps ≥1 prior base lib alive on
/// `/var` independent of the ESP ×2 UKI slot count, so cross-pruned-image
/// rollback re-eval is always satisfiable without re-download.
///
/// `image_gen_dir` is the `image-gen-N/` directory; `evaluator_ref` is the
/// store path of the base-lib + evaluator closure
/// ([`crate::types::ImageGeneration::evaluator_ref`]).
///
/// # Errors
///
/// Returns an error if the `baselib/` directory cannot be created or the
/// symlink cannot be written.
pub fn create_baselib_gc_root(
    image_gen_dir: &Path,
    module_abi: u32,
    evaluator_ref: &str,
) -> Result<()> {
    let baselib_dir = image_gen_dir.join("baselib");
    std::fs::create_dir_all(&baselib_dir)
        .with_context(|| format!("creating {}", baselib_dir.display()))?;
    let link = baselib_dir.join(module_abi.to_string());
    atomic_symlink(evaluator_ref, &link).with_context(|| {
        format!(
            "creating baselib GC root {} -> {evaluator_ref}",
            link.display()
        )
    })
}

/// Computes which `baselib/<module_abi>` roots to retain across
/// §4, OQ1 — "keep ≥1 prior base lib on `/var`, never re-download").
///
/// A base-lib root for `module_abi = K` is retained iff **either** (a) `K` is
/// one of the ESP-resident image-gens (the A/B slots), **or** (b) at least one
/// retained config-gen records `module_abi_pinned == K`. On top of that an
/// absolute **floor** applies: at least one *prior distinct* ABI (a candidate
/// `!= running`) must survive, so cross-ABI rollback re-eval is always
/// satisfiable from `/var`. When (a)/(b) alone leave no prior ABI, the most
/// recent prior candidate (highest ABI below `running`, else the highest
/// distinct candidate) is added to honor the floor.
///
/// - `candidates` — every image-gen `module_abi` that currently has a base-lib
///   closure on disk.
/// - `esp_resident` — the `module_abi`s of the ESP-resident (A/B) image-gens.
/// - `pinned_by_configgens` — the `module_abi_pinned` of every *retained*
///   config-gen.
/// - `running` — the running image's `module_abi`.
///
/// Returns the set of `module_abi`s whose `baselib/` root must be kept; any
/// candidate outside the returned set is collectable.
pub fn baselib_retention_set(
    candidates: &[u32],
    esp_resident: &std::collections::BTreeSet<u32>,
    pinned_by_configgens: &std::collections::BTreeSet<u32>,
    running: u32,
) -> std::collections::BTreeSet<u32> {
    let mut keep = std::collections::BTreeSet::new();
    for &abi in candidates {
        if esp_resident.contains(&abi) || pinned_by_configgens.contains(&abi) {
            keep.insert(abi);
        }
    }

    // Floor: guarantee at least one retained *prior* ABI (distinct from the
    // running one) so a cross-ABI rollback can always re-eval from /var.
    let has_prior = keep.iter().any(|&abi| abi != running);
    if !has_prior {
        // Prefer the most recent prior ABI (highest candidate below running);
        // otherwise the highest distinct candidate at all.
        let prior = candidates
            .iter()
            .copied()
            .filter(|&abi| abi < running)
            .max()
            .or_else(|| candidates.iter().copied().filter(|&abi| abi != running).max());
        if let Some(abi) = prior {
            keep.insert(abi);
        }
    }

    keep
}

/// Write a `<hash> -> <store path>` symlink farm under `dir`, creating `dir`.
///
/// Shared by the `cfg/` and `cfgsrc/` root writers. Each input is an absolute
/// store path; its 32-character store-path hash names the symlink. Duplicate
/// paths collapse to one symlink (idempotent via [`atomic_symlink`]).
fn write_store_path_roots(dir: &Path, paths: &[String]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for path in paths {
        let hash = store_path_hash(path);
        let link = dir.join(hash);
        atomic_symlink(path, &link)
            .with_context(|| format!("creating GC root {} -> {path}", link.display()))?;
    }
    Ok(())
}

/// Remove GC roots for the given store path hashes from a generation.
///
/// Removes `gen_dir/usr/{hash}` and `gen_dir/src/{hash}` symlinks.  Silently
/// ignores hashes for which the symlinks do not exist (idempotent).
///
/// # Errors
///
/// Returns an error if an existing symlink cannot be removed.
pub fn remove_gc_roots(gen_dir: &Path, hashes: &[String]) -> Result<()> {
    let usr_dir = gen_dir.join("usr");
    let src_dir = gen_dir.join("src");

    for hash in hashes {
        let usr_link = usr_dir.join(hash);
        if usr_link.symlink_metadata().is_ok() {
            std::fs::remove_file(&usr_link)
                .with_context(|| format!("removing {}", usr_link.display()))?;
        }

        let src_link = src_dir.join(hash);
        if src_link.symlink_metadata().is_ok() {
            std::fs::remove_file(&src_link)
                .with_context(|| format!("removing {}", src_link.display()))?;
        }
    }

    Ok(())
}

/// Create a symlink atomically by writing to a temp name and renaming.
///
/// On Unix, `std::os::unix::fs::symlink` itself is atomic, but if the link
/// already exists we need to replace it.  We create a temporary symlink next
/// to the target and rename over.
fn atomic_symlink(target: &str, link_path: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    // If the symlink already points to the correct target, nothing to do.
    if let Ok(existing) = std::fs::read_link(link_path) {
        if existing.to_string_lossy() == target {
            return Ok(());
        }
    }

    // Build a temp path next to the final link location.
    let parent = link_path
        .parent()
        .context("symlink has no parent directory")?;
    let file_name = link_path
        .file_name()
        .context("symlink has no file name")?
        .to_string_lossy();
    let tmp_name = format!(".{file_name}.tmp.{}", std::process::id());
    let tmp_path = parent.join(&tmp_name);

    // Remove stale temp file if it exists.  There is a brief window between
    // this removal and the symlink creation below where another process with
    // the same PID could race; however, the subsequent `rename` is atomic on
    // POSIX filesystems, so the final link path is always either the old
    // target or the new target — never a partially-written state.
    let _ = std::fs::remove_file(&tmp_path);

    // Create temp symlink and atomically rename over the final path.
    symlink(target, &tmp_path)
        .with_context(|| format!("creating temp symlink {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, link_path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), link_path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Store closure queries
// ---------------------------------------------------------------------------

/// Walk the store reference graph for a store path.
///
/// Runs `nix-store -qR <path>` to get the full transitive closure.
/// Returns one store path per line.
///
/// # Errors
///
/// Returns an error if `nix-store` cannot be spawned or exits non-zero
/// (e.g. the path is not valid in the store).
pub async fn closure_paths(store_path: &str) -> Result<Vec<String>> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["-qR", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("running nix-store -qR {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix-store -qR failed for {store_path}: {}", stderr.trim());
    }

    Ok(parse_path_lines(&String::from_utf8_lossy(&output.stdout)))
}

/// Query direct references of a single store path.
///
/// Runs `nix-store -q --references <path>`.
///
/// # Errors
///
/// Returns an error if `nix-store` cannot be spawned or exits non-zero
/// (e.g. the path is not valid in the store).
pub async fn direct_references(store_path: &str) -> Result<Vec<String>> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["-q", "--references", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("running nix-store -q --references {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store -q --references failed for {store_path}: {}",
            stderr.trim()
        );
    }

    Ok(parse_path_lines(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse newline-separated store paths from command output.
fn parse_path_lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helper: build a PackageMeta for testing
    // -----------------------------------------------------------------------
    fn test_package(name: &str, hash: &str, source_drv: &str) -> PackageMeta {
        PackageMeta {
            name: name.into(),
            version: "1.0.0".into(),
            description: format!("{name} test package"),
            homepage: None,
            license: "MIT".into(),
            maintainer: "test".into(),
            platform: "x86_64-linux".into(),
            store_path: format!("/var/lib/store/{hash}-{name}-1.0.0"),
            nar_hash: "sha256:0000".into(),
            nar_size: 1024,
            references: vec![],
            source_drv: source_drv.into(),
            source_nar_hash: "sha256:2222".into(),
            closure_size: 2048,
            sysroot: false,
            previous: None,
            images: vec![],
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        }
    }

    // -----------------------------------------------------------------------
    // create_gc_roots tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_gc_roots_creates_usr_and_src_dirs() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        assert!(gen_dir.join("usr").is_dir());
        assert!(gen_dir.join("src").is_dir());
    }

    #[test]
    fn create_gc_roots_creates_correct_usr_symlink() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        let usr_link = gen_dir.join("usr/abc123");
        assert!(
            usr_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let target = std::fs::read_link(&usr_link).unwrap();
        assert_eq!(target.to_string_lossy(), "/var/lib/store/abc123-curl-1.0.0");
    }

    #[test]
    fn create_gc_roots_creates_correct_src_symlink() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        let src_link = gen_dir.join("src/def456");
        assert!(
            src_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let target = std::fs::read_link(&src_link).unwrap();
        assert_eq!(
            target.to_string_lossy(),
            "/var/lib/store/def456-curl-1.0.0.drv"
        );
    }

    #[test]
    fn create_gc_roots_skips_empty_source_drv() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package("zlib", "xyz789", "")];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // usr symlink should exist
        let usr_link = gen_dir.join("usr/xyz789");
        assert!(usr_link.symlink_metadata().is_ok());

        // src directory should exist but be empty (no source drv)
        let src_dir = gen_dir.join("src");
        assert!(src_dir.is_dir());
        let entries: Vec<_> = std::fs::read_dir(&src_dir).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn create_gc_roots_multiple_packages() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![
            test_package("curl", "abc123", "/var/lib/store/def456-curl-1.0.0.drv"),
            test_package("zlib", "ghi789", "/var/lib/store/jkl012-zlib-1.0.0.drv"),
        ];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // Both usr symlinks should exist
        assert!(gen_dir.join("usr/abc123").symlink_metadata().is_ok());
        assert!(gen_dir.join("usr/ghi789").symlink_metadata().is_ok());

        // Both src symlinks should exist
        assert!(gen_dir.join("src/def456").symlink_metadata().is_ok());
        assert!(gen_dir.join("src/jkl012").symlink_metadata().is_ok());
    }

    #[test]
    fn create_gc_roots_idempotent() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        // Run twice — should succeed both times.
        create_gc_roots(&gen_dir, &packages).unwrap();
        create_gc_roots(&gen_dir, &packages).unwrap();

        let usr_link = gen_dir.join("usr/abc123");
        let target = std::fs::read_link(&usr_link).unwrap();
        assert_eq!(target.to_string_lossy(), "/var/lib/store/abc123-curl-1.0.0");
    }

    // -----------------------------------------------------------------------
    // remove_gc_roots tests
    // -----------------------------------------------------------------------

    #[test]
    fn remove_gc_roots_removes_symlinks() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // Verify links exist before removal.
        assert!(gen_dir.join("usr/abc123").symlink_metadata().is_ok());
        assert!(gen_dir.join("src/def456").symlink_metadata().is_ok());

        // Remove using the package hash.
        remove_gc_roots(&gen_dir, &["abc123".into()]).unwrap();

        assert!(gen_dir.join("usr/abc123").symlink_metadata().is_err());
        // src/def456 was created with the drv hash, not the package hash,
        // so it should still exist.
        assert!(gen_dir.join("src/def456").symlink_metadata().is_ok());
    }

    #[test]
    fn remove_gc_roots_removes_src_by_drv_hash() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "abc123",
            "/var/lib/store/def456-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // Remove the src symlink using the drv hash.
        remove_gc_roots(&gen_dir, &["def456".into()]).unwrap();

        assert!(gen_dir.join("src/def456").symlink_metadata().is_err());
        // usr/abc123 should still exist since we only removed by drv hash.
        assert!(gen_dir.join("usr/abc123").symlink_metadata().is_ok());
    }

    #[test]
    fn remove_gc_roots_idempotent() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        // Create the directory structure but no symlinks.
        std::fs::create_dir_all(gen_dir.join("usr")).unwrap();
        std::fs::create_dir_all(gen_dir.join("src")).unwrap();

        // Removing non-existent hashes should not error.
        remove_gc_roots(&gen_dir, &["nonexistent".into()]).unwrap();
    }

    #[test]
    fn remove_gc_roots_multiple_hashes() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![
            test_package("curl", "abc123", "/var/lib/store/def456-curl-1.0.0.drv"),
            test_package("zlib", "ghi789", "/var/lib/store/jkl012-zlib-1.0.0.drv"),
        ];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // Remove both package hashes.
        remove_gc_roots(&gen_dir, &["abc123".into(), "ghi789".into()]).unwrap();

        assert!(gen_dir.join("usr/abc123").symlink_metadata().is_err());
        assert!(gen_dir.join("usr/ghi789").symlink_metadata().is_err());
    }

    // -----------------------------------------------------------------------
    // Symlink naming convention tests
    // -----------------------------------------------------------------------

    #[test]
    fn usr_symlink_uses_store_path_hash() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "h7j3k8l2m9n4",
            "/var/lib/store/i8k4l9m3n0o5-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // The usr symlink name should be the hash extracted from the store path.
        let usr_link = gen_dir.join("usr/h7j3k8l2m9n4");
        assert!(usr_link.symlink_metadata().is_ok());
    }

    #[test]
    fn src_symlink_uses_drv_path_hash() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");

        let packages = vec![test_package(
            "curl",
            "h7j3k8l2m9n4",
            "/var/lib/store/i8k4l9m3n0o5-curl-1.0.0.drv",
        )];

        create_gc_roots(&gen_dir, &packages).unwrap();

        // The src symlink name should be the hash extracted from the drv path.
        let src_link = gen_dir.join("src/i8k4l9m3n0o5");
        assert!(src_link.symlink_metadata().is_ok());
    }

    // -----------------------------------------------------------------------
    // parse_import_output tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_import_output_single_path() {
        let output = "/var/lib/store/abc123-curl-8.5.0\n";
        let path = parse_import_output(output).unwrap();
        assert_eq!(path, "/var/lib/store/abc123-curl-8.5.0");
    }

    #[test]
    fn parse_import_output_multiple_paths() {
        let output = "/var/lib/store/dep1-zlib-1.3.1\n\
                       /var/lib/store/dep2-openssl-3.2.0\n\
                       /var/lib/store/abc123-curl-8.5.0\n";
        let path = parse_import_output(output).unwrap();
        assert_eq!(path, "/var/lib/store/abc123-curl-8.5.0");
    }

    #[test]
    fn parse_import_output_trailing_whitespace() {
        let output = "  /var/lib/store/abc123-curl-8.5.0  \n\n";
        let path = parse_import_output(output).unwrap();
        assert_eq!(path, "/var/lib/store/abc123-curl-8.5.0");
    }

    #[test]
    fn parse_import_output_empty() {
        let result = parse_import_output("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no output"));
    }

    #[test]
    fn parse_import_output_unexpected() {
        let result = parse_import_output("some unexpected output\n");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected"));
    }

    // -----------------------------------------------------------------------
    // parse_path_lines tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_path_lines_basic() {
        let output = "/var/lib/store/aaa-foo-1.0\n\
                       /var/lib/store/bbb-bar-2.0\n\
                       /var/lib/store/ccc-baz-3.0\n";
        let paths = parse_path_lines(output);
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], "/var/lib/store/aaa-foo-1.0");
        assert_eq!(paths[1], "/var/lib/store/bbb-bar-2.0");
        assert_eq!(paths[2], "/var/lib/store/ccc-baz-3.0");
    }

    #[test]
    fn parse_path_lines_empty() {
        let paths = parse_path_lines("");
        assert!(paths.is_empty());
    }

    #[test]
    fn parse_path_lines_with_blank_lines() {
        let output = "/var/lib/store/aaa-foo-1.0\n\n\n/var/lib/store/bbb-bar-2.0\n\n";
        let paths = parse_path_lines(output);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn parse_path_lines_trims_whitespace() {
        let output = "  /var/lib/store/aaa-foo-1.0  \n  /var/lib/store/bbb-bar-2.0\t\n";
        let paths = parse_path_lines(output);
        assert_eq!(paths[0], "/var/lib/store/aaa-foo-1.0");
        assert_eq!(paths[1], "/var/lib/store/bbb-bar-2.0");
    }

    // -----------------------------------------------------------------------
    // atomic_symlink tests
    // -----------------------------------------------------------------------

    #[test]
    fn atomic_symlink_creates_new() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("mylink");

        atomic_symlink("/some/target", &link).unwrap();

        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_string_lossy(), "/some/target");
    }

    #[test]
    fn atomic_symlink_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("mylink");

        // Create initial symlink.
        atomic_symlink("/old/target", &link).unwrap();
        assert_eq!(
            std::fs::read_link(&link).unwrap().to_string_lossy(),
            "/old/target"
        );

        // Replace with new target.
        atomic_symlink("/new/target", &link).unwrap();
        assert_eq!(
            std::fs::read_link(&link).unwrap().to_string_lossy(),
            "/new/target"
        );
    }

    #[test]
    fn atomic_symlink_noop_when_same_target() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("mylink");

        atomic_symlink("/same/target", &link).unwrap();
        atomic_symlink("/same/target", &link).unwrap();

        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_string_lossy(), "/same/target");
    }

    // -----------------------------------------------------------------------
    // Configuration-generation GC roots (cfg/ and cfgsrc/) and base-library retention.
    // -----------------------------------------------------------------------

    #[test]
    fn config_gc_roots_write_cfg_and_cfgsrc() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-7");

        let cfg = vec!["/var/lib/store/cfghash000000-etc-tree".to_string()];
        let cfgsrc = vec![
            "/var/lib/store/srchash0000000-web-config".to_string(),
            "/var/lib/store/hostnix0000000-host.nix".to_string(),
        ];

        create_config_gc_roots(&gen_dir, &cfg, &cfgsrc).unwrap();

        // cfg/ pins the manifest output.
        assert!(gen_dir.join("cfg").is_dir());
        let cfg_link = gen_dir.join("cfg").join("cfghash000000");
        assert_eq!(
            std::fs::read_link(&cfg_link).unwrap().to_string_lossy(),
            "/var/lib/store/cfghash000000-etc-tree"
        );

        // cfgsrc/ pins both the config-module source closure and host.nix.
        // The targets are absent on disk in the test, so check the symlink
        // itself (symlink_metadata) rather than following it (exists).
        assert!(gen_dir.join("cfgsrc").is_dir());
        assert!(
            gen_dir
                .join("cfgsrc")
                .join("srchash0000000")
                .symlink_metadata()
                .is_ok()
        );
        assert_eq!(
            std::fs::read_link(gen_dir.join("cfgsrc").join("hostnix0000000"))
                .unwrap()
                .to_string_lossy(),
            "/var/lib/store/hostnix0000000-host.nix"
        );
    }

    #[test]
    fn prune_drops_cfg_and_cfgsrc_with_generation() {
        // The cfg/ and cfgsrc/ roots live inside gen-N/, so removing the
        // generation directory (what prune_generations does) drops them.
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-7");
        create_config_gc_roots(
            &gen_dir,
            &["/var/lib/store/cfghash000000-etc".to_string()],
            &["/var/lib/store/srchash0000000-cfg".to_string()],
        )
        .unwrap();
        assert!(gen_dir.join("cfg").exists());
        assert!(gen_dir.join("cfgsrc").exists());

        std::fs::remove_dir_all(&gen_dir).unwrap();
        assert!(!gen_dir.join("cfg").exists());
        assert!(!gen_dir.join("cfgsrc").exists());
    }

    #[test]
    fn baselib_gc_root_keyed_by_module_abi() {
        let tmp = TempDir::new().unwrap();
        let image_gen_dir = tmp.path().join("image-gen-3");

        create_baselib_gc_root(&image_gen_dir, 2, "/var/lib/store/baselib0000000-aos-base-lib")
            .unwrap();

        let link = image_gen_dir.join("baselib").join("2");
        assert_eq!(
            std::fs::read_link(&link).unwrap().to_string_lossy(),
            "/var/lib/store/baselib0000000-aos-base-lib"
        );
    }

    #[test]
    fn baselib_retention_keeps_esp_and_pinned_and_floor() {
        use std::collections::BTreeSet;

        let candidates = [1u32, 2, 3];
        let esp: BTreeSet<u32> = [3].into_iter().collect(); // running A/B slot
        let pinned: BTreeSet<u32> = [2].into_iter().collect(); // a retained config-gen
        let running = 3;

        let keep = baselib_retention_set(&candidates, &esp, &pinned, running);
        // 3 (ESP) and 2 (pinned). 2 also satisfies the prior-ABI floor.
        assert!(keep.contains(&3));
        assert!(keep.contains(&2));
        assert!(!keep.contains(&1));
    }

    #[test]
    fn baselib_retention_floor_adds_prior_when_only_running_kept() {
        use std::collections::BTreeSet;

        let candidates = [1u32, 2, 3];
        let esp: BTreeSet<u32> = [3].into_iter().collect();
        let pinned: BTreeSet<u32> = BTreeSet::new(); // no config-gen pins a prior ABI
        let running = 3;

        let keep = baselib_retention_set(&candidates, &esp, &pinned, running);
        // Only the running ABI (3) qualifies via (a)/(b); the floor forces the
        // most recent prior ABI (2) to be retained for cross-ABI re-eval.
        assert!(keep.contains(&3));
        assert!(keep.contains(&2));
        assert!(!keep.contains(&1));
    }
}
