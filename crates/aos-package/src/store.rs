use std::path::Path;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use super::registry::store_path_hash;
use super::types::PackageMeta;
use super::verify::verify_store_path;

// ---------------------------------------------------------------------------
// NAR import
// ---------------------------------------------------------------------------

/// Import a compressed NAR (`.nar.zst`) into the Nix store.
///
/// Steps:
///   1. Decompress the `.nar.zst` file via `zstd -d` to a temporary `.nar`.
///   2. Run `nix-store --import < decompressed.nar` to import into the store.
///   3. Verify the resulting store path matches `expected_store_path`.
///   4. Clean up the temporary decompressed file.
///
/// Returns the imported store path on success.
pub async fn import_nar(nar_path: &Path, expected_store_path: &str) -> Result<String> {
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

    // Import the decompressed NAR into the store.
    let nar_file = tokio::fs::File::open(&decompressed)
        .await
        .with_context(|| format!("opening decompressed NAR {}", decompressed.display()))?;

    let import_output = Command::new("nix-store")
        .arg("--import")
        .stdin(nar_file.into_std().await)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("running nix-store --import")?;

    // Clean up the decompressed file regardless of outcome.
    let _ = tokio::fs::remove_file(&decompressed).await;

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
pub async fn filter_missing(store_paths: &[String]) -> Result<Vec<String>> {
    let mut missing = Vec::new();

    for path in store_paths {
        let status = Command::new("nix-store")
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
pub fn create_gc_roots(gen_dir: &Path, packages: &[PackageMeta]) -> Result<()> {
    let usr_dir = gen_dir.join("usr");
    let src_dir = gen_dir.join("src");

    std::fs::create_dir_all(&usr_dir)
        .with_context(|| format!("creating {}", usr_dir.display()))?;
    std::fs::create_dir_all(&src_dir)
        .with_context(|| format!("creating {}", src_dir.display()))?;

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

/// Remove GC roots for the given store path hashes from a generation.
///
/// Removes `gen_dir/usr/{hash}` and `gen_dir/src/{hash}` symlinks.  Silently
/// ignores hashes for which the symlinks do not exist (idempotent).
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

    // Remove stale temp file if it exists.
    let _ = std::fs::remove_file(&tmp_path);

    // Create temp symlink and rename over the final path.
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
pub async fn closure_paths(store_path: &str) -> Result<Vec<String>> {
    let output = Command::new("nix-store")
        .args(["-qR", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("running nix-store -qR {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store -qR failed for {store_path}: {}",
            stderr.trim()
        );
    }

    Ok(parse_path_lines(&String::from_utf8_lossy(&output.stdout)))
}

/// Query direct references of a single store path.
///
/// Runs `nix-store -q --references <path>`.
pub async fn direct_references(store_path: &str) -> Result<Vec<String>> {
    let output = Command::new("nix-store")
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
            download_hash: "sha256:1111".into(),
            download_size: 512,
            references: vec![],
            source_drv: source_drv.into(),
            source_nar_hash: "sha256:2222".into(),
            closure_size: 2048,
            sysroot: false,
            previous: None,
            images: vec![],
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
        assert!(usr_link.symlink_metadata().unwrap().file_type().is_symlink());
        let target = std::fs::read_link(&usr_link).unwrap();
        assert_eq!(
            target.to_string_lossy(),
            "/var/lib/store/abc123-curl-1.0.0"
        );
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
        assert!(src_link.symlink_metadata().unwrap().file_type().is_symlink());
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
            test_package(
                "curl",
                "abc123",
                "/var/lib/store/def456-curl-1.0.0.drv",
            ),
            test_package(
                "zlib",
                "ghi789",
                "/var/lib/store/jkl012-zlib-1.0.0.drv",
            ),
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
        assert_eq!(
            target.to_string_lossy(),
            "/var/lib/store/abc123-curl-1.0.0"
        );
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
            test_package(
                "curl",
                "abc123",
                "/var/lib/store/def456-curl-1.0.0.drv",
            ),
            test_package(
                "zlib",
                "ghi789",
                "/var/lib/store/jkl012-zlib-1.0.0.drv",
            ),
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no output")
        );
    }

    #[test]
    fn parse_import_output_unexpected() {
        let result = parse_import_output("some unexpected output\n");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected")
        );
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
}
