use std::path::Path;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::profile::Profile;
use aos::output::Printer;

/// Run `apm clean [--generations] [--keep=N]`.
///
/// Without `--generations`: clears the NAR download cache.
/// With `--generations`: prunes old profile generations, keeping the
/// latest `keep` (and always keeping the current generation).
pub async fn run(
    config: &ApmConfig,
    generations: bool,
    keep: u32,
    printer: &Printer,
) -> Result<()> {
    if generations {
        let profile = Profile::open(config.scope)?;
        let removed = profile.prune_generations(keep)?;
        if removed.is_empty() {
            printer.info("No old generations to remove.");
        } else {
            printer.success(&format!("Removed {} old generation(s).", removed.len()));
        }
    } else {
        let cache_dir = config.nar_cache_path();
        let freed = clear_nar_cache(&cache_dir)?;
        printer.success(&format!("Cleared NAR cache, freed {}.", format_size(freed)));
    }

    Ok(())
}

/// Run `apm gc`.
///
/// Delegates to the system's `nix-store --gc` to reclaim unreachable
/// store paths.
pub async fn run_gc(printer: &Printer) -> Result<()> {
    printer.info("Running garbage collection...");

    let output = tokio::process::Command::new("nix-store")
        .arg("--gc")
        .output()
        .await
        .context("failed to run nix-store --gc")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-store --gc failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        printer.plain(stdout.trim_end());
    }

    printer.success("Garbage collection complete.");
    Ok(())
}

/// Clear the NAR cache directory and return the number of bytes freed.
///
/// Removes all regular files in the directory. Subdirectories are left
/// intact (the directory structure itself is cheap).
fn clear_nar_cache(cache_dir: &Path) -> Result<u64> {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading NAR cache directory {}", cache_dir.display()));
        }
    };

    let mut freed: u64 = 0;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            freed += meta.len();
            std::fs::remove_file(entry.path()).with_context(|| {
                format!("removing cached file {}", entry.path().display())
            })?;
        }
    }

    Ok(freed)
}

/// Format a byte count as a human-readable size string.
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn clear_nar_cache_removes_files_and_returns_size() {
        let tmp = TempDir::new().unwrap();

        // Create some fake cached NAR files.
        let file_a = tmp.path().join("abc123.nar.zst");
        let file_b = tmp.path().join("def456.nar.zst");
        std::fs::write(&file_a, vec![0u8; 1024]).unwrap();
        std::fs::write(&file_b, vec![0u8; 2048]).unwrap();

        let freed = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(freed, 3072);

        // Files should be gone.
        assert!(!file_a.exists());
        assert!(!file_b.exists());
    }

    #[test]
    fn clear_nar_cache_empty_dir_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let freed = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn clear_nar_cache_nonexistent_dir_returns_zero() {
        let freed = clear_nar_cache(Path::new("/tmp/nonexistent-apm-test-dir")).unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn format_size_kib() {
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
    }

    #[test]
    fn format_size_mib() {
        assert_eq!(format_size(1048576), "1.0 MiB");
        assert_eq!(format_size(10 * 1048576), "10.0 MiB");
    }

    #[test]
    fn format_size_gib() {
        assert_eq!(format_size(1073741824), "1.0 GiB");
    }
}
