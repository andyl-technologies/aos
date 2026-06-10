use std::path::Path;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::profile::Profile;
use aos_core::nix::aos_nix_env;
use aos_core::output::{OutputMode, Printer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NarCacheCleanResult {
    freed_bytes: u64,
    files_removed: usize,
}

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
    let json_mode = printer.mode() == OutputMode::Json;
    if generations {
        let profile = Profile::open_readonly(config.scope);
        let all_generations = profile.list_generations()?;
        let current_generation = profile.current_generation()?.map(|g| g.number);
        let generations_before: Vec<u32> = all_generations
            .iter()
            .map(|generation| generation.number)
            .collect();

        if all_generations.len() <= keep as usize {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_before,
                    &[],
                ));
            }
            printer.info("No old generations to remove.");
            return Ok(());
        }

        let cutoff = all_generations.len() - keep as usize;
        let has_prunable_generation = all_generations[..cutoff]
            .iter()
            .any(|generation| Some(generation.number) != current_generation);

        if !has_prunable_generation {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_before,
                    &[],
                ));
            }
            printer.info("No old generations to remove.");
            return Ok(());
        }

        let profile = Profile::open(config.scope)?;
        let removed = profile.prune_generations(keep)?;
        let generations_after: Vec<u32> = profile
            .list_generations()?
            .iter()
            .map(|generation| generation.number)
            .collect();
        let removed_generations: Vec<u32> =
            removed.iter().map(|generation| generation.number).collect();
        if removed.is_empty() {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_after,
                    &removed_generations,
                ));
            }
            printer.info("No old generations to remove.");
        } else {
            if json_mode {
                printer.json(&clean_generations_json(
                    "cleaned",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_after,
                    &removed_generations,
                ));
            }
            printer.success(&format!("Removed {} old generation(s).", removed.len()));
        }
    } else {
        let cache_dir = config.nar_cache_path();
        let cleaned = clear_nar_cache(&cache_dir)?;
        if json_mode {
            printer.json(&serde_json::json!({
                "action": "clean",
                "mode": "cache",
                "status": if cleaned.files_removed == 0 { "current" } else { "cleaned" },
                "cache_dir": cache_dir.to_string_lossy(),
                "files_removed": cleaned.files_removed,
                "freed_bytes": cleaned.freed_bytes,
                "freed": format_size(cleaned.freed_bytes),
            }));
        }
        printer.success(&format!(
            "Cleared NAR cache, freed {}.",
            format_size(cleaned.freed_bytes)
        ));
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
        .envs(aos_nix_env())
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
fn clear_nar_cache(cache_dir: &Path) -> Result<NarCacheCleanResult> {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NarCacheCleanResult {
                freed_bytes: 0,
                files_removed: 0,
            });
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading NAR cache directory {}", cache_dir.display()));
        }
    };

    let mut freed: u64 = 0;
    let mut files_removed = 0;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            freed += meta.len();
            files_removed += 1;
            std::fs::remove_file(entry.path())
                .with_context(|| format!("removing cached file {}", entry.path().display()))?;
        }
    }

    Ok(NarCacheCleanResult {
        freed_bytes: freed,
        files_removed,
    })
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

fn clean_generations_json(
    status: &str,
    keep: u32,
    current_generation: Option<u32>,
    generations_before: &[u32],
    generations_after: &[u32],
    removed_generations: &[u32],
) -> serde_json::Value {
    serde_json::json!({
        "action": "clean",
        "mode": "generations",
        "status": status,
        "keep": keep,
        "current_generation": current_generation,
        "generations_before": generations_before,
        "generations_after": generations_after,
        "generations_before_count": generations_before.len(),
        "generations_after_count": generations_after.len(),
        "removed_generations": removed_generations,
        "removed": removed_generations.len(),
    })
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

        let cleaned = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(cleaned.freed_bytes, 3072);
        assert_eq!(cleaned.files_removed, 2);

        // Files should be gone.
        assert!(!file_a.exists());
        assert!(!file_b.exists());
    }

    #[test]
    fn clear_nar_cache_empty_dir_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let cleaned = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(cleaned.freed_bytes, 0);
        assert_eq!(cleaned.files_removed, 0);
    }

    #[test]
    fn clear_nar_cache_nonexistent_dir_returns_zero() {
        let cleaned = clear_nar_cache(Path::new("/tmp/nonexistent-apm-test-dir")).unwrap();
        assert_eq!(cleaned.freed_bytes, 0);
        assert_eq!(cleaned.files_removed, 0);
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
