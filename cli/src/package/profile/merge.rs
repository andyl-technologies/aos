use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::Generation;
use aos::output::Printer;

/// FHS directories to merge from store paths.
///
/// Order matters: more specific paths (e.g. `share/man/man1`) must come after
/// their parent (`share`) so we can skip subdirectories that are handled by
/// a more specific entry.
const MERGE_DIRS: &[&str] = &[
    "bin",
    "sbin",
    "lib",
    "lib64",
    "include",
    "share",
    "etc",
    "share/man/man1",
    "share/man/man2",
    "share/man/man3",
    "share/man/man4",
    "share/man/man5",
    "share/man/man6",
    "share/man/man7",
    "share/man/man8",
];

/// Subdirectories of `share/` that are handled by more specific MERGE_DIRS
/// entries.  When scanning `share/`, we skip these to avoid double-processing.
const SHARE_SKIP_SUBDIRS: &[&str] = &["man"];

/// Directories in the generation root that belong to the profile bookkeeping
/// rather than the FHS merge tree.  `clear_fhs_tree` preserves these.
const PRESERVED_DIRS: &[&str] = &["usr", "src"];

/// Result of building the FHS merge tree.
pub struct MergeResult {
    pub symlinks_created: usize,
    pub conflicts: Vec<FileConflict>,
}

/// A file conflict where two packages provide the same path.
pub struct FileConflict {
    pub path: String,
    pub winner: String,
    pub loser: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the merged FHS tree for a generation.
///
/// For each store path rooted in `gen-N/usr/`:
///   1. Scan the store path for files under each `MERGE_DIR`
///   2. Create symlinks in `gen-N/{dir}/{filename}` -> `store_path/{dir}/{filename}`
///
/// File conflicts (same relative path from multiple packages): last-in-list
/// wins.  A warning is printed for every conflict.
///
/// `store_paths` is an ordered slice -- later entries take priority.
pub fn build_fhs_tree(
    generation: &Generation,
    store_paths: &[(String, PathBuf)],
    printer: &Printer,
) -> Result<MergeResult> {
    // Phase 1: collect the merged file map across all packages.
    // Key: relative path (e.g. "bin/curl"), Value: (package_name, absolute target).
    let mut merged: HashMap<String, (String, PathBuf)> = HashMap::new();
    let mut conflicts: Vec<FileConflict> = Vec::new();

    for (pkg_name, store_path) in store_paths {
        let files = scan_store_path(store_path)
            .with_context(|| format!("scanning store path {}", store_path.display()))?;

        for (rel_path, abs_target) in files {
            if let Some((prev_pkg, _prev_target)) = merged.get(&rel_path) {
                conflicts.push(FileConflict {
                    path: rel_path.clone(),
                    loser: prev_pkg.clone(),
                    winner: pkg_name.clone(),
                });
                printer.warning(&format!(
                    "conflict: {rel_path} provided by both {} and {} (using {})",
                    prev_pkg, pkg_name, pkg_name,
                ));
            }
            merged.insert(rel_path, (pkg_name.clone(), abs_target));
        }
    }

    // Phase 2: create the actual symlinks.
    let mut symlinks_created: usize = 0;

    for (rel_path, (_pkg_name, abs_target)) in &merged {
        create_fhs_symlink(&generation.path, rel_path, abs_target).with_context(|| {
            format!(
                "creating FHS symlink {}/{}",
                generation.path.display(),
                rel_path,
            )
        })?;
        symlinks_created += 1;
    }

    Ok(MergeResult {
        symlinks_created,
        conflicts,
    })
}

/// Remove the FHS tree (all merged symlink directories) from a generation.
///
/// Preserves `usr/` and `src/` directories (GC roots and source roots).
pub fn clear_fhs_tree(generation: &Generation) -> Result<()> {
    let entries = std::fs::read_dir(&generation.path)
        .with_context(|| format!("reading generation directory {}", generation.path.display()))?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip preserved bookkeeping directories.
        if PRESERVED_DIRS.contains(&name_str.as_ref()) {
            continue;
        }

        let ft = entry
            .file_type()
            .with_context(|| format!("reading file type of {}", entry.path().display()))?;

        if ft.is_dir() {
            std::fs::remove_dir_all(entry.path()).with_context(|| {
                format!("removing FHS directory {}", entry.path().display())
            })?;
        } else if ft.is_symlink() || ft.is_file() {
            std::fs::remove_file(entry.path()).with_context(|| {
                format!("removing FHS entry {}", entry.path().display())
            })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Scan a store path for files under FHS directories.
///
/// Returns a map of `relative_path` -> `absolute_file_path`.
/// For example: `"bin/curl"` -> `"/var/lib/store/h7j3-curl-8.5.0/bin/curl"`.
fn scan_store_path(store_path: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut result: HashMap<String, PathBuf> = HashMap::new();

    for &merge_dir in MERGE_DIRS {
        let dir_path = store_path.join(merge_dir);
        if !dir_path.is_dir() {
            continue;
        }

        let entries = std::fs::read_dir(&dir_path)
            .with_context(|| format!("reading directory {}", dir_path.display()))?;

        for entry in entries {
            let entry = entry?;
            let child_name = entry.file_name();
            let child_name_str = child_name.to_string_lossy();

            // When scanning `share/`, skip subdirectories that are handled by
            // more specific MERGE_DIRS entries (e.g. skip `man` because
            // `share/man/manN` entries will pick up individual man pages).
            if merge_dir == "share" {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
                    && SHARE_SKIP_SUBDIRS.contains(&child_name_str.as_ref())
                {
                    continue;
                }
            }

            let rel_path = format!("{merge_dir}/{child_name_str}");
            let abs_path = entry.path();
            result.insert(rel_path, abs_path);
        }
    }

    Ok(result)
}

/// Create a single FHS symlink atomically.
///
/// Creates the parent directory if it does not exist, then creates:
///   `gen_dir/{rel_path}` -> `target`
fn create_fhs_symlink(gen_dir: &Path, rel_path: &str, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    let link_path = gen_dir.join(rel_path);

    // Ensure the parent directory exists.
    if let Some(parent) = link_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }

    // Remove a pre-existing symlink/file at this path (from a previous merge).
    if link_path.symlink_metadata().is_ok() {
        std::fs::remove_file(&link_path)
            .with_context(|| format!("removing existing entry {}", link_path.display()))?;
    }

    symlink(target, &link_path).with_context(|| {
        format!(
            "symlinking {} -> {}",
            link_path.display(),
            target.display(),
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a fake store path with the given files.
    fn make_store_path(tmp: &TempDir, name: &str, files: &[&str]) -> PathBuf {
        let store_path = tmp.path().join(format!("store/{name}"));
        for file in files {
            let path = store_path.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("content of {file}")).unwrap();
        }
        store_path
    }

    /// Create a generation directory in the temp dir.
    fn make_generation(tmp: &TempDir, num: u32) -> Generation {
        let path = tmp.path().join(format!("gen-{num}"));
        fs::create_dir_all(&path).unwrap();
        Generation { number: num, path }
    }

    /// A quiet-mode printer for tests (suppresses all output).
    fn test_printer() -> Printer {
        Printer::new(0, true, false)
    }

    // 1. scan_store_path finds files under FHS directories.
    #[test]
    fn scan_finds_fhs_files() {
        let tmp = TempDir::new().unwrap();
        let sp = make_store_path(
            &tmp,
            "abc123-curl-8.5.0",
            &[
                "bin/curl",
                "lib/libcurl.so",
                "share/man/man1/curl.1",
                "share/doc/curl/README",
            ],
        );

        let files = scan_store_path(&sp).unwrap();
        assert!(files.contains_key("bin/curl"));
        assert!(files.contains_key("lib/libcurl.so"));
        assert!(files.contains_key("share/man/man1/curl.1"));
        // share/doc is a directory child of share/, so it appears as share/doc
        assert!(files.contains_key("share/doc"));
    }

    // 2. build_fhs_tree with a single package creates correct symlinks.
    #[test]
    fn single_package_merge() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc123-curl-8.5.0",
            &["bin/curl", "lib/libcurl.so.4"],
        );

        let result = build_fhs_tree(
            &gn,
            &[("curl".to_string(), sp.clone())],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.symlinks_created, 2);
        assert!(result.conflicts.is_empty());

        // Verify symlinks exist and point to the right place.
        let bin_curl = gn.path.join("bin/curl");
        assert!(bin_curl.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_link(&bin_curl).unwrap(),
            sp.join("bin/curl"),
        );

        let lib_curl = gn.path.join("lib/libcurl.so.4");
        assert!(lib_curl.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_link(&lib_curl).unwrap(),
            sp.join("lib/libcurl.so.4"),
        );
    }

    // 3. build_fhs_tree merges files from two packages.
    #[test]
    fn two_packages_merge() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp_curl = make_store_path(&tmp, "abc-curl", &["bin/curl"]);
        let sp_zlib = make_store_path(&tmp, "def-zlib", &["lib/libz.so"]);

        let result = build_fhs_tree(
            &gn,
            &[
                ("curl".to_string(), sp_curl),
                ("zlib".to_string(), sp_zlib.clone()),
            ],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.symlinks_created, 2);
        assert!(result.conflicts.is_empty());

        assert!(gn.path.join("bin/curl").symlink_metadata().is_ok());
        assert_eq!(
            fs::read_link(gn.path.join("lib/libz.so")).unwrap(),
            sp_zlib.join("lib/libz.so"),
        );
    }

    // 4. File conflict: last-in-list wins, conflict recorded.
    #[test]
    fn conflict_last_wins() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp_py1 = make_store_path(&tmp, "aaa-python-3.11", &["bin/python3"]);
        let sp_py2 = make_store_path(&tmp, "bbb-python-3.12", &["bin/python3"]);

        let result = build_fhs_tree(
            &gn,
            &[
                ("python-3.11".to_string(), sp_py1),
                ("python-3.12".to_string(), sp_py2.clone()),
            ],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.symlinks_created, 1);
        assert_eq!(result.conflicts.len(), 1);

        let conflict = &result.conflicts[0];
        assert_eq!(conflict.path, "bin/python3");
        assert_eq!(conflict.loser, "python-3.11");
        assert_eq!(conflict.winner, "python-3.12");

        // The winner's file should be linked.
        let link_target = fs::read_link(gn.path.join("bin/python3")).unwrap();
        assert_eq!(link_target, sp_py2.join("bin/python3"));
    }

    // 5. clear_fhs_tree removes FHS dirs but preserves usr/ and src/.
    #[test]
    fn clear_preserves_usr_and_src() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);

        // Create FHS directories and bookkeeping directories.
        fs::create_dir_all(gn.path.join("bin")).unwrap();
        fs::write(gn.path.join("bin/curl"), "link").unwrap();
        fs::create_dir_all(gn.path.join("lib")).unwrap();
        fs::write(gn.path.join("lib/libz.so"), "link").unwrap();
        fs::create_dir_all(gn.path.join("share/man/man1")).unwrap();
        fs::write(gn.path.join("share/man/man1/curl.1"), "link").unwrap();
        fs::create_dir_all(gn.path.join("usr")).unwrap();
        fs::write(gn.path.join("usr/abc123"), "root").unwrap();
        fs::create_dir_all(gn.path.join("src")).unwrap();
        fs::write(gn.path.join("src/abc123"), "root").unwrap();

        clear_fhs_tree(&gn).unwrap();

        // FHS dirs should be gone.
        assert!(!gn.path.join("bin").exists());
        assert!(!gn.path.join("lib").exists());
        assert!(!gn.path.join("share").exists());

        // Bookkeeping dirs should be preserved.
        assert!(gn.path.join("usr").exists());
        assert!(gn.path.join("usr/abc123").exists());
        assert!(gn.path.join("src").exists());
        assert!(gn.path.join("src/abc123").exists());
    }

    // 6. Man pages land in correct share/man/manN/ sections.
    #[test]
    fn man_pages_correct_sections() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc-curl",
            &[
                "share/man/man1/curl.1",
                "share/man/man3/libcurl.3",
            ],
        );

        let result = build_fhs_tree(
            &gn,
            &[("curl".to_string(), sp.clone())],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.symlinks_created, 2);

        let man1 = gn.path.join("share/man/man1/curl.1");
        assert!(man1.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_link(&man1).unwrap(),
            sp.join("share/man/man1/curl.1"),
        );

        let man3 = gn.path.join("share/man/man3/libcurl.3");
        assert!(man3.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_link(&man3).unwrap(),
            sp.join("share/man/man3/libcurl.3"),
        );
    }

    // 7. Empty MERGE_DIRS are not created.
    #[test]
    fn empty_dirs_not_created() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        // Package only has bin/curl — no lib, share, etc.
        let sp = make_store_path(&tmp, "abc-curl", &["bin/curl"]);

        build_fhs_tree(
            &gn,
            &[("curl".to_string(), sp)],
            &test_printer(),
        )
        .unwrap();

        // bin/ should exist (has content).
        assert!(gn.path.join("bin").is_dir());
        // These should NOT exist (no content).
        assert!(!gn.path.join("lib").exists());
        assert!(!gn.path.join("lib64").exists());
        assert!(!gn.path.join("sbin").exists());
        assert!(!gn.path.join("include").exists());
        assert!(!gn.path.join("share").exists());
        assert!(!gn.path.join("etc").exists());
    }

    // 8. scan_store_path ignores files not under MERGE_DIRS.
    #[test]
    fn scan_ignores_non_fhs_files() {
        let tmp = TempDir::new().unwrap();
        let sp = make_store_path(
            &tmp,
            "abc-curl",
            &[
                "bin/curl",
                "nix-support/setup-hook",
                "libexec/internal-tool",
                "README.md",
            ],
        );

        let files = scan_store_path(&sp).unwrap();

        assert!(files.contains_key("bin/curl"));
        assert!(!files.contains_key("nix-support/setup-hook"));
        assert!(!files.contains_key("libexec/internal-tool"));
        assert!(!files.contains_key("README.md"));
    }

    // 9. build_fhs_tree with no packages creates nothing.
    #[test]
    fn empty_store_paths() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);

        let result = build_fhs_tree(&gn, &[], &test_printer()).unwrap();

        assert_eq!(result.symlinks_created, 0);
        assert!(result.conflicts.is_empty());
    }

    // 10. clear_fhs_tree on an already-clean generation is a no-op.
    #[test]
    fn clear_clean_generation() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);

        // Should not error when there's nothing to clean.
        clear_fhs_tree(&gn).unwrap();
    }

    // 11. Symlinks from share/ scanning skip the man subdirectory.
    #[test]
    fn share_skips_man_subdir() {
        let tmp = TempDir::new().unwrap();
        let sp = make_store_path(
            &tmp,
            "abc-bash",
            &[
                "share/bash-completion/completions/bash",
                "share/man/man1/bash.1",
            ],
        );

        let files = scan_store_path(&sp).unwrap();

        // bash-completion directory is found under share/ scanning.
        assert!(files.contains_key("share/bash-completion"));
        // man pages are found via share/man/man1 scanning, not share/.
        assert!(files.contains_key("share/man/man1/bash.1"));
        // The `man` directory itself should NOT appear as share/man.
        assert!(!files.contains_key("share/man"));
    }

    // 12. build_fhs_tree then clear_fhs_tree round-trips cleanly.
    #[test]
    fn build_then_clear_round_trip() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc-curl",
            &[
                "bin/curl",
                "lib/libcurl.so",
                "share/man/man1/curl.1",
            ],
        );

        // Create usr/ to simulate a real generation with GC roots.
        fs::create_dir_all(gn.path.join("usr")).unwrap();

        build_fhs_tree(
            &gn,
            &[("curl".to_string(), sp)],
            &test_printer(),
        )
        .unwrap();

        // Verify symlinks are present.
        assert!(gn.path.join("bin/curl").symlink_metadata().is_ok());
        assert!(gn.path.join("lib/libcurl.so").symlink_metadata().is_ok());
        assert!(gn.path.join("share/man/man1/curl.1").symlink_metadata().is_ok());

        clear_fhs_tree(&gn).unwrap();

        // FHS trees should be gone.
        assert!(!gn.path.join("bin").exists());
        assert!(!gn.path.join("lib").exists());
        assert!(!gn.path.join("share").exists());

        // usr/ preserved.
        assert!(gn.path.join("usr").is_dir());
    }

    // 13. Symlinks for etc/ and include/ work correctly.
    #[test]
    fn etc_and_include_merge() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc-openssl",
            &[
                "etc/ssl/openssl.cnf",
                "include/openssl/ssl.h",
            ],
        );

        let result = build_fhs_tree(
            &gn,
            &[("openssl".to_string(), sp.clone())],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.symlinks_created, 2);

        // etc/ scanning: the child is the `ssl` directory.
        let etc_ssl = gn.path.join("etc/ssl");
        assert!(etc_ssl.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&etc_ssl).unwrap(), sp.join("etc/ssl"));

        // include/ scanning: the child is the `openssl` directory.
        let inc_openssl = gn.path.join("include/openssl");
        assert!(inc_openssl.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_link(&inc_openssl).unwrap(),
            sp.join("include/openssl"),
        );
    }
}
