//! The merged FHS symlink tree of a generation.
//!
//! Installed packages live as isolated store paths; this module gives a
//! generation a conventional Unix layout by merging each package's `bin/`,
//! `lib/`, `share/`, `etc/`, ... contents into `gen-N/<dir>/` as symlinks
//! pointing back into the store. The profile's `current` symlink then makes
//! e.g. `current/bin` a stable PATH entry across generation switches.
//!
//! Real directories are merged recursively so documentation, locale data,
//! completion scripts, and development metadata from different packages coexist.
//! Package symlinks remain leaves and are never traversed during the merge.
//!
//! When packages provide conflicting leaves or incompatible entries at the
//! same relative path, the later entry in the ordered store-path slice wins;
//! every such collision is reported as a
//! [`FileConflict`] and a printed warning.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::Generation;
use super::meta::read_generation_meta;
use aos_core::output::Printer;

/// Top-level FHS directories merged from store paths.
const MERGE_DIRS: &[&str] = &["bin", "sbin", "lib", "lib64", "include", "share", "etc"];

/// One scanned directory or leaf within a package's FHS tree.
struct StoreEntry {
    source: PathBuf,
    directory: bool,
}

/// One selected provider for a relative profile path.
struct MergedEntry {
    package: String,
    entry: StoreEntry,
}

/// Directories in the generation root that belong to the profile bookkeeping
/// rather than the FHS merge tree.  `clear_fhs_tree` preserves these.
const PRESERVED_DIRS: &[&str] = &["usr", "src", "meta"];

/// Result of building the FHS merge tree.
pub struct MergeResult {
    /// Number of symlinks created in the generation.
    pub symlinks_created: usize,
    /// Every relative path provided by more than one package.
    pub conflicts: Vec<FileConflict>,
}

/// A path conflict where two packages provide incompatible entries.
pub struct FileConflict {
    /// The contested relative path (e.g. `bin/python3`).
    pub path: String,
    /// Readable package name and version whose entry was selected.
    pub winner: String,
    /// Readable package name and version whose entry was shadowed.
    pub loser: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the merged FHS tree for all roots in a generation.
///
/// Profile generations carry metadata for every APM-managed root. Automatic
/// dependency roots are merged first and explicit roots are merged last, so a
/// directly requested package owns conflicting executable names over an
/// automatic dependency with the same files.
///
/// # Errors
///
/// Returns an error if roots or generation metadata cannot be read, or if the
/// underlying FHS tree cannot be built.
pub fn build_generation_fhs_tree(
    generation: &Generation,
    printer: &Printer,
) -> Result<MergeResult> {
    let roots = ordered_generation_roots(generation)?;
    build_fhs_tree(generation, &roots, printer)
}

/// Build the merged FHS tree for a generation.
///
/// For each store path rooted in `gen-N/usr/`:
///   1. Recursively scan real directories under each `MERGE_DIR`
///   2. Create symlinks in `gen-N/{dir}/{filename}` -> `store_path/{dir}/{filename}`
///
/// File conflicts (same relative path from multiple packages): last-in-list
/// wins.  A warning is printed for every conflict.
///
/// `store_paths` is an ordered slice -- later entries take priority.
///
/// # Errors
///
/// Returns an error if generation metadata cannot be read, a store path cannot
/// be scanned, or a symlink (or its parent directory) cannot be created.
pub fn build_fhs_tree(
    generation: &Generation,
    store_paths: &[(String, PathBuf)],
    printer: &Printer,
) -> Result<MergeResult> {
    let mut merged: BTreeMap<String, MergedEntry> = BTreeMap::new();
    let mut conflicts = Vec::new();

    for (package_id, store_path) in store_paths {
        let package = package_label(generation, package_id, store_path)?;
        let entries = scan_store_path(store_path)
            .with_context(|| format!("scanning store path {}", store_path.display()))?;

        // Parent directories precede children. A directory replacing a leaf
        // removes that obstruction before any descendants are considered.
        for (relative_path, entry) in entries {
            if let Some(previous) = merged.get(&relative_path) {
                if !(previous.entry.directory && entry.directory) {
                    conflicts.push(FileConflict {
                        path: relative_path.clone(),
                        loser: previous.package.clone(),
                        winner: package.clone(),
                    });
                    printer.warning(&format!(
                        "path conflict at {relative_path}: using {package}; shadows {}",
                        previous.package,
                    ));
                }
            }

            if !entry.directory {
                // A later leaf replaces the complete earlier subtree. This
                // also prevents writing through a selected directory symlink.
                let prefix = format!("{relative_path}/");
                merged.retain(|path, _| !path.starts_with(&prefix));
            }
            merged.insert(
                relative_path,
                MergedEntry {
                    package: package.clone(),
                    entry,
                },
            );
        }
    }

    // Rebuild only after all package trees have been read successfully. An
    // existing shallow-directory link must not redirect writes into the store.
    clear_fhs_tree(generation)?;
    let mut symlinks_created = 0;

    for (relative_path, selected) in merged {
        if selected.entry.directory {
            let directory = generation.path.join(&relative_path);
            std::fs::create_dir_all(&directory)
                .with_context(|| format!("creating profile directory {}", directory.display()))?;
        } else {
            create_fhs_symlink(&generation.path, &relative_path, &selected.entry.source)?;
            symlinks_created += 1;
        }
    }

    Ok(MergeResult {
        symlinks_created,
        conflicts,
    })
}

/// Prefer recorded package identity; legacy roots retain the readable store name.
fn package_label(generation: &Generation, hash: &str, store_path: &Path) -> Result<String> {
    if let Some(apm) = read_generation_meta(generation, hash)?.and_then(|meta| meta.apm) {
        return Ok(format!(
            "{} {} [registry: {}]",
            apm.name, apm.version, apm.registry
        ));
    }

    let store_name = store_path.file_name().and_then(|name| name.to_str());
    let label = store_name
        .and_then(|name| name.strip_prefix(hash))
        .and_then(|suffix| suffix.strip_prefix('-'))
        .filter(|name| !name.is_empty())
        .unwrap_or(hash);

    Ok(label.to_string())
}

/// Return generation roots in merge order.
///
/// Later roots win file conflicts. Non-APM and metadata-less roots are treated
/// like explicit roots to avoid demoting legacy profile entries.
fn ordered_generation_roots(generation: &Generation) -> Result<Vec<(String, PathBuf)>> {
    let mut roots = Vec::new();

    for (hash, path) in generation.roots()? {
        let priority = match read_generation_meta(generation, &hash)? {
            Some(meta) => match meta.apm {
                Some(apm) if !apm.explicit => 0_u8,
                _ => 1_u8,
            },
            None => 1_u8,
        };
        roots.push((priority, hash, path));
    }

    roots.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    Ok(roots
        .into_iter()
        .map(|(_priority, hash, path)| (hash, path))
        .collect())
}

/// Remove the FHS tree (all merged symlink directories) from a generation.
///
/// Preserves the `usr/`, `src/`, and `meta/` bookkeeping directories that hold
/// GC roots, source roots, and per-generation package metadata.
///
/// # Errors
///
/// Returns an error if the generation directory cannot be read or an entry
/// cannot be removed.
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
            std::fs::remove_dir_all(entry.path())
                .with_context(|| format!("removing FHS directory {}", entry.path().display()))?;
        } else if ft.is_symlink() || ft.is_file() {
            std::fs::remove_file(entry.path())
                .with_context(|| format!("removing FHS entry {}", entry.path().display()))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Scans package trees without following child symlinks.
fn scan_store_path(store_path: &Path) -> Result<BTreeMap<String, StoreEntry>> {
    let mut entries = BTreeMap::new();

    for &merge_directory in MERGE_DIRS {
        let source = store_path.join(merge_directory);
        if source.is_dir() {
            scan_directory(&source, merge_directory, &mut entries)?;
        }
    }

    Ok(entries)
}

/// Records real directory children and recurses only into those directories.
fn scan_directory(
    source: &Path,
    relative_directory: &str,
    entries: &mut BTreeMap<String, StoreEntry>,
) -> Result<()> {
    for child in std::fs::read_dir(source)
        .with_context(|| format!("reading directory {}", source.display()))?
    {
        let child = child?;
        let name = child.file_name();
        let name = name.to_str().with_context(|| {
            format!(
                "package profile path is not UTF-8: {}",
                child.path().display()
            )
        })?;
        let relative_path = format!("{relative_directory}/{name}");
        let directory = child.file_type()?.is_dir();
        let source = child.path();
        entries.insert(
            relative_path.clone(),
            StoreEntry {
                source: source.clone(),
                directory,
            },
        );

        if directory {
            scan_directory(&source, &relative_path, entries)?;
        }
    }

    Ok(())
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

    symlink(target, &link_path)
        .with_context(|| format!("symlinking {} -> {}", link_path.display(), target.display(),))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApmMeta, InstalledMeta};
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

    /// Add a GC root symlink to a generation.
    fn add_generation_root(generation: &Generation, hash: &str, store_path: &Path) {
        let roots = generation.path.join("usr");
        fs::create_dir_all(&roots).unwrap();
        std::os::unix::fs::symlink(store_path, roots.join(hash)).unwrap();
    }

    /// Write APM metadata into a generation snapshot.
    fn write_generation_apm_meta(
        generation: &Generation,
        hash: &str,
        store_path: &Path,
        explicit: bool,
        name: &str,
        version: &str,
    ) {
        let meta_dir = generation.path.join("meta");
        fs::create_dir_all(&meta_dir).unwrap();
        let meta = InstalledMeta {
            store_path: store_path.to_string_lossy().to_string(),
            pushed_at: 0,
            pushed_by: "apm".to_string(),
            expires_at: None,
            is_root: true,
            last_accessed: 0,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.to_string(),
                version: version.to_string(),
                explicit,
                registry: "test".to_string(),
                installed_at: "1970-01-01T00:00:00Z".to_string(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                deployment: None,
                module_documentation: None,
                qualification: None,
                attestation: Default::default(),
            }),
        };
        fs::write(
            meta_dir.join(format!("{hash}.json")),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
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
        assert!(files.contains_key("share/doc/curl/README"));
    }

    // 2. build_fhs_tree with a single package creates correct symlinks.
    #[test]
    fn single_package_merge() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(&tmp, "abc123-curl-8.5.0", &["bin/curl", "lib/libcurl.so.4"]);

        let result =
            build_fhs_tree(&gn, &[("curl".to_string(), sp.clone())], &test_printer()).unwrap();

        assert_eq!(result.symlinks_created, 2);
        assert!(result.conflicts.is_empty());

        // Verify symlinks exist and point to the right place.
        let bin_curl = gn.path.join("bin/curl");
        assert!(
            bin_curl
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&bin_curl).unwrap(), sp.join("bin/curl"),);

        let lib_curl = gn.path.join("lib/libcurl.so.4");
        assert!(
            lib_curl
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
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

    #[test]
    fn conflicts_use_package_metadata_instead_of_root_hashes() {
        let tmp = TempDir::new().unwrap();
        let generation = make_generation(&tmp, 1);
        let first = make_store_path(&tmp, "aaa-python-3.11", &["bin/python3"]);
        let second = make_store_path(&tmp, "bbb-python-3.12", &["bin/python3"]);
        write_generation_apm_meta(&generation, "aaa", &first, true, "python", "3.11");
        write_generation_apm_meta(&generation, "bbb", &second, true, "python", "3.12");

        let result = build_fhs_tree(
            &generation,
            &[("aaa".into(), first), ("bbb".into(), second.clone())],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].loser, "python 3.11 [registry: test]");
        assert_eq!(result.conflicts[0].winner, "python 3.12 [registry: test]");
        assert_eq!(
            fs::read_link(generation.path.join("bin/python3")).unwrap(),
            second.join("bin/python3"),
        );
    }

    #[test]
    fn legacy_root_labels_strip_only_the_matching_store_hash() {
        let tmp = TempDir::new().unwrap();
        let generation = make_generation(&tmp, 1);

        assert_eq!(
            package_label(&generation, "aaa", Path::new("/nix/store/aaa-python-3.11")).unwrap(),
            "python-3.11",
        );
        assert_eq!(
            package_label(&generation, "python", Path::new("/tmp/unrelated")).unwrap(),
            "python",
        );
    }

    #[test]
    fn generation_merge_prefers_explicit_roots_over_auto_dependencies() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let automatic = make_store_path(&tmp, "zzz-auto-priority-tool", &["bin/priority-tool"]);
        let explicit = make_store_path(&tmp, "aaa-explicit-priority-tool", &["bin/priority-tool"]);

        add_generation_root(&gn, "zzzauto", &automatic);
        add_generation_root(&gn, "aaaexplicit", &explicit);
        write_generation_apm_meta(&gn, "zzzauto", &automatic, false, "priority-tool", "1.0.0");
        write_generation_apm_meta(
            &gn,
            "aaaexplicit",
            &explicit,
            true,
            "priority-tool",
            "1.0.0",
        );

        let result = build_generation_fhs_tree(&gn, &test_printer()).unwrap();

        assert_eq!(result.symlinks_created, 1);
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(
            fs::read_link(gn.path.join("bin/priority-tool")).unwrap(),
            explicit.join("bin/priority-tool"),
        );
    }

    #[test]
    fn shared_package_data_directories_coexist() {
        let tmp = TempDir::new().unwrap();
        let generation = make_generation(&tmp, 1);
        let first = make_store_path(
            &tmp,
            "first",
            &[
                "share/doc/first/README",
                "share/info/first.info",
                "share/locale/en/LC_MESSAGES/first.mo",
                "lib/pkgconfig/first.pc",
                "share/bash-completion/completions/first",
            ],
        );
        let second = make_store_path(
            &tmp,
            "second",
            &[
                "share/doc/second/README",
                "share/info/second.info",
                "share/locale/en/LC_MESSAGES/second.mo",
                "lib/pkgconfig/second.pc",
                "share/bash-completion/completions/second",
            ],
        );

        let result = build_fhs_tree(
            &generation,
            &[
                ("first".into(), first.clone()),
                ("second".into(), second.clone()),
            ],
            &test_printer(),
        )
        .unwrap();

        assert!(result.conflicts.is_empty());
        assert_eq!(result.symlinks_created, 10);
        for (package, source) in [("first", first), ("second", second)] {
            for path in [
                format!("share/doc/{package}/README"),
                format!("share/info/{package}.info"),
                format!("share/locale/en/LC_MESSAGES/{package}.mo"),
                format!("lib/pkgconfig/{package}.pc"),
                format!("share/bash-completion/completions/{package}"),
            ] {
                assert_eq!(
                    fs::read_link(generation.path.join(&path)).unwrap(),
                    source.join(path)
                );
            }
        }
    }

    #[test]
    fn directory_symlink_and_real_directory_conflicts_follow_package_order() {
        let tmp = TempDir::new().unwrap();
        let generation = make_generation(&tmp, 1);
        let linked = make_store_path(&tmp, "linked", &["share/target/original"]);
        std::os::unix::fs::symlink("target", linked.join("share/data")).unwrap();
        let real = make_store_path(&tmp, "real", &["share/data/new"]);

        let result = build_fhs_tree(
            &generation,
            &[
                ("linked".into(), linked.clone()),
                ("real".into(), real.clone()),
            ],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].path, "share/data");
        assert!(!generation.path.join("share/data").is_symlink());
        assert_eq!(
            fs::read_link(generation.path.join("share/data/new")).unwrap(),
            real.join("share/data/new")
        );
        assert!(!linked.join("share/target/new").exists());

        let result = build_fhs_tree(
            &generation,
            &[("real".into(), real), ("linked".into(), linked.clone())],
            &test_printer(),
        )
        .unwrap();

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(
            fs::read_link(generation.path.join("share/data")).unwrap(),
            linked.join("share/data")
        );
        assert!(!generation.path.join("share/data/new").exists());
    }

    #[test]
    fn rebuilding_a_shallow_profile_does_not_modify_the_store() {
        let tmp = TempDir::new().unwrap();
        let generation = make_generation(&tmp, 1);
        let first = make_store_path(&tmp, "first", &["share/doc/first/README"]);
        let second = make_store_path(&tmp, "second", &["share/doc/second/README"]);
        fs::create_dir_all(generation.path.join("share")).unwrap();
        std::os::unix::fs::symlink(first.join("share/doc"), generation.path.join("share/doc"))
            .unwrap();

        build_fhs_tree(
            &generation,
            &[("first".into(), first.clone()), ("second".into(), second)],
            &test_printer(),
        )
        .unwrap();

        assert!(generation.path.join("share/doc/first/README").exists());
        assert!(generation.path.join("share/doc/second/README").exists());
        assert!(!first.join("share/doc/second").exists());
    }

    // 5. clear_fhs_tree removes FHS dirs but preserves bookkeeping.
    #[test]
    fn clear_preserves_profile_bookkeeping() {
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
        fs::create_dir_all(gn.path.join("meta")).unwrap();
        fs::write(gn.path.join("meta/abc123.json"), "{}").unwrap();
        fs::create_dir_all(gn.path.join("expose")).unwrap();
        fs::write(gn.path.join("expose/retired"), "stale").unwrap();
        fs::create_dir_all(gn.path.join("expose-images")).unwrap();
        fs::write(gn.path.join("expose-images/retired"), "stale").unwrap();

        clear_fhs_tree(&gn).unwrap();

        // FHS dirs should be gone.
        assert!(!gn.path.join("bin").exists());
        assert!(!gn.path.join("lib").exists());
        assert!(!gn.path.join("share").exists());
        assert!(!gn.path.join("expose").exists());
        assert!(!gn.path.join("expose-images").exists());

        // Bookkeeping dirs should be preserved.
        assert!(gn.path.join("usr").exists());
        assert!(gn.path.join("usr/abc123").exists());
        assert!(gn.path.join("src").exists());
        assert!(gn.path.join("src/abc123").exists());
        assert!(gn.path.join("meta").exists());
        assert!(gn.path.join("meta/abc123.json").exists());
    }

    // 6. Man pages land in correct share/man/manN/ sections.
    #[test]
    fn man_pages_correct_sections() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc-curl",
            &["share/man/man1/curl.1", "share/man/man3/libcurl.3"],
        );

        let result =
            build_fhs_tree(&gn, &[("curl".to_string(), sp.clone())], &test_printer()).unwrap();

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

        build_fhs_tree(&gn, &[("curl".to_string(), sp)], &test_printer()).unwrap();

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

    // Completion scripts and man pages are both recursive leaf entries.
    #[test]
    fn share_recurses_through_man_and_completions() {
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

        // Both shared directories retain their individual files.
        assert!(files.contains_key("share/bash-completion/completions/bash"));
        assert!(files.contains_key("share/man/man1/bash.1"));
        // Directories are materialized in the profile instead of linked wholesale.
        assert!(files.get("share/man").unwrap().directory);
    }

    // 12. build_fhs_tree then clear_fhs_tree round-trips cleanly.
    #[test]
    fn build_then_clear_round_trip() {
        let tmp = TempDir::new().unwrap();
        let gn = make_generation(&tmp, 1);
        let sp = make_store_path(
            &tmp,
            "abc-curl",
            &["bin/curl", "lib/libcurl.so", "share/man/man1/curl.1"],
        );

        // Create usr/ to simulate a real generation with GC roots.
        fs::create_dir_all(gn.path.join("usr")).unwrap();

        build_fhs_tree(&gn, &[("curl".to_string(), sp)], &test_printer()).unwrap();

        // Verify symlinks are present.
        assert!(gn.path.join("bin/curl").symlink_metadata().is_ok());
        assert!(gn.path.join("lib/libcurl.so").symlink_metadata().is_ok());
        assert!(
            gn.path
                .join("share/man/man1/curl.1")
                .symlink_metadata()
                .is_ok()
        );

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
            &["etc/ssl/openssl.cnf", "include/openssl/ssl.h"],
        );

        let result =
            build_fhs_tree(&gn, &[("openssl".to_string(), sp.clone())], &test_printer()).unwrap();

        assert_eq!(result.symlinks_created, 2);

        let etc_ssl = gn.path.join("etc/ssl");
        assert!(etc_ssl.symlink_metadata().unwrap().file_type().is_dir());
        assert_eq!(
            fs::read_link(etc_ssl.join("openssl.cnf")).unwrap(),
            sp.join("etc/ssl/openssl.cnf"),
        );

        let inc_openssl = gn.path.join("include/openssl");
        assert!(inc_openssl.symlink_metadata().unwrap().file_type().is_dir());
        assert_eq!(
            fs::read_link(inc_openssl.join("ssl.h")).unwrap(),
            sp.join("include/openssl/ssl.h"),
        );
    }
}
