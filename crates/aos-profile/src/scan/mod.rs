//! Per-path content scanner: locate and classify embedded references.
//!
//! Given a *referrer* store path and a set of *target* paths it is known
//! to reference (from `nix-store --query --references`), this module
//! walks the referrer's files and finds where each target's 32-character
//! store hash actually appears — in an ELF section, a shebang, a symlink
//! target, a `pkg-config` file, and so on. The output is a list of
//! [`RefSite`]s per target, which the verdict engine folds into a
//! ruling about whether the reference is load-bearing at runtime.
//!
//! Scanning reads files directly from the local store, so it must run on
//! a host where the closure is realised (the build host). It never
//! follows symlinks out of a store path, and reads symlink *targets* as
//! reference-bearing strings in their own right.

pub mod classify;
pub mod elf;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

pub use classify::{FileCategory, RefLocus, split_store_path, store_hash, store_name};

/// One place a reference to a target path was found.
#[derive(Debug, Clone, Serialize)]
pub struct RefSite {
    /// Path of the containing file, relative to the referrer store path.
    pub file: String,
    /// The kind of file the reference lives in.
    pub category: FileCategory,
    /// Where, within that file, the reference string sits.
    pub locus: RefLocus,
}

/// Returns whether `path` ships any shared library (an `*.so*` file).
///
/// Used to recognise *dead* RPATH/RUNPATH entries: an RPATH that points
/// at a package containing no shared object can never satisfy a runtime
/// load, so the reference that created it is spurious rather than
/// load-bearing. Header-only and build-tool packages are the usual
/// culprits.
pub fn provides_shared_lib(path: &str) -> bool {
    fn walk(dir: &Path) -> bool {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if walk(&p) {
                    return true;
                }
            } else if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && is_shared_object(name)
            {
                return true;
            }
        }
        false
    }
    walk(Path::new(path))
}

/// Returns whether `path` ships any executable file.
///
/// "Executable" means a regular file carrying any Unix execute bit.
/// Together with [`provides_shared_lib`] this distinguishes paths that
/// contribute a runnable or loadable artifact from inert ones (headers,
/// data, source) whose presence in a runtime closure is suspect.
pub fn provides_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fn walk(dir: &Path) -> bool {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if walk(&p) {
                    return true;
                }
            } else if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                return true;
            }
        }
        false
    }
    walk(Path::new(path))
}

/// Returns whether a filename names an ELF shared object.
///
/// A real shared library ends in `.so` or carries a versioned suffix
/// (`.so.1`, `.so.6.0`), so the `.so` token must be followed by the end
/// of the name or a `.`. This excludes incidental matches such as the
/// kernel header build artifact `.socket.h.cmd`, where `.so` is part of
/// an unrelated word.
fn is_shared_object(name: &str) -> bool {
    name.match_indices(".so").any(|(i, _)| {
        let after = &name[i + 3..];
        after.is_empty() || after.starts_with('.')
    })
}

/// Scans `referrer` for references to each path in `targets`.
///
/// `targets` maps a 32-character store hash to the full store path it
/// identifies; only those hashes are searched for, so the cost is bound
/// to the referrer's declared dependency set rather than the whole
/// store. The referrer's own hash should be omitted by the caller to
/// avoid self-matches.
///
/// Returns a map from each referenced target path to the deduplicated
/// sites (by file and locus) at which it was found. Targets with no
/// surviving site are omitted.
///
/// # Errors
///
/// Returns an error if the referrer directory cannot be traversed.
/// Individual unreadable files are skipped rather than aborting the
/// scan.
pub fn scan_path(
    referrer: &str,
    targets: &HashMap<String, String>,
) -> Result<HashMap<String, Vec<RefSite>>> {
    // Stable index space for the multi-pattern search.
    let hashes: Vec<(String, String)> = targets
        .iter()
        .map(|(h, p)| (h.clone(), p.clone()))
        .collect();
    let needles: Vec<&[u8]> = hashes.iter().map(|(h, _)| h.as_bytes()).collect();
    let first_byte = build_first_byte_index(&needles);

    let mut out: HashMap<String, Vec<RefSite>> = HashMap::new();
    let mut seen: HashMap<String, std::collections::HashSet<(String, RefLocus)>> = HashMap::new();
    let root = Path::new(referrer);

    visit(
        root,
        root,
        &hashes,
        &needles,
        &first_byte,
        &mut |target, site| {
            let key = (site.file.clone(), site.locus);
            if seen.entry(target.clone()).or_default().insert(key) {
                out.entry(target).or_default().push(site);
            }
        },
    )
    .with_context(|| format!("scanning {referrer}"))?;

    Ok(out)
}

/// Recursively walks `dir`, invoking `emit` for every reference site.
fn visit(
    root: &Path,
    dir: &Path,
    hashes: &[(String, String)],
    needles: &[&[u8]],
    first_byte: &[Vec<usize>; 256],
    emit: &mut dyn FnMut(String, RefSite),
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();

        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(&path) {
                let bytes = target.to_string_lossy();
                for (idx, _) in find_all(bytes.as_bytes(), needles, first_byte) {
                    let (_, full) = &hashes[idx];
                    emit(
                        full.clone(),
                        RefSite {
                            file: rel.clone(),
                            category: FileCategory::Symlink,
                            locus: RefLocus::SymlinkTarget,
                        },
                    );
                }
            }
        } else if meta.is_dir() {
            visit(root, &path, hashes, needles, first_byte, emit)?;
        } else if meta.is_file() {
            scan_file(&path, &rel, hashes, needles, first_byte, emit);
        }
    }
    Ok(())
}

/// Reads one regular file and emits a site for every reference found.
fn scan_file(
    path: &Path,
    rel: &str,
    hashes: &[(String, String)],
    needles: &[&[u8]],
    first_byte: &[Vec<usize>; 256],
    emit: &mut dyn FnMut(String, RefSite),
) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let hits = find_all(&data, needles, first_byte);
    if hits.is_empty() {
        return;
    }

    let head = &data[..data.len().min(2)];
    let base_category = classify::classify_file(rel, head);
    let elf = elf::parse(&data);
    let category = match &elf {
        Some(info) if info.is_shared => FileCategory::SharedLib,
        Some(_) => FileCategory::ElfExecutable,
        None => base_category,
    };
    let shebang_end = if base_category == FileCategory::Script {
        data.iter().position(|&b| b == b'\n').unwrap_or(data.len())
    } else {
        0
    };

    for (idx, offset) in hits {
        let (hash, full) = &hashes[idx];
        let locus = locus_for(&elf, base_category, offset, shebang_end, hash);
        emit(
            full.clone(),
            RefSite {
                file: rel.to_string(),
                category,
                locus,
            },
        );
    }
}

/// Determines the [`RefLocus`] of a hit at `offset` in a file.
fn locus_for(
    elf: &Option<elf::ElfInfo>,
    category: FileCategory,
    offset: usize,
    shebang_end: usize,
    hash: &str,
) -> RefLocus {
    if let Some(info) = elf {
        // Dynamic-linker path and search paths are the strongest signals
        // and are not always inside an obviously-named section.
        if info.interp.as_deref().is_some_and(|s| s.contains(hash)) {
            return RefLocus::ElfInterp;
        }
        if info.runpaths.iter().any(|r| r.contains(hash)) {
            return RefLocus::ElfRunpath;
        }
        return match info.section_at(offset as u64) {
            Some(".interp") => RefLocus::ElfInterp,
            Some(".dynstr") => RefLocus::ElfRunpath,
            Some(".comment") => RefLocus::ElfComment,
            Some(name) if name.starts_with(".note") => RefLocus::ElfComment,
            Some(name) if name.starts_with(".debug") => RefLocus::ElfDebug,
            Some(".symtab" | ".strtab" | ".dynsym") => RefLocus::ElfDebug,
            _ => RefLocus::ElfLoadable,
        };
    }

    match category {
        FileCategory::Script if offset <= shebang_end => RefLocus::Shebang,
        FileCategory::Script => RefLocus::ScriptBody,
        FileCategory::PkgConfig => RefLocus::PkgConfig,
        FileCategory::LibtoolLa => RefLocus::LibtoolLa,
        FileCategory::ConfigScript => RefLocus::ConfigScript,
        FileCategory::Header => RefLocus::Header,
        FileCategory::StaticLib => RefLocus::StaticArchive,
        FileCategory::NixSupport => RefLocus::NixSupport,
        FileCategory::Doc => RefLocus::Doc,
        FileCategory::Source => RefLocus::Source,
        _ => RefLocus::PlainData,
    }
}

/// Builds a 256-way index from a needle's first byte to the needles
/// starting with it, so the search can skip most positions cheaply.
fn build_first_byte_index(needles: &[&[u8]]) -> [Vec<usize>; 256] {
    let mut table: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, n) in needles.iter().enumerate() {
        if let Some(&b) = n.first() {
            table[b as usize].push(i);
        }
    }
    table
}

/// Finds every `(needle_index, offset)` occurrence of any needle in
/// `haystack` using the first-byte index to prune comparisons.
fn find_all(
    haystack: &[u8],
    needles: &[&[u8]],
    first_byte: &[Vec<usize>; 256],
) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    if haystack.is_empty() {
        return hits;
    }
    for (pos, &b) in haystack.iter().enumerate() {
        let candidates = &first_byte[b as usize];
        if candidates.is_empty() {
            continue;
        }
        for &idx in candidates {
            let n = needles[idx];
            if haystack.len() - pos >= n.len() && &haystack[pos..pos + n.len()] == n {
                hits.push((idx, pos));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_object_name_matching() {
        assert!(is_shared_object("libsystemd.so"));
        assert!(is_shared_object("libc.so.6"));
        assert!(is_shared_object("libfoo.so.1.2.3"));
        // Kernel-header build artifacts must not count as libraries.
        assert!(!is_shared_object(".socket.h.cmd"));
        assert!(!is_shared_object(".sonet.h.cmd"));
        assert!(!is_shared_object("sound.h"));
        assert!(!is_shared_object("resolv.conf"));
    }

    #[test]
    fn finds_multiple_needles() {
        let needles: Vec<&[u8]> = vec![b"abcd", b"wxyz"];
        let idx = build_first_byte_index(&needles);
        let hits = find_all(b"__abcd__wxyz__abcd", &needles, &idx);
        assert_eq!(hits, vec![(0, 2), (1, 8), (0, 14)]);
    }

    #[test]
    fn scans_a_directory_tree() {
        let dir = tempfile::tempdir().unwrap();
        let hash = "0000000000000000000000000000aaaa";
        let dep = format!("/nix/store/{hash}-libdep-1.0");
        fs::create_dir_all(dir.path().join("lib/pkgconfig")).unwrap();
        fs::write(
            dir.path().join("lib/pkgconfig/foo.pc"),
            format!("libdir={dep}/lib\n"),
        )
        .unwrap();

        let mut targets = HashMap::new();
        targets.insert(hash.to_string(), dep.clone());
        let found = scan_path(&dir.path().to_string_lossy(), &targets).unwrap();
        let sites = found.get(&dep).expect("dep found");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].locus, RefLocus::PkgConfig);
    }
}
