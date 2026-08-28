//! Secure discovery and immutable snapshotting of runtime operator modules.
//!
//! Mutable files are traversed descriptor-relatively and opened with
//! `O_NOFOLLOW`; bytes are copied from the validated descriptors into a
//! private staging directory before the tree is admitted to the Nix store.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rustix::fs::{self, Dir, FileType, Mode, OFlags};

const MAX_DEPTH: usize = 16;
const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

/// One immutable snapshot ready to be passed to both evaluator projections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeModuleSnapshot {
    /// Recursive source-tree store path.
    pub store_path: PathBuf,
    /// Canonical NAR hash of [`Self::store_path`].
    pub nar_hash: String,
    /// Sorted direct entrypoint paths beneath [`Self::store_path`].
    pub entrypoints: Vec<PathBuf>,
}

/// Lists discoverable Dendritic entrypoints in a mutable worktree.
///
/// This is an operator-status helper only. [`snapshot`] repeats discovery from
/// opened descriptors and is the sole authority used for evaluation.
///
/// # Errors
///
/// Returns an error when the tree cannot be read or contains a symlink,
/// special object, unsafe name, or non-Nix regular file.
pub fn list_entrypoints(source: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    list_directory(source, Path::new(""), 0, &mut result)?;
    result.sort();
    Ok(result)
}

fn list_directory(
    source: &Path,
    relative: &Path,
    depth: usize,
    result: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("runtime module tree exceeds maximum depth {MAX_DEPTH}");
    }
    let mut entries = std::fs::read_dir(source)
        .with_context(|| format!("reading runtime module directory {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name_text = name.to_str().context("runtime module name is not UTF-8")?;
        if !valid_component_name(name_text) {
            bail!("invalid runtime module path component {name_text:?}");
        }
        let file_type = entry.file_type()?;
        let child_relative = relative.join(&name);
        if file_type.is_symlink() {
            bail!(
                "runtime module tree contains symlink {}",
                child_relative.display()
            );
        }
        if file_type.is_dir() {
            list_directory(&entry.path(), &child_relative, depth + 1, result)?;
        } else if file_type.is_file() {
            if !name_text.ends_with(".nix") {
                bail!(
                    "runtime module source contains non-Nix file {}",
                    child_relative.display()
                );
            }
            if !child_relative
                .components()
                .any(|component| component.as_os_str().as_bytes().starts_with(b"_"))
            {
                result.push(child_relative);
            }
        } else {
            bail!(
                "runtime module source contains unsupported object {}",
                child_relative.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct Limits {
    files: usize,
    bytes: u64,
}

/// Snapshots a runtime module worktree without following mutable path aliases.
///
/// When `require_root_owner` is true the source root must be owned by UID 0 and
/// neither group nor other writable. Tests and off-host preflight may disable
/// that ownership check while retaining no-follow traversal and all limits.
///
/// # Errors
///
/// Returns an error for unsafe ownership or modes, links, special objects,
/// hard links, unsafe or non-UTF-8 names, non-Nix regular files,
/// resource-limit excess, or a failed content-addressed store import.
pub fn snapshot(
    source: &Path,
    staging_parent: &Path,
    require_root_owner: bool,
) -> Result<RuntimeModuleSnapshot> {
    let root = fs::openat(
        fs::CWD,
        source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening runtime module worktree {}", source.display()))?;
    let stat = fs::fstat(&root).context("statting runtime module worktree descriptor")?;
    if require_root_owner && stat.st_uid != 0 {
        bail!("runtime module worktree must be owned by root");
    }
    if stat.st_mode & 0o022 != 0 {
        bail!("runtime module worktree must not be writable by group or other");
    }

    std::fs::create_dir_all(staging_parent).with_context(|| {
        format!(
            "creating snapshot staging parent {}",
            staging_parent.display()
        )
    })?;
    let staging_parent_dir = tempfile::Builder::new()
        .prefix("runtime-module-snapshot-")
        .tempdir_in(staging_parent)
        .context("creating private runtime module snapshot")?;
    let staging = staging_parent_dir.path().join("runtime-modules");
    std::fs::create_dir(&staging)?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;

    let mut limits = Limits::default();
    let mut entrypoints = Vec::new();
    copy_directory(
        &root,
        &staging,
        Path::new(""),
        0,
        require_root_owner,
        &mut limits,
        &mut entrypoints,
    )?;
    entrypoints.sort();
    sync_directory_tree(&staging)?;

    let output = std::process::Command::new("nix-store")
        .envs(aos_core::nix::aos_nix_env())
        .args(["--add-fixed", "--recursive", "sha256"])
        .arg(&staging)
        .output()
        .context("adding runtime module snapshot to the store")?;
    if !output.status.success() {
        bail!(
            "adding runtime module snapshot to the store failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = PathBuf::from(
        String::from_utf8(output.stdout)
            .context("nix-store returned a non-UTF-8 runtime module path")?
            .trim(),
    );
    if !store_path.starts_with("/nix/store") {
        bail!(
            "nix-store returned invalid runtime module path {}",
            store_path.display()
        );
    }
    let nar_hash = super::retained_store_path_nar_hash(&store_path)?;
    let entrypoints = entrypoints
        .into_iter()
        .map(|relative| store_path.join(relative))
        .collect();
    Ok(RuntimeModuleSnapshot {
        store_path,
        nar_hash,
        entrypoints,
    })
}

fn copy_directory(
    source: &OwnedFd,
    destination: &Path,
    relative: &Path,
    depth: usize,
    require_root_owner: bool,
    limits: &mut Limits,
    entrypoints: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("runtime module tree exceeds maximum depth {MAX_DEPTH}");
    }
    let mut entries = Dir::read_from(source)
        .context("opening descriptor-relative runtime module directory stream")?
        .map(|entry| entry.context("reading runtime module directory entry"))
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|left, right| {
        left.file_name()
            .to_bytes()
            .cmp(right.file_name().to_bytes())
    });

    for entry in entries {
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let name = std::str::from_utf8(bytes).context("runtime module name is not UTF-8")?;
        if !valid_component_name(name) {
            bail!("invalid runtime module path component {name:?}");
        }
        let child = fs::openat(
            source,
            OsStr::from_bytes(bytes),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening runtime module component {name:?}"))?;
        let stat =
            fs::fstat(&child).with_context(|| format!("statting runtime module {name:?}"))?;
        let child_relative = relative.join(name);
        if require_root_owner && (stat.st_uid != 0 || stat.st_mode & 0o022 != 0) {
            bail!(
                "runtime module object {} must be root-owned and not writable by group or other",
                child_relative.display()
            );
        }
        let child_destination = destination.join(name);
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                std::fs::create_dir(&child_destination).with_context(|| {
                    format!(
                        "creating snapshot directory {}",
                        child_destination.display()
                    )
                })?;
                std::fs::set_permissions(
                    &child_destination,
                    std::fs::Permissions::from_mode(0o700),
                )?;
                copy_directory(
                    &child,
                    &child_destination,
                    &child_relative,
                    depth + 1,
                    require_root_owner,
                    limits,
                    entrypoints,
                )?;
            }
            FileType::RegularFile => {
                if stat.st_nlink != 1 {
                    bail!(
                        "runtime module file {} is hard-linked",
                        child_relative.display()
                    );
                }
                if !name.ends_with(".nix") {
                    bail!(
                        "runtime module source contains non-Nix file {}",
                        child_relative.display()
                    );
                }
                let size =
                    u64::try_from(stat.st_size).context("runtime module has negative size")?;
                if size > MAX_FILE_BYTES {
                    bail!(
                        "runtime module {} exceeds {} bytes",
                        child_relative.display(),
                        MAX_FILE_BYTES
                    );
                }
                limits.files += 1;
                limits.bytes = limits.bytes.saturating_add(size);
                if limits.files > MAX_FILES || limits.bytes > MAX_TOTAL_BYTES {
                    bail!("runtime module set exceeds file-count or aggregate-byte limit");
                }
                copy_regular_file(child, &child_destination, size)?;
                if !child_relative
                    .components()
                    .any(|component| component.as_os_str().as_bytes().starts_with(b"_"))
                {
                    entrypoints.push(child_relative);
                }
            }
            _ => bail!(
                "runtime module source contains unsupported object {}",
                child_relative.display()
            ),
        }
    }
    Ok(())
}

fn valid_component_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn copy_regular_file(source: OwnedFd, destination: &Path, expected_size: u64) -> Result<()> {
    let mut source = File::from(source).take(MAX_FILE_BYTES + 1);
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    source.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? != expected_size {
        bail!("runtime module changed size while its descriptor was being read");
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| format!("creating snapshot file {}", destination.display()))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn sync_directory_tree(root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            sync_directory_tree(&path)?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_sorted_and_excludes_private_helpers() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("nested")).unwrap();
        std::fs::create_dir(source.path().join("_helpers")).unwrap();
        std::fs::write(source.path().join("z.nix"), b"{}").unwrap();
        std::fs::write(source.path().join("nested/a.nix"), b"{}").unwrap();
        std::fs::write(source.path().join("_helpers/types.nix"), b"{}").unwrap();

        assert_eq!(
            list_entrypoints(source.path()).unwrap(),
            [PathBuf::from("nested/a.nix"), PathBuf::from("z.nix")]
        );
    }

    #[test]
    fn discovery_rejects_symlinks_and_non_nix_files() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("module.nix"), b"{}").unwrap();
        std::os::unix::fs::symlink("module.nix", source.path().join("alias.nix")).unwrap();
        assert!(
            list_entrypoints(source.path())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );

        std::fs::remove_file(source.path().join("alias.nix")).unwrap();
        std::fs::write(source.path().join("notes.txt"), b"not an input").unwrap();
        assert!(
            list_entrypoints(source.path())
                .unwrap_err()
                .to_string()
                .contains("non-Nix")
        );
    }

    #[test]
    fn descriptor_copy_rejects_hard_links() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("module.nix"), b"{}").unwrap();
        std::fs::hard_link(
            source.path().join("module.nix"),
            source.path().join("copy.nix"),
        )
        .unwrap();
        let root = fs::openat(
            fs::CWD,
            source.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let error = copy_directory(
            &root,
            destination.path(),
            Path::new(""),
            0,
            false,
            &mut Limits::default(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("hard-linked"));
    }

    #[test]
    fn descriptor_copy_enforces_per_file_limit() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("large.nix"),
            vec![b'x'; usize::try_from(MAX_FILE_BYTES + 1).unwrap()],
        )
        .unwrap();
        let root = fs::openat(
            fs::CWD,
            source.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let error = copy_directory(
            &root,
            destination.path(),
            Path::new(""),
            0,
            false,
            &mut Limits::default(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn descriptor_copy_rejects_writable_objects_for_root_authority() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let module = source.path().join("module.nix");
        std::fs::write(&module, b"{}").unwrap();
        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o666)).unwrap();
        let root = fs::openat(
            fs::CWD,
            source.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let error = copy_directory(
            &root,
            destination.path(),
            Path::new(""),
            0,
            true,
            &mut Limits::default(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("root-owned"));
    }
}
