//! Pinned image files, bounded decompression, and stable filesystem identity checks.

use crate::registry_ops::store_paths::{StorePathInfo, store_dir_from_store_path};
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

pub(in crate::registry_ops) struct ValidatedImageDirectory {
    pub(in crate::registry_ops) path: PathBuf,
    pub(in crate::registry_ops) file: fs::File,
    pub(in crate::registry_ops) identity: FileIdentity,
}

pub(in crate::registry_ops) struct ValidatedImageFile {
    pub(in crate::registry_ops) path: PathBuf,
    pub(in crate::registry_ops) file: fs::File,
    pub(in crate::registry_ops) identity: FileIdentity,
    pub(in crate::registry_ops) path_bound: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(in crate::registry_ops) struct FileIdentity {
    pub(in crate::registry_ops) len: u64,
    pub(in crate::registry_ops) modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    pub(in crate::registry_ops) device: u64,
    #[cfg(unix)]
    pub(in crate::registry_ops) inode: u64,
    #[cfg(unix)]
    pub(in crate::registry_ops) links: u64,
}

pub(in crate::registry_ops) fn validate_lower_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

pub(in crate::registry_ops) fn open_canonical_store_regular_file(
    store: &StorePathInfo,
    label: &str,
) -> Result<(fs::File, FileIdentity, PathBuf)> {
    if store_dir_from_store_path(&store.path).is_none() {
        bail!("published {label} must be a canonical Nix store path");
    }
    let path = PathBuf::from(&store.path);
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("canonicalizing {label} {}", path.display()))?;
    if canonical != path {
        bail!("published {label} must not traverse aliases or symlinks");
    }
    let (file, identity) = open_stable_regular_file_with_links(&path, true)
        .with_context(|| format!("opening {label} {}", path.display()))?;
    Ok((file, identity, path))
}

pub(in crate::registry_ops) fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    FileIdentity {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        links: metadata.nlink(),
    }
}

/// Opens a regular file while allowing store-optimizer links only for an
/// already-validated immutable Nix store output.
pub(in crate::registry_ops) fn open_stable_regular_file_with_links(
    path: &Path,
    allow_immutable_store_links: bool,
) -> Result<(fs::File, FileIdentity)> {
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!(
            "artifact must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let handle = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {}", path.display()))?;
    let file = fs::File::from(handle);
    let opened_identity = file_identity(&file.metadata()?);
    #[cfg(unix)]
    if !allow_immutable_store_links && opened_identity.links != 1 {
        bail!(
            "artifact must have exactly one hard link: {}",
            path.display()
        );
    }
    if file_identity(&path_metadata) != opened_identity {
        bail!("artifact identity changed while opening {}", path.display());
    }
    Ok((file, opened_identity))
}

/// Opens a direct child while allowing store-optimizer links only for an
/// already-validated immutable Nix store output.
pub(in crate::registry_ops) fn open_stable_regular_file_at_with_links(
    directory: &fs::File,
    name: &str,
    display_path: &Path,
    allow_immutable_store_links: bool,
) -> Result<(fs::File, FileIdentity)> {
    let handle = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {}", display_path.display()))?;
    let file = fs::File::from(handle);
    let identity = file_identity(&file.metadata()?);
    #[cfg(unix)]
    if !allow_immutable_store_links && identity.links != 1 {
        bail!(
            "artifact must have exactly one hard link: {}",
            display_path.display()
        );
    }
    if !file.metadata()?.is_file() {
        bail!(
            "artifact must be a regular file: {}",
            display_path.display()
        );
    }
    Ok((file, identity))
}

impl ValidatedImageFile {
    pub(in crate::registry_ops) fn recheck(&self) -> Result<()> {
        if self.path_bound {
            verify_stable_regular_file(&self.path, &self.file, &self.identity)
        } else if file_identity(&self.file.metadata()?) != self.identity {
            bail!("pinned canonical artifact changed before commit")
        } else {
            Ok(())
        }
    }
}

pub(in crate::registry_ops) fn verify_stable_regular_file(
    path: &Path,
    file: &fs::File,
    expected: &FileIdentity,
) -> Result<()> {
    let descriptor_identity = file_identity(&file.metadata()?);
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("rechecking {}", path.display()))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || &descriptor_identity != expected
        || &file_identity(&path_metadata) != expected
    {
        bail!("artifact identity changed while reading {}", path.display());
    }
    Ok(())
}

pub(in crate::registry_ops) fn validate_single_filename(filename: &str, label: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > 128
        || !filename.is_ascii()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        || !filename
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || filename.contains("..")
    {
        bail!("{label} must be a portable ASCII basename");
    }
    Ok(())
}

/// Returns the lowercase hexadecimal SHA-256 read from one retained file
/// descriptor without retaining the potentially large artifact in memory.
pub(in crate::registry_ops) fn sha256_open_file(
    file: &mut fs::File,
    path: &Path,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seeking image bytes {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading image bytes {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}
