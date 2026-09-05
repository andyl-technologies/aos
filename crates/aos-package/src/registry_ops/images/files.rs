//! Pinned image files, bounded decompression, and stable filesystem identity checks.

use crate::registry_ops::images::{MAX_ZSTD_WINDOW_LOG, PublishedImage};
use crate::registry_ops::store_paths::{StorePathInfo, store_dir_from_store_path};
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Duplicates a pinned descriptor and exposes only that descriptor to a child.
#[cfg(target_os = "linux")]
pub(in crate::registry_ops) fn inheritable_procfd(
    file: &fs::File,
    _fallback: &Path,
) -> Result<(fs::File, PathBuf)> {
    let duplicate = file
        .try_clone()
        .context("duplicating pinned image descriptor")?;
    rustix::io::fcntl_setfd(&duplicate, rustix::io::FdFlags::empty())
        .context("making pinned image descriptor inheritable")?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", duplicate.as_raw_fd()));
    Ok((duplicate, path))
}

#[cfg(not(target_os = "linux"))]
pub(in crate::registry_ops) fn inheritable_procfd(
    file: &fs::File,
    fallback: &Path,
) -> Result<(fs::File, PathBuf)> {
    Ok((
        file.try_clone()
            .context("duplicating pinned image descriptor")?,
        fallback.to_path_buf(),
    ))
}

/// Proves that the separately verified UKI is byte-identical to the UKI
/// embedded in the disk image at the signed ESP path.
#[cfg(target_os = "linux")]
fn decompress_raw_disk(
    source: impl std::io::Read,
    destination: &mut impl std::io::Write,
    expected_size: u64,
) -> Result<()> {
    let mut decoder =
        zstd::stream::read::Decoder::new(source).context("opening compressed raw disk")?;
    decoder
        .window_log_max(MAX_ZSTD_WINDOW_LOG)
        .context("bounding compressed raw disk decode window")?;
    let copied = std::io::copy(
        &mut decoder.take(expected_size.saturating_add(1)),
        destination,
    )
    .context("decompressing canonical raw disk")?;
    if copied != expected_size {
        bail!("compressed raw image expands to {copied} bytes, expected {expected_size}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decompress_pinned_raw_disk(
    source: &fs::File,
    destination: &mut impl std::io::Write,
    expected_size: u64,
) -> Result<()> {
    let mut disk = source
        .try_clone()
        .context("duplicating compressed raw disk")?;
    // File::try_clone shares the open-file-description offset on Unix. Image
    // hashing intentionally leaves that offset at EOF, so every independent
    // consumer must establish its own starting position before reading.
    disk.seek(SeekFrom::Start(0))?;
    decompress_raw_disk(disk, destination, expected_size)
}

#[cfg(target_os = "linux")]
pub(in crate::registry_ops) fn verify_embedded_uki(image: &PublishedImage) -> Result<()> {
    let mut raw = tempfile::tempfile().context("creating pinned raw-image verification file")?;
    let raw_input;
    let raw_path = if image.format == "raw" {
        decompress_pinned_raw_disk(&image.disk.file, &mut raw, image.virtual_size_bytes)?;
        raw.seek(SeekFrom::Start(0))?;
        let (file, path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        raw_input = Some(file);
        path
    } else {
        let (input_file, input_path) = inheritable_procfd(&image.disk.file, &image.disk.path)?;
        // qemu-img must write through the already-open descriptor so path
        // replacement cannot redirect verification. Pre-size the bounded raw
        // target and use -n to suppress target creation and overwrite prompts.
        raw.set_len(image.virtual_size_bytes)
            .context("sizing pinned raw-image verification file")?;
        let (output_file, output_path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        let qemu_img = std::env::var_os("AOS_QEMU_IMG")
            .map(PathBuf::from)
            .context("AOS_QEMU_IMG is required to verify converted image contents")?;
        let input_format = if image.format == "vhd" {
            "vpc"
        } else {
            image.format.as_str()
        };
        let status = Command::new(qemu_img)
            .args(["convert", "-n", "-f", input_format, "-O", "raw"])
            .arg(&input_path)
            .arg(&output_path)
            .status()
            .context("running qemu-img against pinned image descriptors")?;
        drop(output_file);
        drop(input_file);
        if !status.success() {
            bail!("qemu-img failed while materializing the canonical disk for UKI verification");
        }
        raw.seek(SeekFrom::Start(0))?;
        let (file, path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        raw_input = Some(file);
        path
    };

    let mut logical_disk = raw.try_clone().context("duplicating canonical raw disk")?;
    let logical_disk_sha256 = sha256_open_file(&mut logical_disk, Path::new("<logical disk>"))?;
    if logical_disk_sha256 != image.delivery.logical_disk_sha256 {
        bail!("image encoding does not materialize the signed canonical logical disk");
    }
    let rootfs_sha256 = sha256_file_range(
        &mut logical_disk,
        image.root_range.0,
        image.root_range.1,
        "root filesystem partition",
    )?;
    if rootfs_sha256 != image.delivery.rootfs_sha256 {
        bail!("disk root filesystem payload does not match signed logical image identity");
    }

    let mut extracted = tempfile::tempfile().context("creating pinned embedded-UKI file")?;
    let (extracted_child, extracted_path) =
        inheritable_procfd(&extracted, Path::new("<embedded UKI>"))?;
    let mcopy = std::env::var_os("AOS_MCOPY")
        .map(PathBuf::from)
        .context("AOS_MCOPY is required to verify embedded image contents")?;
    let image_spec = format!("{}@@{}", raw_path.display(), image.esp_offset_bytes);
    let source = format!("::/{}", image.delivery.uki.esp_path);
    let status = Command::new(mcopy)
        .env("MTOOLS_SKIP_CHECK", "1")
        // The pinned procfd is an existing Unix destination. `-n` prevents
        // mcopy from reading the maintainer's terminal for overwrite consent.
        .args(["-n", "-i"])
        .arg(image_spec)
        .arg(source)
        .arg(&extracted_path)
        .status()
        .context("extracting the embedded UKI through pinned descriptors")?;
    drop(extracted_child);
    drop(raw_input);
    if !status.success() {
        bail!("the declared UKI is not readable from the disk image ESP");
    }
    extracted.seek(SeekFrom::Start(0))?;
    let extracted_identity = file_identity(&extracted.metadata()?);
    let extracted_sha256 = sha256_open_file(&mut extracted, Path::new("<embedded UKI>"))?;
    if extracted_identity.len != image.delivery.uki.byte_size
        || extracted_sha256 != image.delivery.uki.sha256
    {
        bail!("the UKI embedded in the disk does not match the signed catalog UKI identity");
    }
    Ok(())
}

fn sha256_file_range(file: &mut fs::File, offset: u64, length: u64, label: &str) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seeking to {label}"))?;
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = file
            .read(&mut buffer[..wanted])
            .with_context(|| format!("reading {label}"))?;
        if count == 0 {
            bail!("{label} ended before its signed byte length");
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(not(target_os = "linux"))]
pub(in crate::registry_ops) fn verify_embedded_uki(_image: &PublishedImage) -> Result<()> {
    bail!("image publication requires Linux descriptor-backed verification")
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

pub(in crate::registry_ops) fn validate_portable_relative_path(
    path: &str,
    label: &str,
) -> Result<()> {
    if path.is_empty() || path.len() > 256 || !path.is_ascii() || path.contains('\\') {
        bail!("{label} must be a non-empty portable relative path");
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
        {
            bail!("{label} must be a non-empty portable relative path");
        }
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

#[cfg(test)]
mod tests;
