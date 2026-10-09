//! Bounded immutable process images and private writable-resource reconstruction.
//!
//! Image authority is created only from an authenticated parked native owner.
//! A content reference identifies bytes; it cannot construct this capture seal.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crucible_node_contract::{ContentRef, HashRef, Id, U64, Validate};

use super::{Gem5Boundary, Gem5Completion, Gem5Launch, Gem5LaunchArtifact};
use crate::ProviderError;

#[path = "archive_import.rs"]
mod archive_import;

pub use archive_import::{Gem5ArchiveArtifact, Gem5ArchiveImport, Gem5ArchiveSourceVerifier};

const MAX_FILES: usize = 4096;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
/// Bounds each opaque image artifact under the installed native process profile.
pub const GEM5_MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Pins the actual process-image tools and private checkpoint resources.
#[derive(Clone, Debug)]
pub struct Gem5ProcessImageTools {
    /// Measures the actual installed DMTCP launcher.
    pub launcher: Gem5LaunchArtifact,
    /// Measures the actual installed DMTCP restarter.
    pub restarter: Gem5LaunchArtifact,
    /// Measures the actual executable mapped by a fresh DMTCP reconstruction.
    pub reconstruction_executable: Gem5LaunchArtifact,
    /// Measures the native private-resource rebinding helper.
    pub resource_helper: Gem5LaunchArtifact,
    /// Names a private directory dedicated to this owner's image files.
    pub image_root: PathBuf,
    /// Names a private directory dedicated to operational DMTCP files.
    pub temporary_root: PathBuf,
}

/// Selects fresh private reconstruction routes without changing captured state.
#[derive(Clone, Debug)]
pub struct Gem5RestoreTarget {
    /// Names a fresh native incarnation distinct from the captured source.
    pub incarnation: Id,
    /// Fences the source generation with a strictly larger owner generation.
    pub generation: U64,
    /// Names an empty canonical private directory for restored writable files.
    pub resource_root: PathBuf,
    /// Names an empty private namespace for this incarnation's future captures.
    ///
    /// It remains separate from historical image storage and writable resources.
    pub image_root: PathBuf,
    /// Names a private directory for new operational restore diagnostics.
    pub temporary_root: PathBuf,
    /// Bounds fresh peer establishment using operational host time.
    pub timeout: std::time::Duration,
}

#[derive(Clone, Debug)]
struct CapturedFile {
    relative: PathBuf,
    artifact: Gem5LaunchArtifact,
}

/// Distinguishes native image files from privately reconstructed resource files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gem5CapturedArtifactRole {
    /// Identifies the DMTCP primary image or an original supplementary saved file.
    Image,
    /// Identifies a private runtime resource copied into the fresh owner root.
    Resource,
}

/// Views an original immutable artifact with its exact reconstruction role and name.
#[derive(Clone, Copy, Debug)]
pub struct Gem5CapturedArtifact<'a> {
    /// Selects the original image or writable-resource reconstruction namespace.
    pub role: Gem5CapturedArtifactRole,
    /// Retains its checked path relative to that private namespace root.
    pub relative: &'a Path,
    /// Retains the independent preserved bytes and their measured content identity.
    pub artifact: &'a Gem5LaunchArtifact,
}

/// Retains a genuine stopped owner image and its original private file contents.
///
/// This opaque seal is created by native capture, never from a portable claim.
/// Partial diagnostic coverage grants no execution authority. A complete native
/// closure audit and installed closed-profile policy remain separate obligations.
#[derive(Clone, Debug)]
pub struct Gem5CapturedImage {
    pub(crate) capture: Id,
    pub(crate) source: Gem5Launch,
    pub(crate) boundary: Gem5Boundary,
    pub(crate) completed: BTreeMap<Id, Gem5Completion>,
    pub(crate) pending: Option<Id>,
    pub(crate) last_acknowledged: Option<Id>,
    image_files: Vec<CapturedFile>,
    resource_files: Vec<CapturedFile>,
}

impl Gem5CapturedImage {
    pub(crate) fn original_image_for_audit(&self) -> Result<PathBuf, ProviderError> {
        let tools = self
            .source
            .process_images
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "gem5 original image tools omitted",
            ))?;
        let current = inventory(&tools.image_root, true)?;
        if current.len() != self.image_files.len()
            || current.iter().zip(&self.image_files).any(|(live, saved)| {
                live.relative != saved.relative || live.artifact.content != saved.artifact.content
            })
        {
            return Err(ProviderError::Correlation(
                "gem5 original image custody differs from independent capture seal",
            ));
        }
        let name = self
            .process_image()?
            .file_name()
            .ok_or(ProviderError::Frame("gem5 process image filename omitted"))?;
        Ok(tools.image_root.join(name))
    }

    /// Iterates the exact bounded artifact roster with original reconstruction names.
    ///
    /// Portable archives must retain the role and relative name instead of
    /// inferring them from operational parent directories. This view conveys
    /// neither imported image provenance nor fresh live execution authority.
    pub fn artifact_inventory(&self) -> impl Iterator<Item = Gem5CapturedArtifact<'_>> {
        self.image_files
            .iter()
            .map(|file| Gem5CapturedArtifact {
                role: Gem5CapturedArtifactRole::Image,
                relative: &file.relative,
                artifact: &file.artifact,
            })
            .chain(self.resource_files.iter().map(|file| Gem5CapturedArtifact {
                role: Gem5CapturedArtifactRole::Resource,
                relative: &file.relative,
                artifact: &file.artifact,
            }))
    }

    /// Iterates every bounded independently preserved image and resource artifact.
    ///
    /// These host-local paths identify immutable capture-owned bytes for archive
    /// streaming. Their content references convey no restore or execution authority.
    pub fn artifacts(&self) -> impl Iterator<Item = &Gem5LaunchArtifact> {
        self.image_files
            .iter()
            .chain(&self.resource_files)
            .map(|file| &file.artifact)
    }

    /// Iterates immutable original prefixes captured with native continuation state.
    pub fn completed_prefixes(&self) -> impl ExactSizeIterator<Item = &Gem5Completion> {
        self.completed.values()
    }

    /// Returns the original captured output prefix awaiting custody acknowledgment.
    pub fn pending_completion(&self) -> Option<&Gem5Completion> {
        self.pending
            .as_ref()
            .and_then(|operation| self.completed.get(operation))
    }

    /// Returns the original captured native ACK identity without releasing custody.
    pub fn last_acknowledged(&self) -> Option<&Id> {
        self.last_acknowledged.as_ref()
    }

    /// Returns the original capture operation identity.
    pub fn capture_id(&self) -> &Id {
        &self.capture
    }

    /// Returns the exact original native stopped event boundary.
    pub fn boundary(&self) -> &Gem5Boundary {
        &self.boundary
    }

    /// Returns the immutable original source realization scope.
    pub fn source(&self) -> &Gem5Launch {
        &self.source
    }

    /// Verifies every original image and writable-resource artifact before allocation.
    ///
    /// # Errors
    /// Rejects omitted, replaced, linked, oversized, changing, or tampered files.
    pub fn verify(&self) -> Result<(), ProviderError> {
        let mut total = 0;
        for (saved, limit) in self
            .image_files
            .iter()
            .map(|file| (file, GEM5_MAX_IMAGE_BYTES))
            .chain(
                self.resource_files
                    .iter()
                    .map(|file| (file, MAX_FILE_BYTES)),
            )
        {
            let measured = measure_file_with_limit(&saved.artifact.path, limit)?;
            total = add_length(total, measured.length)?;
            if measured != saved.artifact.content {
                return Err(ProviderError::Correlation("gem5 captured artifact changed"));
            }
        }
        Ok(())
    }

    pub(crate) fn collect(
        capture: Id,
        source: Gem5Launch,
        boundary: Gem5Boundary,
        preserved_root: &Path,
        completed: BTreeMap<Id, Gem5Completion>,
        pending: Option<Id>,
        last_acknowledged: Option<Id>,
    ) -> Result<Self, ProviderError> {
        let tools = source
            .process_images
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "gem5 capture has no measured image tools",
            ))?;
        validate_private_directory(preserved_root)?;
        let original_images = inventory(&tools.image_root, true)?;
        if original_images
            .iter()
            .filter(|file| file.relative.extension().is_some_and(|ext| ext == "dmtcp"))
            .count()
            != 1
        {
            return Err(ProviderError::Correlation(
                "gem5 capture requires one genuine owner process image",
            ));
        }
        let original_resources = inventory(&source.resource_root, false)?;
        if original_images
            .len()
            .checked_add(original_resources.len())
            .is_none_or(|count| count > MAX_FILES)
        {
            return Err(ProviderError::ResourceExhausted(
                "gem5 complete capture file inventory",
            ));
        }
        // Reserve the complete aggregate extent before copying either namespace.
        let mut total = 0;
        for file in original_images.iter().chain(&original_resources) {
            total = add_length(total, file.artifact.content.length)?;
        }
        // DMTCP may reuse its live filename on a later checkpoint. Each seal
        // owns independent image bytes alongside its original resource bytes.
        let image_root = preserved_root.join("image-files");
        let resource_root = preserved_root.join("resource-files");
        fs::create_dir(&image_root)?;
        fs::create_dir(&resource_root)?;
        fs::set_permissions(&image_root, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&resource_root, fs::Permissions::from_mode(0o700))?;
        let mut image_files = Vec::new();
        for file in original_images {
            let target = image_root.join(&file.relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_verified(&file.artifact, &target, GEM5_MAX_IMAGE_BYTES)?;
            image_files.push(CapturedFile {
                relative: file.relative,
                artifact: Gem5LaunchArtifact {
                    path: target,
                    content: file.artifact.content,
                },
            });
        }
        let mut resource_files = Vec::new();
        for file in original_resources {
            let target = resource_root.join(&file.relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_verified(&file.artifact, &target, MAX_FILE_BYTES)?;
            resource_files.push(CapturedFile {
                relative: file.relative,
                artifact: Gem5LaunchArtifact {
                    path: target,
                    content: file.artifact.content,
                },
            });
        }
        let image = Self {
            capture,
            source,
            boundary,
            completed,
            pending,
            last_acknowledged,
            image_files,
            resource_files,
        };
        image.verify()?;
        Ok(image)
    }

    pub(crate) fn prepare_resources(&self, root: &Path) -> Result<(), ProviderError> {
        self.verify()?;
        validate_private_directory(root)?;
        if fs::read_dir(root)?.next().is_some() {
            return Err(ProviderError::Correlation(
                "gem5 restored resource root is occupied",
            ));
        }
        for saved in &self.resource_files {
            let target = root.join(&saved.relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_verified(&saved.artifact, &target, MAX_FILE_BYTES)?;
        }
        Ok(())
    }

    pub(crate) fn process_image(&self) -> Result<&Path, ProviderError> {
        self.image_files
            .iter()
            .find(|file| file.relative.extension().is_some_and(|ext| ext == "dmtcp"))
            .map(|file| file.artifact.path.as_path())
            .ok_or(ProviderError::Correlation(
                "gem5 original process image omitted",
            ))
    }
}

pub(crate) fn validate_private_directory(root: &Path) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
        || fs::canonicalize(root)? != root
    {
        return Err(ProviderError::Correlation(
            "gem5 directory is not canonically private",
        ));
    }
    Ok(())
}

pub(crate) fn measure_file(path: &Path) -> Result<ContentRef, ProviderError> {
    measure_file_with_limit(path, MAX_FILE_BYTES)
}

pub(crate) fn measure_image_file(path: &Path) -> Result<ContentRef, ProviderError> {
    measure_file_with_limit(path, GEM5_MAX_IMAGE_BYTES)
}

fn measure_file_with_limit(path: &Path, limit: u64) -> Result<ContentRef, ProviderError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err(ProviderError::Correlation(
            "gem5 artifact is not a bounded private regular file",
        ));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                .map_err(|_| ProviderError::Frame("native nofollow open flag unrepresentable"))?,
        )
        .open(path)?;
    let before = file.metadata()?;
    if before.dev() != metadata.dev() || before.ino() != metadata.ino() {
        return Err(ProviderError::Correlation(
            "gem5 artifact replaced before measurement",
        ));
    }
    let reference = hash_stream(&mut &file, before.len())?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(ProviderError::Correlation(
            "gem5 artifact changed during measurement",
        ));
    }
    Ok(reference)
}

// Hashes the exact canonical framing while keeping host allocation independent
// of checkpoint size. Both short and excess streams refuse unchanged identity.
fn hash_stream(reader: &mut impl Read, length: u64) -> Result<ContentRef, ProviderError> {
    if length > GEM5_MAX_IMAGE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "gem5 immutable artifact size",
        ));
    }
    let domain = "cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&length.to_be_bytes());
    let mut remaining = length;
    let mut buffer = [0u8; 65536];
    while remaining > 0 {
        let available = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ProviderError::ResourceExhausted("gem5 hash buffer extent"))?;
        let count = reader.read(&mut buffer[..available])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "gem5 artifact stream was truncated",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 {
        return Err(ProviderError::Correlation(
            "gem5 artifact stream exceeds its original extent",
        ));
    }
    let reference = ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".to_owned(),
            domain: domain.to_owned(),
            digest: hasher.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".to_owned(),
    };
    reference.validate()?;
    Ok(reference)
}

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod streaming_tests;

fn inventory(root: &Path, process_images: bool) -> Result<Vec<CapturedFile>, ProviderError> {
    validate_private_directory(root)?;
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    let mut total = 0;
    let mut directories = 1usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if process_images
                && entry.path() == root.join("dmtcp_restart_script.sh")
                && metadata.file_type().is_symlink()
            {
                // DMTCP's latest-image convenience route is never executed or
                // interpreted as image authority; the exact image is pinned.
                continue;
            }
            if metadata.is_dir() {
                directories =
                    directories
                        .checked_add(1)
                        .ok_or(ProviderError::ResourceExhausted(
                            "gem5 captured directory inventory",
                        ))?;
                if directories > MAX_FILES {
                    return Err(ProviderError::ResourceExhausted(
                        "gem5 captured directory inventory",
                    ));
                }
                pending.push(entry.path());
            } else if metadata.file_type().is_socket() && entry.path() == root.join("control.sock")
            {
                // Controller endpoints are operational routes, never image state.
            } else {
                if files.len() >= MAX_FILES {
                    return Err(ProviderError::ResourceExhausted(
                        "gem5 captured file inventory",
                    ));
                }
                let content = if process_images {
                    measure_image_file(&entry.path())?
                } else {
                    measure_file(&entry.path())?
                };
                total = add_length(total, content.length)?;
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| ProviderError::Correlation("gem5 artifact escaped private root"))?
                    .to_owned();
                files.push(CapturedFile {
                    relative,
                    artifact: Gem5LaunchArtifact {
                        path: entry.path(),
                        content,
                    },
                });
            }
        }
    }
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(files)
}

fn add_length(total: u64, length: U64) -> Result<u64, ProviderError> {
    total
        .checked_add(length.get())
        .filter(|next| *next <= MAX_TOTAL_BYTES)
        .ok_or(ProviderError::ResourceExhausted(
            "gem5 captured artifact bytes",
        ))
}

fn copy_verified(
    artifact: &Gem5LaunchArtifact,
    target: &Path,
    limit: u64,
) -> Result<(), ProviderError> {
    if measure_file_with_limit(&artifact.path, limit)? != artifact.content {
        return Err(ProviderError::Correlation(
            "gem5 original file bytes changed",
        ));
    }
    let source = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                .map_err(|_| ProviderError::Frame("native nofollow open flag unrepresentable"))?,
        )
        .open(&artifact.path)?;
    let mut file = fs::File::options()
        .write(true)
        .create_new(true)
        .open(target)?;
    let copied = std::io::copy(
        &mut source.take(artifact.content.length.get() + 1),
        &mut file,
    )?;
    if copied != artifact.content.length.get() {
        return Err(ProviderError::Correlation(
            "gem5 copied artifact extent changed",
        ));
    }
    file.sync_all()?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
    if measure_file_with_limit(target, limit)? != artifact.content {
        return Err(ProviderError::Correlation(
            "gem5 copied artifact bytes changed",
        ));
    }
    Ok(())
}
