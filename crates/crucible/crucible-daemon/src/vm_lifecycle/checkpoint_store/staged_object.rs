//! Closure objects staged on disk while a closure manifest is assembled.
//!
//! A closure holds one QEMU snapshot envelope per node and one host-I/O
//! continuation per failed node, and any of them may approach the authored
//! `fat_checkpoint_bytes`. Publication used to encode every one into memory
//! before the manifest could be built. Each is now written to a temporary
//! file in the object directory as it is encoded, and hashed in the same
//! pass, so a closure's large envelopes are never resident together.
//!
//! A staged object is published by linking its file under its content
//! identity, after re-authenticating it, and is removed when dropped.

use super::*;

/// One closure object written to a temporary file and hashed as it was written.
#[derive(Debug)]
pub(super) struct StagedObject {
    file: tempfile::NamedTempFile,
    identity: ContentHash,
    length: u64,
}

impl StagedObject {
    /// Returns the content identity derived while writing.
    pub(super) const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the staged length in bytes.
    pub(super) const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the temporary file's path.
    pub(super) fn path(&self) -> &Path {
        self.file.path()
    }
}

/// Streams a node's QEMU snapshot envelope into a staged object.
///
/// The snapshot encoder writes one nested owner at a time, so only that
/// owner's encoding is resident.
pub(super) fn stage_snapshot_with_boundary(
    directory: &Path,
    node: &NodeId,
    snapshot: &ExactSnapshotHandle,
    fat_checkpoint_bytes: u64,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<StagedObject, SchedulerError> {
    let mut writer = StagingWriter::create(directory, boundary)?;
    let encoded = snapshot.write_canonical_with_limit(fat_checkpoint_bytes, &mut writer);
    // A boundary refusal surfaces through the writer as an I/O error; report
    // the refusal itself rather than the encoder's view of it.
    if let Some(error) = writer.boundary_error.take() {
        return Err(error);
    }
    encoded.map_err(|error| {
        store_error(format!("encode QEMU snapshot for `{}`: {error}", node.name))
    })?;
    writer.finish()
}

/// Writes already-encoded bytes into a staged object.
pub(super) fn stage_bytes_with_boundary(
    directory: &Path,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<StagedObject, SchedulerError> {
    let mut writer = StagingWriter::create(directory, boundary)?;
    let written = writer.write_all(bytes);
    if let Some(error) = writer.boundary_error.take() {
        return Err(error);
    }
    written.map_err(|error| store_error(format!("write staged checkpoint object: {error}")))?;
    writer.finish()
}

/// Publishes a staged object under its identity in `directory`.
///
/// The staged file is authenticated again before it is linked into place, so
/// a file changed after staging fails closed. An already-present object is
/// authenticated and synchronized instead.
pub(super) fn persist_staged_object_with_boundary(
    directory: &Path,
    staged: &StagedObject,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let destination = object_path(directory, staged.identity);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, staged.identity, boundary);
    }
    validate_file_hash_with_boundary(staged.path(), staged.identity, boundary)?;
    let parent = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(parent)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    boundary()?;
    // Linking never replaces an existing name, so a concurrent publisher of
    // the same identity leaves exactly one authenticated object.
    match fs::hard_link(staged.path(), &destination) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, staged.identity, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {error}",
            staged.identity.to_hex()
        ))),
    }
}

/// Temporary-file writer that hashes, counts, and observes the boundary.
struct StagingWriter<'a> {
    file: tempfile::NamedTempFile,
    hasher: blake3::Hasher,
    length: u64,
    boundary: &'a mut dyn FnMut() -> Result<(), SchedulerError>,
    boundary_error: Option<SchedulerError>,
}

impl<'a> StagingWriter<'a> {
    fn create(
        directory: &Path,
        boundary: &'a mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<Self, SchedulerError> {
        let file = tempfile::Builder::new()
            .prefix(".staged-")
            .tempfile_in(directory)
            .map_err(|error| store_error(format!("stage checkpoint object: {error}")))?;
        Ok(Self {
            file,
            hasher: blake3::Hasher::new(),
            length: 0,
            boundary,
            boundary_error: None,
        })
    }

    fn finish(self) -> Result<StagedObject, SchedulerError> {
        (self.boundary)()?;
        self.file
            .as_file()
            .sync_all()
            .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
        Ok(StagedObject {
            file: self.file,
            identity: ContentHash {
                bytes: *self.hasher.finalize().as_bytes(),
            },
            length: self.length,
        })
    }
}

impl Write for StagingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Large nested owners arrive as one write; split them so the
        // boundary is observed between bounded chunks.
        for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
            if let Err(error) = (self.boundary)() {
                self.boundary_error = Some(error);
                return Err(std::io::Error::other("checkpoint boundary refused staging"));
            }
            self.file.write_all(chunk)?;
            self.hasher.update(chunk);
            self.length = self
                .length
                .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
#[path = "staged_object_tests.rs"]
mod tests;
