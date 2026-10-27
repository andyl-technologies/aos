//! Block overlay chunk objects named by exact-checkpoint block snapshots.
//!
//! A block snapshot carries its copy-on-write overlay as chunk records that
//! name each written 4 MiB chunk by its plain BLAKE3 object key (RFC-0020
//! CMEAS-33). The closure manifest lists the union of those keys, ascending,
//! in `block_overlay_chunks`, so the objects belong to the closure inventory
//! exactly like event-log segments.
//!
//! ```text
//! manifest.block_overlay_chunks = sorted_unique(
//!     chunk identities of every target snapshot's block continuation
//!   + chunk identities of every failed node's block continuation)
//! ```
//!
//! Publication copies each chunk from the live page store one at a time.
//! Loading charges each chunk once against the closure budget and binds a
//! chunk source to every decoded block snapshot; the device authenticates a
//! chunk when restore reads it. No step holds more than one chunk.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crucible_device::{
    BlockOverlayChunkSource, BlockOverlayImage, BlockSnapshot, OVERLAY_CHUNK_BYTES,
};

use super::super::checkpoint_event_log::ClosureObjectOpener;
use super::*;

/// Returns the sorted, distinct chunk keys a set of block snapshots names.
///
/// # Errors
///
/// Returns the device codec error when a live overlay page cannot be read
/// while its chunk identity is computed.
pub(super) fn named_block_overlay_chunks<'a>(
    snapshots: impl IntoIterator<Item = &'a BlockSnapshot>,
) -> Result<Vec<ContentHash>, crucible_device::BlockSnapshotCodecError> {
    let mut identities = BTreeSet::new();
    for snapshot in snapshots {
        identities.extend(
            snapshot
                .overlay_chunk_identities()?
                .into_iter()
                .map(|bytes| ContentHash { bytes }),
        );
    }
    Ok(identities.into_iter().collect())
}

/// Returns the block snapshot of every continuation an exact checkpoint set persists.
pub(super) fn checkpoint_block_snapshots(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> impl Iterator<Item = &BlockSnapshot> {
    checkpoint
        .targets
        .values()
        .map(|target| target.snapshot.host_io())
        .chain(
            checkpoint
                .failed_host_io
                .values()
                .map(|failed| &failed.host_io),
        )
        .filter_map(|host_io| host_io.block())
        .map(|block| block.device_snapshot())
}

/// Copies every chunk the checkpoint's block snapshots name into `object_directory`.
///
/// Chunks already present are re-authenticated instead of rewritten, and a
/// chunk shared by several snapshots is written once.
pub(super) fn persist_block_overlay_chunks_with_boundary(
    object_directory: &Path,
    checkpoint: &ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut persisted = BTreeSet::new();
    let mut buffer = Vec::new();
    for snapshot in checkpoint_block_snapshots(checkpoint) {
        let image = &snapshot.overlay;
        for chunk in image.chunks().map_err(device_store_error)? {
            let Some(identity) = chunk.identity.map(|bytes| ContentHash { bytes }) else {
                continue;
            };
            if !persisted.insert(identity) {
                continue;
            }
            boundary()?;
            let path = object_path(object_directory, identity);
            if path.exists() {
                validate_file_hash_with_boundary(&path, identity, boundary)?;
                continue;
            }
            read_image_chunk(image, chunk.index, &mut buffer)?;
            persist_object_with_boundary(object_directory, identity, &buffer, boundary)?;
        }
    }
    Ok(())
}

/// Returns the total bytes of the distinct chunks a checkpoint set names.
pub(super) fn block_overlay_chunk_bytes(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<u64, SchedulerError> {
    let mut counted = BTreeSet::new();
    let mut total = 0_u64;
    for snapshot in checkpoint_block_snapshots(checkpoint) {
        let image = &snapshot.overlay;
        for chunk in image.chunks().map_err(device_store_error)? {
            if chunk
                .identity
                .is_some_and(|identity| counted.insert(identity))
            {
                let start = chunk.index.saturating_mul(OVERLAY_CHUNK_BYTES);
                total = total.saturating_add(
                    image
                        .length()
                        .saturating_sub(start)
                        .min(OVERLAY_CHUNK_BYTES),
                );
            }
        }
    }
    Ok(total)
}

/// Re-authenticates every chunk of an already-published closure.
pub(super) fn authenticate_published_block_overlay_chunks_with_boundary(
    object_directory: &Path,
    expected: &ClosureManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    for identity in &expected.block_overlay_chunks {
        boundary()?;
        validate_file_hash_with_boundary(
            &object_path(object_directory, *identity),
            *identity,
            boundary,
        )?;
    }
    Ok(())
}

/// Charges each listed chunk once against the closure budget at load.
///
/// Content is authenticated when restore reads the chunk; here only its
/// presence and length bound are checked, so loading holds no chunk bytes.
pub(super) fn admit_block_overlay_chunks_with_boundary(
    object_directory: &Path,
    manifest: &ClosureManifest,
    budget: &mut CheckpointReadBudget,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    for identity in &manifest.block_overlay_chunks {
        boundary()?;
        let path = object_path(object_directory, *identity);
        let length = fs::metadata(&path)
            .map_err(|error| {
                loop_factory_error(format!(
                    "inspect exact checkpoint block overlay chunk {}: {error}",
                    path.display()
                ))
            })?
            .len();
        if length == 0 || length > OVERLAY_CHUNK_BYTES {
            return Err(loop_factory_error(
                "exact checkpoint block overlay chunk has an invalid length",
            ));
        }
        budget.reserve_identity_once(*identity, length)?;
    }
    Ok(())
}

/// Requires the manifest chunk list to equal what the decoded block snapshots name.
pub(super) fn require_named_block_overlay_chunks<'a>(
    listed: &[ContentHash],
    snapshots: impl IntoIterator<Item = &'a BlockSnapshot>,
) -> Result<(), LifecycleApiError> {
    let named = named_block_overlay_chunks(snapshots).map_err(|error| {
        loop_factory_error(format!(
            "identify exact checkpoint block overlay chunks: {error}"
        ))
    })?;
    if named != listed {
        return Err(loop_factory_error(
            "exact checkpoint block overlay chunks are incomplete or contain unreferenced objects",
        ));
    }
    Ok(())
}

/// Serves chunks from a closure's content-addressed object directory.
pub(super) struct DirectoryChunkSource {
    directory: PathBuf,
}

impl DirectoryChunkSource {
    pub(super) fn shared(directory: PathBuf) -> Arc<dyn BlockOverlayChunkSource> {
        Arc::new(Self { directory })
    }
}

impl BlockOverlayChunkSource for DirectoryChunkSource {
    fn read_chunk(&self, identity: [u8; 32], output: &mut Vec<u8>) -> io::Result<()> {
        let file = fs::File::open(object_path(
            &self.directory,
            ContentHash { bytes: identity },
        ))?;
        read_bounded_chunk(file, output)
    }
}

/// Serves chunks through a repository-authenticated closure's object opener.
pub(super) struct RepositoryChunkSource {
    open: ClosureObjectOpener,
}

impl RepositoryChunkSource {
    pub(super) fn shared(open: ClosureObjectOpener) -> Arc<dyn BlockOverlayChunkSource> {
        Arc::new(Self { open })
    }
}

impl BlockOverlayChunkSource for RepositoryChunkSource {
    fn read_chunk(&self, identity: [u8; 32], output: &mut Vec<u8>) -> io::Result<()> {
        read_bounded_chunk((self.open)(ContentHash { bytes: identity })?, output)
    }
}

/// Reads at most one chunk; a longer object is refused before it is buffered.
fn read_bounded_chunk(reader: impl Read, output: &mut Vec<u8>) -> io::Result<()> {
    output.clear();
    reader.take(OVERLAY_CHUNK_BYTES + 1).read_to_end(output)?;
    if output.len() as u64 > OVERLAY_CHUNK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "block overlay chunk exceeds the chunk size",
        ));
    }
    Ok(())
}

fn read_image_chunk(
    image: &BlockOverlayImage,
    index: u64,
    buffer: &mut Vec<u8>,
) -> Result<(), SchedulerError> {
    image
        .read_chunk(index, buffer)
        .map_err(|error| store_error(format!("read block overlay chunk {index}: {error}")))?;
    Ok(())
}

fn device_store_error(error: crucible_device::DeviceError) -> SchedulerError {
    store_error(format!("identify block overlay chunks: {error}"))
}
