//! Lazy logical readers assembled from authenticated checkpoint objects.

use std::io::{self, Read};
use std::sync::Arc;

use super::{ARTIFACT_CHUNK_BYTES, ExactCheckpointArtifactRecord, ExactCheckpointTargetRecord};
use crate::ContentHash;

type ObjectOpener = dyn Fn(ContentHash) -> io::Result<Box<dyn Read + Send>> + Send + Sync + 'static;
type RestoreReaders = (
    Box<dyn Read + Send>,
    Box<dyn Read + Send>,
    Vec<Box<dyn Read + Send>>,
);

/// Opaque logical byte streams for one repository-rooted exact restore.
pub struct ExactCheckpointRestoreStreams {
    root_overlay: Box<dyn Read + Send>,
    device_state: Box<dyn Read + Send>,
    ram_layers: Vec<Box<dyn Read + Send>>,
}

impl std::fmt::Debug for ExactCheckpointRestoreStreams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactCheckpointRestoreStreams")
            .field("ram_layers", &self.ram_layers.len())
            .finish_non_exhaustive()
    }
}

impl ExactCheckpointRestoreStreams {
    /// Consumes the set into the three operation-specific restore streams.
    #[must_use]
    pub fn into_readers(self) -> RestoreReaders {
        (self.root_overlay, self.device_state, self.ram_layers)
    }
}

pub(super) fn open_target_streams(
    target: Arc<ExactCheckpointTargetRecord>,
    open: impl Fn(ContentHash) -> io::Result<Box<dyn Read + Send>> + Send + Sync + 'static,
) -> io::Result<ExactCheckpointRestoreStreams> {
    let open: Arc<ObjectOpener> = Arc::new(open);
    let root_overlay = logical_reader(target.clone(), ArtifactSelector::RootOverlay, open.clone());
    let device_state = logical_reader(target.clone(), ArtifactSelector::DeviceState, open.clone());
    let mut ram_layers = Vec::new();
    ram_layers
        .try_reserve_exact(target.exact_ram.layers.len())
        .map_err(|_| io::Error::other("allocate exact-checkpoint RAM stream inventory"))?;
    for index in 0..target.exact_ram.layers.len() {
        ram_layers.push(logical_reader(
            target.clone(),
            ArtifactSelector::RamLayer(index),
            open.clone(),
        ));
    }

    Ok(ExactCheckpointRestoreStreams {
        root_overlay,
        device_state,
        ram_layers,
    })
}

fn logical_reader(
    target: Arc<ExactCheckpointTargetRecord>,
    selector: ArtifactSelector,
    open: Arc<ObjectOpener>,
) -> Box<dyn Read + Send> {
    Box::new(LogicalArtifactReader {
        target,
        selector,
        open,
        logical_chunk: 0,
        current: None,
        zero_remaining: 0,
    })
}

#[derive(Clone, Copy)]
enum ArtifactSelector {
    RootOverlay,
    DeviceState,
    RamLayer(usize),
}

impl ArtifactSelector {
    fn select(self, target: &ExactCheckpointTargetRecord) -> &ExactCheckpointArtifactRecord {
        match self {
            Self::RootOverlay => &target.overlay,
            Self::DeviceState => &target.exact_ram.device,
            Self::RamLayer(index) => &target.exact_ram.layers[index].artifact,
        }
    }
}

struct OpenObject {
    reader: Box<dyn Read + Send>,
    remaining: u64,
}

struct LogicalArtifactReader {
    target: Arc<ExactCheckpointTargetRecord>,
    selector: ArtifactSelector,
    open: Arc<ObjectOpener>,
    logical_chunk: u64,
    current: Option<OpenObject>,
    zero_remaining: u64,
}

impl LogicalArtifactReader {
    fn artifact(&self) -> &ExactCheckpointArtifactRecord {
        self.selector.select(&self.target)
    }

    fn chunk_length(&self) -> u64 {
        self.artifact()
            .length
            .saturating_sub(self.logical_chunk.saturating_mul(ARTIFACT_CHUNK_BYTES))
            .min(ARTIFACT_CHUNK_BYTES)
    }

    fn chunk_identity(&self) -> Option<ContentHash> {
        let artifact = self.artifact();
        if !artifact.sparse {
            return usize::try_from(self.logical_chunk)
                .ok()
                .and_then(|index| artifact.chunks.get(index))
                .copied();
        }

        artifact.extents.iter().find_map(|extent| {
            let offset = self.logical_chunk.checked_sub(extent.start_chunk)?;
            usize::try_from(offset)
                .ok()
                .and_then(|index| extent.chunks.get(index))
                .copied()
        })
    }
}

impl Read for LogicalArtifactReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        loop {
            if self.zero_remaining != 0 {
                let count = usize::try_from(self.zero_remaining.min(output.len() as u64))
                    .map_err(|_| io::Error::other("exact-checkpoint zero run overflow"))?;
                output[..count].fill(0);
                self.zero_remaining -= count as u64;
                return Ok(count);
            }
            if let Some(object) = &mut self.current {
                if object.remaining != 0 {
                    let count = usize::try_from(object.remaining.min(output.len() as u64))
                        .map_err(|_| io::Error::other("exact-checkpoint object overflow"))?;
                    let count = object.reader.read(&mut output[..count])?;
                    if count == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short exact-checkpoint immutable object",
                        ));
                    }
                    object.remaining -= count as u64;
                    return Ok(count);
                }

                let mut byte = [0_u8; 1];
                if object.reader.read(&mut byte)? != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "long exact-checkpoint immutable object",
                    ));
                }
                self.current = None;
                self.logical_chunk += 1;
                continue;
            }

            let chunk_length = self.chunk_length();
            if chunk_length == 0 {
                return Ok(0);
            }
            if let Some(identity) = self.chunk_identity() {
                self.current = Some(OpenObject {
                    reader: (self.open)(identity)?,
                    remaining: chunk_length,
                });
            } else {
                self.zero_remaining = chunk_length;
                self.logical_chunk += 1;
            }
        }
    }
}
