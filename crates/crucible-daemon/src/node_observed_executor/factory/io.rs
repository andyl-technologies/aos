//! Operator-enrolled immutable storage artifacts and bounded native I/O models.
//!
//! Portable selections bind content and timing, never a host pathname. Only the
//! installed catalog may associate those references with local artifact files.

use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf};

use crucible::{
    DeviceId, NodeId, ScheduledIoNode, SchedulerNodeId, SchedulingNodeKind, Seed,
    node_adapters::HostModel,
};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, FsTree, IoCore, NinepDevice, NinepLatency,
};
use crucible_node_contract::{ContentRef, U64, Validate};
use serde::{Deserialize, Serialize};

use super::{InstalledNodeSelection, NodeObservedError, native, refused};

#[cfg(test)]
#[path = "io_tests.rs"]
mod tests;

/// Bounds each independently enrolled immutable base image or served tree.
pub const MAXIMUM_IO_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// Selects the operator-authorized source of immutable artifact bytes.
///
/// Archive-only enrollment supplies an independent expected identity, not a
/// local file or permission to start a fresh model. Signed archive restoration
/// must authenticate and materialize the bytes before native construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstalledIoArtifactSource {
    /// Gives the absolute operator-installed artifact file.
    Path(PathBuf),
    /// Requires authenticated archive reconstruction and forbids fresh reads.
    ArchiveOnly,
}

/// Associates operator-qualified content with an explicit reconstruction policy.
///
/// This host configuration intentionally has no wire serialization. A client
/// selection cannot install a pathname or certify its own expected content.
#[derive(Clone, Debug)]
pub struct InstalledIoArtifact {
    /// Selects a local file or authenticated archive-only reconstruction.
    pub source: InstalledIoArtifactSource,
    /// Binds independently qualified complete bytes and their media type.
    pub expected: ContentRef,
}

impl InstalledIoArtifact {
    /// Enrolls independently qualified content from an operator-installed file.
    ///
    /// Construction records policy only. Enrollment and each actual file read
    /// still validate metadata, byte ceilings, file type and complete content.
    #[must_use]
    pub fn path(path: PathBuf, expected: ContentRef) -> Self {
        Self {
            source: InstalledIoArtifactSource::Path(path),
            expected,
        }
    }

    /// Enrolls an independent content identity for signed archive restoration.
    ///
    /// This entry cannot provide bytes for fresh admission or model allocation.
    #[must_use]
    pub fn archive_only(expected: ContentRef) -> Self {
        Self {
            source: InstalledIoArtifactSource::ArchiveOnly,
            expected,
        }
    }
}

/// Selects an installed deterministic native storage model and its timing.
///
/// ```json
/// {"kind":"block","base_image":{},"source_node":7,"read_ns":"1",
///  "write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"}
/// ```
/// The abbreviated content reference above denotes the complete public
/// `ContentRef` record. All costs must be positive and fit the native time unit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledHostIoProfile {
    /// Serves an immutable base image with a private captured copy-on-write overlay.
    Block {
        /// Binds the operator-enrolled raw immutable base image.
        base_image: ContentRef,
        /// Gives the exact native producer identifier.
        source_node: u32,
        /// Gives the positive read floor in virtual nanoseconds.
        read_ns: U64,
        /// Gives the positive write floor in virtual nanoseconds.
        write_ns: U64,
        /// Gives the positive flush latency in virtual nanoseconds.
        flush_ns: U64,
        /// Gives the positive get-length latency in virtual nanoseconds.
        get_length_ns: U64,
        /// Gives the positive per-byte transfer cost in virtual nanoseconds.
        per_byte_ns: U64,
    },
    /// Serves a captured 9p session over an immutable canonical filesystem tree.
    Ninep {
        /// Binds the operator-enrolled canonical `FsTree` bytes.
        tree: ContentRef,
        /// Gives the exact native producer identifier.
        source_node: u32,
        /// Gives the positive metadata/control floor in virtual nanoseconds.
        control_ns: U64,
        /// Gives the positive data floor in virtual nanoseconds.
        data_ns: U64,
        /// Gives the positive per-frame-byte transfer cost in virtual nanoseconds.
        per_byte_ns: U64,
    },
}

impl InstalledHostIoProfile {
    /// Returns the complete immutable native input required by this model.
    #[must_use]
    pub fn artifact(&self) -> &ContentRef {
        match self {
            Self::Block { base_image, .. } => base_image,
            Self::Ninep { tree, .. } => tree,
        }
    }

    pub(super) fn role(&self) -> &'static str {
        match self {
            Self::Block { .. } => "block",
            Self::Ninep { .. } => "filesystem",
        }
    }

    pub(super) fn minimum_latency_ps(&self) -> Result<u64, NodeObservedError> {
        let floor = match self {
            Self::Block {
                read_ns,
                write_ns,
                flush_ns,
                get_length_ns,
                ..
            } => [
                read_ns.get(),
                write_ns.get(),
                flush_ns.get(),
                get_length_ns.get(),
            ]
            .into_iter()
            .min(),
            Self::Ninep {
                control_ns,
                data_ns,
                ..
            } => Some(control_ns.get().min(data_ns.get())),
        }
        .ok_or_else(|| refused("native I/O latency floor is absent"))?;
        floor
            .checked_mul(1000)
            .filter(|value| *value > 0)
            .ok_or_else(|| refused("native I/O latency floor is zero or overflows picoseconds"))
    }

    fn validate(&self) -> Result<(), NodeObservedError> {
        self.artifact().validate()?;
        if self.artifact().length.get() == 0
            || self.artifact().length.get() > MAXIMUM_IO_ARTIFACT_BYTES as u64
        {
            return Err(refused(
                "installed I/O artifact is empty or exceeds its byte ceiling",
            ));
        }
        let costs = match self {
            Self::Block {
                read_ns,
                write_ns,
                flush_ns,
                get_length_ns,
                per_byte_ns,
                ..
            } => vec![
                read_ns.get(),
                write_ns.get(),
                flush_ns.get(),
                get_length_ns.get(),
                per_byte_ns.get(),
            ],
            Self::Ninep {
                control_ns,
                data_ns,
                per_byte_ns,
                ..
            } => vec![control_ns.get(), data_ns.get(), per_byte_ns.get()],
        };
        // The largest admitted frame must have a representable positive native
        // completion; saturating native arithmetic is not timing qualification.
        let largest = costs
            .iter()
            .copied()
            .max()
            .ok_or_else(|| refused("I/O timing is absent"))?;
        if costs.contains(&0)
            || largest
                .checked_mul(crucible_shmem::MAX_FRAME_DATA as u64 + 1)
                .and_then(|value| value.checked_mul(1000))
                .is_none()
        {
            return Err(refused(
                "I/O timing has zero cost or exceeds native event coordinates",
            ));
        }
        self.minimum_latency_ps()?;
        Ok(())
    }
}

/// Reads and verifies an operator-enrolled artifact before native allocation.
///
/// # Errors
/// Refuses archive-only enrollment, relative paths, symlinks, nonregular files,
/// excess length, changed content, or unavailable bounded storage for bytes.
pub(super) fn read_artifact(artifact: &InstalledIoArtifact) -> Result<Vec<u8>, NodeObservedError> {
    artifact.expected.validate()?;
    if artifact.expected.length.get() == 0
        || artifact.expected.length.get() > MAXIMUM_IO_ARTIFACT_BYTES as u64
    {
        return Err(refused("installed I/O artifact byte geometry is invalid"));
    }
    let InstalledIoArtifactSource::Path(path) = &artifact.source else {
        return Err(refused(
            "archive-only I/O artifact requires authenticated archive reconstruction",
        ));
    };
    if !path.is_absolute() {
        return Err(refused("installed I/O artifact path is not absolute"));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(native)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(native)?;
    if !metadata.is_file() || metadata.len() != artifact.expected.length.get() {
        return Err(refused("installed I/O artifact type or length changed"));
    }
    let length = usize::try_from(metadata.len()).map_err(native)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(native)?;
    file.take(metadata.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(native)?;
    artifact.expected.verify(&bytes)?;
    Ok(bytes)
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    profile: &InstalledHostIoProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<HostModel, NodeObservedError> {
    profile.validate()?;
    let installed = artifacts
        .get(&profile.artifact().hash.digest)
        .filter(|artifact| &artifact.expected == profile.artifact())
        .ok_or_else(|| refused("I/O content has no independently enrolled artifact"))?;
    let bytes = read_artifact(installed)?;
    build_model_from_bytes(selected, profile, bytes)
}

// The caller supplies bytes through the operator registry or the opaque signed
// archive source. This constructs data only; installed/native qualification and
// complete admission remain mandatory before activation.
pub(super) fn build_model_from_bytes(
    selected: &InstalledNodeSelection,
    profile: &InstalledHostIoProfile,
    bytes: Vec<u8>,
) -> Result<HostModel, NodeObservedError> {
    profile.validate()?;
    profile.artifact().verify(&bytes)?;
    let native_node = NodeId {
        name: selected.node.as_str().to_owned(),
    };
    let target = native_node.clone();
    let device = DeviceId {
        name: "native".into(),
    };
    let seed = Seed::from_u64(0);
    let io = match profile {
        InstalledHostIoProfile::Block {
            source_node,
            read_ns,
            write_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
            ..
        } => ScheduledIoNode::new(
            SchedulerNodeId {
                node: native_node,
                kind: SchedulingNodeKind::Disk,
            },
            target,
            device,
            BlockDevice::new(
                IoCore::new(*source_node, 16, 16).map_err(native)?,
                BaseImage::new(bytes),
                BlockLatency::new(
                    read_ns.get(),
                    write_ns.get(),
                    flush_ns.get(),
                    get_length_ns.get(),
                    per_byte_ns.get(),
                ),
            ),
            seed,
        ),
        InstalledHostIoProfile::Ninep {
            source_node,
            control_ns,
            data_ns,
            per_byte_ns,
            ..
        } => {
            let tree = FsTree::from_canonical_bytes(&bytes).map_err(native)?;
            if tree.canonical_bytes() != bytes {
                return Err(refused(
                    "installed filesystem tree is not its canonical codec",
                ));
            }
            ScheduledIoNode::new_ninep(
                SchedulerNodeId {
                    node: native_node,
                    kind: SchedulingNodeKind::NineP,
                },
                target,
                device,
                NinepDevice::new(
                    IoCore::new(*source_node, 16, 16).map_err(native)?,
                    tree,
                    NinepLatency::new(control_ns.get(), data_ns.get(), per_byte_ns.get()),
                ),
                seed,
            )
        }
    };
    Ok(HostModel::Io(Box::new(io)))
}

// Archive authentication proves original provenance, but does not turn a saved
// mutable latency/source/capacity field into a new installed configuration.
pub(super) fn validate_native_storage(
    selected: &InstalledNodeSelection,
    profile: &InstalledHostIoProfile,
    artifact_bytes: Vec<u8>,
    native_bytes: &[u8],
) -> Result<(), NodeObservedError> {
    let HostModel::Io(mut actual) = build_model_from_bytes(selected, profile, artifact_bytes)?
    else {
        return Err(refused(
            "installed storage builder returned another native family",
        ));
    };
    let original_core = actual
        .block_device()
        .map(|device| device.snapshot().core)
        .or_else(|| actual.ninep_device().map(|device| device.snapshot().core))
        .ok_or_else(|| refused("actual storage has no native queue owner"))?;
    let checkpoint =
        crucible::device_subnode::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(
            native_bytes,
        )
        .map_err(native)?;
    actual.restore_checkpoint(&checkpoint).map_err(native)?;
    let restored_core = match profile {
        InstalledHostIoProfile::Block {
            read_ns,
            write_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
            ..
        } => {
            let block = actual
                .block_device()
                .ok_or_else(|| refused("native block capture changed family"))?;
            if block.latency_model()
                != &BlockLatency::new(
                    read_ns.get(),
                    write_ns.get(),
                    flush_ns.get(),
                    get_length_ns.get(),
                    per_byte_ns.get(),
                )
            {
                return Err(refused("native block capture changed installed latency"));
            }
            block.snapshot().core
        }
        InstalledHostIoProfile::Ninep {
            control_ns,
            data_ns,
            per_byte_ns,
            ..
        } => {
            let filesystem = actual
                .ninep_device()
                .ok_or_else(|| refused("native filesystem capture changed family"))?;
            if filesystem.latency_model()
                != &NinepLatency::new(control_ns.get(), data_ns.get(), per_byte_ns.get())
            {
                return Err(refused(
                    "native filesystem capture changed installed latency",
                ));
            }
            filesystem.snapshot().core
        }
    };
    if restored_core.src_node != original_core.src_node
        || restored_core.ticks_per_ns != original_core.ticks_per_ns
        || restored_core.inbox_capacity != original_core.inbox_capacity
        || restored_core.outbox_capacity != original_core.outbox_capacity
    {
        return Err(refused(
            "native storage capture changed installed source, clock or credits",
        ));
    }
    Ok(())
}
