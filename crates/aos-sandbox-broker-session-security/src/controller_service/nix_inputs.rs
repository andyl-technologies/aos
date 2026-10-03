//! Retains complete local portable inputs for one genuine current Nix Start.
//!
//! The cut exclusively borrows the existing current Start owner and pins every
//! admitted derivation/input inode beneath the actual fixed project source:
//!
//! ```text
//! /var/lib/aos/sandboxd/view-sources/<project-uuid>/sha256-<digest-hex>
//! ```
//!
//! The source is availability, not publication or store authority. Canonical
//! descriptor streaming and exact original metadata comparisons establish only
//! local input custody. No configured worker, Nix session/floor, NAR/private
//! store, output observation, Effect receipt or public readiness follows.
//! The current owner and source remain separate locals outside this borrowed
//! cut; no raw descriptor or self-referential lifetime constructor is exposed.

use std::collections::TryReserveError;
use std::io;
use std::os::fd::AsFd as _;

use aos_sandbox::production_operation_compiler::{
    CurrentRetainedNixStartV2, NixStartContinuationErrorV2,
};
use aos_sandbox_core::model::{ContentLayout, Node};
use aos_sandbox_core::{
    CanonicalCborError, DecodeLimits, ObjectDescriptor, ObjectDescriptorVerificationError,
    ObjectDescriptorVerifier, PortableMediaType, StreamingDirectory,
};
use aos_sandbox_linux::immutable_file::{FsVerityDigest, ObservedSealedPublicationFile};
use aos_sandbox_protocol::nix_build::{NixPreadmittedRecipeV2, NixStoreObjectV2};

use crate::cache_directory_source::{
    ProjectSealedViewObjectSourceV1, ProjectSealedViewSourceErrorV1,
};

const MAXIMUM_INPUT_PINS: usize = 4_096;
const MAXIMUM_INPUT_BYTES: u64 = 1_073_741_824;
const INPUT_SCRATCH_BYTES: usize = 64 * 1_024;

/// Retains concrete failures without granting a retry or an effect outcome.
#[derive(Debug, thiserror::Error)]
pub(super) enum NixLocalInputErrorV2 {
    #[error("current retained Nix Start custody failed: {0}")]
    Current(#[from] NixStartContinuationErrorV2),
    #[error("fixed sealed input source failed: {0}")]
    Source(#[from] ProjectSealedViewSourceErrorV1),
    #[error("original Directory decoding failed: {0}")]
    Directory(#[from] CanonicalCborError),
    #[error("canonical input descriptor verification failed: {0}")]
    Descriptor(#[from] ObjectDescriptorVerificationError),
    #[error("retained input positional read failed: {0}")]
    Read(#[source] io::Error),
    #[error("bounded input allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
    #[error("local input count, byte or read bound exceeded")]
    Bound,
    #[error("one staged basename has inconsistent descriptor or original bytes")]
    Conflict,
    #[error("local input layout is outside the admitted Whole Content profile")]
    UnsupportedLayout,
    #[error("local input root, project, named inode or exact size changed")]
    Changed,
    #[error("local input bytes do not equal their retained original")]
    OriginalMismatch,
    #[error("local input ended before its original encoded size")]
    ShortRead,
    #[error("local input cut is permanently closed")]
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginalInputBytesV2 {
    Derivation,
    Reconstruction {
        input_index: usize,
        record_index: usize,
    },
}

struct InputSpecV2 {
    descriptor: ObjectDescriptor,
    original_bytes: Option<OriginalInputBytesV2>,
}

struct NixInputPinV2<'inputs> {
    spec: InputSpecV2,
    file: ObservedSealedPublicationFile<'inputs>,
}

/// Keeps the same current owner and actual source alive for all retained pins.
///
/// Fields are private and the type is neither cloneable nor serializable. A
/// failed use permanently closes this instance; it never renews its target.
pub(super) struct NixLocalInputCutV2<'inputs, 'current> {
    current: &'inputs mut CurrentRetainedNixStartV2<'current>,
    source: &'inputs ProjectSealedViewObjectSourceV1,
    pins: Vec<NixInputPinV2<'inputs>>,
    latch: InputFailureLatchV2,
}

#[derive(Default)]
struct InputFailureLatchV2 {
    failed: bool,
}

impl InputFailureLatchV2 {
    fn require_open(&self) -> Result<(), NixLocalInputErrorV2> {
        if self.failed {
            return Err(NixLocalInputErrorV2::Closed);
        }
        Ok(())
    }

    fn finish<T>(
        &mut self,
        result: Result<T, NixLocalInputErrorV2>,
    ) -> Result<T, NixLocalInputErrorV2> {
        self.failed |= result.is_err();
        result
    }
}

/// Opens only the original recipe project's existing fixed input directory.
///
/// # Errors
///
/// Rejects current Start failures and unsafe, absent or replaced fixed source
/// custody. No supplied path, project, FD, clock or publication claim is used.
pub(super) fn open_fixed_input_source_v2(
    current: &mut CurrentRetainedNixStartV2<'_>,
) -> Result<ProjectSealedViewObjectSourceV1, NixLocalInputErrorV2> {
    current.recheck()?;
    let project = current.recipe_artifact().recipe().project;
    let opened = ProjectSealedViewObjectSourceV1::open_fixed(project);
    current.recheck()?;

    let source = opened?;
    source.recheck_retained_nix_input_root_v2()?;
    current.recheck()?;
    require_original_project(current, &source)?;
    Ok(source)
}

/// Pins and verifies the complete derivation and admitted portable input closure.
///
/// The genuine current artifact already owns signature/schema validation and
/// the sole complete portable graph validator. This projection enumerates its
/// validated records; it does not create a second graph or output observer.
///
/// # Errors
///
/// Rejects count/aggregate/allocation bounds before input opens, changed current
/// or source custody, unsupported leaves, missing/unsealed inodes and any exact
/// original-byte, canonical descriptor, EOF or final all-pins mismatch.
pub(super) fn pin_local_inputs_v2<'inputs, 'current: 'inputs>(
    current: &'inputs mut CurrentRetainedNixStartV2<'current>,
    source: &'inputs ProjectSealedViewObjectSourceV1,
) -> Result<NixLocalInputCutV2<'inputs, 'current>, NixLocalInputErrorV2> {
    current.recheck()?;
    source.recheck_retained_nix_input_root_v2()?;
    require_original_project(current, source)?;

    // No original recipe borrow survives into a mutable current recheck.
    // Every retained projection growth is checked before allocation; the
    // complete projection precedes all input inode opens.
    let specs = project_inputs(current.recipe_artifact().recipe())?;
    current.recheck()?;
    source.recheck_retained_nix_input_root_v2()?;

    let mut pins = Vec::new();
    pins.try_reserve_exact(specs.len())?;

    let mut scratch = [0_u8; INPUT_SCRATCH_BYTES];
    for spec in specs {
        let file = open_input_pin(current, source, &spec)?;
        let pin = NixInputPinV2 { spec, file };
        verify_input_pin(current, source, &pin, &mut scratch)?;
        pins.push(pin);
    }

    let mut cut = NixLocalInputCutV2 {
        current,
        source,
        pins,
        latch: InputFailureLatchV2::default(),
    };
    cut.recheck()?;
    Ok(cut)
}

impl NixLocalInputCutV2<'_, '_> {
    /// Rechecks every original pin and the same current Start owner.
    ///
    /// # Errors
    ///
    /// Rejects a closed cut, changed root/name/inode/seal or failed current
    /// recheck. Any failure permanently closes this instance.
    pub(super) fn recheck(&mut self) -> Result<(), NixLocalInputErrorV2> {
        self.latch.require_open()?;
        let result = recheck_all_inputs(self.current, self.source, &self.pins);
        self.latch.finish(result)
    }

    /// Reads one bounded slice only after complete current/pin readback.
    ///
    /// The original immutable OFD supplied the complete canonical verification
    /// at construction. Bytes reach the caller's buffer only after the same
    /// complete cut has also passed its post-read checks.
    ///
    /// # Errors
    ///
    /// Rejects invalid index/offset/chunk bounds, premature EOF or failed reads, a closed
    /// cut and any current/physical change. Failure permanently closes the cut.
    pub(super) fn read_input_chunk(
        &mut self,
        pin_index: usize,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, NixLocalInputErrorV2> {
        self.latch.require_open()?;
        let result = self.read_input_chunk_inner(pin_index, offset, destination);
        self.latch.finish(result)
    }

    fn read_input_chunk_inner(
        &mut self,
        pin_index: usize,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, NixLocalInputErrorV2> {
        recheck_all_inputs(self.current, self.source, &self.pins)?;
        let pin = self.pins.get(pin_index).ok_or(NixLocalInputErrorV2::Bound)?;
        let count = checked_read_length(
            pin.spec.descriptor.encoded_size(), offset, destination.len(),
        )?;
        let mut scratch = [0_u8; INPUT_SCRATCH_BYTES];

        let read = if offset == pin.spec.descriptor.encoded_size() {
            require_exact_eof(self.current, self.source, pin)?;
            0
        } else if count == 0 {
            0
        } else {
            let read = pread_input(self.current, self.source, pin, offset, &mut scratch[..count])?;
            if read == 0 {
                return Err(NixLocalInputErrorV2::ShortRead);
            }
            read
        };

        recheck_all_inputs(self.current, self.source, &self.pins)?;
        destination[..read].copy_from_slice(&scratch[..read]);
        Ok(read)
    }
}

#[derive(Clone, Copy)]
struct OriginalProjectionV2<'recipe> {
    locator: OriginalInputBytesV2,
    bytes: &'recipe [u8],
}

struct ProjectedInputV2<'recipe> {
    descriptor: ObjectDescriptor,
    original: Option<OriginalProjectionV2<'recipe>>,
}

/// Reports whether a fully checked addition grew this pure projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionInsertionV2 {
    Inserted,
    Existing,
}

#[derive(Default)]
struct InputProjectionV2<'recipe> {
    inputs: Vec<ProjectedInputV2<'recipe>>,
    distinct_bytes: u64,
}

impl<'recipe> InputProjectionV2<'recipe> {
    fn add(
        &mut self,
        descriptor: &ObjectDescriptor,
        original: Option<OriginalProjectionV2<'recipe>>,
    ) -> Result<ProjectionInsertionV2, NixLocalInputErrorV2> {
        if let Some(expected) = original {
            if u64::try_from(expected.bytes.len()).map_err(|_| NixLocalInputErrorV2::Bound)?
                != descriptor.encoded_size()
            {
                return Err(NixLocalInputErrorV2::OriginalMismatch);
            }
        }

        if let Some(existing) = self.inputs.iter_mut()
            .find(|input| input.descriptor.digest() == descriptor.digest())
        {
            if &existing.descriptor != descriptor {
                return Err(NixLocalInputErrorV2::Conflict);
            }
            match (existing.original, original) {
                (Some(before), Some(after)) if before.bytes != after.bytes => {
                    return Err(NixLocalInputErrorV2::Conflict);
                }
                (None, Some(expected)) => existing.original = Some(expected),
                _ => {}
            }
            return Ok(ProjectionInsertionV2::Existing);
        }

        let next_bytes = checked_projection_growth(
            self.inputs.len(),
            self.distinct_bytes,
            descriptor.encoded_size(),
        )?;
        self.inputs.try_reserve_exact(1)?;
        self.inputs.push(ProjectedInputV2 {
            descriptor: descriptor.clone(),
            original,
        });
        self.distinct_bytes = next_bytes;
        Ok(ProjectionInsertionV2::Inserted)
    }

    fn into_specs(mut self) -> Result<Vec<InputSpecV2>, NixLocalInputErrorV2> {
        self.inputs.sort_unstable_by(|left, right| left.descriptor.cmp(&right.descriptor));
        let mut specs = Vec::new();
        specs.try_reserve_exact(self.inputs.len())?;

        for input in self.inputs {
            specs.push(InputSpecV2 {
                descriptor: input.descriptor,
                original_bytes: input.original.map(|original| original.locator),
            });
        }
        Ok(specs)
    }
}

fn checked_projection_growth(
    count: usize,
    distinct_bytes: u64,
    encoded_size: u64,
) -> Result<u64, NixLocalInputErrorV2> {
    let next_count = count.checked_add(1).ok_or(NixLocalInputErrorV2::Bound)?;
    let next_bytes = distinct_bytes.checked_add(encoded_size).ok_or(NixLocalInputErrorV2::Bound)?;
    if next_count > MAXIMUM_INPUT_PINS
        || encoded_size > MAXIMUM_INPUT_BYTES
        || next_bytes > MAXIMUM_INPUT_BYTES
    {
        return Err(NixLocalInputErrorV2::Bound);
    }
    Ok(next_bytes)
}

fn project_inputs(
    recipe: &NixPreadmittedRecipeV2,
) -> Result<Vec<InputSpecV2>, NixLocalInputErrorV2> {
    let mut projection = InputProjectionV2::default();
    projection.add(
        &recipe.derivation.portable,
        Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: &recipe.derivation_bytes,
        }),
    )?;
    for (input_index, input) in recipe.inputs.iter().enumerate() {
        project_input_object(&mut projection, input_index, input)?;
    }
    projection.into_specs()
}

fn project_input_object<'recipe>(
    projection: &mut InputProjectionV2<'recipe>,
    input_index: usize,
    input: &'recipe NixStoreObjectV2,
) -> Result<(), NixLocalInputErrorV2> {
    match input.portable.media_type().as_str() {
        value if value == PortableMediaType::Content.as_str() => {
            projection.add(&input.portable, None)?;
        }
        value if value == PortableMediaType::Tree.as_str() => {
            // Signature-verified recipe validation already proves this complete
            // record set reachable. Enumerate leaves without a second traversal.
            for (record_index, record) in input.portable_objects.iter().enumerate() {
                let insertion = projection.add(
                    &record.descriptor,
                    Some(OriginalProjectionV2 {
                        locator: OriginalInputBytesV2::Reconstruction {
                            input_index,
                            record_index,
                        },
                        bytes: &record.bytes,
                    }),
                )?;

                // Only this loop inserts Directory into a fresh projection.
                // Its first scan reaches terminal EOF or aborts the projection,
                // so an exact duplicate cannot contribute unprojected leaves.
                if matches!(insertion, ProjectionInsertionV2::Inserted)
                    && record.descriptor.media_type().as_str()
                        == PortableMediaType::Directory.as_str()
                {
                    project_directory_leaves(projection, &record.bytes)?;
                }
            }
        }
        _ => return Err(NixLocalInputErrorV2::UnsupportedLayout),
    }
    Ok(())
}

fn project_directory_leaves<'recipe>(
    projection: &mut InputProjectionV2<'recipe>,
    bytes: &[u8],
) -> Result<(), NixLocalInputErrorV2> {
    let mut stream = StreamingDirectory::new(bytes, DecodeLimits::default())?;
    while let Some(entry) = stream.next_entry()? {
        if let Node::File(file) = entry.node {
            let ContentLayout::Whole { content } = file.content else {
                return Err(NixLocalInputErrorV2::UnsupportedLayout);
            };
            if content.media_type().as_str() != PortableMediaType::Content.as_str() {
                return Err(NixLocalInputErrorV2::UnsupportedLayout);
            }

            // A decoded entry owns its descriptor only until the next entry.
            // Retain this bounded descriptor DATA, not the Directory payload.
            projection.add(&content, None)?;
        }
    }
    Ok(())
}

fn require_original_project(
    current: &CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
) -> Result<(), NixLocalInputErrorV2> {
    if source.project() != current.recipe_artifact().recipe().project {
        return Err(NixLocalInputErrorV2::Changed);
    }
    Ok(())
}

fn open_input_pin<'inputs>(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &'inputs ProjectSealedViewObjectSourceV1,
    spec: &InputSpecV2,
) -> Result<ObservedSealedPublicationFile<'inputs>, NixLocalInputErrorV2> {
    current.recheck()?;
    source.recheck_retained_nix_input_root_v2()?;
    require_original_project(current, source)?;
    let opened = source.open_retained_nix_input_v2(&spec.descriptor);
    source.recheck_retained_nix_input_root_v2()?;
    current.recheck()?;

    let file = opened?;
    if file.bytes() != spec.descriptor.encoded_size() {
        return Err(NixLocalInputErrorV2::Changed);
    }
    Ok(file)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedInputIdentityV2 {
    device: u64,
    inode: u64,
    bytes: u64,
    allocated_bytes: u64,
    verity: FsVerityDigest,
}

impl ObservedInputIdentityV2 {
    fn from_file(file: &ObservedSealedPublicationFile<'_>) -> Self {
        Self {
            device: file.device(),
            inode: file.inode(),
            bytes: file.bytes(),
            allocated_bytes: file.allocated_bytes(),
            verity: file.observed_verity_digest(),
        }
    }
}

fn recheck_input_pin(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
    pin: &NixInputPinV2<'_>,
) -> Result<(), NixLocalInputErrorV2> {
    // The original OFD stays held while the actual name is reobserved. This
    // comparison cannot adopt a replacement or confuse inode-number reuse.
    let observed = open_input_pin(current, source, &pin.spec)?;
    let same = ObservedInputIdentityV2::from_file(&pin.file)
        == ObservedInputIdentityV2::from_file(&observed);
    source.recheck_retained_nix_input_root_v2()?;
    current.recheck()?;
    if !same {
        return Err(NixLocalInputErrorV2::Changed);
    }
    Ok(())
}

fn recheck_all_inputs(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
    pins: &[NixInputPinV2<'_>],
) -> Result<(), NixLocalInputErrorV2> {
    current.recheck()?;
    source.recheck_retained_nix_input_root_v2()?;
    require_original_project(current, source)?;

    for pin in pins {
        recheck_input_pin(current, source, pin)?;
    }
    source.recheck_retained_nix_input_root_v2()?;
    current.recheck()?;
    Ok(())
}

fn pread_input(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
    pin: &NixInputPinV2<'_>,
    offset: u64,
    destination: &mut [u8],
) -> Result<usize, NixLocalInputErrorV2> {
    if offset > pin.spec.descriptor.encoded_size() || destination.len() > INPUT_SCRATCH_BYTES {
        return Err(NixLocalInputErrorV2::Bound);
    }
    recheck_input_pin(current, source, pin)?;
    let read = rustix::io::pread(pin.file.as_fd(), destination, offset)
        .map_err(|error| NixLocalInputErrorV2::Read(error.into()));
    // Even a failed syscall is bracketed by actual current/name readback.
    recheck_input_pin(current, source, pin)?;
    read
}

fn verify_input_pin(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
    pin: &NixInputPinV2<'_>,
    scratch: &mut [u8; INPUT_SCRATCH_BYTES],
) -> Result<(), NixLocalInputErrorV2> {
    recheck_input_pin(current, source, pin)?;
    let mut verifier = ObjectDescriptorVerifier::new(pin.spec.descriptor.clone());
    let mut offset = 0_u64;

    while offset < pin.spec.descriptor.encoded_size() {
        let count = checked_read_length(pin.spec.descriptor.encoded_size(), offset, scratch.len())?;
        let read = pread_input(current, source, pin, offset, &mut scratch[..count])?;
        if read == 0 {
            return Err(NixLocalInputErrorV2::ShortRead);
        }

        require_original_chunk(
            current.recipe_artifact().recipe(), &pin.spec, offset, &scratch[..read],
        )?;
        verifier.update(&scratch[..read])?;
        let read_bytes = u64::try_from(read).map_err(|_| NixLocalInputErrorV2::Bound)?;
        offset = offset.checked_add(read_bytes)
            .ok_or(NixLocalInputErrorV2::Bound)?;
    }

    require_exact_eof(current, source, pin)?;
    recheck_input_pin(current, source, pin)?;
    let verified = verifier.finish().map_err(NixLocalInputErrorV2::from);
    recheck_input_pin(current, source, pin)?;
    verified
}

fn require_exact_eof(
    current: &mut CurrentRetainedNixStartV2<'_>,
    source: &ProjectSealedViewObjectSourceV1,
    pin: &NixInputPinV2<'_>,
) -> Result<(), NixLocalInputErrorV2> {
    let mut extra = [0_u8; 1];
    if pread_input(current, source, pin, pin.spec.descriptor.encoded_size(), &mut extra)? != 0 {
        return Err(ObjectDescriptorVerificationError::TooLong.into());
    }
    Ok(())
}

fn checked_read_length(
    encoded_size: u64,
    offset: u64,
    requested: usize,
) -> Result<usize, NixLocalInputErrorV2> {
    if offset > encoded_size || requested > INPUT_SCRATCH_BYTES {
        return Err(NixLocalInputErrorV2::Bound);
    }
    let remaining = encoded_size.checked_sub(offset).ok_or(NixLocalInputErrorV2::Bound)?;
    let requested = u64::try_from(requested).map_err(|_| NixLocalInputErrorV2::Bound)?;
    usize::try_from(remaining.min(requested)).map_err(|_| NixLocalInputErrorV2::Bound)
}

fn require_original_chunk(
    recipe: &NixPreadmittedRecipeV2,
    spec: &InputSpecV2,
    offset: u64,
    actual: &[u8],
) -> Result<(), NixLocalInputErrorV2> {
    let Some(locator) = spec.original_bytes else {
        return Ok(());
    };
    let original = match locator {
        OriginalInputBytesV2::Derivation => recipe.derivation_bytes.as_slice(),
        OriginalInputBytesV2::Reconstruction { input_index, record_index } => {
            recipe.inputs.get(input_index)
                .and_then(|input| input.portable_objects.get(record_index))
                .map(|record| record.bytes.as_slice())
                .ok_or(NixLocalInputErrorV2::OriginalMismatch)?
        }
    };
    let start = usize::try_from(offset).map_err(|_| NixLocalInputErrorV2::Bound)?;
    let end = start.checked_add(actual.len()).ok_or(NixLocalInputErrorV2::Bound)?;
    if original.get(start..end) != Some(actual) {
        return Err(NixLocalInputErrorV2::OriginalMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // All vectors are UNRUN pure DATA. They construct no current Start owner,
    // protected source root, sealed-file pin, broker session or physical floor.
    use aos_sandbox_core::model::{
        Directory, DirectoryEntry, FileNode, FilesystemMetadata, SparseContent, SymlinkNode, Tree,
    };
    use aos_sandbox_core::{
        MediaType, NodeId, ObjectDigest, PathName, ProjectId, ResourceId, SandboxId,
        descriptor_for_bytes,
    };
    use aos_sandbox_protocol::nix_build::{NixExpectedOutputV2, NixPortableObjectV2};

    use super::*;

    fn descriptor(media: PortableMediaType, bytes: &[u8]) -> ObjectDescriptor {
        descriptor_for_bytes(MediaType::new(media.as_str()).unwrap(), bytes)
    }

    fn content_object(name: char, bytes: &[u8]) -> NixStoreObjectV2 {
        NixStoreObjectV2 {
            path: format!("/nix/store/{}-{name}", "0".repeat(32)),
            portable: descriptor(PortableMediaType::Content, bytes),
            nar_sha256: ObjectDigest::from_bytes([3; 32]),
            nar_size: 64,
            references: Vec::new(),
            portable_objects: Vec::new(),
        }
    }

    fn metadata() -> FilesystemMetadata {
        FilesystemMetadata::new(0o555, 0, 0, 1, 0, Vec::new(), None).unwrap()
    }

    fn directory_with_leaves() -> Directory {
        let entries = vec![
            DirectoryEntry {
                name: PathName::new(b"empty".to_vec()).unwrap(),
                node: Node::File(FileNode {
                    metadata: metadata(),
                    content: ContentLayout::whole(descriptor(PortableMediaType::Content, b"")),
                    hardlink_group: None,
                }),
            },
            DirectoryEntry {
                name: PathName::new(b"file".to_vec()).unwrap(),
                node: Node::File(FileNode {
                    metadata: metadata(),
                    content: ContentLayout::whole(descriptor(PortableMediaType::Content, b"leaf")),
                    hardlink_group: None,
                }),
            },
            DirectoryEntry {
                name: PathName::new(b"link".to_vec()).unwrap(),
                node: Node::Symlink(
                    SymlinkNode::new(metadata(), b"not-a-source-path".to_vec()).unwrap(),
                ),
            },
        ];
        Directory::new(metadata(), entries).unwrap()
    }

    fn tree_object() -> NixStoreObjectV2 {
        let directory_bytes = aos_sandbox_core::format::encode_directory(&directory_with_leaves());
        let directory_descriptor = descriptor(PortableMediaType::Directory, &directory_bytes);
        let tree = Tree::new(directory_descriptor.clone(), Vec::new()).unwrap();
        let tree_bytes = aos_sandbox_core::format::encode_tree(&tree);
        let tree_descriptor = descriptor(PortableMediaType::Tree, &tree_bytes);
        let mut records = vec![
            NixPortableObjectV2 {
                descriptor: directory_descriptor,
                bytes: directory_bytes,
            },
            NixPortableObjectV2 {
                descriptor: tree_descriptor.clone(),
                bytes: tree_bytes,
            },
        ];
        records.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

        NixStoreObjectV2 {
            path: format!("/nix/store/{}-b", "0".repeat(32)),
            portable: tree_descriptor,
            nar_sha256: ObjectDigest::from_bytes([4; 32]),
            nar_size: 80,
            references: Vec::new(),
            portable_objects: records,
        }
    }

    fn recipe() -> NixPreadmittedRecipeV2 {
        let source = tree_object();
        let lock = content_object('a', b"lock");
        let mut derivation = content_object('c', b"derivation");
        derivation.path.push_str(".drv");
        derivation.references = vec![lock.path.clone(), source.path.clone()];

        // These are the protocol's shape coordinates, not physical authority.
        NixPreadmittedRecipeV2 {
            version: 2,
            node: NodeId::from_bytes([1; 16]),
            deployment: ObjectDigest::from_bytes([2; 32]),
            endpoint: ResourceId::from_bytes([3; 16]),
            domain: ResourceId::from_bytes([4; 16]),
            domain_commitment: ObjectDigest::from_bytes([5; 32]),
            disclosure: ObjectDigest::from_bytes([6; 32]),
            project: ProjectId::from_bytes([7; 16]),
            sandbox: SandboxId::from_bytes([8; 16]),
            specification: descriptor(PortableMediaType::SandboxSpec, b"specification"),
            environment: descriptor(PortableMediaType::Environment, b"environment"),
            generation_manifest: vec![1],
            policy: descriptor(PortableMediaType::Policy, b"policy"),
            source: source.portable.clone(),
            lock: lock.portable.clone(),
            source_path: source.path.clone(),
            lock_path: lock.path.clone(),
            selected_output: "packages.default".into(),
            target_system: "x86_64-linux".into(),
            derivation,
            derivation_bytes: b"derivation".to_vec(),
            inputs: vec![lock, source],
            outputs: vec![NixExpectedOutputV2 {
                name: "out".into(),
                object: content_object('d', b"predicted-only"),
            }],
        }
    }

    #[test]
    fn complete_projection_includes_every_input_leaf_and_no_predicted_output() {
        let fixture = recipe();
        fixture.validate().unwrap();

        let specs = project_inputs(&fixture).unwrap();

        assert_eq!(specs.len(), 6);
        assert!(specs.iter().any(|spec| spec.descriptor == fixture.derivation.portable));
        assert!(specs.iter().any(|spec| spec.descriptor == fixture.lock));
        for record in &fixture.inputs[1].portable_objects {
            assert!(specs.iter().any(|spec| spec.descriptor == record.descriptor));
        }
        for bytes in [b"".as_slice(), b"leaf".as_slice()] {
            assert!(specs.iter().any(|spec| {
                spec.descriptor == descriptor(PortableMediaType::Content, bytes)
            }));
        }
        assert!(!specs.iter().any(|spec| spec.descriptor == fixture.outputs[0].object.portable));
    }

    #[test]
    fn an_exact_content_duplicate_keeps_the_derivation_original_obligation() {
        let value = descriptor(PortableMediaType::Content, b"same");
        let mut projection = InputProjectionV2::default();
        projection.add(&value, None).unwrap();
        projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"same",
        })).unwrap();
        projection.add(&value, None).unwrap();

        let specs = projection.into_specs().unwrap();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].original_bytes, Some(OriginalInputBytesV2::Derivation));
    }

    #[test]
    fn duplicate_metadata_requires_full_original_bytes_to_agree() {
        let value = descriptor(PortableMediaType::Directory, b"same");
        let mut projection = InputProjectionV2::default();
        projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Reconstruction {
                input_index: 0,
                record_index: 0,
            },
            bytes: b"same",
        })).unwrap();

        let result = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Reconstruction {
                input_index: 1,
                record_index: 0,
            },
            bytes: b"diff",
        }));

        assert!(matches!(result, Err(NixLocalInputErrorV2::Conflict)));
        assert_eq!(projection.inputs.len(), 1);
    }

    #[test]
    fn equal_metadata_at_two_original_locations_is_deduplicated() {
        let value = descriptor(PortableMediaType::Directory, b"same");
        let mut projection = InputProjectionV2::default();
        for input_index in [0, 1] {
            projection.add(&value, Some(OriginalProjectionV2 {
                locator: OriginalInputBytesV2::Reconstruction {
                    input_index,
                    record_index: 0,
                },
                bytes: b"same",
            })).unwrap();
        }

        assert_eq!(projection.inputs.len(), 1);
        assert_eq!(projection.distinct_bytes, 4);
    }

    #[test]
    fn a_shared_basename_never_accepts_changed_media_or_size() {
        let value = descriptor(PortableMediaType::Content, b"same");
        let substitutions = [
            ObjectDescriptor::new(
                MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
                value.digest(),
                value.encoded_size(),
            ),
            ObjectDescriptor::new(
                value.media_type().clone(),
                value.digest(),
                value.encoded_size() + 1,
            ),
        ];
        for changed in substitutions {
            let mut projection = InputProjectionV2::default();
            projection.add(&value, None).unwrap();

            assert!(matches!(projection.add(&changed, None), Err(NixLocalInputErrorV2::Conflict)));
            assert_eq!(projection.inputs.len(), 1);
        }
    }

    #[test]
    fn distinct_count_is_checked_before_projection_growth() {
        let media = MediaType::new(PortableMediaType::Content.as_str()).unwrap();
        let mut projection = InputProjectionV2::default();
        for index in 0..MAXIMUM_INPUT_PINS {
            let mut digest = [1_u8; 32];
            digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let value = ObjectDescriptor::new(media.clone(), ObjectDigest::from_bytes(digest), 0);
            projection.add(&value, None).unwrap();
        }
        let capacity = projection.inputs.capacity();
        let extra = ObjectDescriptor::new(media, ObjectDigest::from_bytes([9; 32]), 0);

        assert!(matches!(projection.add(&extra, None), Err(NixLocalInputErrorV2::Bound)));
        assert_eq!(projection.inputs.len(), MAXIMUM_INPUT_PINS);
        assert_eq!(projection.inputs.capacity(), capacity);
    }

    #[test]
    fn aggregate_counts_distinct_bytes_and_preserves_the_exact_limit() {
        let media = MediaType::new(PortableMediaType::Content.as_str()).unwrap();
        let full = ObjectDescriptor::new(
            media.clone(), ObjectDigest::from_bytes([1; 32]), MAXIMUM_INPUT_BYTES,
        );
        let empty = descriptor(PortableMediaType::Content, b"");
        let extra = ObjectDescriptor::new(media, ObjectDigest::from_bytes([2; 32]), 1);
        let mut projection = InputProjectionV2::default();
        projection.add(&full, None).unwrap();
        projection.add(&full, None).unwrap();
        projection.add(&empty, None).unwrap();

        assert!(matches!(projection.add(&extra, None), Err(NixLocalInputErrorV2::Bound)));
        assert_eq!(projection.inputs.len(), 2);
        assert_eq!(projection.distinct_bytes, MAXIMUM_INPUT_BYTES);
    }

    #[test]
    fn checked_growth_rejects_integer_and_per_object_overflow() {
        for (count, total, size) in [
            (usize::MAX, 0, 0),
            (0, u64::MAX, 1),
            (0, 0, MAXIMUM_INPUT_BYTES + 1),
        ] {
            assert!(matches!(
                checked_projection_growth(count, total, size),
                Err(NixLocalInputErrorV2::Bound)
            ));
        }
    }

    #[test]
    fn original_declared_length_must_match_before_projection_growth() {
        let value = descriptor(PortableMediaType::Content, b"four");
        let mut projection = InputProjectionV2::default();

        let result = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"short",
        }));

        assert!(matches!(result, Err(NixLocalInputErrorV2::OriginalMismatch)));
        assert!(projection.inputs.is_empty());
    }

    #[test]
    fn sparse_content_is_refused_instead_of_flattened() {
        let file = FileNode {
            metadata: metadata(),
            content: ContentLayout::Sparse(SparseContent::new(10, Vec::new()).unwrap()),
            hardlink_group: None,
        };
        let entries = vec![DirectoryEntry {
            name: PathName::new(b"sparse".to_vec()).unwrap(),
            node: Node::File(file),
        }];
        let directory = Directory::new(metadata(), entries).unwrap();
        let bytes = aos_sandbox_core::format::encode_directory(&directory);
        let mut projection = InputProjectionV2::default();

        assert!(matches!(
            project_directory_leaves(&mut projection, &bytes),
            Err(NixLocalInputErrorV2::UnsupportedLayout)
        ));
    }

    #[test]
    fn the_streaming_directory_decoder_must_reach_exact_terminal_eof() {
        let mut bytes = aos_sandbox_core::format::encode_directory(&directory_with_leaves());
        bytes.push(0);
        let mut projection = InputProjectionV2::default();

        assert!(matches!(
            project_directory_leaves(&mut projection, &bytes),
            Err(NixLocalInputErrorV2::Directory(_))
        ));
    }

    #[test]
    fn original_locator_comparison_checks_exact_chunks_and_indices() {
        let fixture = recipe();
        let specs = project_inputs(&fixture).unwrap();
        let derivation = specs.iter()
            .find(|spec| spec.descriptor == fixture.derivation.portable).unwrap();

        assert!(require_original_chunk(&fixture, derivation, 0, b"deri").is_ok());
        assert!(require_original_chunk(&fixture, derivation, 4, b"vation").is_ok());
        assert!(matches!(
            require_original_chunk(&fixture, derivation, 0, b"DERI"),
            Err(NixLocalInputErrorV2::OriginalMismatch)
        ));
        assert!(matches!(
            require_original_chunk(&fixture, derivation, 10, b"x"),
            Err(NixLocalInputErrorV2::OriginalMismatch)
        ));

        let wrong = InputSpecV2 {
            descriptor: fixture.derivation.portable.clone(),
            original_bytes: Some(OriginalInputBytesV2::Reconstruction {
                input_index: usize::MAX,
                record_index: 0,
            }),
        };
        assert!(matches!(
            require_original_chunk(&fixture, &wrong, 0, b"x"),
            Err(NixLocalInputErrorV2::OriginalMismatch)
        ));
    }

    #[test]
    fn read_bounds_are_checked_without_wrapping_offsets_or_allocating_payloads() {
        assert_eq!(checked_read_length(10, 8, INPUT_SCRATCH_BYTES).unwrap(), 2);
        assert_eq!(checked_read_length(10, 10, 1).unwrap(), 0);
        assert_eq!(checked_read_length(0, 0, 1).unwrap(), 0);
        assert_eq!(checked_read_length(10, 0, 0).unwrap(), 0);
        assert!(matches!(checked_read_length(10, 11, 1), Err(NixLocalInputErrorV2::Bound)));
        assert!(matches!(
            checked_read_length(10, 0, INPUT_SCRATCH_BYTES + 1),
            Err(NixLocalInputErrorV2::Bound)
        ));
    }

    #[test]
    fn canonical_streaming_accepts_empty_content_and_varied_chunk_boundaries() {
        for bytes in [b"".as_slice(), b"canonical payload".as_slice()] {
            let value = descriptor(PortableMediaType::Content, bytes);
            for chunk_size in [1, 3, INPUT_SCRATCH_BYTES] {
                let mut verifier = ObjectDescriptorVerifier::new(value.clone());
                for chunk in bytes.chunks(chunk_size) {
                    verifier.update(chunk).unwrap();
                }
                verifier.finish().unwrap();
            }
        }
    }

    #[test]
    fn canonical_streaming_rejects_truncation_append_and_equal_length_substitution() {
        let value = descriptor(PortableMediaType::Content, b"hello");
        let mut short = ObjectDescriptorVerifier::new(value.clone());
        short.update(b"hell").unwrap();
        assert_eq!(short.finish(), Err(ObjectDescriptorVerificationError::TooShort));

        let mut long = ObjectDescriptorVerifier::new(value.clone());
        assert_eq!(long.update(b"hello!"), Err(ObjectDescriptorVerificationError::TooLong));
        assert_eq!(long.finish(), Err(ObjectDescriptorVerificationError::TooLong));

        let mut substituted = ObjectDescriptorVerifier::new(value);
        substituted.update(b"jello").unwrap();
        assert_eq!(substituted.finish(), Err(ObjectDescriptorVerificationError::DigestMismatch));
    }

    #[test]
    fn canonical_portable_identity_never_substitutes_raw_hash_media_or_size() {
        use sha2::{Digest as _, Sha256};

        let value = descriptor(PortableMediaType::Content, b"hello");
        assert_eq!(
            value.digest().to_string(),
            "sha256:a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903"
        );
        let changed = [
            ObjectDescriptor::new(
                value.media_type().clone(),
                ObjectDigest::from_bytes(Sha256::digest(b"hello").into()),
                value.encoded_size(),
            ),
            ObjectDescriptor::new(
                MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
                value.digest(),
                value.encoded_size(),
            ),
            ObjectDescriptor::new(
                value.media_type().clone(),
                value.digest(),
                value.encoded_size() + 1,
            ),
        ];

        for after in changed {
            let mut verifier = ObjectDescriptorVerifier::new(after);
            verifier.update(b"hello").unwrap();
            assert!(verifier.finish().is_err());
        }
    }

    #[test]
    fn reconstruction_locators_compare_the_complete_original_across_chunks() {
        let fixture = recipe();
        let specs = project_inputs(&fixture).unwrap();

        for (record_index, record) in fixture.inputs[1].portable_objects.iter().enumerate() {
            let spec = specs.iter().find(|spec| spec.descriptor == record.descriptor).unwrap();
            assert_eq!(
                spec.original_bytes,
                Some(OriginalInputBytesV2::Reconstruction { input_index: 1, record_index })
            );
            let mut offset = 0;
            for chunk in record.bytes.chunks(3) {
                assert!(require_original_chunk(&fixture, spec, offset, chunk).is_ok());
                offset += chunk.len() as u64;
            }
            assert_eq!(offset, record.descriptor.encoded_size());
        }
    }

    #[test]
    fn every_observed_identity_field_participates_in_recheck() {
        let original = ObservedInputIdentityV2 {
            device: 1,
            inode: 2,
            bytes: 3,
            allocated_bytes: 4,
            verity: FsVerityDigest::Sha256([5; 32]),
        };
        let changed = [
            ObservedInputIdentityV2 { device: 6, ..original },
            ObservedInputIdentityV2 { inode: 6, ..original },
            ObservedInputIdentityV2 { bytes: 6, ..original },
            ObservedInputIdentityV2 { allocated_bytes: 6, ..original },
            ObservedInputIdentityV2 { verity: FsVerityDigest::Sha256([6; 32]), ..original },
        ];

        assert_eq!(original, original);
        for after in changed {
            assert_ne!(original, after);
        }
    }

    #[test]
    fn a_failed_cut_latch_never_reopens_after_later_success() {
        let mut latch = InputFailureLatchV2::default();
        latch.require_open().unwrap();
        latch.finish(Ok(())).unwrap();
        assert!(matches!(
            latch.finish::<()>(Err(NixLocalInputErrorV2::Changed)),
            Err(NixLocalInputErrorV2::Changed)
        ));

        assert!(matches!(latch.require_open(), Err(NixLocalInputErrorV2::Closed)));
        latch.finish(Ok(())).unwrap();
        assert!(matches!(latch.require_open(), Err(NixLocalInputErrorV2::Closed)));
    }

    fn recipe_with_shared_tree() -> NixPreadmittedRecipeV2 {
        let mut fixture = recipe();
        let mut shared = fixture.inputs[1].clone();
        shared.path = format!("/nix/store/{}-e", "0".repeat(32));
        fixture.inputs.push(shared);
        fixture.validate().unwrap();
        fixture
    }

    #[test]
    fn shared_tree_records_preserve_sorted_specs_and_first_original_locators() {
        let original = recipe();
        original.validate().unwrap();
        let expected = project_inputs(&original).unwrap();
        let fixture = recipe_with_shared_tree();

        let actual = project_inputs(&fixture).unwrap();

        assert_eq!(actual.len(), 6);
        assert!(actual.windows(2).all(|pair| pair[0].descriptor < pair[1].descriptor));
        assert_eq!(
            actual.iter().map(|spec| (&spec.descriptor, spec.original_bytes)).collect::<Vec<_>>(),
            expected.iter().map(|spec| (&spec.descriptor, spec.original_bytes)).collect::<Vec<_>>(),
        );
        assert_eq!(
            actual.iter().map(|spec| spec.descriptor.encoded_size()).sum::<u64>(),
            expected.iter().map(|spec| spec.descriptor.encoded_size()).sum::<u64>(),
        );
        for (record_index, record) in fixture.inputs[1].portable_objects.iter().enumerate() {
            let spec = actual.iter().find(|spec| spec.descriptor == record.descriptor).unwrap();
            assert_eq!(
                spec.original_bytes,
                Some(OriginalInputBytesV2::Reconstruction { input_index: 1, record_index }),
            );
            require_original_chunk(&fixture, spec, 0, &record.bytes).unwrap();
        }
        for bytes in [b"".as_slice(), b"leaf".as_slice()] {
            let content = descriptor(PortableMediaType::Content, bytes);
            assert_eq!(actual.iter().filter(|spec| spec.descriptor == content).count(), 1);
        }
    }

    #[test]
    fn an_existing_result_follows_the_original_obligation_upgrade() {
        let value = descriptor(PortableMediaType::Content, b"same");
        let mut projection = InputProjectionV2::default();
        let inserted = projection.add(&value, None).unwrap();
        let capacity = projection.inputs.capacity();

        let upgraded = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"same",
        })).unwrap();
        let repeated = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Reconstruction { input_index: 2, record_index: 0 },
            bytes: b"same",
        })).unwrap();

        assert_eq!(inserted, ProjectionInsertionV2::Inserted);
        assert_eq!(upgraded, ProjectionInsertionV2::Existing);
        assert_eq!(repeated, ProjectionInsertionV2::Existing);
        assert_eq!(projection.inputs.capacity(), capacity);

        let specs = projection.into_specs().unwrap();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].original_bytes, Some(OriginalInputBytesV2::Derivation));
    }

    #[test]
    fn shared_directory_bytes_are_checked_before_duplicate_scan_suppression() {
        for truncate in [false, true] {
            let mut fixture = recipe_with_shared_tree();
            let record = fixture.inputs[2].portable_objects.iter_mut().find(|record| {
                record.descriptor.media_type().as_str() == PortableMediaType::Directory.as_str()
            }).unwrap();
            if truncate {
                record.bytes.truncate(record.bytes.len() - 1);
            } else {
                record.bytes[0] ^= 1;
            }

            let result = project_inputs(&fixture);

            if truncate {
                assert!(matches!(result, Err(NixLocalInputErrorV2::OriginalMismatch)));
            } else {
                assert!(matches!(result, Err(NixLocalInputErrorV2::Conflict)));
            }
        }
    }

    #[test]
    fn a_first_directory_error_aborts_the_fresh_shared_projection() {
        let mut fixture = recipe_with_shared_tree();
        let record = fixture.inputs[1].portable_objects.iter_mut().find(|record| {
            record.descriptor.media_type().as_str() == PortableMediaType::Directory.as_str()
        }).unwrap();
        record.bytes[0] ^= 1;

        let result = project_inputs(&fixture);

        assert!(matches!(result, Err(NixLocalInputErrorV2::Directory(_))));
    }

    #[test]
    fn duplicate_checks_keep_their_priority_at_both_projection_ceilings() {
        let value = descriptor(PortableMediaType::Content, b"same");
        let mut projection = InputProjectionV2::default();
        projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"same",
        })).unwrap();
        let remainder = ObjectDescriptor::new(
            value.media_type().clone(),
            ObjectDigest::from_bytes([9; 32]),
            MAXIMUM_INPUT_BYTES - value.encoded_size(),
        );
        projection.add(&remainder, None).unwrap();
        for index in 0..MAXIMUM_INPUT_PINS - 2 {
            let mut digest = [2_u8; 32];
            digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let empty = ObjectDescriptor::new(
                value.media_type().clone(), ObjectDigest::from_bytes(digest), 0,
            );
            projection.add(&empty, None).unwrap();
        }
        let capacity = projection.inputs.capacity();
        let changed_media = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
            value.digest(),
            value.encoded_size(),
        );

        let wrong_length = projection.add(&changed_media, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"short",
        }));
        let wrong_descriptor = projection.add(&changed_media, None);
        let wrong_bytes = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Derivation,
            bytes: b"diff",
        }));
        let repeated = projection.add(&value, Some(OriginalProjectionV2 {
            locator: OriginalInputBytesV2::Reconstruction { input_index: 2, record_index: 0 },
            bytes: b"same",
        })).unwrap();
        let extra = ObjectDescriptor::new(
            value.media_type().clone(), ObjectDigest::from_bytes([8; 32]), 0,
        );
        let overflow = projection.add(&extra, None);

        assert!(matches!(wrong_length, Err(NixLocalInputErrorV2::OriginalMismatch)));
        assert!(matches!(wrong_descriptor, Err(NixLocalInputErrorV2::Conflict)));
        assert!(matches!(wrong_bytes, Err(NixLocalInputErrorV2::Conflict)));
        assert_eq!(repeated, ProjectionInsertionV2::Existing);
        assert!(matches!(overflow, Err(NixLocalInputErrorV2::Bound)));
        assert_eq!(projection.inputs.len(), MAXIMUM_INPUT_PINS);
        assert_eq!(projection.distinct_bytes, MAXIMUM_INPUT_BYTES);
        assert_eq!(projection.inputs.capacity(), capacity);
        assert_eq!(
            projection.inputs[0].original.unwrap().locator,
            OriginalInputBytesV2::Derivation,
        );
    }

    #[test]
    fn shared_empty_directories_keep_the_complete_metadata_only_projection() {
        let mut fixture = recipe_with_shared_tree();
        let directory = Directory::new(metadata(), Vec::new()).unwrap();
        let directory_bytes = aos_sandbox_core::format::encode_directory(&directory);
        let directory_descriptor = descriptor(PortableMediaType::Directory, &directory_bytes);
        let tree = Tree::new(directory_descriptor.clone(), Vec::new()).unwrap();
        let tree_bytes = aos_sandbox_core::format::encode_tree(&tree);
        let tree_descriptor = descriptor(PortableMediaType::Tree, &tree_bytes);
        let mut records = vec![
            NixPortableObjectV2 { descriptor: directory_descriptor.clone(), bytes: directory_bytes },
            NixPortableObjectV2 { descriptor: tree_descriptor.clone(), bytes: tree_bytes },
        ];
        records.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
        for input in &mut fixture.inputs[1..] {
            input.portable = tree_descriptor.clone();
            input.portable_objects = records.clone();
        }
        fixture.source = tree_descriptor.clone();
        fixture.validate().unwrap();

        let specs = project_inputs(&fixture).unwrap();

        assert_eq!(specs.len(), 4);
        assert!(specs.windows(2).all(|pair| pair[0].descriptor < pair[1].descriptor));
        for (record_index, record) in records.iter().enumerate() {
            let spec = specs.iter().find(|spec| spec.descriptor == record.descriptor).unwrap();
            assert_eq!(
                spec.original_bytes,
                Some(OriginalInputBytesV2::Reconstruction { input_index: 1, record_index }),
            );
        }
        assert!(!specs.iter().any(|spec| {
            spec.descriptor == descriptor(PortableMediaType::Content, b"")
        }));
    }

    #[test]
    fn reused_scratch_verifies_only_positive_prefixes_with_fresh_object_state() {
        let objects = [
            vec![0x11; INPUT_SCRATCH_BYTES + 7],
            b"a different second object".to_vec(),
            Vec::new(),
        ];
        let mut scratch = [0xa5_u8; INPUT_SCRATCH_BYTES];

        for partial_length in [1, 3, INPUT_SCRATCH_BYTES] {
            for bytes in &objects {
                let value = descriptor(PortableMediaType::Content, bytes);
                let mut verifier = ObjectDescriptorVerifier::new(value.clone());
                let mut offset = 0_usize;
                while offset < bytes.len() {
                    let requested = checked_read_length(
                        value.encoded_size(), offset as u64, INPUT_SCRATCH_BYTES,
                    ).unwrap();
                    let read = requested.min(partial_length);
                    assert!(read > 0);
                    scratch[..read].copy_from_slice(&bytes[offset..offset + read]);
                    verifier.update(&scratch[..read]).unwrap();
                    offset += read;
                }

                assert_eq!(offset as u64, value.encoded_size());
                verifier.finish().unwrap();
            }
        }
    }
}
