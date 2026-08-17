//! Strictly admitted owner for one unpublished packed evaluator generation.
//!
//! The owner joins finalized thunk, frame, immutable-collection, and
//! string/path lanes without adding an object registry or a forwarding table.
//! Construction is the memory admission boundary: it charges the owner itself,
//! every backing vector's allocator-granted capacity, caller-supplied
//! collection scratch, and a caller-supplied safety allowance against the
//! caller-provided RSS ceiling.
//!
//! Retained active thunk shells are the only source-generation identities
//! carried across a future publication. The constructor sorts their allowlist
//! and requires an exact one-to-one population match with independently
//! collected active-lease and mutable-root inventories.

use std::mem;

use thiserror::Error;

use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::{Value, ValueTag};

use super::packed_collection_lane::{
    PackedAttrsRef, PackedCollectionLane, PackedCollectionLaneBytes, PackedCollectionLaneError,
    PackedListRef,
};
use super::packed_frame_lane::{PackedFrameLane, PackedFrameLaneBytes};
use super::packed_scalar_lane::{
    PackedFloatRef, PackedIntRef, PackedScalarLane, PackedScalarLaneBytes, PackedScalarLaneError,
};
use super::packed_string_lane::{
    PackedNixStringView, PackedPathRef, PackedStringLane, PackedStringLaneBytes,
    PackedStringLaneError, PackedStringRef,
};
use super::packed_thunk_lane::{PackedThunkLane, PackedThunkLaneBytes};
use super::packed_translation::PackedTranslationBytes;
use super::{EvalHeap, EvalHeapError};

/// Caller-observed process state charged at packed-generation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedGenerationAdmissionInput {
    /// Current resident bytes immediately before destination admission.
    pub(crate) current_rss_bytes: usize,
    /// Collector scratch that remains committed while the destination exists.
    pub(crate) scratch_bytes: usize,
    /// Explicit unmodeled and allocator safety allowance.
    pub(crate) safety_bytes: usize,
    /// Caller-selected resident-memory ceiling.
    pub(crate) rss_ceiling_bytes: usize,
}

impl Default for PackedGenerationAdmissionInput {
    fn default() -> Self {
        Self {
            current_rss_bytes: 0,
            scratch_bytes: 0,
            safety_bytes: 0,
            rss_ceiling_bytes: usize::MAX,
        }
    }
}

impl PackedGenerationAdmissionInput {
    /// Builds an admission input that charges exact translation scratch.
    ///
    /// `additional_scratch_bytes` covers other live construction state. The
    /// translation directory's allocator-capacity total is always included,
    /// preventing a caller from charging only initialized mappings.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::AdmissionOverflow`] when the scratch
    /// byte sum exceeds `usize`.
    pub(crate) fn try_with_translation(
        current_rss_bytes: usize,
        translation: PackedTranslationBytes,
        additional_scratch_bytes: usize,
        safety_bytes: usize,
        rss_ceiling_bytes: usize,
    ) -> Result<Self, PackedGenerationError> {
        let scratch_bytes = translation
            .capacity_total
            .checked_add(additional_scratch_bytes)
            .ok_or(PackedGenerationError::AdmissionOverflow)?;
        Ok(Self {
            current_rss_bytes,
            scratch_bytes,
            safety_bytes,
            rss_ceiling_bytes,
        })
    }
}

/// A preallocated, unregistered logical domain for one packed generation.
///
/// Construction consumes a domain even when later lane building fails. Domain
/// identities are intentionally non-reusing, so failed attempts cannot make a
/// stale compressed word alias a future generation.
#[derive(Debug)]
pub(crate) struct PackedGenerationDomain {
    domain: ArenaDomainId,
}

impl PackedGenerationDomain {
    /// Allocates the destination identity before translation or lane building.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::DomainExhausted`] when the process-wide
    /// non-reusing logical domain space is exhausted.
    pub(crate) fn try_allocate() -> Result<Self, PackedGenerationError> {
        let domain = ArenaDomainId::allocate_logical()
            .map_err(|_| PackedGenerationError::DomainExhausted)?;
        Ok(Self { domain })
    }

    /// Returns the logical Candidate-C domain for translation construction.
    pub(crate) const fn id(&self) -> ArenaDomainId {
        self.domain
    }
}

/// Exact initialized and allocated-capacity bytes owned by a packed generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedGenerationBytes {
    /// Inline control state, including all vector descriptors and accounting.
    pub(crate) control: usize,
    /// Initialized thunk-head and shape-pool bytes.
    pub(crate) thunk_initialized: PackedThunkLaneBytes,
    /// Allocated thunk-head and shape-pool capacity bytes.
    pub(crate) thunk_capacity: PackedThunkLaneBytes,
    /// Initialized frame-record and frame-slot bytes.
    pub(crate) frame_initialized: PackedFrameLaneBytes,
    /// Allocated frame-record and frame-slot capacity bytes.
    pub(crate) frame_capacity: PackedFrameLaneBytes,
    /// Initialized collection backing bytes, excluding its inline control.
    pub(crate) collection_initialized: usize,
    /// Allocated collection capacity bytes, excluding its inline control.
    pub(crate) collection_capacity: usize,
    /// Initialized string/path backing bytes, excluding its inline control.
    pub(crate) string_initialized: usize,
    /// Allocated string/path capacity bytes, excluding its inline control.
    pub(crate) string_capacity: usize,
    /// Initialized boxed-scalar backing bytes, excluding its inline control.
    pub(crate) scalar_initialized: usize,
    /// Allocated boxed-scalar capacity bytes, excluding its inline control.
    pub(crate) scalar_capacity: usize,
    /// Initialized retained-shell address bytes.
    pub(crate) retained_shells_initialized: usize,
    /// Allocated retained-shell address capacity bytes.
    pub(crate) retained_shells_capacity: usize,
    /// Exact initialized owner bytes.
    pub(crate) initialized_total: usize,
    /// Conservative allocator-capacity owner bytes used for admission.
    pub(crate) capacity_total: usize,
}

/// Successful strict-memory admission for one packed generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedGenerationAdmission {
    /// Current RSS supplied at admission.
    pub(crate) current_rss_bytes: usize,
    /// Destination capacity bytes charged by the owner.
    pub(crate) destination_capacity_bytes: usize,
    /// Caller-supplied scratch bytes.
    pub(crate) scratch_bytes: usize,
    /// Caller-supplied safety bytes.
    pub(crate) safety_bytes: usize,
    /// Checked worst-case overlap peak.
    pub(crate) projected_peak_bytes: usize,
    /// Bytes strictly below the acceptance ceiling.
    pub(crate) headroom_bytes: usize,
}

/// Finalized lanes and the exact retained-source-shell allowlist.
///
/// The owner exposes no mutable lane or allowlist access, so construction
/// cannot be followed by destination or metadata growth. Runtime thunk-state
/// mutation will use a separate publication API once the resolver is wired.
#[derive(Debug)]
pub(crate) struct PackedGeneration {
    domain: ArenaDomainId,
    thunks: PackedThunkLane,
    frames: PackedFrameLane,
    collections: PackedCollectionLane,
    strings: PackedStringLane,
    scalars: PackedScalarLane,
    retained_shells: Vec<usize>,
    bytes: PackedGenerationBytes,
    admission: PackedGenerationAdmission,
}

impl PackedGeneration {
    /// Admits finalized lanes under the strict RSS ceiling.
    ///
    /// `retained_shells`, `active_lease_shells`, and `active_root_shells`
    /// independently name the source addresses expected to remain live. The
    /// method sorts each inventory, rejects duplicates, and requires exact
    /// equality before admitting destination memory.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError`] for byte-accounting overflow,
    /// collection-lane accounting failure, null or duplicate shell identities,
    /// unequal shell populations, or a projected peak that reaches or exceeds
    /// the strict RSS ceiling.
    pub(crate) fn try_admit(
        thunks: PackedThunkLane,
        frames: PackedFrameLane,
        collections: PackedCollectionLane,
        strings: PackedStringLane,
        scalars: PackedScalarLane,
        retained_shells: Vec<usize>,
        active_lease_shells: Vec<usize>,
        active_root_shells: Vec<usize>,
        input: PackedGenerationAdmissionInput,
    ) -> Result<Self, PackedGenerationError> {
        let domain = PackedGenerationDomain::try_allocate()?;
        Self::try_admit_in_domain(
            domain,
            thunks,
            frames,
            collections,
            strings,
            scalars,
            retained_shells,
            active_lease_shells,
            active_root_shells,
            input,
        )
    }

    /// Admits finalized lanes into a previously allocated logical domain.
    ///
    /// This ordering lets a construction transaction build its translation
    /// directory and embedded packed edges against the final destination
    /// identity before attempting owner admission.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError`] for byte-accounting overflow,
    /// collection or string-lane accounting failure, invalid shell inventories,
    /// or a projected peak that reaches or exceeds the strict RSS ceiling.
    pub(crate) fn try_admit_in_domain(
        domain: PackedGenerationDomain,
        thunks: PackedThunkLane,
        frames: PackedFrameLane,
        collections: PackedCollectionLane,
        strings: PackedStringLane,
        scalars: PackedScalarLane,
        mut retained_shells: Vec<usize>,
        mut active_lease_shells: Vec<usize>,
        mut active_root_shells: Vec<usize>,
        input: PackedGenerationAdmissionInput,
    ) -> Result<Self, PackedGenerationError> {
        normalize_shells(&mut retained_shells, PackedShellInventory::Retained)?;
        normalize_shells(&mut active_lease_shells, PackedShellInventory::ActiveLease)?;
        normalize_shells(&mut active_root_shells, PackedShellInventory::ActiveRoot)?;
        if retained_shells.len() != active_lease_shells.len()
            || retained_shells.len() != active_root_shells.len()
        {
            return Err(PackedGenerationError::ShellPopulationMismatch {
                retained: retained_shells.len(),
                active_leases: active_lease_shells.len(),
                active_roots: active_root_shells.len(),
            });
        }
        for (index, ((retained, active_lease), active_root)) in retained_shells
            .iter()
            .zip(&active_lease_shells)
            .zip(&active_root_shells)
            .enumerate()
        {
            if retained != active_lease || retained != active_root {
                return Err(PackedGenerationError::ShellIdentityMismatch {
                    index,
                    retained: *retained,
                    active_lease: *active_lease,
                    active_root: *active_root,
                });
            }
        }

        let bytes = generation_bytes(
            &thunks,
            &frames,
            &collections,
            &strings,
            &scalars,
            &retained_shells,
        )?;
        let projected_peak_bytes = input
            .current_rss_bytes
            .checked_add(bytes.capacity_total)
            .and_then(|total| total.checked_add(input.scratch_bytes))
            .and_then(|total| total.checked_add(input.safety_bytes))
            .ok_or(PackedGenerationError::AdmissionOverflow)?;
        if projected_peak_bytes >= input.rss_ceiling_bytes {
            return Err(PackedGenerationError::RssCeilingReached {
                projected_peak_bytes,
                ceiling_bytes: input.rss_ceiling_bytes,
            });
        }
        let admission = PackedGenerationAdmission {
            current_rss_bytes: input.current_rss_bytes,
            destination_capacity_bytes: bytes.capacity_total,
            scratch_bytes: input.scratch_bytes,
            safety_bytes: input.safety_bytes,
            projected_peak_bytes,
            headroom_bytes: input.rss_ceiling_bytes - projected_peak_bytes,
        };
        Ok(Self {
            domain: domain.id(),
            thunks,
            frames,
            collections,
            strings,
            scalars,
            retained_shells,
            bytes,
            admission,
        })
    }

    /// Returns the logical Candidate-C domain owned by this generation.
    ///
    /// The domain has no process-global native base mapping. Packed values are
    /// resolved only by an [`super::EvalHeap`] that owns this generation, so
    /// legacy context-free pointer reconstruction rejects them.
    pub(crate) const fn domain(&self) -> ArenaDomainId {
        self.domain
    }

    /// Encodes one direct packed-list coordinate as an evaluator value.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::CoordinateEncoding`] if the
    /// Candidate-C codec unexpectedly rejects the fixed heap tag.
    pub(crate) fn list_value(
        &self,
        reference: PackedListRef,
    ) -> Result<Value, PackedGenerationError> {
        self.coordinate_value(ValueTag::List, reference.index())
    }

    /// Encodes one direct packed-attrset coordinate as an evaluator value.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::CoordinateEncoding`] if the
    /// Candidate-C codec unexpectedly rejects the fixed heap tag.
    pub(crate) fn attrs_value(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<Value, PackedGenerationError> {
        self.coordinate_value(ValueTag::Attrs, reference.index())
    }

    /// Encodes one direct packed-string coordinate as an evaluator value.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::CoordinateEncoding`] if the
    /// Candidate-C codec unexpectedly rejects the fixed heap tag.
    pub(crate) fn string_value(
        &self,
        reference: PackedStringRef,
    ) -> Result<Value, PackedGenerationError> {
        self.coordinate_value(ValueTag::String, reference.index())
    }

    /// Encodes one direct packed-path coordinate as an evaluator value.
    ///
    /// # Errors
    ///
    /// Returns [`PackedGenerationError::CoordinateEncoding`] if the
    /// Candidate-C codec unexpectedly rejects the fixed heap tag.
    pub(crate) fn path_value(
        &self,
        reference: PackedPathRef,
    ) -> Result<Value, PackedGenerationError> {
        self.coordinate_value(ValueTag::Path, reference.index())
    }

    /// Decodes a list value owned by this generation.
    pub(crate) fn list_reference(&self, value: Value) -> Option<PackedListRef> {
        self.coordinate_index(value, ValueTag::List)
            .map(PackedListRef::from_index)
    }

    /// Decodes an attrset value owned by this generation.
    pub(crate) fn attrs_reference(&self, value: Value) -> Option<PackedAttrsRef> {
        self.coordinate_index(value, ValueTag::Attrs)
            .map(PackedAttrsRef::from_index)
    }

    /// Decodes a string value owned by this generation.
    pub(crate) fn string_reference(&self, value: Value) -> Option<PackedStringRef> {
        self.coordinate_index(value, ValueTag::String)
            .map(PackedStringRef::from_index)
    }

    /// Decodes a path value owned by this generation.
    pub(crate) fn path_reference(&self, value: Value) -> Option<PackedPathRef> {
        self.coordinate_index(value, ValueTag::Path)
            .map(PackedPathRef::from_index)
    }

    /// Returns an allocation-free packed-string view for an owned value.
    ///
    /// Returns `None` when `value` is not a string coordinate in this
    /// generation. A recognized coordinate can still fail if its finalized
    /// lane record is malformed.
    pub(crate) fn string_view(
        &self,
        value: Value,
    ) -> Option<Result<PackedNixStringView<'_>, PackedStringLaneError>> {
        self.string_reference(value)
            .map(|reference| self.strings.string(reference))
    }

    /// Returns an allocation-free packed-path view for an owned value.
    ///
    /// Returns `None` when `value` is not a path coordinate in this generation.
    /// A recognized coordinate can still fail if its finalized lane record is
    /// malformed.
    pub(crate) fn path_view(
        &self,
        value: Value,
    ) -> Option<Result<PackedNixStringView<'_>, PackedStringLaneError>> {
        self.path_reference(value)
            .map(|reference| self.strings.path(reference))
    }

    /// Encodes one direct packed boxed-integer coordinate.
    pub(crate) fn integer_value(&self, reference: PackedIntRef) -> Value {
        Value::from_word(crate::value::compressed::CompressedValueWord::boxed_int(
            self.domain,
            ArenaIndex::new(reference.index()),
        ))
    }

    /// Encodes one direct packed boxed-float coordinate.
    pub(crate) fn float_value(&self, reference: PackedFloatRef) -> Value {
        Value::from_word(crate::value::compressed::CompressedValueWord::boxed_float(
            self.domain,
            ArenaIndex::new(reference.index()),
        ))
    }

    /// Decodes a boxed-integer value owned by this generation.
    pub(crate) fn integer_reference(&self, value: Value) -> Option<PackedIntRef> {
        self.scalar_coordinate_index(
            value,
            crate::value::compressed::CompressedValueKind::BoxedInt,
        )
        .map(PackedIntRef::from_index)
    }

    /// Decodes a boxed-float value owned by this generation.
    pub(crate) fn float_reference(&self, value: Value) -> Option<PackedFloatRef> {
        self.scalar_coordinate_index(
            value,
            crate::value::compressed::CompressedValueKind::BoxedFloat,
        )
        .map(PackedFloatRef::from_index)
    }

    /// Returns an allocation-free integer payload for an owned boxed value.
    pub(crate) fn integer(&self, value: Value) -> Option<Result<i64, PackedScalarLaneError>> {
        self.integer_reference(value)
            .map(|reference| self.scalars.integer(reference))
    }

    /// Returns an allocation-free float payload for an owned boxed value.
    pub(crate) fn float(&self, value: Value) -> Option<Result<f64, PackedScalarLaneError>> {
        self.float_reference(value)
            .map(|reference| self.scalars.float(reference))
    }

    fn coordinate_value(&self, tag: ValueTag, index: u32) -> Result<Value, PackedGenerationError> {
        Value::from_domain_index(tag, self.domain, ArenaIndex::new(index))
            .map_err(|_| PackedGenerationError::CoordinateEncoding { tag, index })
    }

    fn coordinate_index(&self, value: Value, expected: ValueTag) -> Option<u32> {
        (value.tag() == expected && value.word().arena_domain() == Some(self.domain))
            .then(|| value.word().arena_index())
            .flatten()
            .map(ArenaIndex::raw)
    }

    fn scalar_coordinate_index(
        &self,
        value: Value,
        expected: crate::value::compressed::CompressedValueKind,
    ) -> Option<u32> {
        (value.word().kind() == expected && value.word().arena_domain() == Some(self.domain))
            .then(|| value.word().arena_index())
            .flatten()
            .map(ArenaIndex::raw)
    }

    /// Returns exact initialized and allocated-capacity owner bytes.
    pub(crate) const fn bytes(&self) -> PackedGenerationBytes {
        self.bytes
    }

    /// Returns the successful strict-memory admission.
    pub(crate) const fn admission(&self) -> PackedGenerationAdmission {
        self.admission
    }

    /// Returns the sorted, unique retained-source-shell allowlist.
    pub(crate) fn retained_shells(&self) -> &[usize] {
        &self.retained_shells
    }

    /// Returns the finalized packed thunk lane.
    pub(crate) const fn thunks(&self) -> &PackedThunkLane {
        &self.thunks
    }

    /// Returns the finalized packed frame lane.
    pub(crate) const fn frames(&self) -> &PackedFrameLane {
        &self.frames
    }

    /// Returns the finalized packed immutable-collection lane.
    pub(crate) const fn collections(&self) -> &PackedCollectionLane {
        &self.collections
    }

    /// Returns the finalized packed string/path lane.
    pub(crate) const fn strings(&self) -> &PackedStringLane {
        &self.strings
    }

    /// Returns the finalized packed boxed-scalar lane.
    pub(crate) const fn scalars(&self) -> &PackedScalarLane {
        &self.scalars
    }
}

impl EvalHeap {
    /// Installs an admitted packed owner without publishing packed values.
    ///
    /// This ownership seam makes its logical domain available to typed heap
    /// view resolution. Root and edge rewriting remains a separate atomic
    /// publication transaction; callers must not expose coordinates merely
    /// because the owner was installed.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ShedRejected`] for a shared heap or when a
    /// packed owner is already installed.
    pub(crate) fn install_packed_generation_owner(
        &mut self,
        generation: PackedGeneration,
    ) -> Result<(), EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "packed generations require the serial heap",
            });
        }
        if self.packed_generation.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "a packed generation owner is already installed",
            });
        }
        self.packed_generation = Some(generation);
        Ok(())
    }

    /// Returns the installed packed owner, when present.
    pub(crate) const fn packed_generation(&self) -> Option<&PackedGeneration> {
        self.packed_generation.as_ref()
    }
}

fn generation_bytes(
    thunks: &PackedThunkLane,
    frames: &PackedFrameLane,
    collections: &PackedCollectionLane,
    strings: &PackedStringLane,
    scalars: &PackedScalarLane,
    retained_shells: &Vec<usize>,
) -> Result<PackedGenerationBytes, PackedGenerationError> {
    let thunk_initialized = thunks.initialized_bytes();
    let thunk_capacity = thunks.capacity_bytes();
    let frame_initialized = frames.initialized_bytes();
    let frame_capacity = frames.capacity_bytes();
    let collection_initialized = collection_backing_bytes(collections.initialized_bytes()?)?;
    let collection_capacity = collection_backing_bytes(collections.capacity_bytes()?)?;
    let string_initialized = string_backing_bytes(strings.initialized_bytes()?)?;
    let string_capacity = string_backing_bytes(strings.capacity_bytes()?)?;
    let scalar_initialized = scalar_backing_bytes(scalars.initialized_bytes()?)?;
    let scalar_capacity = scalar_backing_bytes(scalars.capacity_bytes()?)?;
    let retained_shells_initialized = retained_shells
        .len()
        .checked_mul(mem::size_of::<usize>())
        .ok_or(PackedGenerationError::ByteAccountingOverflow)?;
    let retained_shells_capacity = retained_shells
        .capacity()
        .checked_mul(mem::size_of::<usize>())
        .ok_or(PackedGenerationError::ByteAccountingOverflow)?;
    let control = mem::size_of::<PackedGeneration>();
    let initialized_total = checked_sum([
        control,
        thunk_initialized.total(),
        frame_initialized.total(),
        collection_initialized,
        string_initialized,
        scalar_initialized,
        retained_shells_initialized,
    ])?;
    let capacity_total = checked_sum([
        control,
        thunk_capacity.total(),
        frame_capacity.total(),
        collection_capacity,
        string_capacity,
        scalar_capacity,
        retained_shells_capacity,
    ])?;
    Ok(PackedGenerationBytes {
        control,
        thunk_initialized,
        thunk_capacity,
        frame_initialized,
        frame_capacity,
        collection_initialized,
        collection_capacity,
        string_initialized,
        string_capacity,
        scalar_initialized,
        scalar_capacity,
        retained_shells_initialized,
        retained_shells_capacity,
        initialized_total,
        capacity_total,
    })
}

fn string_backing_bytes(bytes: PackedStringLaneBytes) -> Result<usize, PackedGenerationError> {
    bytes
        .total()?
        .checked_sub(bytes.control)
        .ok_or(PackedGenerationError::ByteAccountingOverflow)
}

fn scalar_backing_bytes(bytes: PackedScalarLaneBytes) -> Result<usize, PackedGenerationError> {
    bytes
        .total()?
        .checked_sub(bytes.control)
        .ok_or(PackedGenerationError::ByteAccountingOverflow)
}

fn collection_backing_bytes(
    bytes: PackedCollectionLaneBytes,
) -> Result<usize, PackedGenerationError> {
    bytes
        .total()?
        .checked_sub(bytes.control)
        .ok_or(PackedGenerationError::ByteAccountingOverflow)
}

fn checked_sum<const N: usize>(parts: [usize; N]) -> Result<usize, PackedGenerationError> {
    parts.into_iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part)
            .ok_or(PackedGenerationError::ByteAccountingOverflow)
    })
}

fn normalize_shells(
    shells: &mut [usize],
    inventory: PackedShellInventory,
) -> Result<(), PackedGenerationError> {
    shells.sort_unstable();
    if shells.first() == Some(&0) {
        return Err(PackedGenerationError::NullShell { inventory });
    }
    if let Some(address) = shells
        .windows(2)
        .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
    {
        return Err(PackedGenerationError::DuplicateShell { inventory, address });
    }
    Ok(())
}

/// One independently collected retained-shell identity inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackedShellInventory {
    /// Generation-retained source shells.
    Retained,
    /// Evaluator-owned active work leases.
    ActiveLease,
    /// Mutable active-force roots.
    ActiveRoot,
}

/// Packed-generation construction or strict-memory admission failed.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedGenerationError {
    /// Exact byte accounting overflowed `usize`.
    #[error("packed-generation byte accounting overflow")]
    ByteAccountingOverflow,
    /// Strict peak arithmetic overflowed `usize`.
    #[error("packed-generation RSS admission arithmetic overflow")]
    AdmissionOverflow,
    /// The process-wide non-reusing Candidate-C domain space is exhausted.
    #[error("packed-generation logical Candidate-C domain space is exhausted")]
    DomainExhausted,
    /// A direct packed coordinate could not be encoded with its fixed heap tag.
    #[error("packed-generation {tag:?} coordinate {index} could not be encoded")]
    CoordinateEncoding {
        /// Semantic heap tag for the packed lane.
        tag: ValueTag,
        /// Direct packed-lane record index.
        index: u32,
    },
    /// Collection-lane byte accounting failed.
    #[error("packed-generation collection accounting failed: {0}")]
    Collection(#[from] PackedCollectionLaneError),
    /// String/path-lane byte accounting failed.
    #[error("packed-generation string/path accounting failed: {0}")]
    String(#[from] PackedStringLaneError),
    /// Boxed-scalar-lane byte accounting failed.
    #[error("packed-generation scalar accounting failed: {0}")]
    Scalar(#[from] PackedScalarLaneError),
    /// A shell inventory contains the null address.
    #[error("packed-generation {inventory:?} shell inventory contains a null address")]
    NullShell {
        /// Inventory containing the invalid address.
        inventory: PackedShellInventory,
    },
    /// A shell inventory names one identity more than once.
    #[error(
        "packed-generation {inventory:?} shell inventory contains duplicate address {address:#x}"
    )]
    DuplicateShell {
        /// Inventory containing the duplicate.
        inventory: PackedShellInventory,
        /// Repeated source address.
        address: usize,
    },
    /// Retained, lease, and root shell populations are not identical.
    #[error(
        "packed-generation shell population mismatch: retained={retained}, \
         active_leases={active_leases}, active_roots={active_roots}"
    )]
    ShellPopulationMismatch {
        /// Retained allowlist length.
        retained: usize,
        /// Active-work lease inventory length.
        active_leases: usize,
        /// Active-force root inventory length.
        active_roots: usize,
    },
    /// Equal-sized shell inventories disagree at one sorted coordinate.
    #[error(
        "packed-generation shell identity mismatch at {index}: retained={retained:#x}, \
         active_lease={active_lease:#x}, active_root={active_root:#x}"
    )]
    ShellIdentityMismatch {
        /// Sorted shell coordinate that disagrees.
        index: usize,
        /// Retained allowlist identity.
        retained: usize,
        /// Active-work lease identity.
        active_lease: usize,
        /// Active-force root identity.
        active_root: usize,
    },
    /// The projected peak is not strictly below the acceptance ceiling.
    #[error(
        "packed-generation projected peak {projected_peak_bytes} reaches strict ceiling \
         {ceiling_bytes}"
    )]
    RssCeilingReached {
        /// Checked projected overlap peak.
        projected_peak_bytes: usize,
        /// Strict acceptance ceiling.
        ceiling_bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::super::EvalHeapAttrsMetadata;
    use super::super::EvalRootSet;
    use super::super::packed_collection_lane::{
        PackedAttrBinding, PackedCollectionLaneCapacities, PackedCollectionLaneDirectBuilder,
    };
    use super::super::packed_frame_lane::{
        PackedFrameLaneCapacities, PackedFrameLaneDirectBuilder,
    };
    use super::super::packed_scalar_lane::{
        PackedScalarLaneCapacities, PackedScalarLaneDirectBuilder,
    };
    use super::super::packed_string_lane::{
        PackedStringLaneCapacities, PackedStringLaneDirectBuilder,
    };
    use super::super::packed_thunk_lane::{
        PackedNodeRef, PackedNodeWork, PackedThunkLaneCapacities, PackedValueWord,
    };
    use super::super::packed_translation::{
        PackedTranslationDirectoryBuilder, PackedTranslationSegmentCapacity,
    };
    use super::*;
    use crate::attrs::repr::AttrSetReprKind;
    use crate::string::{NixString, StringContext};
    use crate::syntax::Symbol;
    use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

    fn int(value: i64) -> PackedValueWord {
        PackedValueWord::new(
            CompressedValueWord::inline_int(value)
                .unwrap_or_else(|error| panic!("test integer must fit: {error}")),
        )
    }

    fn lanes() -> (
        PackedThunkLane,
        PackedFrameLane,
        PackedCollectionLane,
        PackedStringLane,
        PackedScalarLane,
    ) {
        let mut thunks = PackedThunkLane::try_with_capacities(PackedThunkLaneCapacities {
            heads: 3,
            node: 1,
            ..PackedThunkLaneCapacities::default()
        })
        .unwrap();
        thunks.allocate_forced(int(1)).unwrap();
        thunks
            .allocate_node(PackedNodeWork::new(PackedNodeRef::new(2, 3), 0))
            .unwrap();

        let mut frames = PackedFrameLaneDirectBuilder::try_new(PackedFrameLaneCapacities {
            frames: 2,
            slots: 3,
        })
        .unwrap();
        frames.append(None, &[int(4)]).unwrap();
        let frames = frames.finish().unwrap();

        let mut collections =
            PackedCollectionLaneDirectBuilder::try_new(PackedCollectionLaneCapacities {
                lists: 2,
                list_values: 3,
                attrs: 1,
                attr_entries: 1,
                source_order: 1,
                iteration_order: 1,
                ..PackedCollectionLaneCapacities::default()
            })
            .unwrap();
        collections.append_list(&[int(5), int(6)]).unwrap();
        collections
            .append_attrs(
                EvalHeapAttrsMetadata::new(9, AttrSetReprKind::Flat),
                &[PackedAttrBinding::new(Symbol::new(7), int(8))],
                &[0],
                &[0],
            )
            .unwrap();
        let collections = collections.finish().unwrap();

        let string = NixString::from_bytes(b"packed".to_vec());
        let path = NixString::from_bytes(b"/packed/path".to_vec());
        let mut strings = PackedStringLaneDirectBuilder::try_new(PackedStringLaneCapacities {
            strings: 1,
            paths: 1,
            contexts: 1,
            bytes: string.len() + path.len(),
            ..PackedStringLaneCapacities::default()
        })
        .unwrap();
        let context = strings.append_context(&StringContext::empty()).unwrap();
        strings.append_string(&string, context).unwrap();
        strings.append_path(&path, context).unwrap();
        let strings = strings.finish().unwrap();
        let mut scalars = PackedScalarLaneDirectBuilder::try_new(PackedScalarLaneCapacities {
            integers: 1,
            floats: 1,
        })
        .unwrap();
        scalars.append_integer(i64::MAX).unwrap();
        scalars.append_float_bits(0x7ff8_0000_0000_1234).unwrap();
        let scalars = scalars.finish().unwrap();
        (thunks, frames, collections, strings, scalars)
    }

    fn admitted_with(
        input: PackedGenerationAdmissionInput,
    ) -> Result<PackedGeneration, PackedGenerationError> {
        let (thunks, frames, collections, strings, scalars) = lanes();
        PackedGeneration::try_admit(
            thunks,
            frames,
            collections,
            strings,
            scalars,
            vec![0x3000, 0x1000, 0x2000],
            vec![0x2000, 0x3000, 0x1000],
            vec![0x1000, 0x2000, 0x3000],
            input,
        )
    }

    #[test]
    fn admission_is_strict_at_the_rss_boundary() {
        const TEST_CEILING_BYTES: usize = 16 * 1024 * 1024;
        let probe = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        assert!(
            crate::heap::reservation_base(probe.domain()).is_none(),
            "packed logical domains must not permit native pointer reconstruction"
        );
        let destination = probe.bytes().capacity_total;
        let below = TEST_CEILING_BYTES
            .checked_sub(destination)
            .and_then(|bytes| bytes.checked_sub(1))
            .unwrap();
        let admitted = admitted_with(PackedGenerationAdmissionInput {
            current_rss_bytes: below,
            rss_ceiling_bytes: TEST_CEILING_BYTES,
            ..PackedGenerationAdmissionInput::default()
        })
        .unwrap();
        assert_eq!(
            admitted.admission().projected_peak_bytes,
            TEST_CEILING_BYTES - 1
        );
        assert_eq!(admitted.admission().headroom_bytes, 1);

        let boundary = admitted_with(PackedGenerationAdmissionInput {
            current_rss_bytes: below + 1,
            rss_ceiling_bytes: TEST_CEILING_BYTES,
            ..PackedGenerationAdmissionInput::default()
        });
        assert!(matches!(
            boundary,
            Err(PackedGenerationError::RssCeilingReached {
                projected_peak_bytes: TEST_CEILING_BYTES,
                ceiling_bytes: TEST_CEILING_BYTES,
            })
        ));
    }

    #[test]
    fn generations_receive_distinct_unmapped_logical_domains() {
        let first = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let second = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();

        assert_ne!(first.domain(), second.domain());
        assert!(crate::heap::reservation_base(first.domain()).is_none());
        assert!(crate::heap::reservation_base(second.domain()).is_none());
    }

    #[test]
    fn preallocated_domain_drives_translation_and_exact_scratch_admission() {
        let destination = PackedGenerationDomain::try_allocate().unwrap();
        let destination_id = destination.id();
        let source = ArenaDomainId::allocate_logical().unwrap();
        let mut translation = PackedTranslationDirectoryBuilder::try_new(
            destination_id,
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::List,
                entries: 1,
            }],
        )
        .unwrap();
        let source_list =
            CompressedValueWord::heap(source, ValueTag::List, ArenaIndex::new(7)).unwrap();
        translation.append(source_list, 0).unwrap();
        let translation_bytes = translation.bytes().unwrap();
        let input =
            PackedGenerationAdmissionInput::try_with_translation(100, translation_bytes, 200, 300)
                .unwrap();
        assert_eq!(input.scratch_bytes, translation_bytes.capacity_total + 200);
        let directory = translation.finish().unwrap();
        assert_eq!(directory.destination_domain(), destination_id);

        let (thunks, frames, collections, strings, scalars) = lanes();
        let generation = PackedGeneration::try_admit_in_domain(
            destination,
            thunks,
            frames,
            collections,
            strings,
            scalars,
            vec![0x1000],
            vec![0x1000],
            vec![0x1000],
            input,
        )
        .unwrap();
        assert_eq!(generation.domain(), destination_id);
        assert_eq!(
            generation.admission().scratch_bytes,
            translation_bytes.capacity_total + 200
        );
    }

    #[test]
    fn packed_coordinates_roundtrip_only_through_the_owning_generation() {
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let list = generation.list_value(PackedListRef::from_index(0)).unwrap();
        let attrs = generation
            .attrs_value(PackedAttrsRef::from_index(0))
            .unwrap();
        let string = generation
            .string_value(PackedStringRef::from_index(0))
            .unwrap();
        let path = generation.path_value(PackedPathRef::from_index(0)).unwrap();
        let integer = generation.integer_value(PackedIntRef::from_index(0));
        let float = generation.float_value(PackedFloatRef::from_index(0));

        assert_eq!(
            generation.list_reference(list),
            Some(PackedListRef::from_index(0))
        );
        assert_eq!(
            generation.attrs_reference(attrs),
            Some(PackedAttrsRef::from_index(0))
        );
        assert_eq!(generation.list_reference(attrs), None);
        assert_eq!(generation.attrs_reference(list), None);
        assert_eq!(
            generation.string_reference(string),
            Some(PackedStringRef::from_index(0))
        );
        assert_eq!(
            generation.path_reference(path),
            Some(PackedPathRef::from_index(0))
        );
        assert_eq!(generation.string_reference(path), None);
        assert_eq!(generation.path_reference(string), None);
        assert_eq!(
            generation.integer_reference(integer),
            Some(PackedIntRef::from_index(0))
        );
        assert_eq!(
            generation.float_reference(float),
            Some(PackedFloatRef::from_index(0))
        );
        assert_eq!(generation.integer_reference(float), None);
        assert_eq!(generation.float_reference(integer), None);
        assert_eq!(generation.integer(integer), Some(Ok(i64::MAX)));
        assert_eq!(
            generation
                .float(float)
                .map(|result| result.map(f64::to_bits)),
            Some(Ok(0x7ff8_0000_0000_1234))
        );
        assert!(
            list.as_list_ptr().is_err(),
            "unregistered packed domains must fail context-free pointer access"
        );
        assert!(
            attrs.as_attrs_ptr().is_err(),
            "unregistered packed domains must fail context-free pointer access"
        );
        assert!(
            string.as_string_ptr().is_err(),
            "unregistered packed domains must fail context-free pointer access"
        );
        assert!(
            path.as_path_ptr().is_err(),
            "unregistered packed domains must fail context-free pointer access"
        );
    }

    #[test]
    fn installed_owner_routes_packed_list_without_native_pointer_materialization() {
        let mut heap = EvalHeap::new();
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let list = generation.list_value(PackedListRef::from_index(0)).unwrap();

        heap.install_packed_generation_owner(generation).unwrap();
        let view = heap.get_list_view(list).unwrap();

        assert_eq!(
            view.iter()
                .map(|value| value.word().raw())
                .collect::<Vec<_>>(),
            [Value::int(5), Value::int(6)]
                .into_iter()
                .map(|value| value.word().raw())
                .collect::<Vec<_>>()
        );
        assert!(list.as_list_ptr().is_err());
    }

    #[test]
    fn installed_owner_routes_packed_scalars_before_the_nursery_store() {
        let mut heap = EvalHeap::new();
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let integer = generation.integer_value(PackedIntRef::from_index(0));
        let float = generation.float_value(PackedFloatRef::from_index(0));

        heap.install_packed_generation_owner(generation).unwrap();

        assert_eq!(heap.decode_int_value(integer), Ok(i64::MAX));
        assert_eq!(
            heap.decode_float_value(float).map(f64::to_bits),
            Ok(0x7ff8_0000_0000_1234)
        );
    }

    #[test]
    fn precise_scan_recognizes_packed_objects_without_pointer_materialization() {
        let mut heap = EvalHeap::new();
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let list = generation.list_value(PackedListRef::from_index(0)).unwrap();
        let string = generation
            .string_value(PackedStringRef::from_index(0))
            .unwrap();
        let integer = generation.integer_value(PackedIntRef::from_index(0));
        let float = generation.float_value(PackedFloatRef::from_index(0));
        heap.install_packed_generation_owner(generation).unwrap();
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, list).unwrap();
        roots.try_push_value_stack(1, string).unwrap();
        roots.try_push_value_stack(2, integer).unwrap();
        roots.try_push_value_stack(3, float).unwrap();

        let scan = heap.scan_precise_roots(&roots).unwrap();

        assert_eq!(scan.objects().len(), 4);
        assert!(
            scan.objects()
                .iter()
                .any(|object| object.value().raw_eq(list))
        );
        assert!(
            scan.objects()
                .iter()
                .any(|object| object.value().raw_eq(string))
        );
        assert!(
            scan.objects()
                .iter()
                .any(|object| object.value().raw_eq(integer))
        );
        assert!(
            scan.objects()
                .iter()
                .any(|object| object.value().raw_eq(float))
        );
        assert!(
            scan.objects()
                .iter()
                .all(|object| object.edges().is_empty())
        );
    }

    #[test]
    fn installed_owner_routes_packed_attrs_and_metadata() {
        let mut heap = EvalHeap::new();
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let attrs = generation
            .attrs_value(PackedAttrsRef::from_index(0))
            .unwrap();

        heap.install_packed_generation_owner(generation).unwrap();
        let view = heap.get_attrs_view(attrs).unwrap();

        assert!(
            view.get(Symbol::new(7))
                .is_some_and(|value| value.raw_eq(Value::int(8)))
        );
        assert_eq!(
            heap.get_attrs_metadata(attrs).unwrap(),
            EvalHeapAttrsMetadata::new(9, AttrSetReprKind::Flat)
        );
        assert!(attrs.as_attrs_ptr().is_err());
    }

    #[test]
    fn installed_owner_routes_packed_string_and_path_views() {
        let mut heap = EvalHeap::new();
        let generation = admitted_with(PackedGenerationAdmissionInput::default()).unwrap();
        let string = generation
            .string_value(PackedStringRef::from_index(0))
            .unwrap();
        let path = generation.path_value(PackedPathRef::from_index(0)).unwrap();

        heap.install_packed_generation_owner(generation).unwrap();
        let owner = heap.packed_generation().unwrap();
        let string_view = owner.string_view(string).unwrap().unwrap();
        let path_view = owner.path_view(path).unwrap().unwrap();

        assert_eq!(string_view.bytes(), b"packed");
        assert!(string_view.context().is_empty());
        assert_eq!(path_view.bytes(), b"/packed/path");
        assert!(path_view.context().is_empty());
        assert!(string.as_string_ptr().is_err());
        assert!(path.as_path_ptr().is_err());
    }

    #[test]
    fn owner_install_rejects_replacement_without_mutation() {
        let mut heap = EvalHeap::new();
        heap.install_packed_generation_owner(
            admitted_with(PackedGenerationAdmissionInput::default()).unwrap(),
        )
        .unwrap();
        let original_domain = heap.packed_generation().unwrap().domain();

        let error = heap
            .install_packed_generation_owner(
                admitted_with(PackedGenerationAdmissionInput::default()).unwrap(),
            )
            .unwrap_err();

        assert!(matches!(error, EvalHeapError::ShedRejected { .. }));
        assert_eq!(
            heap.packed_generation().map(PackedGeneration::domain),
            Some(original_domain)
        );
    }

    #[test]
    fn admission_overflow_fails_closed() {
        let error = admitted_with(PackedGenerationAdmissionInput {
            current_rss_bytes: usize::MAX,
            scratch_bytes: 1,
            safety_bytes: 1,
            rss_ceiling_bytes: usize::MAX,
        })
        .unwrap_err();
        assert_eq!(error, PackedGenerationError::AdmissionOverflow);
    }

    #[test]
    fn duplicate_and_mismatched_shell_inventories_are_rejected() {
        let (thunks, frames, collections, strings, scalars) = lanes();
        let duplicate = PackedGeneration::try_admit(
            thunks,
            frames,
            collections,
            strings,
            scalars,
            vec![0x1000, 0x1000],
            vec![0x1000],
            vec![0x1000],
            PackedGenerationAdmissionInput::default(),
        );
        assert!(matches!(
            duplicate,
            Err(PackedGenerationError::DuplicateShell {
                inventory: PackedShellInventory::Retained,
                address: 0x1000,
            })
        ));

        let (thunks, frames, collections, strings, scalars) = lanes();
        let mismatch = PackedGeneration::try_admit(
            thunks,
            frames,
            collections,
            strings,
            scalars,
            vec![0x1000, 0x2000],
            vec![0x1000],
            vec![0x1000, 0x2000],
            PackedGenerationAdmissionInput::default(),
        );
        assert!(matches!(
            mismatch,
            Err(PackedGenerationError::ShellPopulationMismatch {
                retained: 2,
                active_leases: 1,
                active_roots: 2,
            })
        ));

        let (thunks, frames, collections, strings, scalars) = lanes();
        let identity_mismatch = PackedGeneration::try_admit(
            thunks,
            frames,
            collections,
            strings,
            scalars,
            vec![0x1000, 0x2000],
            vec![0x1000, 0x3000],
            vec![0x1000, 0x2000],
            PackedGenerationAdmissionInput::default(),
        );
        assert!(matches!(
            identity_mismatch,
            Err(PackedGenerationError::ShellIdentityMismatch {
                index: 1,
                retained: 0x2000,
                active_lease: 0x3000,
                active_root: 0x2000,
            })
        ));
    }

    #[test]
    fn accounting_uses_measured_capacity_and_sorted_shell_capacity() {
        let generation = admitted_with(PackedGenerationAdmissionInput {
            current_rss_bytes: 100,
            scratch_bytes: 200,
            safety_bytes: 300,
            rss_ceiling_bytes: usize::MAX,
        })
        .unwrap();
        let bytes = generation.bytes();
        assert!(bytes.thunk_capacity.total() >= bytes.thunk_initialized.total());
        assert!(bytes.frame_capacity.total() >= bytes.frame_initialized.total());
        assert!(bytes.collection_capacity >= bytes.collection_initialized);
        assert!(bytes.string_capacity >= bytes.string_initialized);
        assert!(bytes.retained_shells_capacity >= bytes.retained_shells_initialized);
        assert!(bytes.capacity_total >= bytes.initialized_total);
        assert_eq!(generation.retained_shells(), &[0x1000, 0x2000, 0x3000]);
        assert_eq!(
            generation.admission().projected_peak_bytes,
            100 + bytes.capacity_total + 200 + 300
        );
        assert_eq!(
            generation.admission().destination_capacity_bytes,
            bytes.capacity_total
        );
    }
}
