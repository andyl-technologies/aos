//! Non-mutating preparation for the first mixed packed permanent rotation.
//!
//! Preparation treats a [`PreciseHeapScan`] as the complete reachable graph.
//! It moves every reachable immutable value (string, path, list, attrset, and
//! boxed scalar) into one unpublished logical packed generation while retaining
//! flat lambdas, primops, thunks, and external values. All source inventories,
//! destination coordinates, forwarding segments, and lane capacities are fixed
//! before any destination payload is copied.
//!
//! This module deliberately stops before publication: it does not install the
//! generation, rewrite roots or heap fields, retire source storage, or infer a
//! process RSS measurement. The caller supplies the observed RSS and an
//! explicit safety allowance at the preparation boundary.

use std::cmp::Ordering;
use std::mem;

use thiserror::Error;

use crate::string::StringContext;
use crate::value::compressed::CompressedValueKind;
use crate::value::{Value, ValueTag};

use super::packed_collection_lane::{
    PackedAttrBinding, PackedCollectionLaneCapacities, PackedCollectionLaneDirectBuilder,
    PackedCollectionLaneError,
};
use super::packed_frame_lane::{
    PackedFrameLaneCapacities, PackedFrameLaneDirectBuilder, PackedFrameLaneError,
};
use super::packed_generation::{
    PackedGeneration, PackedGenerationAdmissionInput, PackedGenerationDomain, PackedGenerationError,
};
use super::packed_scalar_lane::{
    PackedScalarLaneCapacities, PackedScalarLaneDirectBuilder, PackedScalarLaneError,
};
use super::packed_string_lane::{
    PackedStringContextRef, PackedStringLaneCapacities, PackedStringLaneDirectBuilder,
    PackedStringLaneError,
};
use super::packed_thunk_lane::{
    PackedThunkLane, PackedThunkLaneCapacities, PackedThunkLaneError, PackedValueWord,
};
use super::packed_translation::{
    PackedTranslationDirectory, PackedTranslationDirectoryBuilder, PackedTranslationError,
    PackedTranslationSegmentCapacity,
};
use super::{
    DirectRootRewrite, DirectRootRewriteError, DirectRootRewritePlan, EvalHeap, EvalHeapError,
    HeapEdgeSource, PreciseHeapScan,
};

/// Caller-observed admission state for one non-mutating rotation preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedRotationAdmissionInput {
    /// Current resident bytes before any destination allocation.
    pub(crate) current_rss_bytes: usize,
    /// Additional caller-owned scratch live during preparation.
    pub(crate) additional_scratch_bytes: usize,
    /// Explicit unmodeled and allocator safety allowance.
    pub(crate) safety_bytes: usize,
    /// Caller-selected resident-memory ceiling.
    pub(crate) rss_ceiling_bytes: usize,
}

impl Default for PackedRotationAdmissionInput {
    fn default() -> Self {
        Self {
            current_rss_bytes: 0,
            additional_scratch_bytes: 0,
            safety_bytes: 0,
            rss_ceiling_bytes: usize::MAX,
        }
    }
}

/// One source value selected for packed movement and its direct destination.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackedRotationSource {
    value: Value,
    destination_index: u32,
    scan_index: u32,
}

const _: () = assert!(mem::size_of::<PackedRotationSource>() == 16);

impl PackedRotationSource {
    /// Returns the exact source value word.
    pub(crate) const fn value(&self) -> Value {
        self.value
    }

    /// Returns the tag-local direct destination coordinate.
    pub(crate) const fn destination_index(&self) -> u32 {
        self.destination_index
    }

    /// Returns the authoritative precise-scan object coordinate.
    pub(crate) const fn scan_index(&self) -> u32 {
        self.scan_index
    }
}

/// A fully built but unpublished mixed packed-generation transaction.
#[derive(Debug)]
pub(crate) struct PreparedPackedPermanentRotation {
    generation: PackedGeneration,
    translation: PackedTranslationDirectory,
    root_rewrites: DirectRootRewritePlan,
    moved_sources: Vec<PackedRotationSource>,
    retained_flat_sources: Vec<Value>,
}

impl PreparedPackedPermanentRotation {
    /// Prepares one mixed packed rotation without mutating `heap`.
    ///
    /// The precise scan is authoritative. Every scanned string, path, list,
    /// attrset, boxed integer, and boxed float receives a direct coordinate in
    /// the new generation. Lambda, primop, thunk, and external words remain
    /// flat; embedded edges to them are preserved byte-for-byte.
    ///
    /// `admission` must contain an actual process RSS observation. Internal
    /// source inventories and builder scratch are measured and added to the
    /// caller's scratch charge. The finalized forwarding directory is charged
    /// separately through [`PackedGenerationAdmissionInput::try_with_translation`].
    ///
    /// # Errors
    ///
    /// Returns [`PackedRotationPrepareError`] if the scan contains an
    /// unsupported, duplicate, foreign, stale, or malformed value; exact
    /// inventory/capacity arithmetic overflows; a reservation fails; an
    /// embedded selected edge lacks a forwarding mapping; lane construction
    /// changes an admitted capacity; or strict RSS admission fails.
    pub(crate) fn try_prepare(
        heap: &EvalHeap,
        scan: &PreciseHeapScan,
        admission: PackedRotationAdmissionInput,
    ) -> Result<Self, PackedRotationPrepareError> {
        let (mut moved_sources, retained_flat_sources) = inventories(scan)?;
        assign_destination_indices(&mut moved_sources)?;

        let domain = PackedGenerationDomain::try_allocate()?;
        let capacities = translation_capacities(&moved_sources)?;
        let mut translation = PackedTranslationDirectoryBuilder::try_new(domain.id(), &capacities)?;
        drop(capacities);
        for source in &moved_sources {
            translation.append(source.value.word(), source.destination_index)?;
        }
        let translation = translation.finish()?;
        let mut root_rewrites =
            try_vec_with_capacity::<DirectRootRewrite>(scan.roots().len(), "root-rewrites")?;
        for root in scan.roots() {
            let replacement = translation.translate_selected_or_preserve(root.value().word())?;
            root_rewrites.push(DirectRootRewrite::new(
                root.source().clone(),
                root.value(),
                Value::from_word(replacement.compressed()),
            ));
        }
        let root_rewrite_capacity_bytes =
            checked_capacity_bytes::<DirectRootRewrite>(root_rewrites.capacity())?;
        let root_rewrites = DirectRootRewritePlan::try_new(root_rewrites)?;

        let lane_capacities = measure_lanes(heap, scan, &moved_sources)?;
        let mut contexts = collect_contexts(heap, &moved_sources)?;
        contexts.sort_by(compare_contexts);
        if contexts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PackedRotationPrepareError::DuplicateContextInventory);
        }

        let mut strings = PackedStringLaneDirectBuilder::try_new(lane_capacities.strings)?;
        for context in &contexts {
            strings.append_context(context)?;
        }

        let mut collections =
            PackedCollectionLaneDirectBuilder::try_new(lane_capacities.collections)?;
        let mut scalars = PackedScalarLaneDirectBuilder::try_new(lane_capacities.scalars)?;
        let mut list_scratch = try_vec_with_capacity::<PackedValueWord>(
            lane_capacities.max_list_values,
            "list-edge-scratch",
        )?;
        let mut attrs_scratch = try_vec_with_capacity::<PackedAttrBinding>(
            lane_capacities.max_attr_entries,
            "attrs-binding-scratch",
        )?;

        for source in &moved_sources {
            let object = scanned_object(scan, source)?;
            match source.value.tag() {
                ValueTag::String => {
                    let string = heap.get_string(source.value)?;
                    let context = context_reference(&contexts, string.context())?;
                    let reference = strings.append_string(string, context)?;
                    require_coordinate(source, reference.index(), "string")?;
                }
                ValueTag::Path => {
                    let path = heap.get_path(source.value)?;
                    let context = context_reference(&contexts, path.context())?;
                    let reference = strings.append_path(path, context)?;
                    require_coordinate(source, reference.index(), "path")?;
                }
                ValueTag::List => {
                    let list = heap.get_list(source.value)?;
                    validate_list_edges(list, object.edges(), source.value.word().raw())?;
                    list_scratch.clear();
                    for edge in object.edges() {
                        list_scratch
                            .push(translation.translate_selected_or_preserve(edge.value().word())?);
                    }
                    let reference = collections.append_list(&list_scratch)?;
                    require_coordinate(source, reference.index(), "list")?;
                }
                ValueTag::Attrs => {
                    let attrs = heap.get_attrs(source.value)?;
                    let metadata = heap.get_attrs_metadata(source.value)?;
                    if attrs.len() != object.edges().len() {
                        return Err(PackedRotationPrepareError::MalformedScannedEdges {
                            raw: source.value.word().raw(),
                        });
                    }
                    attrs_scratch.clear();
                    for (slot, (entry, edge)) in attrs
                        .entries_by_symbol()
                        .iter()
                        .zip(object.edges())
                        .enumerate()
                    {
                        let HeapEdgeSource::AttrBinding {
                            shape,
                            slot: edge_slot,
                            key,
                        } = edge.source()
                        else {
                            return Err(PackedRotationPrepareError::MalformedScannedEdges {
                                raw: source.value.word().raw(),
                            });
                        };
                        if *shape != metadata.shape()
                            || *edge_slot != slot
                            || *key != entry.key
                            || !edge.value().raw_eq(entry.value)
                        {
                            return Err(PackedRotationPrepareError::MalformedScannedEdges {
                                raw: source.value.word().raw(),
                            });
                        }
                        let value =
                            translation.translate_selected_or_preserve(entry.value.word())?;
                        attrs_scratch.push(match entry.position {
                            Some(position) => PackedAttrBinding::with_position(
                                entry.key,
                                value,
                                position.module,
                                position.span,
                            ),
                            None => PackedAttrBinding::new(entry.key, value),
                        });
                    }
                    let reference = collections.append_attrs(
                        metadata,
                        &attrs_scratch,
                        attrs.source_order(),
                        attrs.iteration_order(),
                    )?;
                    require_coordinate(source, reference.index(), "attrs")?;
                }
                ValueTag::Int => {
                    let reference = scalars.append_integer(heap.decode_int_value(source.value)?)?;
                    require_coordinate(source, reference.index(), "integer")?;
                }
                ValueTag::Float => {
                    let reference = scalars
                        .append_float_bits(heap.decode_float_value(source.value)?.to_bits())?;
                    require_coordinate(source, reference.index(), "float")?;
                }
                tag => return Err(PackedRotationPrepareError::UnsupportedMovedTag { tag }),
            }
        }

        let internal_scratch_bytes = internal_scratch_bytes(
            &moved_sources,
            &retained_flat_sources,
            &contexts,
            &list_scratch,
            &attrs_scratch,
            root_rewrite_capacity_bytes,
        )?;
        let additional_scratch_bytes = admission
            .additional_scratch_bytes
            .checked_add(internal_scratch_bytes)
            .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)?;
        let generation_admission = PackedGenerationAdmissionInput::try_with_translation(
            admission.current_rss_bytes,
            translation.bytes()?,
            additional_scratch_bytes,
            admission.safety_bytes,
            admission.rss_ceiling_bytes,
        )?;

        drop(list_scratch);
        drop(attrs_scratch);
        drop(contexts);

        let thunks = PackedThunkLane::try_with_capacities(PackedThunkLaneCapacities::default())?;
        let frames = PackedFrameLaneDirectBuilder::try_new(PackedFrameLaneCapacities::default())?
            .finish()?;
        let generation = PackedGeneration::try_admit_in_domain(
            domain,
            thunks,
            frames,
            collections.finish()?,
            strings.finish()?,
            scalars.finish()?,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            generation_admission,
        )?;

        Ok(Self {
            generation,
            translation,
            root_rewrites,
            moved_sources,
            retained_flat_sources,
        })
    }

    /// Returns the unpublished packed generation.
    pub(crate) const fn generation(&self) -> &PackedGeneration {
        &self.generation
    }

    /// Returns the exact disposable source-to-destination directory.
    pub(crate) const fn translation(&self) -> &PackedTranslationDirectory {
        &self.translation
    }

    /// Returns the exact raw-value rewrite plan for every scanned mutator root.
    pub(crate) const fn root_rewrites(&self) -> &DirectRootRewritePlan {
        &self.root_rewrites
    }

    /// Returns the sorted unique source inventory selected for movement.
    pub(crate) fn moved_sources(&self) -> &[PackedRotationSource] {
        &self.moved_sources
    }

    /// Returns sorted unique flat closure sources retained by this rotation.
    pub(crate) fn retained_flat_sources(&self) -> &[Value] {
        &self.retained_flat_sources
    }

    /// Consumes the preparation into transaction-owned parts.
    pub(crate) fn into_parts(
        self,
    ) -> (
        PackedGeneration,
        PackedTranslationDirectory,
        DirectRootRewritePlan,
        Vec<PackedRotationSource>,
        Vec<Value>,
    ) {
        (
            self.generation,
            self.translation,
            self.root_rewrites,
            self.moved_sources,
            self.retained_flat_sources,
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RotationLaneCapacities {
    strings: PackedStringLaneCapacities,
    collections: PackedCollectionLaneCapacities,
    scalars: PackedScalarLaneCapacities,
    max_list_values: usize,
    max_attr_entries: usize,
}

fn inventories(
    scan: &PreciseHeapScan,
) -> Result<(Vec<PackedRotationSource>, Vec<Value>), PackedRotationPrepareError> {
    let moved_count = scan
        .objects()
        .iter()
        .filter(|object| {
            matches!(
                object.tag(),
                ValueTag::String
                    | ValueTag::Path
                    | ValueTag::List
                    | ValueTag::Attrs
                    | ValueTag::Int
                    | ValueTag::Float
            )
        })
        .count();
    let retained_count = scan
        .objects()
        .len()
        .checked_sub(moved_count)
        .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)?;
    let mut moved = try_vec_with_capacity(moved_count, "moved-source-inventory")?;
    let mut retained = try_vec_with_capacity(retained_count, "retained-source-inventory")?;
    for (scan_index, object) in scan.objects().iter().enumerate() {
        let value = object.value();
        validate_indexed_word(value)?;
        let scan_index = u32::try_from(scan_index)
            .map_err(|_| PackedRotationPrepareError::ScanIndexOverflow { index: scan_index })?;
        match value.tag() {
            ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Int
            | ValueTag::Float => moved.push(PackedRotationSource {
                value,
                destination_index: 0,
                scan_index,
            }),
            ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk | ValueTag::External => {
                retained.push(value);
            }
            tag => return Err(PackedRotationPrepareError::UnsupportedScannedTag { tag }),
        }
    }
    moved.sort_by_key(|source| source_key(source.value));
    retained.sort_by_key(|value| source_key(*value));
    if moved
        .windows(2)
        .any(|pair| source_key(pair[0].value) == source_key(pair[1].value))
        || retained
            .windows(2)
            .any(|pair| source_key(pair[0]) == source_key(pair[1]))
    {
        return Err(PackedRotationPrepareError::DuplicateSourceInventory);
    }
    Ok((moved, retained))
}

fn assign_destination_indices(
    sources: &mut [PackedRotationSource],
) -> Result<(), PackedRotationPrepareError> {
    let mut counts = [0usize; 6];
    for source in sources {
        let lane = lane_number(source.value)?;
        source.destination_index = u32::try_from(counts[lane]).map_err(|_| {
            PackedRotationPrepareError::DestinationIndexOverflow {
                tag: source.value.tag(),
                index: counts[lane],
            }
        })?;
        counts[lane] = counts[lane]
            .checked_add(1)
            .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)?;
    }
    Ok(())
}

fn translation_capacities(
    sources: &[PackedRotationSource],
) -> Result<Vec<PackedTranslationSegmentCapacity>, PackedRotationPrepareError> {
    let mut capacities = try_vec_with_capacity::<PackedTranslationSegmentCapacity>(
        sources.len(),
        "translation-capacities",
    )?;
    for source in sources {
        let domain = source.value.word().arena_domain().ok_or(
            PackedRotationPrepareError::MissingSourceCoordinate {
                raw: source.value.word().raw(),
            },
        )?;
        let kind = source.value.word().kind();
        match capacities.last_mut() {
            Some(previous) if previous.source_domain == domain && previous.source_kind == kind => {
                previous.entries = previous
                    .entries
                    .checked_add(1)
                    .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)?;
            }
            _ => capacities.push(PackedTranslationSegmentCapacity {
                source_domain: domain,
                source_kind: kind,
                entries: 1,
            }),
        }
    }
    Ok(capacities)
}

fn measure_lanes(
    heap: &EvalHeap,
    scan: &PreciseHeapScan,
    sources: &[PackedRotationSource],
) -> Result<RotationLaneCapacities, PackedRotationPrepareError> {
    let mut result = RotationLaneCapacities::default();
    for source in sources {
        let object = scanned_object(scan, source)?;
        match source.value.tag() {
            ValueTag::String | ValueTag::Path => {
                let string = if source.value.tag() == ValueTag::String {
                    heap.get_string(source.value)?
                } else {
                    heap.get_path(source.value)?
                };
                if source.value.tag() == ValueTag::String {
                    checked_increment(&mut result.strings.strings)?;
                } else {
                    checked_increment(&mut result.strings.paths)?;
                }
                result.strings.bytes = checked_add(result.strings.bytes, string.bytes().len())?;
            }
            ValueTag::List => {
                checked_increment(&mut result.collections.lists)?;
                result.collections.list_values =
                    checked_add(result.collections.list_values, object.edges().len())?;
                result.max_list_values = result.max_list_values.max(object.edges().len());
            }
            ValueTag::Attrs => {
                let attrs = heap.get_attrs(source.value)?;
                checked_increment(&mut result.collections.attrs)?;
                result.collections.attr_entries =
                    checked_add(result.collections.attr_entries, attrs.len())?;
                result.collections.positions = checked_add(
                    result.collections.positions,
                    attrs
                        .entries_by_symbol()
                        .iter()
                        .filter(|entry| entry.position.is_some())
                        .count(),
                )?;
                result.collections.source_order =
                    checked_add(result.collections.source_order, attrs.len())?;
                result.collections.iteration_order =
                    checked_add(result.collections.iteration_order, attrs.len())?;
                result.max_attr_entries = result.max_attr_entries.max(attrs.len());
            }
            ValueTag::Int => checked_increment(&mut result.scalars.integers)?,
            ValueTag::Float => checked_increment(&mut result.scalars.floats)?,
            tag => return Err(PackedRotationPrepareError::UnsupportedMovedTag { tag }),
        }
    }
    let contexts = collect_contexts(heap, sources)?;
    result.strings.contexts = contexts.len();
    for context in &contexts {
        result.strings.context_elements =
            checked_add(result.strings.context_elements, context.len())?;
        for element in context {
            result.strings.bytes = checked_add(result.strings.bytes, element.path().len())?;
            result.strings.bytes = checked_add(
                result.strings.bytes,
                element.output().map_or(0, <[u8]>::len),
            )?;
        }
    }
    Ok(result)
}

fn scanned_object<'a>(
    scan: &'a PreciseHeapScan,
    source: &PackedRotationSource,
) -> Result<&'a super::HeapObjectScan, PackedRotationPrepareError> {
    let object = scan.objects().get(source.scan_index as usize).ok_or(
        PackedRotationPrepareError::MissingScannedObject {
            raw: source.value.word().raw(),
        },
    )?;
    if !object.value().raw_eq(source.value) {
        return Err(PackedRotationPrepareError::ScannedObjectIdentityMismatch {
            index: source.scan_index,
            expected: source.value.word().raw(),
            actual: object.value().word().raw(),
        });
    }
    Ok(object)
}

fn validate_list_edges(
    list: &crate::list::NixList,
    edges: &[super::HeapEdge],
    raw: u64,
) -> Result<(), PackedRotationPrepareError> {
    if list.len() != edges.len() {
        return Err(PackedRotationPrepareError::MalformedScannedEdges { raw });
    }
    for (index, (element, edge)) in list.iter().zip(edges).enumerate() {
        if !matches!(
            edge.source(),
            HeapEdgeSource::ListElement { index: edge_index } if *edge_index == index
        ) || !edge.value().raw_eq(*element)
        {
            return Err(PackedRotationPrepareError::MalformedScannedEdges { raw });
        }
    }
    Ok(())
}

fn collect_contexts(
    heap: &EvalHeap,
    sources: &[PackedRotationSource],
) -> Result<Vec<StringContext>, PackedRotationPrepareError> {
    let string_count = sources
        .iter()
        .filter(|source| matches!(source.value.tag(), ValueTag::String | ValueTag::Path))
        .count();
    let mut contexts = try_vec_with_capacity(string_count, "string-context-inventory")?;
    for source in sources {
        let context = match source.value.tag() {
            ValueTag::String => heap.get_string(source.value)?.context(),
            ValueTag::Path => heap.get_path(source.value)?.context(),
            _ => continue,
        };
        contexts.push(context.clone());
    }
    contexts.sort_by(compare_contexts);
    contexts.dedup();
    Ok(contexts)
}

fn compare_contexts(left: &StringContext, right: &StringContext) -> Ordering {
    left.elements().cmp(right.elements())
}

fn context_reference(
    contexts: &[StringContext],
    context: &StringContext,
) -> Result<PackedStringContextRef, PackedRotationPrepareError> {
    let index = contexts
        .binary_search_by(|candidate| compare_contexts(candidate, context))
        .map_err(|_| PackedRotationPrepareError::MissingStringContext)?;
    let index =
        u32::try_from(index).map_err(|_| PackedRotationPrepareError::DestinationIndexOverflow {
            tag: ValueTag::String,
            index,
        })?;
    Ok(PackedStringContextRef::from_index(index))
}

fn source_key(value: Value) -> (u32, u32, u32) {
    (
        value
            .word()
            .arena_domain()
            .map_or(u32::MAX, |domain| domain.raw()),
        value.word().kind() as u32,
        value
            .word()
            .arena_index()
            .map_or(u32::MAX, |index| index.raw()),
    )
}

fn validate_indexed_word(value: Value) -> Result<(), PackedRotationPrepareError> {
    let word = value.word();
    if word.arena_domain().is_none() || word.arena_index().is_none() {
        return Err(PackedRotationPrepareError::MissingSourceCoordinate { raw: word.raw() });
    }
    let expected = match value.tag() {
        ValueTag::Int => CompressedValueKind::BoxedInt,
        ValueTag::Float => CompressedValueKind::BoxedFloat,
        ValueTag::String => CompressedValueKind::String,
        ValueTag::Path => CompressedValueKind::Path,
        ValueTag::List => CompressedValueKind::List,
        ValueTag::Attrs => CompressedValueKind::Attrs,
        ValueTag::Lambda => CompressedValueKind::Lambda,
        ValueTag::Primop => CompressedValueKind::Primop,
        ValueTag::External => CompressedValueKind::External,
        ValueTag::Thunk => CompressedValueKind::Thunk,
        tag => return Err(PackedRotationPrepareError::UnsupportedScannedTag { tag }),
    };
    if word.kind() != expected {
        return Err(PackedRotationPrepareError::SourceKindMismatch {
            tag: value.tag(),
            kind: word.kind(),
        });
    }
    Ok(())
}

fn lane_number(value: Value) -> Result<usize, PackedRotationPrepareError> {
    match value.tag() {
        ValueTag::String => Ok(0),
        ValueTag::Path => Ok(1),
        ValueTag::List => Ok(2),
        ValueTag::Attrs => Ok(3),
        ValueTag::Int => Ok(4),
        ValueTag::Float => Ok(5),
        tag => Err(PackedRotationPrepareError::UnsupportedMovedTag { tag }),
    }
}

fn require_coordinate(
    source: &PackedRotationSource,
    actual: u32,
    lane: &'static str,
) -> Result<(), PackedRotationPrepareError> {
    if source.destination_index != actual {
        return Err(PackedRotationPrepareError::DestinationOrderMismatch {
            lane,
            expected: source.destination_index,
            actual,
        });
    }
    Ok(())
}

fn internal_scratch_bytes(
    moved: &Vec<PackedRotationSource>,
    retained: &Vec<Value>,
    contexts: &Vec<StringContext>,
    list_scratch: &Vec<PackedValueWord>,
    attrs_scratch: &Vec<PackedAttrBinding>,
    root_rewrite_capacity_bytes: usize,
) -> Result<usize, PackedRotationPrepareError> {
    [
        checked_capacity_bytes::<PackedRotationSource>(moved.capacity())?,
        checked_capacity_bytes::<Value>(retained.capacity())?,
        checked_capacity_bytes::<StringContext>(contexts.capacity())?,
        checked_capacity_bytes::<PackedValueWord>(list_scratch.capacity())?,
        checked_capacity_bytes::<PackedAttrBinding>(attrs_scratch.capacity())?,
        root_rewrite_capacity_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| checked_add(total, bytes))
}

fn checked_capacity_bytes<T>(capacity: usize) -> Result<usize, PackedRotationPrepareError> {
    capacity
        .checked_mul(mem::size_of::<T>())
        .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)
}

fn checked_add(left: usize, right: usize) -> Result<usize, PackedRotationPrepareError> {
    left.checked_add(right)
        .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)
}

fn checked_increment(value: &mut usize) -> Result<(), PackedRotationPrepareError> {
    *value = value
        .checked_add(1)
        .ok_or(PackedRotationPrepareError::ByteAccountingOverflow)?;
    Ok(())
}

fn try_vec_with_capacity<T>(
    capacity: usize,
    lane: &'static str,
) -> Result<Vec<T>, PackedRotationPrepareError> {
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_| {
        PackedRotationPrepareError::AllocationFailed {
            lane,
            entries: capacity,
        }
    })?;
    Ok(values)
}

/// Non-mutating packed-rotation preparation failed.
#[derive(Debug, Error)]
pub(crate) enum PackedRotationPrepareError {
    /// A source or scratch byte calculation exceeded `usize`.
    #[error("packed rotation byte accounting overflow")]
    ByteAccountingOverflow,
    /// A temporary exact-capacity inventory could not reserve storage.
    #[error("packed rotation {lane} could not reserve {entries} entries")]
    AllocationFailed {
        /// Inventory or scratch lane that failed.
        lane: &'static str,
        /// Requested exact entry count.
        entries: usize,
    },
    /// A scanned value did not carry an indexed source coordinate.
    #[error("packed rotation source word {raw:#018x} has no indexed coordinate")]
    MissingSourceCoordinate {
        /// Complete malformed source word.
        raw: u64,
    },
    /// A scanned semantic tag disagreed with its Candidate-C representation.
    #[error("packed rotation source tag {tag:?} disagrees with kind {kind:?}")]
    SourceKindMismatch {
        /// Semantic runtime tag.
        tag: ValueTag,
        /// Candidate-C representation kind.
        kind: CompressedValueKind,
    },
    /// The precise scan contained a tag outside the closed rotation policy.
    #[error("packed rotation precise scan contains unsupported tag {tag:?}")]
    UnsupportedScannedTag {
        /// Unsupported scanned tag.
        tag: ValueTag,
    },
    /// A supposedly moved inventory entry had a retained tag.
    #[error("packed rotation moved inventory contains unsupported tag {tag:?}")]
    UnsupportedMovedTag {
        /// Unsupported moved tag.
        tag: ValueTag,
    },
    /// A precise scan contained the same source coordinate more than once.
    #[error("packed rotation source inventory is not unique")]
    DuplicateSourceInventory,
    /// A context inventory unexpectedly retained duplicate canonical contexts.
    #[error("packed rotation string-context inventory is not unique")]
    DuplicateContextInventory,
    /// A source string referred to no admitted canonical context.
    #[error("packed rotation source string context is missing from its inventory")]
    MissingStringContext,
    /// An admitted tag-local coordinate exceeded `u32`.
    #[error("packed rotation {tag:?} destination index {index} exceeds u32")]
    DestinationIndexOverflow {
        /// Destination semantic tag.
        tag: ValueTag,
        /// Rejected destination coordinate.
        index: usize,
    },
    /// The authoritative precise scan exceeded its compact inventory coordinate.
    #[error("packed rotation precise-scan object index {index} exceeds u32")]
    ScanIndexOverflow {
        /// Rejected scan object coordinate.
        index: usize,
    },
    /// The source inventory and lane append order disagreed.
    #[error("packed rotation {lane} destination order mismatch: expected {expected}, got {actual}")]
    DestinationOrderMismatch {
        /// Destination lane.
        lane: &'static str,
        /// Preassigned coordinate.
        expected: u32,
        /// Builder-returned coordinate.
        actual: u32,
    },
    /// A selected source disappeared from the authoritative scan.
    #[error("packed rotation source {raw:#018x} is absent from the precise scan")]
    MissingScannedObject {
        /// Complete missing source word.
        raw: u64,
    },
    /// A compact scan coordinate no longer names its inventoried source.
    #[error(
        "packed rotation scan object {index} identity mismatch: expected {expected:#018x}, \
         got {actual:#018x}"
    )]
    ScannedObjectIdentityMismatch {
        /// Authoritative scan coordinate.
        index: u32,
        /// Inventoried source word.
        expected: u64,
        /// Word currently stored at the coordinate.
        actual: u64,
    },
    /// Object edge labels or payloads disagreed with the precise scan.
    #[error("packed rotation scanned edges for source {raw:#018x} are malformed or stale")]
    MalformedScannedEdges {
        /// Complete source word.
        raw: u64,
    },
    /// Reading or validating a source heap value failed.
    #[error("packed rotation source heap read failed: {0}")]
    Heap(#[from] EvalHeapError),
    /// Translation construction or selected-edge rewriting failed.
    #[error("packed rotation translation failed: {0}")]
    Translation(#[from] PackedTranslationError),
    /// Packed string/path construction failed.
    #[error("packed rotation string/path construction failed: {0}")]
    String(#[from] PackedStringLaneError),
    /// Packed collection construction failed.
    #[error("packed rotation collection construction failed: {0}")]
    Collection(#[from] PackedCollectionLaneError),
    /// Packed scalar construction failed.
    #[error("packed rotation scalar construction failed: {0}")]
    Scalar(#[from] PackedScalarLaneError),
    /// Empty packed frame construction failed.
    #[error("packed rotation frame construction failed: {0}")]
    Frame(#[from] PackedFrameLaneError),
    /// Empty packed thunk construction failed.
    #[error("packed rotation thunk construction failed: {0}")]
    Thunk(#[from] PackedThunkLaneError),
    /// Packed generation domain construction or admission failed.
    #[error("packed rotation generation admission failed: {0}")]
    Generation(#[from] PackedGenerationError),
    /// Raw root rewrite planning found duplicate or conflicting root sources.
    #[error("packed rotation root rewrite planning failed: {0}")]
    DirectRoot(#[from] DirectRootRewriteError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::{AttrEntry, FlatAttrs};
    use crate::heap::ArenaIndex;
    use crate::list::NixList;
    use crate::string::NixString;
    use crate::syntax::SymbolTable;
    use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

    use super::super::EvalRootSet;

    #[test]
    fn preparation_builds_mixed_generation_without_mutating_sources() {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"key").unwrap();
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"value".to_vec()))
            .unwrap();
        let path = heap
            .alloc_path(NixString::from_bytes(b"/nix/store/path".to_vec()))
            .unwrap();
        let integer = heap.alloc_int_value(i64::MAX).unwrap();
        let float_bits = 0x7ff8_0000_0000_1234;
        let float = heap.alloc_float_value(f64::from_bits(float_bits)).unwrap();
        let attrs = heap
            .alloc_attrs(
                17,
                FlatAttrs::new(vec![AttrEntry::new(key, string)], &symbols).unwrap(),
            )
            .unwrap();
        let root = heap
            .alloc_list(NixList::new(vec![attrs, path, integer, float]))
            .unwrap();
        let unreachable = heap
            .alloc_string(NixString::from_bytes(b"unreachable".to_vec()))
            .unwrap();
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, root).unwrap();
        let scan = heap.scan_precise_roots(&roots).unwrap();

        let prepared = PreparedPackedPermanentRotation::try_prepare(
            &heap,
            &scan,
            PackedRotationAdmissionInput::default(),
        )
        .unwrap();

        assert_eq!(prepared.moved_sources().len(), 6);
        assert!(prepared.retained_flat_sources().is_empty());
        assert!(
            prepared
                .moved_sources()
                .iter()
                .all(|source| !source.value().raw_eq(unreachable))
        );

        let packed_root = Value::from_word(
            prepared
                .translation()
                .translate(root.word())
                .unwrap()
                .compressed(),
        );
        let root_reference = prepared.generation().list_reference(packed_root).unwrap();
        let packed_elements = prepared
            .generation()
            .collections()
            .list(root_reference)
            .unwrap();
        assert_eq!(packed_elements.len(), 4);
        assert_eq!(
            packed_elements[2].compressed().kind(),
            CompressedValueKind::BoxedInt
        );
        assert_eq!(
            packed_elements[3].compressed().kind(),
            CompressedValueKind::BoxedFloat
        );
        assert_eq!(
            prepared
                .generation()
                .integer(Value::from_word(packed_elements[2].compressed()))
                .unwrap()
                .unwrap(),
            i64::MAX
        );
        assert_eq!(
            prepared
                .generation()
                .float(Value::from_word(packed_elements[3].compressed()))
                .unwrap()
                .unwrap()
                .to_bits(),
            float_bits
        );

        assert_eq!(heap.get_string(string).unwrap().bytes(), b"value");
        assert_eq!(heap.get_path(path).unwrap().bytes(), b"/nix/store/path");
        assert_eq!(heap.decode_int_value(integer), Ok(i64::MAX));
        assert_eq!(
            heap.decode_float_value(float).map(f64::to_bits),
            Ok(float_bits)
        );
    }

    #[test]
    fn strict_admission_refusal_leaves_source_heap_live() {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"still-live".to_vec()))
            .unwrap();
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, string).unwrap();
        let scan = heap.scan_precise_roots(&roots).unwrap();

        let error = PreparedPackedPermanentRotation::try_prepare(
            &heap,
            &scan,
            PackedRotationAdmissionInput {
                current_rss_bytes: 16 * 1024 * 1024,
                additional_scratch_bytes: 0,
                safety_bytes: 0,
                rss_ceiling_bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PackedRotationPrepareError::Generation(PackedGenerationError::RssCeilingReached { .. })
        ));
        assert_eq!(heap.get_string(string).unwrap().bytes(), b"still-live");
        assert!(heap.packed_generation().is_none());
    }

    #[test]
    fn selected_translation_segment_rejects_a_missing_coordinate() {
        let source_domain = crate::heap::ArenaDomainId::allocate_logical().unwrap();
        let destination = PackedGenerationDomain::try_allocate().unwrap();
        let source =
            CompressedValueWord::heap(source_domain, ValueTag::List, ArenaIndex::new(3)).unwrap();
        let missing =
            CompressedValueWord::heap(source_domain, ValueTag::List, ArenaIndex::new(4)).unwrap();
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination.id(),
            &[PackedTranslationSegmentCapacity {
                source_domain,
                source_kind: CompressedValueKind::List,
                entries: 1,
            }],
        )
        .unwrap();
        builder.append(source, 0).unwrap();
        let translation = builder.finish().unwrap();

        assert!(matches!(
            translation.translate_selected_or_preserve(missing),
            Err(PackedTranslationError::UnknownSourceCoordinate {
                domain,
                index: 4
            }) if domain == source_domain.raw()
        ));
    }

    #[test]
    fn malformed_precise_list_edge_is_rejected() {
        let list = NixList::new(vec![Value::int(1)]);
        let edges = vec![super::super::HeapEdge::new(
            HeapEdgeSource::ListElement { index: 1 },
            Value::int(1),
        )];

        assert!(matches!(
            validate_list_edges(&list, &edges, 7),
            Err(PackedRotationPrepareError::MalformedScannedEdges { raw: 7 })
        ));
    }
}
