//! Unpublished whole-permanent Candidate-C batch copying.
//!
//! A batch accepts the caller's precise reachable flat string, path, list, and
//! attrset set in source-index order. It semantically copies those objects into
//! one aggregate destination generation while retaining source words in copied
//! edge fields. Only after the complete compact forwarding directory exists
//! does it validate permanent-edge closure, rewrite destination list/attrset
//! edges, and repair their relocation-sensitive structural hashes.
//!
//! No phase mutates or retires source objects. Failure drops the locally owned
//! destination generation and all completed copies before anything can be
//! installed in an [`EvalHeap`].

use thiserror::Error;

use crate::attrs::AttrsStorageKind;
use crate::eval::heap::evacuation_forwarding::{
    EvacuationForwardingDirectory, EvacuationForwardingDirectoryBuilder,
    EvacuationForwardingDirectoryError,
};
use crate::string::StringBytesStorageKind;

use super::*;

/// Owns one complete but unpublished permanent-generation batch.
#[derive(Debug)]
pub(in crate::eval::heap) struct UnpublishedPermanentBatch {
    generation: EvacuatedGeneration,
    forwarding: EvacuationForwardingDirectory,
}

impl UnpublishedPermanentBatch {
    /// Semantically copies an exact reachable permanent set from `source`.
    ///
    /// `candidates` must be strictly increasing by source Candidate-C index,
    /// contain no duplicates, and contain every source-domain permanent value
    /// reached by a copied list or attrset. Unreachable registry objects must
    /// not be included. The returned generation is not installed in either
    /// heap; source objects, registries, roots, and hash-cons tables remain
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`PermanentBatchCopyError`] when either heap lacks a
    /// Candidate-C domain, an evacuated generation/resolver/directory is
    /// already installed, the candidate set is unsorted, duplicated, foreign,
    /// incomplete, or names the wrong tag/store, destination allocation fails,
    /// a source object has inconsistent storage metadata, forwarding
    /// construction fails, or destination edge/hash repair fails.
    pub(in crate::eval::heap) fn copy_values_from(
        source: &EvalHeap,
        candidates: &[Value],
    ) -> Result<Self, PermanentBatchCopyError> {
        let generation = EvacuatedGeneration::new()
            .ok_or(PermanentBatchCopyError::DestinationDomainUnavailable)?;
        Self::copy_values_into(source, candidates, generation)
    }

    /// Returns the unpublished aggregate generation.
    pub(in crate::eval::heap) const fn generation(&self) -> &EvacuatedGeneration {
        &self.generation
    }

    /// Returns the complete compact forwarding directory.
    pub(in crate::eval::heap) const fn forwarding(&self) -> &EvacuationForwardingDirectory {
        &self.forwarding
    }

    /// Translates one source permanent value into its copied destination.
    pub(in crate::eval::heap) fn translate(&self, source: Value) -> Option<Value> {
        self.forwarding.translate(source, source.tag())
    }

    /// Consumes the owner into its still-unpublished generation and directory.
    pub(in crate::eval::heap) fn into_parts(
        self,
    ) -> (EvacuatedGeneration, EvacuationForwardingDirectory) {
        (self.generation, self.forwarding)
    }

    fn copy_values_into(
        source: &EvalHeap,
        candidates: &[Value],
        mut generation: EvacuatedGeneration,
    ) -> Result<Self, PermanentBatchCopyError> {
        if source.evacuated_generation.is_some()
            || source.evacuated_serial_reservation.is_some()
            || source.evacuated_closure_forwarding.is_some()
        {
            return Err(PermanentBatchCopyError::ExistingEvacuatedGeneration);
        }
        let source_domain = source
            .flat_arena
            .arena_domain_id()
            .ok_or(PermanentBatchCopyError::SourceDomainUnavailable)?;
        let destination_domain = generation
            .domain()
            .ok_or(PermanentBatchCopyError::DestinationDomainUnavailable)?;
        let expected = candidates.len();
        let mut pending = Vec::new();
        pending.try_reserve_exact(expected).map_err(|_| {
            PermanentBatchCopyError::InventoryAllocationFailed { entries: expected }
        })?;
        let mut previous: Option<crate::heap::ArenaIndex> = None;
        for candidate in candidates {
            let source_index = validate_candidate(source, source_domain, *candidate)?;
            if let Some(previous_index) = previous
                && source_index.raw() <= previous_index.raw()
            {
                return Err(PermanentBatchCopyError::CandidatesNotStrictlyIncreasing {
                    previous: previous_index,
                    rejected: source_index,
                });
            }
            pending.push(PendingPermanentCopy {
                source: *candidate,
                source_index,
                destination: None,
            });
            previous = Some(source_index);
        }

        let mut forwarding = EvacuationForwardingDirectoryBuilder::try_new(
            source_domain,
            destination_domain,
            expected,
        )?;
        for entry in &mut pending {
            let destination = copy_one(source, generation.permanent_mut(), entry.source)?;
            let destination_index = destination
                .word()
                .arena_index()
                .ok_or(PermanentBatchCopyError::DestinationValueMissingIndex)?;
            forwarding.push(entry.source_index, destination_index)?;
            entry.destination = Some(destination);
        }
        let forwarding = forwarding.finish()?;

        validate_complete_permanent_edges(source, source_domain, &pending, &forwarding)?;
        for entry in &pending {
            let destination = entry
                .destination
                .ok_or(PermanentBatchCopyError::IncompleteDestinationMapping)?;
            match destination.tag() {
                ValueTag::List => generation
                    .permanent_mut()
                    .rewrite_list_edges_and_repair_hash(destination, |edge| {
                        match forwarding.translate(edge, edge.tag()) {
                            Some(forwarded) => forwarded,
                            None => edge,
                        }
                    })?,
                ValueTag::Attrs => generation
                    .permanent_mut()
                    .rewrite_attrs_edges_and_repair_hash(destination, |edge| {
                        match forwarding.translate(edge, edge.tag()) {
                            Some(forwarded) => forwarded,
                            None => edge,
                        }
                    })?,
                ValueTag::String | ValueTag::Path => {}
                _ => {
                    return Err(PermanentBatchCopyError::UnsupportedPermanentTag {
                        tag: destination.tag(),
                    });
                }
            }
        }

        Ok(Self {
            generation,
            forwarding,
        })
    }

    #[cfg(test)]
    fn copy_all_from(source: &EvalHeap) -> Result<Self, PermanentBatchCopyError> {
        let expected = source
            .flat
            .live_len()
            .checked_add(source.flat_lists.live_len())
            .and_then(|count| count.checked_add(source.flat_attrs.live_len()))
            .ok_or(PermanentBatchCopyError::PopulationOverflow)?;
        let mut candidates = Vec::new();
        candidates.try_reserve_exact(expected).map_err(|_| {
            PermanentBatchCopyError::InventoryAllocationFailed { entries: expected }
        })?;
        inventory_store(source, &source.flat, &mut candidates)?;
        inventory_store(source, &source.flat_lists, &mut candidates)?;
        inventory_store(source, &source.flat_attrs, &mut candidates)?;
        candidates.sort_unstable_by_key(|value| {
            value
                .word()
                .arena_index()
                .map(crate::heap::ArenaIndex::raw)
                .unwrap_or(u32::MAX)
        });
        Self::copy_values_from(source, &candidates)
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingPermanentCopy {
    source: Value,
    source_index: crate::heap::ArenaIndex,
    destination: Option<Value>,
}

#[cfg(test)]
fn inventory_store<T>(
    source: &EvalHeap,
    store: &FlatObjectStore<T>,
    candidates: &mut Vec<Value>,
) -> Result<(), PermanentBatchCopyError> {
    for stored in store.iter() {
        let tag = match stored.object().kind() {
            FlatObjectKind::String => ValueTag::String,
            FlatObjectKind::Path => ValueTag::Path,
            FlatObjectKind::List => ValueTag::List,
            FlatObjectKind::Attrs => ValueTag::Attrs,
            kind => return Err(PermanentBatchCopyError::UnsupportedFlatKind { kind }),
        };
        let source_value = source.value_for_flat_allocation(tag, stored.ptr())?;
        candidates.push(source_value);
    }
    Ok(())
}

fn validate_candidate(
    source: &EvalHeap,
    source_domain: crate::heap::ArenaDomainId,
    candidate: Value,
) -> Result<crate::heap::ArenaIndex, PermanentBatchCopyError> {
    if !matches!(
        candidate.tag(),
        ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
    ) {
        return Err(PermanentBatchCopyError::UnsupportedPermanentTag {
            tag: candidate.tag(),
        });
    }
    if candidate.word().arena_domain() != Some(source_domain) {
        return Err(PermanentBatchCopyError::ForeignCandidateDomain {
            actual: candidate.word().arena_domain(),
        });
    }
    let source_index = candidate
        .word()
        .arena_index()
        .ok_or(PermanentBatchCopyError::SourceValueMissingIndex)?;
    match candidate.tag() {
        ValueTag::String => {
            source.get_string(candidate)?;
        }
        ValueTag::Path => {
            source.get_path(candidate)?;
        }
        ValueTag::List => {
            source.get_list(candidate)?;
        }
        ValueTag::Attrs => {
            source.get_attrs(candidate)?;
        }
        tag => return Err(PermanentBatchCopyError::UnsupportedPermanentTag { tag }),
    }
    Ok(source_index)
}

fn validate_complete_permanent_edges(
    source: &EvalHeap,
    source_domain: crate::heap::ArenaDomainId,
    pending: &[PendingPermanentCopy],
    forwarding: &EvacuationForwardingDirectory,
) -> Result<(), PermanentBatchCopyError> {
    for entry in pending {
        match entry.source.tag() {
            ValueTag::List => {
                for edge in source.get_list(entry.source)? {
                    validate_permanent_edge(source_domain, *edge, forwarding)?;
                }
            }
            ValueTag::Attrs => {
                for edge in source.get_attrs(entry.source)?.entries_by_symbol() {
                    validate_permanent_edge(source_domain, edge.value, forwarding)?;
                }
            }
            ValueTag::String | ValueTag::Path => {}
            tag => return Err(PermanentBatchCopyError::UnsupportedPermanentTag { tag }),
        }
    }
    Ok(())
}

fn validate_permanent_edge(
    source_domain: crate::heap::ArenaDomainId,
    edge: Value,
    forwarding: &EvacuationForwardingDirectory,
) -> Result<(), PermanentBatchCopyError> {
    if matches!(
        edge.tag(),
        ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
    ) && edge.word().arena_domain() == Some(source_domain)
        && forwarding.translate(edge, edge.tag()).is_none()
    {
        return Err(PermanentBatchCopyError::IncompleteReachableSet {
            missing: edge
                .word()
                .arena_index()
                .ok_or(PermanentBatchCopyError::SourceValueMissingIndex)?,
            tag: edge.tag(),
        });
    }
    Ok(())
}

fn copy_one(
    source: &EvalHeap,
    destination: &mut EvacuatedPermanentGeneration,
    value: Value,
) -> Result<Value, PermanentBatchCopyError> {
    match value.tag() {
        ValueTag::String => {
            let payload = source.get_string(value)?;
            match payload.bytes_storage_kind() {
                StringBytesStorageKind::Owned => {
                    destination.copy_owned_string_from(&source.flat, value)
                }
                StringBytesStorageKind::FlatWitness => {
                    destination.copy_inline_string_from(&source.flat, value)
                }
            }
        }
        ValueTag::Path => {
            let payload = source.get_path(value)?;
            match payload.bytes_storage_kind() {
                StringBytesStorageKind::Owned => {
                    destination.copy_owned_path_from(&source.flat, value)
                }
                StringBytesStorageKind::FlatWitness => {
                    destination.copy_inline_path_from(&source.flat, value)
                }
            }
        }
        ValueTag::List => destination.copy_list_from(&source.flat_lists, value),
        ValueTag::Attrs => {
            let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
            let payload = source
                .flat_attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .map_err(|_| PermanentBatchCopyError::SourceAttrsResolutionFailed {
                    address: ptr.as_ptr() as usize,
                })?
                .payload();
            match payload.attrs.storage_kind() {
                AttrsStorageKind::Owned => {
                    destination.copy_owned_attrs_from(&source.flat_attrs, value)
                }
                AttrsStorageKind::FlatWitness => {
                    destination.copy_inline_attrs_from(&source.flat_attrs, value)
                }
            }
        }
        tag => return Err(PermanentBatchCopyError::UnsupportedPermanentTag { tag }),
    }
    .map_err(PermanentBatchCopyError::Heap)
}

/// A whole-permanent unpublished batch copy failed.
#[derive(Debug, Error)]
pub(in crate::eval::heap) enum PermanentBatchCopyError {
    /// The source heap has no encodable Candidate-C reservation.
    #[error("permanent batch source has no Candidate-C domain")]
    SourceDomainUnavailable,
    /// A destination reservation could not be created or encoded.
    #[error("permanent batch destination has no Candidate-C domain")]
    DestinationDomainUnavailable,
    /// This first-collection-only copier cannot replace an installed generation.
    #[error("permanent batch source already has evacuated generation state installed")]
    ExistingEvacuatedGeneration,
    /// The full-store test inventory population overflowed `usize`.
    #[cfg(test)]
    #[error("permanent batch population overflowed")]
    PopulationOverflow,
    /// Exact inventory storage could not be reserved.
    #[error("failed to reserve permanent batch inventory for {entries} entries")]
    InventoryAllocationFailed {
        /// The exact planned inventory population.
        entries: usize,
    },
    /// A source value did not carry a Candidate-C arena index.
    #[error("permanent batch source value has no Candidate-C index")]
    SourceValueMissingIndex,
    /// One candidate belongs to another Candidate-C reservation.
    #[error("permanent batch candidate belongs to foreign domain {actual:?}")]
    ForeignCandidateDomain {
        /// The candidate domain, or `None` for a non-reservation word.
        actual: Option<crate::heap::ArenaDomainId>,
    },
    /// Candidate indices must be unique and strictly increasing.
    #[error("permanent batch candidate index {rejected:?} does not follow previous {previous:?}")]
    CandidatesNotStrictlyIncreasing {
        /// The previously accepted source index.
        previous: crate::heap::ArenaIndex,
        /// The duplicate or decreasing source index.
        rejected: crate::heap::ArenaIndex,
    },
    /// A copied edge reaches a source permanent omitted by the candidate set.
    #[error("permanent batch omitted reachable {tag:?} at source index {missing:?}")]
    IncompleteReachableSet {
        /// The omitted permanent object's source index.
        missing: crate::heap::ArenaIndex,
        /// The omitted permanent object's semantic tag.
        tag: ValueTag,
    },
    /// A destination value did not carry a Candidate-C arena index.
    #[error("permanent batch destination value has no Candidate-C index")]
    DestinationValueMissingIndex,
    /// A completed copy lacked its temporary destination mapping.
    #[error("permanent batch destination mapping is incomplete")]
    IncompleteDestinationMapping,
    /// A permanent store contained a non-permanent kind.
    #[error("permanent batch encountered unsupported flat kind {kind:?}")]
    UnsupportedFlatKind {
        /// The unexpected flat object kind.
        kind: FlatObjectKind,
    },
    /// A copied value carried a non-permanent semantic tag.
    #[error("permanent batch encountered unsupported value tag {tag:?}")]
    UnsupportedPermanentTag {
        /// The unexpected semantic tag.
        tag: ValueTag,
    },
    /// A source attrset unexpectedly failed direct store resolution.
    #[error("permanent batch could not resolve source attrset at 0x{address:x}")]
    SourceAttrsResolutionFailed {
        /// The unresolved source address.
        address: usize,
    },
    /// A heap/store copy or destination repair failed.
    #[error("permanent batch heap operation failed: {0}")]
    Heap(#[from] EvalHeapError),
    /// Compact forwarding construction failed.
    #[error("permanent batch forwarding failed: {0}")]
    Forwarding(#[from] EvacuationForwardingDirectoryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::attrs::repr::AttrSetReprKind;
    use crate::syntax::SymbolTable;

    fn repair_source_list_hash(heap: &mut EvalHeap, value: Value) {
        let ptr = value.as_list_ptr().expect("test value is a list");
        let hash = {
            let object = heap
                .flat_lists
                .resolve(ptr, FlatObjectKind::List)
                .expect("source list resolves");
            crate::eval::heap::arena::list_structural_hash(object.payload())
        };
        heap.flat_lists
            .update_structural_hash(ptr, FlatObjectKind::List, hash.raw())
            .expect("source list hash repairs");
    }

    fn repair_source_attrs_hash(heap: &mut EvalHeap, value: Value) {
        let ptr = value.as_attrs_ptr().expect("test value is attrs");
        let hash = {
            let object = heap
                .flat_attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .expect("source attrs resolves");
            crate::eval::heap::arena::attrs_structural_hash(
                object.payload().metadata,
                &object.payload().attrs,
            )
        };
        heap.flat_attrs
            .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
            .expect("source attrs hash repairs");
    }

    #[test]
    fn mixed_batch_rewrites_forward_cycle_edges_and_keeps_source_live() {
        let mut symbols = SymbolTable::new();
        let forward_key = symbols.intern(b"forward").expect("forward key interns");
        let owned_key = symbols.intern(b"owned").expect("owned key interns");
        let mut source = EvalHeap::new();
        let inline_string = source
            .alloc_string(NixString::from_bytes(b"inline".to_vec()))
            .expect("inline string allocates");
        let owned_path = source
            .alloc_path(NixString::from_bytes(vec![b'p'; FLAT_INLINE_BYTES_MAX + 1]))
            .expect("owned path allocates");
        let first_list = source
            .alloc_list(NixList::new(vec![Value::null()]))
            .expect("first list allocates");
        let inline_attrs = source
            .alloc_attrs(
                17,
                FlatAttrs::new(vec![AttrEntry::new(forward_key, Value::null())], &symbols)
                    .expect("inline attrs build"),
            )
            .expect("inline attrs allocate");
        let second_list = source
            .alloc_list(NixList::new(vec![first_list, inline_string]))
            .expect("second list allocates");
        let owned_attrs_payload =
            FlatAttrs::new(vec![AttrEntry::new(owned_key, inline_string)], &symbols)
                .expect("owned attrs build");
        let owned_metadata = EvalHeapAttrsMetadata::new(23, AttrSetReprKind::Flat);
        let owned_attrs_allocation = source
            .flat_attrs
            .alloc_with_aux(
                FlatObjectKind::Attrs,
                flat_aux_for_len(owned_attrs_payload.len()),
                crate::eval::heap::arena::attrs_structural_hash(
                    owned_metadata,
                    &owned_attrs_payload,
                )
                .raw(),
                101,
                FlatAttrsPayload {
                    metadata: owned_metadata,
                    attrs: owned_attrs_payload,
                },
            )
            .expect("owned attrs allocate directly");
        let owned_attrs = source
            .value_for_flat_allocation(ValueTag::Attrs, owned_attrs_allocation.ptr)
            .expect("owned attrs value encodes");

        source
            .flat_lists
            .resolve_mut(
                first_list.as_list_ptr().expect("first list has a pointer"),
                FlatObjectKind::List,
            )
            .expect("first list resolves mutably")
            .rewrite_elements(&mut |_| second_list);
        repair_source_list_hash(&mut source, first_list);
        source
            .flat_attrs
            .resolve_mut(
                inline_attrs
                    .as_attrs_ptr()
                    .expect("inline attrs has a pointer"),
                FlatObjectKind::Attrs,
            )
            .expect("inline attrs resolves mutably")
            .attrs
            .rewrite_entry_values(&mut |_| Some(second_list));
        repair_source_attrs_hash(&mut source, inline_attrs);

        let batch = UnpublishedPermanentBatch::copy_all_from(&source)
            .expect("whole permanent batch copies");
        let copied_inline_string = batch.translate(inline_string).expect("string forwards");
        let copied_owned_path = batch.translate(owned_path).expect("path forwards");
        let copied_first_list = batch.translate(first_list).expect("first list forwards");
        let copied_second_list = batch.translate(second_list).expect("second list forwards");
        let copied_inline_attrs = batch
            .translate(inline_attrs)
            .expect("inline attrs forwards");
        let copied_owned_attrs = batch.translate(owned_attrs).expect("owned attrs forwards");
        let destination_domain = batch
            .generation()
            .domain()
            .expect("destination has one domain");

        assert_eq!(batch.forwarding().len(), 6);
        for copied in [
            copied_inline_string,
            copied_owned_path,
            copied_first_list,
            copied_second_list,
            copied_inline_attrs,
            copied_owned_attrs,
        ] {
            assert_eq!(copied.word().arena_domain(), Some(destination_domain));
        }
        let permanent = batch.generation().permanent();
        assert!(
            permanent
                .get_list(copied_first_list)
                .expect("copied first list resolves")
                .get(0)
                .expect("first cycle edge exists")
                .raw_eq(copied_second_list)
        );
        let copied_second = permanent
            .get_list(copied_second_list)
            .expect("copied second list resolves");
        assert!(
            copied_second
                .get(0)
                .expect("second cycle edge exists")
                .raw_eq(copied_first_list)
        );
        assert!(
            copied_second
                .get(1)
                .expect("second string edge exists")
                .raw_eq(copied_inline_string)
        );
        assert!(
            permanent
                .get_attrs(copied_inline_attrs)
                .expect("copied inline attrs resolves")
                .get(forward_key)
                .expect("forward attr edge exists")
                .raw_eq(copied_second_list)
        );
        assert!(
            permanent
                .get_attrs(copied_owned_attrs)
                .expect("copied owned attrs resolves")
                .get(owned_key)
                .expect("owned attr edge exists")
                .raw_eq(copied_inline_string)
        );
        assert_eq!(
            permanent
                .get_attrs_metadata(copied_owned_attrs)
                .expect("owned attrs metadata resolves"),
            owned_metadata
        );
        assert_eq!(
            permanent
                .get_path(copied_owned_path)
                .expect("copied owned path resolves")
                .bytes(),
            vec![b'p'; FLAT_INLINE_BYTES_MAX + 1]
        );

        assert!(
            source
                .get_list(first_list)
                .expect("source first list remains live")
                .get(0)
                .expect("source cycle edge remains")
                .raw_eq(second_list)
        );
        assert!(
            source
                .get_attrs(inline_attrs)
                .expect("source inline attrs remains live")
                .get(forward_key)
                .expect("source forward edge remains")
                .raw_eq(second_list)
        );
        assert_eq!(
            source
                .get_path(owned_path)
                .expect("source path remains live")
                .len(),
            FLAT_INLINE_BYTES_MAX + 1
        );
        assert_eq!(
            source
                .get_attrs_metadata(owned_attrs)
                .expect("source owned attrs remains live"),
            owned_metadata
        );
    }

    #[test]
    fn same_domain_rejection_happens_before_copy_and_leaves_source_live() {
        let mut source = EvalHeap::new();
        let source_string = source
            .alloc_string(NixString::from_bytes(b"source".to_vec()))
            .expect("source string allocates");
        let arena = source.flat_arena.clone();
        let destination = EvacuatedGeneration {
            closures: EvacuatedClosureGeneration::with_shared_arena(arena.clone()),
            permanent: EvacuatedPermanentGeneration::with_shared_arena(arena.clone()),
            arena,
        };

        let error =
            UnpublishedPermanentBatch::copy_values_into(&source, &[source_string], destination)
                .expect_err("same domain is rejected");
        assert!(matches!(
            error,
            PermanentBatchCopyError::Forwarding(
                EvacuationForwardingDirectoryError::SameDomain { .. }
            )
        ));
        assert_eq!(
            source
                .get_string(source_string)
                .expect("source remains live after rejection")
                .bytes(),
            b"source"
        );
        assert_eq!(source.flat.live_len(), 1);
    }

    #[test]
    fn installed_evacuated_generation_is_rejected_as_first_collection_only() {
        let mut source = EvalHeap::new();
        let source_string = source
            .alloc_string(NixString::from_bytes(b"source".to_vec()))
            .expect("source string allocates");
        let Some(installed) = EvacuatedGeneration::new() else {
            return;
        };
        source.evacuated_generation = Some(installed);

        let error = UnpublishedPermanentBatch::copy_values_from(&source, &[source_string])
            .expect_err("installed generation is rejected");

        assert!(matches!(
            error,
            PermanentBatchCopyError::ExistingEvacuatedGeneration
        ));
        assert_eq!(
            source
                .get_string(source_string)
                .expect("source remains live after rejection")
                .bytes(),
            b"source"
        );
    }

    #[test]
    fn caller_selected_set_excludes_unreachable_registry_objects() {
        let mut source = EvalHeap::new();
        let reachable = source
            .alloc_string(NixString::from_bytes(b"reachable".to_vec()))
            .expect("reachable string allocates");
        let unreachable = source
            .alloc_path(NixString::from_bytes(b"/unreachable".to_vec()))
            .expect("unreachable path allocates");

        let batch = UnpublishedPermanentBatch::copy_values_from(&source, &[reachable])
            .expect("selected reachable set copies");

        assert_eq!(batch.forwarding().len(), 1);
        assert!(batch.translate(reachable).is_some());
        assert!(batch.translate(unreachable).is_none());
        assert_eq!(
            source
                .get_path(unreachable)
                .expect("excluded source object remains live")
                .bytes(),
            b"/unreachable"
        );
    }

    #[test]
    fn candidate_validation_rejects_duplicates_foreign_non_permanent_and_missing_edges() {
        let mut source = EvalHeap::new();
        let first = source
            .alloc_string(NixString::from_bytes(b"first".to_vec()))
            .expect("first string allocates");
        let second = source
            .alloc_string(NixString::from_bytes(b"second".to_vec()))
            .expect("second string allocates");
        let mut sorted = [first, second];
        sorted.sort_unstable_by_key(|value| {
            value
                .word()
                .arena_index()
                .expect("source string has an index")
                .raw()
        });

        let duplicate =
            UnpublishedPermanentBatch::copy_values_from(&source, &[sorted[0], sorted[0]])
                .expect_err("duplicate candidate is rejected");
        assert!(matches!(
            duplicate,
            PermanentBatchCopyError::CandidatesNotStrictlyIncreasing { .. }
        ));
        let decreasing =
            UnpublishedPermanentBatch::copy_values_from(&source, &[sorted[1], sorted[0]])
                .expect_err("decreasing candidates are rejected");
        assert!(matches!(
            decreasing,
            PermanentBatchCopyError::CandidatesNotStrictlyIncreasing { .. }
        ));
        let non_permanent = UnpublishedPermanentBatch::copy_values_from(&source, &[Value::int(7)])
            .expect_err("non-permanent candidate is rejected");
        assert!(matches!(
            non_permanent,
            PermanentBatchCopyError::UnsupportedPermanentTag { tag: ValueTag::Int }
        ));

        let mut foreign = EvalHeap::new();
        let foreign_string = foreign
            .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
            .expect("foreign string allocates");
        let foreign_error = UnpublishedPermanentBatch::copy_values_from(&source, &[foreign_string])
            .expect_err("foreign candidate is rejected");
        assert!(matches!(
            foreign_error,
            PermanentBatchCopyError::ForeignCandidateDomain { .. }
        ));

        let list = source
            .alloc_list(NixList::new(vec![first]))
            .expect("list with permanent edge allocates");
        let incomplete = UnpublishedPermanentBatch::copy_values_from(&source, &[list])
            .expect_err("omitted reachable permanent edge is rejected");
        assert!(matches!(
            incomplete,
            PermanentBatchCopyError::IncompleteReachableSet {
                tag: ValueTag::String,
                ..
            }
        ));
        assert!(
            source
                .get_list(list)
                .expect("source list remains live after failed batch")
                .get(0)
                .expect("source edge remains")
                .raw_eq(first)
        );
    }
}
