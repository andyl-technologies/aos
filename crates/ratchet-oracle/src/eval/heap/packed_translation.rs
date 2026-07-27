//! Disposable source-domain translation for packed generation construction.
//!
//! A moving build must rewrite every Candidate-C edge before retiring its
//! source domains, but retaining a forwarding table would erase the packed
//! generation's memory margin. This directory groups exact eight-byte
//! `(source_index, destination_index)` entries by source domain and
//! representation kind. Builders reserve every segment once, require strictly
//! increasing source indices, and cannot grow after admission. Finalized
//! lookup is a segment scan over the small active-generation population
//! followed by binary search.
//!
//! Destination indices are tag-local direct lane coordinates. The source word
//! supplies the semantic tag, so lists, attrsets, strings, paths, thunks,
//! lambdas, primops, externals, and boxed scalar lanes may reuse the same
//! numeric coordinate without ambiguity. Inline values pass through unchanged.

use std::mem;

use thiserror::Error;

use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::ValueTag;
use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

use super::packed_thunk_lane::PackedValueWord;

/// One exact source-to-destination coordinate mapping.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedTranslationEntry {
    source_index: u32,
    destination_index: u32,
}

const _: () = assert!(mem::size_of::<PackedTranslationEntry>() == 8);

/// Exact admission for one source domain and kind's mapping population.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedTranslationSegmentCapacity {
    /// Source domain whose indexed words will be rewritten.
    pub(crate) source_domain: ArenaDomainId,
    /// Representation kind whose tag-local indices will be rewritten.
    pub(crate) source_kind: CompressedValueKind,
    /// Exact maximum mappings admitted for this source domain and kind.
    pub(crate) entries: usize,
}

#[derive(Debug)]
struct PackedTranslationSegment {
    source_domain: ArenaDomainId,
    source_kind: CompressedValueKind,
    entries: Vec<PackedTranslationEntry>,
    admitted_entries: usize,
    admitted_capacity: usize,
}

/// Initialized and allocator-capacity byte accounting for a translation build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedTranslationBytes {
    /// Inline directory control plus initialized segment descriptors.
    pub(crate) control_initialized: usize,
    /// Inline directory control plus allocated segment-descriptor capacity.
    pub(crate) control_capacity: usize,
    /// Initialized eight-byte mapping entries.
    pub(crate) entries_initialized: usize,
    /// Allocator-granted mapping-entry capacity.
    pub(crate) entries_capacity: usize,
    /// Checked initialized total.
    pub(crate) initialized_total: usize,
    /// Checked allocator-capacity total used for admission.
    pub(crate) capacity_total: usize,
}

/// A finalized, disposable multi-domain forwarding directory.
#[derive(Debug)]
pub(crate) struct PackedTranslationDirectory {
    destination_domain: ArenaDomainId,
    segments: Vec<PackedTranslationSegment>,
    // Keeps finalized and builder control accounting identical. The builder's
    // cursor is transient, but omitting its word here would undercharge the
    // admitted construction footprint by one machine word.
    _control_word: usize,
}

impl PackedTranslationDirectory {
    /// Returns whether this directory selected the word's source lane.
    ///
    /// This predicate deliberately tests the admitted source domain and
    /// representation kind rather than requiring an exact forwarding entry.
    /// A post-publication audit must reject stale selected coordinates too:
    /// retiring their source lane would otherwise leave a dangling word.
    pub(crate) fn selects_source_word(&self, word: CompressedValueWord) -> bool {
        let Some(source_domain) = word.arena_domain() else {
            return false;
        };
        self.segments.iter().any(|segment| {
            segment.source_domain == source_domain && segment.source_kind == word.kind()
        })
    }

    /// Translates one Candidate-C word to the packed destination domain.
    ///
    /// Inline integers, booleans, and null pass through unchanged. Indexed
    /// words require an exact source mapping. Heap tags, boxed-scalar kinds,
    /// and the forced-thunk shortcut are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError`] when the source domain/index has no
    /// mapping or the Candidate-C codec unexpectedly rejects a reconstructed
    /// destination word.
    pub(crate) fn translate(
        &self,
        word: CompressedValueWord,
    ) -> Result<PackedValueWord, PackedTranslationError> {
        let Some(source_domain) = word.arena_domain() else {
            return Ok(PackedValueWord::new(word));
        };
        let source_index = word
            .arena_index()
            .ok_or(PackedTranslationError::IndexedWordMissingCoordinate)?
            .raw();
        let source_kind = word.kind();
        let segment = self
            .segments
            .iter()
            .find(|segment| {
                segment.source_domain == source_domain && segment.source_kind == source_kind
            })
            .ok_or(PackedTranslationError::UnknownSourceSegment {
                domain: source_domain.raw(),
                kind: source_kind,
            })?;
        let slot = segment
            .entries
            .binary_search_by_key(&source_index, |entry| entry.source_index)
            .map_err(|_| PackedTranslationError::UnknownSourceCoordinate {
                domain: source_domain.raw(),
                index: source_index,
            })?;
        let destination_index = ArenaIndex::new(segment.entries[slot].destination_index);
        let destination = match word.kind() {
            CompressedValueKind::BoxedInt => {
                CompressedValueWord::boxed_int(self.destination_domain, destination_index)
            }
            CompressedValueKind::BoxedFloat => {
                CompressedValueWord::boxed_float(self.destination_domain, destination_index)
            }
            _ => {
                let destination = CompressedValueWord::heap(
                    self.destination_domain,
                    word.semantic_tag(),
                    destination_index,
                )
                .map_err(|_| PackedTranslationError::DestinationEncoding {
                    tag: word.semantic_tag(),
                    index: destination_index.raw(),
                })?;
                if word.is_forced_thunk() {
                    destination.with_forced_bit().map_err(|_| {
                        PackedTranslationError::DestinationEncoding {
                            tag: word.semantic_tag(),
                            index: destination_index.raw(),
                        }
                    })?
                } else {
                    destination
                }
            }
        };
        Ok(PackedValueWord::new(destination))
    }

    /// Translates a word selected by this directory and preserves other words.
    ///
    /// The admitted `(source domain, representation kind)` segments are the
    /// explicit movement policy. Indexed words whose pair has no segment stay
    /// in their original flat domain. Once a pair is admitted, however, every
    /// translated edge must have an exact coordinate mapping; a missing
    /// coordinate still fails closed. This supports a mixed first rotation
    /// that packs immutable values and scalars while retaining flat closures.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError`] when a selected indexed word has no
    /// coordinate mapping or the Candidate-C codec rejects its destination.
    pub(crate) fn translate_selected_or_preserve(
        &self,
        word: CompressedValueWord,
    ) -> Result<PackedValueWord, PackedTranslationError> {
        if !self.selects_source_word(word) {
            return Ok(PackedValueWord::new(word));
        }
        self.translate(word)
    }

    /// Translates a weak-index entry only when it has an exact mapping.
    ///
    /// Unlike [`Self::translate_selected_or_preserve`], this never preserves
    /// an indexed source word. Inline words, unselected source segments, and
    /// selected coordinates absent from the directory all return `None`.
    /// Weak hash-cons indexes use this policy so neither unreachable selected
    /// values nor retained flat values keep stale source handles alive.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError`] only when an exact mapping exists
    /// but the Candidate-C codec rejects its reconstructed destination word.
    pub(crate) fn translate_weak_mapped(
        &self,
        word: CompressedValueWord,
    ) -> Result<Option<PackedValueWord>, PackedTranslationError> {
        let Some(source_domain) = word.arena_domain() else {
            return Ok(None);
        };
        let source_index = word
            .arena_index()
            .ok_or(PackedTranslationError::IndexedWordMissingCoordinate)?
            .raw();
        let source_kind = word.kind();
        let Some(segment) = self.segments.iter().find(|segment| {
            segment.source_domain == source_domain && segment.source_kind == source_kind
        }) else {
            return Ok(None);
        };
        let Ok(slot) = segment
            .entries
            .binary_search_by_key(&source_index, |entry| entry.source_index)
        else {
            return Ok(None);
        };
        let destination_index = ArenaIndex::new(segment.entries[slot].destination_index);
        let destination = match word.kind() {
            CompressedValueKind::BoxedInt => {
                CompressedValueWord::boxed_int(self.destination_domain, destination_index)
            }
            CompressedValueKind::BoxedFloat => {
                CompressedValueWord::boxed_float(self.destination_domain, destination_index)
            }
            _ => {
                let destination = CompressedValueWord::heap(
                    self.destination_domain,
                    word.semantic_tag(),
                    destination_index,
                )
                .map_err(|_| PackedTranslationError::DestinationEncoding {
                    tag: word.semantic_tag(),
                    index: destination_index.raw(),
                })?;
                if word.is_forced_thunk() {
                    destination.with_forced_bit().map_err(|_| {
                        PackedTranslationError::DestinationEncoding {
                            tag: word.semantic_tag(),
                            index: destination_index.raw(),
                        }
                    })?
                } else {
                    destination
                }
            }
        };
        Ok(Some(PackedValueWord::new(destination)))
    }

    /// Returns exact initialized and allocated-capacity scratch bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError::ByteAccountingOverflow`] when any
    /// multiplication or sum exceeds `usize`.
    pub(crate) fn bytes(&self) -> Result<PackedTranslationBytes, PackedTranslationError> {
        translation_bytes(&self.segments)
    }

    /// Returns the destination logical domain.
    pub(crate) const fn destination_domain(&self) -> ArenaDomainId {
        self.destination_domain
    }
}

/// Exact-capacity builder for a disposable translation directory.
#[derive(Debug)]
pub(crate) struct PackedTranslationDirectoryBuilder {
    destination_domain: ArenaDomainId,
    segments: Vec<PackedTranslationSegment>,
    next_segment: usize,
}

impl PackedTranslationDirectoryBuilder {
    /// Reserves all source-domain segments and mapping entries.
    ///
    /// Capacities must name strictly increasing, unique `(domain, kind)` keys.
    /// Exact allocator-granted capacities are captured immediately and checked
    /// after every append.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError`] for duplicate/out-of-order domains,
    /// allocation failure, or byte-accounting overflow.
    pub(crate) fn try_new(
        destination_domain: ArenaDomainId,
        capacities: &[PackedTranslationSegmentCapacity],
    ) -> Result<Self, PackedTranslationError> {
        if capacities.windows(2).any(|pair| {
            segment_key(pair[0].source_domain, pair[0].source_kind)
                >= segment_key(pair[1].source_domain, pair[1].source_kind)
        }) {
            return Err(PackedTranslationError::SourceSegmentsNotStrictlySorted);
        }
        let mut segments = Vec::new();
        segments.try_reserve_exact(capacities.len()).map_err(|_| {
            PackedTranslationError::AllocationFailed {
                lane: "translation-segments",
                entries: capacities.len(),
            }
        })?;
        for capacity in capacities {
            let mut entries = Vec::new();
            entries.try_reserve_exact(capacity.entries).map_err(|_| {
                PackedTranslationError::AllocationFailed {
                    lane: "translation-entries",
                    entries: capacity.entries,
                }
            })?;
            let admitted_capacity = entries.capacity();
            segments.push(PackedTranslationSegment {
                source_domain: capacity.source_domain,
                source_kind: capacity.source_kind,
                entries,
                admitted_entries: capacity.entries,
                admitted_capacity,
            });
        }
        let builder = Self {
            destination_domain,
            segments,
            next_segment: 0,
        };
        builder.bytes()?;
        Ok(builder)
    }

    /// Appends one mapped indexed source word.
    ///
    /// Segments must be filled in admitted domain order, and indices within a
    /// segment must be strictly increasing. Capacity exhaustion is rejected
    /// before mutation.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError`] for an inline source, unknown or
    /// out-of-order source domain, duplicate/out-of-order index, exhausted
    /// admission, or allocator-capacity drift.
    pub(crate) fn append(
        &mut self,
        source: CompressedValueWord,
        destination_index: u32,
    ) -> Result<(), PackedTranslationError> {
        let source_domain = source
            .arena_domain()
            .ok_or(PackedTranslationError::InlineSource)?;
        let source_index = source
            .arena_index()
            .ok_or(PackedTranslationError::IndexedWordMissingCoordinate)?
            .raw();
        let source_kind = source.kind();
        while self.segments.get(self.next_segment).is_some_and(|segment| {
            segment_key(segment.source_domain, segment.source_kind)
                < segment_key(source_domain, source_kind)
                && segment.entries.len() == segment.admitted_entries
        }) {
            self.next_segment += 1;
        }
        let segment = self.segments.get_mut(self.next_segment).ok_or(
            PackedTranslationError::UnknownSourceSegment {
                domain: source_domain.raw(),
                kind: source_kind,
            },
        )?;
        if segment.source_domain != source_domain || segment.source_kind != source_kind {
            return Err(PackedTranslationError::SourceSegmentOutOfOrder {
                expected: segment.source_domain.raw(),
                expected_kind: segment.source_kind,
                actual: source_domain.raw(),
                actual_kind: source_kind,
            });
        }
        if segment.entries.len() == segment.admitted_entries {
            return Err(PackedTranslationError::CapacityExceeded {
                domain: source_domain.raw(),
                admitted: segment.admitted_entries,
                attempted: segment.entries.len().saturating_add(1),
            });
        }
        if let Some(previous) = segment.entries.last()
            && previous.source_index >= source_index
        {
            return Err(PackedTranslationError::SourceIndexNotStrictlyIncreasing {
                domain: source_domain.raw(),
                previous: previous.source_index,
                next: source_index,
            });
        }
        if segment.entries.capacity() != segment.admitted_capacity {
            return Err(PackedTranslationError::CapacityChanged {
                domain: source_domain.raw(),
                admitted: segment.admitted_capacity,
                actual: segment.entries.capacity(),
            });
        }
        segment.entries.push(PackedTranslationEntry {
            source_index,
            destination_index,
        });
        if segment.entries.capacity() != segment.admitted_capacity {
            return Err(PackedTranslationError::CapacityChanged {
                domain: source_domain.raw(),
                admitted: segment.admitted_capacity,
                actual: segment.entries.capacity(),
            });
        }
        Ok(())
    }

    /// Returns exact current scratch accounting.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError::ByteAccountingOverflow`] when any
    /// multiplication or sum exceeds `usize`.
    pub(crate) fn bytes(&self) -> Result<PackedTranslationBytes, PackedTranslationError> {
        translation_bytes(&self.segments)
    }

    /// Finalizes only when every admitted entry was initialized.
    ///
    /// # Errors
    ///
    /// Returns [`PackedTranslationError::UnderfilledSegment`] for the first
    /// segment whose initialized length differs from its exact admission.
    pub(crate) fn finish(self) -> Result<PackedTranslationDirectory, PackedTranslationError> {
        for segment in &self.segments {
            if segment.entries.len() != segment.admitted_entries {
                return Err(PackedTranslationError::UnderfilledSegment {
                    domain: segment.source_domain.raw(),
                    kind: segment.source_kind,
                    admitted: segment.admitted_entries,
                    initialized: segment.entries.len(),
                });
            }
            if segment.entries.capacity() != segment.admitted_capacity {
                return Err(PackedTranslationError::CapacityChanged {
                    domain: segment.source_domain.raw(),
                    admitted: segment.admitted_capacity,
                    actual: segment.entries.capacity(),
                });
            }
        }
        Ok(PackedTranslationDirectory {
            destination_domain: self.destination_domain,
            segments: self.segments,
            _control_word: 0,
        })
    }
}

fn segment_key(domain: ArenaDomainId, kind: CompressedValueKind) -> (u32, u32) {
    (domain.raw(), kind as u32)
}

fn translation_bytes(
    segments: &Vec<PackedTranslationSegment>,
) -> Result<PackedTranslationBytes, PackedTranslationError> {
    let control_initialized = mem::size_of::<PackedTranslationDirectory>()
        .checked_add(
            segments
                .len()
                .checked_mul(mem::size_of::<PackedTranslationSegment>())
                .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
        )
        .ok_or(PackedTranslationError::ByteAccountingOverflow)?;
    let control_capacity = mem::size_of::<PackedTranslationDirectory>()
        .checked_add(
            segments
                .capacity()
                .checked_mul(mem::size_of::<PackedTranslationSegment>())
                .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
        )
        .ok_or(PackedTranslationError::ByteAccountingOverflow)?;
    let entries_initialized = segments.iter().try_fold(0usize, |total, segment| {
        total
            .checked_add(
                segment
                    .entries
                    .len()
                    .checked_mul(mem::size_of::<PackedTranslationEntry>())
                    .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
            )
            .ok_or(PackedTranslationError::ByteAccountingOverflow)
    })?;
    let entries_capacity = segments.iter().try_fold(0usize, |total, segment| {
        total
            .checked_add(
                segment
                    .entries
                    .capacity()
                    .checked_mul(mem::size_of::<PackedTranslationEntry>())
                    .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
            )
            .ok_or(PackedTranslationError::ByteAccountingOverflow)
    })?;
    Ok(PackedTranslationBytes {
        control_initialized,
        control_capacity,
        entries_initialized,
        entries_capacity,
        initialized_total: control_initialized
            .checked_add(entries_initialized)
            .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
        capacity_total: control_capacity
            .checked_add(entries_capacity)
            .ok_or(PackedTranslationError::ByteAccountingOverflow)?,
    })
}

/// Packed construction translation failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedTranslationError {
    /// Admitted source segments were duplicated or not strictly increasing.
    #[error("packed translation source domain/kind segments are not strictly sorted")]
    SourceSegmentsNotStrictlySorted,
    /// A backing vector could not reserve its exact admission.
    #[error("packed {lane} could not reserve {entries} entries")]
    AllocationFailed {
        /// Translation vector that failed.
        lane: &'static str,
        /// Requested exact admission.
        entries: usize,
    },
    /// An inline word was incorrectly submitted to the mapping builder.
    #[error("packed translation mappings require indexed source words")]
    InlineSource,
    /// An indexed word did not expose its coordinate.
    #[error("packed translation indexed word has no arena coordinate")]
    IndexedWordMissingCoordinate,
    /// No admitted segment exists for a source domain and kind.
    #[error("packed translation has no segment for source domain {domain} kind {kind:?}")]
    UnknownSourceSegment {
        /// Missing source domain.
        domain: u32,
        /// Missing representation kind.
        kind: CompressedValueKind,
    },
    /// Appends did not follow admitted source-segment order.
    #[error(
        "packed translation expected source domain {expected} kind {expected_kind:?}, \
         found domain {actual} kind {actual_kind:?}"
    )]
    SourceSegmentOutOfOrder {
        /// Next admitted domain.
        expected: u32,
        /// Next admitted representation kind.
        expected_kind: CompressedValueKind,
        /// Submitted domain.
        actual: u32,
        /// Submitted representation kind.
        actual_kind: CompressedValueKind,
    },
    /// Source indices were duplicated or not strictly increasing.
    #[error(
        "packed translation source domain {domain} index order is not strict: \
         previous={previous}, next={next}"
    )]
    SourceIndexNotStrictlyIncreasing {
        /// Source domain.
        domain: u32,
        /// Previously appended index.
        previous: u32,
        /// Rejected next index.
        next: u32,
    },
    /// An append exceeded exact admission.
    #[error(
        "packed translation source domain {domain} admitted {admitted} entries, \
         attempted {attempted}"
    )]
    CapacityExceeded {
        /// Source domain.
        domain: u32,
        /// Exact admitted population.
        admitted: usize,
        /// Attempted initialized population.
        attempted: usize,
    },
    /// Allocator-granted capacity changed after admission.
    #[error(
        "packed translation source domain {domain} capacity changed from {admitted} to {actual}"
    )]
    CapacityChanged {
        /// Source domain.
        domain: u32,
        /// Capacity captured at admission.
        admitted: usize,
        /// Capacity observed later.
        actual: usize,
    },
    /// Finalization observed an underfilled exact segment.
    #[error(
        "packed translation source domain {domain} kind {kind:?} admitted {admitted} entries, \
         initialized {initialized}"
    )]
    UnderfilledSegment {
        /// Source domain.
        domain: u32,
        /// Source representation kind.
        kind: CompressedValueKind,
        /// Exact admitted population.
        admitted: usize,
        /// Initialized population.
        initialized: usize,
    },
    /// No mapping exists for an indexed source word.
    #[error("packed translation has no mapping for source domain {domain} index {index}")]
    UnknownSourceCoordinate {
        /// Source domain.
        domain: u32,
        /// Source direct index.
        index: u32,
    },
    /// The destination codec rejected a reconstructed fixed-tag word.
    #[error("packed translation could not encode {tag:?} destination index {index}")]
    DestinationEncoding {
        /// Preserved semantic tag.
        tag: ValueTag,
        /// Destination direct lane index.
        index: u32,
    },
    /// Exact scratch-byte accounting overflowed.
    #[error("packed translation byte accounting overflow")]
    ByteAccountingOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::compressed::CompressedValueWord;

    fn domain() -> ArenaDomainId {
        ArenaDomainId::allocate_logical().expect("test domain allocates")
    }

    fn heap_word(domain: ArenaDomainId, tag: ValueTag, index: u32) -> CompressedValueWord {
        CompressedValueWord::heap(domain, tag, ArenaIndex::new(index)).expect("heap tag encodes")
    }

    #[test]
    fn exact_multi_domain_directory_preserves_every_word_kind_and_forced_bit() {
        let source_a = domain();
        let source_b = domain();
        let destination = domain();
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[
                PackedTranslationSegmentCapacity {
                    source_domain: source_a,
                    source_kind: CompressedValueKind::List,
                    entries: 1,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_a,
                    source_kind: CompressedValueKind::Attrs,
                    entries: 1,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_a,
                    source_kind: CompressedValueKind::Thunk,
                    entries: 1,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_a,
                    source_kind: CompressedValueKind::BoxedInt,
                    entries: 1,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_b,
                    source_kind: CompressedValueKind::BoxedFloat,
                    entries: 1,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_b,
                    source_kind: CompressedValueKind::Path,
                    entries: 1,
                },
            ],
        )
        .unwrap();
        let list = heap_word(source_a, ValueTag::List, 10);
        let attrs = heap_word(source_a, ValueTag::Attrs, 10);
        let forced = heap_word(source_a, ValueTag::Thunk, 30)
            .with_forced_bit()
            .unwrap();
        let boxed_int = CompressedValueWord::boxed_int(source_a, ArenaIndex::new(40));
        let boxed_float = CompressedValueWord::boxed_float(source_b, ArenaIndex::new(5));
        let path = heap_word(source_b, ValueTag::Path, 9);
        for (source, destination_index) in [
            (list, 3),
            (attrs, 4),
            (forced, 5),
            (boxed_int, 6),
            (boxed_float, 7),
            (path, 8),
        ] {
            builder.append(source, destination_index).unwrap();
        }
        let directory = builder.finish().unwrap();

        for (source, destination_index) in [
            (list, 3),
            (attrs, 4),
            (forced, 5),
            (boxed_int, 6),
            (boxed_float, 7),
            (path, 8),
        ] {
            let translated = directory.translate(source).unwrap().compressed();
            assert_eq!(translated.arena_domain(), Some(destination));
            assert_eq!(
                translated.arena_index(),
                Some(ArenaIndex::new(destination_index))
            );
            assert_eq!(translated.kind(), source.kind());
            assert_eq!(translated.is_forced_thunk(), source.is_forced_thunk());
        }
        assert_eq!(
            directory
                .translate(CompressedValueWord::inline_int(17).unwrap())
                .unwrap()
                .compressed(),
            CompressedValueWord::inline_int(17).unwrap()
        );
        assert_eq!(
            directory
                .translate(CompressedValueWord::boolean(true))
                .unwrap()
                .compressed(),
            CompressedValueWord::boolean(true)
        );
        assert_eq!(
            directory
                .translate(CompressedValueWord::null())
                .unwrap()
                .compressed(),
            CompressedValueWord::null()
        );
    }

    #[test]
    fn append_and_finish_fail_before_growth_or_partial_publication() {
        let source = domain();
        let destination = domain();
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::List,
                entries: 1,
            }],
        )
        .unwrap();
        let admitted = builder.bytes().unwrap().capacity_total;
        let first = heap_word(source, ValueTag::List, 10);
        builder.append(first, 0).unwrap();
        let duplicate = builder.append(first, 1);
        assert!(matches!(
            duplicate,
            Err(PackedTranslationError::CapacityExceeded { .. })
        ));
        assert_eq!(builder.bytes().unwrap().capacity_total, admitted);
        assert_eq!(builder.bytes().unwrap().entries_initialized, 8);

        let mut underfilled = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::List,
                entries: 2,
            }],
        )
        .unwrap();
        underfilled.append(first, 0).unwrap();
        assert!(matches!(
            underfilled.finish(),
            Err(PackedTranslationError::UnderfilledSegment { .. })
        ));
    }

    #[test]
    fn unknown_coordinates_and_unsorted_admission_fail_closed() {
        let source_a = domain();
        let source_b = domain();
        let destination = domain();
        let unsorted = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[
                PackedTranslationSegmentCapacity {
                    source_domain: source_b,
                    source_kind: CompressedValueKind::List,
                    entries: 0,
                },
                PackedTranslationSegmentCapacity {
                    source_domain: source_a,
                    source_kind: CompressedValueKind::List,
                    entries: 0,
                },
            ],
        );
        assert!(matches!(
            unsorted,
            Err(PackedTranslationError::SourceSegmentsNotStrictlySorted)
        ));

        let directory = PackedTranslationDirectoryBuilder::try_new(destination, &[])
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(
            directory.translate(heap_word(source_a, ValueTag::List, 1)),
            Err(PackedTranslationError::UnknownSourceSegment { .. })
        ));
    }

    #[test]
    fn selective_translation_preserves_unmoved_kinds_but_rejects_missing_selected_coordinates() {
        let source = domain();
        let destination = domain();
        let mapped_list = heap_word(source, ValueTag::List, 7);
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::List,
                entries: 1,
            }],
        )
        .unwrap();
        builder.append(mapped_list, 2).unwrap();
        let directory = builder.finish().unwrap();

        let flat_lambda = heap_word(source, ValueTag::Lambda, 7);
        assert_eq!(
            directory
                .translate_selected_or_preserve(flat_lambda)
                .unwrap()
                .compressed(),
            flat_lambda
        );
        assert_eq!(
            directory
                .translate_selected_or_preserve(CompressedValueWord::boolean(false))
                .unwrap()
                .compressed(),
            CompressedValueWord::boolean(false)
        );

        let translated = directory
            .translate_selected_or_preserve(mapped_list)
            .unwrap()
            .compressed();
        assert_eq!(translated.arena_domain(), Some(destination));
        assert_eq!(translated.arena_index(), Some(ArenaIndex::new(2)));

        assert!(matches!(
            directory.translate_selected_or_preserve(heap_word(source, ValueTag::List, 8)),
            Err(PackedTranslationError::UnknownSourceCoordinate { .. })
        ));
    }

    #[test]
    fn scratch_accounting_is_exact_and_eight_bytes_per_mapping() {
        let source = domain();
        let destination = domain();
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination,
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::Attrs,
                entries: 3,
            }],
        )
        .unwrap();
        for index in 0..3 {
            builder
                .append(heap_word(source, ValueTag::Attrs, index), index + 9)
                .unwrap();
        }
        let bytes = builder.bytes().unwrap();
        assert_eq!(bytes.entries_initialized, 3 * 8);
        assert!(bytes.entries_capacity >= bytes.entries_initialized);
        assert_eq!(
            bytes.initialized_total,
            bytes.control_initialized + bytes.entries_initialized
        );
        assert_eq!(
            bytes.capacity_total,
            bytes.control_capacity + bytes.entries_capacity
        );
        let directory = builder.finish().unwrap();
        assert_eq!(directory.destination_domain(), destination);
        assert_eq!(directory.bytes().unwrap(), bytes);
    }
}
