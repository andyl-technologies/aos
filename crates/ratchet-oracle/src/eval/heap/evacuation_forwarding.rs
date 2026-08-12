//! Compact forwarding for temporarily retained Candidate-C source words.
//!
//! Selective evacuation can move an object before every incoming reference to
//! it has been rewritten. This directory records only reservation-relative
//! coordinates: the source and destination domains are shared by the whole
//! directory, while each entry is one `(source_offset, destination_offset)`
//! pair. A lookup therefore needs eight bytes per moved object and performs no
//! allocation.
//!
//! [`EvalHeap`](super::EvalHeap) can install the directory together with an
//! owned destination generation for focused alias-routing tests. Production
//! collection does not publish one yet: GC, JIT, FFI, and context-free
//! [`Value`] access must either heal or canonicalize every retained source word
//! first. The builder keeps all allocation and ordering validation on the
//! preflight side of that boundary.

use thiserror::Error;

use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::{Value, ValueTag};

/// One compact source-to-destination reservation-offset mapping.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardingOffset {
    source: u32,
    destination: u32,
}

/// An immutable, allocation-free Candidate-C forwarding lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::eval::heap) struct EvacuationForwardingDirectory {
    source_domain: ArenaDomainId,
    destination_domain: ArenaDomainId,
    offsets: Vec<ForwardingOffset>,
}

impl EvacuationForwardingDirectory {
    /// Returns the reservation domain whose stale words are accepted.
    pub(in crate::eval::heap) const fn source_domain(&self) -> ArenaDomainId {
        self.source_domain
    }

    /// Returns the reservation domain containing forwarded objects.
    pub(in crate::eval::heap) const fn destination_domain(&self) -> ArenaDomainId {
        self.destination_domain
    }

    /// Returns the number of forwarded source offsets.
    pub(in crate::eval::heap) const fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Returns whether no source offsets are forwarded.
    pub(in crate::eval::heap) const fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Translates one expected-tagged source word into its destination word.
    ///
    /// Returns `None` for inline values, another semantic tag, another source
    /// domain, or an offset absent from this directory. The destination keeps
    /// the source word's semantic tag and forced-thunk shortcut bit.
    ///
    /// Lookup performs a binary search over immutable `u32` pairs and does not
    /// allocate or consult the process-global reservation registry.
    #[inline]
    pub(in crate::eval::heap) fn translate(
        &self,
        value: Value,
        expected: ValueTag,
    ) -> Option<Value> {
        if !expected.is_heap() || value.tag() != expected {
            return None;
        }
        let word = value.word();
        if word.arena_domain()? != self.source_domain {
            return None;
        }
        let source = word.arena_index()?.raw();
        let index = self
            .offsets
            .binary_search_by_key(&source, |entry| entry.source)
            .ok()?;
        let destination = self.offsets[index].destination;
        let translated = Value::from_domain_index(
            expected,
            self.destination_domain,
            ArenaIndex::new(destination),
        )
        .ok()?;
        if value.is_forced_thunk() {
            translated.with_forced_bit().ok()
        } else {
            Some(translated)
        }
    }
}

/// Fallible preflight builder for an immutable forwarding directory.
#[derive(Debug)]
pub(in crate::eval::heap) struct EvacuationForwardingDirectoryBuilder {
    source_domain: ArenaDomainId,
    destination_domain: ArenaDomainId,
    expected_entries: usize,
    offsets: Vec<ForwardingOffset>,
}

impl EvacuationForwardingDirectoryBuilder {
    /// Reserves storage for exactly the planned forwarding population.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationForwardingDirectoryError::SameDomain`] when source
    /// and destination name the same reservation, or
    /// [`EvacuationForwardingDirectoryError::AllocationFailed`] when entry
    /// storage cannot be reserved.
    pub(in crate::eval::heap) fn try_new(
        source_domain: ArenaDomainId,
        destination_domain: ArenaDomainId,
        expected_entries: usize,
    ) -> Result<Self, EvacuationForwardingDirectoryError> {
        if source_domain == destination_domain {
            return Err(EvacuationForwardingDirectoryError::SameDomain {
                domain: source_domain,
            });
        }
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(expected_entries).map_err(|_| {
            EvacuationForwardingDirectoryError::AllocationFailed {
                entries: expected_entries,
            }
        })?;
        Ok(Self {
            source_domain,
            destination_domain,
            expected_entries,
            offsets,
        })
    }

    /// Appends one mapping in strictly increasing source-offset order.
    ///
    /// This operation cannot allocate because [`Self::try_new`] reserves the
    /// complete planned population.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationForwardingDirectoryError::TooManyEntries`] after
    /// the planned population is full, or
    /// [`EvacuationForwardingDirectoryError::SourceNotIncreasing`] for a
    /// duplicate or out-of-order source offset.
    pub(in crate::eval::heap) fn push(
        &mut self,
        source: ArenaIndex,
        destination: ArenaIndex,
    ) -> Result<(), EvacuationForwardingDirectoryError> {
        self.prepare_append(source)?.commit(destination);
        Ok(())
    }

    /// Prevalidates the next sorted source before its object is moved.
    ///
    /// The returned token mutably borrows this builder without changing it.
    /// A collector obtains the token, performs the one-object relocation, and
    /// then calls [`PreparedEvacuationForwardingAppend::commit`] with the
    /// resulting destination. If relocation fails, dropping the token leaves
    /// the builder unchanged so its already-completed prefix can be published.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationForwardingDirectoryError::TooManyEntries`] after
    /// the planned population is full, or
    /// [`EvacuationForwardingDirectoryError::SourceNotIncreasing`] for a
    /// duplicate or out-of-order source offset.
    pub(in crate::eval::heap) fn prepare_append(
        &mut self,
        source: ArenaIndex,
    ) -> Result<PreparedEvacuationForwardingAppend<'_>, EvacuationForwardingDirectoryError> {
        if self.offsets.len() == self.expected_entries {
            return Err(EvacuationForwardingDirectoryError::TooManyEntries {
                expected: self.expected_entries,
            });
        }
        let source = source.raw();
        if let Some(previous) = self.offsets.last().map(|entry| entry.source)
            && source <= previous
        {
            return Err(EvacuationForwardingDirectoryError::SourceNotIncreasing {
                previous,
                rejected_source: source,
            });
        }
        Ok(PreparedEvacuationForwardingAppend {
            builder: self,
            source,
        })
    }

    /// Finalizes the directory after its exact planned population is present.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationForwardingDirectoryError::Incomplete`] when fewer
    /// mappings were appended than were reserved by [`Self::try_new`].
    pub(in crate::eval::heap) fn finish(
        self,
    ) -> Result<EvacuationForwardingDirectory, EvacuationForwardingDirectoryError> {
        if self.offsets.len() != self.expected_entries {
            return Err(EvacuationForwardingDirectoryError::Incomplete {
                expected: self.expected_entries,
                actual: self.offsets.len(),
            });
        }
        Ok(EvacuationForwardingDirectory {
            source_domain: self.source_domain,
            destination_domain: self.destination_domain,
            offsets: self.offsets,
        })
    }

    /// Publishes a nonempty successfully moved prefix after a later move fails.
    ///
    /// This is the failure-safe batch door. [`Self::try_new`] already reserved
    /// the complete planned capacity, and [`Self::push`] only accepts sorted
    /// entries within that bound, so a prefix needs no further allocation or
    /// structural validation. Publishing it keeps every already-retired source
    /// resolvable even though the original full batch did not complete.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationForwardingDirectoryError::EmptyPrefix`] when no
    /// object moved before the batch failed. Callers should simply discard an
    /// empty builder because no source was retired.
    pub(in crate::eval::heap) fn finish_prefix(
        self,
    ) -> Result<EvacuationForwardingDirectory, EvacuationForwardingDirectoryError> {
        if self.offsets.is_empty() {
            return Err(EvacuationForwardingDirectoryError::EmptyPrefix);
        }
        Ok(EvacuationForwardingDirectory {
            source_domain: self.source_domain,
            destination_domain: self.destination_domain,
            offsets: self.offsets,
        })
    }
}

/// A sorted directory slot validated before its source object is retired.
#[derive(Debug)]
pub(in crate::eval::heap) struct PreparedEvacuationForwardingAppend<'a> {
    builder: &'a mut EvacuationForwardingDirectoryBuilder,
    source: u32,
}

impl PreparedEvacuationForwardingAppend<'_> {
    /// Records the destination of the successfully moved source.
    ///
    /// This commit is infallible and allocation-free: its token proves source
    /// ordering and remaining length, and the builder reserved the complete
    /// vector capacity before movement began.
    pub(in crate::eval::heap) fn commit(self, destination: ArenaIndex) {
        self.builder.offsets.push(ForwardingOffset {
            source: self.source,
            destination: destination.raw(),
        });
    }
}

/// A forwarding-directory preflight or construction failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(in crate::eval::heap) enum EvacuationForwardingDirectoryError {
    /// Source and destination must name physically distinct reservations.
    #[error("evacuation forwarding source and destination both use domain {domain:?}")]
    SameDomain {
        /// The duplicated reservation domain.
        domain: ArenaDomainId,
    },
    /// The exact forwarding vector could not be reserved.
    #[error("failed to reserve evacuation forwarding storage for {entries} entries")]
    AllocationFailed {
        /// The requested forwarding population.
        entries: usize,
    },
    /// The caller appended more mappings than its preflight declared.
    #[error("evacuation forwarding already contains its planned {expected} entries")]
    TooManyEntries {
        /// The exact preflight population.
        expected: usize,
    },
    /// Source offsets must be unique and strictly increasing.
    #[error(
        "evacuation forwarding source offset {rejected_source} does not follow previous offset {previous}"
    )]
    SourceNotIncreasing {
        /// The last accepted source offset.
        previous: u32,
        /// The rejected duplicate or earlier offset.
        rejected_source: u32,
    },
    /// Finalization requires the complete planned population.
    #[error("evacuation forwarding has {actual} entries, expected {expected}")]
    Incomplete {
        /// The exact preflight population.
        expected: usize,
        /// The mappings appended before finalization.
        actual: usize,
    },
    /// A failed batch with no completed moves needs no forwarding publication.
    #[error("cannot publish an empty evacuation forwarding prefix")]
    EmptyPrefix,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> (ArenaDomainId, ArenaDomainId) {
        (
            ArenaDomainId::from_raw(101).expect("test source domain is valid"),
            ArenaDomainId::from_raw(202).expect("test destination domain is valid"),
        )
    }

    #[test]
    fn forwarding_entry_is_exactly_two_offsets() {
        assert_eq!(std::mem::size_of::<ForwardingOffset>(), 8);
        assert_eq!(std::mem::align_of::<ForwardingOffset>(), 4);
    }

    #[test]
    fn lookup_translates_exact_source_words_without_registry_access() {
        let (source_domain, destination_domain) = domains();
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 2)
                .expect("forwarding storage reserves");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("first mapping appends");
        builder
            .push(ArenaIndex::new(64), ArenaIndex::new(144))
            .expect("second mapping appends");
        let directory = builder.finish().expect("complete directory finalizes");
        let source = Value::from_domain_index(ValueTag::Primop, source_domain, ArenaIndex::new(64))
            .expect("source value encodes");
        let translated = directory
            .translate(source, ValueTag::Primop)
            .expect("mapped source translates");

        assert_eq!(translated.word().arena_domain(), Some(destination_domain));
        assert_eq!(translated.word().arena_index(), Some(ArenaIndex::new(144)));
        assert_eq!(translated.tag(), ValueTag::Primop);
        assert_eq!(directory.len(), 2);
        assert!(!directory.is_empty());
    }

    #[test]
    fn lookup_rejects_wrong_tag_domain_and_unmapped_offset() {
        let (source_domain, destination_domain) = domains();
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 1)
                .expect("forwarding storage reserves");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("mapping appends");
        let directory = builder.finish().expect("complete directory finalizes");
        let source = Value::from_domain_index(ValueTag::Lambda, source_domain, ArenaIndex::new(24))
            .expect("source value encodes");
        let foreign =
            Value::from_domain_index(ValueTag::Lambda, destination_domain, ArenaIndex::new(24))
                .expect("foreign value encodes");
        let absent = Value::from_domain_index(ValueTag::Lambda, source_domain, ArenaIndex::new(32))
            .expect("absent value encodes");

        assert!(directory.translate(source, ValueTag::Primop).is_none());
        assert!(directory.translate(foreign, ValueTag::Lambda).is_none());
        assert!(directory.translate(absent, ValueTag::Lambda).is_none());
        assert!(directory.translate(Value::int(24), ValueTag::Int).is_none());
    }

    #[test]
    fn builder_rejects_same_domain_duplicate_order_and_incomplete_input() {
        let (source_domain, destination_domain) = domains();
        assert_eq!(
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, source_domain, 0)
                .expect_err("same-domain directory is rejected"),
            EvacuationForwardingDirectoryError::SameDomain {
                domain: source_domain
            }
        );

        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 2)
                .expect("forwarding storage reserves");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("first mapping appends");
        assert_eq!(
            builder
                .push(ArenaIndex::new(24), ArenaIndex::new(96))
                .expect_err("duplicate source is rejected"),
            EvacuationForwardingDirectoryError::SourceNotIncreasing {
                previous: 24,
                rejected_source: 24,
            }
        );
        assert_eq!(
            builder
                .push(ArenaIndex::new(16), ArenaIndex::new(96))
                .expect_err("out-of-order source is rejected"),
            EvacuationForwardingDirectoryError::SourceNotIncreasing {
                previous: 24,
                rejected_source: 16,
            }
        );
        assert_eq!(
            builder
                .finish()
                .expect_err("partial directory does not publish"),
            EvacuationForwardingDirectoryError::Incomplete {
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn builder_rejects_entries_beyond_exact_preflight_population() {
        let (source_domain, destination_domain) = domains();
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 1)
                .expect("forwarding storage reserves");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("planned mapping appends");
        assert_eq!(
            builder
                .push(ArenaIndex::new(32), ArenaIndex::new(96))
                .expect_err("excess mapping is rejected"),
            EvacuationForwardingDirectoryError::TooManyEntries { expected: 1 }
        );
    }

    #[test]
    fn failed_batch_can_publish_and_resolve_its_moved_prefix() {
        let (source_domain, destination_domain) = domains();
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 3)
                .expect("complete batch capacity reserves before movement");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("first completed move appends");
        let directory = builder
            .finish_prefix()
            .expect("nonempty completed prefix publishes");
        let moved = Value::from_domain_index(ValueTag::Primop, source_domain, ArenaIndex::new(24))
            .expect("moved source word encodes");
        let not_moved =
            Value::from_domain_index(ValueTag::Primop, source_domain, ArenaIndex::new(32))
                .expect("unmoved source word encodes");

        assert_eq!(directory.len(), 1);
        assert_eq!(
            directory
                .translate(moved, ValueTag::Primop)
                .expect("completed prefix entry resolves")
                .word()
                .arena_index(),
            Some(ArenaIndex::new(80))
        );
        assert!(directory.translate(not_moved, ValueTag::Primop).is_none());

        let empty =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 3)
                .expect("batch capacity reserves");
        assert_eq!(
            empty
                .finish_prefix()
                .expect_err("empty prefix does not publish"),
            EvacuationForwardingDirectoryError::EmptyPrefix
        );
    }

    #[test]
    fn prepared_append_rejects_without_mutation_and_commits_infallibly() {
        let (source_domain, destination_domain) = domains();
        let mut builder =
            EvacuationForwardingDirectoryBuilder::try_new(source_domain, destination_domain, 2)
                .expect("complete batch capacity reserves");
        builder
            .push(ArenaIndex::new(24), ArenaIndex::new(80))
            .expect("first mapping appends");
        assert_eq!(
            builder
                .prepare_append(ArenaIndex::new(24))
                .expect_err("duplicate source is rejected before movement"),
            EvacuationForwardingDirectoryError::SourceNotIncreasing {
                previous: 24,
                rejected_source: 24,
            }
        );

        let append = builder
            .prepare_append(ArenaIndex::new(32))
            .expect("a rejection did not mutate source ordering or length");
        append.commit(ArenaIndex::new(96));
        let directory = builder.finish().expect("both planned mappings publish");
        let source = Value::from_domain_index(ValueTag::Lambda, source_domain, ArenaIndex::new(32))
            .expect("source word encodes");

        assert_eq!(
            directory
                .translate(source, ValueTag::Lambda)
                .expect("infallibly committed append is lookup-visible")
                .word()
                .arena_index(),
            Some(ArenaIndex::new(96))
        );
    }
}
