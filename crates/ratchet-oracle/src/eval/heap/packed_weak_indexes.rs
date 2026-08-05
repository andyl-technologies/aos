//! Non-mutating weak hash-cons index rebuilding for packed heap rotation.
//!
//! Hash-cons tables accelerate immutable-value reuse but do not own liveness.
//! A packed rotation therefore retains only entries that already have exact
//! mappings in its authoritative translation directory. Preparation constructs
//! four independent replacement tables and completes every allocation before
//! [`EvalHeap`] is mutated; commit is four allocation-free moves.

use thiserror::Error;

use super::packed_translation::{PackedTranslationDirectory, PackedTranslationError};
use super::*;

/// Owned, fully allocated weak-index replacements for one packed rotation.
#[derive(Debug)]
pub(in crate::eval) struct PreparedPackedWeakIndexes {
    string_cons: HashConsTable<HotXxh3Hash, Value>,
    path_cons: HashConsTable<HotXxh3Hash, Value>,
    list_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_cons: HashConsTable<HotXxh3Hash, Value>,
}

impl EvalHeap {
    /// Rebuilds weak hash-cons indexes without mutating the source heap.
    ///
    /// Only values with exact entries in `translation` are copied into the
    /// replacements. Unselected values and selected-but-unmapped coordinates
    /// are weakly unreachable and deliberately omitted.
    ///
    /// # Errors
    ///
    /// Returns [`PackedWeakIndexError`] if a mapped destination cannot be
    /// encoded, a replacement table cannot reserve storage, or a freshly
    /// reserved slot is unexpectedly unavailable.
    pub(in crate::eval) fn prepare_packed_weak_indexes(
        &self,
        translation: &PackedTranslationDirectory,
    ) -> Result<PreparedPackedWeakIndexes, PackedWeakIndexError> {
        Ok(PreparedPackedWeakIndexes {
            string_cons: rebuild_table(&self.string_cons, translation)?,
            path_cons: rebuild_table(&self.path_cons, translation)?,
            list_cons: rebuild_table(&self.list_cons, translation)?,
            attrs_cons: rebuild_table(&self.attrs_cons, translation)?,
        })
    }

    /// Replaces all weak hash-cons indexes without allocating.
    ///
    /// This method does not install a packed generation or retire source
    /// storage. Its caller owns transaction ordering around those operations.
    pub(in crate::eval) fn commit_packed_weak_indexes(
        &mut self,
        prepared: PreparedPackedWeakIndexes,
    ) {
        self.string_cons = prepared.string_cons;
        self.path_cons = prepared.path_cons;
        self.list_cons = prepared.list_cons;
        self.attrs_cons = prepared.attrs_cons;
    }
}

fn rebuild_table(
    source: &HashConsTable<HotXxh3Hash, Value>,
    translation: &PackedTranslationDirectory,
) -> Result<HashConsTable<HotXxh3Hash, Value>, PackedWeakIndexError> {
    let mut rebuilt = HashConsTable::new();
    for (key, _index, value) in source.committed_entries() {
        let Some(replacement) = translation.translate_weak_mapped(value.word())? else {
            continue;
        };
        let slot = rebuilt.reserve_slot(*key)?;
        if !rebuilt.push_reserved(slot, Value::from_word(replacement.compressed())) {
            return Err(PackedWeakIndexError::ReservationLost);
        }
    }
    Ok(rebuilt)
}

/// Packed weak hash-cons index preparation failed before heap mutation.
#[derive(Debug, Error)]
pub(in crate::eval) enum PackedWeakIndexError {
    /// An exact mapped destination could not be encoded.
    #[error("packed weak-index translation failed: {0}")]
    Translation(#[from] PackedTranslationError),
    /// A replacement table could not reserve its key or candidate storage.
    #[error("packed weak-index allocation failed: {0}")]
    HashCons(#[from] HashConsError),
    /// A freshly reserved candidate slot unexpectedly disappeared.
    #[error("packed weak-index reservation was lost")]
    ReservationLost,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::ArenaIndex;
    use crate::string::NixString;
    use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

    use super::super::packed_generation::PackedGenerationDomain;
    use super::super::packed_translation::{
        PackedTranslationDirectoryBuilder, PackedTranslationSegmentCapacity,
    };

    #[test]
    fn preparation_retains_only_exact_mappings_and_commit_is_explicit() {
        let mut heap = EvalHeap::new();
        let mapped = heap
            .alloc_string(NixString::from_bytes(b"mapped".to_vec()))
            .expect("mapped string allocates");
        let stale_selected = heap
            .alloc_string(NixString::from_bytes(b"stale".to_vec()))
            .expect("stale string allocates");
        let unselected = heap
            .alloc_path(NixString::from_bytes(b"/unselected".to_vec()))
            .expect("unselected path allocates");
        let source_counts = (
            heap.string_cons.storage_counts(),
            heap.path_cons.storage_counts(),
            heap.list_cons.storage_counts(),
            heap.attrs_cons.storage_counts(),
        );
        let source_words = (
            committed_words(&heap.string_cons),
            committed_words(&heap.path_cons),
            committed_words(&heap.list_cons),
            committed_words(&heap.attrs_cons),
        );

        let source_domain = mapped
            .word()
            .arena_domain()
            .expect("allocated string has a source domain");
        assert_eq!(stale_selected.word().arena_domain(), Some(source_domain));
        let destination =
            PackedGenerationDomain::try_allocate().expect("packed destination domain allocates");
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination.id(),
            &[PackedTranslationSegmentCapacity {
                source_domain,
                source_kind: CompressedValueKind::String,
                entries: 1,
            }],
        )
        .expect("translation builder allocates");
        builder
            .append(mapped.word(), 7)
            .expect("mapped coordinate appends");
        let translation = builder.finish().expect("translation is complete");

        let prepared = heap
            .prepare_packed_weak_indexes(&translation)
            .expect("weak indexes prepare");

        assert_eq!(
            (
                heap.string_cons.storage_counts(),
                heap.path_cons.storage_counts(),
                heap.list_cons.storage_counts(),
                heap.attrs_cons.storage_counts(),
            ),
            source_counts
        );
        assert_eq!(
            (
                committed_words(&heap.string_cons),
                committed_words(&heap.path_cons),
                committed_words(&heap.list_cons),
                committed_words(&heap.attrs_cons),
            ),
            source_words
        );
        assert!(heap.get_string(mapped).is_ok());
        assert!(heap.get_string(stale_selected).is_ok());
        assert!(heap.get_path(unselected).is_ok());

        heap.commit_packed_weak_indexes(prepared);

        let retained = heap
            .string_cons
            .committed_entries()
            .map(|(_key, _index, value)| *value)
            .collect::<Vec<_>>();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].word().arena_domain(), Some(destination.id()));
        assert_eq!(retained[0].word().arena_index(), Some(ArenaIndex::new(7)));
        assert_eq!(retained[0].tag(), ValueTag::String);
        assert!(heap.path_cons.is_empty());
        assert!(heap.list_cons.is_empty());
        assert!(heap.attrs_cons.is_empty());
    }

    fn committed_words(table: &HashConsTable<HotXxh3Hash, Value>) -> Vec<u64> {
        let mut words = table
            .committed_entries()
            .map(|(_key, _index, value)| value.word().raw())
            .collect::<Vec<_>>();
        words.sort_unstable();
        words
    }

    #[test]
    fn weak_translation_drops_inline_unselected_and_stale_words() {
        let source =
            crate::heap::ArenaDomainId::allocate_logical().expect("source domain allocates");
        let destination =
            PackedGenerationDomain::try_allocate().expect("destination domain allocates");
        let mapped = CompressedValueWord::heap(source, ValueTag::List, ArenaIndex::new(3))
            .expect("mapped list encodes");
        let stale = CompressedValueWord::heap(source, ValueTag::List, ArenaIndex::new(4))
            .expect("stale list encodes");
        let unselected = CompressedValueWord::heap(source, ValueTag::Attrs, ArenaIndex::new(5))
            .expect("unselected attrs encodes");
        let mut builder = PackedTranslationDirectoryBuilder::try_new(
            destination.id(),
            &[PackedTranslationSegmentCapacity {
                source_domain: source,
                source_kind: CompressedValueKind::List,
                entries: 1,
            }],
        )
        .expect("translation builder allocates");
        builder.append(mapped, 1).expect("mapping appends");
        let translation = builder.finish().expect("translation completes");

        assert!(
            translation
                .translate_weak_mapped(CompressedValueWord::null())
                .expect("inline translation is infallible")
                .is_none()
        );
        assert!(
            translation
                .translate_weak_mapped(stale)
                .expect("stale translation is infallible")
                .is_none()
        );
        assert!(
            translation
                .translate_weak_mapped(unselected)
                .expect("unselected translation is infallible")
                .is_none()
        );
    }
}
