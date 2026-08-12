//! Transactional healing for flat owners retained across a packed rotation.
//!
//! A mixed packed rotation moves immutable values and boxed scalars while
//! leaving lambdas, primops, thunks, and external handles in their existing
//! stores. Edges owned by those retained objects must therefore be rewritten
//! to the packed coordinates before the source lanes can be retired. This
//! module validates every scanner coordinate and clones every affected payload
//! without mutating the live heap; commit then uses only allocation-free typed
//! write channels.

use std::ptr::NonNull;

use thiserror::Error;

use super::environment_writeback::EnvironmentWritebackStage;
use super::packed_translation::{PackedTranslationDirectory, PackedTranslationError};
use super::roots::{CollectorPollDirectHeapFieldWrite, StagedFlatClosureWrite};
use super::*;

const PLANNED_WRITES_TABLE: &str = "packed-retained-healing-planned-writes";
const RECORD_STAGE_TABLE: &str = "packed-retained-healing-record-stage";
const CLOSURE_STAGE_TABLE: &str = "packed-retained-healing-closure-stage";
const ENVIRONMENT_STAGE_TABLE: &str = "packed-retained-healing-environment-stage";

/// Fully validated live-heap writes for retained owners in a packed rotation.
///
/// The stage owns every cloned record, closure payload, inline capture tail,
/// and shared-environment write needed by publication. Creating it does not
/// mutate the heap. Once prepared under exclusive evaluator access, committing
/// it performs no allocation and cannot fail.
pub(in crate::eval) struct PackedRetainedHeapHealingStage {
    write_count: usize,
    records: Vec<(usize, HeapObjectValue)>,
    closures: Vec<StagedFlatClosureWrite>,
    environment: EnvironmentWritebackStage,
}

impl PackedRetainedHeapHealingStage {
    /// Returns the number of exact retained-owner fields staged for healing.
    pub(in crate::eval) const fn count(&self) -> usize {
        self.write_count
    }
}

impl EvalHeap {
    /// Stages translated fields owned by closures retained across packed rotation.
    ///
    /// List and attrset owners are deliberately skipped because the packed
    /// generation builder has already copied their translated destination
    /// edges. Strings, paths, and boxed scalars have no outgoing fields.
    /// Lambda, primop, thunk, and external owners remain flat, so every one of
    /// their immutable/scalar child words selected by `translation` is
    /// validated against the precise scan and staged through the owner's
    /// existing record, flat-closure, or shared-environment channel.
    ///
    /// # Errors
    ///
    /// Returns [`PackedRetainedHeapHealingError`] if translation fails, exact
    /// staging storage cannot be reserved, an owner/source/value no longer
    /// matches the scan, or a list/attrset write unexpectedly reaches the
    /// retained-owner stage.
    pub(in crate::eval) fn stage_packed_retained_heap_healing(
        &self,
        scan: &PreciseHeapScan,
        translation: &PackedTranslationDirectory,
    ) -> Result<PackedRetainedHeapHealingStage, PackedRetainedHeapHealingError> {
        let write_count = count_healed_fields(scan, translation)?;
        let mut planned =
            try_stage_vec::<CollectorPollDirectHeapFieldWrite>(write_count, PLANNED_WRITES_TABLE)?;

        for object in scan.objects() {
            if !is_retained_owner(object.tag()) {
                continue;
            }
            for (field_index, edge) in object.edges().iter().enumerate() {
                let Some(replacement) = translated_child(edge.value(), translation)? else {
                    continue;
                };
                planned.push(self.plan_permanent_publication_heap_field_write(
                    object.value(),
                    field_index,
                    edge.source(),
                    edge.value(),
                    replacement,
                )?);
            }
        }

        let mut records =
            try_stage_vec::<(usize, HeapObjectValue)>(write_count, RECORD_STAGE_TABLE)?;
        let mut lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut closures =
            try_stage_vec::<StagedFlatClosureWrite>(write_count, CLOSURE_STAGE_TABLE)?;
        let mut environment = EnvironmentWritebackStage::try_new(write_count).map_err(|_| {
            PackedRetainedHeapHealingError::AllocationFailed {
                table: ENVIRONMENT_STAGE_TABLE,
                entries: write_count,
            }
        })?;

        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned,
            &mut records,
            &mut lists,
            &mut attrs,
            &mut closures,
            &mut environment,
            write_count,
        )?;
        if !lists.is_empty() || !attrs.is_empty() {
            return Err(PackedRetainedHeapHealingError::UnexpectedContainerStage);
        }

        Ok(PackedRetainedHeapHealingStage {
            write_count,
            records,
            closures,
            environment,
        })
    }

    /// Commits a prevalidated retained-owner healing stage without allocation.
    ///
    /// The caller must preserve exclusive evaluator access between staging and
    /// commit. Packed generation installation and source retirement are
    /// intentionally outside this operation.
    pub(in crate::eval) fn commit_packed_retained_heap_healing(
        &mut self,
        stage: PackedRetainedHeapHealingStage,
    ) {
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(stage.records);
        self.commit_collector_poll_minor_gc_staged_flat_closure_writes(stage.closures);
        stage.environment.commit();
    }
}

fn count_healed_fields(
    scan: &PreciseHeapScan,
    translation: &PackedTranslationDirectory,
) -> Result<usize, PackedRetainedHeapHealingError> {
    let mut count = 0usize;
    for object in scan.objects() {
        if !is_retained_owner(object.tag()) {
            continue;
        }
        for edge in object.edges() {
            if translated_child(edge.value(), translation)?.is_some() {
                count = count
                    .checked_add(1)
                    .ok_or(PackedRetainedHeapHealingError::LengthOverflow)?;
            }
        }
    }
    Ok(count)
}

fn is_retained_owner(tag: ValueTag) -> bool {
    matches!(
        tag,
        ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk | ValueTag::External
    )
}

fn translated_child(
    source: Value,
    translation: &PackedTranslationDirectory,
) -> Result<Option<Value>, PackedTranslationError> {
    if !matches!(
        source.tag(),
        ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Int
            | ValueTag::Float
    ) {
        return Ok(None);
    }
    let replacement = Value::from_word(
        translation
            .translate_selected_or_preserve(source.word())?
            .compressed(),
    );
    Ok((!replacement.raw_eq(source)).then_some(replacement))
}

fn try_stage_vec<T>(
    entries: usize,
    table: &'static str,
) -> Result<Vec<T>, PackedRetainedHeapHealingError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| PackedRetainedHeapHealingError::AllocationFailed { table, entries })?;
    Ok(values)
}

/// Packed retained-owner healing failed before live heap mutation.
#[derive(Debug, Error)]
pub(in crate::eval) enum PackedRetainedHeapHealingError {
    /// The selected-child count overflowed `usize`.
    #[error("packed retained-owner healing field count overflowed")]
    LengthOverflow,
    /// Exact stage storage could not be reserved.
    #[error("failed to reserve {table} for {entries} packed retained-owner entries")]
    AllocationFailed {
        /// The staging table.
        table: &'static str,
        /// The requested exact entry count.
        entries: usize,
    },
    /// A selected source word could not be translated.
    #[error("packed retained-owner translation failed: {0}")]
    Translation(#[from] PackedTranslationError),
    /// The retained owner or exact scanned field no longer matched the heap.
    #[error("packed retained-owner heap validation failed: {0}")]
    Heap(#[from] EvalHeapError),
    /// A moved collection owner unexpectedly reached a live container channel.
    #[error("packed retained-owner healing unexpectedly staged a list or attrset owner")]
    UnexpectedContainerStage,
}

#[cfg(test)]
mod tests {
    use super::super::packed_generation::PackedGenerationDomain;
    use super::super::packed_translation::{
        PackedTranslationDirectoryBuilder, PackedTranslationSegmentCapacity,
    };
    use super::*;
    use crate::compile::IrId;
    use crate::string::NixString;
    use crate::syntax::{Span, SymbolTable};

    #[test]
    fn stage_leaves_primop_live_until_allocation_free_commit() {
        let mut symbols = SymbolTable::new();
        let symbol = symbols.intern(b"captured").expect("symbol interns");
        let mut heap = EvalHeap::new();
        let source = heap
            .alloc_string(NixString::from_bytes(b"value".to_vec()))
            .expect("string allocates");
        let primop = heap
            .alloc_primop(EvalPrimOp::with_args(
                symbol,
                vec![EvalPrimOpArg::new(IrId::new(1), Span::new(0, 1), source)],
            ))
            .expect("primop allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, primop)
            .expect("root storage reserves");
        let scan = heap.scan_precise_roots(&roots).expect("root graph scans");
        let translation = one_value_translation(source);
        let replacement = Value::from_word(
            translation
                .translate(source.word())
                .expect("source translates")
                .compressed(),
        );

        let stage = heap
            .stage_packed_retained_heap_healing(&scan, &translation)
            .expect("retained owner stages");
        assert_eq!(stage.count(), 1);
        assert!(
            heap.get_primop(primop).expect("primop remains live").args()[0]
                .value()
                .raw_eq(source)
        );

        heap.commit_packed_retained_heap_healing(stage);

        assert!(
            heap.get_primop(primop).expect("primop remains live").args()[0]
                .value()
                .raw_eq(replacement)
        );
    }

    #[test]
    fn stage_skips_moved_list_owner_edges() {
        let mut heap = EvalHeap::new();
        let source = heap
            .alloc_string(NixString::from_bytes(b"value".to_vec()))
            .expect("string allocates");
        let list = heap
            .alloc_list(NixList::new(vec![source]))
            .expect("list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, list)
            .expect("root storage reserves");
        let scan = heap.scan_precise_roots(&roots).expect("root graph scans");
        let translation = one_value_translation(source);

        let stage = heap
            .stage_packed_retained_heap_healing(&scan, &translation)
            .expect("moved collection owner is omitted");

        assert_eq!(stage.count(), 0);
        assert!(
            heap.get_list(list)
                .expect("source list remains untouched")
                .get(0)
                .is_some_and(|value| value.raw_eq(source))
        );
    }

    fn one_value_translation(source: Value) -> PackedTranslationDirectory {
        let destination = PackedGenerationDomain::try_allocate().expect("domain allocates");
        let source_domain = source.word().arena_domain().expect("source is indexed");
        let capacity = PackedTranslationSegmentCapacity {
            source_domain,
            source_kind: source.word().kind(),
            entries: 1,
        };
        let mut builder = PackedTranslationDirectoryBuilder::try_new(destination.id(), &[capacity])
            .expect("translation reserves");
        builder.append(source.word(), 0).expect("mapping appends");
        builder.finish().expect("translation finalizes")
    }
}
