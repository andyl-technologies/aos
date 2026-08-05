//! End-to-end heap-side transaction for one packed permanent rotation.
//!
//! Preparation completes every allocation and validates the exact precise
//! graph while the source heap remains untouched. Publication first installs
//! the admitted packed owner, then performs only allocation-free weak-index
//! replacement and retained-owner healing. Source storage remains live until
//! the tree-walk caller has rewritten roots, rebuilt a precise scan, and proven
//! that no word names a selected source lane.

use thiserror::Error;

use crate::value::compressed::CandidateCScalarRetirementReport;

use super::packed_generation::PackedGeneration;
use super::packed_rotation_prepare::{
    PackedRotationAdmissionInput, PackedRotationPrepareError, PreparedPackedPermanentRotation,
};
use super::packed_source_retirement::{
    PackedSourceRetirementError, PackedSourceRetirementReport, PreparedPackedSourceRetirement,
};
use super::packed_translation::PackedTranslationDirectory;
use super::{
    DirectRootRewritePlan, EvalHeap, EvalHeapError, HeapObjectScan, PackedRetainedHeapHealingError,
    PackedRetainedHeapHealingStage, PackedWeakIndexError, PreciseHeapScan,
    PreparedPackedWeakIndexes,
};

/// A fully allocated, source-untouched packed publication transaction.
pub(in crate::eval) struct PreparedPackedPublication {
    generation: PackedGeneration,
    translation: PackedTranslationDirectory,
    root_rewrites: DirectRootRewritePlan,
    healing: PackedRetainedHeapHealingStage,
    weak_indexes: PreparedPackedWeakIndexes,
    source_retirement: PreparedPackedSourceRetirement,
    moved_objects: usize,
    retained_objects: usize,
}

impl PreparedPackedPublication {
    /// Returns the exact raw mutator-root rewrite plan.
    pub(in crate::eval) const fn root_rewrites(&self) -> &DirectRootRewritePlan {
        &self.root_rewrites
    }

    /// Returns the number of reachable values moved into packed lanes.
    pub(in crate::eval) const fn moved_objects(&self) -> usize {
        self.moved_objects
    }

    /// Returns the number of reachable flat owners retained in place.
    pub(in crate::eval) const fn retained_objects(&self) -> usize {
        self.retained_objects
    }

    /// Returns initialized bytes in the unpublished packed owner.
    pub(in crate::eval) const fn destination_initialized_bytes(&self) -> usize {
        self.generation.bytes().initialized_total
    }

    /// Returns allocator-capacity bytes charged for the unpublished owner.
    pub(in crate::eval) const fn destination_capacity_bytes(&self) -> usize {
        self.generation.bytes().capacity_total
    }

    /// Returns the strictly admitted overlap peak including transaction scratch.
    pub(in crate::eval) const fn projected_peak_bytes(&self) -> usize {
        self.generation.admission().projected_peak_bytes
    }

    /// Returns bytes remaining below the strict half-stock acceptance ceiling.
    pub(in crate::eval) const fn admission_headroom_bytes(&self) -> usize {
        self.generation.admission().headroom_bytes
    }
}

/// Published packed state whose selected source lanes remain live.
///
/// Dropping this token is semantically safe: roots and retained heap edges may
/// already name the packed generation, while every old source allocation is
/// deliberately retained. Only a successful zero-source-alias audit permits
/// [`EvalHeap::retire_published_packed_source`] to consume it.
#[derive(Debug)]
pub(in crate::eval) struct PublishedPackedPublication {
    translation: PackedTranslationDirectory,
    source_retirement: PreparedPackedSourceRetirement,
    moved_objects: usize,
    retained_objects: usize,
    healed_fields: usize,
}

/// A published packed generation whose rebuilt precise graph has no source aliases.
#[derive(Debug)]
pub(in crate::eval) struct ZeroAliasPackedPublication(PublishedPackedPublication);

/// A published packed generation that failed its zero-source-alias audit.
#[derive(Debug)]
pub(in crate::eval) struct PackedSourceAliasAuditFailure {
    published: PublishedPackedPublication,
    residual_aliases: usize,
}

impl PackedSourceAliasAuditFailure {
    /// Returns the number of retained words that still name selected source lanes.
    pub(in crate::eval) const fn residual_aliases(&self) -> usize {
        self.residual_aliases
    }

    /// Returns the still-live published generation for a later audit attempt.
    pub(in crate::eval) fn into_published(self) -> PublishedPackedPublication {
        self.published
    }
}

/// Heap publication result paired with its still-uncommitted root plan.
#[derive(Debug)]
pub(in crate::eval) struct PackedPublicationCommit {
    published: PublishedPackedPublication,
    root_rewrites: DirectRootRewritePlan,
}

impl PackedPublicationCommit {
    /// Returns the raw root rewrites that must immediately be committed.
    pub(in crate::eval) const fn root_rewrites(&self) -> &DirectRootRewritePlan {
        &self.root_rewrites
    }

    /// Separates the published-source lifetime token from the root plan.
    pub(in crate::eval) fn into_parts(self) -> (PublishedPackedPublication, DirectRootRewritePlan) {
        (self.published, self.root_rewrites)
    }
}

/// Reports physical retirement after a successful zero-alias audit.
#[derive(Clone, Copy, Debug)]
pub(in crate::eval) struct PackedPublicationRetirementReport {
    immutable: PackedSourceRetirementReport,
    scalars: CandidateCScalarRetirementReport,
    moved_objects: usize,
    retained_objects: usize,
    healed_fields: usize,
}

impl PackedPublicationRetirementReport {
    /// Returns the immutable-source retirement report.
    pub(in crate::eval) const fn immutable(self) -> PackedSourceRetirementReport {
        self.immutable
    }

    /// Returns the boxed-scalar retirement report.
    pub(in crate::eval) const fn scalars(self) -> CandidateCScalarRetirementReport {
        self.scalars
    }

    /// Returns the number of reachable objects copied into packed lanes.
    pub(in crate::eval) const fn moved_objects(self) -> usize {
        self.moved_objects
    }

    /// Returns the number of reachable owners retained in flat storage.
    pub(in crate::eval) const fn retained_objects(self) -> usize {
        self.retained_objects
    }

    /// Returns the number of retained-owner fields rewritten.
    pub(in crate::eval) const fn healed_fields(self) -> usize {
        self.healed_fields
    }
}

impl EvalHeap {
    /// Prepares every heap-owned part of one packed publication transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PackedPublicationError`] if destination construction,
    /// retained-owner staging, weak-index rebuilding, or source-retirement
    /// inventory validation fails. The heap is unchanged on every error.
    pub(in crate::eval) fn prepare_packed_publication(
        &self,
        scan: &PreciseHeapScan,
        admission: PackedRotationAdmissionInput,
    ) -> Result<PreparedPackedPublication, PackedPublicationError> {
        let rotation = PreparedPackedPermanentRotation::try_prepare(self, scan, admission)?;
        let healing = self.stage_packed_retained_heap_healing(scan, rotation.translation())?;
        let weak_indexes = self.prepare_packed_weak_indexes(rotation.translation())?;
        let source_retirement = self.prepare_packed_source_retirement()?;
        let moved_objects = rotation.moved_sources().len();
        let retained_objects = rotation.retained_flat_sources().len();
        let (generation, translation, root_rewrites, _, _) = rotation.into_parts();
        Ok(PreparedPackedPublication {
            generation,
            translation,
            root_rewrites,
            healing,
            weak_indexes,
            source_retirement,
            moved_objects,
            retained_objects,
        })
    }

    /// Installs the packed owner and commits prevalidated heap-owned state.
    ///
    /// The packed-owner install is the only fallible operation and occurs
    /// before any other mutation. A successful install is followed only by
    /// allocation-free commits. Source immutable and scalar stores remain live
    /// until the caller rewrites roots and proves zero selected-source aliases.
    ///
    /// # Errors
    ///
    /// Returns [`PackedPublicationError::Heap`] if the serial heap cannot
    /// accept the packed owner. The heap is unchanged on this error.
    pub(in crate::eval) fn publish_prepared_packed(
        &mut self,
        prepared: PreparedPackedPublication,
    ) -> Result<PackedPublicationCommit, PackedPublicationError> {
        let PreparedPackedPublication {
            generation,
            translation,
            root_rewrites,
            healing,
            weak_indexes,
            source_retirement,
            moved_objects,
            retained_objects,
        } = prepared;
        let healed_fields = healing.count();
        self.install_packed_generation_owner(generation)?;
        self.commit_packed_retained_heap_healing(healing);
        self.commit_packed_weak_indexes(weak_indexes);
        Ok(PackedPublicationCommit {
            published: PublishedPackedPublication {
                translation,
                source_retirement,
                moved_objects,
                retained_objects,
                healed_fields,
            },
            root_rewrites,
        })
    }

    /// Audits every retained word for selected source-lane aliases.
    ///
    /// The scan must be rebuilt from the rewritten mutator roots. Exact
    /// forwarding membership is intentionally not required: a stale coordinate
    /// in a selected source lane is also a dangling alias and blocks retirement.
    pub(in crate::eval) fn audit_packed_source_aliases(
        &self,
        scan: &PreciseHeapScan,
        published: PublishedPackedPublication,
    ) -> Result<ZeroAliasPackedPublication, PackedSourceAliasAuditFailure> {
        let translation = &published.translation;
        let roots = scan
            .roots()
            .iter()
            .filter(|root| translation.selects_source_word(root.value().word()))
            .count();
        let fields = scan
            .objects()
            .iter()
            .flat_map(HeapObjectScan::edges)
            .filter(|edge| translation.selects_source_word(edge.value().word()))
            .count();
        let indexes = self
            .string_cons
            .committed_entries()
            .chain(self.path_cons.committed_entries())
            .chain(self.list_cons.committed_entries())
            .chain(self.attrs_cons.committed_entries())
            .filter(|(_, _, value)| translation.selects_source_word(value.word()))
            .count();
        let residual_aliases = roots.saturating_add(fields).saturating_add(indexes);
        if residual_aliases == 0 {
            Ok(ZeroAliasPackedPublication(published))
        } else {
            Err(PackedSourceAliasAuditFailure {
                published,
                residual_aliases,
            })
        }
    }

    /// Retires selected immutable and boxed-scalar source stores.
    ///
    /// The proof token can only be constructed by
    /// [`Self::audit_packed_source_aliases`]. Every boxed-scalar and immutable
    /// store validates and lends an exclusive commit token before the first
    /// source cell is retired. All five commits are then allocation-free and
    /// infallible.
    ///
    /// # Errors
    ///
    /// Returns [`PackedPublicationError`] if scalar retirement validation or
    /// immutable source-population validation fails.
    pub(in crate::eval) fn retire_published_packed_source(
        &mut self,
        audited: ZeroAliasPackedPublication,
    ) -> Result<PackedPublicationRetirementReport, PackedPublicationError> {
        let ZeroAliasPackedPublication(published) = audited;
        let PublishedPackedPublication {
            translation: _,
            source_retirement,
            moved_objects,
            retained_objects,
            healed_fields,
        } = published;
        let (immutable, scalars) = self.retire_packed_sources_atomically(source_retirement)?;
        Ok(PackedPublicationRetirementReport {
            immutable,
            scalars,
            moved_objects,
            retained_objects,
            healed_fields,
        })
    }
}

/// Packed publication preparation, installation, or retirement failed.
#[derive(Debug, Error)]
pub(in crate::eval) enum PackedPublicationError {
    /// Packed generation construction failed before mutation.
    #[error("packed rotation preparation failed: {0}")]
    Rotation(#[from] PackedRotationPrepareError),
    /// Retained flat-owner staging failed before mutation.
    #[error("packed retained-owner healing failed: {0}")]
    Healing(#[from] PackedRetainedHeapHealingError),
    /// Weak hash-cons index rebuilding failed before mutation.
    #[error("packed weak-index rebuilding failed: {0}")]
    WeakIndexes(#[from] PackedWeakIndexError),
    /// Immutable source retirement preparation or commit failed.
    #[error("packed immutable source retirement failed: {0}")]
    SourceRetirement(#[from] PackedSourceRetirementError),
    /// Packed owner installation failed before other publication mutations.
    #[error("packed owner installation failed: {0}")]
    Heap(#[from] EvalHeapError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::NixString;

    use super::super::{DirectRootBinding, EvalRootSet, EvalRootSource};

    #[test]
    fn publication_keeps_sources_until_audited_retirement() {
        let mut heap = EvalHeap::new();
        let source = heap
            .alloc_string(NixString::from_bytes(b"packed".to_vec()))
            .expect("source allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, source)
            .expect("root allocates");
        let scan = heap.scan_precise_roots(&roots).expect("source scans");
        let prepared = heap
            .prepare_packed_publication(&scan, PackedRotationAdmissionInput::default())
            .expect("publication prepares");

        let commit = heap
            .publish_prepared_packed(prepared)
            .expect("heap publication commits");
        let (published, root_plan) = commit.into_parts();
        assert!(heap.get_string(source).is_ok());
        let mut root = source;
        root_plan
            .apply(&mut [DirectRootBinding::new(
                EvalRootSource::ValueStack { slot: 0 },
                &mut root,
            )])
            .expect("root rewrite commits");
        assert!(!root.raw_eq(source));
        assert_eq!(
            heap.get_string_view(root)
                .expect("packed replacement resolves")
                .bytes(),
            b"packed"
        );

        let mut healed_roots = EvalRootSet::new();
        healed_roots
            .try_push_value_stack(0, root)
            .expect("healed root allocates");
        let healed_scan = heap
            .scan_precise_roots(&healed_roots)
            .expect("healed graph scans");
        let audited = heap
            .audit_packed_source_aliases(&healed_scan, published)
            .expect("healed graph has no source aliases");
        let report = heap
            .retire_published_packed_source(audited)
            .expect("audited source retires");
        assert_eq!(report.moved_objects(), 1);
        assert_eq!(report.immutable.retired_objects, 1);
        assert!(heap.get_string(source).is_err());
        assert_eq!(
            heap.get_string_view(root)
                .expect("packed replacement remains live")
                .bytes(),
            b"packed"
        );
    }

    #[test]
    fn source_alias_audit_failure_preserves_source_storage() {
        let mut heap = EvalHeap::new();
        let source = heap
            .alloc_string(NixString::from_bytes(b"retained".to_vec()))
            .expect("source allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, source)
            .expect("root allocates");
        let scan = heap.scan_precise_roots(&roots).expect("source scans");
        let prepared = heap
            .prepare_packed_publication(&scan, PackedRotationAdmissionInput::default())
            .expect("publication prepares");
        let commit = heap
            .publish_prepared_packed(prepared)
            .expect("heap publication commits");
        let (published, _root_plan) = commit.into_parts();

        let failure = heap
            .audit_packed_source_aliases(&scan, published)
            .expect_err("stale source root blocks retirement");
        assert_eq!(failure.residual_aliases(), 1);
        assert_eq!(
            heap.get_string(source)
                .expect("source remains live after audit failure")
                .bytes(),
            b"retained"
        );
        drop(failure.into_published());
    }
}
