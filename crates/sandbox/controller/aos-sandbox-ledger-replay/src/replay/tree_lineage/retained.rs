//! Retains the same closed Tree/lineage replay at its actual failure frontiers.
//!
//! The projection, typed row, partially consumed project maps and canonical
//! commitment backing stay beside the same Source observation. These owners
//! are inert DATA; only the actual Source original admits their receiving cost.

use std::collections::btree_map::IntoIter;
use std::mem::{size_of, take};

use aos_sandbox_protocol::domain_ledger::records::{
    ReducerPayloadDecodeCaptureV1, ReplayProjectionRecordsCaptureV1,
    decode_reducer_payload_with_schema_capture_v1, replay_projection_records_with_schema_capture_v1,
};

use super::*;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use crate::hierarchy::codec::{
    HierarchyCodecError, TreeDecodeOriginalsV1, decode_tree_retaining_v1, encode_tree_v1,
    CanonicalEncodingOriginalsV1, encode_tree_retaining_v1,
};

#[derive(Clone, Copy)]
/// Copies the exact saved revision, predecessor and envelope commitment.
pub struct RecordCut {
    revision: u64,
    predecessor: Option<ObjectDigest>,
    digest: ObjectDigest,
}

impl RecordCut {
    fn from_record(record: &crate::replay::hierarchy_records::HierarchyProtectedJournalEnvelopeV1) -> Self {
        Self { revision: record.revision(), predecessor: record.predecessor(), digest: record.digest() }
    }
}

type Trees = BTreeMap<ProjectId, (SandboxTreeV1, RecordCut)>;
type Links = BTreeMap<ProjectId, Vec<(ClosedTreeLineageRecordV1, ObjectDigest)>>;
type Heads = BTreeMap<ProjectId, ClosedTreeLineageHeadV1>;

struct ActiveProject {
    project: ProjectId,
    tree: Option<SandboxTreeV1>,
    record: RecordCut,
    links: Option<Vec<(ClosedTreeLineageRecordV1, ObjectDigest)>>,
    commitment_bytes: Option<CanonicalEncodingOriginalsV1>,
    commitment: Option<ObjectDigest>,
}

/// Keeps partial graph work in the same order as the ordinary local owners.
/// Keeps the same partial row maps and canonical Tree/Lineage work.
///
/// The error parameter preserves the native caller's original classification;
/// it supplies no schema, callback, native handle or role authority.
pub struct LineageWork<H = DomainLedgerDataError> {
    row_payload: Option<ReducerPayloadDecodeCaptureV1>,
    schema: crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1,
    schema_lineage_error: Option<H>,
    row_lineage: Option<LineageDecodeOriginalsV1<H>>,
    pending_lineage: Option<ClosedTreeLineageRecordV1>,
    row_tree: Option<TreeDecodeOriginalsV1>,
    pending_tree: Option<SandboxTreeV1>,
    replaced_tree: Option<(SandboxTreeV1, RecordCut)>,
    active: Option<ActiveProject>,
    remaining: Option<IntoIter<ProjectId, (SandboxTreeV1, RecordCut)>>,
    current: Heads,
    paired_heads: BTreeMap<ObjectDigest, ObjectDigest>,
    links: Links,
    trees: Trees,
}

impl<H: From<DomainLedgerDataError> + std::error::Error + 'static> LineageWork<H> {
    /// Creates an inert, unentered saved-work owner.
    pub fn new() -> Self {
        Self {
            row_payload: None, schema: crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::new(), schema_lineage_error: None,
            row_lineage: None, pending_lineage: None, row_tree: None, pending_tree: None, replaced_tree: None,
            active: None, remaining: None, current: BTreeMap::new(),
            paired_heads: BTreeMap::new(), links: BTreeMap::new(), trees: BTreeMap::new(),
        }
    }

    /// Moves the current heads after the caller has completed validation.
    pub fn take_completed_heads(&mut self) -> Heads {
        take(&mut self.current)
    }

    /// Borrows the first reached original parser or commitment failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.schema.failure()
            .or_else(|| self.schema_lineage_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.row_lineage.as_ref().and_then(|lineage| lineage.failure()))
            .or_else(|| self.row_payload.as_ref().and_then(|payload| payload.failure()).map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.row_tree.as_ref().and_then(|tree| tree.failure()))
            .or_else(|| self.active.as_ref()
                .and_then(|active| active.commitment_bytes.as_ref())
                .and_then(|encoding| encoding.failure()))
    }

    /// Returns the existing bounded fixed work footprint.
    pub fn receiving_fixed_footprint_v1() -> Option<(usize, usize)> {
        let bytes = size_of::<H>()
            .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>())?
            .checked_add(TreeDecodeOriginalsV1::receiving_construction_bytes_v1()?)?
            .checked_add(ReducerPayloadDecodeCaptureV1::receiving_construction_bytes_v1()?)?
            .checked_add(crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::receiving_fixed_bytes_v1()?)?
            .checked_add(size_of::<LineageDecodeOriginalsV1<H>>().checked_mul(2)?)?
            .checked_add(CanonicalEncodingOriginalsV1::fixed_footprint_v1()?.0)?;
        // 13 work fields, 6 active fields, 3 RecordCut fields, actual typed
        // schema/Tree/reducer/lineage destinations, excluding dynamic nodes.
        let cells = 13usize.checked_add(6 + 3)?
            .checked_add(TreeDecodeOriginalsV1::receiving_metadata_cells_v1()?)?
            .checked_add(ReducerPayloadDecodeCaptureV1::receiving_metadata_cells_v1())?
            .checked_add(crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::receiving_fixed_cells_v1()?)?
            .checked_add(LineageDecodeOriginalsV1::<H>::receiving_metadata_cells_v1())?
            .checked_add(CanonicalEncodingOriginalsV1::fixed_footprint_v1()?.1)?;
        Some((bytes, cells))
    }

    /// Releases local scratch at the original ordinary cleanup boundaries.
    ///
    /// # Errors
    /// Rejects malformed or repeated work, or an overflowing receiving bound.
    pub fn into_ordinary(mut self, result: Result<(), H>)
        -> Result<Heads, H>
    {
        // Old locals close at their original complete row/project boundaries.
        // Selected work uses the same engine but keeps these destinations.
        drop(self.row_payload.take());
        drop(self.row_lineage.take());
        drop(self.pending_lineage.take());
        drop(self.row_tree.take());
        drop(self.pending_tree.take());
        drop(self.replaced_tree.take());
        if let Some(mut active) = self.active.take() {
            // The old loop's project_links local drops before its bound Tree.
            // Selected errors keep the whole active owner instead of entering
            // this immediate ordinary-result adapter.
            drop(active.links.take());
            drop(active.tree.take());
            drop(active);
        }
        drop(self.remaining.take());
        match result {
            Ok(()) => Ok(take(&mut self.current)),
            Err(error) => Err(error),
        }
    }
}

fn invalid<H: From<DomainLedgerDataError>>() -> H {
    DomainLedgerDataError::NonCanonicalRecord.into()
}

/// Runs the original row ordering, pair join and contiguous lineage checks.
/// Checks the complete saved Tree/Lineage projection in the original order.
///
/// # Errors
/// Rejects malformed or repeated work, or an overflowing receiving bound.
pub fn verify_projection<H: From<DomainLedgerDataError> + std::error::Error + 'static>(
    projection: &HierarchyProtectedJournalProjectionV1,
    validator: &HierarchyProtectedReplayValidatorV1,
    work: &mut LineageWork<H>,
    retaining: bool,
) -> Result<(), H> {
    for record in projection.records() {
        let kind = record.key().kind();
        if !matches!(kind, HierarchyProtectedRecordKindV1::Tree | HierarchyProtectedRecordKindV1::TreeLineage) {
            continue;
        }
        let payload;
        let ordinary;
        if retaining {
            work.row_payload = Some(ReducerPayloadDecodeCaptureV1::new());
            let capture = work.row_payload.as_mut().ok_or_else(invalid::<H>)?;
            let decoded = decode_reducer_payload_with_schema_capture_v1::<HierarchyProtectedJournalSchemaV1>(
                record.key(), record.payload(), validator, capture, &mut work.schema,
            );
            // Preserve the actual Native diagnostic type before propagation;
            // the same failed codec keeps its partial record/backing resident.
            work.schema_lineage_error = work.schema.take_lineage_failure_once()
                .map(H::from);
            decoded?;
            payload = record.payload().get(capture.body_range_v1().ok_or_else(invalid::<H>)?)
                .ok_or_else(invalid::<H>)?;
        } else {
            ordinary = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
                record.key(), record.payload(), validator,
            )?;
            payload = ordinary.body();
        }
        match kind {
            HierarchyProtectedRecordKindV1::Tree => {
                work.pending_tree = if retaining {
                    work.row_tree = Some(TreeDecodeOriginalsV1::new());
                    let capture = work.row_tree.as_mut().ok_or_else(invalid::<H>)?;
                    decode_tree_retaining_v1(payload, capture).map_err(|_| invalid::<H>())?;
                    Some(capture.take_tree_once().map_err(|_| invalid::<H>())?)
                } else {
                    Some(decode_tree_v1(payload).map_err(|_| invalid::<H>())?)
                };
                if record.revision() != work.pending_tree.as_ref().ok_or_else(invalid::<H>)?.tree_generation().get() {
                    if !retaining { drop(work.pending_tree.take()); }
                    return Err(invalid::<H>());
                }
                let tree = work.pending_tree.take().ok_or_else(invalid::<H>)?;
                work.replaced_tree = work.trees.insert(tree.project(), (tree, RecordCut::from_record(record)));
                if work.replaced_tree.is_some() {
                    // Ordinary insert().is_some() disposes the replaced value
                    // before returning and before the row payload local drops.
                    if !retaining { drop(work.replaced_tree.take()); }
                    return Err(invalid::<H>());
                }
            }
            HierarchyProtectedRecordKindV1::TreeLineage => {
                work.pending_lineage = if retaining {
                    work.row_lineage = Some(LineageDecodeOriginalsV1::new());
                    decode_lineage_retaining_v1(payload, work.row_lineage.as_mut().ok_or_else(invalid::<H>)?)
                } else { decode_closed_tree_lineage_v1(payload) };
                if work.pending_lineage.is_none() { return Err(invalid::<H>()); }
                if record.revision() != 1 || record.predecessor().is_some() { return Err(invalid::<H>()); }
                let link = work.pending_lineage.take().ok_or_else(invalid::<H>)?;
                work.links.entry(link.project).or_default().push((link, record.digest()));
            }
            _ => return Err(invalid::<H>()),
        }
        // The complete typed row has moved into its persistent map. No later
        // operation borrows successful row scratch; failures never reach here.
        drop(work.row_lineage.take());
        drop(work.row_tree.take());
        drop(work.row_payload.take());
    }

    work.paired_heads = projection.transactions().iter().filter(|transaction| {
        transaction.phase() == HierarchyJournalReplayPhaseV1::Observed
            && transaction.records().len() == 2
            && transaction.records()[0].key().kind() == HierarchyProtectedRecordKindV1::Tree
            && transaction.records()[1].key().kind() == HierarchyProtectedRecordKindV1::TreeLineage
    }).map(|transaction| (transaction.records()[0].digest(), transaction.records()[1].digest()))
        .collect();

    work.remaining = Some(take(&mut work.trees).into_iter());
    while let Some((project, (tree, record))) = work.remaining.as_mut().and_then(Iterator::next) {
        work.active = Some(ActiveProject {
            project, tree: Some(tree), record, links: None, commitment_bytes: None, commitment: None,
        });
        let active = work.active.as_mut().ok_or_else(invalid::<H>)?;
        active.links = Some(work.links.remove(&project).ok_or_else(invalid::<H>)?);
        let project_links = active.links.as_mut().ok_or_else(invalid::<H>)?;
        project_links.sort_by_key(|(link, _)| link.generation);
        let tree = active.tree.as_ref().ok_or_else(invalid::<H>)?;
        if project_links.len() as u64 != tree.tree_generation().get() { return Err(invalid::<H>()); }
        let mut prior_tree_head = None;
        let mut prior_lineage_head = None;
        let mut initial_limits = None;
        for (index, (link, lineage_head)) in project_links.iter().enumerate() {
            if link.generation != index as u64 + 1 || link.prior_tree_head != prior_tree_head
                || link.prior_lineage_head != prior_lineage_head {
                return Err(invalid::<H>());
            }
            if let Some(packet) = &link.initial_seed_packet {
                initial_limits = Some(seed_claims(packet).ok_or_else(invalid::<H>)?.limits());
            }
            prior_tree_head = Some(link.tree_head);
            prior_lineage_head = Some(*lineage_head);
        }
        let (last, lineage_head) = project_links.last().ok_or_else(invalid::<H>)?;
        if last.tree_head != record.digest || last.prior_tree_head != record.predecessor {
            return Err(invalid::<H>());
        }
        let commitment = if retaining {
            active.commitment_bytes = Some(CanonicalEncodingOriginalsV1::new());
            let encoding = active.commitment_bytes.as_mut().ok_or_else(invalid::<H>)?;
            encode_tree_retaining_v1(tree, encoding).map_err(|_| invalid::<H>())?;
            let bytes = encoding.bytes().ok_or_else(invalid::<H>)?;
            let digest = crate::hierarchy::codec::tree_commitment_from_bytes_v1(bytes);
            active.commitment = Some(digest);
            digest
        } else {
            tree_commitment_v1(tree).map_err(|_| invalid::<H>())?
        };
        if last.tree_commitment != commitment || initial_limits != Some(tree.limits())
            || tree.tree_generation().get() == 1
                && (tree.records().next().is_some() || tree.tombstones().next().is_some()) {
            return Err(invalid::<H>());
        }
        if work.paired_heads.get(&record.digest) != Some(lineage_head) { return Err(invalid::<H>()); }
        let seed = project_links.first().and_then(|(link, _)| link.initial_seed_packet).ok_or_else(invalid::<H>)?;
        work.current.insert(project, ClosedTreeLineageHeadV1 {
            tree: active.tree.take().ok_or_else(invalid::<H>)?, tree_head: record.digest,
            lineage_head: *lineage_head, initial_seed_packet: seed,
        });
        // Exact tree/lineage/pair equality has completed. The current map owns
        // the persistent tree; canonical scratch and consumed links can drop.
        drop(work.active.take());
    }
    // The old for-loop drops its exhausted IntoIter before the final links
    // check. All consumed persistent trees already live in the current map.
    drop(work.remaining.take());
    if !work.links.is_empty() { return Err(invalid::<H>()); }
    Ok(())
}

/// Copies only the actual completed Source tree comparison tuple.
#[derive(Clone, Copy)]
pub struct SourceCurrentTreeDataV1 {
    /// Holds the saved Tree record revision.
    pub revision: u64,
    /// Holds the saved Tree generation.
    pub generation: u64,
    /// Holds the committed Tree envelope digest.
    pub tree_head: ObjectDigest,
    /// Holds the committed lineage envelope digest.
    pub lineage_head: ObjectDigest,
    /// Holds the canonical current Tree commitment.
    pub commitment: ObjectDigest,
}

/// Retains the actual portable projection and reached matching-project work.
///
/// Full native validation precedes this narrower purpose. Its saved result
/// cannot replace that preceding validation or authorize Source currentness.
pub struct SourceCurrentTreeOriginalsV1<H = DomainLedgerDataError> {
    validator: Option<Result<HierarchyProtectedReplayValidatorV1, H>>,
    projection: ReplayProjectionRecordsCaptureV1<HierarchyProtectedJournalSchemaV1>,
    schema: crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1,
    schema_lineage_error: Option<H>,
    work: LineageWork<H>,
    result: Option<Result<(), H>>,
    selected: Option<Result<SourceCurrentTreeDataV1, H>>,
    selected_encoding: Option<CanonicalEncodingOriginalsV1>,
    closed: bool,
}

impl<H: From<DomainLedgerDataError> + std::error::Error + 'static> SourceCurrentTreeOriginalsV1<H> {
    /// Creates an inert, unentered saved-work owner.
    pub fn new() -> Self {
        Self { validator: None, projection: ReplayProjectionRecordsCaptureV1::new(), schema: crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::new(), schema_lineage_error: None, work: LineageWork::new(),
            result: None, selected: None, selected_encoding: None, closed: false }
    }

    /// Checks only the selected project through the same canonical replay engines.
    ///
    /// # Errors
    /// Rejects malformed or repeated work, or an overflowing receiving bound.
    pub fn observe_once<'records>(
        &mut self, records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>, project: ProjectId,
    ) -> Result<(), ()> {
        if self.validator.is_some() || self.closed { self.closed = true; return Err(()); }
        self.validator = Some(HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])
            .map_err(H::from));
        let validator = self.validator.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        self.result = Some(replay_projection_records_with_schema_capture_v1::<HierarchyProtectedJournalSchemaV1>(
            records.filter(|(namespace, key, _)| matching_project_tree_row(*namespace, key, project)),
            validator, &mut self.projection, &mut self.schema,
        ).map_err(H::from).and_then(|()| {
            verify_projection(self.projection.projection().ok_or_else(invalid::<H>)?, validator, &mut self.work, true)
        }));
        self.schema_lineage_error = self.schema.take_lineage_failure_once()
            .map(H::from);
        if !matches!(self.result, Some(Ok(()))) { return Err(()); }
        self.selected = Some((|| {
            let head = self.work.current.get(&project).ok_or_else(invalid::<H>)?;
            if head.tree.tree_generation().get() != 1 || head.tree.records().next().is_some()
                || head.tree.tombstones().next().is_some() { return Err(invalid::<H>()); }
            self.selected_encoding = Some(CanonicalEncodingOriginalsV1::new());
            let encoding = self.selected_encoding.as_mut().ok_or_else(invalid::<H>)?;
            encode_tree_retaining_v1(&head.tree, encoding).map_err(|_| invalid::<H>())?;
            let bytes = encoding.bytes().ok_or_else(invalid::<H>)?;
            let record = self.projection.projection().ok_or_else(invalid::<H>)?.records().iter().find(|record| {
                record.key().kind() == HierarchyProtectedRecordKindV1::Tree
                    && record.digest() == head.tree_head
            }).ok_or_else(invalid::<H>)?;
            Ok(SourceCurrentTreeDataV1 { revision: record.revision(), generation: head.tree.tree_generation().get(),
                tree_head: head.tree_head, lineage_head: head.lineage_head,
                commitment: crate::hierarchy::codec::tree_commitment_from_bytes_v1(bytes) })
        })());
        if matches!(self.selected, Some(Ok(_))) { Ok(()) } else { Err(()) }
    }

    /// Copies the completed comparison tuple when this owner remains open.
    pub fn value(&self) -> Option<SourceCurrentTreeDataV1> {
        if self.closed { None } else { self.selected.as_ref()?.as_ref().ok().copied() }
    }

    /// Borrows the first reached original parser or commitment failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.validator.as_ref().and_then(|result| result.as_ref().err()) { return Some(error); }
        if let Some(error) = self.schema.failure() { return Some(error); }
        if let Some(error) = self.schema_lineage_error.as_ref() { return Some(error); }
        if let Some(error) = self.work.schema.failure() { return Some(error); }
        if let Some(error) = self.work.schema_lineage_error.as_ref() { return Some(error); }
        if let Some(error) = self.work.row_lineage.as_ref().and_then(|lineage| lineage.failure()) { return Some(error); }
        if let Some(error) = self.projection.failure() { return Some(error); }
        if let Some(error) = self.work.row_payload.as_ref().and_then(|capture| capture.failure()) { return Some(error); }
        if let Some(error) = self.work.row_tree.as_ref().and_then(|capture| capture.failure()) { return Some(error); }
        self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
            .or_else(|| self.selected_encoding.as_ref().and_then(|encoding| encoding.failure()))
            .or_else(|| self.selected.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }

    /// Computes bounded demand from the actual matching raw rows.
    ///
    /// # Errors
    /// Rejects malformed or repeated work, or an overflowing receiving bound.
    pub fn receiving_dynamic_demand_v1<'rows>(
        rows: impl Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
        project: ProjectId,
    ) -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let overflow = || aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::LimitExceeded("Source17 actual project replay geometry");
        let mut count = 0_usize;
        let mut encoded = 0_usize;
        let mut typed_bytes = 0_usize;
        let mut typed_cells = 0_usize;
        for (namespace, key, value) in rows {
            if !matching_project_tree_row(namespace, key, project) { continue; }
            count = count.checked_add(1).ok_or_else(overflow)?;
            encoded = encoded.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(overflow)?;
            if key.get(b"\0aos-hierarchy-v1\0".len() + 1) == Some(&1) {
                // This upper bound uses actual held enclosing bytes. The same
                // decoder checks complete advertised widths before reserving.
                let (bytes, cells) = TreeDecodeOriginalsV1::receiving_dynamic_footprint_v1(value.len()).ok_or_else(overflow)?;
                typed_bytes = typed_bytes.checked_add(bytes).ok_or_else(overflow)?;
                typed_cells = typed_cells.checked_add(cells).ok_or_else(overflow)?;
            }
        }
        let carrier = size_of::<(ProjectId, SandboxTreeV1, RecordCut, [usize; 3])>()
            .checked_add(size_of::<(ProjectId, ClosedTreeLineageRecordV1, ObjectDigest, [usize; 3])>())
            .and_then(|bytes| bytes.checked_add(size_of::<(ObjectDigest, ObjectDigest, [usize; 3])>()))
            .and_then(|bytes| bytes.checked_add(size_of::<(ProjectId, ClosedTreeLineageHeadV1, [usize; 3])>()))
            .ok_or_else(overflow)?;
        // Persistent row maps, current output, pair join, consumed iterator,
        // active/replaced row and growing link vector coexist by actual row.
        let maps = carrier.checked_mul(count.max(4)).and_then(|bytes| bytes.checked_mul(3)).ok_or_else(overflow)?;
        let bytes = ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_carrier_bytes_v1(count)
            .and_then(|bytes| bytes.checked_add(ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_encoded_backing_bytes_v1(encoded)?))
            .and_then(|bytes| bytes.checked_add(typed_bytes))
            .and_then(|bytes| bytes.checked_add(maps))
            .and_then(|bytes| bytes.checked_add(encoded.checked_mul(3)?)).ok_or_else(overflow)?;
        let cells = ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_metadata_cells_v1(count)
            .and_then(|cells| cells.checked_add(typed_cells))
            .and_then(|cells| cells.checked_add(count.checked_mul(12)?)).ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| overflow())?))
    }

    /// Returns the actual fixed construction peak for this diagnostic type.
    pub fn receiving_fixed_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<H>())?
            .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>())?
            .checked_add(TreeDecodeOriginalsV1::receiving_construction_bytes_v1()?)?
            .checked_add(ReducerPayloadDecodeCaptureV1::receiving_construction_bytes_v1()?)?
            .checked_add(ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_construction_bytes_v1()?)?
            .checked_add(crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::receiving_fixed_bytes_v1()?.checked_mul(2)?)?
            .checked_add(CanonicalEncodingOriginalsV1::fixed_footprint_v1()?.0.checked_mul(2)?)
    }

    /// Returns the existing fixed footprint helper without changing its policy.
    pub fn receiving_fixed_cells_v1() -> Option<usize> {
        // Eight outer fields, thirteen work destinations, six active project fields,
        // five selected tuple fields and the active RecordCut's three fields,
        // and the two inner once decoders coexist. Row/map cells remain in
        // the actual matching-family supplier, independently of these bytes.
        8_usize.checked_add(13)?.checked_add(6)?.checked_add(5)?.checked_add(3)?
            .checked_add(ReducerPayloadDecodeCaptureV1::receiving_metadata_cells_v1())?
            .checked_add(TreeDecodeOriginalsV1::receiving_metadata_cells_v1()?)?
            .checked_add(crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1::receiving_fixed_cells_v1()?.checked_mul(2)?)?
            .checked_add(LineageDecodeOriginalsV1::<H>::receiving_metadata_cells_v1())?
            .checked_add(CanonicalEncodingOriginalsV1::fixed_footprint_v1()?.1.checked_mul(2)?)
    }
}

/// Bounds the named collections reached by complete saved Tree/Lineage replay.
///
/// This allocation-free recipe walks the same borrowed input rows before the
/// canonical replay grows its projection, typed models or lookup indices. It
/// neither decodes a header nor validates any row. Encoded extents bound the
/// sole Tree and History decoders' checked cardinalities, including malformed
/// prefixes. Rust fields, result destinations and buffer capacity add no fee.
///
/// # Errors
/// Returns the mechanical geometry refusal if a named cardinality overflows.
pub fn closed_tree_lineage_named_entries_v2<'rows>(
    rows: impl Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
) -> Result<u64, aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1> {
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1 as _;

    let overflow = || aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::LimitExceeded(
        "complete Tree/Lineage named collections",
    );
    let prefix = HierarchyProtectedJournalSchemaV1::KEY_PREFIX;
    let mut projection_rows = 0usize;
    let mut trees = 0usize;
    let mut links = 0usize;
    let mut typed = 0usize;
    for (_, key, value) in rows {
        // The portable replay tests this same prefix before key decoding and
        // namespace validation. Foreign namespaces cannot evade prepayment.
        if !key.starts_with(prefix) {
            continue;
        }
        projection_rows = projection_rows.checked_add(1).ok_or_else(overflow)?;
        match key.get(prefix.len() + 1) {
            Some(1) => {
                trees = trees.checked_add(1).ok_or_else(overflow)?;
                typed = typed.checked_add(TreeDecodeOriginalsV1::receiving_named_entries_v2(value.len())
                    .ok_or_else(overflow)?).ok_or_else(overflow)?;
            }
            Some(2) => {
                typed = typed.checked_add(crate::hierarchy::codec::history_receiving_named_entries_v2(value.len())
                    .ok_or_else(overflow)?).ok_or_else(overflow)?;
            }
            Some(7) => links = links.checked_add(1).ok_or_else(overflow)?,
            _ => {}
        }
    }

    // Trees/consumed iterator, paired heads and completed heads are three
    // project-keyed planes, each bounded by actual Tree rows. Per-project link
    // maps and their durable link rows are two planes bounded by Lineage rows.
    let lineage = trees.checked_mul(3)
        .and_then(|entries| entries.checked_add(links.checked_mul(2)?))
        .ok_or_else(overflow)?;
    let projection = ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_named_entries_v2(projection_rows)
        .ok_or_else(overflow)?;
    let entries = projection.checked_add(typed)
        .and_then(|entries| entries.checked_add(lineage)).ok_or_else(overflow)?;
    u64::try_from(entries).map_err(|_| overflow())
}

// This is a purpose selector over borrowed raw keys, not canonical acceptance.
// Native full replay has already completed; included keys/envelopes/grouping
// still pass the same canonical portable and typed schema engines above.
/// Selects only the named project's canonical Tree and Lineage key families.
///
/// This inert filter shares the same selected-project recipe for empty Create
/// and full Delete comparisons; the caller still runs the complete saved fold.
pub fn matching_project_tree_row(namespace: RecordNamespace, key: &[u8], project: ProjectId) -> bool {
    const PREFIX: &[u8] = b"\0aos-hierarchy-v1\0";
    namespace == RecordNamespace::DesiredState && key.starts_with(PREFIX)
        && matches!(key.get(PREFIX.len() + 1), Some(1 | 7))
        && key.get(PREFIX.len() + 4..PREFIX.len() + 20) == Some(project.as_bytes().as_slice())
}

use crate::replay::hierarchy_records::lineage::decode_lineage_retaining_v1;
type LineageDecodeOriginalsV1<H> = crate::replay::hierarchy_records::lineage::LineageDecodeOriginalsV1<H>;
