//! Owns complete, unfiltered Source lineage replay and its enclosing family join.
//!
//! The closed Source receiving owner pays these DATA destinations. The same
//! portable replay and typed lineage engines run here; no matching-project
//! iterator, fresh reader or successful parser result supplies authority.

use super::*;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::records::{
    ReplayProjectionRecordsCaptureV1,
    replay_projection_records_with_schema_capture_v1,
    DomainKeyDecodeCaptureV1, DurableMemberCaptureV1,
    decode_domain_key_retaining_v1, decode_durable_member_with_schema_capture_v1,
};
use crate::replay::source_tree_genesis::{SourceGenesisRowsV1};
use crate::replay::source_tree_genesis::SourceGenesisRowsOriginalsV1;
use crate::replay::hierarchy_records::SourceTreeSchemaOriginalsV1;

type Heads = BTreeMap<ProjectId, ClosedTreeLineageHeadV1>;
type Reconstructed = (ObjectDigest, ObjectDigest, Vec<u8>, Vec<u8>);

pub struct CompleteLineageOriginalsV1<H = DomainLedgerDataError> {
    validator: Option<Result<HierarchyProtectedReplayValidatorV1, H>>,
    projection: ReplayProjectionRecordsCaptureV1<HierarchyProtectedJournalSchemaV1>,
    schema: SourceTreeSchemaOriginalsV1,
    schema_lineage_error: Option<H>,
    work: retained::LineageWork<H>,
    outcome: Option<Result<(), H>>,
    closed: Option<H>,
    taken: bool,
}

impl<H: From<DomainLedgerDataError> + std::error::Error + 'static> CompleteLineageOriginalsV1<H> {
    pub fn empty() -> Self {
        Self {
            validator: None,
            projection: ReplayProjectionRecordsCaptureV1::new(),
            schema: SourceTreeSchemaOriginalsV1::new(),
            schema_lineage_error: None,
            work: retained::LineageWork::new(),
            outcome: None,
            closed: None,
            taken: false,
        }
    }

    pub fn observe_once<'records>(
        &mut self,
        records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    ) -> Result<(), H> {
        if self.validator.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(H::from(DomainLedgerDataError::NonCanonicalRecord));
            return Err(H::from(DomainLedgerDataError::NonCanonicalRecord));
        }
        self.validator = Some(HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])
            .map_err(H::from));
        let validator = self.validator.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(H::from(DomainLedgerDataError::NonCanonicalRecord))?;
        self.outcome = Some(replay_projection_records_with_schema_capture_v1::<HierarchyProtectedJournalSchemaV1>(
            records, validator, &mut self.projection, &mut self.schema,
        ).map_err(H::from).and_then(|()| {
            retained::verify_projection(
                self.projection.projection().ok_or(H::from(DomainLedgerDataError::NonCanonicalRecord))?,
                validator, &mut self.work, true,
            )
        }));
        self.schema_lineage_error = self.schema.take_lineage_failure_once()
            .map(H::from);
        match &self.outcome {
            Some(Ok(())) => Ok(()),
            _ => Err(H::from(DomainLedgerDataError::NonCanonicalRecord)),
        }
    }

    pub fn take_heads_once(&mut self) -> Result<Heads, H> {
        if self.taken || self.failure().is_some() || !matches!(self.outcome, Some(Ok(()))) {
            self.closed.get_or_insert(H::from(DomainLedgerDataError::NonCanonicalRecord));
            return Err(H::from(DomainLedgerDataError::NonCanonicalRecord));
        }
        self.taken = true;
        Ok(self.work.take_completed_heads())
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.validator.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.schema.failure())
            .or_else(|| self.schema_lineage_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.projection.failure().map(|cause| cause as _))
            .or_else(|| self.work.failure())
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (work_bytes, work_cells) = retained::LineageWork::<H>::receiving_fixed_footprint_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<H>())?
            .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>())?
            .checked_add(ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_construction_bytes_v1()?)?
            .checked_add(SourceTreeSchemaOriginalsV1::receiving_fixed_bytes_v1()?)?
            .checked_add(work_bytes)?;
        let cells = 7usize.checked_add(work_cells)?
            .checked_add(ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_metadata_cells_v1(0)?)?
            .checked_add(SourceTreeSchemaOriginalsV1::receiving_fixed_cells_v1()?)?;
        Some((bytes, cells))
    }
}

// Two actual proposed members, retained through their enclosing COMMIT.
pub struct SourceAppendedPairOriginalsV1<H = DomainLedgerDataError> {
    keys: [DomainKeyDecodeCaptureV1<HierarchyProtectedJournalSchemaV1>; 2],
    members: [DurableMemberCaptureV1<HierarchyProtectedJournalSchemaV1>; 2],
    schemas: [SourceTreeSchemaOriginalsV1; 2],
    schema_lineage_errors: [Option<H>; 2],
}

impl<H: From<DomainLedgerDataError> + std::error::Error + 'static> SourceAppendedPairOriginalsV1<H> {
    pub fn new() -> Self {
        Self { keys: std::array::from_fn(|_| DomainKeyDecodeCaptureV1::new()),
            members: std::array::from_fn(|_| DurableMemberCaptureV1::new()),
            schemas: std::array::from_fn(|_| SourceTreeSchemaOriginalsV1::new()),
            schema_lineage_errors: [None, None] }
    }

    pub fn observe_member_once(&mut self, index: usize, record: &JournalRecord,
        validator: &HierarchyProtectedReplayValidatorV1,
    ) -> Result<&aos_sandbox_protocol::domain_ledger::records::DurableDomainMemberV1<HierarchyProtectedJournalSchemaV1>, JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        let key_capture = self.keys.get_mut(index).ok_or_else(invalid)?;
        decode_domain_key_retaining_v1(record.key(), key_capture).map_err(|_| invalid())?;
        let key = key_capture.take_key_once().ok_or_else(invalid)?;
        let capture = self.members.get_mut(index).ok_or_else(invalid)?;
        let schema = self.schemas.get_mut(index).ok_or_else(invalid)?;
        let decoded = decode_durable_member_with_schema_capture_v1(key, record.value().ok_or_else(invalid)?,
            validator, capture, schema);
        // The actual Native error is parked before the ordinary coarse return.
        let projected = self.schema_lineage_errors.get_mut(index).ok_or_else(invalid)?;
        *projected = schema.take_lineage_failure_once().map(H::from);
        decoded.map_err(|_| invalid())?;
        capture.member().ok_or_else(invalid)
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for index in 0..2 {
            if let Some(cause) = self.keys[index].failure() { return Some(cause); }
            if let Some(cause) = self.schemas[index].failure() { return Some(cause); }
            if let Some(cause) = self.schema_lineage_errors[index].as_ref() { return Some(cause); }
            if let Some(cause) = self.members[index].failure() { return Some(cause); }
        }
        None
    }

    pub fn fixed_peak_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Key = DomainKeyDecodeCaptureV1<HierarchyProtectedJournalSchemaV1>;
        type Member = DurableMemberCaptureV1<HierarchyProtectedJournalSchemaV1>;
        let schema_bytes = SourceTreeSchemaOriginalsV1::receiving_fixed_bytes_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<H>())?
            .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>())?
            .checked_add(Key::receiving_construction_bytes_v1()?.checked_sub(size_of::<Key>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(Member::receiving_construction_bytes_v1()?.checked_sub(size_of::<Member>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(schema_bytes.checked_sub(size_of::<SourceTreeSchemaOriginalsV1>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(size_of::<Option<&mut Self>>())?
            .checked_add(size_of::<&JournalRecord>())?
            .checked_add(size_of::<&HierarchyProtectedReplayValidatorV1>())?
            .checked_add(size_of::<usize>())?;
        // The two portable decoder capsules do not install namespace entries.
        // Their fixed controls are covered by bytes; actual row/index/map
        // cardinality remains in the existing reached-row supplier.
        Some(bytes)
    }
}

pub struct SourceSuccessorMembersOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub appended: SourceAppendedPairOriginalsV1<H>,
    pub before: CompleteLineageOriginalsV1<H>,
    pub after: CompleteLineageOriginalsV1<H>,
    pub before_heads: Option<Heads>,
    pub heads: Option<Heads>,
    pub genesis_parser: SourceGenesisRowsOriginalsV1<E, R>,
    pub genesis: Option<SourceGenesisRowsV1>,
    pub reconstructed: Option<Reconstructed>,
    pub reconstruction_error: Option<H>,
    outcome: Option<Result<(), E>>,
    closed: Option<E>,
    entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceSuccessorMembersOriginalsV1<E, H, R> {
    pub fn new() -> Self {
        Self {
            appended: SourceAppendedPairOriginalsV1::new(),
            before: CompleteLineageOriginalsV1::empty(),
            after: CompleteLineageOriginalsV1::empty(),
            before_heads: None,
            heads: None,
            genesis_parser: SourceGenesisRowsOriginalsV1::new(),
            genesis: None,
            reconstructed: None,
            reconstruction_error: None,
            outcome: None,
            closed: None,
            entered: false,
        }
    }

    pub fn observe_once(
        &mut self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        recipe: SourceSuccessorMemberRecipe<'_>,
        appended_pair: Option<&[JournalRecord]>,
        parsed_genesis: Option<&SourceGenesisRowsV1>,
    ) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.outcome = Some(validate_source_successor_members_with_originals(
            state, recipe, appended_pair, parsed_genesis, Some(self),
        ));
        match &self.outcome {
            Some(Ok(())) => Ok(()),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure().or_else(|| self.appended.failure()).or_else(|| self.after.failure())
            .or_else(|| self.genesis_parser.cause())
            .or_else(|| self.reconstruction_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn receiving_dynamic_demand_v1<'rows>(
        rows: impl Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
    ) -> Result<aos_sandbox_core::ResourceVector, E> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use std::mem::size_of;

        let overflow = || E::from(JournalError::LimitExceeded("Source complete lineage geometry"));
        let mut count = 0usize;
        let mut encoded = 0usize;
        let mut member_keys = 0usize;
        let mut member_bytes = 0usize;
        let mut typed_bytes = 0usize;
        let mut typed_cells = 0usize;
        for (namespace, key, value) in rows {
            // The portable iterator sees the actual unfiltered Native rows.
            // Count them before that parser decides which envelope is present.
            count = count.checked_add(1).ok_or_else(overflow)?;
            encoded = encoded.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or_else(overflow)?;
            member_keys = member_keys.checked_add(key.len()).ok_or_else(overflow)?;
            member_bytes = member_bytes.checked_add(value.len()).ok_or_else(overflow)?;
            const PREFIX: &[u8] = b"\0aos-hierarchy-v1\0";
            if namespace == RecordNamespace::DesiredState && key.starts_with(PREFIX)
                && key.get(PREFIX.len() + 1) == Some(&1)
            {
                let (bytes, cells) = crate::hierarchy::codec::TreeDecodeOriginalsV1::receiving_dynamic_footprint_v1(value.len())
                    .ok_or_else(overflow)?;
                typed_bytes = typed_bytes.checked_add(bytes).ok_or_else(overflow)?;
                typed_cells = typed_cells.checked_add(cells).ok_or_else(overflow)?;
            }
        }
        fn nodes<T>(count: usize) -> Option<usize> {
            let node = size_of::<T>().checked_mul(11)?
                .checked_add(size_of::<usize>().checked_mul(12)?)?;
            node.checked_mul(count)
        }
        // Persistent trees, per-project links, paired heads and completed heads
        // are separate planes. A consumed IntoIter moves those same nodes.
        let maps = nodes::<(ProjectId, (SandboxTreeV1, retained::RecordCut))>(count)
            .and_then(|bytes| bytes.checked_add(nodes::<(ProjectId, Vec<(ClosedTreeLineageRecordV1, ObjectDigest)>)>(count)?))
            .and_then(|bytes| bytes.checked_add(nodes::<(ObjectDigest, ObjectDigest)>(count)?))
            .and_then(|bytes| bytes.checked_add(nodes::<(ProjectId, ClosedTreeLineageHeadV1)>(count)?))
            .ok_or_else(overflow)?;
        let links = count.checked_mul(4).and_then(|count| count.checked_mul(size_of::<(ClosedTreeLineageRecordV1, ObjectDigest)>()))
            .and_then(|bytes| bytes.checked_mul(3)).ok_or_else(overflow)?;
        let pair_sort = count.checked_add(4).and_then(|count| count.checked_mul(size_of::<(ObjectDigest, ObjectDigest)>()))
            .and_then(|bytes| bytes.checked_mul(3)).ok_or_else(overflow)?;
        let proposed_backing = DurableMemberCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_encoded_backing_bytes_v1(member_keys, member_bytes)
            .and_then(|bytes| bytes.checked_add(DomainKeyDecodeCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_encoded_backing_bytes_v1(member_keys)?))
            .and_then(|bytes| bytes.checked_add(typed_bytes)).ok_or_else(overflow)?;
        let bytes = ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_carrier_bytes_v1(count)
            .and_then(|bytes| bytes.checked_add(ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_encoded_backing_bytes_v1(encoded)?))
            .and_then(|bytes| bytes.checked_add(typed_bytes))
            .and_then(|bytes| bytes.checked_add(maps))
            .and_then(|bytes| bytes.checked_add(links))
            .and_then(|bytes| bytes.checked_add(pair_sort))
            .and_then(|bytes| bytes.checked_add(encoded.checked_mul(3)?))
            // The exact proposed-member recipe can retain both complete before
            // and after replays. No request counter or configured maximum is used.
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(proposed_backing)).ok_or_else(overflow)?;
        let cells = ReplayProjectionRecordsCaptureV1::<HierarchyProtectedJournalSchemaV1>::receiving_metadata_cells_v1(count)
            .and_then(|cells| cells.checked_add(typed_cells))
            .and_then(|cells| cells.checked_add(count.checked_mul(5)?))
            .and_then(|cells| cells.checked_mul(2))
            .and_then(|cells| cells.checked_add(typed_cells)).ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| overflow())?))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_core::bounded_codec::CaptureOnDropV1;
        use std::mem::size_of;

        let appended_bytes = SourceAppendedPairOriginalsV1::<H>::fixed_peak_bytes_v1()?;
        let (lineage_bytes, lineage_cells) = CompleteLineageOriginalsV1::<H>::fixed_footprint_v1()?;
        let (genesis_bytes, genesis_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(appended_bytes.checked_sub(size_of::<SourceAppendedPairOriginalsV1<H>>().checked_mul(2)?)?)?
            .checked_add(lineage_bytes.checked_sub(size_of::<CompleteLineageOriginalsV1<H>>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(genesis_bytes.checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, Heads>>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisRowsV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, Reconstructed>>())?;
        // The appended byte capsule adds no namespace entries. Existing
        // member-layer accounting continues separately below; four two-field
        // guards, two head roots, three genesis roots and two encoded vectors.
        let cells = 11usize.checked_add(lineage_cells.checked_mul(2)?)?
            .checked_add(genesis_cells)?.checked_add(8 + 2 + 3 + 2)?;
        Some((bytes, cells))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type CompleteLineageOriginalsV1 = super::CompleteLineageOriginalsV1<DomainLedgerDataError>;
    type SourceAppendedPairOriginalsV1 = super::SourceAppendedPairOriginalsV1<DomainLedgerDataError>;
    type SourceSuccessorMembersOriginalsV1 = super::SourceSuccessorMembersOriginalsV1<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>;

    use aos_sandbox_protocol::domain_ledger::records::{domain_transaction_set_digest, encode_durable_member};
    use aos_sandbox_protocol::controller_source_seed::sign_controller_source_tree_seed_v1;
    use ed25519_dalek::SigningKey;
    use aos_sandbox_core::source_tree_model::TreeLimitsV1;
    use aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedV1;

    pub(super) fn rows() -> BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        let mut rows = BTreeMap::new();
        for byte in [21, 22] {
            let project = ProjectId::from_bytes([byte; 16]);
            let limits = TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap();
            let seed = ControllerSourceTreeSeedV1::new(project, limits, 5,
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]), [byte; 16], 9).unwrap();
            let packet = sign_controller_source_tree_seed_v1(seed, 7, &SigningKey::from_bytes(&[41; 32])).unwrap();
            let tree = SandboxTreeV1::from_records(project, Revision::new(1), limits, Vec::new()).unwrap();
            let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
            let envelopes = source_tree_pair_envelopes(&tree, None, None, Some(packet), &validator).unwrap();
            let set = domain_transaction_set_digest([byte; 16], &envelopes);
            for (index, envelope) in envelopes.into_iter().enumerate() {
                let member = encode_durable_member([byte; 16], index as u16, 2, set, envelope).unwrap();
                rows.insert((RecordNamespace::DesiredState, member.envelope().key().as_bytes().to_vec()),
                    member.encoded().to_vec());
            }
        }
        rows
    }

    #[test]
    fn complete_lineage_replay_keeps_both_actual_projects_without_filtering() {
        let rows = rows();
        let ordinary = replay_closed_tree_lineage_state_v2(&rows).unwrap();
        let mut originals = CompleteLineageOriginalsV1::empty();
        originals.observe_once(rows.iter().map(|((namespace, key), value)|
            (*namespace, key.as_slice(), value.as_slice()))).unwrap();
        let heads = originals.take_heads_once().unwrap();

        assert_eq!(heads.len(), 2);
        for (project, expected) in &ordinary {
            let actual = heads.get(project).unwrap();
            assert_eq!(actual.tree_head, expected.tree_head);
            assert_eq!(actual.lineage_head, expected.lineage_head);
        }
        assert_eq!(originals.projection.projection().unwrap().records().len(), 4);
        assert!(originals.take_heads_once().is_err());
    }

    #[test]
    fn later_genesis_join_refusal_keeps_the_whole_completed_heads_and_projection() {
        let rows = rows();
        let receipts = BTreeMap::new();
        let mut originals = SourceSuccessorMembersOriginalsV1::new();
        assert!(originals.observe_once(&rows,
            SourceSuccessorMemberRecipe::MixedProjectsV3 { receipts: &receipts, proposed: None },
            None, None).is_err());

        assert_eq!(originals.heads.as_ref().unwrap().len(), 2);
        assert_eq!(originals.after.projection.projection().unwrap().records().len(), 4);
        assert!(originals.genesis.as_ref().unwrap().receipts.is_empty());
        let cause = originals.failure().unwrap() as *const dyn std::error::Error;
        assert!(originals.observe_once(&BTreeMap::new(),
            SourceSuccessorMemberRecipe::MixedProjectsV3 { receipts: &receipts, proposed: None },
            None, None).is_err());
        assert!(std::ptr::addr_eq(originals.failure().unwrap(), cause));
        assert_eq!(originals.heads.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn malformed_unfiltered_member_keeps_the_actual_portable_cause() {
        let mut rows = rows();
        let bytes = rows.values_mut().last().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let mut originals = CompleteLineageOriginalsV1::empty();
        assert!(originals.observe_once(rows.iter().map(|((namespace, key), value)|
            (*namespace, key.as_slice(), value.as_slice()))).is_err());
        let cause = originals.failure().unwrap() as *const dyn std::error::Error;

        assert!(originals.projection.failure().is_some());
        assert!(originals.observe_once(std::iter::empty()).is_err());
        assert!(std::ptr::addr_eq(originals.failure().unwrap(), cause));
        assert!(originals.take_heads_once().is_err());
    }

    #[test]
    fn complete_lineage_shape_uses_the_actual_rows_and_no_descriptor_increment() {
        use aos_sandbox_core::ResourceDimension as D;
        let rows = rows();
        let demand = SourceSuccessorMembersOriginalsV1::receiving_dynamic_demand_v1(
            rows.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))).unwrap();
        assert!(demand.get(D::MemoryBytes) > 0);
        assert!(demand.get(D::MetadataEntries) > 0);
        assert_eq!(demand.get(D::OpenFiles), 0);
        assert!(SourceSuccessorMembersOriginalsV1::fixed_footprint_v1().is_some());
    }
}

#[cfg(test)]
mod appended_member_tests {
    use super::*;
    type CompleteLineageOriginalsV1 = super::CompleteLineageOriginalsV1<DomainLedgerDataError>;
    type SourceAppendedPairOriginalsV1 = super::SourceAppendedPairOriginalsV1<DomainLedgerDataError>;
    type SourceSuccessorMembersOriginalsV1 = super::SourceSuccessorMembersOriginalsV1<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>;


    #[test]
    fn actual_source_member_prefix_is_owned_before_later_pair_comparisons() {
        let rows = super::tests::rows();
        let ((namespace, key), encoded) = rows.iter().next().unwrap();
        let record = JournalRecord::put(*namespace, key.clone(), encoded.clone());
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut capture = SourceAppendedPairOriginalsV1::new();
        let actual = capture.observe_member_once(0, &record, &validator).unwrap();
        assert_eq!(actual.encoded(), encoded);
        assert!(capture.members[0].member().is_some());
        assert!(capture.failure().is_none());
        assert!(capture.observe_member_once(0, &record, &validator).is_err());
        assert!(capture.failure().is_some());
    }

    #[test]
    fn malformed_actual_source_member_keeps_key_before_the_durable_refusal() {
        let rows = super::tests::rows();
        let ((namespace, key), encoded) = rows.iter().next().unwrap();
        let mut invalid = encoded.clone();
        invalid[0] ^= 1;
        let record = JournalRecord::put(*namespace, key.clone(), invalid);
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut capture = SourceAppendedPairOriginalsV1::new();
        assert!(capture.observe_member_once(0, &record, &validator).is_err());
        assert!(capture.members[0].failure().is_some());
        assert!(capture.failure().is_some());
        assert!(capture.keys[0].failure().is_none());
        assert!(SourceAppendedPairOriginalsV1::fixed_peak_bytes_v1().is_some());
    }
}
