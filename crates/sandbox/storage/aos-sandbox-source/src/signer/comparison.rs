//! Lends only this actual completed fixed replay to the shared signing body.
//!
//! Construction stays private and checks the same selected owner. No supplied
//! saved map, query implementation, identity, native tuple or signing packet can
//! replace the genuine receiving/currentness stages around this borrow.

use aos_sandbox_model::{ObjectDigest, ProjectId};
use aos_sandbox_ledger_replay::replay::{source_tree_genesis, source_tree_successor, tree_lineage};
use aos_sandbox_ledger_replay::replay::hierarchy_records::{self,
    HierarchyProtectedJournalSchemaV1, HierarchyProtectedJournalKeyV1,
    HierarchyProtectedRecordKindV1};
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError,
    records::{current_record_candidates_from_rows, replay_projection_records},
    protected_names::ProtectedJournalNamesV1,
    source_policy_hold::SourceDomainPolicyHoldV1,
    source_project_history::{SourceProjectAdmissionChallengeV1,
        SourceProjectAdmissionReservationV1, SourceProjectAdmissionTerminalV1}};
use crate::signer_comparison::SourceSignerComparisonV1;
use super::readonly_native::SourceReadonlyNativeOriginalV1;
use super::readback_error::{SourceSignerReadbackErrorV1, SourceReadbackGenesisErrorV1};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;

pub(super) struct SourceFixedComparisonV1<'view> {
    original: &'view mut SourceReadonlyNativeOriginalV1,
    names: ProtectedJournalNamesV1,
}

impl SourceReadonlyNativeOriginalV1 {
    pub(super) fn comparison_v1(&mut self) -> Result<SourceFixedComparisonV1<'_>, SourceSignerReadbackErrorV1> {
        if self.readback_mut().is_none() { return Err(JournalError::ProtectedBoundary.into()); }
        let names = self.physical_names_v1()?;
        Ok(SourceFixedComparisonV1 { original: self, names })
    }
}

impl SourceSignerComparisonV1 for SourceFixedComparisonV1<'_> {
    type Error = SourceSignerReadbackErrorV1;

    fn stale() -> Self::Error { SourceSignerReadbackErrorV1::Stale }
    fn noncanonical_genesis() -> Self::Error { SourceReadbackGenesisErrorV1::NonCanonical.into() }
    fn conflicting_genesis() -> Self::Error { SourceReadbackGenesisErrorV1::Conflict.into() }
    fn stale_genesis() -> Self::Error { SourceReadbackGenesisErrorV1::Stale.into() }
    fn physical_names_v1(&self) -> ProtectedJournalNamesV1 { self.names }
    fn snapshot_sequence(&mut self) -> u64 { self.original.snapshot_sequence() }
    fn has_records(&mut self) -> bool { self.original.all_records().next().is_some() }

    fn source_project_genesis_data_v3(&mut self, project: ProjectId)
        -> Result<source_tree_successor::SourceProjectFamilyDataV3, Self::Error>
    { self.original.source_project_genesis_data_v3(project).map_err(Into::into) }

    fn source_tree_genesis_rows_v1(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>
    { self.original.source_tree_genesis_rows_v1().map_err(Into::into) }

    fn source_first_successor_rows_v2(&mut self)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>
    { self.original.source_first_successor_rows_v2().map_err(Into::into) }

    fn source_project_continuation_rows_v3(&mut self, selected: Option<ProjectId>)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>
    { self.original.source_project_continuation_rows_v3(selected).map_err(Into::into) }

    fn validate_genesis_rows(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>
    {
        let rows = self.original.source_tree_genesis_rows_v1()
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        let heads = tree_lineage::replay_closed_tree_lineage_state_v2(self.original.state()?)
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        use aos_sandbox_ledger_replay::source_readback_queries::SourceGenesisRowsReadbackErrorV1;
        aos_sandbox_ledger_replay::source_readback_queries::validate_rows_with_lineage_v1(
            self.original.state()?, rows, &heads,
        ).map_err(|cause| match cause {
            SourceGenesisRowsReadbackErrorV1::Conflict => SourceReadbackGenesisErrorV1::Conflict,
            SourceGenesisRowsReadbackErrorV1::Hierarchy(cause) => SourceReadbackGenesisErrorV1::Hierarchy(cause),
        }).map_err(Into::into)
    }

    fn source_domain_policy_hold_v1(&mut self)
        -> Result<Option<SourceDomainPolicyHoldV1>, Self::Error>
    { self.original.source_domain_policy_hold_v1().map_err(Into::into) }

    fn ancestry_head(&mut self, project: ProjectId) -> Result<Option<ObjectDigest>, Self::Error> {
        if project.as_bytes() == &[0; 16] {
            return Err(SourceReadbackGenesisErrorV1::Hierarchy(DomainLedgerDataError::NonCanonicalRecord).into());
        }
        let candidates = current_record_candidates_from_rows::<HierarchyProtectedJournalSchemaV1>(self.original.all_records())
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        let validator = hierarchy_records::ancestry_validator_from_saved_rows_v1(&candidates)
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        let projection = replay_projection_records::<HierarchyProtectedJournalSchemaV1>(self.original.all_records(), &validator)
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        let mut identity = Vec::with_capacity(48);
        for _ in 0..3 { identity.extend_from_slice(project.as_bytes()); }
        let key = HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        aos_sandbox_ledger_replay::source_readback_queries::ancestry_fields_from_projection_v1(
            &projection, &key, &validator, project,
        ).map(|fields| fields.map(|(_, _, _, head)| head))
            .map_err(SourceReadbackGenesisErrorV1::from).map_err(Into::into)
    }

    fn successor_tree(&mut self, project: ProjectId)
        -> Result<(ObjectDigest, ObjectDigest, ObjectDigest, u64), Self::Error>
    {
        let heads = tree_lineage::replay_closed_tree_lineage_state_v2(self.original.state()?)
            .map_err(SourceReadbackGenesisErrorV1::from)?;
        let head = heads.get(&project).ok_or(SourceReadbackGenesisErrorV1::Hierarchy(DomainLedgerDataError::NonCanonicalRecord))?;
        let commitment = aos_sandbox_ledger_replay::hierarchy::codec::tree_commitment_v1(&head.tree)
            .map_err(|_| SourceReadbackGenesisErrorV1::Hierarchy(DomainLedgerDataError::NonCanonicalRecord))?;
        Ok((head.tree_head, head.lineage_head, commitment, head.tree.tree_generation().get()))
    }

    fn project_challenge(&mut self) -> Result<Option<SourceProjectAdmissionChallengeV1>, Self::Error> {
        self.original.get(aos_sandbox_model::RecordNamespace::DesiredState,
            aos_sandbox_ledger_replay::source_project_readback::KEY)
            .map(|bytes| SourceProjectAdmissionChallengeV1::decode(bytes)
                .map_err(|_| JournalError::ProtectedBoundary)).transpose().map_err(Into::into)
    }

    fn source_project_admission_reservation_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionReservationV1, bool)>, Self::Error>
    { self.original.source_project_admission_reservation_status_v1().map_err(Into::into) }

    fn source_project_admission_reservation_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionReservationV1>, Self::Error>
    { self.original.source_project_admission_reservation_v1().map_err(Into::into) }

    fn source_project_admission_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, Self::Error>
    { self.original.source_project_admission_status_v1().map_err(Into::into) }

    fn source_project_admission_terminal_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionTerminalV1>, Self::Error>
    { self.original.source_project_admission_terminal_v1().map_err(Into::into) }
}
