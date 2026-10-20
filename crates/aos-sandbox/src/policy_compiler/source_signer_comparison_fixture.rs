//! Adapts actual protected Journal fixtures to the canonical Source comparisons.
//!
//! Compiled only for Linux unit tests. This owns no signer mount/opening,
//! service credential, native receiving account, or production signing factory.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use aos_sandbox_source::signer_comparison::SourceSignerComparisonV1;
use aos_sandbox_ledger_replay::replay::{source_tree_genesis, source_tree_successor};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{ReadOnlyProtectedJournal, ProtectedJournalNamesV1,
    SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1,
    SourceProjectAdmissionTerminalV1, JournalError};
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;
use aos_sandbox_ledger_replay::source_signer_data::{SourceHoldReadbackErrorV1,
    SourceSignerGenesisDataErrorV1};

/// Preserves native query failures in the actual canonical comparison fixtures.
#[derive(Debug, thiserror::Error)]
pub enum SourceSignerComparisonFixtureErrorV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("Source hold and typed hierarchy head are not current")]
    Stale,
    #[error(transparent)]
    Signing(#[from] SourceHoldReadbackErrorV1),
    #[error(transparent)]
    FirstSuccessor(#[from] SourceGenesisErrorV1),
}

impl From<SourceSignerGenesisDataErrorV1> for SourceSignerComparisonFixtureErrorV1 {
    fn from(cause: SourceSignerGenesisDataErrorV1) -> Self {
        Self::FirstSuccessor(cause.into())
    }
}

impl SourceSignerComparisonV1 for ReadOnlyProtectedJournal {
    type Error = SourceSignerComparisonFixtureErrorV1;

    fn stale() -> Self::Error { SourceSignerComparisonFixtureErrorV1::Stale }
    fn noncanonical_genesis() -> Self::Error { SourceGenesisErrorV1::NonCanonical.into() }
    fn conflicting_genesis() -> Self::Error { SourceGenesisErrorV1::Conflict.into() }
    fn stale_genesis() -> Self::Error { SourceGenesisErrorV1::Stale.into() }

    fn physical_names_v1(&self) -> ProtectedJournalNamesV1 {
        ReadOnlyProtectedJournal::physical_names_v1(self)
    }

    fn snapshot_sequence(&mut self) -> u64 {
        // This is the same diagnostic watermark, not an additional observation.
        self.journal_mut().snapshot_sequence()
    }

    fn has_records(&mut self) -> bool { self.journal_mut().all_records().next().is_some() }

    fn source_project_genesis_data_v3(&mut self, project: ProjectId)
        -> Result<source_tree_successor::SourceProjectFamilyDataV3, Self::Error>
    {
        self.journal_mut().source_project_genesis_data_v3(project).map_err(Into::into)
    }

    fn source_tree_genesis_rows_v1(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>
    {
        self.journal_mut().source_tree_genesis_rows_v1().map_err(Into::into)
    }

    fn source_first_successor_rows_v2(&mut self)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>
    {
        self.journal_mut().source_first_successor_rows_v2().map_err(Into::into)
    }

    fn source_project_continuation_rows_v3(&mut self, project: Option<ProjectId>)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>
    {
        self.journal_mut().source_project_continuation_rows_v3(project).map_err(Into::into)
    }

    fn validate_genesis_rows(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>
    {
        crate::hierarchy::source_genesis::validate_actual_rows(self.journal_mut()).map_err(Into::into)
    }

    fn source_domain_policy_hold_v1(&mut self)
        -> Result<Option<SourceDomainPolicyHoldV1>, Self::Error>
    {
        self.journal_mut().source_domain_policy_hold_v1().map_err(Into::into)
    }

    fn ancestry_head(&mut self, project: ProjectId) -> Result<Option<ObjectDigest>, Self::Error> {
        crate::hierarchy::protected_journal::replay_project_ancestry_head_v1(self.journal_mut(), project)
            .map(|head| head.map(|head| head.head()))
            .map_err(|cause| SourceGenesisErrorV1::from(cause).into())
    }

    fn successor_tree(&mut self, project: ProjectId)
        -> Result<(ObjectDigest, ObjectDigest, ObjectDigest, u64), Self::Error>
    {
        crate::hierarchy::source_first_successor_tree_readback_v2(self.journal_mut(), project)
            .map_err(|cause| SourceGenesisErrorV1::from(cause).into())
    }

    fn project_challenge(&mut self) -> Result<Option<SourceProjectAdmissionChallengeV1>, Self::Error> {
        crate::journal::replay_source_project_admission_challenge_v1(self.journal_mut()).map_err(Into::into)
    }

    fn source_project_admission_reservation_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionReservationV1, bool)>, Self::Error>
    {
        self.journal_mut().source_project_admission_reservation_status_v1().map_err(Into::into)
    }

    fn source_project_admission_reservation_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionReservationV1>, Self::Error>
    {
        self.journal_mut().source_project_admission_reservation_v1().map_err(Into::into)
    }

    fn source_project_admission_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, Self::Error>
    {
        self.journal_mut().source_project_admission_status_v1().map_err(Into::into)
    }

    fn source_project_admission_terminal_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionTerminalV1>, Self::Error>
    {
        self.journal_mut().source_project_admission_terminal_v1().map_err(Into::into)
    }
}
