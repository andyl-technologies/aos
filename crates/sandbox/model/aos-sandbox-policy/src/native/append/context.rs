//! Binds the sole append schedule to Policy's actual held native storage.
//!
//! The context borrows the existing owner and retains its same native stage.
//! Root's prearmed independent post remains in the journal, outside this stack
//! context, so a failed primary result cannot dispose its native prefix.

use aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorAppendV1;
use aos_sandbox_broker::canonical_journal::{CommitResult, CanonicalJournalMechanicalErrorV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::gate::PolicyMutationGateV1;
use crate::native::journal::append_stage::PolicyAppendStageV1;
use crate::native::journal::{PolicyJournalStorageV1, RootPolicyJournalV1};
use crate::native::PolicyNativeJournalErrorV1 as ErrorV1;

pub(in crate::native) struct PolicyAppendContextV1<'journal, 'transaction> {
    pub(super) journal: &'journal mut RootPolicyJournalV1,
    stage: Option<PolicyAppendStageV1<'transaction>>,
}

impl<'journal, 'transaction> PolicyAppendContextV1<'journal, 'transaction> {
    pub(in crate::native) fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<Result<CommitResult, ErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(u64, u64), ErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<u64, ErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<bool, ErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), ErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<Option<()>, ErrorV1>>().checked_mul(3)?)
    }

    pub(super) fn new(journal: &'journal mut RootPolicyJournalV1) -> Self {
        Self { journal, stage: None }
    }

    pub(super) fn prepare(&mut self, transaction: &'transaction JournalTransaction)
        -> Result<(), ErrorV1>
    {
        self.stage = Some(self.journal.storage.prepare_append(transaction)?);
        Ok(())
    }

    pub(super) fn projected_materialized_bytes(&self) -> Option<usize> {
        self.stage.as_ref()?.projected_materialized_bytes()
    }

    pub(super) fn coordinates(&mut self) -> Result<(u64, u64), ErrorV1> {
        self.journal.storage.append_coordinates(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        )
    }

    pub(super) fn expected_length(&mut self) -> Result<u64, ErrorV1> {
        self.journal.storage.expected_append_length(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        )
    }

    // These two fixed Root journals never arm Domain's optional Cache gate.
    // Their actual held Cache prerequisite belongs to the genuine Gen1/Input
    // gate. This stage therefore has no hold-journal lock to acquire or advance.
    pub(super) fn before_cache_append(&self, _: &mut PolicyMutationGateV1<'_, '_, '_, '_, '_>)
        -> Result<Option<()>, ErrorV1>
    {
        Ok(None)
    }

    pub(super) fn own_cache_successor(&mut self, _: &mut PolicyMutationGateV1<'_, '_, '_, '_, '_>,
        _: &JournalTransaction, _: u64, _: u64) -> Result<(), ErrorV1>
    {
        Ok(())
    }

    pub(super) fn append(&mut self) -> Result<u64, ErrorV1> {
        self.journal.storage.append_prepared(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        )
    }

    pub(super) fn apply_next_record(&mut self) -> Result<bool, ErrorV1> {
        self.journal.storage.apply_next_record(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        )
    }

    pub(super) fn publish(&mut self) -> Result<(), ErrorV1> {
        self.journal.storage.publish_append(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        ).map(|_| ())
    }

    pub(super) fn poison(&mut self) {
        match &mut self.journal.storage {
            PolicyJournalStorageV1::Selected { writer, .. } => writer.poison(),
            PolicyJournalStorageV1::Ordinary { writer } => writer.poison(),
        }
    }

    pub(super) fn is_ordinary(&self) -> bool {
        matches!(self.journal.storage, PolicyJournalStorageV1::Ordinary { .. })
    }

    pub(super) fn finish_ordinary(&mut self) -> Result<(), ErrorV1> {
        if !self.is_ordinary() {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary.into());
        }
        self.journal.storage.finish_append_after_posts(
            self.stage.as_mut().ok_or_else(ErrorV1::boundary)?,
        )
    }

    pub(super) fn finish_selected(&mut self, primary: Result<CommitResult, ErrorV1>)
        -> Result<CommitResult, ErrorV1>
    {
        self.journal.finish_native_append_interval_v1(primary, self.stage.take())
    }

    pub(super) fn drop_stage(&mut self) {
        drop(self.stage.take());
    }
}
