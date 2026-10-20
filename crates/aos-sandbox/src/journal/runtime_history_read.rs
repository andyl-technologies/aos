//! Lends historical Runtime comparisons from this same private Journal owner.
//!
//! The generic compaction policy/location type remains private here. Every
//! method delegates to the sole Protocol engine over the actual native/index/
//! location borrow; it authenticates no standalone Runtime or effect proof.

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history as data;
use data::crosslinks::RuntimeCrosslinkDataErrorV1;
use data::ledger_read::{self as read, RuntimeHistoryReadErrorV1};

use super::Journal;
#[cfg(target_os = "linux")]
type Compaction = super::runtime_deployment_history::OriginalCompactionSelectionV1;
#[cfg(not(target_os = "linux"))]
type Compaction = ();

#[derive(Clone, Copy)]
pub(crate) struct RuntimeHistoryReadV1<'journal> {
    journal: &'journal Journal,
}

impl Journal {
    pub(crate) const fn runtime_history_read_v1(&self) -> RuntimeHistoryReadV1<'_> {
        RuntimeHistoryReadV1 { journal: self }
    }
}

impl<'journal> RuntimeHistoryReadV1<'journal> {
    fn view(self) -> read::HistoricalRuntimeLedgerReadV1<'journal,
        aos_sandbox_journal::protected_storage::ProtectedJournalLocation<Compaction>>
    {
        self.journal.native.read_view().runtime_history()
    }

    pub(crate) fn scan(
        self,
        limits: data::RuntimeAuthorityLimits,
        subject: Option<SandboxId>,
    ) -> Result<(usize, usize, bool), RuntimeHistoryReadErrorV1> {
        read::scan_namespace(self.view(), limits, subject)
    }

    pub(crate) fn current(
        self,
        sandbox: SandboxId,
    ) -> Result<Option<data::RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1> {
        read::current_from_journal(self.view(), sandbox)
    }

    pub(crate) fn binding(
        self,
        sandbox: SandboxId,
        revision: u64,
    ) -> Result<data::RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1> {
        read::binding_in_validated_namespace(self.view(), sandbox, revision)
    }

    pub(crate) fn continuity(
        self,
        origin: &data::RuntimeAuthorityBindingV1,
        current: &data::RuntimeAuthorityBindingV1,
    ) -> Result<(), RuntimeHistoryReadErrorV1> {
        read::validate_continuity_in_validated_namespace(self.view(), origin, current)
    }

    pub(crate) fn validate_operation_intent(
        self,
        operation: OperationId,
        digest: ObjectDigest,
    ) -> Result<(), RuntimeHistoryReadErrorV1> {
        read::validate_operation_intent(self.view(), operation, digest)
    }

    pub(crate) fn validate_activated_pending(
        self,
        pending: &data::RuntimeAuthorityPendingV1,
        publication: ObjectDigest,
        generation: u64,
        lease: ObjectDigest,
    ) -> Result<(), RuntimeHistoryReadErrorV1> {
        read::validate_activated_pending(self.view(), pending, publication, generation, lease)
    }

    pub(crate) fn pending_links(
        self,
        pending: &data::RuntimeAuthorityPendingV1,
    ) -> Result<(), RuntimeCrosslinkDataErrorV1> {
        read::validate_pending_links(self.view(), pending)
    }

    pub(crate) fn binding_links(
        self,
        binding: &data::RuntimeAuthorityBindingV1,
    ) -> Result<(), RuntimeCrosslinkDataErrorV1> {
        read::validate_binding_links(self.view(), binding)
    }

    pub(crate) fn operation_links(self) -> Result<(), RuntimeCrosslinkDataErrorV1> {
        read::validate_operation_links(self.view())
    }
}
