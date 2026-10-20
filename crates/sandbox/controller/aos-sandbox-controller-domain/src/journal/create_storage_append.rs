//! Dispatches closed original Create Storage role loans into one native engine.
//!
//! Each variant borrows its genuine payer and retained role-specific currentness
//! owner. The enum shares routing only: it constructs no original, accepts no
//! scalar budget, and cannot turn a decoded history record into append authority.

use super::{CommitResult, Journal, JournalError, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::create_storage_history::OwnerV1;

// Cache borrows both its own retained initializer and the live J borrower.
// Their invariant lifetimes are independent of the earlier C/Source crossing.
// The ACK-dependent terminal context likewise has its own loan/turn pair: its
// nested context outlives that loan, not an unrelated history crossing.
pub(super) enum CreateStorageAppendOriginalV1<'call, 'cut, 'original, 'terminal_loan, 'terminal_turn, 'cache_crossing, 'cache_original, 'cache, 'listener, 'startup, 'execution_cut, 'execution_source, 'execution_original> {
    ExecutionNoApplyController(&'call mut crate::controller_execution_operation::ControllerExecutionNoApplyAppendLoanV2<'execution_cut, 'execution_source, 'execution_original>),
    DeleteAdmission(&'call mut dyn super::delete_admission::DeleteAdmissionOriginalV3),
    OperatorRecover(&'call mut super::operator_recover_floor::OperatorRecoverAppendLoanV1<'cut>),
    CreateStoppedTerminal(&'call mut super::create_stopped_terminal::CreateStoppedControllerTerminalAppendLoanV1<'terminal_loan, 'terminal_turn>),
    CreateStoppedPreAck(&'call mut super::create_stopped_pre_ack::CreateStoppedControllerPreAckAppendLoanV1<'cut>),
    SourceProvisioning(&'call mut super::source_provisioning::SourceProvisioningAppendLoanV1<'cut>),
    Provisioning(&'call mut crate::reconciler::provisioning::ProvisioningAppendLoanV1<'cut>),
    ExecutionNoApplyFloor(&'call mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorAppendLoanV2<'cut, 'listener, 'startup>),
    Root(&'call mut crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenAppendLoanV1<'cut, 'listener, 'startup>),
    Controller(&'call mut crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'cut, 'original>),
    Source(&'call mut crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'cut, 'original>),
    Cache(&'call mut crate::cache_residency::CacheHeldAppendLoanV1<'cache_crossing, 'cache_original, 'cache>),
    CacheReleased(&'call mut crate::cache_residency::CacheReleasedAppendLoanV1<'cache_crossing, 'cache_original, 'cache>),
}

impl<'call, 'cut, 'original, 'terminal_loan, 'terminal_turn, 'cache_crossing, 'cache_original, 'cache, 'listener, 'startup, 'execution_cut, 'execution_source, 'execution_original>
    CreateStorageAppendOriginalV1<'call, 'cut, 'original, 'terminal_loan, 'terminal_turn, 'cache_crossing, 'cache_original, 'cache, 'listener, 'startup, 'execution_cut, 'execution_source, 'execution_original>
{
    pub(super) fn require_transition(&mut self, journal: &Journal, transaction: &JournalTransaction)
        -> Result<(), JournalError>
    {
        match self {
            Self::ExecutionNoApplyController(original) => original.require_transition(journal, transaction),
            Self::DeleteAdmission(original) => original.require_transition_v3(journal, transaction),
            Self::OperatorRecover(original) => original.require_transition(journal, transaction),
            Self::CreateStoppedTerminal(original) => original.require_transition(journal, transaction),
            Self::CreateStoppedPreAck(original) => original.require_transition(journal, transaction),
            Self::SourceProvisioning(original) => original.require_transition(journal, transaction),
            Self::Provisioning(original) => original.require_transition(journal, transaction),
            Self::ExecutionNoApplyFloor(original) => original.require_transition(journal, transaction),
            Self::Root(original) => original.require_transition(journal, transaction),
            Self::Cache(original) => original.require_transition(journal, transaction),
            Self::CacheReleased(original) => original.require_transition(journal, transaction),
            Self::Controller(original) => original.require_transition_for_owner(journal, transaction, OwnerV1::Controller),
            Self::Source(original) => original.require_transition_for_owner(journal, transaction, OwnerV1::Source),
        }
    }

    pub(super) fn execution_no_apply_floor_successor(&self)
        -> Option<&crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorAppendLoanV2<'cut, 'listener, 'startup>> {
        match self { Self::ExecutionNoApplyFloor(original) => Some(original), _ => None }
    }

    pub(super) fn execution_no_apply_controller_successor(&self)
        -> Option<&crate::controller_execution_operation::ControllerExecutionNoApplyAppendLoanV2<'execution_cut, 'execution_source, 'execution_original>> {
        match self { Self::ExecutionNoApplyController(original) => Some(original), _ => None }
    }

    pub(super) fn delete_admission_successor(&self)
        -> Option<&dyn super::delete_admission::DeleteAdmissionOriginalV3> {
        match self { Self::DeleteAdmission(original) => Some(&**original), _ => None }
    }

    pub(super) fn operator_recover_successor(&self)
        -> Option<&super::operator_recover_floor::OperatorRecoverAppendLoanV1<'cut>> {
        match self { Self::OperatorRecover(original) => Some(original), _ => None }
    }

    pub(super) fn create_stopped_terminal_successor(&self)
        -> Option<&super::create_stopped_terminal::CreateStoppedControllerTerminalAppendLoanV1<'terminal_loan, 'terminal_turn>> {
        match self { Self::CreateStoppedTerminal(original) => Some(original), _ => None }
    }

    pub(super) fn create_stopped_pre_ack_successor(&self)
        -> Option<&super::create_stopped_pre_ack::CreateStoppedControllerPreAckAppendLoanV1<'cut>> {
        match self { Self::CreateStoppedPreAck(original) => Some(original), _ => None }
    }

    pub(super) fn source_provisioning_successor(&self)
        -> Option<&super::source_provisioning::SourceProvisioningAppendLoanV1<'cut>>
    {
        match self { Self::SourceProvisioning(original) => Some(original), _ => None }
    }

    pub(super) fn provisioning_successor(&self)
        -> Option<&crate::reconciler::provisioning::ProvisioningAppendLoanV1<'cut>>
    {
        match self { Self::Provisioning(original) => Some(original), _ => None }
    }

    pub(super) fn root_open_history_successor(&self)
        -> Option<&crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenAppendLoanV1<'cut, 'listener, 'startup>>
    {
        match self { Self::Root(original) => Some(original), _ => None }
    }

    pub(super) fn controller_history_successor(&self)
        -> Option<&crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'cut, 'original>>
    {
        match self { Self::Controller(original) => Some(original), _ => None }
    }

    pub(super) fn final_crossing(&mut self, journal: &Journal) -> Result<(), JournalError> {
        match self {
            Self::ExecutionNoApplyController(original) => original.final_crossing(journal),
            Self::DeleteAdmission(original) => original.final_crossing_v3(journal),
            Self::OperatorRecover(original) => original.final_crossing(journal),
            Self::CreateStoppedTerminal(original) => original.final_crossing(journal),
            Self::CreateStoppedPreAck(original) => original.final_crossing(journal),
            Self::SourceProvisioning(original) => original.final_crossing(journal),
            Self::Provisioning(original) => original.final_crossing(journal),
            Self::ExecutionNoApplyFloor(original) => original.final_crossing(journal),
            Self::Root(original) => original.final_crossing(journal),
            Self::Cache(original) => original.final_crossing(journal),
            Self::CacheReleased(original) => original.final_crossing(journal),
            Self::Controller(original) | Self::Source(original) => original.final_crossing(journal),
        }
    }
}

impl Journal {
    /// Uses the same native engine with only the actual paid Root floor loan.
    pub(crate) fn commit_execution_no_apply_floor_original_v2(&mut self,
        transaction: &JournalTransaction,
        original: &mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorAppendLoanV2<'_, '_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_create_storage_original_v1(transaction, CreateStorageAppendOriginalV1::ExecutionNoApplyFloor(original))
    }

    // This is the same semantic/native append engine, selected only by the
    // private exact Core recipe and its actual retained C original.
    pub(crate) fn commit_create_provisioning_v1(&mut self,
        transaction: &JournalTransaction,
        original: &mut crate::reconciler::provisioning::ProvisioningAppendLoanV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_create_storage_original_v1(transaction,
            CreateStorageAppendOriginalV1::Provisioning(original))
    }

    // Generic append validators read this SAME original's current map. They
    // do not replay historical physical frames here, so reached map cells and
    // their actual retained encoded extent feed the shared representation math.
    pub(crate) fn create_storage_semantic_append_demand_v1(&self)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        self.ensure_healthy()?;
        let encoded = self.native.state().iter().try_fold(0_usize, |total, ((_, key), value)| {
            total.checked_add(key.capacity()).and_then(|n| n.checked_add(value.capacity()))
                .ok_or(JournalError::JournalTooLarge)
        })?;
        super::semantic_receiving::semantic_representation_demand_v1(encoded, self.native.state().len())
    }

    /// Appends the actual paid Controller original's exact closed history pair.
    ///
    /// # Errors
    /// Retains original-currentness, semantic validation and durability failures.
    pub(crate) fn commit_create_storage_controller_history_v1(&mut self, transaction: &JournalTransaction,
        original: &mut crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'_, '_>)
        -> Result<CommitResult, JournalError>
    {
        self.commit_create_storage_original_v1(transaction, CreateStorageAppendOriginalV1::Controller(original))
    }

    /// Appends only the actual paid Source original's first Held pair.
    ///
    /// # Errors
    /// Retains original-currentness, semantic validation and durability failures.
    pub(crate) fn commit_create_storage_source_held_v1(&mut self, transaction: &JournalTransaction,
        original: &mut crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'_, '_>)
        -> Result<CommitResult, JournalError>
    {
        self.commit_create_storage_original_v1(transaction, CreateStorageAppendOriginalV1::Source(original))
    }

    // HOLD is the actual initialized writer; no State/Authority Resident gate
    // is substituted and the ordinary Exclusive/GitCoverage refusal remains.
    pub(crate) fn commit_create_storage_cache_held_v1(&mut self, transaction: &JournalTransaction,
        original: &mut crate::cache_residency::CacheHeldAppendLoanV1<'_, '_, '_>)
        -> Result<CommitResult, JournalError>
    {
        self.commit_create_storage_original_v1(transaction, CreateStorageAppendOriginalV1::Cache(original))
    }

    pub(crate) fn commit_create_storage_cache_released_v1(&mut self, transaction: &JournalTransaction,
        original: &mut crate::cache_residency::CacheReleasedAppendLoanV1<'_, '_, '_>)
        -> Result<CommitResult, JournalError> {
        self.commit_create_storage_original_v1(transaction, CreateStorageAppendOriginalV1::CacheReleased(original))
    }

    pub(super) fn commit_create_storage_original_v1(&mut self, transaction: &JournalTransaction,
        original: CreateStorageAppendOriginalV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>)
        -> Result<CommitResult, JournalError>
    {
        self.commit_with_native_scope_and_storage_clock(transaction,
            super::semantic_append::AppendScope::default(),
            super::CacheMutationGateV1::Ordinary,
            None, None, None, None, Some(original))
    }
}
