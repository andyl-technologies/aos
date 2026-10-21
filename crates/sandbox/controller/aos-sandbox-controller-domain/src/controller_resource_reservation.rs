//! Owns the Controller's Native resource custody and original-loan transitions.
//!
//! Protocol owns the sole passive bank models, canonical codecs and complete
//! replay. Native originals, returned commits, clocks, enrollment factories and
//! final crossings remain here and are not reconstructed from lower DATA.
//!
//! Account records are inclusive grants: a child grant is reserved once in
//! its immediate parent, while use inside the child consumes that same grant.
//! Native bytes are replay DATA, not a constructor for an allocation permit.
//! Enrollment additionally requires the original image/PID1 producer custody.
//! Ambiguous writes and lost owners remain charged until protected recovery;
//! dropping a handle never establishes physical cleanup.

mod bootstrap;
mod operation_intake;
pub(crate) use create_intake::provisioning::receiving::storage_io::{ExecutionAvailabilityIoOriginalV2, ExecutionNoApplyIoOriginalV2};
pub(crate) use operation_intake::{
    ControllerOperationIntakeOriginalV1, ControllerOperationIntakeReceivingLoanV1,
    ControllerOperationIntakeDisposalV1, ControllerOperationIntakeDemandDataV1,
    ControllerOperationIntakeFailureViewV1,
    ControllerExecutionSourceScopeV1, ControllerExecutionSourceDisposalV1,
    ControllerExecutionSourceCompleteBorrowV1,
};
mod runtime_receiving;
mod startup_credentials;
pub(crate) mod operator_create_recovery;
#[doc(hidden)]
pub use operator_create_recovery::{OperatorCreateRecoveryOriginalV1, OperatorCreateRecoveryLoanV1, OperatorCreateRecoveryClosedV1, OperatorStopCleanupObservationLoanV1};
pub use operator_create_recovery::OperatorExecutionNoApplyRecoveryCompletedHandoffV2;
pub use operator_create_recovery::OperatorStopCleanupRecoveryCompletedHandoffV1;
pub(crate) use operator_create_recovery::storage::inventory::InventoryOriginalsV1 as ControllerRecoveryInventoryOriginalsV3;
pub(crate) use operator_create_recovery::storage::inventory::borrow_stop_cleanup_source_inventory_once_v1;
pub use operator_create_recovery::OperatorRecoveredStoppedCreateSeedV1;
mod initial_session;
pub use initial_session::{
    ControllerInitialBrokerSessionRoleV1, ControllerInitialBrokerSessionCaptureShapeV1,
    ControllerInitialBrokerSessionShapeV1, ControllerInitialBrokerSessionClosedV1,
    ControllerInitialBrokerSessionReceivingV1, ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialSessionCompletedNativeBorrowV1,
};
pub(crate) use initial_session::ControllerInitialBrokerSessionOwnerLinkV1;
mod service_identity;
mod publisher_environment;
pub(crate) mod publisher_receiving;
pub use publisher_environment::{
    ControllerPublisherBusEnvironmentErrorV1, ControllerPublisherBusEnvironmentV1,
};
pub use publisher_receiving::{ControllerPublisherReceivingV1, ControllerPublisherStartupDataV1};
pub use startup_credentials::{ControllerSourceGenesisReceivingV1, ControllerPublicTlsReceivingV1};
pub use service_identity::ControllerAttachmentStartupV1;
pub use runtime_receiving::{
    ControllerRuntimeStartupShapeV1, ControllerRuntimeCredentialShapeV1,
    ControllerRuntimeRequestedCountsV1, ControllerRuntimeTaskEnvelopeV1,
    CONTROLLER_RUNTIME_TASKS_V1, CONTROLLER_RUNTIME_ROLE_TASKS_V1,
    CONTROLLER_RUNTIME_BLOCKING_THREADS_V1, CONTROLLER_RUNTIME_STACK_BYTES_V1,
};
mod grant;
mod component;
pub(crate) mod component_receiving;
mod root_component;
pub(crate) use root_component::{RootStopCleanupChunkPostsV1, RootExecutionNoApplyChunkPostsV2, RootDeleteChunkPostsV1, RootApplyChunkPostsV1, RootStartAssignmentInputsChunkPostsV2, RootHostLaunchChunkPostsV2, RootMaintenanceStorageChunkPostsV2, RootReceivingOriginalV1, RootContinuationDemandV1, RootContinuationStageV1, RootStopCleanupStageV1, StopCleanupRootPeerPurposeV1, RootMaintenanceStorageStageV2, RootExecutionNoApplyReadPhaseV2, RootContinuationStagesV1, RootPurposePeerAdmissionV1, RootPurposePeerPostV1, RootPeerPurposeV1, DeleteRootPeerPurposeV1, EnvironmentRootPeerPurposeV1, ApplyRootPeerPurposeV1, HostLaunchRootPeerPurposeV1, MaintenanceStorageRootPeerPurposeV2, ExecutionNoApplyRootPeerPurposeV2, FinalityRecoverRootPeerPurposeV1, StartAssignmentInputsRootPeerPurposeV2};
pub(crate) use operator_create_recovery::RequestModelsV1 as OperatorCreateRecoveryRequestDataV1;
mod preparation;
mod q04;
mod settlement;
mod terminal_append;

pub(crate) use terminal_append::Q04TerminalBankAppendV1;
pub(crate) mod service_interval;
mod nix_intake;
mod q04_intake;

// The actual upper capture derives its own native widths. Security cannot
// supply arbitrary layouts or turn comparison DATA into an admission.
pub(crate) fn initial_profile_native_layout_v1() -> bank::NativeLayoutDemand {
    q04_intake::native_layout()
}

mod create_intake;
pub(crate) use create_intake::ready::{CreateStorageOriginalLoanV1, CacheTerminalReceivingLoanV1, CacheReleaseReceivingLoanV1,
    CreateStorageUseBankOriginalsV1, CreateStorageUseBankAppendV1, CreateStorageUseHistoryReceivingLoanV1};
#[doc(hidden)]
pub use aos_sandbox_cache::CreateStorageCacheCurrentExtentsDataV1;
pub use create_intake::ready::create_storage_cache_current_dynamic_receiving_demand_v1;
#[doc(hidden)]
pub use create_intake::ready::create_storage_cache_current_fixed_receiving_demand_v1;
#[doc(hidden)]
pub use create_intake::ready::create_storage_held_release_receiving_demand_v1;
pub use create_intake::ready::{CreateStorageRootUseTailShapeDataV1, create_storage_root_use_tail_shape_v1};
#[doc(hidden)]
pub use create_intake::ready::{
    OriginalCreateStorageReadyV1, CreateStorageReadyClosedV1,
    OriginalCreateStorageUseSigningV1, CreateStorageUseSigningInputsDataV1, CreateStoragePrepareInputsDataV1,
    OriginalCreateStorageRootExchangeV1, CreateStorageRootExchangeClosedV1, CreateStorageControllerDriverShapeDataV1,
    CreateStorageClientSessionClosedV1, CreateStorageClientSessionShapeDataV1,
    CreateStorageEndpointRevalidationShapeDataV1,
    OriginalCreateStorageClientSessionV1, CreateStorageClientPositiveDisposalV1,
    OriginalCreateStorageInventoryV1, CreateStorageInventoryClosedV1,
    CreateStorageInventoryShapeDataV1, CreateStorageInventoryPendingDisposalV1,
    CreateStorageOwnershipProgressV1,
};
pub(crate) use create_intake::history::{CreateStorageHistoryAppendLoanV1, CreateStorageWriterPositionV1, HistoryRoleV1};
mod create_intake_append;
#[doc(hidden)]
pub use crate::reconciler::provisioning::{CreateProvisioningStorageIoOriginalV1,
    CreateProvisioningStorageIoLoanV1, CreateProvisioningStorageIoErrorV1};
#[doc(hidden)]
pub(crate) use create_intake::provisioning::CreateStorageCompletedIntakeOriginalV1;
pub(crate) use create_intake::provisioning::{SourceAdmissionAuthorizationV1, SourcePurposeV1};
pub use create_intake::provisioning::{CreateProvisioningOriginalsV1, OriginalCreateProvisioningRootLoanV1,
    StorageProvisioningIoDisposalV1, StorageProvisioningWorkspaceOriginalV1, StorageProvisioningSessionIoShapeDataV1, DeleteStoragePreparationIoOriginalV3, DeleteStorageApplyIoOriginalV3, DeleteNetworkApplyIoOriginalV4, DeleteMountReapIoOriginalV4,
    CreateProvisioningClientSessionAssociationErrorV1, StorageProvisioningSessionPostShapeDataV1};
pub use create_intake::CreateContinuationIntakeAttemptV1;
pub(crate) use create_intake_append::CreateIntakeBankAppendV1;

pub(crate) use grant::ProjectResourceGrantAttemptV1;
pub use service_interval::ControllerFirstGlobalPrefixAttemptV1;
pub use nix_intake::NixOriginalStartIntakeAttemptV1;
pub use nix_intake::NixOriginalStartIntakeLoanV1;
pub(crate) use nix_intake::{AcquisitionFailureV1, PaidNixStartOriginalsV1};
pub use preparation::ProjectPreparationReservationAttemptV1;
pub(crate) use preparation::OriginalPreparationData;
pub(crate) use q04::Q04ResourceTransferV1;
pub(crate) use settlement::Q04TerminalDispositionV1;

pub use bootstrap::{
    ControllerResourceBankOpeningV1, ControllerResourcePreopenLoanV1,
    ControllerResourcePreopenPostV1,
};
pub(crate) use component::StorageComponentPairPostV1;

pub use component::{
    StorageComponentEnvelopeOriginalV1,
};

use aos_sandbox_model::{AccountingError, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{
    self as bank, AccountHead, AccountKind, AccountMutation, Claim, ClaimCut, ClaimPurpose,
    ClaimState, EnrollmentIdentity, ImageBootstrapPolicy, PreparationBinding, TerminalBinding,
};

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
use crate::policy_compiler::create_q04::CreateQ04ErrorV1;
use crate::{JournalTransaction, RecordNamespace};

// Pure compiled component geometry; actual Root/C callers independently
// prove their originals and pay before entering the closed U append.
pub(crate) fn create_storage_use_bank_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    CreateStorageUseBankOriginalsV1::fixed_receiving_demand_v1()
}

pub(crate) fn create_storage_use_commit_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    create_intake::ready::commit_receiving_demand_v1()
}

// These cost projections do not construct a history pair or admit its work.
pub(crate) fn create_storage_use_history_pair_receiving_demand_v1(
    record_bytes: usize,
    semantic: &ResourceVector,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_intake::history::use_history_pair_receiving_demand_v1(record_bytes, semantic)
}

aos_sandbox_policy::define_storage_create_use_profile_rows_v1! {
    pub(crate) fn create_storage_use_profile_rows_receiving_demand_v1,
    error = ResourceReservationErrorV1,
    row_error = |error| ResourceReservationErrorV1::BootstrapProfile(error.into()),
    multiply_error = |_| ResourceReservationErrorV1::Conflict,
}

// The bootstrap interval is paid by the same original enrollment, not the
// per-operation request. This is observation only and issues no child loan.
pub(crate) fn require_controller_interval(
    bank: &std::sync::Arc<std::sync::Mutex<ControllerResourceBankOpeningV1>>,
    journal: &crate::Journal,
    profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
) -> Result<(), ResourceReservationErrorV1> {
    bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
        .require_enrolled(journal, profile).map(|_| ())
}

/// Reports missing enrollment, invalid native custody, or exhausted capacity.
#[derive(Debug, thiserror::Error)]
pub enum ResourceReservationErrorV1 {
    /// Retains the actual Cache-native forecast cause across the owner boundary.
    #[error(transparent)]
    NativeCache(#[from] aos_sandbox_cache::CacheHeldErrorV1),
    /// Retains the actual lower Root financial error on its original allocation.
    #[error(transparent)]
    RootReceiving(aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1),
    /// The same closed Controller receiving original refused an operation.
    #[error(transparent)]
    ControllerReceiving(#[from] aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1),
    /// The same fixed writer or live PID1 Bank/launch stage refused.
    #[error(transparent)]
    ControllerBankLaunch(#[from] aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1),
    /// An original bootstrap file read failed; the owning files remain held.
    #[error(transparent)]
    BootstrapIo(#[from] std::io::Error),
    /// The kernel refused an original descriptor or mount observation.
    #[error(transparent)]
    BootstrapDescriptor(#[from] rustix::io::Errno),
    /// The existing fixed Controller launch or confinement changed.
    #[error(transparent)]
    BootstrapProfile(#[from] crate::normal_root::NormalRootStartupErrorV1),
    /// The existing bounded kernel-boot observation failed.
    #[error(transparent)]
    BootstrapKernel(#[from] aos_linux_descriptors::Error),
    /// The image-owned enrollment producer is absent or no longer held.
    #[error("shared resource enrollment is unavailable")]
    EnrollmentUnavailable,
    /// Complete native replay disagrees with its identities or account heads.
    #[error("shared resource ledger is corrupt")]
    CorruptLedger,
    /// The durable predecessor differs from the same original expected head.
    #[error("shared resource predecessor changed")]
    Conflict,
    /// The sole resource arithmetic rejected the proposed reservation.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    /// Retains an actual bounded bank-history allocation refusal.
    #[error(transparent)]
    Representation(#[from] std::collections::TryReserveError),
    /// The original protected writer refused or could not durably append.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// The same current Controller, Source or original Root join failed.
    #[error(transparent)]
    Source(#[from] crate::hierarchy::genesis_profile::SourceGenesisErrorV1),
    /// The same canonical admitted specification could not be rejoined.
    #[error(transparent)]
    Specification(Box<crate::sandbox_spec_state::SandboxSpecStateError>),
    /// The original native history or terminal Q04 borrower changed.
    #[error(transparent)]
    Terminal(Box<crate::policy_compiler::create_q04::CreateQ04ErrorV1>),
}

impl From<bank::ResourceBankDataError> for ResourceReservationErrorV1 {
    fn from(error: bank::ResourceBankDataError) -> Self {
        match error {
            bank::ResourceBankDataError::CorruptLedger => Self::CorruptLedger,
            bank::ResourceBankDataError::Conflict => Self::Conflict,
            bank::ResourceBankDataError::EnrollmentUnavailable => Self::EnrollmentUnavailable,
            bank::ResourceBankDataError::Accounting(error) => Self::Accounting(error),
            bank::ResourceBankDataError::Names(error) => Self::Journal(crate::JournalError::from(error)),
            bank::ResourceBankDataError::Transaction(error) => Self::Journal(crate::JournalError::from(error)),
            bank::ResourceBankDataError::Frame(error) => Self::Journal(crate::JournalError::from(error)),
            bank::ResourceBankDataError::Representation(error) => Self::Representation(error),
        }
    }
}

// Preserve the Native cause before placing it in the Q04 retained error slot.
fn q04_resource_error(error: impl Into<ResourceReservationErrorV1>) -> CreateQ04ErrorV1 {
    CreateQ04ErrorV1::ResourceReservation(Box::new(error.into()))
}

/// Compares the original fixed Host policy and PID1 delivery as borrowed DATA.
///
/// The expectations come from the independently measured Host image profile.
/// Success creates neither native enrollment nor an operation reservation.
///
/// # Errors
/// Retains the actual file, kernel, codec or complete-profile binding refusal.
#[doc(hidden)]
pub fn require_original_host_component_pair_v2(
    policy: &std::fs::File,
    enrollment: &std::fs::File,
    expected_node: &[u8; 16],
    expected_epoch: &[u8; 16],
    expected_policy_sha256: &[u8; 32],
    expected_recipient_invocation: &[u8; 16],
    expected_producer_invocation: &[u8; 16],
    expected_host_service: &ResourceVector,
    expected_host_control: &ResourceVector,
) -> Result<(), ResourceReservationErrorV1> {
    let original = aos_sandbox_broker::receiving::observe_original_pair(
        policy, enrollment, q04_intake::native_layout(),
    ).map_err(ResourceReservationErrorV1::from)?;
    let host_service = *expected_host_service;
    let host_control = *expected_host_control;
    if !original.identity.matches_host_fields(
        *expected_node,
        *expected_epoch,
        *expected_policy_sha256,
        *expected_producer_invocation,
    ) || original.recipient_invocation != *expected_recipient_invocation
        || !original.policy.host_matches(host_service, host_control)
    {
        return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
    }
    Ok(())
}


/// Carries an exact, private bank mutation into the shared append engine.
///
/// Its fields cannot be synthesized by a journal caller. The live bank will
/// create it only while holding its original enrollment and allocation owner.
pub(crate) struct Transition<'original> {
    original: TransitionOriginal<'original>,
    crossing: Option<NativeCrossing<'original>>,
}

struct Q04TerminalOriginalsV1<'original> {
    original: &'original Q04ResourceTransferV1,
    native: &'original [Option<Result<crate::journal::CommitResult, CreateQ04ErrorV1>>; 8],
    posts: &'original [Option<Result<(), CreateQ04ErrorV1>>; 7],
}

struct NativeCrossing<'original> {
    original: aos_sandbox_model::RawPairedClockSample,
    deadline: u64,
    result: &'original std::cell::OnceCell<Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
}

enum TransitionOriginal<'original> {
    Account(&'original AccountTransition),
    Q04Terminal(Q04TerminalBankAppendV1<'original>),
    CreateIntake(CreateIntakeBankAppendV1<'original>),
    CreateStorageUse(CreateStorageUseBankAppendV1<'original>),
    Enrollment(&'original aos_sandbox_broker::controller_receiving::bank_launch::ControllerPreparedEnrollmentMutationV1),
    ControllerLaunch(&'original aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1),
    Q04(&'original Q04ResourceTransferV1),
}

impl Transition<'_> {
    // Runs only at the shared engine's final pre-append frontier. This is a
    // kernel-only observation: no reentrant Root or Source call holds a lock.
    pub(crate) fn final_crossing(&self) -> Result<(), crate::JournalError> {
        if let TransitionOriginal::CreateStorageUse(original) = &self.original {
            let crossing = self.crossing.as_ref().ok_or(crate::JournalError::ProtectedBoundary)?;
            return original.final_crossing(crossing.result);
        }
        let Some(crossing) = &self.crossing else {
            return match self.original {
                TransitionOriginal::Enrollment(_) => Ok(()),
                TransitionOriginal::ControllerLaunch(original) => original.final_crossing()
                    .map_err(|_| crate::JournalError::ProtectedBoundary),
                TransitionOriginal::Account(_) | TransitionOriginal::Q04(_)
                | TransitionOriginal::Q04Terminal(_) | TransitionOriginal::CreateIntake(_)
                | TransitionOriginal::CreateStorageUse(_) =>
                    Err(crate::JournalError::ProtectedBoundary),
            };
        };
        if crossing.result.get().is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        // The sole initializer is this closed kernel recipe. It cannot call
        // back into this cell; exclusive journal custody excludes another writer.
        let resident = crossing.result.get_or_init(|| {
            let first_global = matches!(self.original,
                TransitionOriginal::Account(original)
                    if matches!(original.claim.native_fields().purpose,
                        ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
                            | ClaimPurpose::Q04OriginalIntake))
                || matches!(self.original, TransitionOriginal::CreateIntake(_));
            let observed = if first_global {
                // This closed boot-lifetime subdivision has no inherited
                // operation's 65-second recipe. Its boot-lifetime first use
                // retains the original pair without inventing a Root deadline.
                crate::policy_compiler::observe_root_first_source_successor_clock_v2(None)
                    .and_then(|sample| {
                        crossing.original.validate_later_sample(sample)
                            .map_err(|_| crate::hierarchy::genesis_profile::SourceGenesisErrorV1::Stale)?;
                        Ok(sample)
                    })
            } else {
                crate::policy_compiler::observe_root_first_source_successor_clock_v2(
                    Some(crossing.original),
                )
            };
            observed.and_then(|sample| {
                if !first_global && sample.boottime_nanoseconds() >= crossing.deadline {
                    Err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::Stale)
                } else {
                    Ok(sample)
                }
            })
        });
        if resident.is_ok() {
            Ok(())
        } else {
            Err(crate::JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        match &self.original {
            TransitionOriginal::Account(original) if original.terminal.is_none()
                && !matches!(original.claim.native_fields().purpose,
                    ClaimPurpose::CreateContinuationIntake | ClaimPurpose::CreateStorageUse
                        | ClaimPurpose::DeleteOperationIntake | ClaimPurpose::ExecutionOperationIntake) => {
                original.require_current(state, transaction)
            }
            TransitionOriginal::Account(_) => Err(crate::JournalError::ProtectedBoundary),
            TransitionOriginal::Q04Terminal(original) => original.require_current(state, transaction),
            TransitionOriginal::CreateIntake(original) => original.require_current(state, transaction),
            TransitionOriginal::CreateStorageUse(original) => original.require_current(state, transaction),
            TransitionOriginal::Enrollment(original) => original.require_exact(state, transaction)
                .map_err(|_| crate::JournalError::ProtectedBoundary),
            TransitionOriginal::ControllerLaunch(original) => original.require_exact(state, transaction)
                .map_err(|_| crate::JournalError::ProtectedBoundary),
            TransitionOriginal::Q04(original) => original.require_current(state, transaction)
                .map_err(|_| crate::JournalError::ProtectedBoundary),
        }
    }
}

struct AccountTransition {
    transaction_id: [u8; 16],
    before: AccountHead,
    after: AccountHead,
    claim: Claim,
    previous_claim: Option<Claim>,
    child: Option<AccountHead>,
    original_clock: Option<aos_sandbox_model::RawPairedClockSample>,
    preparation: Option<PreparationBinding>,
    terminal: Option<TerminalBinding>,
    create_storage_use: Option<bank::CreateStorageUseBindingV1>,
}

impl AccountTransition {
    fn reserve(before: AccountHead, claim: Claim) -> Result<Self, ResourceReservationErrorV1> {
        let after = bank::reserve_head(before, claim).map_err(ResourceReservationErrorV1::from)?;
        Ok(Self::reserved_parts(before, after, claim,
            aos_sandbox_model::OperationId::new().into_bytes()))
    }

    fn reserve_create_storage_use(before: AccountHead, claim: Claim,
        binding: bank::CreateStorageUseBindingV1, original_clock: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let after = bank::reserve_head(before, claim).map_err(ResourceReservationErrorV1::from)?;
        let mut transition = Self::reserved_parts(before, after, claim, binding.reserve_transaction_id()?);
        transition.original_clock = Some(original_clock);
        transition.create_storage_use = Some(binding);
        Ok(transition)
    }

    fn commit_create_storage_use(before: AccountHead, previous: Claim,
        binding: bank::CreateStorageUseBindingV1, original_clock: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let mut transition = Self::settle(before, previous, true)?;
        transition.transaction_id = binding.commit_transaction_id()?;
        transition.original_clock = Some(original_clock);
        transition.create_storage_use = Some(binding);
        Ok(transition)
    }

    fn reserved_parts(before: AccountHead, after: AccountHead, claim: Claim,
        transaction_id: [u8; 16],
    ) -> Self {
        Self {
            transaction_id,
            before,
            after,
            claim,
            previous_claim: None,
            child: None,
            original_clock: None,
            preparation: None,
            terminal: None,
            create_storage_use: None,
        }
    }

    fn settle(before: AccountHead, previous_claim: Claim, committed: bool) -> Result<Self, ResourceReservationErrorV1> {
        let (after, claim) = bank::settled_pair(before, previous_claim, committed)
            .map_err(ResourceReservationErrorV1::from)?;
        Ok(Self {
            transaction_id: aos_sandbox_model::OperationId::new().into_bytes(),
            before,
            after,
            claim,
            previous_claim: Some(previous_claim),
            child: None,
            original_clock: None,
            preparation: None,
            terminal: None,
            create_storage_use: None,
        })
    }

    // The current authority borrower supplies proposed grant DATA. Only this
    // exact immediate-parent transition makes that amount a paid grant.
    fn grant(
        before: AccountHead,
        child: AccountHead,
        claim: Claim,
        original_clock: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let generation = bank::require_grant_generation(before, child, claim, original_clock)
            .map_err(ResourceReservationErrorV1::from)?;
        Ok(Self {
            transaction_id: aos_sandbox_model::OperationId::new().into_bytes(),
            before,
            after: before
                .reserve_at_generation(generation, claim.native_fields().amount)
                .map_err(ResourceReservationErrorV1::from)?,
            claim,
            previous_claim: None,
            child: Some(child),
            original_clock: Some(original_clock),
            preparation: None,
            terminal: None,
            create_storage_use: None,
        })
    }


    fn history(&self) -> AccountMutation<'_> {
        let mutation = AccountMutation::new((
            &self.transaction_id,
            &self.before,
            &self.after,
            &self.claim,
            &self.previous_claim,
            &self.child,
            &self.preparation,
            &self.terminal,
        ));
        match self.create_storage_use.as_ref() {
            Some(binding) => mutation.with_create_storage_use_v1(binding),
            None => mutation,
        }
    }

    fn transaction(&self) -> Result<JournalTransaction, ResourceReservationErrorV1> {
        self.history()
            .transaction()
            .map_err(ResourceReservationErrorV1::from)
    }

    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        self.require_exact(state, transaction)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    fn require_exact(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.history()
            .require_exact(state, transaction)
            .map_err(ResourceReservationErrorV1::from)
    }
}


// A native append is not projected to a loan before its complete result and
// independent physical-name post are resident. Both remain owned on failure.
struct ReturnedAppend {
    original: Option<Result<AccountTransition, ResourceReservationErrorV1>>,
    transaction: Option<Result<JournalTransaction, ResourceReservationErrorV1>>,
    names: Option<Result<crate::journal::ProtectedJournalNamesV1, crate::JournalError>>,
    preflight: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    native_clock: std::cell::OnceCell<Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    readback: Option<Result<RecoveredAppend, ResourceReservationErrorV1>>,
    post: Option<Result<(), crate::JournalError>>,
}

enum AppendOriginals<'original> {
    Account,
    CreateStorageUse(CreateStorageUseBankOriginalsV1<'original>),
    Q04Terminal(Q04TerminalOriginalsV1<'original>),
    CreateIntake {
        parent: &'original ProjectPreparationReservationAttemptV1,
        entry: q04_intake::CreateIntakeBankOriginalsV1<'original>,
    },
}

impl ReturnedAppend {
    const fn new() -> Self {
        Self {
            original: None,
            transaction: None,
            names: None,
            preflight: None,
            native: None,
            native_clock: std::cell::OnceCell::new(),
            readback: None,
            post: None,
        }
    }

    // The caller parks this owner before it prepares or appends a mutation.
    // An actual native Err is retained; readback cannot overwrite that cause.
    fn append_into(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
    ) {
        self.append_for(journal, original, AppendOriginals::Account);
    }

    // Only the parent retaining the actual moved child lends these originals.
    // The common engine parks the transition before selecting its typed loan.
    fn append_q04_terminal_into(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
        retained: Q04TerminalOriginalsV1<'_>,
    ) {
        self.append_for(journal, original, AppendOriginals::Q04Terminal(retained));
    }

    fn append_create_intake_into(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
        parent: &ProjectPreparationReservationAttemptV1,
        entry: q04_intake::CreateIntakeBankOriginalsV1<'_>,
    ) {
        self.append_for(journal, original, AppendOriginals::CreateIntake { parent, entry });
    }

    // The only caller holds the actual completed Root turn, RootValidated
    // native owner and its funded same-bank use preparation simultaneously.
    fn append_create_storage_use_into(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
        retained: CreateStorageUseBankOriginalsV1<'_>,
    ) {
        self.append_for(journal, original, AppendOriginals::CreateStorageUse(retained));
    }

    fn append_for(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
        retained: AppendOriginals<'_>,
    ) {
        if self.original.is_some() {
            return;
        }
        let storage_use = match &retained {
            AppendOriginals::CreateStorageUse(original) => Some(original.observations_v1()),
            _ => None,
        };
        self.original = Some(original);
        if let Some(Ok(original)) = self.original.as_ref() {
            self.transaction = Some(original.transaction());
        }
        self.names = Some(journal.protected_writer_physical_names_v1());
        if let (Some(Ok(original)), Some(Ok(transaction))) =
            (self.original.as_ref(), self.transaction.as_ref())
        {
            self.preflight = Some(journal.controller_resource_state_v1()
                .map_err(ResourceReservationErrorV1::from)
                .and_then(|state| original.require_exact(state, transaction)));
            if self.names.as_ref().is_some_and(Result::is_ok)
                && self.preflight.as_ref().is_some_and(Result::is_ok)
            {
                self.native = Some(journal.commit_controller_resource_transition_v1(
                    transaction,
                    &Transition {
                        original: match retained {
                            AppendOriginals::Q04Terminal(retained) => TransitionOriginal::Q04Terminal(
                                Q04TerminalBankAppendV1::new(original, retained),
                            ),
                            AppendOriginals::CreateIntake { parent, entry } => TransitionOriginal::CreateIntake(
                                CreateIntakeBankAppendV1::new(original, parent, entry),
                            ),
                            AppendOriginals::CreateStorageUse(retained) => TransitionOriginal::CreateStorageUse(
                                retained.bind_transition_v1(original),
                            ),
                            AppendOriginals::Account => TransitionOriginal::Account(original),
                        },
                        crossing: match (
                            original.original_clock,
                            original.claim.native_fields().cut,
                        ) {
                            (Some(clock), ClaimCut::BootLifetime)
                                if matches!(original.claim.native_fields().purpose,
                                    ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
                                        | ClaimPurpose::Q04OriginalIntake | ClaimPurpose::CreateContinuationIntake) =>
                                Some(NativeCrossing {
                                        original: clock,
                                        deadline: clock.boottime_nanoseconds(),
                                        result: &self.native_clock,
                                    }),
                            (Some(clock), ClaimCut::Operation { deadline_boottime_nanoseconds, .. }) => Some(NativeCrossing {
                                original: clock,
                                deadline: deadline_boottime_nanoseconds,
                                result: &self.native_clock,
                            }),
                            _ => None,
                        },
                    },
                ));
            }
        }

        if self.native.is_some() {
            self.readback = Some(self.recover(journal));
        }
        self.post = Some(match storage_use {
            Some(original) => original.observe_post_once(journal, self.transaction.as_ref(), self.native.as_ref()),
            None => journal.validate_held_protected_names(),
        });
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.transaction.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.preflight.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native_clock.get().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.readback.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }

    fn require_committed(&self) -> Result<&AccountTransition, ResourceReservationErrorV1> {
        if self.failure().is_some()
            || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.native_clock.get(), Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(RecoveredAppend::Committed)))
            || !matches!(self.post, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    fn recover(&self, journal: &crate::Journal) -> Result<RecoveredAppend, ResourceReservationErrorV1> {
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if journal.protected_writer_physical_names_v1()? != *names {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let state = journal.controller_resource_state_v1()?;
        if bank::validate(state).map_err(ResourceReservationErrorV1::from)?
            != Some(original.before.native_fields().enrollment)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let head = bank::find_head(state, original.before.native_fields().id)
            .map_err(ResourceReservationErrorV1::from)?;
        let claim = bank::claim_bytes(state, original.claim.native_fields().id)
            .map(|bytes| Claim::decode(bytes).map_err(ResourceReservationErrorV1::from))
            .transpose()?;
        let recorded =
            journal.controller_resource_contains_transaction_v1(&original.transaction_id)?;
        if head == original.before
            && claim == original.previous_claim
            && original
                .child
                .is_none_or(|child| !bank::has_head(state, child.native_fields().id))
            && !recorded
            && original.preparation.is_none_or(|binding|
                bank::preparation_bytes(state, binding.claim().native_fields().id).is_none())
            && original.terminal.is_none_or(|binding|
                bank::terminal_bytes(state, binding.native_fields().original_id).is_none())
        {
            return Ok(RecoveredAppend::NotCommitted);
        }
        let child_matches = match original.child {
            Some(child) => bank::find_head(state, child.native_fields().id).map_err(ResourceReservationErrorV1::from)? == child,
            None => true,
        };
        if head == original.after && claim == Some(original.claim)
            && child_matches && recorded
        {
            if let Some(binding) = original.preparation {
                let bytes = bank::preparation_bytes(state, binding.claim().native_fields().id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if !binding
                    .matches_canonical(bytes)
                    .map_err(ResourceReservationErrorV1::from)?
                {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            if let Some(binding) = original.terminal {
                if binding.native_fields().names != *names {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                if let Some(Ok(native)) = self.native.as_ref() {
                    journal.require_q04_returned_commit_v1(native)
                        .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error)))?;
                }
                let bytes = bank::terminal_bytes(state, binding.native_fields().original_id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if !binding
                    .matches_canonical(bytes)
                    .map_err(ResourceReservationErrorV1::from)?
                {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                journal.require_controller_resource_history_v1()
                    .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error)))?;
            }
            return Ok(RecoveredAppend::Committed);
        }
        Err(ResourceReservationErrorV1::Conflict)
    }
}

enum RecoveredAppend {
    Committed,
    NotCommitted,
}

/// Rejects every generic writer's attempt to modify the private bank.
pub(crate) fn require_transition(
    state: &State,
    transaction: &JournalTransaction,
    transition: Option<&Transition>,
) -> Result<(), crate::JournalError> {
    let selected = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
    });
    match (selected, transition) {
        (false, None) => Ok(()),
        (true, Some(original)) => original.require_current(state, transaction),
        _ => Err(crate::JournalError::ProtectedBoundary),
    }
}

impl From<aos_sandbox_broker::receiving::OriginalPairErrorV1> for ResourceReservationErrorV1 {
    fn from(error: aos_sandbox_broker::receiving::OriginalPairErrorV1) -> Self {
        use aos_sandbox_broker::receiving::OriginalPairErrorV1;
        match error {
            OriginalPairErrorV1::Io(error) => Self::BootstrapIo(error),
            OriginalPairErrorV1::Descriptor(error) => Self::BootstrapDescriptor(error),
            OriginalPairErrorV1::Kernel(error) => Self::BootstrapKernel(error),
            OriginalPairErrorV1::Data(error) => error.into(),
            OriginalPairErrorV1::EnrollmentUnavailable => Self::EnrollmentUnavailable,
            OriginalPairErrorV1::Conflict => Self::Conflict,
        }
    }
}

#[doc(hidden)]
pub use create_intake::ready::{CreateStorageReadyNativeInputsV1,
    CreateStorageBundleShapeDataV1, CreateStorageBundleClosedV1, OriginalCreateStorageBundleV1};

pub use initial_session::ControllerStorageFloorPhysicalReceivingV1;

// The actual once-only signing loan and both peers use this same inert cost.
pub(crate) fn create_storage_signing_originals_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    create_intake::ready::signing_originals_receiving_demand_v1()
}

// The actual request caller and both peers share this compiled Native layout.
pub(crate) fn create_storage_preparation_originals_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_intake::ready::preparation_originals_receiving_demand_v1()
}

// The C8-only Native IO entrance and both peers use this same actual layout.
pub(crate) fn create_storage_preparation_io_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1> {
    create_intake::ready::preparation_io_receiving_demand_v1()
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use bootstrap::{ControllerDeletePlanningRootOriginalV1, ControllerDeletePlanningRootLoanV1};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use bootstrap::{ControllerDeleteFinalDisposalOriginalV4, ControllerDeletePendingRootClientOriginalV2,
    ControllerDeletePendingRootChallengeLoanV2, ControllerDeletePendingRootFailureViewV2, OriginalDeleteResourceSigningV2};

#[doc(hidden)]
pub use create_intake::provisioning::{CreateProvisioningSourceWorkspaceContextV1,
    CreateStoppedCompletionAttemptV1, CreateStoppedPreAckContextV1,
    CreateStoppedCompletionAssociationV1, CreateStoppedPreAckOriginalV1,
    CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1, CreateStoppedTerminalCustodyV1};

#[doc(hidden)]
pub use create_intake::provisioning::AcceptedStartEntryOriginalV1;

pub(crate) use create_intake::provisioning::{SourceAppendBoundaryV1,StartSourceAdmissionAuthorizationV1,StartSourcePurposeV2};

// Private typed borrowers cross module privacy without exposing their owners.
pub(crate) use create_intake::provisioning::{StartNativeStateV1, AcceptedStartPlanOriginalV1, StartTerminalAppendContextV2};

#[doc(hidden)]
pub use create_intake::provisioning::OriginalStartHostRootLoanV1;


#[doc(hidden)]
pub use create_intake::provisioning::{PreparedStartResourceRequestOriginalV2,
    PreparedStartResourceRequestClosedV2, StartHostCatalogPublicationLoanV2, StartHostCatalogIoLoanV2, StartHostCatalogNativeCompletionV2, StartHostCatalogCompletionRefusalV2, StartHostSessionRejoinOriginalV2, StartHostCatalogProjectionOriginalV2, StartHostCatalogProjectionClosedV2, StartResourceUpperDisposalV2, StartResourceSessionOpeningOriginalV2,
    StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
    StartResourceColdCompletionOriginalV4,
    StartResourceSessionAssociationV4, StartResourceHelloDisposalV4,
    StartResourceHelloDisposalErrorV4, StartResourceSessionCurrentnessErrorV4,
    StartResourceProvisioningIoLoanV2, StartResourcePreparedRequestBorrowV2,
    StartResourceSessionPostShapeDataV2, StartResourceSessionResidentShapeDataV4};

pub use create_intake::provisioning::{OriginalStartAssignmentInputsLoanV2, StartAssignmentInputsCompletedTurnV2};

#[doc(hidden)]
pub use operator_create_recovery::{OperatorReconciliationObservationCustodyV2,
    OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
    OperatorFirstLocalReconciliationCompleteV2, OperatorReconciliationInventoryProofV2,
    OperatorReconciliationInventoryLoanV2, ControllerRecoveryInventoryLoanV2,
    OperatorReconciliationObservationEntryRefusalV2, OperatorReconciliationObservationOriginalV2,
    OperatorReconciliationObservationLoanV2, ControllerReconciliationInventoryRoleV2};

pub(crate) use create_intake::provisioning::StartHostPublicationContractV2;

pub(crate) use create_intake::provisioning::start_host_publication_operation_id_data_v2;

mod source_family;

mod catalog_maintenance;
pub(crate) use catalog_maintenance::ControllerCatalogMaintenanceRootLoanV3;
#[doc(hidden)]
pub use catalog_maintenance::ControllerCatalogMaintenanceSigningBorrowV3;
#[doc(hidden)]
pub use catalog_maintenance::ControllerMaintenanceStorageRequestOriginalV3;
#[doc(hidden)]
pub use catalog_maintenance::ControllerMaintenanceStorageIoLoanV3;
#[doc(hidden)]
pub use catalog_maintenance::ControllerMaintenanceStorageSdkDisposalV3;
pub(crate) use catalog_maintenance::CatalogMaintenanceAppendContextV2;
pub(crate) use catalog_maintenance::CatalogMaintenanceSourceReceivingV2;
pub(crate) use catalog_maintenance::{
    CatalogMaintenanceCompletedStartDataV1, CatalogMaintenanceCompletedStartOriginalV1,
};
pub use catalog_maintenance::{CatalogMaintenanceClosedV2, CatalogMaintenanceOriginalV2, ControllerCatalogMaintenanceLoanV2};

pub use catalog_maintenance::{ControllerCatalogMaintenanceIoLoanV2, ControllerCatalogMaintenanceSessionCurrentnessErrorV2};

pub use catalog_maintenance::{ControllerCatalogMaintenanceCompletionRefusalV2, ControllerCatalogMaintenanceCatalogDisposalV2};

#[doc(hidden)]
pub use catalog_maintenance::CatalogMaintenanceColdCompletedNativeBorrowV2;
pub use catalog_maintenance::CatalogMaintenanceRefreshCompletedNativeBorrowV2;

#[doc(hidden)]
pub use catalog_maintenance::CatalogMaintenanceSdkShapeDataV2;

#[doc(hidden)]
pub use catalog_maintenance::CatalogMaintenanceSourceBorrowV2;
