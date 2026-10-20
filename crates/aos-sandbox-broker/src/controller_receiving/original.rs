//! Shares the same original Controller C custody with its selected receiver.
//!
//! The original first-table files, one residual ledger and retained control
//! bookends stay together. A selected profile may borrow this private owner;
//! decoded policy DATA and caller resource amounts cannot construct it.

mod catalog_maintenance;
use catalog_maintenance::require_ordinary_session_context_v2;
mod recovered_sessions;
use recovered_sessions::recovered_session_is_current_v2;

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use aos_sandbox_core::ResourceVector;

use super::budget::{BaselineDemand, BaselineOwner};
use crate::receiving::ComponentReceivingOwnedOperationV1;
use super::startup_envelope::{ControllerStartupEnvelopeV1, CredentialPurposeV1};
use crate::receiving::{OriginalEnrollment, OriginalEnrollmentPairAttemptV1};
use super::initial_delivery::ControllerEnrollmentDeliveryV1;
use super::ControllerReceivingErrorV1;
use aos_sandbox_protocol::domain_ledger::resource_bank as bank;

/// Holds one actual first-table Controller original and its monotonic ledger.
pub struct ControllerReceivingOriginalV1 {
    original: ControllerEnrollmentDeliveryV1,
    layout: bank::NativeLayoutDemand,
    usage: Mutex<BaselineOriginalState>,
    initial_self_execution: std::sync::OnceLock<Result<
        Arc<aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard>,
        Arc<aos_sandbox_linux::self_execution::RetainedSelfExecutionCaptureError>,
    >>,
    pub(in crate::controller_receiving) operation_intakes:
        Mutex<super::operation_intake::ControllerOperationIntakesV1>,
}

/// Records an actual permanent recovered intake debit on the SAME B ledger.
///
/// Fields and constructor stay in this owning module. This is financial
/// provenance only; no claim, native completion, operation or Ready is minted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) struct RecoveredOperationIntakeFundingV2 {
    purpose: super::operation_intake::OperationIntakePurposeV1,
    identity: bank::EnrollmentIdentity,
    recipient: [u8; 16],
    complete: ResourceVector,
    declared: ResourceVector,
    record: bank::RecoveredOperationFundingDataV1,
}

impl RecoveredOperationIntakeFundingV2 {
    pub(in crate::controller_receiving) fn purpose_v2(self)
        -> super::operation_intake::OperationIntakePurposeV1 { self.purpose }

    pub(in crate::controller_receiving) fn complete_v2(self) -> ResourceVector { self.complete }
    pub(in crate::controller_receiving) fn record_data_v1(self) -> bank::RecoveredOperationFundingDataV1 { self.record }
}

/// Holds only the genuine initial Stop seed debit captured by this original.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) struct RecoveredLifecycleStopFundingV3 {
    record: bank::RecoveredStopSeedFundingDataV3,
}

impl RecoveredLifecycleStopFundingV3 {
    pub(in crate::controller_receiving) fn record_data_v3(self) -> bank::RecoveredStopSeedFundingDataV3 {
        self.record
    }
}

/// Selects one closed residual liability on the same current C ledger.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum ContinuationReceivingPurposeV1 {
    CreateProvisioning,
    LifecycleStop,
    RecoveredLifecycleStop,
    OperatorRecover,
    RecoveredEnrollment,
    CatalogMaintenance,
    RecoveredOrdinarySession(super::initial_session::ControllerInitialBrokerSessionRoleV1),
}

impl ContinuationReceivingPurposeV1 {
    fn owner_v1(self) -> BaselineOwner {
        match self {
            Self::CreateProvisioning | Self::LifecycleStop => BaselineOwner::CreateProvisioning,
            Self::RecoveredLifecycleStop => BaselineOwner::RecoveredLifecycleStop,
            Self::OperatorRecover => BaselineOwner::OperatorRecover,
            Self::RecoveredEnrollment => BaselineOwner::RecoveredEnrollment,
            Self::CatalogMaintenance => BaselineOwner::CatalogMaintenance,
            Self::RecoveredOrdinarySession(role) => role.recovered_owner_v2(),
        }
    }
}

struct BaselineOriginalState {
    initial_pair: OriginalEnrollmentPairAttemptV1,
    original: Option<OriginalEnrollment>,
    baseline: Option<ResourceVector>,
    demand: BaselineDemand,
    initial_session_claimed: [bool; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
    recovered_sessions_entered: bool,
    recovered_session_claimed: [bool; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
    recovered_session_completed: [bool; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
    source_construction_claimed: bool,
    create_continuation_claimed: bool,
    original_observers_claimed: [bool; 3],
    cache_prebank_import_claimed: bool,
    selected_entered: bool,
    launch_entered: bool,
    runtime_entered: bool,
    source_issue_entered: bool,
    continuation_base: Option<ResourceVector>,
    continuation_purpose: Option<ContinuationReceivingPurposeV1>,
    recovered_enrollment_entered: bool,
    startup: Option<ControllerStartupEnvelopeV1>,
    failed_profile_operation: Option<ComponentReceivingOwnedOperationV1>,
    publisher: super::publisher_schedule::PublisherOperationReservationV1,
    active_scope: bool,
    closed: bool,
    construction_pool_entered: bool,
    construction_pool_paid: bool,
    posts_entered: [bool; 2],
    posts_retired: [bool; 2],
}

/// Names only the two real staged Native construction bookends.
#[derive(Clone, Copy)]
pub(in crate::controller_receiving) enum ControllerConstructionPostV1 {
    SourceConstruction,
    ControllerConstruction,
}

impl ControllerReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn begin(original: ControllerEnrollmentDeliveryV1, layout: bank::NativeLayoutDemand) -> Self {
        Self {
            original,
            layout,
            operation_intakes: Mutex::new(super::operation_intake::ControllerOperationIntakesV1::new()),
            initial_self_execution: std::sync::OnceLock::new(),
            usage: Mutex::new(BaselineOriginalState {
                initial_pair: OriginalEnrollmentPairAttemptV1::new_controller(layout),
                original: None,
                baseline: None,
                demand: BaselineDemand::new(),
                initial_session_claimed: [false; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
                recovered_sessions_entered: false,
                recovered_session_claimed: [false; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
                recovered_session_completed: [false; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
                source_construction_claimed: false,
                create_continuation_claimed: false,
                original_observers_claimed: [false; 3],
                cache_prebank_import_claimed: false,
                selected_entered: false,
                launch_entered: false,
                runtime_entered: false,
                source_issue_entered: false,
                continuation_base: None,
                continuation_purpose: None,
                recovered_enrollment_entered: false,
                startup: None,
                failed_profile_operation: None,
                publisher: super::publisher_schedule::PublisherOperationReservationV1::new(),
                active_scope: false,
                closed: false,
                construction_pool_entered: false,
                construction_pool_paid: false,
                posts_entered: [false; 2],
                posts_retired: [false; 2],
            }),
        }
    }

    /// Compares the actual upper native layout DATA before selected admission.
    ///
    /// This performs no IO and establishes no original or receiving authority.
    #[must_use]
    pub fn matches_native_layout(&self, layout: bank::NativeLayoutDemand) -> bool {
        self.layout == layout
    }

    /// Reports deny-only closure of this actual receiving original.
    #[doc(hidden)]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.usage.try_lock().map_or(true, |state| state.closed || state.demand.is_closed())
    }

    // Called only by the opening that consumed the original first-table pair.
    // The fixed pair attempt precedes dynamic receiver growth; its initial
    // installed Controller envelope is also its negative-prefix backstop.
    pub(super) fn enter_selected_once(&self) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.selected_entered || state.closed || self.process != std::process::id() {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.selected_entered = true;
        let original = match state.initial_pair.observe_once(&self.policy, &self.enrollment) {
            Ok(original) => *original,
            Err(_) => {
                state.closed = true;
                return Err(ControllerReceivingErrorV1::EnrollmentUnavailable);
            }
        };
        let (heads, ..) = match bank::prepare_enrollment_subdivisions(
            original.identity, original.policy, self.layout,
        ) {
            Ok(prepared) => prepared,
            Err(cause) => {
                state.closed = true;
                return Err(ControllerReceivingErrorV1::from(cause));
            }
        };
        state.original = Some(original);
        let baseline = heads[1].recorded_baseline();
        state.baseline = Some(baseline);
        if original.policy.bootstrap_provisions().controller_recovery.is_some() {
            let result = (|| {
                let (image_baseline, normal, recovery) = original.policy.controller_baseline_partition_v1()?;
                let (recipients, allowance) = original.policy.controller_recovery_range_v1()
                    .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
                let commitment = bank::controller_recipient_range_commitment_v1(original.identity, original.policy)?;
                if original.controller_range_commitment_v2 != Some(commitment) {
                    return Err(ControllerReceivingErrorV1::Conflict);
                }
                let prefix = super::ControllerStartupOpeningV1::enrollment_range_prefix_receiving_demand_v2(recipients)?;
                // Both envelopes must contain the actual compiled prefix. The
                // image-authorized producer backstop still precedes this read.
                normal.checked_sub(prefix)?;
                allowance.checked_sub(prefix)?;
                let generation = original.controller_generation_v1
                    .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
                if image_baseline != baseline { return Err(ControllerReceivingErrorV1::Conflict); }
                state.demand.bind_recipient_range_v2(baseline, normal, recovery, allowance, recipients, generation)
            })();
            if result.is_err() { state.closed = true; }
            result?;
        } else if original.controller_generation_v1.is_some() {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    // This leaf compares the already-admitted actual C. It performs no IO or
    // allocation and cannot construct an original from a decoded claim.
    pub(in crate::controller_receiving) fn operation_intake_enrollment_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || !state.selected_entered || !state.runtime_entered {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
    }

    fn recovered_operation_enrollment_v2(&self, state: &BaselineOriginalState,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self)
            || state.closed || state.demand.is_closed() || state.active_scope
            || !state.selected_entered || !state.runtime_entered
            || state.continuation_base.is_some() || state.continuation_purpose.is_some()
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
        { return Err(ControllerReceivingErrorV1::Conflict); }
        let observed = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        if !is_recovered_range_recipient_v2(observed) {
            return Err(ControllerReceivingErrorV1::EnrollmentUnavailable);
        }
        Ok(observed)
    }

    pub(in crate::controller_receiving) fn recovered_operation_remaining_data_v2(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        self.recovered_operation_enrollment_v2(&state, profile)?;
        state.demand.remaining_data_v2()
    }

    // Only the closed same completed Recover/Bank/Launch factory calls this.
    // The old D/X reservations remain unknown and entirely untouched.
    pub(in crate::controller_receiving) fn fund_recovered_operation_intake_v2(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        purpose: super::operation_intake::OperationIntakePurposeV1,
        complete: ResourceVector, controller_next: u64, controller_end: u64,
    ) -> Result<RecoveredOperationIntakeFundingV2, ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let observed = self.recovered_operation_enrollment_v2(&state, profile)?;
        let result = (|| {
            let declared = purpose.declared_amount_v2(observed.policy)
                .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            declared.checked_sub(complete)?;
            let owner = purpose.recovered_baseline_owner_v2();
            if complete == ResourceVector::ZERO || state.demand.owner_complete(owner) != ResourceVector::ZERO {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let charged_before = provision.checked_sub(state.demand.remaining_data_v2()?)?;
            // This real complete debit consumes remaining R after carried N,
            // all prior Recover spending and every existing owner highwater.
            state.demand.begin()?;
            state.demand.raise(owner, complete, provision)?;
            let charged_after = provision.checked_sub(state.demand.remaining_data_v2()?)?;
            let record = bank::RecoveredOperationFundingDataV1 {
                purpose: match purpose {
                    super::operation_intake::OperationIntakePurposeV1::Delete => bank::RecoveredOperationFundingPurposeV1::Delete,
                    super::operation_intake::OperationIntakePurposeV1::Execution => bank::RecoveredOperationFundingPurposeV1::Execution,
                    super::operation_intake::OperationIntakePurposeV1::LifecycleStop => return Err(ControllerReceivingErrorV1::Conflict),
                },
                enrollment: observed.identity, recipient: observed.recipient_invocation,
                baseline: provision, charged_before, charged_after, complete, declared,
                controller_next, controller_end,
            };
            record.encode_v1()?;
            Ok(RecoveredOperationIntakeFundingV2 { purpose, identity: observed.identity,
                recipient: observed.recipient_invocation, complete, declared, record })
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    pub(in crate::controller_receiving) fn require_recovered_operation_funding_v2(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        receipt: RecoveredOperationIntakeFundingV2,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let observed = self.recovered_operation_enrollment_v2(&state, profile)?;
        if receipt.identity != observed.identity || receipt.recipient != observed.recipient_invocation
            || receipt.complete == ResourceVector::ZERO
            || receipt.declared != receipt.purpose.declared_amount_v2(observed.policy)
                .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
            || state.demand.owner_complete(receipt.purpose.recovered_baseline_owner_v2()) != receipt.complete
        { return Err(ControllerReceivingErrorV1::Conflict); }
        receipt.declared.checked_sub(receipt.complete)?;
        Ok(())
    }

    pub(in crate::controller_receiving) fn begin_operation_intake_profile_v1(
        self: &Arc<Self>,
        purpose: super::operation_intake::OperationIntakePurposeV1,
        slot: usize,
    ) -> Result<ControllerControlScopeV1, ControllerReceivingErrorV1> {
        // Only a consumed full flight can select these finite bookends. The
        // after slots remain owed after primary poison; this is no fresh entry.
        self.operation_intakes.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .slot_mut(purpose).enter_profile_once(slot)?;
        let mut scope = ControllerControlScopeV1::new(Arc::clone(self), None);
        scope.intake = Some((purpose, slot));
        scope.before_result = Some(scope.observe_before());
        scope.before_binding = Some(scope.compare_before());
        Ok(scope)
    }

    // The sole opening parks this returned whole Result beside its actual
    // launch owner. Neither a caller vector nor a second reservation escapes.
    pub(in crate::controller_receiving) fn reserve_bank_launch_once(
        &self,
    ) -> Result<(), super::bank_launch::ControllerBankLaunchErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.launch_entered || state.closed || state.active_scope
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict.into());
        }
        state.launch_entered = true;
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let demand = super::bank_launch::ControllerBankLaunchOriginalV1::fixed_demand_v1()?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::ControllerLaunch, demand, provision)?;
            Ok(())
        })();
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    pub(in crate::controller_receiving) fn bind_initial_program_fd_mode_v1(
        &self,
        capture: &super::profile::ControllerProfileCaptureV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if !state.selected_entered || state.active_scope || state.closed
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let result = state.demand.bind_initial_program_mode_v1(
            capture.has_original_tpm_image_delivery_v1(),
        );
        if result.is_err() { state.closed = true; }
        result
    }

    pub(in crate::controller_receiving) fn capture_initial_execution_v1(
        self: &Arc<Self>,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<crate::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
        crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>
    {
        use crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1 as Failure;
        self.require_initial_session_current_v1(role).map_err(|_| Failure::Unavailable)?;
        self.capture_fixed_session_execution_v1(role)
    }

    pub(in crate::controller_receiving) fn capture_fixed_session_execution_v1(
        self: &Arc<Self>, role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<crate::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
        crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>
    {
        use crate::endpoint_native_files::{ControllerEndpointExecutionOriginalV1 as Guard,
            ControllerEndpointExecutionCaptureErrorV1 as Failure};
        let required = self.usage.try_lock().map_err(|_| Failure::Unavailable)?
            .demand.initial_program_required_v1().map_err(|_| Failure::Unavailable)?;
        // Never hold the accounting Mutex during native capture. The once-only
        // destination itself serializes the sole capture and preserves its raw
        // negative owner; later roles cannot recapture/reconnect after refusal.
        let capture = || aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard::capture_retaining()
            .map(Arc::new).map_err(Arc::new);
        let mut freshly_captured = false;
        let captured = if required {
            match self.initial_self_execution.get_or_init(|| {
                freshly_captured = true;
                capture()
            }) {
                Ok(guard) => Ok(Arc::clone(guard)),
                Err(cause) => Err(Arc::clone(cause)),
            }
        } else {
            // NonRequired selected routes retain their independent original
            // native capture at the same old frontier.
            freshly_captured = true;
            capture()
        };
        captured.map(|guard| Guard::from_shared_v1(guard, self, role, freshly_captured))
            .map_err(Failure::Native)
    }

    // Runtime's closed constructor calls this once inside its already paid
    // original profile scope. Only pure structural/Core arithmetic occurs
    // under this Mutex; both independent PID1 bookends stay outside it.
    pub(super) fn reserve_runtime_startup_once(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        shape: super::shapes::ControllerRuntimeStartupShapeV1,
        credentials: super::shapes::ControllerRuntimeCredentialShapeV1,
        recipient: ([u8; 16], [u8; 16]),
        task_envelope: super::shapes::ControllerRuntimeTaskEnvelopeV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let (profile_bound, credential_profile_bound, construction_bound) = profile.original_startup_pool_bounds(self)?;
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.runtime_entered || state.source_issue_entered || !state.selected_entered || !state.active_scope
            || state.closed || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.runtime_entered = true;
        let result = (|| {
            let expected = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            if expected.recipient_invocation != recipient.0
                || expected.identity.native_fields().invocation != recipient.1
            {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            task_envelope.require_same_profile_v1(profile)?;
            state.demand.require_initial_program_mode_v1(profile.has_tpm_image_delivery())?;
            let fixed = shape.fixed_demand_with_task_envelope_v1(task_envelope)?;
            let resident = credentials.resident_credential_demand()?;
            let public = credentials.public_tls_demand()?;
            let publisher = if shape.publisher {
                super::publisher_schedule::operation_demand()?
            } else { ResourceVector::ZERO };
            state.startup = Some(ControllerStartupEnvelopeV1::new(
                profile_bound, credential_profile_bound, construction_bound,
                credentials.source_proof_files.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?,
                public, publisher, shape.public_listener, shape.publisher,
            )?);
            let peak = state.startup.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?.peak();
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::SelectedProfile, peak, provision)?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::RuntimeFixed, fixed, provision)?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::RuntimeCredentials, resident, provision)
        })();
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    /// Restricts this same C to the installed issue-only retained startup.
    ///
    /// `complete` describes the actual upper fixed credential/constructor
    /// representation. It supplies no work, native handle or semantic grant.
    /// Runtime admission is a different, mutually exclusive continuation.
    ///
    /// # Errors
    /// Retains unavailable, foreign, repeated or insufficient original demand.
    #[doc(hidden)]
    pub fn debit_source_successor_issue_startup_once_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.source_issue_entered || state.runtime_entered || state.startup.is_some()
            || !state.selected_entered || state.closed || state.active_scope
            || state.construction_pool_entered || self.process != std::process::id()
        { return Err(ControllerReceivingErrorV1::Conflict); }
        state.source_issue_entered = true;
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::SourceSuccessorIssue, complete, provision)
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    // The same fixed role latch is spent before Domain derives actual native
    // geometry. No native/profile IO runs while this pure Mutex is held.
    pub(in crate::controller_receiving) fn claim_initial_session_role_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.runtime_entered
            || state.initial_session_claimed[role.index()]
            || state.original.is_some_and(|original| is_recovered_range_recipient_v2(original))
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.initial_session_claimed[role.index()] = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_initial_session_current_v1(
        &self,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || !state.initial_session_claimed[role.index()]
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn initial_session_current_temporary_shape_v1() -> (usize, usize) {
        type Guard = std::sync::MutexGuard<'static, BaselineOriginalState>;
        (std::mem::size_of::<std::sync::TryLockResult<Guard>>()
            + std::mem::size_of::<Guard>()
            + std::mem::size_of::<super::initial_session::ControllerInitialBrokerSessionRoleV1>()
            + std::mem::size_of::<usize>() + std::mem::size_of::<&Self>() + std::mem::size_of::<u32>(), 0)
    }

    // Purpose-local representation debit only. This returns no Native capture,
    // account, limit, IO permission or positive semantic disposition.
    pub(in crate::controller_receiving) fn debit_initial_session_complete_v1(
        &self,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        // This second lock follows the actual upper geometry computation and
        // rechecks the same Serving/role/process state before the sole ledger.
        if state.closed || state.active_scope || !state.runtime_entered
            || !state.initial_session_claimed[role.index()]
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            state.demand.begin()?;
            state.demand.raise(role.owner(), complete, provision)
        })();
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    // The actual persistent Storage receiver calls this only after charging
    // its complete bound on the same InitialStorageSession ledger owner. No
    // capacity or operation escapes; the whole arithmetic original is parked
    // in that receiver before consumption can fail.
    pub(in crate::controller_receiving) fn prepare_storage_physical_operation_v1(
        &self,
        required: ResourceVector,
        destination: &mut Option<ComponentReceivingOwnedOperationV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.prepare_storage_physical_with_context_v1(PhysicalSessionFundingV3::Initial, required, destination)
    }

    pub(in crate::controller_receiving) fn prepare_operator_recover_physical_operation_v1(
        &self, base: ResourceVector, required: ResourceVector,
        destination: &mut Option<ComponentReceivingOwnedOperationV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.prepare_storage_physical_with_context_v1(PhysicalSessionFundingV3::OperatorRecover(base), required, destination)
    }

    fn prepare_storage_physical_with_context_v1(
        &self, funding: PhysicalSessionFundingV3, required: ResourceVector,
        destination: &mut Option<ComponentReceivingOwnedOperationV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let role = super::initial_session::ControllerInitialBrokerSessionRoleV1::Storage;
        if destination.is_some() || state.closed || state.demand.is_closed()
            || state.active_scope || !state.runtime_entered
            || match funding {
                PhysicalSessionFundingV3::Initial => !state.initial_session_claimed[role.index()],
                PhysicalSessionFundingV3::OperatorRecover(base) => state.continuation_base != Some(base)
                    || state.continuation_purpose != Some(ContinuationReceivingPurposeV1::OperatorRecover),
                PhysicalSessionFundingV3::RecoveredOrdinary(role) =>
                    !recovered_session_is_current_v2(&state, role),
            }
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let baseline = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        *destination = Some(ComponentReceivingOwnedOperationV1::preflight(baseline, required));
        let operation = destination.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?;
        if operation.consume_once().is_err() {
            state.closed = true;
            return Err(operation.failure().map(|cause| ControllerReceivingErrorV1::Accounting(*cause))
                .unwrap_or(ControllerReceivingErrorV1::Conflict));
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn fence_initial_session_representation_v1(
        &self,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        state.closed = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn initial_session_node_v1(
        &self,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<[u8; 16], ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || !state.initial_session_claimed[role.index()]
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let original = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        Ok(original.identity.native_fields().node)
    }

    // Only the genuine opening constructs the fixed Publisher receiver.
    // No native/profile work runs while this pure accounting Mutex is held.
    pub(super) fn claim_publisher_receiving(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        startup: super::publisher_schedule::ControllerPublisherStartupDataV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.runtime_entered
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let expected = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        if expected.identity.native_fields().node != *startup.scope.node.as_bytes()
            || startup.uid == 0 || startup.gid == 0
            || super::publisher_schedule::validate_scope(startup.scope).is_err()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let capacity = state.startup.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .publisher_capacity()?;
        let result = state.publisher.claim_startup_capacity(capacity);
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    pub(super) fn begin_publisher_operation(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.runtime_entered
            || self.process != std::process::id()
        {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .publisher_capacity()?;
        let result = state.publisher.begin();
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    pub(in crate::controller_receiving) fn require_publisher_operation(&self) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.runtime_entered
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.publisher.require_active()
    }

    pub(super) fn finish_publisher_operation(&self) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || self.process != std::process::id() {
            state.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let result = state.publisher.finish();
        if result.is_err() {
            state.closed = true;
        }
        result
    }

    pub(super) fn close_publisher_receiving(&self) {
        let Ok(mut state) = self.usage.lock() else {
            std::process::abort();
        };
        state.publisher.close();
        state.closed = true;
    }

    pub(super) fn claim_startup_credential(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        purpose: CredentialPurposeV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.runtime_entered
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .claim_credential(purpose)
    }

    pub(super) fn begin_startup_credential(&self, purpose: CredentialPurposeV1)
        -> Result<(ResourceVector, ResourceVector), ControllerReceivingErrorV1>
    {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || self.process != std::process::id() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .begin_credential(purpose)
    }

    // The fixed credential engine has disposed native proofs and its complete
    // profile scope before invoking this private continuation.
    pub(super) fn finish_startup_credential(&self, purpose: CredentialPurposeV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || self.process != std::process::id() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .credential_disposed(purpose)
    }

    pub(super) fn enrolled_startup_disposition(&self) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || state.posts_retired != [true; 2]
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?.enrolled()
    }

    pub(super) fn serve_startup_without_public(&self) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || self.process != std::process::id() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?.serve_without_public()
    }

    pub(super) fn require_runtime_recipient(
        &self,
        invocation: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_cache_recipient(invocation, producer)
    }

    pub(super) fn require_native_complete(
        &self,
        owner: BaselineOwner,
        demand: ResourceVector,
        provision: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.demand.begin()?;
        state.demand.raise(owner, demand, provision)
    }

    // Only the Cache initializer's genuine selected scope uses this route.
    // It performs pure Core arithmetic under its already-current original;
    // no bank/profile/Native IO occurs while an authority Mutex is held.
    pub(in crate::controller_receiving) fn raise_cache_complete(
        &self,
        owner: BaselineOwner,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || !state.active_scope {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        state.demand.begin()?;
        state.demand.raise(owner, complete, provision)
    }

    pub(in crate::controller_receiving) fn reserve_construction_posts_once(
        &self,
        demand: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.construction_pool_entered || state.active_scope || state.closed {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.construction_pool_entered = true;
        if let Some(envelope) = state.startup.as_mut() {
            envelope.begin_construction()?;
            envelope.construction_capacity()?.checked_sub(demand)?;
        }
        let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        state.demand.begin()?;
        state.demand.raise(BaselineOwner::SelectedProfile, demand, provision)?;
        state.construction_pool_paid = true;
        Ok(())
    }

    // These once-only lanes were paid BEFORE the actual Controller/Source
    // operation. An earlier primary failure cannot turn them into new funding.
    pub(in crate::controller_receiving) fn begin_construction_post(
        self: &Arc<Self>,
        purpose: ControllerConstructionPostV1,
    ) -> Result<ControllerControlScopeV1, ControllerReceivingErrorV1> {
        {
            let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if !state.construction_pool_paid || state.posts_entered[purpose as usize] {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            state.posts_entered[purpose as usize] = true;
        }
        let bound = {
            let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            match state.startup.as_ref() {
                Some(envelope) => envelope.construction_post_capacity()?,
                None => ResourceVector::ZERO,
            }
        };
        let operation = if bound == ResourceVector::ZERO {
            None
        } else {
            Some(self.consume_profile_operation(bound)?)
        };
        let mut scope = ControllerControlScopeV1::new(Arc::clone(self), Some(purpose));
        scope.operation = operation;
        scope.before_result = Some(scope.observe_before());
        scope.before_binding = Some(scope.compare_before());
        Ok(scope)
    }

    pub(in crate::controller_receiving) fn raise_profile_complete(
        &self,
        demand: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || !state.active_scope {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        state.demand.begin()?;
        state.demand.raise(BaselineOwner::SelectedProfile, demand, provision)
    }

    // Only the actual selected admission/currentness receiver invokes this
    // private fixed-owner entry. The amount is its in-crate shape supplier,
    // never a public payer, caller epoch, replacement file or resource claim.
    pub(in crate::controller_receiving) fn begin_profile_scope(
        self: &Arc<Self>,
        demand: ResourceVector,
    ) -> Result<ControllerControlScopeV1, ControllerReceivingErrorV1> {
        {
            let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if !state.selected_entered || state.closed || state.active_scope {
                state.closed = true;
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            // Arm before arithmetic: interruption cannot silently permit a
            // second receiver under the same retained original.
            state.active_scope = true;
            if let Some(envelope) = &state.startup {
                envelope.profile_capacity()?.checked_sub(demand)?;
            }
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::SelectedProfile, demand, provision)?;
        }
        let operation = self.consume_profile_operation(demand)?;
        let mut scope = ControllerControlScopeV1::new(Arc::clone(self), None);
        scope.operation = Some(operation);
        scope.before_result = Some(scope.observe_before());
        scope.before_binding = Some(scope.compare_before());
        Ok(scope)
    }

    fn consume_profile_operation(&self, required: ResourceVector)
        -> Result<ComponentReceivingOwnedOperationV1, ControllerReceivingErrorV1>
    {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let capacity = match &state.startup {
            Some(envelope) => envelope.profile_capacity()?,
            None => required,
        };
        let mut operation = ComponentReceivingOwnedOperationV1::preflight(capacity, required);
        if operation.consume_once().is_err() {
            let cause = operation.failure().map(|cause| ControllerReceivingErrorV1::Accounting(*cause))
                .unwrap_or(ControllerReceivingErrorV1::Conflict);
            state.failed_profile_operation = Some(operation);
            state.closed = true;
            return Err(cause);
        }
        Ok(operation)
    }

    pub(in crate::controller_receiving) fn require_cache_recipient(
        &self,
        invocation: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.expected()?;
        if expected.recipient_invocation != invocation
            || expected.identity.native_fields().invocation != producer
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows the original canonical enrollment as comparison DATA only.
    ///
    /// This does not observe currentness, enroll a Bank or construct a loan.
    /// Actual callers independently join the same measured profile/controls.
    ///
    /// # Errors
    /// Refuses unavailable, closed or foreign-process original custody.
    #[doc(hidden)]
    pub fn observed_enrollment_data_v1(&self) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.is_closed() || self.process != std::process::id() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.expected()
    }

    /// Claims one named original P/I/Q observer entrance once.
    ///
    /// # Errors
    /// Rejects foreign profile/process custody, reentry or closed/unselected C.
    pub(in crate::controller_receiving) fn claim_original_observers_once_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        purpose: super::bank_launch::OriginalObserverPurposeV1,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let ordinal = match purpose {
            super::bank_launch::OriginalObserverPurposeV1::FirstGlobal => 0,
            super::bank_launch::OriginalObserverPurposeV1::NixIntake => 1,
            super::bank_launch::OriginalObserverPurposeV1::Q04Intake => 2,
            super::bank_launch::OriginalObserverPurposeV1::CreateIntake => {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        };
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.original_observers_claimed[ordinal] {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.original_observers_claimed[ordinal] = true;
        if state.closed || state.demand.is_closed() || !state.selected_entered {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
    }

    /// Rejoins this named observer origin to its actual original/profile.
    ///
    /// # Errors
    /// Rejects unclaimed, closed or foreign original/profile custody.
    pub(in crate::controller_receiving) fn require_original_observer_profile_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        purpose: super::bank_launch::OriginalObserverPurposeV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let ordinal = match purpose {
            super::bank_launch::OriginalObserverPurposeV1::FirstGlobal => 0,
            super::bank_launch::OriginalObserverPurposeV1::NixIntake => 1,
            super::bank_launch::OriginalObserverPurposeV1::Q04Intake => 2,
            super::bank_launch::OriginalObserverPurposeV1::CreateIntake => {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        };
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if !state.original_observers_claimed[ordinal] || state.closed || state.demand.is_closed()
            || !state.selected_entered
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    /// Claims the same original's one Create-continuation financial entrance.
    ///
    /// Failed native-claim validation cannot create a second J ledger.
    ///
    /// # Errors
    /// Refuses a foreign profile/process, repeated claim or closed/unselected C.
    pub(in crate::controller_receiving) fn claim_create_continuation_once_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.create_continuation_claimed { return Err(ControllerReceivingErrorV1::Conflict); }
        state.create_continuation_claimed = true;
        if state.closed || state.demand.is_closed() || !state.selected_entered {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
    }

    /// Rejoins the claimed J to the actual same original/profile without IO.
    ///
    /// # Errors
    /// Refuses unclaimed, closed, foreign-process or foreign-profile custody.
    pub(in crate::controller_receiving) fn require_create_continuation_profile_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.process != std::process::id() || !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if !state.create_continuation_claimed || state.closed || state.demand.is_closed()
            || !state.selected_entered {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    // Only the fixed Bank/writer subtree consumes these original projections.
    // They do not expose a ledger or accept an imported provision/layout.
    pub(in crate::controller_receiving) fn writer_native_layout(&self) -> bank::NativeLayoutDemand {
        self.layout
    }

    pub(in crate::controller_receiving) fn writer_enrollment(
        &self,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        self.expected()
    }

    pub(in crate::controller_receiving) fn claim_source_prebank_construction_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.source_construction_claimed || !state.construction_pool_paid
            || state.closed || state.active_scope || state.posts_entered[0]
            || self.process != std::process::id()
        { return Err(ControllerReceivingErrorV1::Conflict); }
        state.source_construction_claimed = true;
        if let Some(envelope) = state.startup.as_ref() { envelope.construction_capacity()?; }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_source_native_representation_v1(
        &self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let provision = {
            let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if !state.source_construction_claimed || state.closed || self.process != std::process::id() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
        };
        self.require_native_complete(BaselineOwner::SourceNative, complete, provision)
    }

    pub(in crate::controller_receiving) fn claim_cache_prebank_import_once_v1(
        &self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !profile.has_same_baseline_original(self) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.selected_entered || !state.runtime_entered
            || state.cache_prebank_import_claimed || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.startup.as_ref().ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
            .require_cache_prebank_import()?;
        state.cache_prebank_import_claimed = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn arm_create_provisioning_control_v1(
        self: &Arc<Self>,
        demand: ResourceVector,
    ) -> ControllerControlScopeV1 {
        let mut scope = ControllerControlScopeV1::new(Arc::clone(self), None);
        scope.provisioning = true;
        let prepared = (|| {
            let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if state.closed || state.active_scope || state.continuation_base.is_none()
                || self.process != std::process::id()
            {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let purpose = state.continuation_purpose.ok_or(ControllerReceivingErrorV1::Conflict)?;
            scope.continuation_purpose = Some(purpose);
            let paid = state.demand.owner_complete(purpose.owner_v1());
            scope.operation = Some(ComponentReceivingOwnedOperationV1::preflight(paid, demand));
            scope.operation.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
                .consume_once().map_err(|_| ControllerReceivingErrorV1::Conflict)
        })();
        if let Err(cause) = prepared { scope.before_binding = Some(Err(cause)); }
        scope
    }

    // Minted only while the same active provisioning purpose still owns its
    // financial base. Its actual destination later verifies completed native
    // custody before entering slots2/3; no post-ACK debit or claim is created.
    pub(in crate::controller_receiving) fn arm_create_provisioning_completion_control_v1(
        self: &Arc<Self>, demand: ResourceVector,
    ) -> ControllerControlScopeV1 {
        let mut control = self.arm_create_provisioning_control_v1(demand);
        control.provisioning_completion = true;
        control
    }

    pub(in crate::controller_receiving) fn begin_continuation_complete_v1(
        &self,
        purpose: ContinuationReceivingPurposeV1,
        complete: ResourceVector,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        use aos_sandbox_core::component_receiving::operation_traffic_demand_v1;
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || !state.selected_entered || !state.runtime_entered
            || state.continuation_base.is_some()
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        // Old images cannot reconstruct a safe residual after a recipient cut.
        // The actual writer/Launch gate separately requires the durable seal.
        let original = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        original.policy.controller_baseline_partition_v1()?;
        match (purpose, original.controller_generation_v1) {
            (ContinuationReceivingPurposeV1::CreateProvisioning, Some(0))
            | (ContinuationReceivingPurposeV1::LifecycleStop, Some(0))
                => {}
            (ContinuationReceivingPurposeV1::OperatorRecover, Some(ordinal))
                if ordinal > 0 && is_recovered_range_recipient_v2(original) => {}
            (ContinuationReceivingPurposeV1::CatalogMaintenance, Some(_)) => {
                require_ordinary_session_context_v2(&state)?;
            }
            (ContinuationReceivingPurposeV1::RecoveredOrdinarySession(role), Some(ordinal))
                if ordinal > 0 && is_recovered_range_recipient_v2(original) => {
                if !state.recovered_sessions_entered || state.recovered_session_claimed[role.index()] {
                    return Err(ControllerReceivingErrorV1::Conflict);
                }
                state.recovered_session_claimed[role.index()] = true;
            }
            (ContinuationReceivingPurposeV1::RecoveredLifecycleStop, Some(ordinal))
                if ordinal > 0 && is_recovered_range_recipient_v2(original) => {
                // Only the closed native factory can obtain this purpose. Its
                // own intrinsic seed remains occupied; no durable row adopts it.
                self.operation_intakes.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?
                    .slot(super::operation_intake::OperationIntakePurposeV1::LifecycleStop)
                    .require_stop_seed_v3()?;
            }
            (ContinuationReceivingPurposeV1::RecoveredEnrollment, Some(ordinal))
                if ordinal > 0 && is_recovered_range_recipient_v2(original) => {
                if state.recovered_enrollment_entered {
                    return Err(ControllerReceivingErrorV1::Conflict);
                }
                // This finite enrollment remains spent on failure; another
                // fresh interval cannot renew it or reset residual liability.
                state.recovered_enrollment_entered = true;
            }
            _ => return Err(ControllerReceivingErrorV1::EnrollmentUnavailable),
        }
        let base = operation_traffic_demand_v1(state.demand.owner_complete(purpose.owner_v1()));
        // Arm before arithmetic, so refusal or interruption cannot silently
        // start another provisioning turn on this same original.
        state.continuation_base = Some(base);
        state.continuation_purpose = Some(purpose);
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(complete)?;
            state.demand.begin()?;
            state.demand.raise(purpose.owner_v1(), complete, provision)
        })();
        if result.is_err() { state.closed = true; }
        result.map(|()| base)
    }

    pub(in crate::controller_receiving) fn require_operator_recover_session_current_v1(
        &self, base: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || state.continuation_base != Some(base)
            || state.continuation_purpose != Some(ContinuationReceivingPurposeV1::OperatorRecover)
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_recovered_stop_session_current_v1(
        &self, base: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || state.continuation_base != Some(base)
            || state.continuation_purpose != Some(ContinuationReceivingPurposeV1::RecoveredLifecycleStop)
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn raise_continuation_complete_v1(
        &self,
        purpose: ContinuationReceivingPurposeV1,
        base: ResourceVector,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || (state.continuation_base != Some(base) || state.continuation_purpose != Some(purpose))
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(complete)?;
            state.demand.begin()?;
            state.demand.raise(purpose.owner_v1(), complete, provision)
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    // Only the owning fixed receiver calls this after its real independent
    // names/profile/control/Ended/launch posts succeeded. Nothing is refunded:
    // owner highwater and all traffic from this turn stay in the same ledger.
    pub(in crate::controller_receiving) fn finish_continuation_native_v1(
        &self,
        purpose: ContinuationReceivingPurposeV1,
        base: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || (state.continuation_base != Some(base) || state.continuation_purpose != Some(purpose))
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.continuation_base = None;
        state.continuation_purpose = None;
        Ok(())
    }

    /// Restricts upper coordinator representation on this SAME genuine ledger.
    ///
    /// This non-authorizing debit returns no account, permit, handler, finish
    /// token or protected IO ability. The real Domain coordinator computes its
    /// actual compiled layout before wrapper growth and retains this Result.
    /// Fixed role admission and all native/Bank/launch gates remain mandatory.
    ///
    /// # Errors
    /// Refuses unavailable/closed original, arithmetic overflow or insufficient
    /// original capacity. Refusal cannot open or rearm another financial owner.
    #[doc(hidden)]
    pub fn debit_coordinator_representation_v1(
        &self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let provision = {
            let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if !state.selected_entered || state.closed || self.process != std::process::id() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
        };
        self.require_native_complete(BaselineOwner::CoordinatorRepresentation, complete, provision)
    }

    pub(in crate::controller_receiving) fn require_fixed_writer_complete(
        &self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let provision = {
            let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if !state.selected_entered || state.closed || self.process != std::process::id() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
        };
        self.require_native_complete(BaselineOwner::ControllerNative, complete, provision)
    }

    fn expected(&self) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
    }
}

impl Drop for ControllerReceivingOriginalV1 {
    fn drop(&mut self) {
        let abandoned = self.usage.get_mut().map_or(true, |state| {
            state.closed || state.active_scope || state.continuation_base.is_some() || state.demand.is_closed()
                || state.startup.as_ref().is_some_and(|startup| startup.is_unfinished())
        });
        let intake_unfinished = self.operation_intakes.get_mut()
            .map_or(true, |intakes| intakes.is_unfinished());
        if abandoned || intake_unfinished {
            std::process::abort();
        }
    }
}

impl Deref for ControllerReceivingOriginalV1 {
    type Target = ControllerEnrollmentDeliveryV1;

    fn deref(&self) -> &Self::Target {
        &self.original
    }
}

/// Retains complete original controls around one actually prepaid receive.
pub(in crate::controller_receiving) struct ControllerControlScopeV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    before: Option<OriginalEnrollmentPairAttemptV1>,
    after: Option<OriginalEnrollmentPairAttemptV1>,
    before_result: Option<Result<OriginalEnrollment, ControllerReceivingErrorV1>>,
    before_binding: Option<Result<(), ControllerReceivingErrorV1>>,
    after_result: Option<Result<OriginalEnrollment, ControllerReceivingErrorV1>>,
    binding: Option<Result<(), ControllerReceivingErrorV1>>,
    retired: bool,
    post: Option<ControllerConstructionPostV1>,
    intake: Option<(super::operation_intake::OperationIntakePurposeV1, usize)>,
    provisioning: bool,
    continuation_purpose: Option<ContinuationReceivingPurposeV1>,
    provisioning_completion: bool,
    operation: Option<ComponentReceivingOwnedOperationV1>,
}

impl ControllerControlScopeV1 {
    fn new(original: Arc<ControllerReceivingOriginalV1>, post: Option<ControllerConstructionPostV1>) -> Self {
        let layout = original.layout;
        Self {
            original,
            before: Some(OriginalEnrollmentPairAttemptV1::new_controller(layout)),
            after: Some(OriginalEnrollmentPairAttemptV1::new_controller(layout)),
            before_result: None,
            before_binding: None,
            after_result: None,
            binding: None,
            retired: false,
            post,
            intake: None,
            provisioning: false,
            continuation_purpose: None,
            provisioning_completion: false,
            operation: None,
        }
    }

    pub(in crate::controller_receiving) fn start_prearmed_provisioning_v1(
        &mut self,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !self.provisioning || self.before_result.is_some() || self.before_binding.is_some()
            || self.operation.as_ref().is_none_or(|operation| !operation.is_consumed_current())
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.before_result = Some(self.observe_before());
        self.before_binding = Some(self.compare_before());
        self.require_before()
    }

    fn observe_before(&mut self) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        self.before.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .observe_once(&self.original.policy, &self.original.enrollment)
            .copied().map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)
    }

    fn compare_before(&self) -> Result<(), ControllerReceivingErrorV1> {
        let before = self.before_result.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        if self.original.process != std::process::id() || *before != self.original.expected()? {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_before(&self) -> Result<(), ControllerReceivingErrorV1> {
        if matches!(self.before_binding, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerReceivingErrorV1::EnrollmentUnavailable) }
    }

    pub(in crate::controller_receiving) fn before_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation.as_ref().filter(|_| self.provisioning && self.before_result.is_none())
            .and_then(ComponentReceivingOwnedOperationV1::failure).map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.before.as_ref().and_then(OriginalEnrollmentPairAttemptV1::failure))
            .or_else(|| self.before_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.before_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    // Runs independently after receiver/semantic failure. This actual pair
    // attempt owns the same file Results and partial buffers on every path.
    pub(in crate::controller_receiving) fn finish_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.after_result.is_some() || self.retired {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.after_result = Some(self.after.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .observe_once(&self.original.policy, &self.original.enrollment)
            .copied().map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable));
        self.binding = Some((|| {
            self.require_before()?;
            let after = self.after_result.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            if *after != self.original.expected()? {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            Ok(())
        })());
        if matches!(self.binding, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerReceivingErrorV1::EnrollmentUnavailable) }
    }

    pub(in crate::controller_receiving) fn require_recipient(
        &self,
        invocation: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.original.expected()?;
        if expected.recipient_invocation != invocation
            || expected.identity.native_fields().invocation != producer
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    // The closed receiver calls this ONLY after complete semantic success,
    // clean native Ended and actual transport disposal. It changes no account
    // or charge; it merely permits another operation at the same paid peak.
    pub(in crate::controller_receiving) fn retire_positive_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.retired || self.intake.is_some() || !matches!(self.binding, Some(Ok(()))) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let mut state = self.original.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if self.provisioning {
            if state.closed || (!self.provisioning_completion && (state.continuation_base.is_none()
                    || state.continuation_purpose != self.continuation_purpose))
                || state.demand.is_closed() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        } else if self.post.is_none() && (state.closed || !state.active_scope || state.demand.is_closed()) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        // These actual successful fixed control reservoirs are disposed while
        // entry is still closed. No next receive can overlap their storage.
        drop(self.before.take());
        drop(self.after.take());
        self.before_result = None;
        self.before_binding = None;
        self.after_result = None;
        if let Some(purpose) = self.post {
            state.posts_retired[purpose as usize] = true;
        } else if !self.provisioning {
            state.active_scope = false;
            if let Some(envelope) = state.startup.as_mut() {
                // Only the first normal disposal after Runtime funding can
                // leave RuntimeProfile; every later disposal preserves stage.
                envelope.profile_disposed()?;
            }
        }
        if let Some(operation) = self.operation.take() {
            operation.complete_after_disposal();
        }
        self.retired = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn uses_operation_intake_v1(&self) -> bool {
        self.intake.is_some()
    }

    pub(in crate::controller_receiving) fn prepare_operation_intake_disposal_v1(
        &mut self,
    ) -> Result<ControllerOperationProfileDisposalV1<'_>, ControllerReceivingErrorV1> {
        if self.retired || !matches!(self.binding, Some(Ok(()))) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let (purpose, slot) = self.intake.ok_or(ControllerReceivingErrorV1::Conflict)?;
        let mut state = self.original.operation_intakes.try_lock()
            .map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        state.slot_mut(purpose).prepare_profile_disposal_once(slot)?;
        Ok(ControllerOperationProfileDisposalV1 {
            state, purpose, slot, before: &mut self.before, after: &mut self.after,
            retired: &mut self.retired,
        })
    }

    pub(in crate::controller_receiving) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // The actual before comparison happened before any independent after
        // IO. Its retained Conflict must win over a later native read error.
        self.before_failure()
            .or_else(|| self.after.as_ref().and_then(OriginalEnrollmentPairAttemptV1::failure))
            .or_else(|| self.after_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

}

impl Drop for ControllerControlScopeV1 {
    fn drop(&mut self) {
        if !self.retired {
            // An abandoned negative/ambiguous scope must not release native
            // causes or partial inputs before its service is terminated.
            std::process::abort();
        }
    }
}

// All fallible profile/control checks and this lock happen with the actual
// archive/local/partial owners resident. Completion follows their real Drop.
pub(in crate::controller_receiving) struct ControllerOperationProfileDisposalV1<'scope> {
    state: std::sync::MutexGuard<'scope, super::operation_intake::ControllerOperationIntakesV1>,
    purpose: super::operation_intake::OperationIntakePurposeV1,
    slot: usize,
    before: &'scope mut Option<OriginalEnrollmentPairAttemptV1>,
    after: &'scope mut Option<OriginalEnrollmentPairAttemptV1>,
    retired: &'scope mut bool,
}

impl ControllerOperationProfileDisposalV1<'_> {
    pub(in crate::controller_receiving) fn complete_after_disposal_v1(mut self) {
        drop(self.before.take());
        drop(self.after.take());
        self.state.slot_mut(self.purpose).retire_profile_after_disposal(self.slot);
        *self.retired = true;
    }
}

impl ControllerReceivingOriginalV1 {
    // DATA only: no capacity return, debt reset or new interval admission.
    pub(in crate::controller_receiving) fn completed_operator_recover_resident_demand_v1(
        &self,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.active_scope || state.continuation_base.is_some()
            || self.process != std::process::id()
            || state.original.is_none_or(|original| !is_recovered_range_recipient_v2(original))
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(aos_sandbox_core::component_receiving::without_operation_traffic_v1(
            state.demand.owner_complete(BaselineOwner::OperatorRecover),
        ))
    }
}


impl ControllerReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn require_recovered_intakes_funded_v2(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        use super::operation_intake::OperationIntakePurposeV1 as Purpose;
        let intakes = self.operation_intakes.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        for purpose in [Purpose::Delete, Purpose::Execution] {
            let receipt = intakes.slot(purpose).recovered_idle_funding_v2()?;
            self.require_recovered_operation_funding_v2(profile, receipt)?;
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_recovered_enrollment_active_v2(
        &self, base: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope
            || !state.recovered_enrollment_entered || !state.runtime_entered
            || state.continuation_base != Some(base)
            || state.continuation_purpose != Some(ContinuationReceivingPurposeV1::RecoveredEnrollment)
            || self.process != std::process::id() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }
}


#[derive(Clone, Copy)]
enum PhysicalSessionFundingV3 {
    Initial,
    OperatorRecover(ResourceVector),
    RecoveredOrdinary(super::initial_session::ControllerInitialBrokerSessionRoleV1),
}


impl ControllerReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn fund_recovered_stop_seed_v3(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        complete: ResourceVector, next: u64, end: u64,
    ) -> Result<RecoveredLifecycleStopFundingV3, ControllerReceivingErrorV1> {
        self.fund_recovered_stop_seed_kind_v4(profile, complete, next, end, None)
    }

    pub(in crate::controller_receiving) fn fund_recovered_stop_cleanup_seed_v1(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        complete: ResourceVector, next: u64, end: u64,
        association: bank::RecoveredHostStopCleanupAssociationDataV1,
    ) -> Result<RecoveredLifecycleStopFundingV3, ControllerReceivingErrorV1> {
        self.fund_recovered_stop_seed_kind_v4(profile, complete, next, end, Some(association))
    }

    // Both finite origins raise the SAME permanent owner in the SAME ledger.
    // Their private native association and replay prerequisites stay distinct.
    fn fund_recovered_stop_seed_kind_v4(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        complete: ResourceVector, next: u64, end: u64,
        association: Option<bank::RecoveredHostStopCleanupAssociationDataV1>,
    ) -> Result<RecoveredLifecycleStopFundingV3, ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let observed = self.recovered_operation_enrollment_v2(&state, profile)?;
        let result = (|| {
            let owner = BaselineOwner::RecoveredLifecycleStop;
            if complete == ResourceVector::ZERO || state.demand.owner_complete(owner) != ResourceVector::ZERO {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let baseline = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let charged_before = baseline.checked_sub(state.demand.remaining_data_v2()?)?;
            state.demand.begin()?;
            state.demand.raise(owner, complete, baseline)?;
            let charged_after = baseline.checked_sub(state.demand.remaining_data_v2()?)?;
            let ordinary = bank::RecoveredLifecycleStopFundingDataV2 {
                enrollment: observed.identity, recipient: observed.recipient_invocation,
                baseline, charged_before, charged_after, complete,
                controller_next: next, controller_end: end,
            };
            let record = match association {
                None => {
                    ordinary.encode_v2()?;
                    bank::RecoveredStopSeedFundingDataV3::Ordinary(ordinary)
                }
                Some(association) => {
                    let cleanup = bank::RecoveredHostStopCleanupFundingDataV1 {
                        enrollment: ordinary.enrollment, recipient: ordinary.recipient,
                        baseline: ordinary.baseline, charged_before: ordinary.charged_before,
                        charged_after: ordinary.charged_after, complete: ordinary.complete,
                        controller_next: ordinary.controller_next, controller_end: ordinary.controller_end,
                        association,
                    };
                    cleanup.encode_v1()?;
                    bank::RecoveredStopSeedFundingDataV3::Cleanup(cleanup)
                }
            };
            Ok(RecoveredLifecycleStopFundingV3 { record })
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    pub(in crate::controller_receiving) fn require_recovered_stop_seed_v3(
        &self, profile: &super::profile::ControllerSelfProfileOriginalV1,
        receipt: RecoveredLifecycleStopFundingV3,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        // Current native turns legitimately own continuation_base; the actual
        // immutable recipient/profile/baseline and permanent seed still match.
        let observed = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        if state.closed || state.demand.is_closed() || self.process != std::process::id()
            || !profile.has_same_baseline_original(self)
            || !is_recovered_range_recipient_v2(observed)
            || observed.identity != receipt.record.enrollment_v3()
            || observed.recipient_invocation != receipt.record.recipient_v3()
            || state.baseline != Some(receipt.record.baseline_v3())
        { return Err(ControllerReceivingErrorV1::Conflict); }
        state.demand.owner_complete(BaselineOwner::RecoveredLifecycleStop)
            .checked_sub(receipt.record.complete_v3())?;
        Ok(())
    }
}

impl ControllerReceivingOriginalV1 {
    // The first native seed interval consumes its exact earlier debit once.
    // Subsequent Stop turns use ordinary begin_continuation_complete_v1 and
    // accumulate traffic from this permanently retained owner highwater.
    pub(in crate::controller_receiving) fn begin_recovered_stop_seed_continuation_v3(
        &self, complete: ResourceVector,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope
            || !state.selected_entered || !state.runtime_entered
            || state.continuation_base.is_some() || state.continuation_purpose.is_some()
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
            || state.original.is_none_or(|original| !is_recovered_range_recipient_v2(original))
        { return Err(ControllerReceivingErrorV1::Conflict); }
        self.operation_intakes.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .slot(super::operation_intake::OperationIntakePurposeV1::LifecycleStop)
            .require_stop_seed_v3()?;
        state.continuation_base = Some(ResourceVector::ZERO);
        state.continuation_purpose = Some(ContinuationReceivingPurposeV1::RecoveredLifecycleStop);
        let result = state.demand.owner_complete(BaselineOwner::RecoveredLifecycleStop)
            .checked_sub(complete).map(|_| ResourceVector::ZERO).map_err(Into::into);
        if result.is_err() { state.closed = true; }
        result
    }
}

// This deny-only predicate borrows the actual paired observation. It cannot
// authenticate a scalar ordinal or replace the live Launch/current-writer gate.
fn is_recovered_range_recipient_v2(original: crate::receiving::OriginalEnrollment) -> bool {
    match (original.controller_generation_v1, original.policy.controller_recovery_range_v1()) {
        (Some(ordinal), Some((recipients, _))) if ordinal > 0 && ordinal <= recipients =>
            bank::controller_recipient_range_commitment_v1(original.identity, original.policy)
                .is_ok_and(|commitment| original.controller_range_commitment_v2 == Some(commitment)),
        _ => false,
    }
}
