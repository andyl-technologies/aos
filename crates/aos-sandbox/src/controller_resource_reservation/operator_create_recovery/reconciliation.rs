//! Observes one fresh endpoint under the existing successor's residual R.
//!
//! Each role has a new actual native Recover interval. Previous observations,
//! completed recovery custody and uncertain predecessor N remain resident.
//! These observations never restore old claims or enroll ordinary service.

mod receiving;
mod completion;
mod enrollment;
pub use completion::{OperatorFirstLocalReconciliationCompleteV2, OperatorReconciliationInventoryProofV2};
pub use enrollment::OperatorFirstLocalOrdinaryEnrollmentOriginalV2;

use super::*;

const CLOSED: OperatorCreateRecoveryClosedV1 = OperatorCreateRecoveryClosedV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1 as Clock, RootContinuationHorizonDataV1,
};
use aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1 as SourcePair;

pub use aos_sandbox_broker::controller_receiving::bank_launch::ControllerReconciliationInventoryRoleV2;

/// Retains either the whole entered observation or its unpaid native frontier.
///
/// Neither variant proves physical absence, service enrollment or readiness.
#[doc(hidden)]
#[must_use = "retain the complete observation and all independent posts"]
pub enum OperatorReconciliationObservationCustodyV2 {
    /// Contains the upper owner only after its complete fixed entry was paid.
    Entered(Box<OperatorReconciliationObservationOriginalV2>),
    /// Retains the original native refusal without growing the upper capsule.
    EntryRefused(OperatorReconciliationObservationEntryRefusalV2),
}

/// Retains the actual attempted lower native receiver and original contexts.
#[doc(hidden)]
pub struct OperatorReconciliationObservationEntryRefusalV2 {
    _bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    _profile: Arc<ProductionControllerNormalRootProfileV1>,
    _runtime: Arc<tokio::runtime::Runtime>,
    native: Result<ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1>,
    _fixed: Option<ResourceVector>,
    _resident: Option<ResourceVector>,
    horizon: Result<(RootContinuationHorizonDataV1, u64), ResourceReservationErrorV1>,
}

impl OperatorReconciliationObservationEntryRefusalV2 {
    /// Borrows the precise lower failure while retaining its native owner.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        if let Err(cause) = &self.horizon {
            return Some(cause);
        }
        match &self.native {
            Err(cause) => Some(cause),
            Ok(native) => native.failure(),
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Native,
    Clock,
    SourceBefore,
    SourceIdentity,
    SourceComparison,
    Funding,
    Preparation,
    Inventory,
    Sdk,
    Body,
    SourceAfter,
    ControllerAfter,
    SourceDisposal,
    FinalClock,
}

/// Retains one role's real native, cold and query observation interval.
///
/// Construction requires the genuine completed stopped seed. The containing
/// Runtime keeps prior SDK/Session owners resident while this receiver runs.
/// A completed receiver remains observation custody; ordinary enrollment still
/// needs independently authenticated complete physical reconciliation.
#[doc(hidden)]
#[must_use = "retain the whole role through native and Source disposal"]
pub struct OperatorReconciliationObservationOriginalV2 {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    runtime: Arc<tokio::runtime::Runtime>,
    native: Result<ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1>,
    role: ControllerReconciliationInventoryRoleV2,
    target: aos_sandbox_core::OperationId,
    fixed: ResourceVector,
    reached: ResourceVector,
    horizon: RootContinuationHorizonDataV1,
    cutoff: u64,
    clock: Clock,
    source: Option<Result<SourcePair, ResourceReservationErrorV1>>,
    source_identity: Option<Result<SourceProvisioningIdentityV1, crate::JournalError>>,
    source_comparison: Option<Result<(), OperatorCreateRecoveryClosedV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    receiver: Option<crate::ControllerInitialBrokerSessionReceivingV1>,
    pub(in crate::controller_resource_reservation::operator_create_recovery)
    inventory: [super::storage::inventory::InventoryOriginalsV1; 1],
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    receiver_taken: bool,
    sdk_refusal: Option<OperatorCreateRecoveryClosedV1>,
    body: Option<Result<(), OperatorCreateRecoveryClosedV1>>,
    source_after: Option<Result<(), crate::JournalError>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    source_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    final_clock_native: crate::controller::RetainedControllerProtectedClockAttemptV1,
    final_clock: Option<Result<RawPairedClockSample, crate::JournalError>>,
    final_comparison: Option<Result<(), crate::JournalError>>,
    first: Option<First>,
}

/// Lends the actual current role without lending a normal Session or intake.
#[doc(hidden)]
pub struct OperatorReconciliationObservationLoanV2<'owner, 'seed, 'completed, 'controller> {
    pub(in crate::controller_resource_reservation::operator_create_recovery)
    owner: &'owner mut OperatorReconciliationObservationOriginalV2,
    seed: &'seed OperatorRecoveredStoppedCreateSeedV1<'completed>,
    controller: &'controller Journal,
}

impl OperatorRecoveredStoppedCreateSeedV1<'_> {
    /// Begins the next closed physical observation using the same remaining R.
    ///
    /// The first role is Host, followed by Mount and Network. A successor role
    /// requires the exact previous positive native interval and includes its
    /// complete remaining residents. No old normal claim or traffic is reused.
    /// The returned owner retains refusals; it never proves an empty machine.
    #[doc(hidden)]
    pub fn begin_physical_observation_v2(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        previous: Option<&OperatorReconciliationObservationOriginalV2>,
        role: ControllerReconciliationInventoryRoleV2,
    ) -> OperatorReconciliationObservationCustodyV2 {
        let bank = Arc::clone(&self.owner.bank);
        let profile = Arc::clone(&self.owner.profile);
        let runtime = Arc::clone(&self.owner.runtime);
        let fixed = OperatorReconciliationObservationOriginalV2::fixed_demand_v2();
        let resident = (|| {
            self.require_same_current_source_v1(source)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let held = bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.require_same_completed_v1(&held, controller, &profile)?;
            drop(held);
            match (previous, role) {
                (None, ControllerReconciliationInventoryRoleV2::Host) =>
                    self.completed_resident_demand_v1(controller),
                (Some(prior), ControllerReconciliationInventoryRoleV2::Mount)
                    if prior.role == ControllerReconciliationInventoryRoleV2::Host =>
                    prior.completed_resident_v2(self, controller, source),
                (Some(prior), ControllerReconciliationInventoryRoleV2::Network)
                    if prior.role == ControllerReconciliationInventoryRoleV2::Mount =>
                    prior.completed_resident_v2(self, controller, source),
                _ => Err(ResourceReservationErrorV1::Conflict),
            }
        })();
        let resident_data = resident.as_ref().ok().copied();
        let horizon = self.original_horizon_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)
            .and_then(|(original, cutoff, wall)|
                RootContinuationHorizonDataV1::from_original_data_v1(original, cutoff)
                    .map(|horizon| (horizon.with_wall_expiry_data_v1(wall), cutoff))
                    .map_err(ResourceReservationErrorV1::Journal));
        let native = (|| {
            let fixed = fixed.ok_or(ResourceReservationErrorV1::Conflict)?;
            let resident = resident?;
            if horizon.is_err() { return Err(ResourceReservationErrorV1::Conflict); }
            bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_operator_recover_receiving_v1(controller, &profile,
                    fixed.checked_add(resident)?)
        })();
        if !native.as_ref().is_ok_and(|native| native.require_prepaid_owed_observation_v1().is_ok()) {
            return OperatorReconciliationObservationCustodyV2::EntryRefused(
                OperatorReconciliationObservationEntryRefusalV2 {
                    _bank: bank, _profile: profile, _runtime: runtime, native,
                    _fixed: fixed, _resident: resident_data, horizon,
                });
        }
        // These fields were validated before the sole lower debit. Their
        // failure branch remains a whole lower entry above, never an unpaid Box.
        let (horizon, cutoff) = match horizon {
            Ok(bounds) => bounds,
            Err(cause) => return OperatorReconciliationObservationCustodyV2::EntryRefused(
                OperatorReconciliationObservationEntryRefusalV2 {
                    _bank: bank, _profile: profile, _runtime: runtime, native,
                    _fixed: fixed, _resident: resident_data, horizon: Err(cause),
                }),
        };
        OperatorReconciliationObservationCustodyV2::Entered(Box::new(
            OperatorReconciliationObservationOriginalV2 {
                bank, profile, runtime, native, role, target: self.target_v1(),
                fixed: fixed.unwrap_or(ResourceVector::ZERO),
                reached: resident_data.unwrap_or(ResourceVector::ZERO),
                horizon, cutoff, clock: Clock::new_controller_authorization_v1(horizon),
                source: None, source_identity: None, source_comparison: None,
                funding: None, receiver: None, inventory: std::array::from_fn(|_| Default::default()),
                preparation: None, receiver_taken: false,
                sdk_refusal: None, body: None, source_after: None, controller_after: None,
                source_disposal: None, final_clock_native: Default::default(),
                final_clock: None, final_comparison: None, first: None,
            }))
    }
}
