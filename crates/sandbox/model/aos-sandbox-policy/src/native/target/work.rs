//! Retains the actual Q04 compilation, publication and returned native results.
//!
//! This work borrows the resident compiler-state target. Its genuine Authority
//! gen1 loan is short-lived at each operation, so Authority can later advance
//! without a self-reference or a second target writer. A failed result remains
//! resident before independently owed native or original-clock checks.

mod current;
mod verifier;
mod compilation;
mod history;
mod prehold;
mod publication;
mod terminal;
mod receiving;

use super::RootPolicyTargetOriginalV1;
use crate::native::publication::{
    PolicyCompilerJournalErrorV1, PolicyCompilerReplayValidatorV1,
    PolicyPublicationPrerequisitesV1, PreparedPolicyPublicationV1, Q04PolicyPublicationAttemptV1,
    Q04PolicyPublicationReadbackV1, Q04PublicationCapacityV1,
};
use crate::{CompiledPolicyCandidateV1, PolicyCompilerInputV1};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use std::cell::RefCell;
use std::sync::OnceLock;

pub use current::RootOriginalInputLoanV1;
pub use history::RootPolicyHistoryAdmissionFailureV1;
pub(in crate::native) use current::{RootCurrentOwnerLoanV1, RootOriginalPublicationLoanV1};
pub(in crate::native) use verifier::{RootCurrentInputVerifierV1, RootInputCurrentPurposeV1};

/// Preserves a refused Policy role's original typed native or model cause.
#[derive(Debug, thiserror::Error)]
pub enum RootPolicyPublicationErrorV1 {
    /// The actual native Authority/gen1 join failed.
    #[error(transparent)]
    Authority(#[from] crate::native::authority::RootAuthorityErrorV1),
    /// The actual target's fixed native, append or financial owner refused.
    #[error(transparent)]
    Journal(#[from] crate::native::PolicyNativeJournalErrorV1),
    /// The same native Origin retained its crossing failure and owed posts.
    #[error(transparent)]
    Origin(#[from] aos_sandbox_broker::receiving::RootQ04OriginErrorV1),
    /// The actual Origin was already borrowed by another reached operation.
    #[error(transparent)]
    OriginBorrow(#[from] std::cell::BorrowMutError),
    /// The canonical Q04 packet or Stage was malformed.
    #[error(transparent)]
    Data(#[from] crate::q04_data::PolicyQ04DataErrorV1),
    /// The sole signed original-row trio comparison refused.
    #[error(transparent)]
    OriginalRows(#[from] aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowsDataErrorV1),
    /// The existing publication schema or typed transaction custody refused.
    #[error(transparent)]
    Publication(#[from] PolicyCompilerJournalErrorV1),
    /// The same authenticated model constructor refused the input.
    #[error(transparent)]
    Model(#[from] crate::PolicyModelError),
    /// The sole inherited parentless input recipe refused its model.
    #[error(transparent)]
    Input(#[from] crate::parentless_input::ParentlessPolicyInputDataErrorV1),
    /// The same signed project/deployment model refused materialization.
    #[error(transparent)]
    SignedInput(#[from] crate::signed_inputs::SignedPolicyInputDataErrorV1),
    /// The same deterministic compiler rejected its retained input.
    #[error(transparent)]
    Compilation(#[from] crate::PolicyCompilationError),
    /// The canonical Cache hold DATA comparison failed.
    #[error(transparent)]
    Cache(#[from] aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1),
    /// An actual original field or current-role association changed.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The actual unchanged original flight deadline was reached.
    #[error("the original Q04 flight deadline expired")]
    Expired,
    /// A complete actual representation exceeded its existing bound.
    #[error("the original Q04 input or suffix exceeds its bound")]
    Bounds,
}

// These are compiler DATA, not a caller-installable publication capability.
pub(in crate::native) struct RootCompilerInputDataV1 {
    input: PolicyCompilerInputV1,
    prerequisites: PolicyPublicationPrerequisitesV1,
    normalized: ObjectDigest,
    candidate: CompiledPolicyCandidateV1,
    binding: Vec<u8>,
}

// This retains the actual compiler result. A scalar snapshot cannot create
// the validator, publication capability or native binding-history eligibility.
struct RootPreholdCompilationV1 {
    data: RootCompilerInputDataV1,
    validator: PolicyCompilerReplayValidatorV1,
    before_controller: ObjectDigest,
    effect_plan: ObjectDigest,
    operation_revision: ObjectDigest,
    desired_precondition: ObjectDigest,
    controller: crate::controller_project_readback::VerifiedControllerProjectAdmissionV1,
}

type RootPolicyTargetBeforeDataV1 = (
    u64,
    aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
    ObjectDigest,
);

// The recipe is resident comparison DATA from the actual adapter. It has no
// commit entry and cannot replace the real held compiler or native History.
struct RootPreholdPublicationPlanV1 {
    capacity: Q04PublicationCapacityV1,
    identity: aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    root_before: RootPolicyTargetBeforeDataV1,
    original_precut: ObjectDigest,
    policy_before: ObjectDigest,
    independent_recipe: ObjectDigest,
    claim_length: usize,
}

// The private marker identifies only this reached observation's retained
// names sink. It never enters the public owning error projection surface.
struct RootPolicyReadbackObservationV1 {
    outcome: Result<Q04PolicyPublicationReadbackV1, RootPolicyPublicationErrorV1>,
    names_failure: Option<usize>,
}

// Only an actual parked prehold plan can lend this passive forecast input.
pub(in crate::native) struct RootPolicyPreholdHistoryInputV1<'work> {
    pub(in crate::native) identity: &'work aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    pub(in crate::native) binding: &'work [u8],
    pub(in crate::native) root_before: RootPolicyTargetBeforeDataV1,
    pub(in crate::native) target_before: RootPolicyTargetBeforeDataV1,
    pub(in crate::native) claim_length: usize,
}

// This receipt is borrowed only after this Work retained the real positive
// strict append and its exact native readback. There is no DATA constructor.
pub(in crate::native) struct RootPolicyPublicationReceiptV1<'work> {
    pub(in crate::native) identity: &'work aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    pub(in crate::native) binding: &'work [u8],
    pub(in crate::native) target_before: RootPolicyTargetBeforeDataV1,
    pub(in crate::native) sequence: u64,
    pub(in crate::native) transaction: ObjectDigest,
    pub(in crate::native) current: ObjectDigest,
}

// Only the Work that authenticated both compiler inputs can lend this receipt.
// Its binding is borrowed from the resident actual compiler result; a caller
// cannot install another binding or synthesize the original target observation.
pub(in crate::native) struct RootPolicyHeldHistoryInputV1<'work> {
    pub(in crate::native) identity: &'work aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    pub(in crate::native) binding: &'work [u8],
    pub(in crate::native) target_before: RootPolicyTargetBeforeDataV1,
    pub(in crate::native) claim_length: usize,
}

/// Owns one actual target loan and its same-flight publication reservoirs.
///
/// The inert work constructor grants no admission or currentness. Every
/// positive entry separately receives the genuine Authority gen1 borrower,
/// verifies the original packets and retains the same Origin through Finish.
#[must_use]
pub struct RootPolicyPublicationWorkV1<'target> {
    target: &'target mut RootPolicyTargetOriginalV1,
    cause: OnceLock<RootPolicyPublicationErrorV1>,
    postcheck_debt: OnceLock<RootPolicyPublicationErrorV1>,
    target_post_failure: OnceLock<RootPolicyPublicationErrorV1>,
    secondary_panic: RefCell<Option<Box<dyn std::any::Any + Send>>>,
    prehold_entered: bool,
    prehold_compilation: Option<Result<RootPreholdCompilationV1, RootPolicyPublicationErrorV1>>,
    target_before_entered: bool,
    target_before: Option<Result<RootPolicyTargetBeforeDataV1, RootPolicyPublicationErrorV1>>,
    root_before_entered: bool,
    root_before: Option<Result<RootPolicyTargetBeforeDataV1, RootPolicyPublicationErrorV1>>,
    held_entered: bool,
    held_claim_length: Option<usize>,
    held_compilation: Option<Result<RootCompilerInputDataV1, RootPolicyPublicationErrorV1>>,
    prehold_plan_entered: bool,
    prehold_plan: Option<Result<RootPreholdPublicationPlanV1, RootPolicyPublicationErrorV1>>,
    history_entered: bool,
    history_complete: bool,
    publication_entered: bool,
    publication_complete: bool,
    decision_readback_entered: bool,
    decision_readback: Option<RootPolicyReadbackObservationV1>,
    held_consumed: bool,
    readback_names: Vec<crate::native::RootPolicyNameObservationOriginalV1>,
    repeated_readbacks: Vec<RootPolicyReadbackObservationV1>,
    publication: Option<Q04PolicyPublicationAttemptV1>,
    preparation: Option<Result<PreparedPolicyPublicationV1, RootPolicyPublicationErrorV1>>,
    native: Option<JournalTransaction>,
    returned: Option<Result<(), RootPolicyPublicationErrorV1>>,
    readback: Option<RootPolicyReadbackObservationV1>,
}

impl RootPolicyTargetOriginalV1 {
    /// Borrows the actual resident target into inert per-flight result custody.
    ///
    /// The real receiver prepays the compiled work/control representations
    /// before this infallible move. No path, map, payer or success DATA is input.
    #[must_use]
    pub fn begin_q04_publication_work_v1(&mut self) -> RootPolicyPublicationWorkV1<'_> {
        RootPolicyPublicationWorkV1 {
            target: self,
            cause: OnceLock::new(),
            postcheck_debt: OnceLock::new(),
            target_post_failure: OnceLock::new(),
            secondary_panic: RefCell::new(None),
            prehold_entered: false,
            prehold_compilation: None,
            target_before_entered: false,
            target_before: None,
            root_before_entered: false,
            root_before: None,
            held_entered: false,
            held_claim_length: None,
            held_compilation: None,
            prehold_plan_entered: false,
            prehold_plan: None,
            history_entered: false,
            history_complete: false,
            publication_entered: false,
            publication_complete: false,
            decision_readback_entered: false,
            decision_readback: None,
            held_consumed: false,
            readback_names: Vec::new(),
            repeated_readbacks: Vec::new(),
            publication: None,
            preparation: None,
            native: None,
            returned: None,
            readback: None,
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1>
    for RootPolicyPublicationErrorV1
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1,
    ) -> Self {
        Self::Data(crate::q04_data::PolicyQ04DataErrorV1::History(error))
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Bounds actual resident work, constructor and return/control planes.
    ///
    /// Dynamic compiler/model/packet/native demands remain separately paid at
    /// their original before-growth frontiers; this DATA issues no receiving grant.
    #[must_use]
    pub fn fixed_carrier_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(current::target_names_post_control_bytes_v1()?)?
            .checked_add(std::mem::size_of::<&Self>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), ()>>().checked_mul(3)?)
    }
}

pub(in crate::native) fn retain_model_verification_v1(
    cause: &OnceLock<RootPolicyPublicationErrorV1>,
    outcome: Result<bool, RootPolicyPublicationErrorV1>,
) -> bool {
    match outcome {
        Ok(true) => true,
        Ok(false) => {
            let _later = cause.set(RootPolicyPublicationErrorV1::ChangedCut);
            false
        }
        Err(error) => {
            let _later = cause.set(error);
            false
        }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Borrows the actual target and same-origin current loan for Authority append.
    ///
    /// The short gen1 association is checked before the borrower returns; the
    /// borrower retains the real external Origin, not an Authority alias.
    ///
    /// # Errors
    /// Preserves native/payer errors and rejects a refused or foreign original.
    pub fn borrow_authority_input_v1<'cut, 'origin, 'startup>(
        &'cut self,
        flight: &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>,
    ) -> Result<RootOriginalInputLoanV1<'cut, 'origin, 'startup>, ()>
    {
        if self.failure_v1().is_some() { return Err(()); }
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let controls = std::mem::size_of::<Result<RootOriginalInputLoanV1<'_, '_, '_>, ()>>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok());
        let admitted = controls
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)
            .and_then(|bytes| self.target.journal.admit_role_observation_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            ));
        if let Err(error) = admitted {
            let _later = self.cause.set(error.into());
            return Err(());
        }
        match RootOriginalInputLoanV1::from_ready_flight_v1(self.target, flight,
            &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)
        {
            Ok(original) => Ok(original),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }
}


impl RootPolicyPublicationWorkV1<'_> {
    /// Rechecks the actual borrowed target at the original named-location slot.
    ///
    /// # Errors
    /// Retains the target's actual native name/health failure before later posts.
    pub fn require_original_target_names_v1(&self) -> Result<(), crate::native::PolicyNativeJournalErrorV1> {
        self.target.require_original_input_names_v1()
    }

    /// Completes the actual independent Target names post after an earlier refusal.
    ///
    /// This uses the same real Target as the Input loan and retains the actual
    /// reached failure in its dedicated post site; it creates no current loan.
    ///
    /// # Errors
    /// Returns a marker only after retaining the exact Target post failure.
    pub fn require_original_target_names_post_once_v1(&self) -> Result<(), ()> {
        current::observe_target_names_post_once_v1(self.target, &self.target_post_failure)
    }

    /// Borrows Input currentness for an actual pre-gen1 Source observation.
    ///
    /// This checks the genuine ready Flight and same selected financial owner;
    /// it confers neither a completed floor nor Policy publication eligibility.
    ///
    /// # Errors
    /// Rejects refused, ordinary or foreign custody and retains original causes.
    pub fn source_observation_input_loan_v1<'cut, 'origin, 'startup>(
        &'cut self,
        flight: &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>,
    ) -> Result<RootOriginalInputLoanV1<'cut, 'origin, 'startup>, ()> {
        if self.failure_v1().is_some() { return Err(()); }
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let controls = std::mem::size_of::<Result<RootOriginalInputLoanV1<'_, '_, '_>, ()>>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok());
        let admitted = controls
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)
            .and_then(|bytes| self.target.journal.admit_role_observation_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            ));
        if let Err(error) = admitted {
            let _later = self.cause.set(error.into());
            return Err(());
        }
        match RootOriginalInputLoanV1::from_ready_flight_v1(
            self.target, flight, &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic,
        ) {
            Ok(original) => Ok(original),
            Err(error) => {
                let _later = self.cause.set(error);
                Err(())
            }
        }
    }
}


impl Drop for RootPolicyPublicationWorkV1<'_> {
    fn drop(&mut self) {
        let failed_prehold = self.prehold_entered
            && !matches!(self.prehold_compilation, Some(Ok(_)));
        let failed_target_before = self.target_before_entered
            && !matches!(self.target_before, Some(Ok(_)));
        let failed_held = self.held_entered
            && !self.held_consumed && !matches!(self.held_compilation, Some(Ok(_)));
        let failed_plan = self.prehold_plan_entered
            && !matches!(self.prehold_plan, Some(Ok(_)));
        if self.root_before_entered && !matches!(self.root_before, Some(Ok(_)))
            || self.decision_readback_entered && !self.decision_readback.as_ref().is_some_and(|observation| observation.outcome.is_ok())
            || self.publication_entered && !self.publication_complete
            || failed_plan || self.history_entered && !self.history_complete
            || failed_prehold || failed_target_before || failed_held || self.cause.get().is_some()
            || self.postcheck_debt.get().is_some() || self.target_post_failure.get().is_some()
            || self.secondary_panic.get_mut().is_some()
            || matches!(self.held_compilation, Some(Err(_)))
            || matches!(self.preparation, Some(Err(_)))
            || matches!(self.returned, Some(Err(_)))
            || self.readback.as_ref().is_some_and(|observation| observation.outcome.is_err())
        {
            std::process::abort();
        }
    }
}


impl From<aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1> for RootPolicyPublicationErrorV1 {
    fn from(error: aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1) -> Self {
        Self::Data(error.into())
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Retains the original target rows at the prehold plan's native frontier.
    ///
    /// # Errors
    /// Refuses reentry or a compiler entry preceding this original observation.
    /// Native replay,
    /// name and row-hash failures remain parked before the caller's owed posts.
    pub fn capture_original_target_before_once_v1(
        &mut self,
        flight: &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        if self.target_before_entered || self.prehold_entered || self.failure_v1().is_some()
        {
            self.refuse_entry_v1();
            return Err(());
        }
        self.target_before_entered = true;
        self.target_before = Some((|| {
            use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

            let bytes = std::mem::size_of::<Result<RootPolicyTargetBeforeDataV1,
                crate::native::PolicyNativeJournalErrorV1>>()
                .checked_add(std::mem::size_of::<Result<RootPolicyTargetBeforeDataV1,
                    crate::native::authority::RootAuthorityErrorV1>>().checked_mul(3)
                    .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?)
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?
                .checked_add(std::mem::size_of::<Result<RootPolicyTargetBeforeDataV1,
                    RootPolicyPublicationErrorV1>>().checked_mul(2)
                    .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
            self.target.journal.admit_role_observation_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            )?;
            self.target.journal.q04_before_rows_v1().map_err(Into::into)
        })());
        if !matches!(self.target_before, Some(Ok(_))) { return Err(()); }
        // The old Root before-capture follows Target and precedes compilation.
        self.root_before_entered = true;
        self.root_before = Some(flight.q04_before_rows().map_err(Into::into));
        if matches!(self.root_before, Some(Ok(_))) { Ok(()) } else { Err(()) }
    }

    pub(in crate::native) fn held_history_receipt_bytes_v1() -> Option<usize> {
        std::mem::size_of::<RootPolicyHeldHistoryInputV1<'_>>()
            .checked_add(std::mem::size_of::<Result<RootPolicyHeldHistoryInputV1<'_>, ()>>())?
            .checked_mul(3)
    }

    pub(in crate::native) fn held_history_input_v1(
        &self,
    ) -> Result<RootPolicyHeldHistoryInputV1<'_>, ()> {
        if self.cause.get().is_some() || self.postcheck_debt.get().is_some() {
            return Err(());
        }
        let (Some(Ok(held)), Some(Ok(prehold)), Some(Ok(target_before)), Some(claim_length)) = (
            &self.held_compilation, &self.prehold_compilation,
            &self.target_before, self.held_claim_length,
        ) else {
            let _later = self.cause.set(RootPolicyPublicationErrorV1::ChangedCut);
            return Err(());
        };
        if held.binding != prehold.data.binding
            || held.normalized != prehold.data.normalized
            || held.candidate.commitment() != prehold.data.candidate.commitment()
            || held.prerequisites != prehold.data.prerequisites
        {
            let _later = self.cause.set(RootPolicyPublicationErrorV1::ChangedCut);
            return Err(());
        }
        let current_target = match self.target.journal.q04_before_rows_v1() {
            Ok(current) => current,
            Err(error) => {
                let _later = self.cause.set(error.into());
                return Err(());
            }
        };
        if current_target != *target_before {
            let _later = self.cause.set(RootPolicyPublicationErrorV1::ChangedCut);
            return Err(());
        }
        let identity = match self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(plan) => &plan.identity,
            None => { let _later = self.cause.set(RootPolicyPublicationErrorV1::ChangedCut); return Err(()); }
        };
        Ok(RootPolicyHeldHistoryInputV1 {
            identity,
            binding: &held.binding,
            target_before: *target_before,
            claim_length,
        })
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Borrows the same retained first failure without clearing refusal custody.
    ///
    /// Native Target markers resolve only against this Work's actual Target.
    /// Other role errors retain their own original cause and source chain.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let owning = self.cause.get()
            .or_else(|| self.prehold_compilation.as_ref()?.as_ref().err())
            .or_else(|| self.target_before.as_ref()?.as_ref().err())
            .or_else(|| self.root_before.as_ref()?.as_ref().err())
            .or_else(|| self.held_compilation.as_ref()?.as_ref().err())
            .or_else(|| self.prehold_plan.as_ref()?.as_ref().err())
            .or_else(|| self.preparation.as_ref()?.as_ref().err())
            .or_else(|| self.returned.as_ref()?.as_ref().err());
        if let Some(error) = owning { return Some(self.owning_failure_v1(error)); }
        for observation in [&self.readback, &self.decision_readback].into_iter().flatten()
            .chain(self.repeated_readbacks.iter()) {
            if let Err(error) = &observation.outcome {
                if let Some(index) = observation.names_failure {
                    return self.readback_names.get(index).and_then(|original| original.failure())
                        .or(Some(error));
                }
                return Some(self.owning_failure_v1(error));
            }
        }
        self.postcheck_debt.get().map(|error| self.owning_failure_v1(error))
            .or_else(|| self.target_post_failure_v1())
    }

    /// Borrows the actual independently retained Policy postcheck failure.
    ///
    /// This reports secondary debt only; it never repeats the primary cause.
    #[must_use]
    pub fn postcheck_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.postcheck_debt.get().map(|error| self.owning_failure_v1(error))
            .or_else(|| self.target_post_failure_v1())
    }

    /// Borrows the failure from the separately reached Target-name post.
    ///
    /// This site remains distinct when an upper or Authority cause was primary.
    #[must_use]
    pub fn target_post_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.target_post_failure.get().map(|error| match error {
            RootPolicyPublicationErrorV1::Journal(crate::native::PolicyNativeJournalErrorV1::TargetCurrent(_)) =>
                self.target.retained_owed_names_failure_v1().unwrap_or(error),
            _ => self.owning_failure_v1(error),
        })
    }

    fn owning_failure_v1<'error>(&'error self, error: &'error RootPolicyPublicationErrorV1)
        -> &'error (dyn std::error::Error + 'static)
    {
        match error {
            RootPolicyPublicationErrorV1::Journal(crate::native::PolicyNativeJournalErrorV1::TargetCurrent(_)) =>
                self.target.current.failure().unwrap_or(error),
            RootPolicyPublicationErrorV1::Journal(crate::native::PolicyNativeJournalErrorV1::Q04Current(_)) =>
                self.target.journal.q04_readback_failure_v1().unwrap_or(error),
            _ => error,
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1>
    for RootPolicyPublicationErrorV1
{
    fn from(error: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        Self::Data(crate::q04_data::PolicyQ04DataErrorV1::ProtectedHistory(error))
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    // Refused entry cannot hide an earlier typed error in a resident result.
    fn refuse_entry_v1(&self) {
        if self.failure_v1().is_none() {
            let _later = self.cause.set(RootPolicyPublicationErrorV1::ChangedCut);
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>
    for RootPolicyPublicationErrorV1
{
    fn from(error: aos_sandbox_protocol::domain_ledger::JournalTransactionDataError) -> Self {
        Self::Data(crate::q04_data::PolicyQ04DataErrorV1::Transaction(error))
    }
}

impl From<aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1>
    for RootPolicyPublicationErrorV1
{
    fn from(error: aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1) -> Self {
        Self::Journal(crate::native::PolicyNativeJournalErrorV1::Mechanical(error))
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Rechecks the same original owners and retains every typed refusal here.
    ///
    /// This positive bookend uses the single Input prefix, Authority, Target and
    /// final-clock engine. Independent refusal posts use their separate entry.
    ///
    /// # Errors
    /// Retains constructor, original-owner, target-name and clock failures before
    /// returning a unit marker. An earlier Work failure prevents positive entry.
    ///
    /// # Panics
    /// Resumes an actual owner panic after the Input engine finishes owed posts.
    pub fn recheck_original_owners_v1(
        &self,
        flight: &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
    ) -> Result<aos_sandbox_model::RawPairedClockSample, ()> {
        use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
        use std::mem::size_of;

        if self.failure_v1().is_some() {
            return Err(());
        }
        let controls = size_of::<Result<RawPairedClockSample, ()>>()
            .checked_add(size_of::<Result<RawPairedClockSample, RootPolicyPublicationErrorV1>>())
            .and_then(|bytes| bytes.checked_add(size_of::<(&Self,
                &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, '_, '_>)>()))
            .and_then(|bytes| bytes.checked_add(size_of::<ResourceVector>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<(), crate::native::PolicyNativeJournalErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Option<usize>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<u64, std::num::TryFromIntError>>()))
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok());
        let admitted = controls.ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)
            .and_then(|bytes| self.target.journal.admit_role_observation_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            ));
        if let Err(error) = admitted {
            let _later = self.cause.set(error.into());
            return Err(());
        }

        let original = self.source_observation_input_loan_v1(flight)?;
        match original.recheck_with_authority_v1(flight) {
            Ok(current) => Ok(current),
            Err(error) => {
                // The shared engine has already parked reached body failures.
                // This retains an earlier prefix or final-clock owning failure
                // when no body failure occupied that same first-cause slot.
                let _later = self.cause.set(error);
                Err(())
            }
        }
    }
}
