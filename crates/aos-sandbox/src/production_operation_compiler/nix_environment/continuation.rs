//! Owns current grant and assignment custody for one retained pending Start.
//!
//! The fixed Controller writer supplies the original accepted operation,
//! authorization, request, idempotency, Effect and Desired bytes. Those originals
//! select the inputs to the existing protected capability evaluator and genuine
//! assignment owner. Historical carrier data alone cannot construct this owner.
//! The selected paid intake captures partial or assembled custody externally
//! and archives it once after independent posts and original D clock LAST.
//! Its input-only handoff short-borrows Current beside the external Source
//! inventory; that borrow ends before the same intake's consuming closure.
//! That prerequisite neither issues an operation reservation nor runs Storage57.
//! No TLS evidence, broker session, physical floor or Resolve permission is
//! created here. Future effect boundaries must join their own concrete owners.

use aos_sandbox_core::RawPairedClockSample;
use buffa::Message as _;
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, BrokerMethod, NixBuildRequestV2, NixBuildResponseV2, RequestHeader,
};

use super::*;
use crate::cli_model::authorization_adapter::{
    CliAuthorizationAdapterError, CurrentCapabilityDecisionV1,
    evaluate_current_protected_capability,
    evaluate_current_protected_capability_retained, RetainedAuthorizationTimeFloorV1,
};
use crate::controller::ControllerProtectedClockV1;
use crate::journal::controller::{ControllerJournalError, validate_controller_journal};
use crate::publisher_authority::PublisherAuthorityLimits;
use crate::publisher_policy::PublisherPolicyLimits;
use crate::reconciler::EffectPlan;
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::controller_resource_reservation::{AcquisitionFailureV1, PaidNixStartOriginalsV1};

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

/// Reports failure to retain current custody for an original pending Start.
///
/// Typed underlying startup, journal, ledger, assignment, clock and protected
/// grant failures remain available through the standard error source chain.
#[derive(Debug, thiserror::Error)]
#[error("retained Nix Start current custody failed: {cause}")]
pub struct NixStartContinuationErrorV2 {
    #[source]
    cause: ContinuationFailureV2,
}

#[derive(Debug, thiserror::Error)]
enum ContinuationFailureV2 {
    #[error("original Start admission failed: {0}")]
    Admission(#[from] NixStartAdmissionErrorV2),
    #[error("fixed Controller journal failed: {0}")]
    Journal(#[from] crate::JournalError),
    #[error("retained Start ledger failed: {0}")]
    Ledger(#[from] crate::ReconcilerError),
    #[error("retained Controller node failed: {0}")]
    Controller(#[from] ControllerJournalError),
    #[error("protected paired clock failed: {0}")]
    Clock(#[from] crate::ProtectedOwnershipClockError),
    #[error("current protected grant failed: {0}")]
    Authorization(#[from] CliAuthorizationAdapterError),
    #[error("current assignment custody failed: {0}")]
    Assignment(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    #[error("protected runtime authority failed: {0}")]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    #[error("protected paired-clock ordering failed: {0}")]
    ClockPair(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error("original Start request failed: {0}")]
    Request(#[from] crate::public_mutation_compiler::PublicMutationResolutionErrorV1),
    #[error("canonical Nix request validation failed: {0}")]
    BrokerRequest(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error("canonical Nix authorization plan failed: {0}")]
    BrokerPlan(#[from] aos_sandbox_core::InvalidBrokerAuthorizationPlan),
    #[error("original Nix generation input failed: {0}")]
    Generation(#[from] NixGenerationOriginalErrorV1),
    #[error("original Nix intake payment failed: {0}")]
    Intake(#[from] crate::controller_resource_reservation::ResourceReservationErrorV1),
}

impl From<ContinuationFailureV2> for NixStartContinuationErrorV2 {
    fn from(cause: ContinuationFailureV2) -> Self {
        Self { cause }
    }
}

/// Retains genuine current custody for one exact accepted pending Start Effect.
///
/// The owner exclusively borrows the original fixed Controller journal and
/// retains the same protected clock and non-renewable assignment target. It is
/// neither cloneable nor serializable. Any failed recheck permanently closes
/// this instance; rechecking cannot renew its assignment deadline or replace
/// the original capability, policy, recipe, assignment or signed lease.
///
/// This owner does not grant broker endpoint, floor, build or publication access.
/// Its public projections are data, not transferable authorization evidence.
pub struct CurrentRetainedNixStartV2<'current> {
    // Denial-only Drop closes selected observations before owning originals.
    // The ordinary None route leaves the existing field Drop order unchanged.
    intake: Option<crate::NixOriginalStartIntakeLoanV1<'current>>,
    selector: &'current ControllerNixStartRecipeSelectorV2,
    journal: &'current mut Journal,
    expected_plan: &'current EffectPlan,
    carrier: NixStartAdmissionCarrierV2,
    recipe: &'current VerifiedNixRecipeArtifactV2,
    target: CurrentAssignmentTarget,
    clock: ControllerProtectedClockV1,
    decision: CurrentCapabilityDecisionV1,
    acquisition_clock: Option<RawPairedClockSample>,
    failed: bool,
    input_entered: bool,
    successor: Option<OriginalNixSuccessorV2>,
}

impl PaidNixStartOriginalsV1 {
    fn failure(&self, site: AcquisitionFailureV1) -> Option<&NixStartContinuationErrorV2> {
        match site {
            AcquisitionFailureV1::Intake => self.intake.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::FixedWriter => self.fixed_writer.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Carrier => self.carrier.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::CurrentEffect => self.current_effect.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::BoundWriter => self.bound_writer.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Recipe => self.recipe.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Binding => self.binding.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Assignment => self.assignment.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Clock => self.clock.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Decision => self.decision.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Target => self.target.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::TargetBinding => self.target_binding.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::Promotion => self.promotion.as_ref()?.as_ref().err(),
            AcquisitionFailureV1::InitialRecheck => self.initial_recheck.as_ref()?.as_ref().err(),
        }
    }

    fn take_failure(&mut self, site: AcquisitionFailureV1) -> Option<NixStartContinuationErrorV2> {
        match site {
            AcquisitionFailureV1::Intake => self.intake.take()?.err(),
            AcquisitionFailureV1::FixedWriter => self.fixed_writer.take()?.err(),
            AcquisitionFailureV1::Carrier => self.carrier.take()?.err(),
            AcquisitionFailureV1::CurrentEffect => self.current_effect.take()?.err(),
            AcquisitionFailureV1::BoundWriter => self.bound_writer.take()?.err(),
            AcquisitionFailureV1::Recipe => self.recipe.take()?.err(),
            AcquisitionFailureV1::Binding => self.binding.take()?.err(),
            AcquisitionFailureV1::Assignment => self.assignment.take()?.err(),
            AcquisitionFailureV1::Clock => self.clock.take()?.err(),
            AcquisitionFailureV1::Decision => self.decision.take()?.err(),
            AcquisitionFailureV1::Target => self.target.take()?.err(),
            AcquisitionFailureV1::TargetBinding => self.target_binding.take()?.err(),
            AcquisitionFailureV1::Promotion => self.promotion.take()?.err(),
            AcquisitionFailureV1::InitialRecheck => self.initial_recheck.take()?.err(),
        }
    }

    pub(crate) fn first_failure(&self) -> Option<&NixStartContinuationErrorV2> {
        self.failure(self.first?)
    }

    pub(crate) fn final_clock_failure(&self) -> Option<&NixStartContinuationErrorV2> {
        self.final_sample.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.final_clock.as_ref().and_then(|result| result.as_ref().err()))
    }
}

/// Keeps a complete selected acquisition outside its borrowed intake and writer.
///
/// Partial acquisition and assembled initial-recheck failure both keep their
/// actual originals. Only one successful linear promotion constructs Current;
/// neither the diagnostic nor this owner grants a paid operation or effect.
#[doc(hidden)]
#[must_use]
pub struct PaidNixStartAcquisitionV1<'current> {
    // Partial acquisition also closes its loan before disposing any originals.
    intake: Option<crate::NixOriginalStartIntakeLoanV1<'current>>,
    current: Option<CurrentRetainedNixStartV2<'current>>,
    originals: PaidNixStartOriginalsV1,
    journal: Option<&'current mut Journal>,
}

impl<'current> PaidNixStartAcquisitionV1<'current> {
    /// Borrows the actual first failed acquisition or initial recheck Result.
    #[must_use]
    pub fn failure(&self) -> Option<&NixStartContinuationErrorV2> {
        self.originals.first_failure()
    }

    /// Borrows Current only after the full original acquisition and recheck.
    #[must_use]
    pub fn current_mut(&mut self) -> Option<&mut CurrentRetainedNixStartV2<'current>> {
        if self.originals.first.is_some() { None } else { self.current.as_mut() }
    }

    /// Short-borrows the same assembled Current for paid input capture.
    ///
    /// The external destination may borrow Source, never this acquisition.
    /// `None` preserves a failed partial acquisition without adding input I/O;
    /// the caller still consumes that original outcome into its paid intake.
    ///
    /// # Errors
    /// A reached `Some(Err(()))` reports closed entry or a cause retained in
    /// the destination. The marker cannot replace the actual input owner.
    pub fn capture_current_nix_preflight_once<'source>(
        &mut self,
        source: &'source mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        destination: &mut crate::policy_compiler::CurrentNixPreflightAttemptV1<'source>,
    ) -> Option<Result<(), ()>> {
        self.current_mut().map(|current| {
            current.capture_current_nix_preflight_once(source, destination)
        })
    }

    /// Consumes the acquisition into its original intake's negative archive.
    ///
    /// Independent original posts run before the original Start clock LAST,
    /// even after acquisition or recheck failure. Reached owning payloads move
    /// once into the intake; no borrowed Current or writer escapes settlement.
    /// This closes only intake and never completes the generation Effect.
    ///
    /// # Errors
    /// Reports retained acquisition, post or original-clock failure, or a
    /// missing original intake. Every actual reached original remains owned
    /// by the same intake on the selected path before this projection returns.
    pub fn close_into_intake(
        self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        self.close_originals_into_intake(source, None)
    }

    /// Archives captured input originals before closing the same paid intake.
    ///
    /// The consumed payload holds no Source or Current borrow. Independent
    /// Controller/Source/profile posts and the original D clock still run in
    /// the existing closure, including after input capture failure.
    ///
    /// # Errors
    /// Reports the retained acquisition, input, post or original-clock cause.
    /// This never completes generation or lends operation/Storage authority.
    pub fn close_with_input_into_intake(
        self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        input: crate::policy_compiler::CurrentNixPreflightOriginalsV1,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        self.close_originals_into_intake(source, Some(input))
    }

    fn close_originals_into_intake(
        self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        input: Option<crate::policy_compiler::CurrentNixPreflightOriginalsV1>,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        let Self { current, mut originals, journal, intake } = self;
        let (journal, intake) = match current {
            Some(current) => {
                let CurrentRetainedNixStartV2 {
                    journal, carrier, target, clock, decision, acquisition_clock,
                    intake, selector: _, expected_plan: _, recipe: _, failed: _, input_entered: _, successor: _,
                } = current;
                originals.carrier = Some(Ok(carrier));
                originals.target = Some(Ok(target));
                originals.clock = Some(Ok(clock));
                originals.decision = Some(Ok(decision));
                originals.acquisition_clock = acquisition_clock;
                (Some(journal), intake)
            }
            None => (journal, intake),
        };
        let (Some(journal), Some(intake)) = (journal, intake) else {
            // The ordinary-only internal constructor immediately consumes its
            // outcome; no public factory can manufacture a paid missing loan.
            return Err(crate::ResourceReservationErrorV1::Conflict);
        };
        let mut closing = intake.begin_closing(journal, source, input);
        match (originals.clock.as_mut(), originals.decision.as_ref(), originals.target.as_ref()) {
            (Some(Ok(clock)), Some(Ok(decision)), Some(Ok(target))) => {
                originals.final_sample = Some(clock.sample()
                    .map_err(ContinuationFailureV2::from).map_err(Into::into));
                originals.final_clock = match originals.final_sample.as_ref() {
                    Some(Ok(later)) => Some(require_original_clock_sample(decision, target, *later)),
                    _ => None,
                };
            }
            _ => closing.park_unavailable_start_clock(),
        }
        closing.finish(originals)
    }

    fn into_ordinary(mut self) -> Result<CurrentRetainedNixStartV2<'current>, NixStartContinuationErrorV2> {
        if let Some(site) = self.originals.first {
            return Err(self.originals.take_failure(site)
                .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?);
        }
        self.current.take()
            .ok_or_else(|| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into())
    }
}

// These are comparison DATA derived from the same actual Resolve response.
// Later drafts compare them; they cannot replace the original predecessor.
struct OriginalNixSuccessorV2 {
    resolve_observation: [u8; 32],
    build_transaction: [u8; 32],
}

/// Retains one fresh unsigned online Nix plan beside its original signed lease.
///
/// This historical draft still requires the installed Controller signer,
/// authenticated Session, receiver admission and atomic physical-floor commit.
/// It is not a currentness token or an executable store permit.
pub struct NixResolveAuthorizationDraftV2 {
    plan: aos_sandbox_core::BrokerAuthorizationPlan,
    lease: SignedOwnershipLease,
    request: Vec<u8>,
    observed: RawPairedClockSample,
}

impl NixResolveAuthorizationDraftV2 {
    /// Borrows the exact newly constructed unsigned plan.
    #[must_use]
    pub fn plan(&self) -> &aos_sandbox_core::BrokerAuthorizationPlan {
        &self.plan
    }

    /// Borrows the original independently signed current assignment lease.
    #[must_use]
    pub fn lease(&self) -> &SignedOwnershipLease {
        &self.lease
    }

    /// Borrows the exact canonical method body matched by the grant.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }

    /// Returns the actual protected observation used to issue this draft.
    #[must_use]
    pub const fn observed(&self) -> RawPairedClockSample {
        self.observed
    }
}

impl std::fmt::Debug for CurrentRetainedNixStartV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentRetainedNixStartV2(<borrowed current custody>)")
    }
}

impl ControllerNixStartRecipeSelectorV2 {
    /// Borrows genuine current custody for one exact retained pending Start.
    ///
    /// All authority inputs come from the original accepted ledger. The caller
    /// supplies only the operation/step and expected full Effect to compare;
    /// it cannot select a holder, capability, policy, clock, recipe or path.
    /// Existing protected time-floor advancement runs only after the complete
    /// original admission and fixed writer custody have been checked.
    ///
    /// # Errors
    /// Rejects changed startup or credentials; a wrong, poisoned or replaced
    /// fixed writer; missing/inconsistent admission, idempotency, Effect or
    /// Desired; a nonpending operation; denied or changed current grant; and
    /// changed, expired or unauthentic original assignment/lease custody.
    pub fn borrow_current_retained_start_v2<'current>(
        &'current self,
        journal: &'current mut Journal,
        operation: OperationId,
        step: u32,
        expected_plan: &'current EffectPlan,
    ) -> Result<CurrentRetainedNixStartV2<'current>, NixStartContinuationErrorV2> {
        self.capture_current_retained_start(journal, operation, step, expected_plan, None)
            .into_ordinary()
    }

    /// Consumes the separate original-paid intake into the same Start engine.
    ///
    /// This keeps the actual intake and its retained authorization-floor
    /// crossings borrowed for the whole current owner. It grants no Storage
    /// or compiled-policy operation permission and never renews original D.
    ///
    /// Every failed step stays in the returned external outcome before its
    /// diagnostic is borrowed. This is not a bare Err that drops prior inputs.
    pub fn borrow_paid_current_retained_start_v2<'current>(
        &'current self,
        journal: &'current mut Journal,
        intake: crate::NixOriginalStartIntakeLoanV1<'current>,
    ) -> PaidNixStartAcquisitionV1<'current> {
        let operation = intake.operation;
        let step = intake.step;
        let plan = intake.plan;
        self.capture_current_retained_start(journal, operation, step, plan, Some(intake))
    }

    fn capture_current_retained_start<'current>(
        &'current self,
        journal: &'current mut Journal,
        operation: OperationId,
        step: u32,
        expected_plan: &'current EffectPlan,
        mut intake: Option<crate::NixOriginalStartIntakeLoanV1<'current>>,
    ) -> PaidNixStartAcquisitionV1<'current> {
        let mut originals = PaidNixStartOriginalsV1::default();
        let mut selected_recipe = None;
        macro_rules! park {
            ($field:ident, $site:ident, $value:expr) => {{
                originals.$field = Some($value);
                match originals.$field.as_mut() {
                    Some(Ok(value)) => value,
                    _ => return Err(AcquisitionFailureV1::$site),
                }
            }};
        }
        let acquisition = (|| -> Result<(), AcquisitionFailureV1> {
            if let Some(intake) = intake.as_ref() {
                park!(intake, Intake, intake.require_open()
                    .map_err(ContinuationFailureV2::from).map_err(Into::into));
            }
            park!(fixed_writer, FixedWriter, self.require_fixed_writer(journal)
                .map_err(ContinuationFailureV2::from).map_err(Into::into));
            let carrier = park!(carrier, Carrier,
                crate::reconciler::accepted_nix_start_admission_v2(journal, operation)
                    .map_err(ContinuationFailureV2::from)
                    .and_then(|carrier| carrier.ok_or(NixStartAdmissionErrorV2::Invalid)
                        .map_err(ContinuationFailureV2::from)).map_err(Into::into));
            park!(current_effect, CurrentEffect,
                crate::reconciler::require_current_effect_v2(carrier, journal, operation, step, expected_plan)
                    .map_err(ContinuationFailureV2::from).map_err(Into::into));
            park!(bound_writer, BoundWriter, self.require_bound_writer(journal));
            originals.recipe = Some(self.original_recipe(carrier)
                .map(|recipe| selected_recipe = Some(recipe))
                .map_err(ContinuationFailureV2::from).map_err(Into::into));
            if !matches!(originals.recipe, Some(Ok(()))) {
                return Err(AcquisitionFailureV1::Recipe);
            }
            let Some(recipe) = selected_recipe else { return Err(AcquisitionFailureV1::Recipe) };
            let binding = park!(binding, Binding, current_binding(journal, recipe.recipe().sandbox)
                .map_err(Into::into));
            park!(assignment, Assignment,
                self.require_original_assignment(journal, carrier, recipe, binding)
                    .map_err(ContinuationFailureV2::from).map_err(Into::into));
            let clock = park!(clock, Clock, ControllerProtectedClockV1::open_fixed()
                .map_err(ContinuationFailureV2::from).map_err(Into::into));
            let decision = match intake.as_mut() {
                Some(intake) => intake.authorization_crossing()
                    .map_err(ContinuationFailureV2::from).map_err(Into::into)
                    .and_then(|crossing| evaluate_original_grant_inner(journal, carrier, clock, Some(crossing))),
                None => evaluate_original_grant(journal, carrier, clock),
            };
            park!(decision, Decision, decision);
            let target = park!(target, Target, (|| {
                let policy = self.assignment_policy().map_err(ContinuationFailureV2::from)?;
                crate::runtime_scope::acquire_current_assignment(
                    journal,
                    RuntimeScopeHolder { sandbox: recipe.recipe().sandbox, holder: carrier.authority().holder() },
                    policy, &mut || {
                        let result = clock.sample();
                        if let Ok(sample) = &result { originals.acquisition_clock.get_or_insert(*sample); }
                        result
                    },
                ).map_err(ContinuationFailureV2::from).map_err(Into::into)
            })());
            park!(target_binding, TargetBinding, if target.binding() == &*binding { Ok(()) }
                else { Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into()) });
            Ok(())
        })();
        if let Err(site) = acquisition {
            originals.first = Some(site);
            return PaidNixStartAcquisitionV1 {
                current: None, originals, journal: Some(journal), intake,
            };
        }

        // One exhaustive linear promotion. Even an impossible incomplete
        // success shape returns its reached originals as a refusing outcome.
        let PaidNixStartOriginalsV1 {
            first,
            carrier, clock, decision, target, acquisition_clock,
            binding, fixed_writer, current_effect, bound_writer, recipe,
            assignment, target_binding, intake: intake_check,
            promotion, initial_recheck, final_sample, final_clock,
        } = originals;
        let mut originals = PaidNixStartOriginalsV1 {
            first,
            binding, fixed_writer, current_effect, bound_writer, recipe,
            assignment, target_binding, intake: intake_check,
            promotion, initial_recheck, final_sample, final_clock, ..Default::default()
        };
        let (carrier, clock, decision, target, recipe) = match
            (carrier, clock, decision, target, selected_recipe)
        {
            (Some(Ok(carrier)), Some(Ok(clock)), Some(Ok(decision)), Some(Ok(target)), Some(recipe)) =>
                (carrier, clock, decision, target, recipe),
            (carrier, clock, decision, target, _) => {
                originals.carrier = carrier;
                originals.clock = clock;
                originals.decision = decision;
                originals.target = target;
                originals.acquisition_clock = acquisition_clock;
                originals.promotion = Some(Err(ContinuationFailureV2::Admission(
                    NixStartAdmissionErrorV2::Invalid).into()));
                originals.first = Some(AcquisitionFailureV1::Promotion);
                return PaidNixStartAcquisitionV1 {
                    current: None, originals, journal: Some(journal), intake,
                };
            }
        };
        let owner = CurrentRetainedNixStartV2 {
            selector: self, journal, expected_plan, carrier, recipe, target, clock, decision,
            acquisition_clock,
            failed: false, input_entered: false, successor: None, intake,
        };
        let mut outcome = PaidNixStartAcquisitionV1 {
            current: Some(owner), originals, journal: None, intake: None,
        };
        // Park the assembled owner before the fallible initial recheck.
        outcome.originals.initial_recheck = Some(match outcome.current.as_mut() {
            Some(owner) => owner.recheck(),
            None => Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into()),
        });
        if matches!(outcome.originals.initial_recheck, Some(Err(_))) {
            outcome.originals.first = Some(AcquisitionFailureV1::InitialRecheck);
        }
        outcome
    }

    pub(crate) fn original_start_intake_demand(
        controller: &crate::journal::JournalShape,
        source: &crate::journal::JournalShape,
        provision: aos_sandbox_core::ResourceVector,
        intake_owner_bytes: usize,
    ) -> Result<aos_sandbox_core::ResourceVector, crate::ResourceReservationErrorV1> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let refused = || crate::ResourceReservationErrorV1::Conflict;
        // The existing two-member bank framer bounds each smaller time-floor
        // TX (revision128/head48 and fixed keys), as well as I's own TX. It
        // does not substitute a transaction ceiling for measured framing.
        let one_append = aos_sandbox_protocol::domain_ledger::resource_bank::first_global_prefix_append_bytes()
            .map_err(crate::JournalError::from)?;
        let append = one_append.checked_mul(7).ok_or_else(refused)?;
        if one_append > u64::try_from(controller.maximum_transaction_bytes).map_err(|_| refused())?
            || controller.maximum_record_bytes < 945
        {
            return Err(refused());
        }
        let map_cells = controller.cells.checked_add(source.cells)
            .and_then(|cells| cells.checked_mul(8)).ok_or_else(refused)?;
        // Bound retained writer state, publisher registry/policy material,
        // assignment comparisons and decoder-facing copies together. Include
        // map/container words separately from the known Vec capacities.
        let map_cell_bytes = std::mem::size_of::<(
            crate::RecordNamespace, Vec<u8>, Vec<u8>, [usize; 4],
        )>();
        let caller_slots = std::mem::size_of::<Option<Result<(), crate::ResourceReservationErrorV1>>>()
            .checked_mul(3).and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<
                std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
            >>())).ok_or_else(refused)?;
        let bytes = controller.retained_bytes.checked_add(source.retained_bytes)
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(map_cells.checked_mul(map_cell_bytes)?))
            .and_then(|bytes| bytes.checked_add(intake_owner_bytes))
            .and_then(|bytes| bytes.checked_add(caller_slots))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CurrentRetainedNixStartV2<'_>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PaidNixStartAcquisitionV1<'_>>()))
            // Native bytes are charged once below. Their proposal/expected,
            // unsigned and framing-facing buffers coexist in retained slots.
            .and_then(|bytes| bytes.checked_add(usize::try_from(append).ok()?.checked_mul(4)?))
            // Canonical carrier decoding and its roundtrip coexist. Charge
            // element/container overhead, not only the maximum encoded bytes.
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::public_api::mutation_history::NIX_START_ADMISSION_MAXIMUM_BYTES_V2.checked_mul(
                4 + 2 * std::mem::size_of::<(Vec<u8>, Vec<u8>, usize)>(),
            )?))
            .ok_or_else(refused)?;
        let cells = map_cells.checked_add(aos_sandbox_protocol::public_api::mutation_history::NIX_START_ADMISSION_MAXIMUM_BYTES_V2)
            .ok_or_else(refused)?;
        let native = controller.native_bytes.checked_add(source.native_bytes)
            .and_then(|bytes| bytes.checked_add(append)).ok_or_else(refused)?;
        let bytes = u64::try_from(bytes).map_err(|_| refused())?;
        Ok(ResourceVector::ZERO
            .with(D::CpuMicrosPerPeriod, provision.get(D::CpuMicrosPerPeriod))
            .with(D::MemoryBytes, bytes.checked_add(native).ok_or_else(refused)?)
            .with(D::Pids, 1)
            .with(D::OpenFiles, 3 + 3 + 2)
            .with(D::StorageBytes, native)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| refused())?)
            .with(D::PublicationStagingBytes, bytes)
            .with(D::LogBytes, bytes)
            .with(D::OutputBytes, bytes)
            .with(D::ConcurrentOperations, 1))
    }

    fn require_fixed_writer(&self, journal: &Journal) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;
        journal.validate_held_owned_at_for_uid(
            CONTROLLER_DIRECTORY, CONTROLLER_JOURNAL, self.pins.identities[0],
        )?;
        self.recheck()?;
        Ok(())
    }

    fn require_bound_writer(&self, journal: &mut Journal) -> Result<(), NixStartContinuationErrorV2> {
        self.require_fixed_writer(journal).map_err(ContinuationFailureV2::from)?;
        validate_controller_journal(journal, *self.pins.node.as_bytes())
            .map_err(ContinuationFailureV2::from)?;
        self.require_fixed_writer(journal).map_err(ContinuationFailureV2::from)?;
        Ok(())
    }

    fn original_recipe<'selector>(
        &'selector self,
        carrier: &NixStartAdmissionCarrierV2,
    ) -> Result<&'selector VerifiedNixRecipeArtifactV2, NixStartAdmissionErrorV2> {
        carrier.validate()?;
        if carrier.credential_commitments() != &self.commitments()? {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let artifact = self.recipes.iter().find(|artifact| {
            carrier.matches_recipe(artifact)
        }).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        self.require_recipe_pins(artifact)?;
        Ok(artifact)
    }

    fn require_original_assignment(
        &self,
        journal: &mut Journal,
        carrier: &NixStartAdmissionCarrierV2,
        recipe: &VerifiedNixRecipeArtifactV2,
        binding: &RuntimeAuthorityBindingV1,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        require_recipe_assignment(recipe, binding, carrier.authority())?;
        let manifest = binding.manifest().manifest();
        let claims = carrier.authority().capability().claims();
        if binding.holder() != Some(carrier.authority().holder())
            || manifest.node() != self.pins.node
            || manifest.desired_generation().get() != carrier.original_generation().checked_add(1)
                .ok_or(NixStartAdmissionErrorV2::Invalid)?
            || manifest.incarnation().as_bytes() != carrier.original_incarnation()
            || claims.sandbox.is_some_and(|sandbox| sandbox != manifest.sandbox())
            || claims.incarnation.is_some_and(|incarnation| incarnation != manifest.incarnation())
            || claims.assignment_epoch.is_some_and(|epoch| epoch != manifest.epoch())
            || !checked_assignment_readback(journal, binding)?.matches_original(carrier.assignment())
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        require_desired_assignment(carrier, binding)
    }
}

impl CurrentRetainedNixStartV2<'_> {
    /// Captures the same paid current-Start and protected Source input once.
    ///
    /// The external destination retains the Source inventory, not this Current
    /// borrow. Entered capture retains both actual Current rechecks, including
    /// input refusal; a closed-I admission parks its original error without
    /// any added Current or Source observation.
    /// The genuine acquisition clock is optional only to preserve a refusing
    /// missing-original outcome; no replacement sample or deadline is created.
    /// This entry performs no Root flight, Source16, compiler or Storage work.
    ///
    /// # Errors
    /// Returns a diagnostic marker for closed entry or a cause retained in
    /// the destination. Reentry and absent intake close Current without I/O;
    /// reached input failures retain both independent Current bookends.
    pub(crate) fn capture_current_nix_preflight_once<'source>(
        &mut self,
        source: &'source mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        destination: &mut crate::policy_compiler::CurrentNixPreflightAttemptV1<'source>,
    ) -> Result<(), ()> {
        // Latch before any fallible gate, evaluator or Source observation.
        // A different empty destination cannot rearm this paid interval.
        if self.input_entered {
            self.failed = true;
            return Err(());
        }
        self.input_entered = true;
        let Some(intake) = self.intake.as_ref() else {
            // Only the private paid-acquisition handoff reaches this entry.
            // Do not turn an ordinary Current into a funded negative read.
            self.failed = true;
            return Err(());
        };
        if let Err(error) = intake.require_open() {
            self.failed = true;
            return destination.park_paid_entry_refusal(error);
        }
        let source_join = intake.require_original_source(source);
        if destination.park_paid_source_result(source_join).is_err() {
            self.failed = true;
            return Err(());
        }
        let before = self.recheck();
        let captured = destination.capture_current_originals_once(
            self.journal, source, &self.carrier, self.target.binding(),
            self.acquisition_clock, self.target.deadline_boottime_nanoseconds(), before,
        );

        // Keep the post independent of input/Source failure. The same existing
        // evaluator retains its native floor crossing inside the paid intake.
        let after = self.recheck();
        let posted = destination.park_current_post(after);
        if captured.is_err() || posted.is_err() {
            self.failed = true;
            Err(())
        } else {
            Ok(())
        }
    }

    /// Forms the existing-output Realize51 body beside the original Resolve.
    ///
    /// The predecessor is comparison DATA. The installed caller must continue
    /// holding its actual Session and confirmed native terminal; this method
    /// supplies neither of those owners. The transaction excludes all future
    /// request, outcome, root and journal-head fields.
    ///
    /// # Errors
    /// Rejects a closed or changed Start, a substituted predecessor/response,
    /// an invalid identity, an expired original cutoff or canonical encoding.
    pub fn prepare_realize_request_v2(
        &mut self,
        request_id: [u8; 16],
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        if predecessor.method() != BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 {
            self.failed = true;
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.prepare_successor_request(request_id, predecessor, response)
    }

    /// Forms Query52 against the exact original Realize51 observation.
    ///
    /// It does not replace the original realization or renew its deadline.
    /// Physical roots and the native terminal remain the caller's obligations.
    ///
    /// # Errors
    /// Rejects a closed or changed Start, a substituted predecessor/response,
    /// an invalid identity, an expired original cutoff or canonical encoding.
    pub fn prepare_query_request_v2(
        &mut self,
        request_id: [u8; 16],
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        if predecessor.method() != BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 {
            self.failed = true;
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.prepare_successor_request(request_id, predecessor, response)
    }

    fn prepare_successor_request(
        &mut self,
        request_id: [u8; 16],
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        if self.failed || request_id == [0; 16] || request_id == [0xff; 16] {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.failed = true;
        self.recheck_inner()?;
        let body = self.original_successor_request(request_id, predecessor, response)?;
        self.recheck_inner()?;
        self.failed = false;
        Ok(body)
    }

    fn original_successor_request(
        &mut self,
        request_id: [u8; 16],
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        let prior = predecessor.wire();
        let prior_id = predecessor.header().request_id();
        let mut expected = self.original_resolve_request_v2(*prior_id)?;
        expected.build_transaction_digest = prior.build_transaction_digest.clone();
        expected.original_realization_digest = prior.original_realization_digest.clone();
        let resolve = predecessor.method() == BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2;
        if prior != &expected
            || if resolve { response.recipe_admission != self.recipe.canonical_bytes() }
                else { !response.recipe_admission.is_empty() }
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let (observation, build_transaction, original_observation) =
            Self::existing_output_successor_coordinates_v2(predecessor, response)
                .map_err(ContinuationFailureV2::from)?;
        if observation.inputs != self.recipe.recipe().inputs
            || !resolve && observation.outputs != self.recipe.recipe().outputs
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }

        let mut body = self.original_resolve_request_v2(request_id)?;
        match predecessor.method() {
            BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 => {
                let resolve_observation = original_observation;
                if let Some(original) = self.successor.as_ref() {
                    if original.build_transaction != build_transaction
                        || original.resolve_observation != resolve_observation
                    {
                        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
                    }
                } else {
                    self.successor = Some(OriginalNixSuccessorV2 {
                        resolve_observation, build_transaction,
                    });
                }
                body.build_transaction_digest = build_transaction.to_vec();
            }
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 => {
                let original = self.successor.as_ref().ok_or(
                    ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid),
                )?;
                if prior.build_transaction_digest.as_slice() != original.build_transaction {
                    return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
                }
                body.build_transaction_digest = original.build_transaction.to_vec();
                body.original_realization_digest = original_observation.to_vec();
            }
            _ => return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into()),
        }
        Ok(body)
    }

    /// Computes closed successor comparison DATA from the exact prior response.
    ///
    /// Both installed owners use this same canonical decoder and digest recipe.
    /// The caller must separately hold the authentic native terminal, current
    /// Session and physical originals; these returned coordinates grant none.
    ///
    /// # Errors
    /// Rejects an unsupported predecessor or a noncanonical/mismatched response.
    #[doc(hidden)]
    pub fn existing_output_successor_coordinates_v2(
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
    ) -> Result<(
        aos_sandbox_protocol::nix_build::NixBuildObservationV2,
        [u8; 32],
        [u8; 32],
    ), aos_sandbox_protocol::ProtocolValidationError> {
        use aos_sandbox_protocol::ProtocolValidationError;

        aos_sandbox_protocol::nix_build::decode_nix_build_response_v2(
            &response.encode_to_vec(), predecessor, predecessor.method(),
        )?;
        let observation = aos_sandbox_protocol::nix_build::decode_nix_build_observation_v2(
            &response.observation, predecessor,
        )?;
        let transaction = match predecessor.method() {
            BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 => Sha256::new()
                .chain_update(b"aos.sandbox.nix.existing-output-transaction.v2\0")
                .chain_update(&predecessor.wire().operation_id)
                .chain_update(predecessor.commitment())
                .chain_update(Sha256::digest(response.encode_to_vec()))
                .finalize().into(),
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 => predecessor.wire()
                .build_transaction_digest.as_slice().try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("build_transaction_digest"))?,
            _ => return Err(ProtocolValidationError::InvalidField("Nix successor predecessor")),
        };
        Ok((observation, transaction, Sha256::digest(&response.observation).into()))
    }

    /// Computes purpose-separated input and predicted-output comparison data.
    ///
    /// Both fixed online owners use this same canonical typed serialization.
    /// The output digest does not attest that predicted outputs exist, and
    /// neither digest supplies local input, store, Session or floor authority.
    ///
    /// # Errors
    /// Rejects an invalid recipe or failure to encode its canonical maps.
    pub fn recipe_coordinate_digests_v2(
        recipe: &aos_sandbox_protocol::nix_build::NixPreadmittedRecipeV2,
    ) -> Result<([u8; 32], [u8; 32]), NixStartAdmissionErrorV2> {
        recipe.validate()?;
        let inputs = serde_json::to_vec(&recipe.inputs)?;
        let outputs = serde_json::to_vec(&recipe.outputs)?;
        Ok((
            Sha256::new()
                .chain_update(b"aos.sandbox.nix.resolve-input-map.v2\0")
                .chain_update((inputs.len() as u64).to_be_bytes())
                .chain_update(&inputs)
                .finalize()
                .into(),
            Sha256::new()
                .chain_update(b"aos.sandbox.nix.resolve-predicted-output-map.v2\0")
                .chain_update((outputs.len() as u64).to_be_bytes())
                .chain_update(&outputs)
                .finalize()
                .into(),
        ))
    }

    /// Forms the fixed Resolve50 body from this same genuine pending Start.
    ///
    /// Only the request identity is caller-selected comparison data. The
    /// assignment fence, admitted recipe, parent carrier and exclusive cutoff
    /// come from the retained originals, never a supplied lease or deadline.
    /// The body still delegates current-held evidence through the authenticated
    /// Controller role; its scalar coordinates are not a remote live lease.
    ///
    /// # Errors
    /// Rejects a closed owner, a sentinel request identity, any changed original
    /// custody or expired cutoff, and bounded carrier/map encoding failure.
    /// A returned error or caught unwind permanently closes this owner.
    pub fn prepare_resolve_request_v2(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        if self.failed || request_id == [0; 16] || request_id == [0xff; 16] {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }

        // Pre-arm before the first check. Only this complete observation may
        // reopen the same owner; abandonment cannot produce a reusable target.
        self.failed = true;
        self.recheck_inner()?;
        let body = self.original_resolve_request_v2(request_id)?;
        self.recheck_inner()?;
        self.failed = false;
        Ok(body)
    }

    fn original_resolve_request_v2(
        &self,
        request_id: [u8; 16],
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        let (inputs, outputs) = Self::recipe_coordinate_digests_v2(self.recipe.recipe())
            .map_err(ContinuationFailureV2::from)?;
        let parent = self.carrier.encode().map_err(NixStartAdmissionErrorV2::from).map_err(ContinuationFailureV2::from)?;
        let parent_digest: [u8; 32] = parent.get(parent.len().saturating_sub(32)..)
            .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?
            .try_into()
            .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?;
        let binding = self.target.binding();
        let manifest = binding.manifest().manifest();
        let recipe = self.recipe.recipe();
        let body = NixBuildRequestV2 {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: self.target.deadline_boottime_nanoseconds(),
                maximum_response_bytes: aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 as u32,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: manifest.sandbox().as_bytes().to_vec(),
                incarnation_id: manifest.incarnation().as_bytes().to_vec(),
                assignment_epoch: manifest.epoch().get(),
                desired_generation: manifest.desired_generation().get(),
                assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
                ..Default::default()
            }).into(),
            operation_id: self.carrier.operation().as_bytes().to_vec(),
            recipe_digest: self.recipe.digest().as_bytes().to_vec(),
            domain_digest: recipe.domain_commitment.as_bytes().to_vec(),
            disclosure_digest: recipe.disclosure.as_bytes().to_vec(),
            environment_digest: recipe.environment.digest().as_bytes().to_vec(),
            parent_admission_digest: parent_digest.to_vec(),
            input_presentation_digest: inputs.to_vec(),
            expected_output_map_digest: outputs.to_vec(),
            ..Default::default()
        };
        Ok(body)
    }

    /// Stages a fresh canonical Resolve50 plan before the final original check.
    ///
    /// The body must equal the request constructed from this same Start. The
    /// genuine current lease and protected clock select the assignment, signer
    /// generation and exclusive expiry; the caller cannot nominate any of them.
    /// Only the original request identity is comparison DATA. The unsigned
    /// draft remains resident when the final check fails or unwinds.
    ///
    /// # Errors
    /// Preserves actual original-custody, request, plan and clock causes. Rejects
    /// a closed owner, occupied output, substituted request or expired bound.
    /// Failure or interruption permanently fences this owner.
    pub fn retain_resolve_authorization_into(
        &mut self,
        request: &NixBuildRequestV2,
        target: &mut Option<NixResolveAuthorizationDraftV2>,
    ) -> Result<(), NixStartContinuationErrorV2> {
        self.retain_authorization_into(
            request, BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2, None, target,
        )
    }

    /// Retains an independently granted successor draft under the same Start.
    ///
    /// The actual predecessor request and response stay borrowed from the
    /// caller's resident completed phase. They are not a native commit proof.
    ///
    /// # Errors
    /// Rejects substituted phase/body data, occupied custody, changed originals
    /// and expired original authorization. A failure permanently fences use.
    pub fn retain_successor_authorization_into(
        &mut self,
        request: &NixBuildRequestV2,
        predecessor: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        response: &NixBuildResponseV2,
        target: &mut Option<NixResolveAuthorizationDraftV2>,
    ) -> Result<(), NixStartContinuationErrorV2> {
        let method = match predecessor.method() {
            BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 =>
                BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2,
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 =>
                BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2,
            _ => return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into()),
        };
        self.retain_authorization_into(request, method, Some((predecessor, response)), target)
    }

    fn retain_authorization_into(
        &mut self,
        request: &NixBuildRequestV2,
        method: BrokerMethod,
        predecessor: Option<(&aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2, &NixBuildResponseV2)>,
        target: &mut Option<NixResolveAuthorizationDraftV2>,
    ) -> Result<(), NixStartContinuationErrorV2> {
        if self.failed {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.failed = true;
        if target.is_some() {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.recheck_inner()?;

        let request_id = request.header.as_option()
            .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?
            .request_id.as_slice().try_into()
            .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?;
        // Preserve the old Resolve short circuit before its body allocation.
        if request_id == [0; 16] || request_id == [0xff; 16] {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let expected = match predecessor {
            None => self.original_resolve_request_v2(request_id)?,
            Some((prior, response)) => self.original_successor_request(request_id, prior, response)?,
        };
        if request != &expected {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let bytes = request.encode_to_vec();
        let (lease, observed) = self.target.verified_plan_lease(
            self.journal,
            &mut || self.clock.sample(),
        ).map_err(ContinuationFailureV2::from)?;
        self.carrier.assignment().require_original_lease(&lease).map_err(NixStartAdmissionErrorV2::from)
            .map_err(ContinuationFailureV2::from)?;

        let identities = self.selector.pins.identities;
        let checked = aos_sandbox_protocol::nix_build::decode_nix_build_request_v2(
            &bytes,
            method,
            aos_sandbox_protocol::PeerCredentials {
                uid: identities[0],
                gid: identities[1],
                pid: None,
            },
            aos_sandbox_protocol::PeerPolicy {
                uid: identities[0],
                gid: Some(identities[1]),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            observed.boottime_nanoseconds(),
        ).map_err(ContinuationFailureV2::from)?;
        let (policy_digest, revocation_scope) = {
            let loan = self.selector.recheck_and_borrow_publics()
                .map_err(ContinuationFailureV2::from)?;
            let credentials = loan.publics()
                .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::CredentialCustodyClosed))?;
            let anchor = plan_anchor_from_publics(&credentials, 6)
                .map_err(ContinuationFailureV2::from)?;
            (ObjectDigest::from_bytes(Sha256::digest(credentials[6].bytes()).into()),
                anchor.revocation_scope())
        };

        let binding = self.target.binding();
        let manifest = binding.manifest().manifest();
        let assignment = aos_sandbox_core::BrokerAssignment::new(
            manifest.sandbox(),
            manifest.incarnation(),
            manifest.epoch(),
            manifest.desired_generation(),
            binding.assignment_digest(),
        ).map_err(ContinuationFailureV2::from)?;
        let target_handle = aos_sandbox_core::BrokerResourceHandle::from_bytes(
            *self.recipe.recipe().domain_commitment.as_bytes(),
        ).map_err(ContinuationFailureV2::from)?;
        let commitment = aos_sandbox_core::BrokerArgumentCommitment::from_digest(
            ObjectDigest::from_bytes(checked.commitment()),
        ).map_err(ContinuationFailureV2::from)?;
        let grant = aos_sandbox_core::BrokerGrant::new(
            match method {
                BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 =>
                    aos_sandbox_core::BrokerVerb::NixResolveProtectedRecipe,
                BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 =>
                    aos_sandbox_core::BrokerVerb::NixRealizeAuthorizedDerivation,
                BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 =>
                    aos_sandbox_core::BrokerVerb::NixQueryAuthorizedPathInfo,
                _ => return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into()),
            },
            aos_sandbox_core::BrokerGrantTarget::Resource(target_handle),
            commitment,
            aos_sandbox_protocol::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2 as u32,
            0,
        ).map_err(ContinuationFailureV2::from)?;
        let features = [
            "aos.sandbox.authorization.signed-plan-lease",
            aos_sandbox_core::NIX_NARROWING_PROXY_FEATURE_NAMESPACE,
        ].into_iter().map(|namespace| {
            aos_sandbox_core::FeatureRef::new(namespace, 1, 0)
                .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))
        }).collect::<Result<Vec<_>, _>>()?;
        let expires = self.target.expires_wall_seconds().min(lease.authority_expires_seconds());
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            aos_sandbox_core::BrokerAudience::Nix,
            aos_sandbox_core::ProtocolId::NixBuildBroker,
            aos_sandbox_core::ProtocolVersion::new(1, 0),
            assignment,
            lease.node(),
            lease.signer().clone(),
            vec![grant],
            policy_digest,
            revocation_scope,
            observed.wall_seconds(),
            expires,
            features,
        ).map_err(ContinuationFailureV2::from)?;
        *target = Some(NixResolveAuthorizationDraftV2 {
            plan,
            lease,
            request: bytes,
            observed,
        });

        self.recheck_inner()?;
        self.failed = false;
        Ok(())
    }

    /// Parks one selected Storage Prepare draft from this same pending Start.
    ///
    /// The Session supplies only its next request identity. All assignment,
    /// original clock and independently signed origin coordinates come from
    /// the retained owners. Storage must independently resolve the Clone and
    /// authenticate the complete wrapper; this draft is not a receipt.
    ///
    /// # Errors
    /// Rejects an occupied output, changed originals, invalid canonical body,
    /// unauthentic original lease or expired original bound. The draft is
    /// parked before final checks, and failure permanently fences this owner.
    pub fn retain_storage_generation_prepare_into(
        &mut self,
        original: &mut ControllerNixGenerationOriginalV1,
        request_id: [u8; 16],
        target: &mut Option<StorageGenerationPreparationDraftV1>,
    ) -> Result<(), NixStartContinuationErrorV2> {
        use aos_proto::aos::sandbox::local::v1::{
            PrepareNixStorageGenerationRequestV1, PrepareStorageCatalogRequest, StorageAction,
        };
        use aos_sandbox_protocol::nix_generation::{
            CanonicalNixGenerationPreparationV1, NixGenerationStartPrefixV1,
            NIX_GENERATION_REQUEST_MAXIMUM_BYTES_V1,
        };

        if self.failed {
            return Err(ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Closed).into());
        }
        self.failed = true;
        if target.is_some() || request_id == [0; 16] || request_id == [0xff; 16] {
            return Err(ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Changed).into());
        }
        self.recheck_inner()?;
        original.recheck_original(self.selector, self.recipe)
            .map_err(ContinuationFailureV2::from)?;
        let family = original.family().map_err(ContinuationFailureV2::from)?;
        let origin = family.origin();
        let origin_bytes = origin.encode().map_err(ContinuationFailureV2::from)?;
        let first = self.acquisition_clock
            .ok_or(ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Changed))?;
        let binding = self.target.binding();
        let manifest = binding.manifest().manifest();
        if origin.incarnation != *manifest.incarnation().as_bytes() {
            return Err(ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Changed).into());
        }
        let assignment = aos_sandbox_core::BrokerAssignment::new(
            manifest.sandbox(), manifest.incarnation(), manifest.epoch(),
            manifest.desired_generation(), binding.assignment_digest(),
        ).map_err(ContinuationFailureV2::from)?;

        let presentation = self.carrier.original_presentation_commitment();
        let prefix = NixGenerationStartPrefixV1 {
            operation: *self.carrier.operation().as_bytes(),
            step: 0,
            assignment: *binding.assignment_digest().as_bytes(),
            desired: Sha256::digest(&self.carrier.desired().1).into(),
            effect: Sha256::digest(&self.carrier.ordinary_effect()).into(),
            recipe: *self.recipe.digest().as_bytes(),
            input_set: family.artifact_digest(),
            presentation,
            domain: origin.domain,
            project: origin.project,
            sandbox: origin.sandbox,
            incarnation: origin.incarnation,
            origin: Sha256::digest(&origin_bytes).into(),
            source_generation: origin.source_generation,
            next_generation: origin.source_generation.checked_add(1)
                .ok_or(ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Changed))?,
            host_boot_id: first.host_boot_id(),
            first_wall_seconds: first.wall_seconds(),
            first_boottime_nanoseconds: first.boottime_nanoseconds(),
            deadline_boottime_nanoseconds: self.target.deadline_boottime_nanoseconds(),
        };
        let nested = PrepareStorageCatalogRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: prefix.deadline_boottime_nanoseconds,
                maximum_response_bytes: 65_536,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: manifest.sandbox().as_bytes().to_vec(),
                incarnation_id: manifest.incarnation().as_bytes().to_vec(),
                assignment_epoch: manifest.epoch().get(),
                desired_generation: manifest.desired_generation().get(),
                assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
                ..Default::default()
            }).into(),
            action: StorageAction::STORAGE_ACTION_CLONE.into(),
            operation_id: prefix.operation.to_vec(),
            storage_handle: origin.storage_handle.to_vec(),
            source_version_handle: origin.source_version_handle.to_vec(),
            requested_quota_bytes: origin.quota_bytes,
            requested_reservation_bytes: origin.reservation_bytes,
            requested_hold_id: origin.hold_id.to_vec(),
            inventory_generation: origin.inventory_generation,
            inventory_digest: origin.inventory_digest.to_vec(),
            expected_catalog_generation: origin.catalog_generation,
            expected_catalog_digest: origin.catalog_digest.to_vec(),
            preparation_expires_boottime_nanoseconds: prefix.deadline_boottime_nanoseconds,
            ..Default::default()
        };
        let bytes = PrepareNixStorageGenerationRequestV1 {
            canonical_prepare: nested.encode_to_vec(),
            original_start_prefix: prefix.encode().map_err(ContinuationFailureV2::from)?,
            generation_origin: origin_bytes,
            ..Default::default()
        }.encode_to_vec();

        let (lease, observed) = self.target.verified_plan_lease(
            self.journal, &mut || self.clock.sample(),
        ).map_err(ContinuationFailureV2::from)?;
        self.carrier.assignment().require_original_lease(&lease).map_err(NixStartAdmissionErrorV2::from)
            .map_err(ContinuationFailureV2::from)?;
        first.validate_later_sample(observed).map_err(ContinuationFailureV2::from)?;
        let identities = self.selector.pins.identities;
        let checked = CanonicalNixGenerationPreparationV1::decode(
            &bytes,
            aos_sandbox_protocol::PeerCredentials {
                uid: identities[0], gid: identities[1], pid: None,
            },
            aos_sandbox_protocol::PeerPolicy {
                uid: identities[0], gid: Some(identities[1]),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            observed.boottime_nanoseconds(),
        ).map_err(ContinuationFailureV2::from)?;
        let (policy_digest, revocation_scope) = {
            let loan = self.selector.recheck_and_borrow_publics()
                .map_err(ContinuationFailureV2::from)?;
            let credentials = loan.publics()
                .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::CredentialCustodyClosed))?;
            let anchor = plan_anchor_from_publics(&credentials, 6)
                .map_err(ContinuationFailureV2::from)?;
            (ObjectDigest::from_bytes(Sha256::digest(credentials[6].bytes()).into()),
                anchor.revocation_scope())
        };
        let grant = aos_sandbox_core::BrokerGrant::new(
            aos_sandbox_core::BrokerVerb::StoragePrepareCatalog,
            aos_sandbox_core::BrokerGrantTarget::Assignment,
            checked.argument_commitment(),
            NIX_GENERATION_REQUEST_MAXIMUM_BYTES_V1 as u32,
            0,
        ).map_err(ContinuationFailureV2::from)?;
        let feature = aos_sandbox_core::FeatureRef::new(
            "aos.sandbox.authorization.signed-plan-lease", 1, 0,
        ).map_err(|_| ContinuationFailureV2::Generation(NixGenerationOriginalErrorV1::Changed))?;
        let expires = self.target.expires_wall_seconds().min(lease.authority_expires_seconds());
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            aos_sandbox_core::BrokerAudience::Storage,
            aos_sandbox_core::ProtocolId::StorageBroker,
            aos_sandbox_core::ProtocolVersion::new(1, 0),
            assignment, lease.node(), lease.signer().clone(), vec![grant],
            policy_digest, revocation_scope, observed.wall_seconds(), expires, vec![feature],
        ).map_err(ContinuationFailureV2::from)?;
        *target = Some(StorageGenerationPreparationDraftV1 { plan, lease, request: bytes, observed });

        original.recheck_original(self.selector, self.recipe)
            .map_err(ContinuationFailureV2::from)?;
        self.recheck_inner()?;
        self.failed = false;
        Ok(())
    }

    /// Returns the immutable accepted operation identity as data.
    #[must_use]
    pub fn operation_id(&self) -> OperationId {
        self.carrier.operation()
    }

    /// Returns the original signed recipe artifact as historical data.
    #[must_use]
    pub fn recipe_artifact(&self) -> &VerifiedNixRecipeArtifactV2 {
        self.recipe
    }

    /// Returns the original accepted time, never the latest observation time.
    #[must_use]
    pub fn accepted_wall_seconds(&self) -> i64 {
        self.carrier.authority().accepted_wall_seconds()
    }

    /// Returns the assignment owner's exclusive, non-renewable BOOTTIME bound.
    #[must_use]
    pub fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.target.deadline_boottime_nanoseconds()
    }

    /// Rechecks the same current grant, ledger, clock and original assignment.
    ///
    /// The existing grant evaluator advances only its existing protected time
    /// floor. This method never reacquires a target, refreshes a deadline,
    /// selects a replacement recipe, or settles an operation or Effect.
    ///
    /// # Errors
    /// Rejects any changed original/current custody or expired bound. Every
    /// failure permanently closes this instance, including subsequent calls.
    pub fn recheck(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        if self.failed {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let result = self.recheck_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Observes the same original clock even after a selected failure.
    ///
    /// This negative-only bookend never clears the failure latch, reacquires a
    /// target or grants currentness. It preserves the original exclusive D.
    ///
    /// # Errors
    /// Rejects clock acquisition/noncontinuity, another boot or elapsed D.
    pub fn observe_original_clock_after_failure(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        let later = self.clock.sample().map_err(ContinuationFailureV2::from)?;
        require_original_clock_sample(&self.decision, &self.target, later)
    }

    fn require_original_ledger(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        self.selector.require_fixed_writer(self.journal).map_err(ContinuationFailureV2::from)?;
        crate::reconciler::require_current_effect_v2(
            &self.carrier, self.journal, self.carrier.operation(), 0, self.expected_plan,
        ).map_err(ContinuationFailureV2::from)?;
        self.selector.require_bound_writer(self.journal)?;
        self.selector.original_recipe(&self.carrier).map_err(ContinuationFailureV2::from)?;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        self.require_original_ledger()?;
        let decision = match self.intake.as_mut() {
            Some(intake) => evaluate_original_grant_inner(self.journal, &self.carrier, &mut self.clock,
                Some(intake.authorization_crossing().map_err(ContinuationFailureV2::from)?))?,
            None => evaluate_original_grant(self.journal, &self.carrier, &mut self.clock)?,
        };
        self.decision.clock().validate_later_sample(decision.clock())
            .map_err(ContinuationFailureV2::from)?;
        let binding = current_binding(self.journal, self.recipe.recipe().sandbox)
            .map_err(ContinuationFailureV2::from)?;
        if &binding != self.target.binding() {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_original_assignment(self.journal, &self.carrier, self.recipe, &binding)
            .map_err(ContinuationFailureV2::from)?;
        let (lease, observed) = self.target.verified_plan_lease(self.journal, &mut || self.clock.sample())
            .map_err(ContinuationFailureV2::from)?;
        self.carrier.assignment().require_original_lease(&lease).map_err(NixStartAdmissionErrorV2::from)
            .map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority(), decision.clock(), observed)
            .map_err(ContinuationFailureV2::from)?;

        let after = self.clock.sample().map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority(), observed, after)
            .map_err(ContinuationFailureV2::from)?;
        if after.wall_seconds() >= self.target.expires_wall_seconds()
            || after.wall_seconds() >= lease.authority_expires_seconds()
            || current_binding(self.journal, self.recipe.recipe().sandbox)
                .map_err(ContinuationFailureV2::from)? != binding
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_original_assignment(self.journal, &self.carrier, self.recipe, &binding)
            .map_err(ContinuationFailureV2::from)?;
        self.target.recheck(self.journal, &mut || self.clock.sample())
            .map_err(ContinuationFailureV2::from)?;
        self.require_original_ledger()?;
        let final_sample = self.clock.sample().map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority(), after, final_sample)
            .map_err(ContinuationFailureV2::from)?;
        if final_sample.wall_seconds() >= self.target.expires_wall_seconds()
            || final_sample.wall_seconds() >= lease.authority_expires_seconds()
            || final_sample.boottime_nanoseconds() >= self.target.deadline_boottime_nanoseconds()
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_fixed_writer(self.journal).map_err(ContinuationFailureV2::from)?;
        self.decision = decision;
        Ok(())
    }
}

// Both ordinary negative bookends and selected retained closure compare the
// same original clock and exclusive assignment D without granting currentness.
fn require_original_clock_sample(
    decision: &CurrentCapabilityDecisionV1,
    target: &CurrentAssignmentTarget,
    later: RawPairedClockSample,
) -> Result<(), NixStartContinuationErrorV2> {
    decision.clock().validate_later_sample(later)
        .map_err(ContinuationFailureV2::from)?;
    if later.host_boot_id() != decision.clock().host_boot_id()
        || later.boottime_nanoseconds() >= target.deadline_boottime_nanoseconds()
    {
        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
    }
    Ok(())
}

fn evaluate_original_grant(
    journal: &mut Journal,
    carrier: &NixStartAdmissionCarrierV2,
    clock: &mut ControllerProtectedClockV1,
) -> Result<CurrentCapabilityDecisionV1, NixStartContinuationErrorV2> {
    evaluate_original_grant_inner(journal, carrier, clock, None)
}

fn evaluate_original_grant_inner(
    journal: &mut Journal,
    carrier: &NixStartAdmissionCarrierV2,
    clock: &mut ControllerProtectedClockV1,
    crossing: Option<&mut RetainedAuthorizationTimeFloorV1>,
) -> Result<CurrentCapabilityDecisionV1, NixStartContinuationErrorV2> {
    let original = carrier.authority();
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
        original.original_request(),
    ).map_err(ContinuationFailureV2::from)?;
    let selector = request.selector()
        .ok_or(NixStartAdmissionErrorV2::Invalid).map_err(ContinuationFailureV2::from)?;
    let claims = original.capability().claims();
    let decision = match crossing {
        Some(crossing) => evaluate_current_protected_capability_retained(
            journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
            claims.id, original.project(), original.holder(), claims.channel_binding, clock,
            request.resource_kind(), request.operation(), selector, crossing,
        ),
        None => evaluate_current_protected_capability(
            journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
            claims.id, original.project(), original.holder(), claims.channel_binding, clock,
            request.resource_kind(), request.operation(), selector,
        ),
    }.map_err(ContinuationFailureV2::from)?;
    let current = decision.original_coordinates(original.coordinates().session_commitment());
    original.coordinates().require_coordinate_identity(current).map_err(NixStartAdmissionErrorV2::from)
        .map_err(ContinuationFailureV2::from)?;
    if decision.capability() != original.capability()
        || decision.policy().descriptor() != original.policy()
        || decision.policy().canonical_policy() != original.canonical_policy()
        || decision.authorized_wall_seconds() < original.accepted_wall_seconds()
    {
        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
    }
    Ok(decision)
}

fn current_binding(
    journal: &mut Journal,
    sandbox: SandboxId,
) -> Result<RuntimeAuthorityBindingV1, ContinuationFailureV2> {
    RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
        .map_err(ContinuationFailureV2::from)?.current(sandbox)
        .map_err(ContinuationFailureV2::from)?
        .ok_or_else(|| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))
}

fn require_observation(
    original: &CheckedStartAuthorityV2,
    before: RawPairedClockSample,
    after: RawPairedClockSample,
) -> Result<(), ContinuationFailureV2> {
    before.validate_later_sample(after).map_err(ContinuationFailureV2::from)?;
    if after.wall_seconds() < original.accepted_wall_seconds()
        || after.wall_seconds() >= original.coordinates().capability_expires_at()
        || after.wall_seconds() >= original.coordinates().policy_expires_at()
    {
        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid));
    }
    Ok(())
}
