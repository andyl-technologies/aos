//! Retains the actual prepared, invoked and strictly read-back Policy outcome.
//!
//! A genuine Authority publication cut lends the same committed binding prefix.
//! The target adapter keeps its real instance identity and original strict
//! refusal behavior; no replayed transaction or capacity DATA adopts a handle.

use super::{RootCurrentInputVerifierV1, RootCurrentOwnerLoanV1,
    RootInputCurrentPurposeV1, RootOriginalInputLoanV1, RootOriginalPublicationLoanV1,
    RootPolicyPublicationErrorV1 as ErrorV1, RootPolicyPublicationWorkV1};
use crate::native::authority::{RootAuthorityGen1LoanV1, RootAuthorityQ04FlightOriginalV1};
use crate::native::publication::{PolicyCompilerProtectedJournalV1,
    PreparedPolicyPublicationV1, Q04PolicyPublicationAttemptV1, Q04PolicyPublicationReadbackV1,
    VerifiedPolicyPublicationV1};
use crate::q04_data::Q04RootStageRecipeV1;
use crate::signed_inputs::PolicyDeploymentInputsV1;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

// This exact lexical construction is shared by preparation and invocation.
// The real Authority/Origin and signed models remain borrowed in their caller
// scope, including the concrete gate after slow native encoding.
macro_rules! held_current {
    ($this:ident, $gen1:ident, $stage:ident, $identity:ident, $claim_packet:ident,
        $cache_uid:ident, $original:expr, $current:ident) => {
        $this.admit_current_verifier_controls_v1()?;
        let claim = $gen1.verify_claim($claim_packet, $identity)?;
        let fields = claim.fields();
        let (controller, held) = $gen1.controller_cut(fields[9], fields[10], fields[8], $stage, $identity)?;
        let original = $original;
        let now = original.recheck()?.wall_seconds();
        let inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = $gen1.signed_project_sources(fields[7], &inputs, now)?;
        let cache = $gen1.cache_cut(fields[12], fields[8], $stage, $identity, $cache_uid)?;
        let $current = RootCurrentInputVerifierV1 {
            original, gen1: $gen1, stage: $stage, controller, project: &project,
            deployment_head, project_input: fields[7], deployment_inputs: inputs,
            controller_packet: fields[9], proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity: $identity, held, held_packet: fields[10], cache_packet: fields[12],
                cache, cache_uid: $cache_uid,
            },
        };
        $current.recheck()?;
    };
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Prepares and parks the same original publication without invoking it.
    ///
    /// # Errors
    /// Retains the exact model, native-before and preparation error. Reentry,
    /// missing earned History or an earlier refused phase prevents preparation.
    pub fn prepare_held_policy_once_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ()> {
        if self.publication_entered || !self.history_complete || self.failure_v1().is_some() {
            self.refuse_entry_v1(); return Err(());
        }
        self.publication_entered = true;
        self.preparation = Some(self.prepare_policy_publication_v1(flight, stage,
            claim_packet, controller_packet, source_packet, cache_uid));
        let prepared = match self.preparation.take() {
            Some(Ok(prepared)) => prepared,
            Some(Err(error)) => { let _later = self.cause.set(error); return Err(()); }
            None => { self.refuse_entry_v1(); return Err(()); }
        };
        self.publication = Some(Q04PolicyPublicationAttemptV1::park(prepared));
        let native = (|| -> Result<JournalTransaction, ErrorV1> {
            let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            Ok(JournalTransaction::new(plan.capacity.transaction_id(),
                plan.capacity.journal_records().to_vec())?)
        })();
        match native {
            Ok(transaction) => { self.native = Some(transaction); Ok(()) }
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }

    /// Invokes the parked strict attempt and retains its whole returned class.
    ///
    /// # Errors
    /// Retains the actual strict preparation, applied or ambiguous native error.
    /// A missing original attempt or repeated invocation refuses without retry.
    pub fn invoke_held_policy_once_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ()> {
        if !self.publication_entered || self.publication.is_none() || self.native.is_none()
            || self.returned.is_some() || self.failure_v1().is_some()
        { self.refuse_entry_v1(); return Err(()); }
        self.returned = Some(self.invoke_policy_publication_v1(flight, stage,
            claim_packet, controller_packet, source_packet, cache_uid));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    /// Parks the independent first publication readback after the caller's bookend.
    ///
    /// This body adds no fresh gen1 or original-clock observation. Root performs
    /// its original owner recheck immediately before entry and held checks after.
    ///
    /// # Errors
    /// Retains exact physical-name, native-prefix, sequence and schema failures.
    pub fn observe_first_publication_body_once_v1(&mut self) -> Result<(), ()> {
        if self.readback.is_some() || !matches!(self.returned, Some(Ok(())))
            || self.failure_v1().is_some()
        { self.refuse_entry_v1(); return Err(()); }
        let mut names_failure = None;
        let outcome = self.read_policy_publication_body_v1(&mut names_failure);
        self.readback = Some(super::RootPolicyReadbackObservationV1 { outcome, names_failure });
        if self.readback.as_ref().is_some_and(|observation| observation.outcome.is_ok()) {
            self.publication_complete = true;
            Ok(())
        } else { Err(()) }
    }

    fn prepare_policy_publication_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<PreparedPolicyPublicationV1, ErrorV1> {
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let before = self.target_before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        if self.target.journal.q04_before_rows_v1()? != *before { return Err(ErrorV1::ChangedCut); }
        let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        self.admit_publication_materialization_v1(&compilation.data.candidate, &compilation.validator,
            super::receiving::PublicationReceivingPhaseV1::Prepare)?;
        let data = match self.held_compilation.take() {
            Some(Ok(data)) => data,
            Some(Err(error)) => return Err(error),
            None => return Err(ErrorV1::ChangedCut),
        };
        self.held_consumed = true;
        let gen1 = flight.refresh_completed_gen1_v1(controller_packet, source_packet)?;
        let gen1 = &gen1;
        let identity = &plan.identity;
        held_current!(self, gen1, stage, identity, claim_packet, cache_uid,
            RootCurrentOwnerLoanV1::Publication(RootOriginalPublicationLoanV1::new(
                self.target, gen1, &self.cause)?), current);
        let verified = VerifiedPolicyPublicationV1::authenticate(&data.input,
            data.candidate, data.prerequisites, &current)?;
        let adapter = PolicyCompilerProtectedJournalV1::claim(&mut self.target.journal,
            compilation.validator.clone())?;
        adapter.q04_current_plan(identity.publication_id(), verified, &plan.capacity).map_err(Into::into)
    }

    fn invoke_policy_publication_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ErrorV1> {
        let cut = flight.borrow_q04_publication_cut_v1(stage, controller_packet, source_packet)?;
        let gen1 = cut.gen1_v1();
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        self.admit_publication_materialization_v1(&compilation.data.candidate, &compilation.validator,
            super::receiving::PublicationReceivingPhaseV1::Invoke)?;
        let identity = &plan.identity;
        held_current!(self, gen1, stage, identity, claim_packet, cache_uid,
            RootCurrentOwnerLoanV1::Publication(RootOriginalPublicationLoanV1::new(
                self.target, gen1, &self.cause)?), current);
        let mut adapter = PolicyCompilerProtectedJournalV1::claim(&mut self.target.journal,
            compilation.validator.clone())?;
        adapter.q04_commit_original(self.publication.as_mut().ok_or(ErrorV1::ChangedCut)?,
            &current).map_err(Into::into)
    }

    pub(super) fn require_held_current_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1, claim_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ErrorV1> {
        let identity = &self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?.identity;
        held_current!(self, gen1, stage, identity, claim_packet, cache_uid,
            RootCurrentOwnerLoanV1::Input(RootOriginalInputLoanV1::new(self.target, gen1,
                &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?), current);
        current.recheck()
    }

    pub(super) fn read_policy_publication_body_v1(
        &mut self,
        names_failure: &mut Option<usize>,
    ) -> Result<Q04PolicyPublicationReadbackV1, ErrorV1> {
        let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        self.admit_publication_materialization_v1(&compilation.data.candidate, &compilation.validator,
            super::receiving::PublicationReceivingPhaseV1::Readback)?;
        let backing = super::super::RootPolicyTargetOriginalV1::physical_names_additional_demand_v1()?;
        self.target.journal.admit_role_observation_v1(backing)?;
        let index = self.readback_names.len();
        self.readback_names.push(crate::native::RootPolicyNameObservationOriginalV1::new());
        let original = self.readback_names.last_mut().ok_or(ErrorV1::ChangedCut)?;
        let names = match self.target.observe_held_physical_names_once_v1(original) {
            Ok(names) => names,
            Err(()) => { *names_failure = Some(index); return Err(ErrorV1::ChangedCut); }
        };
        original.settle_positive_once_v1();
        if original.failure().is_some() { *names_failure = Some(index); return Err(ErrorV1::ChangedCut); }
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let before = self.target_before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        if names != before.1 || self.target.journal.snapshot_sequence()
            != before.0.checked_add(6).ok_or(ErrorV1::Bounds)?
        { return Err(ErrorV1::ChangedCut); }
        self.target.journal.require_q04_native_recipe_prefix_v1(
            std::slice::from_ref(self.native.as_ref().ok_or(ErrorV1::ChangedCut)?), before.0)?;
        let adapter = PolicyCompilerProtectedJournalV1::claim(&mut self.target.journal,
            compilation.validator.clone())?;
        adapter.q04_observe_original_publication(self.publication.as_ref()
            .ok_or(ErrorV1::ChangedCut)?, &plan.capacity).map_err(Into::into)
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    pub(in crate::native) fn publication_receipt_bytes_v1() -> Option<usize> {
        std::mem::size_of::<super::RootPolicyPublicationReceiptV1<'_>>()
            .checked_add(std::mem::size_of::<Result<super::RootPolicyPublicationReceiptV1<'_>, ()>>())?
            .checked_add(std::mem::size_of::<Result<super::RootPolicyPublicationReceiptV1<'_>, ErrorV1>>())?
            .checked_mul(3)
    }

    pub(in crate::native) fn publication_receipt_v1(
        &self,
    ) -> Result<super::RootPolicyPublicationReceiptV1<'_>, ()> {
        if self.failure_v1().is_some() { return Err(()); }
        let returned = (|| -> Result<super::RootPolicyPublicationReceiptV1<'_>, ErrorV1> {
            if !self.publication_complete || self.failure_v1().is_some()
                || !matches!(self.returned, Some(Ok(())))
                || self.publication.as_ref().and_then(|attempt| attempt.applied()).is_none()
            { return Err(ErrorV1::ChangedCut); }
            let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let readback = self.decision_readback.as_ref().and_then(|observation| observation.outcome.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let before = *self.target_before.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            if readback.sequence != before.0.checked_add(6).ok_or(ErrorV1::Bounds)?
                || readback.transaction != plan.identity.policy_transaction()
                || readback.current != plan.identity.policy_current()
            { return Err(ErrorV1::ChangedCut); }
            let binding = &self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?.data.binding;
            Ok(super::RootPolicyPublicationReceiptV1 { identity: &plan.identity, binding,
                target_before: before, sequence: readback.sequence,
                transaction: readback.transaction, current: readback.current })
        })();
        match returned {
            Ok(receipt) => Ok(receipt),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Repeats the held-input and native publication observation for Decision.
    ///
    /// The earlier successful readback remains resident. This separate reached
    /// result is parked before Decision admission and independently owed posts.
    ///
    /// # Errors
    /// Retains original currentness, native replay and exact member failures.
    /// Reentry or an incomplete strict publication refuses without retry.
    pub fn refresh_publication_for_decision_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ()> {
        if self.decision_readback_entered || !self.publication_complete
            || self.failure_v1().is_some()
        {
            self.refuse_entry_v1();
            return Err(());
        }
        self.decision_readback_entered = true;
        let returned = (|| -> Result<(), ErrorV1> {
            self.require_held_originals_body_v1(flight, stage, claim_packet,
                controller_packet, source_packet, cache_uid)?;
            self.require_original_owners_current_v1(flight)?;
            Ok(())
        })();
        if let Err(error) = returned {
            self.decision_readback = Some(super::RootPolicyReadbackObservationV1 {
                outcome: Err(error), names_failure: None,
            });
            return Err(());
        }
        let mut names_failure = None;
        let outcome = self.read_policy_publication_body_v1(&mut names_failure);
        self.decision_readback = Some(super::RootPolicyReadbackObservationV1 { outcome, names_failure });
        if self.decision_readback.as_ref().is_some_and(|observation| observation.outcome.is_ok()) { Ok(()) } else { Err(()) }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Rechecks the real held compiler input without returning an issuing token.
    ///
    /// # Errors
    /// Retains original currentness, pinned Claim, Cache or signed input errors.
    pub fn require_held_input_current_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim: &[u8], cache_uid: u32,
    ) -> Result<(), ()> {
        match self.require_held_current_v1(gen1, stage, claim, cache_uid) {
            Ok(()) => Ok(()),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    // These are the original full Root bookends, with the real Authority at
    // its old queue-before-Target position. No current snapshot is adopted.
    fn require_original_owners_current_v1(
        &self,
        flight: &RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
    ) -> Result<(), ErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector, RawPairedClockSample};
        let controls = std::mem::size_of::<Result<RawPairedClockSample, ErrorV1>>()
            .checked_add(std::mem::size_of::<Result<(), ErrorV1>>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<&super::RootPreholdPublicationPlanV1>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), crate::native::PolicyNativeJournalErrorV1>>()))
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ErrorV1::Bounds)?;
        self.target.journal.admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, controls))?;
        let original = RootOriginalInputLoanV1::from_ready_flight_v1(self.target, flight,
            &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?;
        let current = original.recheck_with_authority_v1(flight)?;
        if let Some(plan) = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok()) {
            // The authenticated prehold already joined Controller's boot to
            // this same Root boot; the identity retains that original cutoff.
            if current.host_boot_id() != crate::q04_data::fixed(plan.identity.bytes(), 112)
                || current.boottime_nanoseconds()
                    >= u64::from_be_bytes(crate::q04_data::fixed(plan.identity.bytes(), 136))
            { return Err(ErrorV1::Expired); }
        }
        Ok(())
    }

    fn require_held_originals_body_v1(
        &self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ErrorV1> {
        self.require_original_owners_current_v1(flight)?;
        let gen1 = flight.refresh_completed_gen1_v1(controller_packet, source_packet)?;
        self.require_held_current_v1(&gen1, stage, claim_packet, cache_uid)?;
        drop(gen1);
        self.require_original_owners_current_v1(flight)
    }

    /// Rechecks the real held compiler cut between its two original owner bookends.
    ///
    /// # Errors
    /// Retains the actual Authority, Target, Claim, model or original clock cause.
    /// The returned unit is selected from this same Work before any later post.
    pub fn require_held_originals_current_v1(
        &self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim_packet: &[u8], controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
    ) -> Result<(), ()> {
        if self.failure_v1().is_some() { self.refuse_entry_v1(); return Err(()); }
        match self.require_held_originals_body_v1(flight, stage, claim_packet,
            controller_packet, source_packet, cache_uid)
        {
            Ok(()) => Ok(()),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }
}
