//! Forms the original nonissuing four-member plan on the real Policy target.
//!
//! The independent compiler result, native before-state and capacity remain in
//! the same Work. This plan is not eligible native Authority history; that owner
//! separately pays and forecasts its exact suffix before sending a reply.

use super::{RootPolicyPublicationErrorV1 as ErrorV1, RootPolicyPublicationWorkV1,
    RootPreholdPublicationPlanV1, RootOriginalInputLoanV1};
use crate::native::authority::RootAuthorityGen1LoanV1;
use crate::native::publication::PolicyCompilerProtectedJournalV1;
use crate::q04_data::{Q04PreholdInputDataV1, Q04PreviewV1, Q04RootStageRecipeV1};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    MAXIMUM_CLAIM_BYTES, Q04CutIdentityV1, Q04CutRecipeV1,
};

impl RootPolicyPublicationWorkV1<'_> {
    /// Parks the same target's complete independent publication capacity.
    ///
    /// # Errors
    /// Retains native, signed-model, compiler and canonical representation
    /// failures. Reentry, a changed original row set or foreign nonce refuses.
    pub fn prepare_prehold_publication_once_v1(
        &mut self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8],
        preview_packet: &[u8],
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<(), ()> {
        if self.prehold_plan_entered || self.failure_v1().is_some() {
            self.refuse_entry_v1();
            return Err(());
        }
        self.prehold_plan_entered = true;
        self.prehold_plan = Some(self.form_prehold_publication_v1(gen1, stage,
            request_packet, preview_packet, controller_packet, source_packet));
        if matches!(self.prehold_plan, Some(Ok(_))) { Ok(()) } else { Err(()) }
    }

    fn form_prehold_publication_v1(
        &mut self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8],
        preview_packet: &[u8],
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<RootPreholdPublicationPlanV1, ErrorV1> {
        let original = RootOriginalInputLoanV1::new(self.target, gen1,
            &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?;
        original.recheck()?;
        let clock = original.original_clock_data_v1();
        drop(original);
        let compilation = self.prehold_compilation.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(ErrorV1::ChangedCut)?;
        let state_before = self.target_before.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(ErrorV1::ChangedCut)?;
        let root_before = *self.root_before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let request = Q04PreholdInputDataV1::decode(request_packet)?;
        let nonce = stage.staged().challenge();
        let preview = Q04PreviewV1::decode(preview_packet, nonce)?;
        let metadata = preview.fields()[0];
        if metadata[32..40] != root_before.0.to_be_bytes()
            || metadata[40..88] != root_before.1.to_bytes()
            || metadata[88..120] != *root_before.2.as_bytes()
        {
            return Err(ErrorV1::ChangedCut);
        }
        let original_precut = crate::q04_data::q04_original_precut_digest_v1(
            &request, &preview, controller_packet, source_packet, state_before.1, state_before.0,
        )?;
        let request_fields = request.fields();
        let preview_fields = preview.fields();
        let claim_length = request_fields[1..4].iter()
            .chain(preview_fields[3..7].iter())
            .chain(std::iter::once(&preview_fields[8]))
            .try_fold(2504_usize.checked_add(source_packet.len()).ok_or(ErrorV1::Bounds)?,
                |sum, field| sum.checked_add(field.len()).ok_or(ErrorV1::Bounds))?;
        if claim_length > MAXIMUM_CLAIM_BYTES { return Err(ErrorV1::Bounds); }
        let floor = gen1.floor().digest();
        let ancestry = gen1.floor().tree_head();
        gen1.recheck()?;
        self.admit_publication_materialization_v1(&compilation.data.candidate,
            &compilation.validator, super::receiving::PublicationReceivingPhaseV1::Plan)?;
        let adapter = PolicyCompilerProtectedJournalV1::claim(
            &mut self.target.journal, compilation.validator.clone(),
        )?;
        let recipe = adapter.q04_independent_recipe(&compilation.data.input,
            &compilation.data.candidate, &compilation.data.prerequisites)?;
        let policy_before = recipe.before_digest();
        let independent_recipe = recipe.recipe_digest();
        let seed = crate::q04_data::q04_publication_precut_seed_v1(original_precut,
            root_before.2, compilation.before_controller, floor, ancestry, policy_before)?;
        let publication = recipe.initial_transaction_id(seed, nonce)?;
        if publication == *stage.transaction().id() { return Err(ErrorV1::ChangedCut); }
        let returned = adapter.q04_capacity_plan(publication, recipe, &compilation.data.input,
            &compilation.data.candidate, &compilation.data.prerequisites);
        drop(adapter);
        let capacity = returned?;
        let controller_metadata = request_fields[0];
        let origin = gen1.original_transport_v1()?;
        let identities = origin.try_borrow_mut()?.expected_identities_data_v1()?;
        let digests = [compilation.operation_revision, compilation.desired_precondition,
            compilation.effect_plan, compilation.before_controller, floor, ancestry,
            original_precut, crate::q04_data::closed_policy_binding_digest_v2(&compilation.data.binding)?,
            compilation.data.normalized, compilation.data.candidate.commitment().digest(),
            capacity.transaction_digest(), capacity.current_envelope_digest(),
            ObjectDigest::from_bytes(crate::q04_data::fixed(controller_metadata, 144)), root_before.2];
        let cut = Q04CutRecipeV1 { nonce, project: compilation.controller.project(),
            operation: compilation.controller.operation(), sandbox: compilation.controller.sandbox(),
            controller_uid: identities[0], source_uid: identities[2], controller_metadata,
            root_boot: clock.host_boot_id(), root_started: clock.boottime_nanoseconds(),
            handoff_epoch: stage.staged().base().next_generation(), stage: *stage.transaction().id(),
            publication, digests };
        let identity = aos_sandbox_protocol::encode_original_q04_cut_recipe_v1!(cut, ErrorV1)?;
        if self.target.journal.q04_before_rows_v1()? != *state_before
            || gen1.q04_before_rows_v1()? != root_before
        { return Err(ErrorV1::ChangedCut); }
        gen1.recheck()?;
        RootOriginalInputLoanV1::new(self.target, gen1, &self.cause,
            &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?.recheck()?;
        Ok(RootPreholdPublicationPlanV1 { capacity, identity, root_before,
            original_precut, policy_before, independent_recipe, claim_length })
    }

    /// Borrows the original comparison identity from this Work's parked plan.
    #[must_use]
    pub fn prehold_identity_data_v1(&self) -> Option<&Q04CutIdentityV1> {
        self.prehold_plan.as_ref()?.as_ref().ok().map(|plan| &plan.identity)
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    pub(in crate::native) fn prehold_history_receipt_bytes_v1() -> Option<usize> {
        std::mem::size_of::<super::RootPolicyPreholdHistoryInputV1<'_>>()
            .checked_add(std::mem::size_of::<Result<super::RootPolicyPreholdHistoryInputV1<'_>, ()>>())?
            .checked_add(std::mem::size_of::<Result<super::RootPolicyPreholdHistoryInputV1<'_>, ErrorV1>>())?
            .checked_mul(3)
    }

    pub(in crate::native) fn prehold_history_input_v1(
        &self,
    ) -> Result<super::RootPolicyPreholdHistoryInputV1<'_>, ()> {
        if self.failure_v1().is_some() { return Err(()); }
        let returned = (|| -> Result<super::RootPolicyPreholdHistoryInputV1<'_>, ErrorV1> {
            let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let target_before = *self.target_before.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            if self.target.journal.q04_before_rows_v1()? != target_before {
                return Err(ErrorV1::ChangedCut);
            }
            Ok(super::RootPolicyPreholdHistoryInputV1 { identity: &plan.identity,
                binding: &compilation.data.binding, root_before: plan.root_before,
                target_before, claim_length: plan.claim_length })
        })();
        match returned {
            Ok(receipt) => Ok(receipt),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }

    /// Forecasts the complete passive Root suffix on its actual Authority payer.
    ///
    /// # Errors
    /// Classifies this Work's original receipt refusal separately from the
    /// actual Authority's retained suffix allocation or preflight refusal.
    pub fn forecast_prehold_suffix_once_v1(
        &mut self,
        flight: &mut crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8], preview_packet: &[u8], source_packet: &[u8],
    ) -> Result<(), super::RootPolicyHistoryAdmissionFailureV1> {
        match flight.forecast_q04_prehold_suffix_v1(self, stage,
            request_packet, preview_packet, source_packet)
        {
            Ok(()) => Ok(()),
            Err(()) => Err(if self.failure_v1().is_some() {
                super::RootPolicyHistoryAdmissionFailureV1::PolicyHeld
            } else { super::RootPolicyHistoryAdmissionFailureV1::AuthorityHeld }),
        }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Copies only the original complete Claim width from the actual plan.
    #[must_use]
    pub fn prehold_claim_length_data_v1(&self) -> Option<usize> {
        self.prehold_plan.as_ref()?.as_ref().ok().map(|plan| plan.claim_length)
    }

    /// Rechecks the original prehold sources and complete native before-states.
    ///
    /// # Errors
    /// Retains a changed signed source, compiler/controller association, floor,
    /// original target or clock in this same Work before separate caller posts.
    pub fn require_prehold_current_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8], preview_packet: &[u8],
    ) -> Result<(), ()> {
        let returned = (|| -> Result<(), ErrorV1> {
            let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            let state_before = self.target_before.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ErrorV1::ChangedCut)?;
            if self.target.journal.q04_before_rows_v1()? != *state_before
                || gen1.q04_before_rows_v1()? != plan.root_before
            { return Err(ErrorV1::ChangedCut); }
            self.admit_current_verifier_controls_v1()?;
            let (request, controller) = gen1.prehold_input(request_packet, stage)?;
            let original = RootOriginalInputLoanV1::new(self.target, gen1,
                &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?;
            let now = original.recheck()?.wall_seconds();
            let preview = Q04PreviewV1::decode(preview_packet, stage.staged().challenge())?;
            let fields = preview.fields();
            let inputs = crate::signed_inputs::PolicyDeploymentInputsV1 {
                node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
            };
            let (project, deployment_head, _) = gen1.signed_project_sources(fields[8], &inputs, now)?;
            let current = super::RootCurrentInputVerifierV1 {
                original: super::RootCurrentOwnerLoanV1::Input(original), gen1, stage,
                controller, project: &project, deployment_head, project_input: fields[8],
                deployment_inputs: inputs, controller_packet: request.fields()[5],
                proposed: request.fields()[4],
                purpose: super::RootInputCurrentPurposeV1::Prehold { request_packet },
            };
            current.recheck()?;
            if controller != compilation.controller
                || gen1.floor().digest() != plan.identity.gen1_floor()
                || gen1.floor().tree_head() != compilation.data.prerequisites.ancestry_head()
            { return Err(ErrorV1::ChangedCut); }
            Ok(())
        })();
        match returned { Ok(()) => Ok(()), Err(error) => { let _later = self.cause.set(error); Err(()) } }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Encodes nonissuing prehold DATA only after the actual Authority forecast.
    ///
    /// # Errors
    /// Retains failed forecast association, missing original plan or canonical
    /// width/codec errors; no reply can create native History or publication.
    pub fn publication_data_reply_v1(
        &self,
        flight: &crate::native::authority::RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        request_packet: &[u8],
    ) -> Result<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PreholdPublicationDataV1, ()> {
        let returned = (|| -> Result<_, ErrorV1> {
            use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
            type Reply = aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PreholdPublicationDataV1;
            let bytes = std::mem::size_of::<Reply>()
                .checked_add(std::mem::size_of::<Result<Reply, ErrorV1>>())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<Reply, ()>>()))
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
            self.target.journal.admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;

        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let identity = &plan.identity;
        flight.require_positive_prehold_forecast_v1()?;
        let state_before = self.target_before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let compilation = self.prehold_compilation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ErrorV1::ChangedCut)?;
        let request = Q04PreholdInputDataV1::decode(request_packet)?;
        let mut body = [0; aos_sandbox_protocol::domain_ledger::create_q04_history::PREHOLD_RESPONSE_BYTES];
        body[16..32].copy_from_slice(&identity.nonce());
        body[32..64].copy_from_slice(request.digest().as_bytes());
        body[64..96].copy_from_slice(plan.original_precut.as_bytes());
        body[96..128].copy_from_slice(plan.policy_before.as_bytes());
        body[128..144].copy_from_slice(&identity.stage_id());
        body[144..160].copy_from_slice(&identity.publication_id());
        body[160..192].copy_from_slice(plan.capacity.transaction_digest().as_bytes());
        body[192..224].copy_from_slice(plan.capacity.current_envelope_digest().as_bytes());
        body[224..256].copy_from_slice(plan.independent_recipe.as_bytes());
        body[256..288].copy_from_slice(plan.root_before.2.as_bytes());
        body[288..320].copy_from_slice(compilation.before_controller.as_bytes());
        body[320..352].copy_from_slice(identity.gen1_floor().as_bytes());
        body[352..384].copy_from_slice(identity.ancestry().as_bytes());
        body[384..392].copy_from_slice(&plan.root_before.0.to_be_bytes());
        body[392..400].copy_from_slice(&state_before.0.to_be_bytes());
        body[400..448].copy_from_slice(&state_before.1.to_bytes());
        body[448..452].copy_from_slice(&u32::try_from(plan.claim_length)
            .map_err(|_| ErrorV1::Bounds)?.to_be_bytes());
        let count = aos_sandbox_protocol::domain_ledger::create_q04_history::claim_chunk_count(plan.claim_length)?;
        body[452..454].copy_from_slice(&count.to_be_bytes());
        body[454..456].copy_from_slice(&(count.checked_add(127)
            .ok_or(ErrorV1::Bounds)? / 128).to_be_bytes());

        // The adapter's sole S::order recipe is Candidate/Diagnostics/Effect/
        // Current. These are actual durable members, not reducer-body widths.
        let members = plan.capacity.journal_records();
        if members.len() != 4 {
            return Err(ErrorV1::ChangedCut);
        }
        for (index, member) in members.iter().enumerate() {
            let length = u32::try_from(member.value().ok_or(ErrorV1::ChangedCut)?.len())
                .map_err(|_| ErrorV1::Bounds)?;
            let start = 456 + index * 4;
            body[start..start + 4].copy_from_slice(&length.to_be_bytes());
        }
        aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PreholdPublicationDataV1::from_body(body, identity.nonce())
            .map_err(ErrorV1::from)

        })();
        match returned { Ok(reply) => Ok(reply), Err(error) => { let _later = self.cause.set(error); Err(()) } }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Copies original Root rows from the actual plan without observing Target.
    #[must_use]
    pub fn prehold_root_before_data_v1(&self) -> Option<super::RootPolicyTargetBeforeDataV1> {
        self.prehold_plan.as_ref()?.as_ref().ok().map(|plan| plan.root_before)
    }
}
