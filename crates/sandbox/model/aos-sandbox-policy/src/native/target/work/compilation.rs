//! Keeps the same authenticated prehold compilation in actual Target work.
//!
//! The parent lends its genuine current gen1 after original bookends. This
//! operation independently checks pinned packets, the exact original row trio,
//! signed sources and deterministic compiler result before retaining any recipe.

use super::{
    RootCompilerInputDataV1, RootCurrentInputVerifierV1, RootCurrentOwnerLoanV1,
    RootInputCurrentPurposeV1, RootOriginalInputLoanV1, RootPolicyPublicationErrorV1 as ErrorV1,
    RootPolicyPublicationWorkV1, RootPreholdCompilationV1,
};
use crate::native::authority::RootAuthorityGen1LoanV1;
use crate::q04_data::Q04RootStageRecipeV1;
use crate::signed_inputs::PolicyDeploymentInputsV1;

impl RootPolicyPublicationWorkV1<'_> {
    /// Retains the original nonissuing compilation under the genuine current gen1.
    ///
    /// # Errors
    /// Refuses reentry or any pinned packet, original-row, signed input, compiler
    /// or currentness mismatch. The complete returned error remains in this Work.
    pub fn reconstruct_prehold_input_once_v1(
        &mut self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8],
        preview_packet: &[u8],
    ) -> Result<(), ()> {
        if self.prehold_entered || self.cause.get().is_some()
            || !matches!(self.target_before, Some(Ok(_)))
        {
            self.refuse_entry_v1();
            return Err(());
        }
        self.prehold_entered = true;
        self.prehold_compilation = Some(self.reconstruct_prehold_input_body_v1(
            gen1,
            stage,
            request_packet,
            preview_packet,
        ));
        if matches!(self.prehold_compilation, Some(Ok(_))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn admit_compiler_materialization_v1(&self) -> Result<(), ErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let shape = crate::parentless_input::compiler_materialization_shape_v1()
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        let controls = std::mem::size_of::<
            Option<crate::parentless_input::CompilerMaterializationShapeDataV1>,
        >()
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<Result<RootPreholdCompilationV1, ErrorV1>>().checked_mul(2)?,
            )
        })
        .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        let memory = shape
            .compiler_memory
            .checked_add(controls)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, memory);
        self.target.journal.admit_role_observation_v1(demand)?;
        Ok(())
    }

    fn reconstruct_prehold_input_body_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        request_packet: &[u8],
        preview_packet: &[u8],
    ) -> Result<RootPreholdCompilationV1, ErrorV1> {
        self.admit_current_verifier_controls_v1()?;
        let (request, controller) = gen1.prehold_input(request_packet, stage)?;
        let fields = request.fields();
        let source = controller.source_commitment();
        let proposal = crate::q04_data::ClosedPolicyRootBindingV2::q04_decode(fields[4])?;
        let view = proposal.q04_fields(&source);
        let rows = aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::read_original_q04_rows_v1(
            fields[1], fields[2], fields[3], aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::Q04OriginalRowBindingV1 {
                operation: *view.operation,
                sandbox: *view.sandbox,
                project: *view.project,
                accepted_generation: *view.accepted_generation,
                desired_precondition: *view.projection_revision,
            },
        )?;
        let before_controller = rows.before;
        let effect_plan = rows.effect_plan_digest()?;
        let original = RootOriginalInputLoanV1::new(
            self.target,
            gen1,
            &self.cause,
            &self.postcheck_debt,
            &self.target_post_failure,
            &self.secondary_panic,
        )?;
        let now = original.recheck()?.wall_seconds();
        let preview =
            crate::q04_data::Q04PreviewV1::decode(preview_packet, stage.staged().challenge())?;
        let signed = preview.fields();
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: signed[3],
            site: signed[4],
            backend: signed[5],
            catalogs: signed[6],
        };
        let (project, deployment_head, deployment) =
            gen1.signed_project_sources(signed[8], &deployment_inputs, now)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original),
            gen1,
            stage,
            controller,
            project: &project,
            deployment_head,
            project_input: signed[8],
            deployment_inputs,
            controller_packet: fields[5],
            proposed: fields[4],
            purpose: RootInputCurrentPurposeV1::Prehold { request_packet },
        };
        current.recheck()?;
        self.admit_compiler_materialization_v1()?;
        let (input, prerequisites, normalized, candidate) =
            current.compile_authenticated_input(&deployment)?;
        let checked_draft = crate::parentless_input::parentless_explicit_draft_digest_v2(
            source,
            project.head().packet_digest(),
            project.head().input_digest(),
            prerequisites.digest(),
            normalized,
        );
        let binding = crate::q04_data::encode_closed_proposal_fields(
            &view,
            project.head().packet_digest(),
            project.head().input_digest(),
            deployment_head,
            normalized,
            candidate.commitment().digest(),
            stage.staged().base(),
            checked_draft,
        )?;
        if binding.as_slice() != fields[4] {
            return Err(ErrorV1::ChangedCut);
        }
        current.recheck()?;
        let validator = crate::native::publication::PolicyCompilerReplayValidatorV1::authenticate(
            [prerequisites.clone()],
            &current,
        )?;
        current.recheck()?;
        Ok(RootPreholdCompilationV1 {
            data: RootCompilerInputDataV1 {
                input,
                prerequisites,
                normalized,
                candidate,
                binding,
            },
            validator,
            before_controller,
            effect_plan,
            operation_revision: *view.operation_revision,
            desired_precondition: *view.projection_revision,
            controller,
        })
    }

    /// Reconstructs and retains the held compiler input under the actual floor.
    ///
    /// # Errors
    /// Refuses reentry, a substituted Claim/Source observation, failed native
    /// currentness, signed models or a compiler result differing from prehold.
    /// The full returned result remains owned by this Work before later posts.
    pub fn reconstruct_held_input_once_v1(
        &mut self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
        claim_packet: &[u8],
        source_packet: &[u8],
        cache_uid: u32,
    ) -> Result<(), ()> {
        if self.held_entered
            || self.cause.get().is_some()
            || !matches!(self.prehold_compilation, Some(Ok(_)))
        {
            self.refuse_entry_v1();
            return Err(());
        }
        self.held_entered = true;
        let returned = self.reconstruct_held_input_body_v1(
            gen1,
            stage,
            identity,
            claim_packet,
            source_packet,
            cache_uid,
        );
        self.held_compilation = Some(returned);
        let (Some(Ok(held)), Some(Ok(prehold))) =
            (&self.held_compilation, &self.prehold_compilation)
        else {
            return Err(());
        };
        if held.binding != prehold.data.binding
            || held.normalized != prehold.data.normalized
            || held.candidate.commitment() != prehold.data.candidate.commitment()
            || held.prerequisites != prehold.data.prerequisites
        {
            let _later = self.cause.set(ErrorV1::ChangedCut);
            return Err(());
        }
        self.held_claim_length = Some(claim_packet.len());
        Ok(())
    }

    fn reconstruct_held_input_body_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
        claim_packet: &[u8],
        source_packet: &[u8],
        cache_uid: u32,
    ) -> Result<RootCompilerInputDataV1, ErrorV1> {
        self.admit_current_verifier_controls_v1()?;
        let claim = gen1.verify_claim(claim_packet, identity)?;
        let fields = claim.fields();
        // Claim11 must be the complete actual Source observation returned by
        // Root on this same held flight, not merely a separately valid signed
        // packet or a copied floor/hash selected by Controller.
        if fields[11] != source_packet {
            return Err(ErrorV1::ChangedCut);
        }
        aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::validate_original_claim_rows_v1(
            fields[0], fields[1], fields[2], identity,
        )?;
        let (controller, held) =
            gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
        let original = RootOriginalInputLoanV1::new(
            self.target,
            gen1,
            &self.cause,
            &self.postcheck_debt,
            &self.target_post_failure,
            &self.secondary_panic,
        )?;
        original.require_cache_uid_v1(cache_uid)?;
        original
            .recheck_cut_v1(identity)
            .map_err(|()| ErrorV1::ChangedCut)?;
        let now = original.recheck()?.wall_seconds();
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: fields[3],
            site: fields[4],
            backend: fields[5],
            catalogs: fields[6],
        };
        let (project, deployment_head, deployment) =
            gen1.signed_project_sources(fields[7], &deployment_inputs, now)?;
        let cache = gen1.cache_cut(fields[12], fields[8], stage, identity, cache_uid)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original),
            gen1,
            stage,
            controller,
            project: &project,
            deployment_head,
            project_input: fields[7],
            deployment_inputs,
            controller_packet: fields[9],
            proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity,
                held,
                held_packet: fields[10],
                cache_packet: fields[12],
                cache,
                cache_uid: cache_uid,
            },
        };
        current.recheck()?;

        self.admit_compiler_materialization_v1()?;
        let (input, prerequisites, normalized, candidate) =
            current.compile_authenticated_input(&deployment)?;

        // The original closed producer owns the sole barrier/Effect-TX/B664
        // serializer. These borrowed fields are independently authenticated
        // above; the new view grants no authority and fabricates no local
        // CurrentCreateProjectPolicySourceV1 or Controller journal.
        let source = controller.source_commitment();
        let operation = controller.operation();
        let operation_revision = identity.operation_revision();
        let generation = identity.accepted_generation();
        let sandbox = controller.sandbox();
        let project_id = controller.project();
        let projection = identity.desired_precondition();
        let publisher_generation = controller.publisher_generation();
        let publisher_head = controller.publisher_digest();
        let cache_domain = controller.cache_domain_head();
        let revocation = controller.revocation_head();
        let ancestry = gen1.floor().tree_head();
        let partition = cache.hold().partition();
        let physical_cache = cache.hold().cache_head();
        let view = crate::q04_data::ClosedCreateProposalFieldViewV2 {
            source_commitment: &source,
            operation: &operation,
            operation_revision: &operation_revision,
            accepted_generation: &generation,
            sandbox: &sandbox,
            project: &project_id,
            projection_revision: &projection,
            publisher_generation: &publisher_generation,
            publisher_head: &publisher_head,
            cache_domain_head: &cache_domain,
            revocation_head: &revocation,
            ancestry: &ancestry,
            physical_partition: &partition,
            physical_cache: &physical_cache,
        };
        let checked_draft = crate::parentless_input::parentless_explicit_draft_digest_v2(
            source,
            project.head().packet_digest(),
            project.head().input_digest(),
            prerequisites.digest(),
            normalized,
        );
        let binding = crate::q04_data::encode_closed_proposal_fields(
            &view,
            project.head().packet_digest(),
            project.head().input_digest(),
            deployment_head,
            normalized,
            candidate.commitment().digest(),
            stage.staged().base(),
            checked_draft,
        )?;
        if binding.as_slice() != fields[8]
            || crate::q04_data::closed_policy_binding_digest_v2(&binding)? != identity.binding()
            || identity.bytes()[456..488] != *normalized.as_bytes()
            || identity.bytes()[488..520] != *candidate.commitment().digest().as_bytes()
        {
            return Err(ErrorV1::ChangedCut);
        }
        current.recheck()?;
        Ok(RootCompilerInputDataV1 {
            input,
            prerequisites,
            normalized,
            candidate,
            binding,
        })
    }
}
