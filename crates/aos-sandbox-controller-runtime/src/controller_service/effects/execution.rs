//! Concrete Controller effect dispatch, native clocks and broker recovery.
//!
//! The complete existing executor trait implementation remains one ordered
//! dispatch owner. Role matches, refusal gates, session loans and native clock
//! sampling retain their original boundaries; no callback or backend is added.

use super::*;
use crate::controller_service::execution;

#[cfg(test)]
mod tests;

fn reject_unqualified_delete_effect(plan: &EffectPlan) -> Result<(), EffectFailure> {
    if plan.public_mutation_method()
        == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::DeleteSandbox)
    {
        // Retained operations cannot run until the protected dependency plan exists.
        return Err(EffectFailure::Permanent(
            "sandbox deletion awaits a protected dependency plan".to_owned(),
        ));
    }

    Ok(())
}

impl SingleNodeEffectExecutor for ProductionEffectExecutor {
    #[cfg(target_os = "linux")]
    fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        operation: &mut aos_sandbox::reconciler::GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        use aos_sandbox::cache_residency::CacheResidentUnavailableV1;

        self.cache_mutation.require_completed_or_empty()?;
        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let physical = self.cache_physical.as_ref().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.run_existing_git_coverage_read_metadata_v1(
            protected, physical, &mut self.source_domains, journal,
            original_inputs, operation,
        )
    }

    #[cfg(target_os = "linux")]
    fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.capture_existing_git_coverage_account_cut(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    fn commit_existing_git_coverage_account_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.commit_existing_git_coverage_account(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    fn compare_existing_cache_git_coverage_v1(
        &mut self,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        flight: aos_sandbox_core::format::git_upload_enrollment::GitCoverageFlightV1,
        original_nonce: [u8; 16],
        original_account: Option<&mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.compare_existing_cache_git_coverage(original_inputs, flight, original_nonce, original_account)
    }

    fn select_original_create_q04_policy_subgate_v1(
        &mut self,
        profile: Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), EffectFailure> {
        create_q04::select(self, profile)
    }

    fn reconcile_original_create_q04_policy_subgate_v1(
        &mut self,
        operation: OperationId,
        step: u32,
        effect_count: u32,
        plan: &EffectPlan,
        dispatch: Option<&PreparedAuthorityEffectV1>,
        authority_gate: Option<(aos_sandbox_core::SandboxId, ObjectDigest)>,
        journal: &mut Journal,
    ) -> Option<Result<(), EffectFailure>> {
        create_q04::reconcile(
            self, operation, step, effect_count, plan, dispatch, authority_gate, journal,
        )
    }

    fn existing_cache_project_usage_v1(
        &mut self,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<aos_sandbox::cache_residency::CacheProjectUsageLoanV1<'_>, aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.observe_existing_cache_usage(project)
    }

    fn recheck_existing_cache_project_usage_v1(
        &mut self,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        let owner = self.cache_inventory.as_mut()
            .ok_or(aos_sandbox::cache_residency::CacheResidentUnavailableV1)?;
        self.cache_resident_usage.recheck(owner)
    }

    fn reconcile_operator_storage_repair(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
        completion_wall_seconds: i64,
    ) -> Result<aos_sandbox::OperatorStorageRepairReconcileV1, EffectFailure> {
        operator_repair::reconcile(self, operation_id, step, plan, journal, completion_wall_seconds)
    }

    fn coordinate_provisioned_source_genesis_v1(
        &mut self,
        journal: &mut Journal,
        input: &ProvisionedControllerSourceGenesisInputV1,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, ControllerSourceGenesisInputErrorV1> {
        // This is the existing fixed Controller-purpose role, independently
        // pinned by Root. It supplies no administrative seed or Root authority.
        with_process_controller_hold_signer_v1(|generation, signer| {
            Ok(
                aos_sandbox::policy_compiler::coordinate_provisioned_source_genesis_v1(
                    journal,
                    &mut self.source_domains,
                    input,
                    profile,
                    generation,
                    signer,
                ),
            )
        })
        .map_err(aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?
    }

    fn issue_source_successor_v2<'writers, 'profile, 'credentials>(
        &'writers mut self,
        journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut aos_sandbox::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<
        aos_sandbox::hierarchy::source_successor::SourceSuccessorApprovalDataV2,
        aos_sandbox::policy_compiler::FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        let mut original = aos_sandbox::policy_compiler::OriginalSourceSuccessorInvocationV2::park(
            journal, &mut self.source_domains, profile, credentials,
        );
        if let Err(cause) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_controller_signer(generation, signer);
            Ok(())
        }) {
            original.fail_controller_signer_admission(cause);
        }
        original.into_outcome()
    }

    fn coordinate_configured_project_genesis_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, aos_sandbox::policy_compiler::FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalConfiguredProjectGenesisInvocationV3::park(
            journal, &mut self.source_domains, input, profile,
        );
        if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_signer(generation, signer);
            Ok(())
        }) { original.fail_signer_admission(error); }
        original.into_outcome()
    }

    fn prepare_first_global_prefix_v1(
        &mut self,
        journal: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        let bank = self.resource_bank.as_ref()
            .ok_or(aos_sandbox::ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if self.first_global_prefix.is_some() {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        self.first_global_prefix = Some(
            aos_sandbox::ControllerFirstGlobalPrefixAttemptV1::new(Arc::clone(bank)),
        );
        // These are actual resident original representations, not deployment
        // flags or a new default Session masquerading as an unused owner.
        let shape = (|| {
            let sessions = self.sessions.lock()
                .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
            if sessions.host.is_some()
                || sessions.mount.is_some()
                || sessions.storage.is_some()
                || sessions.storage_cold.is_some()
                || sessions.network.is_some()
                || sessions.storage_root.has_pending()
                || sessions.storage_root.requires_reconnect()
                || self.pending_attachment_slot_attempt.is_some()
                || self.pending_attachment_catalog_query.is_some()
                || self.pending_attachment_mount_attempt.is_some()
                || self.pending_attachment_source_attempt.is_some()
                || self.pending_attachment_source_consume.is_some()
                || self.pending_cache_pin.is_some()
                || self.pending_cache_unpin.is_some()
                || self.pending_source_commit.is_some()
                || self.pending_snapshot_coordination.is_some()
                || self.pending_atomic_snapshot.is_some()
                || self.pending_snapshot_derivative.is_some()
                || self.q04.is_some()
            {
                return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
            }
            #[cfg(feature = "online-nix")]
            if sessions.nix_resolve.is_some() || sessions.nix_input_source.is_some() {
                return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        self.first_global_prefix.as_mut()
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?
            .prepare_once(journal, &mut self.source_domains, profile, shape)
    }

    fn coordinate_configured_global_genesis_v2<'writers, 'profile>(
        &'writers mut self,
        journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ObjectDigest,
        aos_sandbox::policy_compiler::FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>,
    > {
        let mut original = aos_sandbox::policy_compiler::OriginalConfiguredGlobalGenesisInvocationV2::park_with_resource_bank(
            journal,
            &mut self.source_domains,
            input,
            profile,
            self.resource_bank.clone(),
        );
        if let Some(prefix) = self.first_global_prefix.as_ref() {
            if original.attach_first_global_prefix(prefix).is_err() {
                // The whole attachment failure and independent posts/LAST
                // precede fixed credential loading or SigningKey creation.
                return original.into_outcome();
            }
        }

        if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_signer(generation, signer);
            Ok(())
        }) {
            original.fail_signer_admission(error);
        }

        original.into_outcome()
    }

    fn issue_project_source_successor_v3<'writers, 'profile, 'credentials>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut aos_sandbox::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<aos_sandbox::hierarchy::source_successor::SourceSuccessorApprovalDataV2, aos_sandbox::policy_compiler::FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        let mut original = aos_sandbox::policy_compiler::OriginalSourceProjectSuccessorInvocationV3::park(
            journal, &mut self.source_domains, profile, credentials,
        );
        if let Err(cause) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_controller_signer(generation, signer);
            Ok(())
        }) { original.fail_controller_signer_admission(cause); }
        original.into_outcome()
    }

    fn coordinate_retained_first_source_successor_v2<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalFirstSourceSuccessorInvocationV2::park(
            journal, &mut self.source_domains, profile,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            // The invocation predates the selected signer/catch boundary. Its
            // whole returned failure retains both writers through termination.
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) {
                original.fail_controller_signer_admission(error);
            }
        }
        original.into_outcome()
    }

    fn coordinate_project_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalProjectSuccessorInvocationV3::park(
            journal, &mut self.source_domains, profile, project,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) { original.fail_controller_signer_admission(error); }
        }
        original.into_outcome()
    }

    fn coordinate_predecessor_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalProjectSuccessorInvocationV3::park_predecessor(
            journal, &mut self.source_domains, profile, input,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) { original.fail_controller_signer_admission(error); }
        }
        original.into_outcome()
    }

    fn prepare_guardian_plan(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        request: &GuardianPlanRequestV1,
    ) -> Option<SignedBrokerPlan> {
        let signer = self.broker_plan_signer.as_ref()?;
        let now_seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let plan = request.plan_at(now_seconds).ok()?;
        signer.sign_plan(plan, now_seconds).ok()
    }

    fn authority_effect_timing(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
    ) -> Option<AuthorityEffectAttemptTimingV1> {
        production_authority_effect_timing()
    }

    fn observe(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        if plan.public_mutation_method().is_some() {
            return Err(EffectFailure::Permanent(
                "controller mutation bypassed its journal-custody hook".to_owned(),
            ));
        }
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }

    fn apply(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        if plan.public_mutation_method().is_some() {
            return Err(EffectFailure::Permanent(
                "controller mutation bypassed its journal-custody hook".to_owned(),
            ));
        }
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }

    fn observe_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectObservation, EffectFailure> {
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            #[cfg(feature = "online-nix")]
            if self.nix_generation_enabled {
                return nix_generation::observe(self, operation_id, step);
            }
            #[cfg(feature = "online-nix")]
            return nix_environment::observe(self, operation_id, step);
            #[cfg(not(feature = "online-nix"))]
            // Admission is real, but no namespace47 floor/archive/publication
            // owner exists in this slice. Generic lifecycle cannot stand in.
            return Ok(EffectObservation::Absent);
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        {
            self.require_current_create_effect(operation_id, plan, journal)?;
            return Ok(EffectObservation::Absent);
        }

        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return Ok(observation);
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::observe(self, operation_id, &context, journal)?;
            return Ok(EffectObservation::Absent);
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent = execution::ControllerExecutionIntentV1::from_request(
                operation_id,
                &context,
                journal,
            )?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(|| {
                EffectFailure::Retryable("Host session is unavailable".to_owned())
            })?;
            let authorization = host
                .needs_fresh_execution_authorization()
                .then(|| {
                    intent.prepare_authorization(
                        execution::ExecutionAuthorizationKindV1::Query,
                        context.project(),
                        self.node,
                        journal,
                        self.broker_plan_signer.as_ref(),
                    )
                })
                .transpose()?;
            let observation = host.query_execution(&intent, authorization.as_ref(), context.project(), journal)?;
            return match observation {
                execution::ControllerExecutionObservationV1::Absent => {
                    Ok(EffectObservation::Absent)
                }
                execution::ControllerExecutionObservationV1::Applied(completion) => {
                    Ok(EffectObservation::Applied(completion.receipt))
                }
            };
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
        {
            return Self::ownership_recovery_receipt(operation_id, &context, journal).map(
                |receipt| receipt.map_or(EffectObservation::Absent, EffectObservation::Applied),
            );
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::AttachView
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::ReplaceAttachment
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::DetachView
            )
        ) {
            // Generic lifecycle receipts do not prove an attachment or Mount effect.
            return Ok(EffectObservation::Absent);
        }
        if plan.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
        {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some((_, current)) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            {
                if current.operation().terminal_result()
                    == Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::CanceledBeforeCommit)
                {
                    return Ok(EffectObservation::Applied(
                        EffectReceipt::canceled_before_commit(current.record().digest()),
                    ));
                }
            }
            drop(owner);
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(EffectObservation::Applied(receipt));
            }
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
        {
            let cancellation = Self::cancellation_request(&context)?;
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some(resolution) = owner
                .cancellation_resolution(
                    context.caller(),
                    context.project(),
                    cancellation.target_operation,
                    cancellation.idempotency,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            {
                return Self::cancellation_receipt(&resolution).map(EffectObservation::Applied);
            }
            drop(owner);
            if let Some(receipt) =
                Self::terminal_public_operation_receipt(journal, cancellation.target_operation)?
            {
                return Ok(EffectObservation::Applied(receipt));
            }
        }
        if let DormantSandboxRequestKindV1::ViewCreate(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            return view_mutations::observe_create_view(operation_id, &context, &request, journal);
        }
        if let DormantSandboxRequestKindV1::ViewRelease(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            return view_mutations::observe_release_view(operation_id, &context, &request, journal);
        }
        Ok(EffectObservation::Absent)
    }

    fn apply_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectReceipt, EffectFailure> {
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            #[cfg(feature = "online-nix")]
            if self.nix_generation_enabled {
                return nix_generation::prepare(self, operation_id, step, plan, journal);
            }
            #[cfg(feature = "online-nix")]
            return nix_environment::resolve(self, operation_id, step, plan, journal);
            #[cfg(not(feature = "online-nix"))]
            return Err(EffectFailure::Retryable(
                "retained Nix Start awaits genuine session floor and recipe publication owners".to_owned(),
            ));
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        {
            let source = self.require_current_create_effect(operation_id, plan, journal)?;
            let progress =
                crate::controller_service::project_admission::advance_create_project_admission_v1(
                    journal,
                    &mut self.source_domains,
                    &source,
                    self.request_scope,
                    plan,
                )
                .map_err(|error| {
                    EffectFailure::Retryable(format!(
                        "protected project admission is pending: {error}"
                    ))
                })?;
            if matches!(
                progress,
                crate::controller_service::project_admission::ProjectAdmissionProgressV1::RetiredPrior
            ) {
                return Err(EffectFailure::Retryable(
                    "prior project admission was retired; retry exact Create".to_owned(),
                ));
            }
            // V2 source admission is a prerequisite, not the held four-owner
            // compiler publication or a public Create completion.
            return Err(EffectFailure::Retryable(
                CREATE_Q04_AUTHORITY_PENDING.to_owned(),
            ));
        }

        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return match observation {
                EffectObservation::Applied(receipt) => Ok(receipt),
                EffectObservation::Absent => Err(EffectFailure::Retryable(
                    "protected source commit recovery is incomplete".to_owned(),
                )),
            };
        }
        if self.pending_cache_unpin.is_some() {
            self.ensure_cache_physical_owner()?;
            self.recover_pending_cache_unpin(operation_id)?;
        }
        if self.pending_cache_pin.is_some() {
            self.ensure_cache_physical_owner()?;
            self.recover_pending_cache_pin(operation_id)?;
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::apply(self, operation_id, &context, journal)?;
            return Err(EffectFailure::Retryable(
                "execution Create awaits physical Storage backing and Host launch".to_owned(),
            ));
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent = execution::ControllerExecutionIntentV1::from_request(
                operation_id,
                &context,
                journal,
            )?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(|| {
                EffectFailure::Retryable("Host session is unavailable".to_owned())
            })?;
            let authorization = host
                .needs_fresh_execution_authorization()
                .then(|| {
                    intent.prepare_authorization(
                        execution::ExecutionAuthorizationKindV1::Apply,
                        context.project(),
                        self.node,
                        journal,
                        self.broker_plan_signer.as_ref(),
                    )
                })
                .transpose()?;
            let completion = host.apply_execution(&intent, authorization.as_ref(), context.project(), journal)?;
            return Ok(completion.receipt);
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
        {
            return Self::ownership_recovery_receipt(operation_id, &context, journal)?.ok_or_else(
                || {
                    EffectFailure::Retryable(
                        "operator recovery is awaiting explicit ownership activation".to_owned(),
                    )
                },
            );
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
        {
            let cancellation = Self::cancellation_request(&context)?;
            let admission = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                if owner
                    .current_operation_by_id(cancellation.target_operation)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    .is_none()
                {
                    None
                } else {
                    Some(
                        owner
                            .admit_cancellation(
                                operation_id,
                                context.caller(),
                                context.project(),
                                cancellation.target_operation,
                                cancellation.idempotency,
                                cancellation.requested_at,
                            )
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
                    )
                }
            };
            if let Some(admission) = admission {
                return self.settle_cancellation_admission(operation_id, admission);
            }
            if let Some(receipt) =
                Self::terminal_public_operation_receipt(journal, cancellation.target_operation)?
            {
                return Ok(receipt);
            }
            return Err(EffectFailure::Retryable(
                "cancellation target is awaiting protected lifecycle admission".to_owned(),
            ));
        }
        let request = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if let DormantSandboxRequestKindV1::ViewCreate(create) = &request {
            return view_mutations::apply_create_view(operation_id, &context, create, journal);
        }
        if let DormantSandboxRequestKindV1::ViewRelease(release) = &request {
            return view_mutations::apply_release_view(operation_id, &context, release, journal);
        }
        if matches!(
            &request,
            DormantSandboxRequestKindV1::ViewAttach(_)
                | DormantSandboxRequestKindV1::ViewReplace(_)
                | DormantSandboxRequestKindV1::ViewDetach(_)
        ) {
            let (sandbox, slot, attachment) = attachment_target::admitted_attachment(
                journal,
                operation_id,
                context.project(),
                &request,
            )?;
            if attachment_physical::drain_pending_before_slot(self, journal)? {
                return Err(EffectFailure::Retryable(
                    "fresh authenticated Mount inventory is pending".to_owned(),
                ));
            }
            attachment_slot_effect::advance(
                self,
                operation_id,
                &context,
                &request,
                sandbox,
                slot,
                journal,
            )?;
            if let DormantSandboxRequestKindV1::ViewAttach(attach) = &request {
                attachment_desired::advance_immutable_attach(
                    self,
                    operation_id,
                    &context,
                    attach,
                    &attachment,
                    sandbox,
                    slot,
                    journal,
                )?;
            } else {
                attachment_desired::advance_existing(
                    self,
                    operation_id,
                    &context,
                    &request,
                    &attachment,
                    sandbox,
                    slot,
                    journal,
                )?;
            }
            let attachment_id: [u8; 16] =
                attachment
                    .attachment_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                        EffectFailure::Permanent(
                            "admitted attachment identity is invalid".to_owned(),
                        )
                    })?;
            let verified = attachment_physical::observe(
                self,
                operation_id,
                AttachmentId::from_bytes(attachment_id),
                sandbox,
                journal,
            )?;
            return verified.receipt(operation_id);
        }
        let cache_consumer = if matches!(
            &request,
            DormantSandboxRequestKindV1::CachePin(_) | DormantSandboxRequestKindV1::CacheUnpin(_)
        ) {
            Some(
                aos_sandbox::production_operation_compiler::recheck_cache_consumer_projection_v1(
                    journal,
                    context.project(),
                    &request,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
            )
        } else {
            None
        };
        if matches!(&request, DormantSandboxRequestKindV1::CachePin(_)) {
            let consumer = cache_consumer.as_ref().ok_or_else(|| {
                EffectFailure::Permanent("cache pin consumer is unavailable".to_owned())
            })?;
            return self.apply_public_cache_pin(operation_id, consumer, journal, &request);
        }
        if matches!(&request, DormantSandboxRequestKindV1::CacheUnpin(_)) {
            let consumer = cache_consumer.as_ref().ok_or_else(|| {
                EffectFailure::Permanent("cache unpin consumer is unavailable".to_owned())
            })?;
            return self.apply_public_cache_unpin(operation_id, consumer, journal, &request);
        }
        if is_lifecycle_mutation(&request) {
            let operation =
                self.validate_lifecycle_admission(operation_id, &context, &request, journal)?;
            let admission = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .admit_operation(operation)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            self.settle_lifecycle_admission(operation_id, admission)?;
            self.bind_lifecycle_plan(operation_id)?;
            self.ensure_initial_lifecycle_reservation(operation_id)?;
            if self.advance_terminal_lifecycle_publication(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(receipt);
            }
            if self.advance_controller_lifecycle_effect(operation_id)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_runtime_lifecycle_effect(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_storage_lifecycle_effect(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_lifecycle_semantic_commit(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_terminal_lifecycle_publication(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(receipt);
            }
        }
        Err(EffectFailure::Retryable(
            CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
        ))
    }

    fn observe_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        let method = prepared
            .broker_request()
            .map_err(|_| {
                EffectFailure::Permanent("durable authority effect is malformed".to_owned())
            })?
            .method();
        if self.prepared_in_this_process(prepared) {
            let retained = {
                let mut sessions = self.sessions.lock().map_err(|_| {
                    EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                })?;
                resume_controller_authority_effect(&mut sessions, method, prepared)?
            };
            return match retained {
                Some(receipt) => Ok(AuthorityEffectObservationV1::Applied(receipt)),
                None => Ok(AuthorityEffectObservationV1::Absent),
            };
        }
        let recovered = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            recover_controller_terminal_authority_effect(&mut sessions, method, prepared)?
        };
        if let Some(receipt) = recovered {
            return Ok(AuthorityEffectObservationV1::Applied(receipt));
        }
        if method == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            return sessions
                .host
                .as_mut()
                .ok_or_else(missing_broker_session)?
                .query_authority_effect(prepared);
        }
        let retained = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            resume_controller_authority_effect(&mut sessions, method, prepared)?
        };
        if let Some(receipt) = retained {
            return Ok(AuthorityEffectObservationV1::Applied(receipt));
        }
        Err(EffectFailure::Retryable(
            "durable authority effect requires authenticated restart observation".to_owned(),
        ))
    }

    fn apply_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        let method = prepared
            .broker_request()
            .map_err(|_| {
                EffectFailure::Permanent("durable authority effect is malformed".to_owned())
            })?
            .method();
        if method == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            && (self.pending_atomic_snapshot.is_some() || self.pending_snapshot_derivative.is_some())
        {
            return Err(EffectFailure::Retryable(
                "Storage session is reserved for an atomic snapshot".to_owned(),
            ));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| EffectFailure::Retryable("broker session lock is poisoned".to_owned()))?;
        apply_controller_authority_effect(&mut sessions, method, prepared)
    }
}

/// Samples the original paired clock DATA and checked effect deadline.
pub(in crate::controller_service) fn production_authority_effect_timing() -> Option<AuthorityEffectAttemptTimingV1> {
    let (host_boot_id, boottime_nanoseconds) = current_boot_and_boottime()?;
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let deadline = boottime_nanoseconds.checked_add(5_000_000_000)?;
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock").ok()?;
    let clock = RawPairedClockSample::new_untrusted(
        provenance,
        host_boot_id,
        realtime.tv_sec,
        boottime_nanoseconds,
    )
    .ok()?;
    Some(AuthorityEffectAttemptTimingV1::new(clock, deadline))
}

/// Reads the original realtime projection into bounded lifecycle DATA.
///
/// # Errors
///
/// Rejects the original negative or overflowing realtime projection.
pub(in crate::controller_service) fn current_lifecycle_time() -> Result<LifecycleTimeV1, EffectFailure> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let seconds = u64::try_from(realtime.tv_sec).map_err(|_| {
        EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
    })?;
    let nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u64::try_from(realtime.tv_nsec).ok()?))
        .ok_or_else(|| {
            EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
        })?;
    LifecycleTimeV1::new(nanoseconds).map_err(|_| {
        EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
    })
}

/// Samples the original boot identity around the bounded boot-time clock read.
pub(in crate::controller_service) fn current_boot_and_boottime() -> Option<([u8; 16], u64)> {
    let boot_before = KernelBootId::current().ok()?.into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let boot_after = KernelBootId::current().ok()?.into_bytes();
    if boot_before != boot_after {
        return None;
    }
    let boottime_nanoseconds = u64::try_from(boottime.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(boottime.tv_nsec).ok()?)?;

    Some((boot_before, boottime_nanoseconds))
}

fn apply_controller_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
    match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        _ => Err(EffectFailure::Permanent(
            "durable authority effect selected a non-Apply method".to_owned(),
        )),
    }
}

fn resume_controller_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
    let retained = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        _ => {
            return Err(EffectFailure::Permanent(
                "durable authority effect selected a non-Apply method".to_owned(),
            ));
        }
    };
    retained.transpose()
}

fn recover_controller_terminal_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
    match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        _ => Err(EffectFailure::Permanent(
            "durable authority effect selected a non-Apply method".to_owned(),
        )),
    }
}

/// Projects the original missing-session retryable refusal.
pub(in crate::controller_service) fn missing_broker_session() -> EffectFailure {
    EffectFailure::Retryable("authenticated broker session is unavailable".to_owned())
}
