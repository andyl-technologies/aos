//! Original protected mutation admission, cancellation and recovery recipes.
//!
//! The same executor retains pending Source commits and process provenance.
//! Request validation and recovery precede concrete effect dispatch at their
//! original frontiers; these helpers add no generic authority or currentness.

use super::*;

impl ProductionEffectExecutor {
    pub(super) fn public_mutation_context(
        &mut self,
        plan: &EffectPlan,
    ) -> Result<PublicMutationEffectV1, EffectFailure> {
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut self.source_domains)
            .and_then(|owner| owner.replay())
            .map_err(|error| {
                EffectFailure::Permanent(format!("protected source-domain replay failed: {error}"))
            })?;
        plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Permanent(
                    "controller effect lacks authenticated admission context".to_owned(),
                )
            })
    }

    pub(super) fn require_current_create_effect(
        &mut self,
        operation_id: OperationId,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1, EffectFailure>
    {
        // A generic lifecycle recovery must never become a Create receipt.
        if self.pending_source_commit.is_some() {
            return Err(EffectFailure::Retryable(
                "protected source commit recovery is pending".to_owned(),
            ));
        }
        let context = self.public_mutation_context(plan)?;
        if !matches!(
            context
                .validated_request()
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
            DormantSandboxRequestKindV1::Create(_)
        ) {
            return Err(EffectFailure::Permanent(
                "Create effect has the wrong admitted request".to_owned(),
            ));
        }
        require_current_parentless_create_source(
            operation_id,
            context.project(),
            self.request_scope,
            plan,
            journal,
        )
    }

    pub(super) fn cancellation_request(
        context: &PublicMutationEffectV1,
    ) -> Result<ProductionCancellationRequest, EffectFailure> {
        let DormantSandboxRequestKindV1::CancelOperation(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "controller cancellation effect has the wrong public method".to_owned(),
            ));
        };
        let target: [u8; 16] = request.operation_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent(
                "controller cancellation target identity is invalid".to_owned(),
            )
        })?;
        let mutation = request.mutation.as_option().ok_or_else(|| {
            EffectFailure::Permanent("controller cancellation has no mutation context".to_owned())
        })?;
        let accepted_seconds = u64::try_from(context.accepted_wall_seconds()).map_err(|_| {
            EffectFailure::Permanent("controller cancellation time is invalid".to_owned())
        })?;
        let accepted_nanoseconds =
            accepted_seconds.checked_mul(1_000_000_000).ok_or_else(|| {
                EffectFailure::Permanent("controller cancellation time overflows".to_owned())
            })?;

        Ok(ProductionCancellationRequest {
            target_operation: OperationId::from_bytes(target),
            idempotency: LifecycleCancelIdempotencyDigestV1::commit(&mutation.idempotency_key),
            requested_at: LifecycleTimeV1::new(accepted_nanoseconds).map_err(|_| {
                EffectFailure::Permanent("controller cancellation time is invalid".to_owned())
            })?,
        })
    }

    pub(super) fn cancellation_receipt(
        resolution: &LifecycleProtectedCancellationResolutionV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(b"AOSCAN01");
        bytes.extend_from_slice(resolution.receipt().as_bytes());
        EffectReceipt::new(bytes).map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    pub(super) fn ownership_recovery_receipt(
        recovery_operation: OperationId,
        context: &PublicMutationEffectV1,
        journal: &Journal,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let DormantSandboxRequestKindV1::OperatorRecover(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "operator recovery effect has the wrong request method".to_owned(),
            ));
        };
        if request.action.as_known() != Some(OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY)
        {
            return Ok(None);
        }
        let target_bytes: [u8; 16] = request.resource_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("operator recovery target is invalid".to_owned())
        })?;
        let target = OperationId::from_bytes(target_bytes);
        if public_operation_resource_from_journal_v1(journal, target)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_none()
        {
            return Ok(None);
        }
        let Some(publication_digest) =
            activated_ownership_gate_digest_from_journal_v1(journal, target)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Ok(None);
        };
        let receipt = [
            b"AOSORE01".as_slice(),
            recovery_operation.as_bytes(),
            target.as_bytes(),
            publication_digest.as_bytes(),
        ]
        .concat();
        EffectReceipt::new(receipt)
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    pub(super) fn terminal_public_operation_receipt(
        journal: &Journal,
        target: OperationId,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let operation = public_operation_resource_from_journal_v1(journal, target)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Permanent("controller cancellation target is unknown".to_owned())
            })?;
        if !matches!(
            operation.phase.as_known(),
            Some(
                OperationPhase::OPERATION_PHASE_SUCCEEDED
                    | OperationPhase::OPERATION_PHASE_FAILED_BEFORE_COMMIT
                    | OperationPhase::OPERATION_PHASE_CANCELED_BEFORE_COMMIT
                    | OperationPhase::OPERATION_PHASE_COMMITTED_WITH_RESIDUAL_CLEANUP
                    | OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED
            )
        ) {
            return Ok(None);
        }
        let receipt: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller.cancel-terminal-operation.v1\0")
            .chain_update(target.as_bytes())
            .chain_update((operation.resource_version.len() as u64).to_be_bytes())
            .chain_update(&operation.resource_version)
            .finalize()
            .into();
        EffectReceipt::new([b"AOSCAT01".as_slice(), receipt.as_slice()].concat())
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    pub(super) fn recover_pending_source_commit(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<EffectObservation>, EffectFailure> {
        let Some(pending) = self.pending_source_commit.take() else {
            return Ok(None);
        };
        if pending.operation_id != operation_id {
            self.pending_source_commit = Some(pending);
            return Err(EffectFailure::Retryable(
                "another protected source commit still requires recovery".to_owned(),
            ));
        }

        let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
            &mut self.source_domains,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        match owner
            .recover_effect_progress(pending.pending)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            LifecycleProgressRecoveryV1::Applied(_) => {
                Ok(pending.receipt.map(EffectObservation::Applied))
            }
            LifecycleProgressRecoveryV1::Retry(prepared) => {
                match owner
                    .commit_effect_progress(prepared)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                {
                    LifecycleProgressCommitOutcomeV1::Applied(_) => {
                        Ok(pending.receipt.map(EffectObservation::Applied))
                    }
                    LifecycleProgressCommitOutcomeV1::OutcomeUnknown {
                        pending: retained, ..
                    } => {
                        self.pending_source_commit = Some(PendingSourceCommit {
                            pending: retained,
                            ..pending
                        });
                        Err(EffectFailure::Retryable(
                            "protected cancellation durability is still unknown".to_owned(),
                        ))
                    }
                }
            }
            LifecycleProgressRecoveryV1::Diverged(retained) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    pending: retained,
                    ..pending
                });
                Err(EffectFailure::Permanent(
                    "protected cancellation commit diverged".to_owned(),
                ))
            }
        }
    }

    pub(super) fn settle_cancellation_admission(
        &mut self,
        operation_id: OperationId,
        admission: LifecycleProtectedCancellationAdmissionV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        match admission {
            LifecycleProtectedCancellationAdmissionV1::Existing(resolution) => {
                Self::cancellation_receipt(&resolution)
            }
            LifecycleProtectedCancellationAdmissionV1::Admitted { resolution, commit } => {
                let receipt = Self::cancellation_receipt(&resolution)?;
                match commit {
                    LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(receipt),
                    LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                        self.pending_source_commit = Some(PendingSourceCommit {
                            operation_id,
                            receipt: Some(receipt),
                            pending,
                        });
                        Err(EffectFailure::Retryable(
                            "protected cancellation durability is unknown".to_owned(),
                        ))
                    }
                }
            }
        }
    }

    pub(super) fn prepared_in_this_process(&self, prepared: &PreparedAuthorityEffectV1) -> bool {
        self.process_start
            .is_some_and(|(host_boot_id, started_at)| {
                prepared.preparation_host_boot_id() == host_boot_id
                    && prepared.preparation_boottime_nanoseconds() >= started_at
            })
    }

    pub(super) fn validate_lifecycle_admission(
        &self,
        operation: OperationId,
        context: &PublicMutationEffectV1,
        request: &DormantSandboxRequestKindV1,
        journal: &mut Journal,
    ) -> Result<LifecycleOperationV1, EffectFailure> {
        if !is_lifecycle_mutation(request) {
            return Err(EffectFailure::Permanent(
                "public mutation does not use lifecycle admission".to_owned(),
            ));
        }

        let admission = lifecycle_public_mutation_admission_v1(
            journal,
            operation,
            context.project(),
            self.node,
            request,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        lifecycle_operation_from_public_mutation_v1(
            operation,
            context.caller(),
            context.project(),
            context.accepted_wall_seconds(),
            context.canonical_request(),
            request,
            admission,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    pub(super) fn settle_lifecycle_admission(
        &mut self,
        operation_id: OperationId,
        admission: LifecycleOperationAdmissionV1,
    ) -> Result<(), EffectFailure> {
        match admission {
            LifecycleOperationAdmissionV1::Replay(_) => Ok(()),
            LifecycleOperationAdmissionV1::Admitted { outcome, .. } => match outcome {
                LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(()),
                LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                    self.pending_source_commit = Some(PendingSourceCommit {
                        operation_id,
                        receipt: None,
                        pending,
                    });
                    Err(EffectFailure::Retryable(
                        "protected lifecycle admission durability is unknown".to_owned(),
                    ))
                }
            },
        }
    }
}

fn require_current_parentless_create_source(
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    journal: &mut Journal,
) -> Result<aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1, EffectFailure> {
    aos_sandbox::policy_compiler::current_parentless_create_project_source_for_operation_v1(
        journal,
        operation,
        project,
        scope,
        effect_plan,
    )
    .map_err(|error| {
        EffectFailure::Retryable(format!("admitted Create source is not current: {error}"))
    })
}

pub(super) const fn is_lifecycle_mutation(request: &DormantSandboxRequestKindV1) -> bool {
    use DormantSandboxRequestKindV1 as Request;

    matches!(
        request,
        Request::Create(_)
            | Request::UpdatePolicy(_)
            | Request::Start(_)
            | Request::Stop(_)
            | Request::Suspend(_)
            | Request::Resume(_)
            | Request::Delete(_)
            | Request::Exec(_)
            | Request::CancelExec(_)
            | Request::ViewCreate(_)
            | Request::ViewAttach(_)
            | Request::ViewReplace(_)
            | Request::ViewDetach(_)
            | Request::ViewRelease(_)
            | Request::Snapshot(_)
            | Request::Restore(_)
            | Request::Fork(_)
            | Request::DeleteSnapshot(_)
    )
}
