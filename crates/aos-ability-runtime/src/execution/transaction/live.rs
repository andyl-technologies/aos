//! Live ownership of checked plans, journals, and replay state.

use super::*;

impl<'plan> ExecutionTransaction<'plan> {
    /// Opens and validates the complete journal against one checked plan.
    ///
    /// An empty journal is initialized with the exact plan, retained artifact
    /// closures, and the aggregate finite recovery budget before this function
    /// returns. Existing records are checked in one pass against every plan
    /// operation, decision, branch, and merge identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is not executable, its aggregate budget
    /// overflows, the journal is unavailable
    /// or corrupt, or a digest-valid record violates the checked plan or finite
    /// state machines.
    pub fn open<RootStore>(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        path: impl AsRef<Path>,
        limits: JournalLimits,
        root_store: &mut RootStore,
    ) -> Result<Self, TransactionError>
    where
        RootStore: TrustedRootStore + TrustedPlanStore,
    {
        if !plan.is_executable() {
            return Err(TransactionError::PlanNotExecutable);
        }
        let total_recovery_millis = aggregate_recovery_budget(plan)?;
        let runtime_artifacts = required_runtime_artifacts(plan);
        let retained_roots = retained_roots(&runtime_artifacts);
        let plan_retention = root_store
            .retain_plan(&transaction, plan)
            .map_err(|source| TransactionError::PlanRetention(anyhow::Error::new(source)))?;
        if plan_retention.transaction() != &transaction || plan_retention.plan() != plan.id() {
            return Err(invalid(
                1,
                "plan-store receipt does not match the transaction and checked plan",
            ));
        }
        let opened: JournalOpenResult<ExecutionEvent> = FileJournal::open(path, limits)?;
        let mut replay = ReplayState::new(
            plan,
            transaction.clone(),
            plan_retention.bundle(),
            retained_roots.clone(),
            total_recovery_millis,
        );

        for record in opened.recovery.records() {
            replay.apply(plan, record.sequence(), record.body().body())?;
        }

        let retention = root_store
            .retain(&transaction, &runtime_artifacts)
            .map_err(|source| TransactionError::RootRetention(anyhow::Error::new(source)))?;
        if retention.transaction() != &transaction || retention.roots() != retained_roots {
            return Err(invalid(
                replay.next_sequence,
                "root-store receipt does not match the transaction and checked artifacts",
            ));
        }

        let mut execution = Self {
            plan,
            journal: opened.journal,
            replay,
            retention,
            plan_retention,
            session: Arc::new(()),
            live_reservations: Arc::new(Mutex::new(BTreeSet::new())),
        };
        if execution.replay.next_sequence == 1 {
            execution.append(ExecutionEventKind::TransactionPlanned {
                transaction,
                plan: plan.id(),
                plan_bundle: execution.plan_retention.bundle(),
                retained_roots,
                total_recovery_millis,
            })?;
        } else if !execution.replay.planned {
            return Err(invalid(1, "first record is not the transaction plan root"));
        }

        Ok(execution)
    }

    /// Returns the exact checked plan bound to this journal writer.
    #[must_use]
    pub const fn plan(&self) -> &'plan CheckedEffectPlan {
        self.plan
    }

    /// Returns the durable execution allocation identity.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.replay.transaction
    }

    /// Returns the trusted receipt that gates admission for this open process.
    #[must_use]
    pub const fn retention(&self) -> &RootRetentionReceipt {
        &self.retention
    }

    /// Returns the trusted receipt proving the complete checked plan is reloadable.
    #[must_use]
    pub const fn plan_retention(&self) -> &PlanRetentionReceipt {
        &self.plan_retention
    }

    pub(crate) const fn session(&self) -> &Arc<()> {
        &self.session
    }

    /// Returns the conservative sum of persisted operation recovery time.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.replay.elapsed_millis
    }

    /// Returns the aggregate finite recovery budget rooted in the journal.
    #[must_use]
    pub const fn total_recovery_millis(&self) -> u64 {
        self.replay.total_recovery_millis
    }

    /// Returns replay state for one exact checked operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is absent from the checked plan.
    pub fn history(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<&OperationHistory, TransactionError> {
        self.replay
            .operations
            .get(operation)
            .ok_or(TransactionError::OperationMissing)
    }

    /// Selects the checked next action for one operation's durable state.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation or its checked outcome descriptor is
    /// unavailable from this exact plan.
    pub fn next_action(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<crate::execution::RecoveryAction, TransactionError> {
        let blocked = durably_blocked_operations(self.plan, &self.replay);
        self.next_action_with_blocked(operation, &blocked)
    }

    /// Durably requests explicit compensation of one completed operation.
    ///
    /// This preserves the original completion record separately while making
    /// its outputs unavailable to future graph consumers immediately.
    ///
    /// # Errors
    ///
    /// Returns an error unless the transaction remains nonterminal and the
    /// operation declares compensation, completed successfully, released its
    /// original resources, has no prior request, and has no progressed
    /// transitive consumer of its successful result.
    pub fn request_compensation(
        &mut self,
        operation: &ScopedOperationKey,
        reason: aos_ability_model::AbilityValue,
    ) -> Result<(), TransactionError> {
        if self.summary().terminal().is_some() {
            return Err(TransactionError::CompensationAfterTerminal);
        }
        let checked = self
            .plan
            .operation(operation)
            .ok_or(TransactionError::OperationMissing)?;
        if checked.recovery.compensate.is_none() {
            return Err(TransactionError::CompensationMissing);
        }
        let history = self.history(operation)?;
        if history.original_completion().is_none()
            || !history.resources_released()
            || history.compensation_state().is_some()
        {
            return Err(TransactionError::CompensationNotEligible);
        }
        if compensation_dependent_has_progressed(self.plan, &self.replay, operation) {
            return Err(TransactionError::CompensationDependentProgressed);
        }
        self.append(ExecutionEventKind::CompensationRequested {
            transaction: self.transaction().clone(),
            operation: history.operation_id().clone(),
            reason,
            elapsed_millis: history.elapsed_millis(),
        })
    }

    pub(crate) fn next_action_with_blocked(
        &self,
        operation: &ScopedOperationKey,
        blocked: &BTreeSet<ScopedOperationKey>,
    ) -> Result<crate::execution::RecoveryAction, TransactionError> {
        let checked = self
            .plan
            .operation(operation)
            .ok_or(TransactionError::OperationMissing)?;
        let history = self.history(operation)?;
        let action = history.recovery_action(
            &checked.recovery.retry,
            checked.deadline.total_recovery_millis.get(),
        );
        if action == crate::execution::RecoveryAction::Admit && blocked.contains(operation) {
            return Ok(crate::execution::RecoveryAction::SettleFailureBeforeEffect);
        }
        if matches!(
            action,
            crate::execution::RecoveryAction::ReconcileBeforeRetry { .. }
        ) {
            let semantics = self
                .plan
                .operation_outcome_semantics(checked)
                .map_err(|source| TransactionError::Scheduling {
                    reason: format!("operation outcome semantics are unavailable: {source}"),
                })?;
            if semantics.indeterminate
                == aos_ability_model::IndeterminateSemantics::InterventionRequired
            {
                return Ok(crate::execution::RecoveryAction::InterventionRequired);
            }
        }
        if action == crate::execution::RecoveryAction::ReconcileCompensation {
            let Some(compensate) = checked.recovery.compensate.as_ref() else {
                return Ok(crate::execution::RecoveryAction::CompensationInterventionRequired);
            };
            let semantics = self
                .plan
                .method_outcome_semantics(checked, compensate)
                .map_err(|source| TransactionError::Scheduling {
                    reason: format!("compensation outcome semantics are unavailable: {source}"),
                })?;
            if checked.recovery.reconcile.is_none()
                || semantics.indeterminate
                    == aos_ability_model::IndeterminateSemantics::InterventionRequired
            {
                return Ok(crate::execution::RecoveryAction::CompensationInterventionRequired);
            }
        }
        Ok(action)
    }

    pub(crate) fn merged_output(
        &self,
        merge: &ScopedOperationKey,
        output: &LocalKey,
    ) -> Option<&aos_ability_model::AbilityValue> {
        self.replay
            .merged
            .get(merge)
            .and_then(|merged| merged.outputs.get(output))
    }

    pub(crate) fn selected_branch(&self, decision: &ScopedOperationKey) -> Option<&LocalKey> {
        self.replay.selections.get(decision)
    }

    pub(crate) fn operation_is_skipped(&self, operation: &ScopedOperationKey) -> bool {
        self.replay.skipped.contains(operation)
    }

    pub(crate) fn operation_histories(&self) -> impl Iterator<Item = &OperationHistory> {
        self.replay.operations.values()
    }

    /// Returns operations for which at least one attempt recorded durable effect intent.
    pub fn operations_reaching_effect_intent(
        &self,
    ) -> impl Iterator<Item = &aos_ability_model::OperationId> {
        self.replay
            .operations
            .values()
            .filter(|history| history.effect_intent_recorded())
            .map(OperationHistory::operation_id)
    }

    /// Returns every exact operation attempt with durable effect intent.
    pub fn effect_intent_attempts(
        &self,
    ) -> impl Iterator<Item = (aos_ability_model::OperationId, std::num::NonZeroU32)> + '_ {
        self.replay.operations.values().flat_map(|history| {
            history
                .effect_intent_attempts()
                .iter()
                .copied()
                .map(|attempt| (history.operation_id().clone(), attempt))
        })
    }

    /// Returns clean pre-intent claim attempts authorized by checked replay.
    pub fn clean_claim_attempts(
        &self,
    ) -> impl Iterator<Item = (aos_ability_model::OperationId, std::num::NonZeroU32)> + '_ {
        self.replay.operations.values().flat_map(|history| {
            let operation = history.operation_id().clone();
            history
                .clean_claim_attempts()
                .into_iter()
                .map(move |attempt| (operation.clone(), attempt))
        })
    }

    pub(crate) fn durably_blocked_operations(&self) -> BTreeSet<ScopedOperationKey> {
        durably_blocked_operations(self.plan, &self.replay)
    }

    pub(crate) fn merge_is_complete(&self, merge: &ScopedOperationKey) -> bool {
        self.replay.merged.contains_key(merge)
    }

    pub(crate) fn branch_is_active(&self, context: &[aos_ability_model::BranchMembership]) -> bool {
        branch_context_selected(context, &self.replay.selections)
    }

    pub(crate) fn node_is_ready(&self, node: &PlanNodeKey) -> bool {
        ensure_node_predecessors(self.plan, &self.replay, node, self.replay.next_sequence).is_ok()
    }

    pub(crate) fn selected_decision_alternative(
        &self,
        decision: &DecisionNode,
    ) -> Result<LocalKey, TransactionError> {
        selected_alternative(self.plan, &self.replay, decision, self.replay.next_sequence)
    }

    pub(crate) fn result_value(
        &self,
        reference: &aos_ability_model::OperationResultReference,
    ) -> Result<&serde_json::Value, TransactionError> {
        resolve_result_json(&self.replay, reference, self.replay.next_sequence)
    }

    /// Resolves the checked readiness output for an operation using a planned provider.
    ///
    /// The returned assignment is derived only from a durably completed
    /// readiness producer and is revalidated against the exact planned
    /// binding. Operations using an already available provider return `None`.
    ///
    /// # Errors
    ///
    /// Returns an error when `operation` is foreign, readiness has not
    /// completed, its typed output is missing, or the assignment names another
    /// provider, interface, or implementation.
    pub fn provider_assignment_for(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<Option<aos_ability_model::ProviderAssignment>, TransactionError> {
        let operation = self
            .plan
            .operation(operation)
            .ok_or(TransactionError::OperationMissing)?;
        let Some(readiness) = self.plan.provider_readiness(&operation.binding) else {
            return Ok(None);
        };
        let reference = aos_ability_model::OperationResultReference {
            producer: ResultProducerKey::Operation {
                key: readiness.producer.clone(),
            },
            output: readiness.output.clone(),
        };
        let value = resolve_result_json(&self.replay, &reference, self.replay.next_sequence)?;
        let value = aos_ability_model::AbilityValue::new(value.clone()).map_err(|source| {
            invalid(
                self.replay.next_sequence,
                format!("provider readiness value is not bounded: {source}"),
            )
        })?;
        self.plan
            .validate_provider_assignment(readiness, &value)
            .map(Some)
            .map_err(|source| {
                invalid(
                    self.replay.next_sequence,
                    format!("provider readiness does not match the planned binding: {source}"),
                )
            })
    }

    pub(crate) fn check_operation_ready(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<(), TransactionError> {
        self.provider_assignment_for(operation)?;
        ensure_operation_ready(
            self.plan,
            &self.replay,
            operation,
            self.replay.next_sequence,
        )
    }

    pub(crate) fn claim_live_reservation(
        &self,
        operation: ScopedOperationKey,
        attempt: std::num::NonZeroU32,
    ) -> Result<LiveReservationGuard, TransactionError> {
        let key = (operation, attempt);
        let mut live = self
            .live_reservations
            .lock()
            .map_err(|_| TransactionError::LiveRegistryPoisoned)?;
        if !live.insert(key.clone()) {
            return Err(TransactionError::OperationAlreadyLive);
        }
        drop(live);

        Ok(LiveReservationGuard {
            key,
            registry: Arc::clone(&self.live_reservations),
            remove_on_drop: true,
        })
    }

    pub(crate) fn append(&mut self, event: ExecutionEventKind) -> Result<(), TransactionError> {
        let sequence = self.replay.next_sequence;
        self.replay.validate(self.plan, sequence, &event)?;

        let event = ExecutionEvent::new(event);
        let record = self.journal.append(&event)?;
        if record.sequence() != sequence {
            return Err(invalid(
                sequence,
                "journal sequence diverged from transaction replay",
            ));
        }
        self.replay.commit(self.plan, sequence, event.body())?;
        Ok(())
    }

    pub(crate) fn record_compensation_intervention(
        &mut self,
        operation: &ScopedOperationKey,
        reason: CompensationInterventionReason,
        elapsed_millis: u64,
    ) -> Result<(), TransactionError> {
        let history = self.history(operation)?;
        self.append(ExecutionEventKind::CompensationInterventionRequired {
            transaction: self.transaction().clone(),
            operation: history.operation_id().clone(),
            reason,
            elapsed_millis: elapsed_millis.max(history.elapsed_millis()),
        })
    }

    pub(crate) fn record_operation_intervention(
        &mut self,
        operation: &ScopedOperationKey,
        reason: OperationInterventionReason,
        elapsed_millis: u64,
    ) -> Result<(), TransactionError> {
        let history = self.history(operation)?;
        let attempt = history.current_attempt().ok_or_else(|| {
            invalid(
                self.replay.next_sequence,
                "operation intervention requires an admitted attempt",
            )
        })?;
        self.append(ExecutionEventKind::OperationInterventionRequired {
            transaction: self.transaction().clone(),
            operation: history.operation_id().clone(),
            attempt,
            reason,
            elapsed_millis: elapsed_millis.max(history.elapsed_millis()),
        })
    }

    pub(crate) fn ensure_journal_capacity(
        &mut self,
        additional_records: usize,
    ) -> Result<(), TransactionError> {
        self.journal.ensure_capacity(additional_records)?;
        Ok(())
    }
}
