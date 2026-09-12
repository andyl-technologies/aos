//! Observed native consumer verification and exact journal provenance checks.

use super::*;

impl NativeInventoryState {
    pub(in crate::config_eval::ability_store::inventory) fn validate_current_journal_plans(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        for owner in &ledger.owners {
            self.classify_current_journal(
                &owner.generation,
                &owner.transaction,
                owner.plan,
                "provider owner",
            )?;
            if let Some(establishment) = &owner.established_by {
                self.classify_current_journal(
                    &establishment.generation,
                    &establishment.transaction,
                    establishment.plan,
                    "provider owner establishment",
                )?;
            }
            for claim in &owner.claim_by {
                self.classify_current_journal(
                    &claim.generation,
                    &claim.transaction,
                    claim.plan,
                    "provider owner claim",
                )?;
            }
            if let Some(receipt) = &owner.adoption {
                self.classify_current_journal(
                    &receipt.source_generation,
                    &receipt.source_transaction,
                    receipt.source_plan,
                    "adoption receipt source",
                )?;
                self.classify_current_journal(
                    &receipt.source_establishment.generation,
                    &receipt.source_establishment.transaction,
                    receipt.source_establishment.plan,
                    "adoption receipt source establishment",
                )?;
                if let Some(verification) = &receipt.linked_verification {
                    self.classify_current_journal(
                        &verification.generation,
                        &verification.transaction,
                        verification.plan,
                        "linked adoption verification",
                    )?;
                }
            }
        }
        for consumer in &ledger.consumers {
            let current = self.classify_current_journal(
                &consumer.generation,
                &consumer.transaction,
                consumer.plan,
                "consumer",
            )?;
            if current && consumer.operation.plan != self.plan {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current native consumer operation names a different checked plan".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(in crate::config_eval::ability_store) fn preflight_observed_current_owners(
        &self,
    ) -> Result<(), GenerationAbilityStoreError> {
        let ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        for owner in &ledger.owners {
            self.validate_retained_owner_provenance(owner)?;
        }
        self.require_current_owner_rows(&ledger, &self.desired_owner_selections)?;
        self.require_current_owner_rows(&ledger, &self.current_owner_selections)?;
        self.authenticate_retained_consumers_before_effects(&ledger)
    }

    pub(in crate::config_eval::ability_store) fn verify_observed_current_consumers(
        &self,
        observations: &[NativeNoOpResourceObservation],
        consumer_backed_resources: &BTreeSet<ResourceId>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        self.authenticate_retained_consumers_before_effects(&ledger)?;
        self.verify_observed_current_consumers_in_ledger(
            &ledger,
            observations,
            consumer_backed_resources,
            |consumer, owner_handler| self.consumer_operation_succeeded(consumer, owner_handler),
        )
    }

    #[cfg(test)]
    pub(in crate::config_eval::ability_store::inventory) fn verify_observed_current_consumers_with_status(
        &self,
        observations: &[NativeNoOpResourceObservation],
        consumer_backed_resources: &BTreeSet<ResourceId>,
        consumer_operation_succeeded: impl FnMut(
            &ActiveNativeConsumer,
            Option<&NativeProviderHandlerIdentity>,
        ) -> Result<bool, GenerationAbilityStoreError>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        self.verify_observed_current_consumers_in_ledger(
            &ledger,
            observations,
            consumer_backed_resources,
            consumer_operation_succeeded,
        )
    }

    fn verify_observed_current_consumers_in_ledger(
        &self,
        ledger: &NativeResourceLedger,
        observations: &[NativeNoOpResourceObservation],
        consumer_backed_resources: &BTreeSet<ResourceId>,
        mut consumer_operation_succeeded: impl FnMut(
            &ActiveNativeConsumer,
            Option<&NativeProviderHandlerIdentity>,
        )
            -> Result<bool, GenerationAbilityStoreError>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let mut observed_resources = BTreeSet::new();
        for observation in observations {
            if !observed_resources.insert(observation.qualified.logical.clone()) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "fresh native observations contain a duplicate logical resource".to_string(),
                ));
            }

            let consumers = ledger
                .consumers
                .iter()
                .filter(|consumer| consumer.logical == observation.qualified.logical)
                .collect::<Vec<_>>();
            let consumer_backed =
                consumer_backed_resources.contains(&observation.qualified.logical);
            if !consumer_backed {
                if !consumers.is_empty() {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "fresh resource-only observation retained an active consumer".to_string(),
                    ));
                }
                continue;
            }

            let expected_revision = match observation.state {
                aos_ability_plan::RuntimeResourceState::Present { revision, .. } => Some(revision),
                aos_ability_plan::RuntimeResourceState::Absent => None,
            };
            for consumer in &consumers {
                if consumer.physical != observation.qualified.physical
                    || expected_revision.is_some() && consumer.desired_revision != expected_revision
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "fresh native consumer differs from its physical resource or revision"
                            .to_string(),
                    ));
                }
            }

            let requires_active_consumer = matches!(
                observation.state,
                aos_ability_plan::RuntimeResourceState::Present {
                    health: aos_ability_plan::RuntimeResourceHealth::Healthy
                        | aos_ability_plan::RuntimeResourceHealth::Divergent,
                    ..
                }
            );
            if !requires_active_consumer {
                if consumers.len() > 1
                    && !self.has_exact_linked_candidate_consumer_ambiguity(
                        &ledger,
                        &consumers,
                        &mut consumer_operation_succeeded,
                    )?
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "stopped or absent native resource has ambiguous active consumers"
                            .to_string(),
                    ));
                }
                continue;
            }

            let mut successful = Vec::new();
            let mut current_candidates = Vec::new();
            for consumer in &consumers {
                let owner_handler =
                    super::super::retained_consumer_owner_handler(&ledger, consumer)?;
                if self.is_current_consumer(consumer) {
                    current_candidates.push(*consumer);
                } else if consumer_operation_succeeded(consumer, owner_handler)? {
                    successful.push(*consumer);
                }
            }
            let [active] = successful.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "healthy or divergent native resource lacks one exact authenticated active consumer"
                        .to_string(),
                ));
            };
            match current_candidates.as_slice() {
                [] if consumers.len() == 1 => {}
                [candidate]
                    if consumers.len() == 2
                        && self.is_exact_linked_candidate_consumer(&ledger, active, candidate) => {}
                _ => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "healthy or divergent native resource has ambiguous active consumers"
                            .to_string(),
                    ));
                }
            }
        }

        if ledger
            .consumers
            .iter()
            .any(|consumer| !observed_resources.contains(&consumer.logical))
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native ledger has an active consumer outside the fresh observation union"
                    .to_string(),
            ));
        }
        for owner in &ledger.owners {
            let observations = observations
                .iter()
                .filter(|observation| observation.qualified.logical == owner.resource)
                .collect::<Vec<_>>();
            let [observation] = observations.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native owner is absent or ambiguous in the fresh observation union"
                        .to_string(),
                ));
            };
            if owner.physical != observation.qualified.physical {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native owner differs from its freshly classified physical resource"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn has_exact_linked_candidate_consumer_ambiguity(
        &self,
        ledger: &NativeResourceLedger,
        consumers: &[&ActiveNativeConsumer],
        consumer_operation_succeeded: &mut impl FnMut(
            &ActiveNativeConsumer,
            Option<&NativeProviderHandlerIdentity>,
        )
            -> Result<bool, GenerationAbilityStoreError>,
    ) -> Result<bool, GenerationAbilityStoreError> {
        if consumers.len() != 2 {
            return Ok(false);
        }
        for (source, candidate) in [(consumers[0], consumers[1]), (consumers[1], consumers[0])] {
            if !self.is_current_consumer(candidate)
                || !self.is_exact_linked_candidate_consumer(ledger, source, candidate)
            {
                continue;
            }
            let source_handler = super::super::retained_consumer_owner_handler(ledger, source)?;
            if consumer_operation_succeeded(source, source_handler)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_exact_linked_candidate_consumer(
        &self,
        ledger: &NativeResourceLedger,
        source: &ActiveNativeConsumer,
        candidate: &ActiveNativeConsumer,
    ) -> bool {
        if !self.is_current_consumer(candidate)
            || source.logical != candidate.logical
            || source.physical != candidate.physical
            || source.desired_revision != candidate.desired_revision
        {
            return false;
        }
        let Some(owner) = ledger
            .owners
            .iter()
            .find(|owner| owner.resource == source.logical)
        else {
            return false;
        };
        owner.adoption.as_ref().is_some_and(|receipt| {
            source.owner.as_ref() == Some(&receipt.source)
                && candidate.owner.as_ref() == Some(&owner.identity)
                && owner.claim_by.iter().any(|claim| {
                    claim.generation == candidate.generation
                        && claim.transaction == candidate.transaction
                        && claim.plan == candidate.plan
                        && claim.operation == candidate.operation
                        && claim.attempt == candidate.attempt
                        && claim.artifacts == candidate.artifacts
                })
        })
    }

    pub(in crate::config_eval::ability_store) fn verify_linked_adoption_no_op_with_consumer_status(
        &self,
        reconciliation: &aos_ability_plan::TransitionReconciliation,
        observations: &[NativeNoOpResourceObservation],
        changed_resources: &BTreeSet<ResourceId>,
        settle: bool,
        mut consumer_operation_succeeded: impl FnMut(
            &ActiveNativeConsumer,
            Option<&NativeProviderHandlerIdentity>,
        )
            -> Result<bool, GenerationAbilityStoreError>,
    ) -> Result<(), GenerationAbilityStoreError> {
        if reconciliation.unsettled_provider_adoptions.is_empty() {
            return Err(GenerationAbilityStoreError::Conflict(
                "linked adoption settlement has no unsettled receipt resources".to_string(),
            ));
        }
        let mut ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        let linked_resources = reconciliation
            .unsettled_provider_adoptions
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let pending_whole_union_verification = linked_resources.iter().all(|resource| {
            ledger.owners.iter().any(|owner| {
                owner.resource == *resource
                    && owner.adoption.as_ref().is_some_and(|receipt| {
                        receipt.consumer_requirement.is_none()
                            && receipt.linked_verification.is_none()
                    })
            })
        });
        let verification_resources = reconciliation
            .observations
            .iter()
            .filter(|observation| {
                pending_whole_union_verification
                    || linked_resources.contains(&observation.resource)
                    || !changed_resources.contains(&observation.resource)
            })
            .map(|observation| observation.resource.clone())
            .collect::<BTreeSet<_>>();
        let mut authenticated_consumers = Vec::new();
        for consumer in ledger
            .consumers
            .iter()
            .filter(|consumer| verification_resources.contains(&consumer.logical))
        {
            let owner_handler = super::super::retained_consumer_owner_handler(&ledger, consumer)?;
            let succeeded = consumer_operation_succeeded(consumer, owner_handler)?;
            if !succeeded && !self.is_current_consumer(consumer) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption retained consumer lacks exact successful provenance"
                        .to_string(),
                ));
            }
            authenticated_consumers.push((consumer, succeeded));
        }
        for resource in &verification_resources {
            let historical = authenticated_consumers
                .iter()
                .filter(|(consumer, succeeded)| {
                    *succeeded
                        && consumer.logical == *resource
                        && !self.is_current_consumer(consumer)
                })
                .count();
            if historical > 1 {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption resource has duplicate historical consumers".to_string(),
                ));
            }
        }

        let mut verification_consumers = Vec::new();
        for (consumer, succeeded) in &authenticated_consumers {
            if !*succeeded {
                continue;
            }
            let observation = observations
                .iter()
                .find(|observation| observation.qualified.logical == consumer.logical)
                .ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(
                        "linked adoption retained consumer lacks a fresh observation".to_string(),
                    )
                })?;
            let stopped_or_absent = matches!(
                observation.state,
                aos_ability_plan::RuntimeResourceState::Absent
                    | aos_ability_plan::RuntimeResourceState::Present {
                        health: aos_ability_plan::RuntimeResourceHealth::Stopped,
                        ..
                    }
            );
            let has_checked_repair = self.has_checked_consumer_repair(
                &ledger,
                consumer,
                super::super::retained_consumer_owner_handler(&ledger, consumer)?,
            );
            if !settle && stopped_or_absent && has_checked_repair {
                continue;
            }

            let current_candidate_succeeded =
                authenticated_consumers
                    .iter()
                    .any(|(candidate, candidate_succeeded)| {
                        *candidate_succeeded
                            && self.is_current_consumer(candidate)
                            && candidate.logical == consumer.logical
                            && ledger
                                .owners
                                .iter()
                                .find(|owner| owner.resource == consumer.logical)
                                .is_some_and(|owner| {
                                    candidate.owner.as_ref() == Some(&owner.identity)
                                })
                    });
            let source_consumer_after_recovery = (settle || current_candidate_succeeded)
                && ledger
                    .owners
                    .iter()
                    .find(|owner| owner.resource == consumer.logical)
                    .and_then(|owner| owner.adoption.as_ref())
                    .is_some_and(|receipt| consumer.owner.as_ref() == Some(&receipt.source));
            if source_consumer_after_recovery {
                continue;
            }
            verification_consumers.push((*consumer).clone());
        }
        let verification_ledger = NativeResourceLedger {
            schema: ledger.schema.clone(),
            owners: ledger
                .owners
                .iter()
                .filter(|owner| verification_resources.contains(&owner.resource))
                .cloned()
                .collect(),
            consumers: verification_consumers,
        };
        let verification_observations = observations
            .iter()
            .filter(|observation| verification_resources.contains(&observation.qualified.logical))
            .cloned()
            .collect::<Vec<_>>();
        let expected_verification = self.linked_adoption_verification(reconciliation)?;
        super::super::verify_retained_native_consumers_with_status(
            &verification_ledger,
            &verification_observations,
            &mut consumer_operation_succeeded,
        )?;
        let mut verified_requirements = BTreeMap::new();
        for resource in &reconciliation.unsettled_provider_adoptions {
            let matching_owners = ledger
                .owners
                .iter()
                .filter(|owner| owner.resource == *resource && owner.adoption.is_some())
                .collect::<Vec<_>>();
            let [owner] = matching_owners.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement lacks one exact unsettled owner".to_string(),
                ));
            };
            let matching_selections = self
                .desired_owner_selections
                .iter()
                .filter(|selection| {
                    selection.resource == *resource
                        && selection.identity == owner.identity
                        && selection.handler == owner.handler
                })
                .collect::<Vec<_>>();
            let [_selection] = matching_selections.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement differs from its selected owner endpoint"
                        .to_string(),
                ));
            };
            let fresh = observations
                .iter()
                .find(|observation| observation.qualified.logical == *resource)
                .ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(
                        "linked adoption settlement lacks a fresh resource observation".to_string(),
                    )
                })?;
            if owner.physical != fresh.qualified.physical {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement physical resource changed after classification"
                        .to_string(),
                ));
            }
            if !settle {
                continue;
            }
            let desired_revision = self.desired_revisions.get(resource).ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement resource is absent from desired state".to_string(),
                )
            })?;
            if fresh.state
                != (aos_ability_plan::RuntimeResourceState::Present {
                    revision: *desired_revision,
                    health: aos_ability_plan::RuntimeResourceHealth::Healthy,
                })
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement resource is not healthy at the desired revision"
                        .to_string(),
                ));
            }
            let resource_consumers = verification_ledger
                .consumers
                .iter()
                .filter(|consumer| consumer.logical == *resource)
                .collect::<Vec<_>>();
            if fresh.consumer_requirement == NativeConsumerRequirement::Required {
                let [consumer] = resource_consumers.as_slice() else {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "linked adoption settlement lacks one exact successful active consumer"
                            .to_string(),
                    ));
                };
                if consumer.physical != fresh.qualified.physical
                    || consumer.consumer != resource.provider
                    || consumer.owner.as_ref() != Some(&owner.identity)
                    || consumer.desired_revision != Some(*desired_revision)
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "linked adoption settlement consumer differs from its exact successful live evidence"
                            .to_string(),
                    ));
                }
            } else if !resource_consumers.is_empty() {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption settlement resource-only route has retained active consumers"
                        .to_string(),
                ));
            }
            // Resource-only adapters prove their complete live subject through
            // the catalog observation itself. PostgreSQL's healthy observation
            // additionally scans and pins the global slot process group, exact
            // executable, data directory, configuration, and application role,
            // so an old source executable cannot remain hidden behind the state file.
            verified_requirements.insert(resource.clone(), fresh.consumer_requirement);
        }
        let mut changed = false;
        for owner in &mut ledger.owners {
            if !linked_resources.contains(&owner.resource) {
                continue;
            }
            let requirement = verified_requirements.get(&owner.resource);
            let receipt = owner.adoption.as_mut().ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "verified linked owner lost its unsettled adoption receipt".to_string(),
                )
            })?;
            match (&receipt.consumer_requirement, &receipt.linked_verification) {
                (None, None) => {}
                (Some(recorded), Some(verification))
                    if requirement.is_none_or(|requirement| recorded == requirement)
                        && verification == &expected_verification =>
                {
                    if requirement.is_none() {
                        continue;
                    }
                }
                (None, Some(verification)) if verification == &expected_verification => {
                    if requirement.is_none() {
                        continue;
                    }
                }
                _ => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "verified linked owner retained a mismatched recovery witness".to_string(),
                    ));
                }
            }
            if let Some(requirement) = requirement {
                receipt.consumer_requirement = Some(*requirement);
            }
            if receipt.linked_verification.as_ref() != Some(&expected_verification) {
                receipt.linked_verification = Some(expected_verification.clone());
            }
            changed = true;
        }
        if changed {
            canonicalize_native_ledger(&mut ledger)?;
            save_native_resource_ledger(&self.ledger_path, &ledger)?;
        }
        Ok(())
    }

    pub(in crate::config_eval::ability_store) fn consumer_operation_succeeded(
        &self,
        consumer: &ActiveNativeConsumer,
        owner_handler: Option<&NativeProviderHandlerIdentity>,
    ) -> Result<bool, GenerationAbilityStoreError> {
        if self.classify_current_journal(
            &consumer.generation,
            &consumer.transaction,
            consumer.plan,
            "consumer",
        )? {
            self.validate_current_consumer(consumer, owner_handler)?;
            return self
                .replayed_current_successes
                .lock()
                .map_err(|_| {
                    GenerationAbilityStoreError::Conflict(
                        "current native success replay set is unavailable".to_string(),
                    )
                })
                .map(|successful| {
                    successful.contains(&(consumer.operation.clone(), consumer.attempt))
                });
        }
        let profile = self.ledger_path.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource ledger has no profile parent".to_string(),
            )
        })?;
        let terminal = exact_terminal_result(
            &self.ledger_path,
            &consumer.generation,
            &consumer.transaction,
            consumer.plan,
        )?
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "linked adoption consumer has no exact terminal transaction evidence".to_string(),
            )
        })?;
        let retained = super::super::super::RetainedAbilityDiagnosticSource::load_from_profile(
            profile.join(&consumer.generation),
            &consumer.transaction,
            self.supported_features.clone(),
            profile,
        )?;
        super::super::validate_retained_native_consumer_claim(
            consumer,
            retained.plan(),
            retained.provider_adoptions(),
            owner_handler,
        )?;
        retained.operation_succeeded(
            aos_ability_runtime::journal::JournalLimits::default(),
            &consumer.operation,
            consumer.attempt,
            terminal,
        )
    }

    pub(in crate::config_eval::ability_store) fn current_consumer_operation_succeeded(
        &self,
        consumer: &ActiveNativeConsumer,
        owner_handler: Option<&NativeProviderHandlerIdentity>,
        successful_operations: &BTreeMap<aos_ability_model::ScopedOperationKey, u32>,
    ) -> Result<bool, GenerationAbilityStoreError> {
        self.classify_current_journal(
            &consumer.generation,
            &consumer.transaction,
            consumer.plan,
            "consumer",
        )?
        .then_some(())
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native consumer does not belong to the current journal".to_string(),
            )
        })?;
        self.validate_current_consumer(consumer, owner_handler)?;

        Ok(successful_operations
            .get(&consumer.operation.operation)
            .is_some_and(|attempt| *attempt == consumer.attempt))
    }

    fn validate_current_consumer(
        &self,
        consumer: &ActiveNativeConsumer,
        owner_handler: Option<&NativeProviderHandlerIdentity>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let operation = self
            .operations
            .get(&consumer.operation.operation)
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "current native consumer operation is absent".to_string(),
                )
            })?;
        if consumer.generation != self.generation
            || consumer.transaction != self.transaction
            || consumer.plan != self.plan
            || consumer.operation.plan != self.plan
            || consumer.binding != operation.binding
            || consumer.consumer != operation.consumer
            || consumer.provider != operation.provider
            || consumer.logical != operation.operation.target.resource
            || consumer.owner != operation.owner
            || owner_handler != operation.owner_handler.as_ref()
            || consumer.desired_revision != self.desired_revisions.get(&consumer.logical).copied()
            || consumer.artifacts != self.artifacts
            || !operation.retains_consumer
            || consumer.attempt > operation.operation.recovery.retry.max_attempts().get()
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "current native consumer differs from its exact checked claim".to_string(),
            ));
        }
        Ok(())
    }
}
