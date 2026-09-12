//! Terminal provider ownership settlement and durable admission updates.

use super::*;

impl NativeInventoryState {
    /// Applies terminal adoption settlement and lifecycle consumer updates.
    ///
    /// # Errors
    ///
    /// Returns an error when durable ownership, retained consumers, or the
    /// terminal summary differ, or the ledger cannot be updated.
    pub(in crate::config_eval::ability_store) fn finalize_terminal_ownership(
        &self,
        summary: &TransactionSummary,
    ) -> Result<(), GenerationAbilityStoreError> {
        if summary.transaction() != &self.transaction || summary.plan() != self.plan {
            return Err(GenerationAbilityStoreError::Conflict(
                "terminal ownership summary differs from its native transaction".to_string(),
            ));
        }
        let terminal = summary.terminal();
        let successful_operations = successful_operation_attempts(summary)?;
        *self.replayed_current_successes.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "current native success replay set is unavailable".to_string(),
            )
        })? = successful_operations
            .iter()
            .map(|(operation, attempt)| {
                (
                    aos_ability_model::OperationId {
                        plan: self.plan,
                        operation: operation.clone(),
                    },
                    *attempt,
                )
            })
            .collect();
        *self.replayed_current_terminal.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "current native terminal replay state is unavailable".to_string(),
            )
        })? = terminal;
        self.finalize_terminal_ownership_with_evidence(terminal, &successful_operations)
    }

    /// Applies the testable ownership settlement core from exact durable outcomes.
    ///
    /// `successful_operations` contains only operation keys whose recovered
    /// journal status is `Succeeded`; skipped or failed branches therefore
    /// cannot establish ownership or replace active consumers.
    ///
    /// # Errors
    ///
    /// Returns an error when adoption or lifecycle evidence differs from the
    /// durable ledger, selected endpoint, linked observations, or retained
    /// consumer evidence, or when persistence fails.
    pub(in crate::config_eval::ability_store::inventory) fn finalize_terminal_ownership_with_evidence(
        &self,
        terminal: Option<aos_ability_model::document::TerminalResult>,
        successful_operations: &BTreeMap<aos_ability_model::ScopedOperationKey, u32>,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.finalize_terminal_ownership_with_consumer_status(
            terminal,
            successful_operations,
            |consumer, owner_handler| {
                if self.is_current_consumer(consumer) {
                    self.current_consumer_operation_succeeded(
                        consumer,
                        owner_handler,
                        successful_operations,
                    )
                } else {
                    self.consumer_operation_succeeded(consumer, owner_handler)
                }
            },
        )
    }

    pub(in crate::config_eval::ability_store) fn finalize_terminal_ownership_with_consumer_status(
        &self,
        terminal: Option<aos_ability_model::document::TerminalResult>,
        successful_operations: &BTreeMap<aos_ability_model::ScopedOperationKey, u32>,
        mut consumer_operation_succeeded: impl FnMut(
            &ActiveNativeConsumer,
            Option<&NativeProviderHandlerIdentity>,
        )
            -> Result<bool, GenerationAbilityStoreError>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let mut ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        let actionable_terminal = matches!(
            terminal,
            Some(
                aos_ability_model::document::TerminalResult::Succeeded
                    | aos_ability_model::document::TerminalResult::SettledFailure
            )
        );
        if !actionable_terminal {
            return Ok(());
        }
        let mut changed = false;
        for owner in &mut ledger.owners {
            let establishment = self
                .operations
                .iter()
                .filter(|(key, operation)| {
                    successful_operations.contains_key(*key)
                        && operation.owner.as_ref() == Some(&owner.identity)
                        && operation.owner_handler.as_ref() == Some(&owner.handler)
                        && operation.operation.target.resource == owner.resource
                        && operation.operation.target.lifetime
                            == aos_ability_model::ResourceLifetime::Persistent
                        && operation.operation.accesses.iter().any(|access| {
                            access.resource == owner.resource && access.mode.is_write()
                        })
                })
                .max_by_key(|(key, _)| self.dispatch_positions.get(*key).copied())
                .map(|(key, _)| NativeProviderEstablishment {
                    generation: self.generation.clone(),
                    transaction: self.transaction.clone(),
                    plan: self.plan,
                    operation: aos_ability_model::OperationId {
                        plan: self.plan,
                        operation: key.clone(),
                    },
                    attempt: successful_operations[key],
                    artifacts: self.artifacts.clone(),
                });
            if let Some(establishment) = establishment {
                let establishment_position = self
                    .dispatch_positions
                    .get(&establishment.operation.operation)
                    .copied()
                    .ok_or_else(|| {
                        GenerationAbilityStoreError::Conflict(
                            "successful native owner establishment lacks a dispatch position"
                                .to_string(),
                        )
                    })?;
                let mut remaining_claims = Vec::new();
                for claim in &owner.claim_by {
                    let current_claim = self.classify_current_journal(
                        &claim.generation,
                        &claim.transaction,
                        claim.plan,
                        "provider owner claim",
                    )?;
                    let superseded = if current_claim {
                        self.dispatch_positions
                            .get(&claim.operation.operation)
                            .is_some_and(|position| *position <= establishment_position)
                    } else {
                        true
                    };
                    if !superseded {
                        remaining_claims.push(claim.clone());
                    }
                }

                if owner.established_by.as_ref() == Some(&establishment)
                    && owner.claim_by == remaining_claims
                {
                    continue;
                }
                owner.generation = establishment.generation.clone();
                owner.transaction = establishment.transaction.clone();
                owner.plan = establishment.plan;
                owner.artifacts = establishment.artifacts.clone();
                owner.claim_by = remaining_claims;
                owner.established_by = Some(establishment);
                changed = true;
            }
        }
        let is_exact_successful_consumer = |consumer: &ActiveNativeConsumer| {
            consumer.generation == self.generation
                && consumer.transaction == self.transaction
                && consumer.plan == self.plan
                && successful_operations
                    .get(&consumer.operation.operation)
                    .is_some_and(|attempt| *attempt == consumer.attempt)
                && self
                    .operations
                    .get(&consumer.operation.operation)
                    .is_some_and(|operation| operation.retains_consumer)
        };
        let mut refreshed_resources = BTreeMap::new();
        for (key, operation) in self.operations.iter().filter(|(key, operation)| {
            operation.retains_consumer && successful_operations.contains_key(*key)
        }) {
            let expected_attempt = successful_operations[key];
            let matching_consumers = ledger
                .consumers
                .iter()
                .filter(|consumer| {
                    consumer.generation == self.generation
                        && consumer.transaction == self.transaction
                        && consumer.plan == self.plan
                        && consumer.operation.plan == self.plan
                        && consumer.operation.operation == *key
                        && consumer.attempt == expected_attempt
                })
                .collect::<Vec<_>>();
            let [consumer] = matching_consumers.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful lifecycle refresh lacks one exact active native consumer"
                        .to_string(),
                ));
            };
            if consumer.logical != operation.operation.target.resource
                || consumer.binding != operation.binding
                || consumer.consumer != operation.consumer
                || consumer.provider != operation.provider
                || consumer.owner != operation.owner
                || consumer.desired_revision
                    != self.desired_revisions.get(&consumer.logical).copied()
                || consumer.artifacts != self.artifacts
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful lifecycle consumer differs from its exact checked operation"
                        .to_string(),
                ));
            }
            if refreshed_resources
                .insert(consumer.logical.clone(), (*key).clone())
                .is_some()
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful lifecycle operations ambiguously refresh one native resource"
                        .to_string(),
                ));
            }
        }
        let stopped_resources = self
            .operations
            .iter()
            .filter(|(key, operation)| {
                successful_operations.contains_key(*key)
                    && matches!(
                        operation.operation.family,
                        aos_ability_model::OperationFamily::ServiceLifecycle {
                            action: aos_ability_model::ServiceAction::Stop
                        }
                    )
                    && operation.operation.accesses.iter().any(|access| {
                        access.resource == operation.operation.target.resource
                            && access.mode.is_write()
                    })
            })
            .map(|(_, operation)| operation.operation.target.resource.clone())
            .collect::<BTreeSet<_>>();
        for (resource, start) in &refreshed_resources {
            let Some(owner) = ledger
                .owners
                .iter()
                .find(|owner| owner.resource == *resource)
            else {
                continue;
            };
            let Some(receipt) = owner.adoption.as_ref() else {
                continue;
            };
            let retains_source_consumer = ledger.consumers.iter().any(|consumer| {
                consumer.logical == *resource
                    && consumer.owner.as_ref() == Some(&receipt.source)
                    && !self
                        .has_current_journal_identity(&consumer.generation, &consumer.transaction)
            });
            if !retains_source_consumer {
                continue;
            }
            let stops = self
                .operations
                .iter()
                .filter(|(key, operation)| {
                    successful_operations.contains_key(*key)
                        && operation.operation.target.resource == *resource
                        && operation.owner.as_ref() == Some(&receipt.source)
                        && operation.owner_handler.as_ref() == Some(&receipt.source_handler)
                        && matches!(
                            operation.operation.family,
                            aos_ability_model::OperationFamily::ServiceLifecycle {
                                action: aos_ability_model::ServiceAction::Stop
                            }
                        )
                })
                .map(|(key, _)| key)
                .collect::<Vec<_>>();
            let [stop] = stops.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "candidate lifecycle replacement lacks one exact successful source Stop"
                        .to_string(),
                ));
            };
            if self.dispatch_positions.get(*stop) >= self.dispatch_positions.get(start) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "candidate lifecycle replacement does not order source Stop before Start"
                        .to_string(),
                ));
            }
        }
        for (resource, start) in refreshed_resources
            .iter()
            .filter(|(resource, _)| stopped_resources.contains(*resource))
        {
            let stops = self
                .operations
                .iter()
                .filter(|(key, operation)| {
                    successful_operations.contains_key(*key)
                        && operation.operation.target.resource == *resource
                        && matches!(
                            operation.operation.family,
                            aos_ability_model::OperationFamily::ServiceLifecycle {
                                action: aos_ability_model::ServiceAction::Stop
                            }
                        )
                })
                .map(|(key, _)| key)
                .collect::<Vec<_>>();
            let [stop] = stops.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "terminal replacement lacks one exact successful Stop".to_string(),
                ));
            };
            if self.dispatch_positions.get(*stop) >= self.dispatch_positions.get(start) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "terminal replacement does not order successful Stop before Start".to_string(),
                ));
            }
        }
        for resource in &stopped_resources {
            let matching_stops = self
                .operations
                .iter()
                .filter(|(key, operation)| {
                    successful_operations.contains_key(*key)
                        && operation.operation.target.resource == *resource
                        && matches!(
                            operation.operation.family,
                            aos_ability_model::OperationFamily::ServiceLifecycle {
                                action: aos_ability_model::ServiceAction::Stop
                            }
                        )
                })
                .map(|(_, operation)| operation)
                .collect::<Vec<_>>();
            let [stop] = matching_stops.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "terminal native Stop lacks one exact checked operation".to_string(),
                ));
            };
            let owner = ledger
                .owners
                .iter()
                .find(|owner| owner.resource == *resource);
            for consumer in ledger
                .consumers
                .iter()
                .filter(|consumer| consumer.logical == *resource)
            {
                let current_transaction =
                    self.has_current_journal_identity(&consumer.generation, &consumer.transaction);
                if current_transaction {
                    continue;
                }
                let direct_owner = consumer.owner.as_ref() == stop.owner.as_ref();
                let receipt_source = owner
                    .and_then(|owner| owner.adoption.as_ref())
                    .is_some_and(|receipt| consumer.owner.as_ref() == Some(&receipt.source));
                let owner_handler =
                    super::super::retained_consumer_owner_handler(&ledger, consumer)?;
                if (!direct_owner && !receipt_source)
                    || !consumer_operation_succeeded(consumer, owner_handler)?
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "terminal native Stop consumer differs from its exact retained provenance"
                            .to_string(),
                    ));
                }
            }
        }

        let consumer_count = ledger.consumers.len();
        ledger.consumers.retain(|consumer| {
            let current_transaction =
                self.has_current_journal_identity(&consumer.generation, &consumer.transaction);
            if current_transaction && !is_exact_successful_consumer(consumer) {
                return false;
            }
            if refreshed_resources.contains_key(&consumer.logical) {
                return is_exact_successful_consumer(consumer);
            }
            if stopped_resources.contains(&consumer.logical) {
                return false;
            }
            true
        });
        changed |= ledger.consumers.len() != consumer_count;

        if terminal == Some(aos_ability_model::document::TerminalResult::SettledFailure) {
            if changed {
                canonicalize_native_ledger(&mut ledger)?;
                save_native_resource_ledger(&self.ledger_path, &ledger)?;
            }
            return Ok(());
        }

        let mut settled_resources = BTreeSet::new();
        for owner in &mut ledger.owners {
            let Some(receipt) = owner.adoption.as_ref() else {
                continue;
            };
            let matching_selections = self
                .desired_owner_selections
                .iter()
                .filter(|selection| {
                    selection.resource == owner.resource
                        && selection.identity == owner.identity
                        && selection.handler == owner.handler
                })
                .collect::<Vec<_>>();
            let matching_adoptions = self
                .adoptions
                .iter()
                .filter(|adoption| {
                    adoption.resource == owner.resource
                        && NativeProviderIdentity::from_endpoint(&adoption.source) == receipt.source
                        && handler_from_endpoint(&adoption.source) == receipt.source_handler
                        && NativeProviderIdentity::from_endpoint(&adoption.candidate)
                            == owner.identity
                        && handler_from_endpoint(&adoption.candidate) == owner.handler
                })
                .count();
            let successful_owner_write =
                self.operations.iter().any(|(key, operation)| {
                    successful_operations.contains_key(key)
                        && operation.owner.as_ref() == Some(&owner.identity)
                        && operation.owner_handler.as_ref() == Some(&owner.handler)
                        && operation.operation.target.resource == owner.resource
                        && operation.operation.target.lifetime
                            == aos_ability_model::ResourceLifetime::Persistent
                        && operation.operation.accesses.iter().any(|access| {
                            access.resource == owner.resource && access.mode.is_write()
                        })
                });
            let successful_owner_observation = self.operations.iter().any(|(key, operation)| {
                successful_operations.contains_key(key)
                    && operation.owner.as_ref() == Some(&owner.identity)
                    && operation.owner_handler.as_ref() == Some(&owner.handler)
                    && operation.operation.target.resource == owner.resource
            });
            let linked_observation_healthy = self
                .linked_recovery_observations
                .get(&owner.resource)
                .zip(self.desired_revisions.get(&owner.resource))
                .is_some_and(|(observation, desired_revision)| {
                    matches!(
                        observation,
                        aos_ability_plan::RuntimeResourceState::Present {
                            revision,
                            health: aos_ability_plan::RuntimeResourceHealth::Healthy,
                        } if revision == desired_revision
                    )
                });
            let resource_consumers = ledger
                .consumers
                .iter()
                .filter(|consumer| consumer.logical == owner.resource)
                .collect::<Vec<_>>();
            let exact_consumer_recovery = match receipt.consumer_requirement {
                Some(NativeConsumerRequirement::Required) => match resource_consumers.as_slice() {
                    [consumer]
                        if consumer.owner.as_ref() == Some(&owner.identity)
                            && consumer.desired_revision
                                == self.desired_revisions.get(&owner.resource).copied() =>
                    {
                        consumer_operation_succeeded(consumer, Some(&owner.handler))?
                    }
                    _ => {
                        return Err(GenerationAbilityStoreError::Conflict(
                            "linked adoption recovery consumer differs from its exact durable provenance"
                                .to_string(),
                        ));
                    }
                },
                Some(NativeConsumerRequirement::Forbidden) if resource_consumers.is_empty() => true,
                Some(NativeConsumerRequirement::Forbidden) => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "linked adoption resource-only recovery retained active consumers"
                            .to_string(),
                    ));
                }
                None => false,
            };
            let healthy_linked_recovery = linked_observation_healthy
                && exact_consumer_recovery
                && (successful_owner_observation
                    || self.has_exact_native_no_op_verification()?
                    || self.has_exact_linked_adoption_verification(receipt)
                    || matches!(
                        receipt.consumer_requirement,
                        Some(NativeConsumerRequirement::Required)
                    ));
            let linked_recovery = self
                .linked_recovery_observations
                .contains_key(&owner.resource)
                && self.operations.values().any(|operation| {
                    operation.owner.as_ref() == Some(&owner.identity)
                        && operation.owner_handler.as_ref() == Some(&owner.handler)
                        && operation.operation.target.resource == owner.resource
                        && operation.operation.target.lifetime
                            == aos_ability_model::ResourceLifetime::Persistent
                        && operation.operation.accesses.iter().any(|access| {
                            access.resource == owner.resource && access.mode.is_write()
                        })
                });
            if matching_selections.is_empty() && matching_adoptions == 0 && !linked_recovery {
                continue;
            }
            let [_selection] = matching_selections.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful provider adoption lacks one exact selected recovery endpoint"
                        .to_string(),
                ));
            };
            if matching_adoptions != 1 && !linked_recovery && !healthy_linked_recovery {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful provider adoption lacks one exact selected recovery endpoint"
                        .to_string(),
                ));
            }
            if !successful_owner_write && !healthy_linked_recovery {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful provider adoption lacks durable completed recovery evidence"
                        .to_string(),
                ));
            }

            let Some(establishment) = owner.established_by.clone() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful provider adoption has no authenticated candidate establishment"
                        .to_string(),
                ));
            };
            self.authenticate_source_establishment(owner, &establishment)?;
            owner.artifacts = establishment.artifacts;
            // The authenticated candidate write remains the durable
            // establishment proof after the transfer receipt is cleared.
            owner.adoption = None;
            settled_resources.insert(owner.resource.clone());
            changed = true;
        }

        for consumer in ledger
            .consumers
            .iter()
            .filter(|consumer| settled_resources.contains(&consumer.logical))
        {
            let owner = ledger
                .owners
                .iter()
                .find(|owner| owner.resource == consumer.logical)
                .ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(
                        "successful adoption consumer lost its exact durable owner".to_string(),
                    )
                })?;
            if consumer.owner.as_ref() != Some(&owner.identity) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "successful adoption consumer differs from its exact durable owner".to_string(),
                ));
            }
        }
        if changed {
            canonicalize_native_ledger(&mut ledger)?;
            save_native_resource_ledger(&self.ledger_path, &ledger)?;
        }
        Ok(())
    }

    fn has_exact_native_no_op_verification(&self) -> Result<bool, GenerationAbilityStoreError> {
        let Some(plan_bundle) = self.plan_bundle else {
            return Ok(false);
        };
        let profile = self.ledger_path.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource ledger has no profile parent".to_string(),
            )
        })?;
        let path = profile
            .join(&self.generation)
            .join(super::super::TRANSACTION_ROOT)
            .join(self.transaction.0.as_str())
            .join(super::super::super::NATIVE_NO_OP_VERIFICATION_FILE);
        let bytes = match super::super::read_regular_file(
            &path,
            super::super::super::NATIVE_NO_OP_VERIFICATION_MAX_BYTES,
            "native no-op verification marker",
        ) {
            Ok(bytes) => bytes,
            Err(GenerationAbilityStoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let marker: super::super::super::NativeNoOpVerificationMarker =
            aos_contract::canonical::from_slice(&bytes, "native no-op verification marker")
                .map_err(|source| {
                    GenerationAbilityStoreError::Conflict(format!(
                        "invalid native no-op verification marker: {source}"
                    ))
                })?;
        let canonical = aos_contract::canonical::to_vec(&marker).map_err(|source| {
            GenerationAbilityStoreError::Operation(anyhow::anyhow!(
                "encoding native no-op verification marker: {source:#}"
            ))
        })?;
        if canonical != bytes
            || marker.schema != super::super::super::NATIVE_NO_OP_VERIFICATION_SCHEMA
            || marker.transaction != self.transaction
            || marker.plan != self.plan
            || marker.plan_bundle != plan_bundle
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native no-op verification marker differs from its ownership transaction"
                    .to_string(),
            ));
        }
        Ok(true)
    }

    /// Admits a persistent resource under its exact checked owner and handler.
    ///
    /// # Errors
    ///
    /// Returns an error when fresh execution authority differs from the checked
    /// handler or durable ownership conflicts with the candidate.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::config_eval::ability_store::inventory) fn authorize_provider_owner(
        &self,
        ledger: &mut NativeResourceLedger,
        candidate: &NativeProviderIdentity,
        resource: &NativeQualifiedResource,
        checked_handler: Option<&NativeProviderHandlerIdentity>,
        execution_assignment: Option<&aos_ability_model::ProviderAssignment>,
        admits_receipt_source: bool,
        claim_operation: &aos_ability_model::OperationId,
        claim_attempt: u32,
    ) -> Result<bool, GenerationAbilityStoreError> {
        let assignment = require_owner_assignment(checked_handler, execution_assignment)?;
        if claim_operation.plan != self.plan || claim_attempt == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "native provider owner claim differs from its checked reservation context"
                    .to_string(),
            ));
        }
        let claim = NativeProviderClaim {
            generation: self.generation.clone(),
            transaction: self.transaction.clone(),
            plan: self.plan,
            operation: claim_operation.clone(),
            attempt: claim_attempt,
            artifacts: self.artifacts.clone(),
        };
        if admits_receipt_source
            && ledger.owners.iter().any(|owner| {
                owner.resource == resource.logical
                    && owner.physical == resource.physical
                    && owner.adoption.as_ref().is_some_and(|receipt| {
                        receipt.source == *candidate && receipt.source_handler == *assignment
                    })
            })
        {
            return Ok(false);
        }
        let related = ledger
            .owners
            .iter()
            .enumerate()
            .filter(|(_, owner)| owner.identity.provider == candidate.provider)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if related.is_empty() {
            if self.adoptions.iter().any(|adoption| {
                NativeProviderIdentity::from_endpoint(&adoption.candidate) == *candidate
            }) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption has no exact sole source owner".to_string(),
                ));
            }
            ledger.owners.push(NativeProviderOwner {
                resource: resource.logical.clone(),
                physical: resource.physical.clone(),
                identity: candidate.clone(),
                handler: assignment.clone(),
                generation: self.generation.clone(),
                transaction: self.transaction.clone(),
                plan: self.plan,
                artifacts: self.artifacts.clone(),
                claim_by: vec![claim.clone()],
                established_by: None,
                adoption: None,
            });
            return Ok(true);
        }

        if related
            .iter()
            .all(|index| ledger.owners[*index].identity == *candidate)
        {
            let matching_resource = ledger
                .owners
                .iter()
                .filter(|owner| owner.resource == resource.logical)
                .collect::<Vec<_>>();
            let retained_claims = match matching_resource.as_slice() {
                [] => Vec::new(),
                [owner] if owner.physical == resource.physical && owner.handler == *assignment => {
                    self.validate_retained_owner_provenance(owner)?;
                    let mut retained = Vec::with_capacity(owner.claim_by.len());
                    let mut prior_intent = false;
                    for prior_claim in &owner.claim_by {
                        let current = self.classify_current_journal(
                            &prior_claim.generation,
                            &prior_claim.transaction,
                            prior_claim.plan,
                            "provider owner claim",
                        )?;
                        if current || self.authenticate_candidate_claim(owner, prior_claim)? {
                            prior_intent |= !current;
                            retained.push(prior_claim.clone());
                        }
                    }
                    if prior_intent && owner.established_by.is_none() {
                        let exact_linked_repair = owner.adoption.as_ref().is_some_and(|receipt| {
                            Some(receipt.authority) == self.transition_authority
                                && self
                                    .linked_recovery_observations
                                    .contains_key(&owner.resource)
                        }) && self.adoptions.iter().any(|adoption| {
                            adoption.resource == owner.resource
                                && NativeProviderIdentity::from_endpoint(&adoption.candidate)
                                    == *candidate
                                && handler_from_endpoint(&adoption.candidate) == *assignment
                        });
                        if !exact_linked_repair {
                            return Err(GenerationAbilityStoreError::Conflict(
                                "intent-reaching native provider owner claim permits only exact linked same-owner repair"
                                    .to_string(),
                            ));
                        }
                    }
                    retained
                }
                [..] => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native provider owner differs from the sealed checked handler assignment"
                            .to_string(),
                    ));
                }
            };
            if let Some(owner) = ledger
                .owners
                .iter_mut()
                .find(|owner| owner.resource == resource.logical)
            {
                let changed = owner.claim_by != retained_claims;
                owner.claim_by = retained_claims;
                let appended = append_provider_claim(owner, claim)?;
                align_unestablished_owner_to_initial_claim(owner)?;
                return Ok(changed || appended);
            }
            ledger.owners.push(NativeProviderOwner {
                resource: resource.logical.clone(),
                physical: resource.physical.clone(),
                identity: candidate.clone(),
                handler: assignment.clone(),
                generation: self.generation.clone(),
                transaction: self.transaction.clone(),
                plan: self.plan,
                artifacts: self.artifacts.clone(),
                claim_by: vec![claim],
                established_by: None,
                adoption: None,
            });
            return Ok(true);
        }

        Err(GenerationAbilityStoreError::Conflict(
            "native provider owner differs after atomic adoption preflight".to_string(),
        ))
    }
}
