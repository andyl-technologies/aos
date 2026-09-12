//! Provider ownership recovery, authentication, and effect preflight checks.

use super::*;

impl NativeInventoryState {
    /// Replays a pre-existing terminal marker against recovered execution state.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker is invalid, differs from recovered
    /// state, or its durable ownership update cannot be applied atomically.
    pub(in crate::config_eval::ability_store) fn finalize_existing_terminal_marker(
        &self,
        recovered: &TransactionSummary,
    ) -> Result<(), GenerationAbilityStoreError> {
        let marker_terminal = exact_terminal_result(
            &self.ledger_path,
            &self.generation,
            &self.transaction,
            self.plan,
        )?;
        let Some(marker_terminal) = marker_terminal else {
            return Ok(());
        };
        if recovered.transaction() != &self.transaction
            || recovered.plan() != self.plan
            || recovered.terminal() != Some(marker_terminal)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "ability terminal marker differs from the recovered execution result".to_string(),
            ));
        }
        let successful_operations = successful_operation_attempts(recovered)?;
        self.finalize_existing_terminal_marker_with_evidence(
            recovered.terminal(),
            &successful_operations,
        )
    }

    pub(in crate::config_eval::ability_store::inventory) fn finalize_existing_terminal_marker_with_evidence(
        &self,
        recovered_terminal: Option<aos_ability_model::document::TerminalResult>,
        successful_operations: &BTreeMap<aos_ability_model::ScopedOperationKey, u32>,
    ) -> Result<(), GenerationAbilityStoreError> {
        let marker_terminal = exact_terminal_result(
            &self.ledger_path,
            &self.generation,
            &self.transaction,
            self.plan,
        )?;
        if marker_terminal != recovered_terminal {
            return Err(GenerationAbilityStoreError::Conflict(
                "ability terminal marker differs from the recovered execution result".to_string(),
            ));
        }
        self.finalize_terminal_ownership_with_evidence(recovered_terminal, successful_operations)
    }

    /// Performs durable owner and adoption checks before any provider effect.
    ///
    /// # Errors
    ///
    /// Returns an error when retained ownership, transition authority, or an
    /// adoption receipt differs from the checked plan.
    pub(in crate::config_eval::ability_store) fn preflight_provider_owners(
        &self,
        bundle: &ReloadablePlanBundle,
        transaction: &ExecutionTransaction<'_>,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.seed_current_claim_replay_evidence(transaction)?;
        self.preflight_provider_owners_for_current(|resource| {
            bundle.current_contains_resource(resource)
        })
    }

    #[cfg(test)]
    pub(in crate::config_eval::ability_store::inventory) fn preflight_provider_owners_for_recovery_test(
        &self,
        transaction: &ExecutionTransaction<'_>,
        current_contains_resource: impl Fn(&ResourceId) -> bool,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.seed_current_claim_replay_evidence(transaction)?;
        self.preflight_provider_owners_for_current(current_contains_resource)
    }

    fn seed_current_claim_replay_evidence(
        &self,
        transaction: &ExecutionTransaction<'_>,
    ) -> Result<(), GenerationAbilityStoreError> {
        if transaction.transaction() != &self.transaction || transaction.plan().id() != self.plan {
            return Err(GenerationAbilityStoreError::Conflict(
                "current claim replay evidence differs from its inventory transaction".to_string(),
            ));
        }
        let effect_intents = transaction
            .effect_intent_attempts()
            .map(|(operation, attempt)| (operation, attempt.get()))
            .collect();
        let clean_claims = transaction
            .clean_claim_attempts()
            .map(|(operation, attempt)| (operation, attempt.get()))
            .collect();
        let summary = transaction.summary();
        let successes = summary
            .operations()
            .iter()
            .filter(|operation| operation.status() == OperationStatus::Succeeded)
            .filter_map(|operation| {
                operation
                    .attempt()
                    .map(|attempt| (operation.operation().clone(), attempt.get()))
            })
            .collect();
        *self.replayed_current_effect_intents.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "current native effect-intent replay set is unavailable".to_string(),
            )
        })? = effect_intents;
        *self.replayed_clean_current_claims.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "clean current native claim replay set is unavailable".to_string(),
            )
        })? = clean_claims;
        *self.replayed_current_successes.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "current native success replay set is unavailable".to_string(),
            )
        })? = successes;
        *self.replayed_current_terminal.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "current native terminal replay state is unavailable".to_string(),
            )
        })? = summary.terminal();
        Ok(())
    }

    /// Performs provider-owner preflight using an explicit prior-resource query.
    ///
    /// # Errors
    ///
    /// Returns an error when retained ownership, transition authority, or an
    /// adoption receipt differs from the checked plan, or ledger persistence
    /// fails.
    pub(in crate::config_eval::ability_store::inventory) fn preflight_provider_owners_for_current(
        &self,
        current_contains_resource: impl Fn(&ResourceId) -> bool,
    ) -> Result<(), GenerationAbilityStoreError> {
        let mut ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        let mut ledger_changed = self.compact_clean_provider_claims(&mut ledger)?;
        ledger_changed |=
            self.remove_clean_unestablished_replacements(&mut ledger, &current_contains_resource)?;
        self.validate_retained_provider_owners(&ledger, &current_contains_resource)?;
        self.authenticate_retained_consumers_before_effects(&ledger)?;

        let mut already_adopted = None;
        let adoption_authority = if self.adoptions.is_empty() {
            None
        } else {
            Some(self.transition_authority.ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption lacks its sealed transition authority".to_string(),
                )
            })?)
        };
        for adoption in &self.adoptions {
            let source = NativeProviderIdentity::from_endpoint(&adoption.source);
            let candidate = NativeProviderIdentity::from_endpoint(&adoption.candidate);
            let source_handler = handler_from_endpoint(&adoption.source);
            let candidate_handler = handler_from_endpoint(&adoption.candidate);
            let candidate_artifacts = artifacts_from_endpoint(&adoption.candidate)?;
            if candidate_artifacts
                .iter()
                .any(|artifact| !self.artifacts.contains(artifact))
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption candidate artifacts are absent from the checked effect plan"
                        .to_string(),
                ));
            }
            let candidate_acquisitions = self
                .operations
                .iter()
                .filter(|(_, operation)| {
                    operation.binding == adoption.candidate.handler_binding
                        && operation.owner.as_ref() == Some(&candidate)
                        && operation.owner_handler.as_ref() == Some(&candidate_handler)
                        && operation.operation.target.resource == adoption.resource
                        && operation.operation.target.interface == adoption.resource_interface
                        && operation.operation.target.lifetime == ResourceLifetime::Persistent
                        && operation.operation.method == adoption.candidate.handler_method
                        && operation.operation.accesses.iter().any(|access| {
                            access.resource == adoption.resource && access.mode.is_write()
                        })
                })
                .collect::<Vec<_>>();
            let candidate_claim = match candidate_acquisitions.as_slice() {
                [] => None,
                [(candidate_operation, _)] => Some(NativeProviderClaim {
                    generation: self.generation.clone(),
                    transaction: self.transaction.clone(),
                    plan: self.plan,
                    operation: aos_ability_model::OperationId {
                        plan: self.plan,
                        operation: (*candidate_operation).clone(),
                    },
                    attempt: 1,
                    artifacts: self.artifacts.clone(),
                }),
                _ => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "provider adoption candidate does not have one exact checked acquisition operation"
                            .to_string(),
                    ));
                }
            };
            let matching_candidate = ledger
                .owners
                .iter()
                .filter(|owner| {
                    owner.resource == adoption.resource
                        && owner.identity == candidate
                        && owner.handler == candidate_handler
                })
                .collect::<Vec<_>>();
            if let [owner] = matching_candidate.as_slice() {
                self.validate_candidate_provenance(owner)?;
                let receipt_matches = match owner.adoption.as_ref() {
                    Some(receipt) => {
                        self.validate_receipt_source(owner, receipt)?;
                        Some(receipt.authority) == adoption_authority
                            && receipt.source == source
                            && receipt.source_handler == source_handler
                            && (receipt.linked_verification.is_none()
                                || self.has_exact_linked_adoption_verification(receipt))
                    }
                    None => false,
                };
                let effect_free_linked_recovery = if candidate_claim.is_none() {
                    match owner.adoption.as_ref() {
                        Some(receipt) if receipt_matches => {
                            self.allows_effect_free_linked_adoption_recovery(owner, receipt)?
                        }
                        _ => false,
                    }
                } else {
                    false
                };
                let exact_current_claim = candidate_claim.as_ref().is_some_and(|candidate_claim| {
                    owner.claim_by.iter().any(|claim| {
                        claim.generation == self.generation
                            && claim.transaction == self.transaction
                            && claim.plan == self.plan
                            && claim.operation.operation == candidate_claim.operation.operation
                            && claim.artifacts == self.artifacts
                    })
                });
                let exact_current_linked_verification = owner
                    .adoption
                    .as_ref()
                    .is_some_and(|receipt| self.has_exact_linked_adoption_verification(receipt));
                let exact_current_receipt = receipt_matches
                    && (exact_current_claim
                        || (exact_current_linked_verification && effect_free_linked_recovery)
                        || (owner.generation == self.generation
                            && owner.transaction == self.transaction
                            && owner.plan == self.plan
                            && owner.established_by.is_some()));
                let finalized_current_receipt = owner.adoption.is_none()
                    && owner.generation == self.generation
                    && owner.transaction == self.transaction
                    && owner.plan == self.plan
                    && owner.artifacts == self.artifacts
                    && owner.claim_by.is_empty()
                    && owner.established_by.is_some()
                    && self.authenticated_retained_terminal_result(
                        &self.generation,
                        &self.transaction,
                        self.plan,
                    )? == Some(aos_ability_model::document::TerminalResult::Succeeded);
                if candidate_claim.is_none()
                    && !effect_free_linked_recovery
                    && !finalized_current_receipt
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "effect-free provider adoption recovery lacks exact healthy observation and authenticated candidate establishment"
                            .to_string(),
                    ));
                }
                if exact_current_receipt || finalized_current_receipt {
                    if already_adopted.replace(true) == Some(false) {
                        return Err(GenerationAbilityStoreError::Conflict(
                            "provider adoption ledger contains a mixed partial transfer"
                                .to_string(),
                        ));
                    }
                    continue;
                }

                let Some(receipt) = owner.adoption.clone() else {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "adopted provider owner has stale or mismatched receipt evidence"
                            .to_string(),
                    ));
                };
                if receipt.source != source
                    || receipt.source_handler != source_handler
                    || self.authenticated_retained_terminal_result(
                        &owner.generation,
                        &owner.transaction,
                        owner.plan,
                    )? != Some(aos_ability_model::document::TerminalResult::SettledFailure)
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "adopted provider owner has stale or mismatched receipt evidence"
                            .to_string(),
                    ));
                }
                let retained_source_artifacts = canonical_artifacts(
                    &owner
                        .artifacts
                        .iter()
                        .chain(&receipt.source_artifacts)
                        .chain(
                            ledger
                                .consumers
                                .iter()
                                .filter(|consumer| consumer.logical == adoption.resource)
                                .flat_map(|consumer| &consumer.artifacts),
                        )
                        .cloned()
                        .collect::<Vec<_>>(),
                )?;
                let owner = ledger.owners.iter_mut().find(|candidate_owner| {
                    candidate_owner.resource == adoption.resource
                        && candidate_owner.identity == candidate
                        && candidate_owner.handler == candidate_handler
                });
                let owner = owner.ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(
                        "adopted provider owner disappeared during atomic preflight".to_string(),
                    )
                })?;
                if owner.established_by.is_none() {
                    let candidate_claim = candidate_claim.clone().ok_or_else(|| {
                        GenerationAbilityStoreError::Conflict(
                            "provider adoption candidate does not have one exact checked acquisition operation"
                                .to_string(),
                        )
                    })?;
                    append_provider_claim(owner, candidate_claim.clone())?;
                    align_unestablished_owner_to_initial_claim(owner)?;
                }
                owner.adoption = Some(NativeProviderAdoptionReceipt {
                    authority: adoption_authority.ok_or_else(|| {
                        GenerationAbilityStoreError::Conflict(
                            "provider adoption lost its sealed transition authority".to_string(),
                        )
                    })?,
                    source: receipt.source,
                    source_handler: receipt.source_handler,
                    source_generation: receipt.source_generation,
                    source_transaction: receipt.source_transaction,
                    source_plan: receipt.source_plan,
                    source_artifacts: retained_source_artifacts,
                    source_establishment: receipt.source_establishment,
                    // A new recovery transaction must authenticate its own
                    // complete reconciliation union before effects.
                    consumer_requirement: None,
                    linked_verification: None,
                });
                ledger_changed = true;
                if already_adopted.replace(true) == Some(false) {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "provider adoption ledger contains a mixed partial transfer".to_string(),
                    ));
                }
                continue;
            }
            if !matching_candidate.is_empty() {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption identifies ambiguous durable candidate ownership"
                        .to_string(),
                ));
            }

            let matching_source = ledger
                .owners
                .iter()
                .enumerate()
                .filter(|(_, owner)| {
                    owner.resource == adoption.resource
                        && owner.identity == source
                        && owner.handler == source_handler
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let [source_index] = matching_source.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption does not identify exactly one durable source owner"
                        .to_string(),
                ));
            };
            let source_owner = ledger.owners[*source_index].clone();
            if already_adopted.replace(false) == Some(true) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption ledger contains a mixed partial transfer".to_string(),
                ));
            }
            let candidate_claim = candidate_claim.ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption candidate does not have one exact checked acquisition operation"
                        .to_string(),
                )
            })?;
            let establishment = source_owner.established_by.clone().ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption source has no authenticated successful owner write"
                        .to_string(),
                )
            })?;
            self.authenticate_source_establishment(&source_owner, &establishment)?;
            if !source_owner.claim_by.is_empty() {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider adoption source retains an unsettled owner-write claim".to_string(),
                ));
            }

            let source_artifacts = canonical_artifacts(
                &source_owner
                    .artifacts
                    .iter()
                    .chain(
                        source_owner
                            .adoption
                            .iter()
                            .flat_map(|receipt| &receipt.source_artifacts),
                    )
                    .chain(
                        ledger
                            .consumers
                            .iter()
                            .filter(|consumer| consumer.logical == source_owner.resource)
                            .flat_map(|consumer| &consumer.artifacts),
                    )
                    .cloned()
                    .collect::<Vec<_>>(),
            )?;
            ledger.owners[*source_index] = NativeProviderOwner {
                resource: source_owner.resource,
                physical: source_owner.physical,
                identity: candidate,
                handler: candidate_handler,
                generation: self.generation.clone(),
                transaction: self.transaction.clone(),
                plan: self.plan,
                artifacts: self.artifacts.clone(),
                claim_by: vec![candidate_claim],
                established_by: None,
                adoption: Some(NativeProviderAdoptionReceipt {
                    authority: adoption_authority.ok_or_else(|| {
                        GenerationAbilityStoreError::Conflict(
                            "provider adoption lost its sealed transition authority".to_string(),
                        )
                    })?,
                    source: source_owner.identity,
                    source_handler: source_owner.handler,
                    source_generation: establishment.generation.clone(),
                    source_transaction: establishment.transaction.clone(),
                    source_plan: establishment.plan,
                    source_artifacts,
                    source_establishment: establishment,
                    consumer_requirement: None,
                    linked_verification: None,
                }),
            };
            ledger_changed = true;
        }
        self.validate_consumer_replacement_handoffs(&ledger)?;
        self.validate_observed_consumer_repairs_before_effects(&ledger)?;
        if ledger_changed {
            canonicalize_native_ledger(&mut ledger)?;
            save_native_resource_ledger(&self.ledger_path, &ledger)?;
        }
        self.mark_persisted_current_claims_authenticated(&ledger)?;
        Ok(())
    }

    fn compact_clean_provider_claims(
        &self,
        ledger: &mut NativeResourceLedger,
    ) -> Result<bool, GenerationAbilityStoreError> {
        let mut changed = false;
        let mut clean_claims = Vec::new();
        for owner in &mut ledger.owners {
            let mut retained = Vec::with_capacity(owner.claim_by.len());
            for claim in owner.claim_by.clone() {
                let is_current = self.classify_current_journal(
                    &claim.generation,
                    &claim.transaction,
                    claim.plan,
                    "provider owner claim",
                )?;
                if is_current {
                    if self.authenticate_current_provider_claim(owner, &claim)? {
                        retained.push(claim);
                    } else {
                        clean_claims.push((owner.resource.clone(), owner.identity.clone(), claim));
                    }
                } else if self.authenticate_candidate_claim(owner, &claim)? {
                    retained.push(claim);
                }
            }
            if retained != owner.claim_by {
                owner.claim_by = retained;
                canonicalize_provider_claim_chain(owner)?;
                changed = true;
            }
        }
        if !clean_claims.is_empty() {
            let consumer_count = ledger.consumers.len();
            ledger.consumers.retain(|consumer| {
                !clean_claims.iter().any(|(resource, owner, claim)| {
                    consumer.logical == *resource
                        && consumer.owner.as_ref() == Some(owner)
                        && consumer.generation == claim.generation
                        && consumer.transaction == claim.transaction
                        && consumer.plan == claim.plan
                        && consumer.operation == claim.operation
                        && consumer.attempt == claim.attempt
                        && consumer.artifacts == claim.artifacts
                })
            });
            changed |= ledger.consumers.len() != consumer_count;
        }
        self.require_current_effect_intent_claims(ledger)?;
        Ok(changed)
    }

    fn remove_clean_unestablished_replacements(
        &self,
        ledger: &mut NativeResourceLedger,
        current_contains_resource: &impl Fn(&ResourceId) -> bool,
    ) -> Result<bool, GenerationAbilityStoreError> {
        let mut changed = false;
        let mut owners = Vec::with_capacity(ledger.owners.len());
        for owner in ledger.owners.drain(..) {
            if owner.established_by.is_some()
                || !owner.claim_by.is_empty()
                || (owner.adoption.is_none() && current_contains_resource(&owner.resource))
            {
                owners.push(owner);
                continue;
            }

            ledger.consumers.retain(|consumer| {
                consumer.logical != owner.resource
                    || consumer.owner.as_ref() != Some(&owner.identity)
            });
            if let Some(receipt) = owner.adoption.as_ref() {
                self.validate_receipt_source(&owner, receipt)?;
                let establishment = receipt.source_establishment.clone();
                owners.push(NativeProviderOwner {
                    resource: owner.resource,
                    physical: owner.physical,
                    identity: receipt.source.clone(),
                    handler: receipt.source_handler.clone(),
                    generation: establishment.generation.clone(),
                    transaction: establishment.transaction.clone(),
                    plan: establishment.plan,
                    artifacts: establishment.artifacts.clone(),
                    claim_by: Vec::new(),
                    established_by: Some(establishment),
                    adoption: None,
                });
            }
            changed = true;
        }
        ledger.owners = owners;
        Ok(changed)
    }

    fn validate_candidate_provenance(
        &self,
        owner: &NativeProviderOwner,
    ) -> Result<(), GenerationAbilityStoreError> {
        if let Some(establishment) = &owner.established_by {
            self.authenticate_source_establishment(owner, establishment)?;
        }
        for claim in &owner.claim_by {
            self.validate_candidate_claim_shape(owner, claim)?;
        }
        if owner.claim_by.is_empty() && owner.established_by.is_none() {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider owner lacks claim and establishment provenance".to_string(),
            ));
        }
        if owner.established_by.is_none()
            && owner.claim_by.first().is_none_or(|claim| {
                claim.generation != owner.generation
                    || claim.transaction != owner.transaction
                    || claim.plan != owner.plan
                    || claim.artifacts != owner.artifacts
            })
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "unestablished provider owner differs from its initial claim provenance"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(in crate::config_eval::ability_store::inventory) fn validate_retained_owner_provenance(
        &self,
        owner: &NativeProviderOwner,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.validate_candidate_provenance(owner)?;
        for claim in &owner.claim_by {
            if self.classify_current_journal(
                &claim.generation,
                &claim.transaction,
                claim.plan,
                "provider owner claim",
            )? {
                if !self.authenticate_current_provider_claim(owner, claim)? {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "clean current provider owner claim was not compacted before validation"
                            .to_string(),
                    ));
                }
                continue;
            }
            self.authenticate_candidate_claim(owner, claim)?;
        }
        Ok(())
    }

    fn authenticate_current_provider_claim(
        &self,
        owner: &NativeProviderOwner,
        claim: &NativeProviderClaim,
    ) -> Result<bool, GenerationAbilityStoreError> {
        let operation = self
            .operations
            .get(&claim.operation.operation)
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "current provider owner claim operation is absent".to_string(),
                )
            })?;
        if claim.operation.plan != self.plan
            || claim.attempt == 0
            || operation.owner.as_ref() != Some(&owner.identity)
            || operation.owner_handler.as_ref() != Some(&owner.handler)
            || operation.operation.target.resource != owner.resource
            || operation.operation.target.lifetime != ResourceLifetime::Persistent
            || !operation
                .operation
                .accesses
                .iter()
                .any(|access| access.resource == owner.resource && access.mode.is_write())
            || claim.attempt > operation.operation.recovery.retry.max_attempts().get()
            || claim.artifacts != self.artifacts
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "current provider owner claim is not an exact checked owner write".to_string(),
            ));
        }
        if self.current_claim_is_authenticated(claim)? {
            return Ok(true);
        }
        let claim_key = (claim.operation.clone(), claim.attempt);
        if self
            .replayed_current_effect_intents
            .lock()
            .map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "current native effect-intent replay set is unavailable".to_string(),
                )
            })?
            .contains(&claim_key)
        {
            self.mark_current_claim_authenticated(claim)?;
            return Ok(true);
        }
        if self
            .replayed_clean_current_claims
            .lock()
            .map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "clean current native claim replay set is unavailable".to_string(),
                )
            })?
            .contains(&claim_key)
        {
            return Ok(false);
        }

        Err(GenerationAbilityStoreError::Conflict(
            "current provider owner claim attempt has no exact checked replay evidence".to_string(),
        ))
    }

    fn current_claim_is_authenticated(
        &self,
        claim: &NativeProviderClaim,
    ) -> Result<bool, GenerationAbilityStoreError> {
        let digest = current_claim_digest(claim)?;
        self.authenticated_current_claims
            .lock()
            .map(|claims| claims.contains(&digest))
            .map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "authenticated native owner claim set is unavailable".to_string(),
                )
            })
    }

    fn mark_current_claim_authenticated(
        &self,
        claim: &NativeProviderClaim,
    ) -> Result<(), GenerationAbilityStoreError> {
        let digest = current_claim_digest(claim)?;
        self.authenticated_current_claims
            .lock()
            .map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "authenticated native owner claim set is unavailable".to_string(),
                )
            })?
            .insert(digest);
        Ok(())
    }

    pub(in crate::config_eval::ability_store::inventory) fn mark_persisted_current_claims_authenticated(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        for claim in ledger.owners.iter().flat_map(|owner| &owner.claim_by) {
            if self.classify_current_journal(
                &claim.generation,
                &claim.transaction,
                claim.plan,
                "provider owner claim",
            )? {
                self.mark_current_claim_authenticated(claim)?;
            }
        }
        Ok(())
    }

    fn require_current_effect_intent_claims(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        let effect_intents = self
            .replayed_current_effect_intents
            .lock()
            .map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "current native effect-intent replay set is unavailable".to_string(),
                )
            })?
            .clone();
        for (operation_id, attempt) in effect_intents {
            let Some(operation) = self.operations.get(&operation_id.operation) else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current EffectIntent operation is absent from its checked owner claims"
                        .to_string(),
                ));
            };
            let Some((owner_identity, owner_handler)) = operation
                .owner
                .as_ref()
                .zip(operation.owner_handler.as_ref())
            else {
                continue;
            };
            if operation.admits_receipt_source
                || operation.operation.target.lifetime != ResourceLifetime::Persistent
                || !operation.operation.accesses.iter().any(|access| {
                    access.resource == operation.operation.target.resource && access.mode.is_write()
                })
            {
                continue;
            }
            let owners = ledger
                .owners
                .iter()
                .filter(|owner| {
                    owner.resource == operation.operation.target.resource
                        && &owner.identity == owner_identity
                        && &owner.handler == owner_handler
                })
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current owner-write EffectIntent lacks one exact durable owner row"
                        .to_string(),
                ));
            };
            let claimed = owner.claim_by.iter().any(|claim| {
                claim.generation == self.generation
                    && claim.transaction == self.transaction
                    && claim.plan == self.plan
                    && claim.operation == operation_id
                    && claim.attempt == attempt
                    && claim.artifacts == self.artifacts
            });
            let intent_position = self.dispatch_positions.get(&operation_id.operation);
            let established = owner.established_by.as_ref().is_some_and(|establishment| {
                establishment.generation == self.generation
                    && establishment.transaction == self.transaction
                    && establishment.plan == self.plan
                    && establishment.artifacts == self.artifacts
                    && intent_position
                        .zip(
                            self.dispatch_positions
                                .get(&establishment.operation.operation),
                        )
                        .is_some_and(|(intent, successful)| intent <= successful)
            });
            if !claimed && !established {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current owner-write EffectIntent lacks its exact durable claim or establishment"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_candidate_claim_shape(
        &self,
        _owner: &NativeProviderOwner,
        claim: &NativeProviderClaim,
    ) -> Result<(), GenerationAbilityStoreError> {
        validate_generation_name(&claim.generation)?;
        if claim.operation.plan != claim.plan || claim.attempt == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider owner claim provenance is malformed".to_string(),
            ));
        }
        Ok(())
    }

    pub(in crate::config_eval::ability_store::inventory) fn authenticate_candidate_claim(
        &self,
        owner: &NativeProviderOwner,
        claim: &NativeProviderClaim,
    ) -> Result<bool, GenerationAbilityStoreError> {
        self.validate_candidate_claim_shape(owner, claim)?;
        if self.classify_current_journal(
            &claim.generation,
            &claim.transaction,
            claim.plan,
            "provider owner claim",
        )? {
            return self.authenticate_current_provider_claim(owner, claim);
        }
        let terminal = self
            .authenticated_retained_terminal_result(
                &claim.generation,
                &claim.transaction,
                claim.plan,
            )?
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "unestablished provider owner claim has no terminal marker and journal"
                        .to_string(),
                )
            })?;
        if terminal != aos_ability_model::document::TerminalResult::SettledFailure {
            return Err(GenerationAbilityStoreError::Conflict(
                "unestablished provider owner claim is not protected by a settled failure"
                    .to_string(),
            ));
        }
        let profile = self.ledger_path.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource ledger has no profile parent".to_string(),
            )
        })?;
        let retained = super::super::super::RetainedAbilityDiagnosticSource::load_from_profile(
            profile.join(&claim.generation),
            &claim.transaction,
            self.supported_features.clone(),
            profile,
        )?;
        authenticate_retained_provenance_artifacts(
            retained.plan(),
            &claim.artifacts,
            "provider owner claim",
        )?;
        let operation = retained
            .plan()
            .operation(&claim.operation.operation)
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "unestablished provider owner claim operation is absent".to_string(),
                )
            })?;
        let expected =
            operation_provider_identity(retained.plan(), operation, retained.provider_adoptions())?;
        if expected.as_ref() != Some(&(owner.identity.clone(), owner.handler.clone()))
            || operation.target.lifetime != ResourceLifetime::Persistent
            || claim.attempt > operation.recovery.retry.max_attempts().get()
            || !operation
                .accesses
                .iter()
                .any(|access| access.resource == owner.resource && access.mode.is_write())
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "unestablished provider owner claim is not an exact checked owner write"
                    .to_string(),
            ));
        }

        retained.operation_reached_effect_intent(
            aos_ability_runtime::journal::JournalLimits::default(),
            &claim.operation,
            claim.attempt,
            terminal,
        )
    }

    fn validate_receipt_source(
        &self,
        owner: &NativeProviderOwner,
        receipt: &NativeProviderAdoptionReceipt,
    ) -> Result<(), GenerationAbilityStoreError> {
        let establishment = &receipt.source_establishment;
        if receipt.source_generation != establishment.generation
            || receipt.source_transaction != establishment.transaction
            || receipt.source_plan != establishment.plan
            || (receipt.consumer_requirement.is_some() && receipt.linked_verification.is_none())
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider adoption receipt source lineage is not canonical".to_string(),
            ));
        }
        validate_receipt_artifact_union(&receipt.source_artifacts, &establishment.artifacts)?;
        let source_owner = NativeProviderOwner {
            resource: owner.resource.clone(),
            physical: owner.physical.clone(),
            identity: receipt.source.clone(),
            handler: receipt.source_handler.clone(),
            generation: receipt.source_generation.clone(),
            transaction: receipt.source_transaction.clone(),
            plan: receipt.source_plan,
            artifacts: establishment.artifacts.clone(),
            claim_by: Vec::new(),
            established_by: Some(establishment.clone()),
            adoption: None,
        };
        self.authenticate_source_establishment(&source_owner, establishment)
    }

    pub(in crate::config_eval::ability_store::inventory) fn authenticate_source_establishment(
        &self,
        owner: &NativeProviderOwner,
        establishment: &NativeProviderEstablishment,
    ) -> Result<(), GenerationAbilityStoreError> {
        validate_generation_name(&establishment.generation)?;
        if establishment.generation != owner.generation
            || establishment.transaction != owner.transaction
            || establishment.plan != owner.plan
            || establishment.operation.plan != establishment.plan
            || establishment.attempt == 0
            || establishment.artifacts != owner.artifacts
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider adoption source establishment differs from its durable owner row"
                    .to_string(),
            ));
        }
        let is_current = self.classify_current_journal(
            &establishment.generation,
            &establishment.transaction,
            establishment.plan,
            "provider owner establishment",
        )?;
        if is_current {
            let terminal = self.authenticated_retained_terminal_result(
                &establishment.generation,
                &establishment.transaction,
                establishment.plan,
            )?;
            let successful = self
                .replayed_current_successes
                .lock()
                .map_err(|_| {
                    GenerationAbilityStoreError::Conflict(
                        "current native success replay set is unavailable".to_string(),
                    )
                })?
                .contains(&(establishment.operation.clone(), establishment.attempt));
            let operation = self
                .operations
                .get(&establishment.operation.operation)
                .ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(
                        "current provider owner establishment operation is absent".to_string(),
                    )
                })?;
            if !matches!(
                terminal,
                Some(aos_ability_model::document::TerminalResult::Succeeded)
                    | Some(aos_ability_model::document::TerminalResult::SettledFailure)
            ) || !successful
                || operation.owner.as_ref() != Some(&owner.identity)
                || operation.owner_handler.as_ref() != Some(&owner.handler)
                || operation.operation.target.resource != owner.resource
                || operation.operation.target.lifetime != ResourceLifetime::Persistent
                || !operation
                    .operation
                    .accesses
                    .iter()
                    .any(|access| access.resource == owner.resource && access.mode.is_write())
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current provider owner establishment lacks exact successful replay evidence"
                        .to_string(),
                ));
            }
            return Ok(());
        }
        let terminal = self
            .authenticated_retained_terminal_result(
                &establishment.generation,
                &establishment.transaction,
                establishment.plan,
            )?
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption source establishment has no terminal marker and journal"
                        .to_string(),
                )
            })?;
        if !matches!(
            terminal,
            aos_ability_model::document::TerminalResult::Succeeded
                | aos_ability_model::document::TerminalResult::SettledFailure
        ) {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider adoption source establishment is not terminal".to_string(),
            ));
        }
        let profile = self.ledger_path.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native owner ledger has no profile directory".to_string(),
            )
        })?;
        let source = super::super::super::RetainedAbilityDiagnosticSource::load_from_profile(
            profile.join(&establishment.generation),
            &establishment.transaction,
            self.supported_features.clone(),
            profile,
        )?;
        authenticate_retained_provenance_artifacts(
            source.plan(),
            &establishment.artifacts,
            "provider owner establishment",
        )?;
        let operation = source
            .plan()
            .operation(&establishment.operation.operation)
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption source establishment operation is absent".to_string(),
                )
            })?;
        let expected =
            operation_provider_identity(source.plan(), operation, source.provider_adoptions())?;
        if expected.as_ref() != Some(&(owner.identity.clone(), owner.handler.clone()))
            || operation.target.lifetime != ResourceLifetime::Persistent
            || !operation
                .accesses
                .iter()
                .any(|access| access.resource == owner.resource && access.mode.is_write())
            || !source.operation_succeeded(
                aos_ability_runtime::journal::JournalLimits::default(),
                &establishment.operation,
                establishment.attempt,
                terminal,
            )?
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "provider adoption source establishment is not an exact successful owner write"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn allows_effect_free_linked_adoption_recovery(
        &self,
        owner: &NativeProviderOwner,
        receipt: &NativeProviderAdoptionReceipt,
    ) -> Result<bool, GenerationAbilityStoreError> {
        if Some(receipt.authority) != self.transition_authority
            || self.operations.values().any(|operation| {
                operation
                    .operation
                    .accesses
                    .iter()
                    .any(|access| access.resource == owner.resource && access.mode.is_write())
            })
        {
            return Ok(false);
        }
        let exact_healthy_observation = self
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
        let Some(establishment) = owner.established_by.as_ref() else {
            return Ok(false);
        };
        if !exact_healthy_observation {
            return Ok(false);
        }

        self.validate_receipt_source(owner, receipt)?;
        self.authenticate_source_establishment(owner, establishment)?;
        Ok(true)
    }

    fn validate_consumer_replacement_handoffs(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        for owner in ledger
            .owners
            .iter()
            .filter(|owner| owner.adoption.is_some())
        {
            let receipt = owner.adoption.as_ref().ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "provider adoption receipt disappeared during lifecycle preflight".to_string(),
                )
            })?;
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
                .collect::<Vec<_>>();
            let [adoption] = matching_adoptions.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider replacement lacks one exact sealed adoption during lifecycle preflight"
                        .to_string(),
                ));
            };

            let stops = self.operations.iter().filter(|(_, operation)| {
                operation.operation.target.resource == owner.resource
                    && operation.owner.as_ref() == Some(&receipt.source)
                    && operation.owner_handler.as_ref() == Some(&receipt.source_handler)
                    && matches!(
                        operation.operation.family,
                        aos_ability_model::OperationFamily::ServiceLifecycle {
                            action: aos_ability_model::ServiceAction::Stop
                        }
                    )
            });
            let acquisitions =
                self.operations.iter().filter(|(_, operation)| {
                    operation.operation.target.resource == owner.resource
                        && operation.binding == adoption.candidate.handler_binding
                        && operation.operation.method == adoption.candidate.handler_method
                        && operation.owner.as_ref() == Some(&owner.identity)
                        && operation.owner_handler.as_ref() == Some(&owner.handler)
                        && operation.operation.target.lifetime == ResourceLifetime::Persistent
                        && operation.operation.accesses.iter().any(|access| {
                            access.resource == owner.resource && access.mode.is_write()
                        })
                });
            let starts = self.operations.iter().filter(|(_, operation)| {
                operation.operation.target.resource == owner.resource
                    && operation.retains_consumer
                    && operation.owner.as_ref() == Some(&owner.identity)
                    && operation.owner_handler.as_ref() == Some(&owner.handler)
                    && matches!(
                        operation.operation.family,
                        aos_ability_model::OperationFamily::ServiceLifecycle {
                            action: aos_ability_model::ServiceAction::Start
                                | aos_ability_model::ServiceAction::Restart
                        }
                    )
            });
            let stop_keys = stops.map(|(key, _)| key).collect::<Vec<_>>();
            let acquisition_keys = acquisitions.map(|(key, _)| key).collect::<Vec<_>>();
            let start_keys = starts.map(|(key, _)| key).collect::<Vec<_>>();
            if stop_keys.is_empty()
                && acquisition_keys.is_empty()
                && start_keys.is_empty()
                && self.allows_effect_free_linked_adoption_recovery(owner, receipt)?
            {
                continue;
            }
            let ([stop], [acquisition], [start]) = (
                stop_keys.as_slice(),
                acquisition_keys.as_slice(),
                start_keys.as_slice(),
            ) else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider replacement requires one exact source Stop, candidate acquisition, and candidate lifecycle operation before native effects"
                        .to_string(),
                ));
            };
            if !self.has_required_success_path(stop, acquisition) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider replacement acquisition lacks a RequiredSuccess path from its source Stop"
                        .to_string(),
                ));
            }
            if !self.has_required_success_path(stop, start) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "provider replacement candidate lacks a RequiredSuccess path from its source Stop"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn has_required_success_path(
        &self,
        source: &aos_ability_model::ScopedOperationKey,
        target: &aos_ability_model::ScopedOperationKey,
    ) -> bool {
        let source = aos_ability_model::PlanNodeKey::Operation {
            key: source.clone(),
        };
        let target = aos_ability_model::PlanNodeKey::Operation {
            key: target.clone(),
        };
        let mut pending = vec![source];
        let mut visited = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if node == target {
                return true;
            }
            if !visited.insert(node.clone()) {
                continue;
            }
            pending.extend(
                self.required_success_edges
                    .iter()
                    .filter(|(from, _)| from == &node)
                    .map(|(_, to)| to.clone()),
            );
        }
        false
    }

    pub(in crate::config_eval::ability_store::inventory) fn has_checked_consumer_repair(
        &self,
        ledger: &NativeResourceLedger,
        consumer: &ActiveNativeConsumer,
        consumer_handler: Option<&NativeProviderHandlerIdentity>,
    ) -> bool {
        let Some(consumer_owner) = consumer.owner.as_ref() else {
            return false;
        };
        let Some(consumer_handler) = consumer_handler else {
            return false;
        };
        let owner = ledger
            .owners
            .iter()
            .find(|owner| owner.resource == consumer.logical);

        self.operations.values().any(|operation| {
            if !operation.retains_consumer
                || operation.operation.target.resource != consumer.logical
                || operation.operation.target.lifetime != ResourceLifetime::Persistent
                || !operation
                    .operation
                    .accesses
                    .iter()
                    .any(|access| access.resource == consumer.logical && access.mode.is_write())
            {
                return false;
            }

            let repairs_same_owner = operation.owner.as_ref() == Some(consumer_owner)
                && operation.owner_handler.as_ref() == Some(consumer_handler);
            let repairs_adopted_owner = owner.is_some_and(|owner| {
                owner.adoption.as_ref().is_some_and(|receipt| {
                    receipt.source == *consumer_owner
                        && receipt.source_handler == *consumer_handler
                        && operation.owner.as_ref() == Some(&owner.identity)
                        && operation.owner_handler.as_ref() == Some(&owner.handler)
                })
            });

            repairs_same_owner || repairs_adopted_owner
        })
    }

    fn validate_observed_consumer_repairs_before_effects(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        for (resource, observation) in &self.linked_recovery_observations {
            if !matches!(
                observation,
                aos_ability_plan::RuntimeResourceState::Absent
                    | aos_ability_plan::RuntimeResourceState::Present {
                        health: aos_ability_plan::RuntimeResourceHealth::Stopped,
                        ..
                    }
            ) {
                continue;
            }
            let consumers = ledger
                .consumers
                .iter()
                .filter(|consumer| consumer.logical == *resource)
                .collect::<Vec<_>>();
            if !consumers.is_empty() {
                for consumer in consumers {
                    let owner_handler =
                        super::super::retained_consumer_owner_handler(ledger, consumer)?;
                    if !self.has_checked_consumer_repair(ledger, consumer, owner_handler) {
                        return Err(GenerationAbilityStoreError::Conflict(
                            "stopped or absent native consumer lacks an exact checked Start, Reload, or Restart repair"
                                .to_string(),
                        ));
                    }
                }
                continue;
            }

            let owners = ledger
                .owners
                .iter()
                .filter(|owner| owner.resource == *resource)
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                continue;
            };
            let has_repair = self.operations.values().any(|operation| {
                operation.retains_consumer
                    && operation.operation.target.resource == *resource
                    && operation.operation.target.lifetime == ResourceLifetime::Persistent
                    && operation.owner.as_ref() == Some(&owner.identity)
                    && operation.owner_handler.as_ref() == Some(&owner.handler)
                    && operation
                        .operation
                        .accesses
                        .iter()
                        .any(|access| access.resource == *resource && access.mode.is_write())
            });
            if !has_repair {
                return Err(GenerationAbilityStoreError::Conflict(
                    "stopped or absent stateful native resource lacks an exact checked Start, Reload, or Restart repair"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_retained_provider_owners(
        &self,
        ledger: &NativeResourceLedger,
        current_contains_resource: &impl Fn(&ResourceId) -> bool,
    ) -> Result<(), GenerationAbilityStoreError> {
        for owner in &ledger.owners {
            self.validate_retained_owner_provenance(owner)?;
        }
        self.require_current_owner_rows(ledger, &self.current_owner_selections)?;
        if ledger.owners.iter().any(|owner| {
            current_contains_resource(&owner.resource)
                && !self.desired_resources.contains(&owner.resource)
        }) {
            return Err(GenerationAbilityStoreError::Conflict(
                "removing a retained durable owner requires typed deletion and tombstone evidence"
                    .to_string(),
            ));
        }
        if ledger.owners.iter().any(|owner| {
            !self.desired_resources.contains(&owner.resource)
                && !current_contains_resource(&owner.resource)
        }) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native ownership ledger contains an owner outside the selected desired/current resources"
                    .to_string(),
            ));
        }
        if ledger.consumers.iter().any(|consumer| {
            !self.desired_resources.contains(&consumer.logical)
                && !current_contains_resource(&consumer.logical)
        }) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native ownership ledger contains a consumer outside the selected desired/current resources"
                    .to_string(),
            ));
        }
        for incumbent in ledger.owners.iter().filter(|owner| {
            current_contains_resource(&owner.resource)
                && self.desired_resources.contains(&owner.resource)
        }) {
            let selections = self
                .desired_owner_selections
                .iter()
                .filter(|selection| selection.resource == incumbent.resource)
                .collect::<Vec<_>>();
            let [selection] = selections.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "retained stateful resource lacks exactly one desired owner selection"
                        .to_string(),
                ));
            };
            if selection.identity == incumbent.identity && selection.handler == incumbent.handler {
                continue;
            }

            let matching_adoptions = self
                .adoptions
                .iter()
                .filter(|adoption| {
                    adoption.resource == incumbent.resource
                        && NativeProviderIdentity::from_endpoint(&adoption.source)
                            == incumbent.identity
                        && handler_from_endpoint(&adoption.source) == incumbent.handler
                        && NativeProviderIdentity::from_endpoint(&adoption.candidate)
                            == selection.identity
                        && handler_from_endpoint(&adoption.candidate) == selection.handler
                })
                .count();
            if matching_adoptions != 1 {
                return Err(GenerationAbilityStoreError::Conflict(
                    "retained stateful resource lost its exact selected owner or sealed handler without one exact adoption"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    pub(in crate::config_eval::ability_store::inventory) fn require_current_owner_rows(
        &self,
        ledger: &NativeResourceLedger,
        selections: &[NativeProviderSelection],
    ) -> Result<(), GenerationAbilityStoreError> {
        for selection in selections {
            let owners = ledger
                .owners
                .iter()
                .filter(|owner| owner.resource == selection.resource)
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current stateful resource lacks exactly one durable owner row".to_string(),
                ));
            };
            let direct = owner.identity == selection.identity && owner.handler == selection.handler;
            let retained_source = owner.adoption.as_ref().is_some_and(|receipt| {
                receipt.source == selection.identity && receipt.source_handler == selection.handler
            });
            if !direct && !retained_source {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current stateful resource differs from its authenticated durable owner row"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(in crate::config_eval::ability_store::inventory) fn authenticate_retained_consumers_before_effects(
        &self,
        ledger: &NativeResourceLedger,
    ) -> Result<(), GenerationAbilityStoreError> {
        for consumer in &ledger.consumers {
            let owner_handler = super::super::retained_consumer_owner_handler(ledger, consumer)?;
            let current = self.classify_current_journal(
                &consumer.generation,
                &consumer.transaction,
                consumer.plan,
                "consumer",
            )?;
            if current {
                let operation = self
                    .operations
                    .get(&consumer.operation.operation)
                    .ok_or_else(|| {
                        GenerationAbilityStoreError::Conflict(
                            "current native consumer operation is absent".to_string(),
                        )
                    })?;
                if consumer.operation.plan != self.plan
                    || consumer.binding != operation.binding
                    || consumer.consumer != operation.consumer
                    || consumer.provider != operation.provider
                    || consumer.logical != operation.operation.target.resource
                    || consumer.owner != operation.owner
                    || owner_handler != operation.owner_handler.as_ref()
                    || consumer.desired_revision
                        != self.desired_revisions.get(&consumer.logical).copied()
                    || consumer.artifacts != self.artifacts
                    || !operation.retains_consumer
                    || consumer.attempt > operation.operation.recovery.retry.max_attempts().get()
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "current native consumer differs from its exact checked claim".to_string(),
                    ));
                }
                if let Some(owner_identity) = &consumer.owner {
                    let owner = ledger
                        .owners
                        .iter()
                        .find(|owner| {
                            owner.resource == consumer.logical
                                && (&owner.identity == owner_identity
                                    || owner
                                        .adoption
                                        .as_ref()
                                        .is_some_and(|receipt| &receipt.source == owner_identity))
                        })
                        .ok_or_else(|| {
                            GenerationAbilityStoreError::Conflict(
                                "current native consumer lost its durable owner claim".to_string(),
                            )
                        })?;
                    if !owner.claim_by.iter().any(|claim| {
                        claim.generation == consumer.generation
                            && claim.transaction == consumer.transaction
                            && claim.plan == consumer.plan
                            && claim.operation == consumer.operation
                            && claim.attempt == consumer.attempt
                            && claim.artifacts == consumer.artifacts
                    }) {
                        return Err(GenerationAbilityStoreError::Conflict(
                            "current native consumer differs from its exact owner claim"
                                .to_string(),
                        ));
                    }
                }
                continue;
            }
            if !self.consumer_operation_succeeded(consumer, owner_handler)? {
                return Err(GenerationAbilityStoreError::Conflict(
                    "retained native consumer lacks exact successful checked provenance"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}
