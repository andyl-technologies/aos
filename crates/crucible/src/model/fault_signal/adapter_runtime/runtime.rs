//! Transactional contribution state for one production adapter family.

use super::*;

/// Transactional contribution state for one production adapter family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionalAdapterRuntime {
    adapter: FaultAdapter,
    manifest: FaultCapabilityManifest,
    resource_limits: FaultResourceLimits,
    active: ActiveContributionTable,
    impulse_sequence: u64,
    digest: ContentHash,
    prepared: Option<PreparedAdapterState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedAdapterState {
    transaction: ContentHash,
    active: ActiveContributionTable,
    impulse_sequence: u64,
    digest: ContentHash,
    results: Vec<PreparedActionResult>,
}

impl TransactionalAdapterRuntime {
    /// Creates empty adapter state after validating its backend identity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::AdapterManifestMismatch`] when `manifest`
    /// names another adapter family.
    pub fn new(
        adapter: FaultAdapter,
        manifest: FaultCapabilityManifest,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        resource_limits
            .validate()
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let family = adapter_name(adapter);
        if manifest.backend.as_str() != family
            && !manifest.backend.as_str().starts_with(&format!("{family}-"))
        {
            return Err(FaultRuntimeError::AdapterManifestMismatch);
        }
        let active = ActiveContributionTable::default();
        let digest = state_digest(adapter, 0, &active, resource_limits);
        Ok(Self {
            adapter,
            manifest,
            resource_limits,
            active,
            impulse_sequence: 0,
            digest,
            prepared: None,
        })
    }

    /// Returns the adapter family.
    #[must_use]
    pub const fn adapter(&self) -> FaultAdapter {
        self.adapter
    }

    /// Returns committed contributions in canonical composition groups.
    #[must_use]
    pub fn composition_groups(&self) -> Vec<EffectComposition> {
        self.active.composition_groups()
    }

    /// Returns the committed state identity.
    #[must_use]
    pub const fn state_digest(&self) -> ContentHash {
        self.digest
    }

    /// Encodes the complete committed contribution and impulse state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::AdapterTransactionPending`] while a batch
    /// is prepared, or [`FaultRuntimeError::AdapterCheckpointCodec`] when the
    /// canonical payload cannot be encoded.
    pub fn checkpoint(&self) -> Result<AdapterCheckpointState, FaultRuntimeError> {
        if self.prepared.is_some() {
            return Err(FaultRuntimeError::AdapterTransactionPending);
        }
        let entries = self
            .active
            .entries()
            .iter()
            .map(|(key, contribution)| AdapterContributionWire {
                key: key.clone(),
                request: (*contribution.request).clone(),
                mapped_parameters: contribution.mapped_parameters,
                mapping_output: (*contribution.mapping_output).clone(),
                transition_sequence: contribution.transition_sequence,
            })
            .collect();
        let bytes = serde_json::to_vec(&AdapterCheckpointWire {
            semantic_version: ADAPTER_CHECKPOINT_VERSION,
            adapter: self.adapter,
            resource_limits: self.resource_limits,
            impulse_sequence: self.impulse_sequence,
            entries,
        })
        .map_err(|_| FaultRuntimeError::AdapterCheckpointCodec)?;
        AdapterCheckpointState::new(ADAPTER_CHECKPOINT_VERSION, bytes, self.resource_limits)
    }

    /// Restores and revalidates one committed production-adapter state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the payload, adapter identity,
    /// contribution contract, or live capability manifest does not match.
    pub fn restore(
        adapter: FaultAdapter,
        manifest: FaultCapabilityManifest,
        checkpoint: &AdapterCheckpointState,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        checkpoint.validate(resource_limits)?;
        if checkpoint.semantic_version != ADAPTER_CHECKPOINT_VERSION {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        }
        let wire: AdapterCheckpointWire = serde_json::from_slice(&checkpoint.bytes)
            .map_err(|_| FaultRuntimeError::AdapterCheckpointCodec)?;
        if wire.semantic_version != ADAPTER_CHECKPOINT_VERSION
            || wire.adapter != adapter
            || wire.resource_limits != resource_limits
        {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        }
        let mut runtime = Self::new(adapter, manifest, resource_limits)?;
        for entry in wire.entries {
            let descriptor = entry.request.kind().descriptor();
            let capability = FaultCapabilityId::parse(entry.request.capability())
                .map_err(FaultRuntimeError::Contract)?;
            if descriptor.adapter != adapter
                || !runtime.manifest.capabilities.contains(&capability)
                || entry.key.effect != entry.request.kind()
            {
                return Err(FaultRuntimeError::AdapterActionMismatch);
            }
            runtime.active.activate(
                entry.key,
                ActiveEffectContribution {
                    request: Arc::new(entry.request),
                    mapped_parameters: entry.mapped_parameters,
                    mapping_output: Arc::new(entry.mapping_output),
                    transition_sequence: entry.transition_sequence,
                },
                resource_limits,
            )?;
        }
        runtime.impulse_sequence = wire.impulse_sequence;
        runtime.digest = state_digest(
            adapter,
            runtime.impulse_sequence,
            &runtime.active,
            resource_limits,
        );
        Ok(runtime)
    }

    fn validate_action(&self, action: &ResolvedBindingAction) -> Result<(), FaultRuntimeError> {
        let descriptor = action.effect.kind().descriptor();
        if descriptor.adapter != self.adapter
            || action.target.kind().adapter() != self.adapter
            || !descriptor.targets.contains(&action.target.kind())
            || !descriptor.phases.contains(&action.phase)
        {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let capability = FaultCapabilityId::parse(action.effect.capability())
            .map_err(FaultRuntimeError::Contract)?;
        if !self.manifest.capabilities.contains(&capability) {
            return Err(FaultRuntimeError::MissingCapability(capability));
        }
        match action.kind {
            BindingActionKind::UpsertPersistent | BindingActionKind::RemovePersistent
                if action.effect.lifetime() != EffectLifetime::Persistent =>
            {
                Err(FaultRuntimeError::NonPersistentActivation)
            }
            BindingActionKind::Apply if action.effect.lifetime() == EffectLifetime::Persistent => {
                Err(FaultRuntimeError::AdapterActionMismatch)
            }
            _ => Ok(()),
        }
    }

    fn rejection(
        &self,
        action: Option<&ResolvedBindingAction>,
        error: FaultRuntimeError,
    ) -> Box<RejectedActionBatch> {
        Box::new(RejectedActionBatch {
            error,
            observations: action
                .map(|action| FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: self.digest,
                })
                .into_iter()
                .collect(),
            rejected_action: action.map(ResolvedBindingAction::id),
        })
    }
}

impl FaultActionSink for TransactionalAdapterRuntime {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(self.rejection(None, FaultRuntimeError::AdapterTransactionPending));
        }
        let mut active = self.active.clone();
        let mut impulse_sequence = self.impulse_sequence;
        let mut action_ids = Vec::with_capacity(actions.len());
        let mut seen = BTreeSet::new();
        for action in actions {
            self.validate_action(action)
                .map_err(|error| self.rejection(Some(action), error))?;
            let id = action.id();
            if !seen.insert(id) {
                return Err(self.rejection(Some(action), FaultRuntimeError::DuplicateAdapterAction));
            }
            let key = ActiveContributionKey {
                target: action.target.clone(),
                phase: action.phase,
                effect: action.effect.kind(),
                binding: action.binding.clone(),
            };
            match action.kind {
                BindingActionKind::UpsertPersistent => {
                    active
                        .activate(
                            key,
                            ActiveEffectContribution {
                                request: action.effect.clone(),
                                mapped_parameters: action.mapped_digest,
                                mapping_output: action.mapping_output.clone(),
                                transition_sequence: action.transition_sequence,
                            },
                            self.resource_limits,
                        )
                        .map_err(|error| self.rejection(Some(action), error))?;
                }
                BindingActionKind::RemovePersistent => {
                    let _ = active.deactivate(&key);
                }
                BindingActionKind::Apply => {
                    impulse_sequence = impulse_sequence.checked_add(1).ok_or_else(|| {
                        self.rejection(
                            Some(action),
                            FaultRuntimeError::SequenceOverflow("adapter_impulse"),
                        )
                    })?;
                }
            }
            action_ids.push(id);
        }
        let digest = state_digest(
            self.adapter,
            impulse_sequence,
            &active,
            self.resource_limits,
        );
        let transaction = transaction_digest(self.digest, digest, &action_ids);
        let results: Vec<PreparedActionResult> = actions
            .iter()
            .zip(action_ids)
            .map(|(action, id)| PreparedActionResult {
                action: id,
                precondition: Some(self.digest),
                observation: FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: match action.kind {
                        BindingActionKind::UpsertPersistent => {
                            FaultObservationKind::BindingActivation
                        }
                        BindingActionKind::RemovePersistent => {
                            FaultObservationKind::BindingDeactivation
                        }
                        BindingActionKind::Apply => FaultObservationKind::EffectCommitted,
                    },
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: digest,
                },
            })
            .collect();
        self.prepared = Some(PreparedAdapterState {
            transaction,
            active,
            impulse_sequence,
            digest,
            results: results.clone(),
        });
        Ok(PreparedActionBatch {
            transaction,
            results,
        })
    }

    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(FaultRuntimeError::UnknownAdapterTransaction)?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultRuntimeError::UnknownAdapterTransaction);
        }
        Ok(())
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            FaultActionCommitError::Rejected(
                self.rejection(None, FaultRuntimeError::UnknownAdapterTransaction),
            )
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Rejected(
                self.rejection(None, FaultRuntimeError::UnknownAdapterTransaction),
            ));
        }
        self.active = prepared.active;
        self.impulse_sequence = prepared.impulse_sequence;
        self.digest = prepared.digest;
        Ok(PreparedActionBatch {
            transaction,
            results: prepared.results,
        })
    }
}

pub(super) fn adapter_name(adapter: FaultAdapter) -> &'static str {
    match adapter {
        FaultAdapter::Network => "network",
        FaultAdapter::Storage => "storage",
        FaultAdapter::Node => "node",
    }
}

pub(super) fn state_digest(
    adapter: FaultAdapter,
    impulse_sequence: u64,
    active: &ActiveContributionTable,
    resource_limits: FaultResourceLimits,
) -> ContentHash {
    let mut material = format!(
        "adapter={};impulses={impulse_sequence};\n{}",
        adapter_name(adapter),
        resource_limits.canonical_material(),
    );
    for group in active.composition_groups() {
        material.push_str(&group.digest.to_hex());
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.production-adapter-state.v2", &material)
}

pub(super) fn transaction_digest(
    before: ContentHash,
    after: ContentHash,
    actions: &[ContentHash],
) -> ContentHash {
    let mut material = format!("before={};after={};", before.to_hex(), after.to_hex());
    for action in actions {
        material.push_str(&action.to_hex());
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.adapter-transaction.v1", &material)
}

pub(super) fn mirrored_transaction_digest(
    state: ContentHash,
    backend: ContentHash,
    actions: &[ContentHash],
) -> ContentHash {
    let mut material = format!("state={};backend={};", state.to_hex(), backend.to_hex());
    for action in actions {
        material.push_str(&action.to_hex());
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.mirrored-adapter-transaction.v1", &material)
}
