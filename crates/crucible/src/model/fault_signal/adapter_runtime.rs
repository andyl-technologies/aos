//! Atomic state shared by executable fault adapters.
//!
//! Signal evaluation prepares complete action batches here before a domain
//! adapter exposes their effects. The committed contribution groups are the
//! sole input to network, storage, and node opportunity resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;

const ADAPTER_CHECKPOINT_VERSION: u16 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterCheckpointWire {
    semantic_version: u16,
    adapter: FaultAdapter,
    resource_limits: FaultResourceLimits,
    impulse_sequence: u64,
    entries: Vec<AdapterContributionWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterContributionWire {
    key: ActiveContributionKey,
    request: EffectRequest,
    mapped_parameters: ContentHash,
    mapping_output: ResolvedMappingOutput,
    transition_sequence: u64,
}

/// Live capability manifests for all executable adapter families.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAdapterManifests {
    /// Network backend capabilities.
    pub network: FaultCapabilityManifest,
    /// Storage and 9p backend capabilities.
    pub storage: FaultCapabilityManifest,
    /// Node and QEMU backend capabilities.
    pub node: FaultCapabilityManifest,
}

/// One atomic transaction spanning network, storage, and node adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionalFaultAdapters {
    network: TransactionalAdapterRuntime,
    storage: TransactionalAdapterRuntime,
    node: TransactionalAdapterRuntime,
    prepared: Option<PreparedAdapterSet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedAdapterSet {
    transaction: ContentHash,
    actions: Vec<ContentHash>,
    network: Option<ContentHash>,
    storage: Option<ContentHash>,
    node: Option<ContentHash>,
}

/// One transaction mirrored into canonical adapter state and a live backend.
pub(super) struct MirroredFaultActionSink<'a, B> {
    state: &'a mut TransactionalFaultAdapters,
    backend: &'a mut B,
    prepared: Option<PreparedMirroredBatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedMirroredBatch {
    transaction: ContentHash,
    state_transaction: ContentHash,
    backend_transaction: ContentHash,
    state_before: TransactionalFaultAdapters,
}

impl<'a, B> MirroredFaultActionSink<'a, B>
where
    B: FaultActionSink,
{
    /// Couples canonical adapter state to one live production backend.
    #[must_use]
    pub(super) fn new(state: &'a mut TransactionalFaultAdapters, backend: &'a mut B) -> Self {
        Self {
            state,
            backend,
            prepared: None,
        }
    }

    fn abort_prepared(
        &mut self,
        prepared: &PreparedMirroredBatch,
    ) -> Result<(), FaultRuntimeError> {
        let state = self.state.abort_batch(prepared.state_transaction);
        let backend = self.backend.abort_batch(prepared.backend_transaction);
        if state.is_err() || backend.is_err() {
            *self.state = prepared.state_before.clone();
            return Err(FaultRuntimeError::AdapterTransactionRollback);
        }
        Ok(())
    }
}

impl<B> FaultActionSink for MirroredFaultActionSink<'_, B>
where
    B: FaultActionSink,
{
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::AdapterTransactionPending,
                observations: Vec::new(),
                rejected_action: None,
            }));
        }
        let state_before = self.state.clone();
        let backend_batch = self.backend.prepare_batch(actions)?;
        let state_batch = match self.state.prepare_batch(actions) {
            Ok(batch) => batch,
            Err(error) => {
                if self.backend.abort_batch(backend_batch.transaction).is_err() {
                    return Err(Box::new(RejectedActionBatch {
                        error: FaultRuntimeError::AdapterTransactionRollback,
                        observations: error.observations,
                        rejected_action: error.rejected_action,
                    }));
                }
                return Err(error);
            }
        };
        let expected = actions
            .iter()
            .map(ResolvedBindingAction::id)
            .collect::<Vec<_>>();
        let backend_actions = backend_batch
            .results
            .iter()
            .map(|result| result.action)
            .collect::<Vec<_>>();
        let state_actions = state_batch
            .results
            .iter()
            .map(|result| result.action)
            .collect::<Vec<_>>();
        if backend_actions != expected || state_actions != expected {
            let prepared = PreparedMirroredBatch {
                transaction: ContentHash::default(),
                state_transaction: state_batch.transaction,
                backend_transaction: backend_batch.transaction,
                state_before,
            };
            let error = if self.abort_prepared(&prepared).is_ok() {
                FaultRuntimeError::IncompleteAdapterState
            } else {
                FaultRuntimeError::AdapterTransactionRollback
            };
            return Err(Box::new(RejectedActionBatch {
                error,
                observations: Vec::new(),
                rejected_action: None,
            }));
        }
        let transaction = mirrored_transaction_digest(
            state_batch.transaction,
            backend_batch.transaction,
            &expected,
        );
        self.prepared = Some(PreparedMirroredBatch {
            transaction,
            state_transaction: state_batch.transaction,
            backend_transaction: backend_batch.transaction,
            state_before,
        });
        Ok(PreparedActionBatch {
            transaction,
            results: backend_batch.results,
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
        self.abort_prepared(&prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            FaultActionCommitError::Rejected(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::UnknownAdapterTransaction,
                observations: Vec::new(),
                rejected_action: None,
            }))
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Rejected(Box::new(
                RejectedActionBatch {
                    error: FaultRuntimeError::UnknownAdapterTransaction,
                    observations: Vec::new(),
                    rejected_action: None,
                },
            )));
        }
        let backend = match self.backend.commit_batch(prepared.backend_transaction) {
            Ok(committed) => committed,
            Err(FaultActionCommitError::Rejected(error)) => {
                let state_abort = self.state.abort_batch(prepared.state_transaction);
                *self.state = prepared.state_before;
                if state_abort.is_err() {
                    return Err(FaultActionCommitError::Fatal(
                        FaultRuntimeError::AdapterTransactionRollback,
                    ));
                }
                return Err(FaultActionCommitError::Rejected(error));
            }
            Err(FaultActionCommitError::Fatal(error)) => {
                *self.state = prepared.state_before;
                return Err(FaultActionCommitError::Fatal(error));
            }
        };
        if self.state.commit_batch(prepared.state_transaction).is_err() {
            *self.state = prepared.state_before;
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::AdapterTransactionRollback,
            ));
        }
        Ok(PreparedActionBatch {
            transaction,
            results: backend.results,
        })
    }
}

impl TransactionalFaultAdapters {
    /// Creates the three production adapter transaction domains.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a manifest names the wrong family.
    pub fn new(
        manifests: FaultAdapterManifests,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        Ok(Self {
            network: TransactionalAdapterRuntime::new(
                FaultAdapter::Network,
                manifests.network,
                resource_limits,
            )?,
            storage: TransactionalAdapterRuntime::new(
                FaultAdapter::Storage,
                manifests.storage,
                resource_limits,
            )?,
            node: TransactionalAdapterRuntime::new(
                FaultAdapter::Node,
                manifests.node,
                resource_limits,
            )?,
            prepared: None,
        })
    }

    /// Returns the committed runtime for one adapter family.
    #[must_use]
    pub const fn adapter(&self, adapter: FaultAdapter) -> &TransactionalAdapterRuntime {
        match adapter {
            FaultAdapter::Network => &self.network,
            FaultAdapter::Storage => &self.storage,
            FaultAdapter::Node => &self.node,
        }
    }

    /// Encodes all three committed adapter states for a fat checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] if an adapter has an in-flight transaction,
    /// its canonical state cannot be encoded, or the payload bound is exceeded.
    pub fn checkpoints(
        &self,
    ) -> Result<BTreeMap<FaultAdapter, AdapterCheckpointState>, FaultRuntimeError> {
        [
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ]
        .into_iter()
        .map(|adapter| Ok((adapter, self.adapter(adapter).checkpoint()?)))
        .collect()
    }

    /// Restores all three adapter transaction domains from a fat checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a checkpoint family is missing or
    /// added, a payload is corrupt, or restored state exceeds a live manifest.
    pub fn restore(
        manifests: FaultAdapterManifests,
        mut checkpoints: BTreeMap<FaultAdapter, AdapterCheckpointState>,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let network = checkpoints
            .remove(&FaultAdapter::Network)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        let storage = checkpoints
            .remove(&FaultAdapter::Storage)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        let node = checkpoints
            .remove(&FaultAdapter::Node)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        if !checkpoints.is_empty() {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        Ok(Self {
            network: TransactionalAdapterRuntime::restore(
                FaultAdapter::Network,
                manifests.network,
                &network,
                resource_limits,
            )?,
            storage: TransactionalAdapterRuntime::restore(
                FaultAdapter::Storage,
                manifests.storage,
                &storage,
                resource_limits,
            )?,
            node: TransactionalAdapterRuntime::restore(
                FaultAdapter::Node,
                manifests.node,
                &node,
                resource_limits,
            )?,
            prepared: None,
        })
    }

    fn adapter_mut(&mut self, adapter: FaultAdapter) -> &mut TransactionalAdapterRuntime {
        match adapter {
            FaultAdapter::Network => &mut self.network,
            FaultAdapter::Storage => &mut self.storage,
            FaultAdapter::Node => &mut self.node,
        }
    }

    fn abort_prepared(&mut self, prepared: &PreparedAdapterSet) -> Result<(), FaultRuntimeError> {
        for (adapter, transaction) in [
            (FaultAdapter::Network, prepared.network),
            (FaultAdapter::Storage, prepared.storage),
            (FaultAdapter::Node, prepared.node),
        ] {
            if let Some(transaction) = transaction {
                self.adapter_mut(adapter).abort_batch(transaction)?;
            }
        }
        Ok(())
    }
}

impl FaultActionSink for TransactionalFaultAdapters {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::AdapterTransactionPending,
                observations: Vec::new(),
                rejected_action: None,
            }));
        }
        let mut prepared = PreparedAdapterSet {
            transaction: ContentHash::default(),
            actions: actions.iter().map(ResolvedBindingAction::id).collect(),
            network: None,
            storage: None,
            node: None,
        };
        let mut by_action = std::collections::BTreeMap::new();
        for adapter in [
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ] {
            let subset = actions
                .iter()
                .filter(|action| action.effect.kind().descriptor().adapter == adapter)
                .cloned()
                .collect::<Vec<_>>();
            if subset.is_empty() {
                continue;
            }
            let batch = match self.adapter_mut(adapter).prepare_batch(&subset) {
                Ok(batch) => batch,
                Err(error) => {
                    if self.abort_prepared(&prepared).is_err() {
                        return Err(Box::new(RejectedActionBatch {
                            error: FaultRuntimeError::AdapterTransactionRollback,
                            observations: error.observations,
                            rejected_action: error.rejected_action,
                        }));
                    }
                    return Err(error);
                }
            };
            match adapter {
                FaultAdapter::Network => prepared.network = Some(batch.transaction),
                FaultAdapter::Storage => prepared.storage = Some(batch.transaction),
                FaultAdapter::Node => prepared.node = Some(batch.transaction),
            }
            for result in batch.results {
                by_action.insert(result.action, result);
            }
        }
        let results = match actions
            .iter()
            .map(|action| {
                by_action
                    .remove(&action.id())
                    .ok_or(FaultRuntimeError::IncompleteAdapterState)
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(results) if by_action.is_empty() => results,
            Ok(_) | Err(_) => {
                let error = if self.abort_prepared(&prepared).is_ok() {
                    FaultRuntimeError::IncompleteAdapterState
                } else {
                    FaultRuntimeError::AdapterTransactionRollback
                };
                return Err(Box::new(RejectedActionBatch {
                    error,
                    observations: Vec::new(),
                    rejected_action: None,
                }));
            }
        };
        let transactions = [prepared.network, prepared.storage, prepared.node]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        prepared.transaction = transaction_digest(
            self.network.state_digest(),
            self.node.state_digest(),
            &transactions,
        );
        let transaction = prepared.transaction;
        self.prepared = Some(prepared);
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
        self.abort_prepared(&prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            FaultActionCommitError::Rejected(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::UnknownAdapterTransaction,
                observations: Vec::new(),
                rejected_action: None,
            }))
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Rejected(Box::new(
                RejectedActionBatch {
                    error: FaultRuntimeError::UnknownAdapterTransaction,
                    observations: Vec::new(),
                    rejected_action: None,
                },
            )));
        }
        let mut by_action = BTreeMap::new();
        for (adapter, transaction) in [
            (FaultAdapter::Network, prepared.network),
            (FaultAdapter::Storage, prepared.storage),
            (FaultAdapter::Node, prepared.node),
        ] {
            if let Some(transaction) = transaction {
                let committed = self.adapter_mut(adapter).commit_batch(transaction)?;
                for result in committed.results {
                    by_action.insert(result.action, result);
                }
            }
        }
        let results = prepared
            .actions
            .iter()
            .map(|action| by_action.remove(action))
            .collect::<Option<Vec<_>>>()
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        if !by_action.is_empty() {
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ));
        }
        Ok(PreparedActionBatch {
            transaction,
            results,
        })
    }
}

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
                        BindingActionKind::Apply => FaultObservationKind::EffectApplied,
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

fn adapter_name(adapter: FaultAdapter) -> &'static str {
    match adapter {
        FaultAdapter::Network => "network",
        FaultAdapter::Storage => "storage",
        FaultAdapter::Node => "node",
    }
}

fn state_digest(
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

fn transaction_digest(
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

fn mirrored_transaction_digest(
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use super::*;

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
    }

    fn manifest(adapter: FaultAdapter) -> FaultCapabilityManifest {
        let capabilities = EffectKind::all()
            .iter()
            .filter(|kind| kind.descriptor().adapter == adapter)
            .map(|kind| {
                FaultCapabilityId::parse(kind.descriptor().capability)
                    .unwrap_or_else(|error| panic!("registry capability must be valid: {error}"))
            })
            .collect::<BTreeSet<_>>();
        FaultCapabilityManifest {
            backend: id(adapter_name(adapter)),
            capabilities,
            bounds: BTreeMap::new(),
        }
    }

    fn network_action() -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect must be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::UpsertPersistent,
            binding: id("outage-binding"),
            target: ResolvedFaultTarget::NetworkSegment {
                segment: id("wan-segment"),
                direction: FaultDirection::AToB,
            },
            phase: FaultPhase::Admit,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"mapped"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        }
    }

    fn manifests() -> FaultAdapterManifests {
        FaultAdapterManifests {
            network: manifest(FaultAdapter::Network),
            storage: manifest(FaultAdapter::Storage),
            node: manifest(FaultAdapter::Node),
        }
    }

    struct TransactionProbe {
        ledger: TransactionalFaultAdapters,
        reject_commit: bool,
        evidence: ContentHash,
    }

    impl TransactionProbe {
        fn new(reject_commit: bool) -> Self {
            Self {
                ledger: TransactionalFaultAdapters::new(
                    manifests(),
                    FaultResourceLimits::default(),
                )
                .unwrap_or_else(|error| panic!("transaction probe: {error}")),
                reject_commit,
                evidence: ContentHash::from_bytes(b"backend-evidence"),
            }
        }
    }

    impl FaultActionSink for TransactionProbe {
        fn prepare_batch(
            &mut self,
            actions: &[ResolvedBindingAction],
        ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
            self.ledger.prepare_batch(actions)
        }

        fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
            self.ledger.abort_batch(transaction)
        }

        fn commit_batch(
            &mut self,
            transaction: ContentHash,
        ) -> Result<PreparedActionBatch, FaultActionCommitError> {
            if self.reject_commit {
                self.ledger
                    .abort_batch(transaction)
                    .map_err(FaultActionCommitError::Fatal)?;
                return Err(FaultActionCommitError::Rejected(Box::new(
                    RejectedActionBatch {
                        error: FaultRuntimeError::AdapterActionMismatch,
                        observations: Vec::new(),
                        rejected_action: None,
                    },
                )));
            }
            let mut committed = self.ledger.commit_batch(transaction)?;
            for result in &mut committed.results {
                result.observation.evidence = self.evidence;
            }
            Ok(committed)
        }
    }

    #[test]
    fn prepared_state_is_invisible_until_commit_and_abort_is_exact() {
        let mut runtime = TransactionalAdapterRuntime::new(
            FaultAdapter::Network,
            manifest(FaultAdapter::Network),
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
        let initial = runtime.state_digest();
        let action = network_action();
        let prepared = runtime
            .prepare_batch(std::slice::from_ref(&action))
            .unwrap_or_else(|error| panic!("prepare: {}", error.error));
        assert_eq!(runtime.state_digest(), initial);
        assert!(runtime.composition_groups().is_empty());
        runtime
            .abort_batch(prepared.transaction)
            .unwrap_or_else(|error| panic!("abort: {error}"));
        assert_eq!(runtime.state_digest(), initial);

        let prepared = runtime
            .prepare_batch(&[action])
            .unwrap_or_else(|error| panic!("prepare again: {}", error.error));
        runtime
            .commit_batch(prepared.transaction)
            .unwrap_or_else(|error| panic!("commit: {error}"));
        assert_ne!(runtime.state_digest(), initial);
        assert_eq!(runtime.composition_groups().len(), 1);
    }

    #[test]
    fn capability_and_cross_adapter_checks_fail_before_staging() {
        let mut missing = manifest(FaultAdapter::Network);
        missing.capabilities.clear();
        let mut runtime = TransactionalAdapterRuntime::new(
            FaultAdapter::Network,
            missing,
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
        let action = network_action();
        let rejection = match runtime.prepare_batch(&[action]) {
            Ok(_) => panic!("missing capability must reject"),
            Err(rejection) => rejection,
        };
        assert!(matches!(
            rejection.error,
            FaultRuntimeError::MissingCapability(_)
        ));
        assert!(runtime.composition_groups().is_empty());
    }

    #[test]
    fn checkpoint_round_trip_revalidates_live_capabilities() {
        let mut runtime = TransactionalAdapterRuntime::new(
            FaultAdapter::Network,
            manifest(FaultAdapter::Network),
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
        let action = network_action();
        let prepared = runtime
            .prepare_batch(&[action])
            .unwrap_or_else(|error| panic!("prepare: {}", error.error));
        runtime
            .commit_batch(prepared.transaction)
            .unwrap_or_else(|error| panic!("commit: {error}"));

        let checkpoint = runtime
            .checkpoint()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        let restored = TransactionalAdapterRuntime::restore(
            FaultAdapter::Network,
            manifest(FaultAdapter::Network),
            &checkpoint,
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(restored, runtime);

        let mut different_limits = FaultResourceLimits::default();
        different_limits.active_contributions_per_target = 1;
        assert_eq!(
            TransactionalAdapterRuntime::restore(
                FaultAdapter::Network,
                manifest(FaultAdapter::Network),
                &checkpoint,
                different_limits,
            ),
            Err(FaultRuntimeError::VersionOrIdentityMismatch)
        );

        let mut insufficient = manifest(FaultAdapter::Network);
        insufficient.capabilities.clear();
        assert!(matches!(
            TransactionalAdapterRuntime::restore(
                FaultAdapter::Network,
                insufficient,
                &checkpoint,
                FaultResourceLimits::default(),
            ),
            Err(FaultRuntimeError::AdapterActionMismatch)
        ));

        let mut corrupt = checkpoint;
        corrupt.bytes.push(b' ');
        assert_eq!(
            TransactionalAdapterRuntime::restore(
                FaultAdapter::Network,
                manifest(FaultAdapter::Network),
                &corrupt,
                FaultResourceLimits::default(),
            ),
            Err(FaultRuntimeError::AdapterCheckpointDigest)
        );
    }

    #[test]
    fn mirrored_sink_returns_backend_evidence_and_commits_both_views() {
        let mut state =
            TransactionalFaultAdapters::new(manifests(), FaultResourceLimits::default())
                .unwrap_or_else(|error| panic!("adapter state: {error}"));
        let mut backend = TransactionProbe::new(false);
        let expected_evidence = backend.evidence;
        let action = network_action();
        let mut sink = MirroredFaultActionSink::new(&mut state, &mut backend);
        let prepared = sink
            .prepare_batch(&[action])
            .unwrap_or_else(|error| panic!("prepare: {}", error.error));
        let committed = sink
            .commit_batch(prepared.transaction)
            .unwrap_or_else(|error| panic!("commit: {error}"));
        assert_eq!(committed.results[0].observation.evidence, expected_evidence);
        assert_eq!(
            state
                .adapter(FaultAdapter::Network)
                .composition_groups()
                .len(),
            1
        );
        assert_eq!(
            backend
                .ledger
                .adapter(FaultAdapter::Network)
                .composition_groups()
                .len(),
            1
        );
    }

    #[test]
    fn mirrored_sink_restores_canonical_state_after_backend_commit_rejection() {
        let mut state =
            TransactionalFaultAdapters::new(manifests(), FaultResourceLimits::default())
                .unwrap_or_else(|error| panic!("adapter state: {error}"));
        let before = state.clone();
        let mut backend = TransactionProbe::new(true);
        let action = network_action();
        let mut sink = MirroredFaultActionSink::new(&mut state, &mut backend);
        let prepared = sink
            .prepare_batch(&[action])
            .unwrap_or_else(|error| panic!("prepare: {}", error.error));
        let rejection = match sink.commit_batch(prepared.transaction) {
            Ok(_) => panic!("backend commit must reject"),
            Err(FaultActionCommitError::Rejected(rejection)) => rejection,
            Err(FaultActionCommitError::Fatal(error)) => {
                panic!("backend rejection must not be fatal: {error}")
            }
        };
        assert_eq!(rejection.error, FaultRuntimeError::AdapterActionMismatch);
        assert_eq!(state, before);
        assert!(
            backend
                .ledger
                .adapter(FaultAdapter::Network)
                .composition_groups()
                .is_empty()
        );
    }
}
