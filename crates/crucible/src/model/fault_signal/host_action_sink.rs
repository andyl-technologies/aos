//! Transactional live state for host-owned network and storage adapters.
//!
//! The sink retains complete typed actions, not flattened legacy profiles.
//! Network links and storage/9p devices consume this state at their exact
//! opportunities, so every accepted effect remains available with its target,
//! phase, mapping output, and binding identity.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod checkpoint_codec;

/// Committed live state for host-owned network and storage effects.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFaultActionState {
    active: BTreeMap<ActiveContributionKey, ResolvedBindingAction>,
    impulses: Vec<ResolvedBindingAction>,
    digest: ContentHash,
}

impl Default for HostFaultActionState {
    fn default() -> Self {
        let mut state = Self {
            active: BTreeMap::new(),
            impulses: Vec::new(),
            digest: ContentHash::default(),
        };
        state.recompute_digest();
        state
    }
}

impl HostFaultActionState {
    /// Returns persistent actions in canonical target/effect/binding order.
    #[must_use]
    pub const fn active(&self) -> &BTreeMap<ActiveContributionKey, ResolvedBindingAction> {
        &self.active
    }

    /// Removes and returns committed impulse actions in application order.
    pub fn drain_impulses(&mut self) -> Vec<ResolvedBindingAction> {
        let impulses = std::mem::take(&mut self.impulses);
        self.recompute_digest();
        impulses
    }

    /// Returns the complete visible-state identity.
    #[must_use]
    pub const fn digest(&self) -> ContentHash {
        self.digest
    }

    /// Returns whether no persistent or unconsumed impulse action exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.impulses.is_empty()
    }

    /// Returns persistent actions matching an exact target and phase.
    pub fn matching(
        &self,
        target: &ResolvedFaultTarget,
        phase: FaultPhase,
    ) -> impl Iterator<Item = &ResolvedBindingAction> {
        self.active
            .iter()
            .filter(move |(key, _action)| key.target == *target && key.phase == phase)
            .map(|(_key, action)| action)
    }

    /// Verifies persistent host state against the canonical binding ledger.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::IncompleteAdapterState`] when a network or
    /// storage contribution is missing, added, or differs in typed request,
    /// mapped values, or transition sequence.
    pub fn validate_mirror(
        &self,
        canonical: &ActiveContributionTable,
    ) -> Result<(), FaultRuntimeError> {
        let expected = canonical
            .entries()
            .iter()
            .filter(|(key, _contribution)| {
                matches!(
                    key.effect.descriptor().adapter,
                    FaultAdapter::Network | FaultAdapter::Storage
                )
            })
            .collect::<BTreeMap<_, _>>();
        if self.active.len() != expected.len() {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        for (key, action) in &self.active {
            let contribution = expected
                .get(key)
                .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
            if action.kind != BindingActionKind::UpsertPersistent
                || action.binding != key.binding
                || action.target != key.target
                || action.phase != key.phase
                || action.effect.as_ref() != contribution.request.as_ref()
                || action.mapped_digest != contribution.mapped_parameters
                || action.mapping_output.as_ref() != contribution.mapping_output.as_ref()
                || action.transition_sequence != contribution.transition_sequence
            {
                return Err(FaultRuntimeError::IncompleteAdapterState);
            }
        }
        Ok(())
    }

    fn recompute_digest(&mut self) {
        let mut bytes = Vec::with_capacity((self.active.len() + self.impulses.len()) * 32);
        for action in self.active.values().chain(self.impulses.iter()) {
            bytes.extend_from_slice(&action.committed_state_id().bytes);
        }
        self.digest = ContentHash::from_canonical_material(
            "crucible.host-fault-action-state.v2",
            &hex_bytes(&bytes),
        );
    }
}

#[derive(Clone, Debug)]
struct PreparedHostFaultBatch {
    transaction: ContentHash,
    next: HostFaultActionState,
    results: Vec<PreparedActionResult>,
}

/// Atomic production sink for the host network and storage device families.
#[derive(Clone, Debug)]
pub struct HostFaultActionSink {
    state: HostFaultActionState,
    prepared: Option<PreparedHostFaultBatch>,
    resource_limits: FaultResourceLimits,
}

impl HostFaultActionSink {
    /// Creates an empty host adapter state.
    #[must_use]
    pub fn new(resource_limits: FaultResourceLimits) -> Self {
        Self {
            state: HostFaultActionState::default(),
            prepared: None,
            resource_limits,
        }
    }

    /// Restores previously committed host adapter state.
    #[must_use]
    pub fn from_state(
        mut state: HostFaultActionState,
        resource_limits: FaultResourceLimits,
    ) -> Self {
        state.recompute_digest();
        Self {
            state,
            prepared: None,
            resource_limits,
        }
    }

    /// Returns the committed live host adapter state.
    #[must_use]
    pub const fn state(&self) -> &HostFaultActionState {
        &self.state
    }

    /// Returns mutable committed state for draining exact impulse work.
    #[must_use]
    pub const fn state_mut(&mut self) -> &mut HostFaultActionState {
        &mut self.state
    }

    fn reject(
        &self,
        action: Option<&ResolvedBindingAction>,
        error: FaultRuntimeError,
    ) -> Box<RejectedActionBatch> {
        Box::new(RejectedActionBatch {
            error,
            observations: action
                .map(|action| {
                    observation(
                        action,
                        FaultObservationKind::EffectRejected,
                        self.state.digest,
                    )
                })
                .into_iter()
                .collect(),
            rejected_action: action.map(ResolvedBindingAction::id),
        })
    }
}

impl FaultActionSink for HostFaultActionSink {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(self.reject(None, FaultRuntimeError::AdapterTransactionPending));
        }
        if !self.state.impulses.is_empty() {
            return Err(self.reject(None, FaultRuntimeError::IncompleteAdapterState));
        }
        for action in actions {
            if let Some(expected) = action.expected_precondition
                && expected != self.state.digest
            {
                return Err(self.reject(
                    Some(action),
                    FaultRuntimeError::ReplayPreconditionMismatch {
                        action: action.id(),
                        expected,
                        observed: self.state.digest,
                    },
                ));
            }
        }
        let mut next = self.state.clone();
        let mut seen = BTreeSet::new();
        for action in actions {
            let adapter = action.effect.kind().descriptor().adapter;
            if !matches!(adapter, FaultAdapter::Network | FaultAdapter::Storage)
                || action.target.kind().adapter() != adapter
            {
                return Err(self.reject(Some(action), FaultRuntimeError::AdapterActionMismatch));
            }
            if !seen.insert(action.id()) {
                return Err(self.reject(Some(action), FaultRuntimeError::DuplicateAdapterAction));
            }
            let key = ActiveContributionKey {
                target: action.target.clone(),
                phase: action.phase,
                effect: action.effect.kind(),
                binding: action.binding.clone(),
            };
            match action.kind {
                BindingActionKind::UpsertPersistent => {
                    next.active.insert(key, action.clone());
                }
                BindingActionKind::RemovePersistent => {
                    next.active.remove(&key);
                }
                BindingActionKind::Apply => {
                    next.impulses.push(action.clone());
                }
            }
        }
        let mut active_per_target = BTreeMap::<ResolvedFaultTarget, u64>::new();
        for key in next.active.keys() {
            let count = active_per_target.entry(key.target.clone()).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                self.reject(
                    None,
                    FaultRuntimeError::CountOverflow("active_contributions_per_target"),
                )
            })?;
        }
        for count in active_per_target.values().copied() {
            if let Err(error) =
                self.resource_limits
                    .reserve("active_contributions_per_target", 0, count)
            {
                return Err(self.reject(None, FaultRuntimeError::ResourceLimit(error)));
            }
        }
        next.recompute_digest();
        let transaction = transaction_digest(actions, self.state.digest, next.digest);
        let results = actions
            .iter()
            .map(|action| PreparedActionResult {
                action: action.id(),
                precondition: Some(self.state.digest),
                observation: observation(
                    action,
                    FaultObservationKind::EffectCommitted,
                    next.digest,
                ),
            })
            .collect::<Vec<_>>();
        self.prepared = Some(PreparedHostFaultBatch {
            transaction,
            next,
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
        let prepared = self.prepared.take().ok_or({
            FaultActionCommitError::Fatal(FaultRuntimeError::UnknownAdapterTransaction)
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ));
        }
        self.state = prepared.next;
        Ok(PreparedActionBatch {
            transaction,
            results: prepared.results,
        })
    }
}

fn transaction_digest(
    actions: &[ResolvedBindingAction],
    before: ContentHash,
    after: ContentHash,
) -> ContentHash {
    let mut bytes = Vec::with_capacity((actions.len() + 2) * 32);
    bytes.extend_from_slice(&before.bytes);
    bytes.extend_from_slice(&after.bytes);
    for action in actions {
        bytes.extend_from_slice(&action.id().bytes);
    }
    ContentHash::from_bytes(&bytes)
}

fn observation(
    action: &ResolvedBindingAction,
    kind: FaultObservationKind,
    evidence: ContentHash,
) -> FaultObservation {
    let kind = match action.kind {
        BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
        BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
        BindingActionKind::Apply => kind,
    };
    FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind,
        coordinate: action.coordinate,
        binding: Some(action.binding.clone()),
        target: Some(action.target.clone()),
        opportunity: action.opportunity,
        evidence,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod checkpoint_codec_tests {
    use super::*;

    #[test]
    fn empty_host_state_codec_round_trips_canonically() {
        let state = HostFaultActionState::default();
        let bytes = state
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("host state should encode: {error}"));
        let restored = HostFaultActionState::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("host state should decode: {error}"));
        assert_eq!(restored, state);
        assert_eq!(
            restored
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("restored state should encode: {error}")),
            bytes
        );
    }

    #[test]
    fn host_state_codec_rejects_trailing_bytes() {
        let mut bytes = HostFaultActionState::default()
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("host state should encode: {error}"));
        bytes.push(0);
        assert!(HostFaultActionState::from_canonical_bytes(&bytes).is_err());
    }
}
