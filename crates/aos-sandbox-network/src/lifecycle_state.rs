//! Durable admission state for existing Network namespace operations.
//!
//! This journal is deliberately separate from one-time namespace creation.
//! It serializes operations by opaque network handle, retains the signed
//! authorization/effect links for every attempt, and makes recovery from the
//! pre-effect boundary observation-only.

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker::{
    BrokerAuthorizationFenceV1, BrokerEffectStatusV2, BrokerLocalRecordDomain,
};
use aos_sandbox_core::{BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::namespace_catalog::{
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleAuthorityV1, NetworkNamespaceLifecycleTransitionV1,
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
};

const MAGIC: &[u8; 8] = b"AOSNLC01";
const VERSION: u16 = 2;
const LEGACY_VERSION: u16 = 1;
const MAXIMUM_OPERATIONS: usize = 16_384;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-effect.v2\0";
const LEGACY_EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-effect.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-transaction.v1\0";

fn record_domain() -> Result<BrokerLocalRecordDomain, NetworkLifecycleStateError> {
    BrokerLocalRecordDomain::new(*b"AOSNETLIFECYCLE1")
        .map_err(|_| NetworkLifecycleStateError::AuthorityLink)
}

fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 512 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 32,
        maximum_records_per_transaction: 5,
        maximum_transaction_bytes: 320 * 1024,
        maximum_transactions: MAXIMUM_OPERATIONS * 3,
        maximum_materialized_bytes: MAXIMUM_OPERATIONS * (MAXIMUM_RECORD_BYTES + 512),
        maximum_materialized_records: MAXIMUM_OPERATIONS * 5,
    }
}

/// Reports durable existing-handle lifecycle admission failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkLifecycleStateError {
    /// The protected journal failed validation, locking, or publication.
    #[error("network lifecycle journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// A sealed record or its authority/effect links did not authenticate.
    #[error("network lifecycle authority links are invalid")]
    AuthorityLink,
    /// Durable bytes violate the closed lifecycle schema.
    #[error("network lifecycle record is corrupt")]
    CorruptRecord,
    /// A request ID was reused for different lifecycle intent.
    #[error("network lifecycle request equivocation")]
    Equivocation,
    /// Another operation for the same handle has not committed.
    #[error("network lifecycle handle already has a pending operation")]
    PendingConflict,
    /// The bounded lifecycle journal epoch is exhausted.
    #[error("network lifecycle operation epoch is exhausted")]
    ResourceExhausted,
    /// The requested phase or verified result is not current.
    #[error("network lifecycle phase transition is invalid")]
    InvalidTransition,
}

/// Reports the durable phase of one existing-handle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableNetworkLifecyclePhase {
    /// Authority and effect intent are durable, but no effect may have run.
    Prepared,
    /// An effect may have run; recovery may only observe or clean up.
    Ambiguous,
    /// A complete verified transition was durably committed.
    Committed,
}

/// Carries the stable result returned for exact lifecycle replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedNetworkLifecycleResultV1 {
    request_id: [u8; 16],
    network_handle: [u8; 32],
    action: NetworkNamespaceLifecycleActionV1,
    transition_digest: ObjectDigest,
    observation_digest: ObjectDigest,
}

impl CommittedNetworkLifecycleResultV1 {
    /// Returns the request that owns the committed transition.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the existing namespace handle that was changed.
    #[must_use]
    pub const fn network_handle(self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the closed lifecycle action that committed.
    #[must_use]
    pub const fn action(self) -> NetworkNamespaceLifecycleActionV1 {
        self.action
    }

    /// Returns the digest of the complete catalog transition.
    #[must_use]
    pub const fn transition_digest(self) -> ObjectDigest {
        self.transition_digest
    }

    /// Returns the helper's complete postcondition commitment.
    #[must_use]
    pub const fn observation_digest(self) -> ObjectDigest {
        self.observation_digest
    }
}

/// Describes one bounded authenticated lifecycle recovery entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkLifecycleRecoveryEntryV1 {
    request_id: [u8; 16],
    network_handle: [u8; 32],
    action: NetworkNamespaceLifecycleActionV1,
    phase: DurableNetworkLifecyclePhase,
    effect_digest: ObjectDigest,
    prior_resource_digest: ObjectDigest,
}

impl NetworkLifecycleRecoveryEntryV1 {
    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the serialized existing-resource handle.
    #[must_use]
    pub const fn network_handle(self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the admitted lifecycle action.
    #[must_use]
    pub const fn action(self) -> NetworkNamespaceLifecycleActionV1 {
        self.action
    }

    /// Returns the durable crash phase.
    #[must_use]
    pub const fn phase(self) -> DurableNetworkLifecyclePhase {
        self.phase
    }

    /// Returns the deterministic lifecycle-effect identity.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the exact catalog head admitted before the effect.
    #[must_use]
    pub const fn prior_resource_digest(self) -> ObjectDigest {
        self.prior_resource_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleBeginOutcome {
    Prepared {
        effect_digest: ObjectDigest,
    },
    ObserveOnly {
        phase: DurableNetworkLifecyclePhase,
        effect_digest: ObjectDigest,
    },
    Replay(CommittedNetworkLifecycleResultV1),
}

#[must_use]
pub(crate) struct AmbiguousNetworkLifecycleDispatchV1 {
    pub(crate) request_id: [u8; 16],
    pub(crate) sandbox_id: [u8; 16],
    pub(crate) transport_digest: ObjectDigest,
    pub(crate) semantic_digest: ObjectDigest,
    pub(crate) verb: BrokerVerb,
    pub(crate) action: NetworkNamespaceLifecycleActionV1,
    pub(crate) preparation_generation: u64,
    pub(crate) preparation_digest: ObjectDigest,
    pub(crate) authority: NetworkNamespaceLifecycleAuthorityV1,
    pub(crate) desired_state: NetworkNamespaceObservedStateV1,
    pub(crate) effect_digest: ObjectDigest,
    pub(crate) current_fence: Vec<u8>,
    pub(crate) operation_fence: Vec<u8>,
    pub(crate) effect: Vec<u8>,
}

pub(crate) struct PreparedNetworkLifecycleRecordInput {
    pub(crate) request_id: [u8; 16],
    pub(crate) sandbox_id: [u8; 16],
    pub(crate) transport_digest: ObjectDigest,
    pub(crate) semantic_digest: ObjectDigest,
    pub(crate) verb: BrokerVerb,
    pub(crate) action: NetworkNamespaceLifecycleActionV1,
    pub(crate) preparation_generation: u64,
    pub(crate) preparation_digest: ObjectDigest,
    pub(crate) authority: NetworkNamespaceLifecycleAuthorityV1,
    pub(crate) desired_state: NetworkNamespaceObservedStateV1,
    pub(crate) current_fence: Vec<u8>,
    pub(crate) operation_fence: Vec<u8>,
    pub(crate) effect: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableNetworkLifecycleRecord {
    phase: DurableNetworkLifecyclePhase,
    request_id: [u8; 16],
    sandbox_id: [u8; 16],
    transport_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    verb: BrokerVerb,
    action: NetworkNamespaceLifecycleActionV1,
    preparation_generation: u64,
    preparation_digest: ObjectDigest,
    authority: NetworkNamespaceLifecycleAuthorityV1,
    desired_state: NetworkNamespaceObservedStateV1,
    effect_digest: ObjectDigest,
    current_fence: Vec<u8>,
    operation_fence: Vec<u8>,
    effect: Vec<u8>,
    result: Option<CommittedNetworkLifecycleResultV1>,
}

pub(crate) fn prepared_lifecycle_record(
    input: PreparedNetworkLifecycleRecordInput,
) -> DurableNetworkLifecycleRecord {
    let effect_digest = lifecycle_effect_digest(
        input.request_id,
        input.transport_digest,
        input.semantic_digest,
        input.action,
        input.authority,
        input.desired_state,
    );
    DurableNetworkLifecycleRecord {
        phase: DurableNetworkLifecyclePhase::Prepared,
        request_id: input.request_id,
        sandbox_id: input.sandbox_id,
        transport_digest: input.transport_digest,
        semantic_digest: input.semantic_digest,
        verb: input.verb,
        action: input.action,
        preparation_generation: input.preparation_generation,
        preparation_digest: input.preparation_digest,
        authority: input.authority,
        desired_state: input.desired_state,
        effect_digest,
        current_fence: input.current_fence,
        operation_fence: input.operation_fence,
        effect: input.effect,
        result: None,
    }
}

/// Owns the exclusive existing-handle lifecycle journal.
pub struct NetworkLifecycleStateStore {
    journal: Journal,
    records: BTreeMap<[u8; 16], DurableNetworkLifecycleRecord>,
    heads: BTreeMap<[u8; 32], [u8; 16]>,
}

impl NetworkLifecycleStateStore {
    /// Opens and authenticates lifecycle state in an exact root-owned directory.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkLifecycleStateError`] for filesystem protection,
    /// journal corruption, authority-link failure, or inconsistent heads.
    pub fn open_root_owned(
        directory: &Path,
        authority: &NetworkAuthorityV1,
    ) -> Result<Self, NetworkLifecycleStateError> {
        let (journal, _) = Journal::open_protected_at(
            directory,
            "network-lifecycle-state.journal",
            journal_limits(),
        )?;
        Self::from_journal(journal, authority)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        directory: &Path,
        authority: &NetworkAuthorityV1,
    ) -> Result<Self, NetworkLifecycleStateError> {
        let (journal, _) = Journal::open(
            directory.join("network-lifecycle-state.journal"),
            journal_limits(),
        )?;
        Self::from_journal(journal, authority)
    }

    fn from_journal(
        journal: Journal,
        authority: &NetworkAuthorityV1,
    ) -> Result<Self, NetworkLifecycleStateError> {
        let mut records = BTreeMap::new();
        for (key, sealed) in journal.records(RecordNamespace::Operation) {
            let request_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
            let payload = authority
                .open_local(&request_id, record_domain()?, sealed)
                .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
            let record = decode_record(payload)?;
            if record.request_id != request_id || records.insert(request_id, record).is_some() {
                return Err(NetworkLifecycleStateError::CorruptRecord);
            }
        }

        let mut heads = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::NetworkResourceInventory) {
            let handle: [u8; 32] = key
                .try_into()
                .map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
            let request_id: [u8; 16] = value
                .try_into()
                .map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
            if heads.insert(handle, request_id).is_some() {
                return Err(NetworkLifecycleStateError::CorruptRecord);
            }
        }

        validate_materialized_view(&journal, authority, &records, &heads)?;
        Ok(Self {
            journal,
            records,
            heads,
        })
    }

    pub(crate) fn current_fence(&self, sandbox_id: &[u8; 16]) -> Option<&[u8]> {
        self.journal.get(RecordNamespace::DesiredState, sandbox_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn existing_authorized_outcome(
        &self,
        request_id: [u8; 16],
        sandbox_id: [u8; 16],
        transport_digest: ObjectDigest,
        semantic_digest: ObjectDigest,
        verb: BrokerVerb,
        preparation_generation: u64,
        preparation_digest: ObjectDigest,
        network_handle: [u8; 32],
        kernel_plan_digest: ObjectDigest,
    ) -> Result<Option<NetworkLifecycleBeginOutcome>, NetworkLifecycleStateError> {
        let Some(existing) = self.records.get(&request_id) else {
            return Ok(None);
        };
        if existing.sandbox_id != sandbox_id
            || existing.transport_digest != transport_digest
            || existing.semantic_digest != semantic_digest
            || existing.verb != verb
            || existing.preparation_generation != preparation_generation
            || existing.preparation_digest != preparation_digest
            || existing.authority.identity.network_handle() != network_handle
            || existing.authority.kernel_plan_digest != Some(kernel_plan_digest)
        {
            return Err(NetworkLifecycleStateError::Equivocation);
        }
        Ok(Some(match (existing.phase, existing.result) {
            (DurableNetworkLifecyclePhase::Committed, Some(result)) => {
                NetworkLifecycleBeginOutcome::Replay(result)
            }
            (phase, _) => NetworkLifecycleBeginOutcome::ObserveOnly {
                phase,
                effect_digest: existing.effect_digest,
            },
        }))
    }

    pub(crate) fn begin_authorized(
        &mut self,
        authority: &NetworkAuthorityV1,
        record: DurableNetworkLifecycleRecord,
    ) -> Result<NetworkLifecycleBeginOutcome, NetworkLifecycleStateError> {
        if let Some(existing) = self.records.get(&record.request_id) {
            if !same_intent(existing, &record) {
                return Err(NetworkLifecycleStateError::Equivocation);
            }
            return Ok(match (existing.phase, existing.result) {
                (DurableNetworkLifecyclePhase::Committed, Some(result)) => {
                    NetworkLifecycleBeginOutcome::Replay(result)
                }
                (phase, _) => NetworkLifecycleBeginOutcome::ObserveOnly {
                    phase,
                    effect_digest: existing.effect_digest,
                },
            });
        }
        if self.records.len() >= MAXIMUM_OPERATIONS {
            return Err(NetworkLifecycleStateError::ResourceExhausted);
        }
        if let Some(head_request) = self.heads.get(&record.authority.identity.network_handle()) {
            let head = self
                .records
                .get(head_request)
                .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
            if head.phase != DurableNetworkLifecyclePhase::Committed {
                return Err(NetworkLifecycleStateError::PendingConflict);
            }
            if head.authority.resource_digest == record.authority.resource_digest {
                return Err(NetworkLifecycleStateError::InvalidTransition);
            }
        }
        let payload = encode_record(&record)?;
        let sealed = authority
            .seal_local(&record.request_id, record_domain()?, &payload)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let handle = record.authority.identity.network_handle();
        let transaction = JournalTransaction::new(
            transaction_id(b"begin", &record.request_id),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    record.sandbox_id.to_vec(),
                    record.current_fence.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    record.request_id.to_vec(),
                    record.effect.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    record.request_id.to_vec(),
                    record.operation_fence.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    record.request_id.to_vec(),
                    sealed,
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    handle.to_vec(),
                    record.request_id.to_vec(),
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        let effect_digest = record.effect_digest;
        self.heads.insert(handle, record.request_id);
        self.records.insert(record.request_id, record);
        Ok(NetworkLifecycleBeginOutcome::Prepared { effect_digest })
    }

    pub(crate) fn mark_effect_ambiguous(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<AmbiguousNetworkLifecycleDispatchV1, NetworkLifecycleStateError> {
        let mut record = self.exact_current(request_id, effect_digest)?.clone();
        if record.phase != DurableNetworkLifecyclePhase::Prepared
            || record.authority.kernel_plan_digest.is_none()
        {
            return Err(NetworkLifecycleStateError::InvalidTransition);
        }
        record.phase = DurableNetworkLifecyclePhase::Ambiguous;
        let dispatch = ambiguous_dispatch(&record)?;
        self.publish(authority, record, b"ambiguous")?;
        Ok(dispatch)
    }

    pub(crate) fn commit_verified(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        transition: NetworkNamespaceLifecycleTransitionV1,
    ) -> Result<CommittedNetworkLifecycleResultV1, NetworkLifecycleStateError> {
        self.validate_verified_transition(request_id, effect_digest, transition)?;
        let mut record = self.exact_current(request_id, effect_digest)?.clone();
        let observation = transition.observation();
        let result = CommittedNetworkLifecycleResultV1 {
            request_id,
            network_handle: record.authority.identity.network_handle(),
            action: record.action,
            transition_digest: transition.digest(),
            observation_digest: observation.observation_digest(),
        };
        record.phase = DurableNetworkLifecyclePhase::Committed;
        record.result = Some(result);
        self.publish(authority, record, b"commit")?;
        Ok(result)
    }

    pub(crate) fn validate_verified_transition(
        &self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        transition: NetworkNamespaceLifecycleTransitionV1,
    ) -> Result<(), NetworkLifecycleStateError> {
        let record = self.exact_current(request_id, effect_digest)?;
        let observation = transition.observation();
        if record.phase != DurableNetworkLifecyclePhase::Ambiguous
            || transition.action() != record.action
            || observation.request_id() != record.request_id
            || observation.prior_resource_digest() != record.authority.resource_digest
            || observation.namespace() != record.authority.identity
            || observation.observed_state() != record.desired_state
        {
            return Err(NetworkLifecycleStateError::InvalidTransition);
        }
        Ok(())
    }

    /// Returns deterministic authenticated lifecycle history for recovery.
    pub fn recovery_entries(&self) -> impl Iterator<Item = NetworkLifecycleRecoveryEntryV1> + '_ {
        self.records.values().map(recovery_entry)
    }

    #[cfg(test)]
    pub(crate) fn delete_desired_fence_for_test(
        &mut self,
        sandbox_id: [u8; 16],
    ) -> Result<(), NetworkLifecycleStateError> {
        let transaction = JournalTransaction::new(
            transaction_id(b"test-delete-fence", &sandbox_id),
            vec![JournalRecord::delete(
                RecordNamespace::DesiredState,
                sandbox_id.to_vec(),
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn restore_historical_fence_for_test(
        &mut self,
        sandbox_id: [u8; 16],
        request_id: [u8; 16],
    ) -> Result<(), NetworkLifecycleStateError> {
        let fence = self
            .records
            .get(&request_id)
            .filter(|record| record.sandbox_id == sandbox_id)
            .map(|record| record.current_fence.clone())
            .ok_or(NetworkLifecycleStateError::InvalidTransition)?;
        let transaction = JournalTransaction::new(
            transaction_id(b"test-stale-fence", &request_id),
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                sandbox_id.to_vec(),
                fence,
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn replace_current_fence_for_test(
        &mut self,
        sandbox_id: [u8; 16],
        fence: Vec<u8>,
    ) -> Result<(), NetworkLifecycleStateError> {
        let transaction = JournalTransaction::new(
            transaction_id(b"test-replace-fence", &sandbox_id),
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                sandbox_id.to_vec(),
                fence,
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn delete_handle_head_for_test(
        &mut self,
        network_handle: [u8; 32],
    ) -> Result<(), NetworkLifecycleStateError> {
        let request_id = self
            .heads
            .get(&network_handle)
            .copied()
            .ok_or(NetworkLifecycleStateError::InvalidTransition)?;
        let transaction = JournalTransaction::new(
            transaction_id(b"test-delete-head", &request_id),
            vec![JournalRecord::delete(
                RecordNamespace::NetworkResourceInventory,
                network_handle.to_vec(),
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn rewrite_transport_digest_for_test(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        transport_digest: ObjectDigest,
    ) -> Result<(), NetworkLifecycleStateError> {
        let mut record = self
            .records
            .get(&request_id)
            .cloned()
            .ok_or(NetworkLifecycleStateError::InvalidTransition)?;
        record.transport_digest = transport_digest;
        record.effect_digest = lifecycle_effect_digest(
            record.request_id,
            record.transport_digest,
            record.semantic_digest,
            record.action,
            record.authority,
            record.desired_state,
        );
        self.rewrite_record_for_test(authority, record, b"test-transport-mislink")
    }

    #[cfg(test)]
    pub(crate) fn mislink_current_fence_for_test(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        current_fence: Vec<u8>,
    ) -> Result<(), NetworkLifecycleStateError> {
        let mut record = self
            .records
            .get(&request_id)
            .cloned()
            .ok_or(NetworkLifecycleStateError::InvalidTransition)?;
        record.current_fence = current_fence;
        self.rewrite_record_for_test(authority, record, b"test-fence-mislink")
    }

    #[cfg(test)]
    fn rewrite_record_for_test(
        &mut self,
        authority: &NetworkAuthorityV1,
        record: DurableNetworkLifecycleRecord,
        label: &[u8],
    ) -> Result<(), NetworkLifecycleStateError> {
        let payload = encode_record(&record)?;
        let sealed = authority
            .seal_local(&record.request_id, record_domain()?, &payload)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let transaction = JournalTransaction::new(
            transaction_id(label, &record.request_id),
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                record.request_id.to_vec(),
                sealed,
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    fn exact_current(
        &self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<&DurableNetworkLifecycleRecord, NetworkLifecycleStateError> {
        let record = self
            .records
            .get(&request_id)
            .ok_or(NetworkLifecycleStateError::InvalidTransition)?;
        if record.effect_digest != effect_digest
            || self.heads.get(&record.authority.identity.network_handle()) != Some(&request_id)
        {
            return Err(NetworkLifecycleStateError::InvalidTransition);
        }
        Ok(record)
    }

    fn publish(
        &mut self,
        authority: &NetworkAuthorityV1,
        record: DurableNetworkLifecycleRecord,
        label: &[u8],
    ) -> Result<(), NetworkLifecycleStateError> {
        let payload = encode_record(&record)?;
        let sealed = authority
            .seal_local(&record.request_id, record_domain()?, &payload)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let transaction = JournalTransaction::new(
            transaction_id(label, &record.request_id),
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                record.request_id.to_vec(),
                sealed,
            )],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(record.request_id, record);
        Ok(())
    }
}

fn validate_materialized_view(
    journal: &Journal,
    authority: &NetworkAuthorityV1,
    records: &BTreeMap<[u8; 16], DurableNetworkLifecycleRecord>,
    heads: &BTreeMap<[u8; 32], [u8; 16]>,
) -> Result<(), NetworkLifecycleStateError> {
    for record in records.values() {
        if journal.get(RecordNamespace::Effect, &record.request_id) != Some(&record.effect)
            || journal.get(RecordNamespace::AuthorityPublication, &record.request_id)
                != Some(&record.operation_fence)
        {
            return Err(NetworkLifecycleStateError::AuthorityLink);
        }
        let current_effect = authority
            .validate_links(
                &record.sandbox_id,
                &record.request_id,
                &record.current_fence,
                &record.effect,
            )
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let operation_effect = authority
            .validate_operation_links(
                &record.sandbox_id,
                &record.request_id,
                &record.operation_fence,
                &record.effect,
            )
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let current_fence = authority
            .open_fence(&record.sandbox_id, &record.current_fence)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let operation_fence = authority
            .open_operation_fence(&record.request_id, &record.operation_fence)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        let expected_target = BrokerGrantTarget::Resource(
            BrokerResourceHandle::from_bytes(record.authority.identity.network_handle())
                .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?,
        );
        if current_fence != operation_fence
            || current_effect != operation_effect
            || operation_effect.request_id() != &record.request_id
            || operation_effect.transport_request_digest() != record.transport_digest
            || operation_effect.request_digest() != record.semantic_digest
            || operation_effect.verb() != record.verb
            || operation_effect.target() != expected_target
            || operation_effect.plan_digest() != operation_fence.plan_digest()
            || operation_effect.status() != BrokerEffectStatusV2::Pending
        {
            return Err(NetworkLifecycleStateError::AuthorityLink);
        }

        let is_head =
            heads.get(&record.authority.identity.network_handle()) == Some(&record.request_id);
        if !is_head && record.phase != DurableNetworkLifecyclePhase::Committed {
            return Err(NetworkLifecycleStateError::CorruptRecord);
        }
    }
    for (handle, request_id) in heads {
        let record = records
            .get(request_id)
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
        if record.authority.identity.network_handle() != *handle {
            return Err(NetworkLifecycleStateError::CorruptRecord);
        }
    }
    if records
        .values()
        .any(|record| !heads.contains_key(&record.authority.identity.network_handle()))
    {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    let mut durable_sandboxes = BTreeMap::new();
    for (sandbox_id, fence_bytes) in journal.records(RecordNamespace::DesiredState) {
        let sandbox_id: [u8; 16] = sandbox_id
            .try_into()
            .map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
        let durable_fence = authority
            .open_fence(&sandbox_id, fence_bytes)
            .and_then(|fence| {
                authority.check_current_fence(&fence)?;
                Ok(fence)
            })
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        if durable_sandboxes
            .insert(sandbox_id, durable_fence)
            .is_some()
        {
            return Err(NetworkLifecycleStateError::CorruptRecord);
        }
    }
    for record in records.values() {
        let durable = durable_sandboxes
            .get(&record.sandbox_id)
            .ok_or(NetworkLifecycleStateError::AuthorityLink)?;
        let historical = authority
            .open_fence(&record.sandbox_id, &record.current_fence)
            .map_err(|_| NetworkLifecycleStateError::AuthorityLink)?;
        if !fence_follows(durable, &historical) {
            return Err(NetworkLifecycleStateError::AuthorityLink);
        }
    }
    if durable_sandboxes.keys().any(|sandbox_id| {
        !records
            .values()
            .any(|record| &record.sandbox_id == sandbox_id)
    }) {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    for (key, _) in journal.records(RecordNamespace::Effect) {
        if !records.contains_key(key) {
            return Err(NetworkLifecycleStateError::AuthorityLink);
        }
    }
    for (key, _) in journal.records(RecordNamespace::AuthorityPublication) {
        if !records.contains_key(key) {
            return Err(NetworkLifecycleStateError::AuthorityLink);
        }
    }
    Ok(())
}

fn fence_follows(
    current: &BrokerAuthorizationFenceV1,
    historical: &BrokerAuthorizationFenceV1,
) -> bool {
    let current_assignment = current.assignment();
    let historical_assignment = historical.assignment();
    if current.node() != historical.node()
        || current_assignment.sandbox() != historical_assignment.sandbox()
        || current_assignment.epoch() < historical_assignment.epoch()
    {
        return false;
    }
    if current_assignment.epoch() > historical_assignment.epoch() {
        return true;
    }
    if current_assignment.incarnation() != historical_assignment.incarnation()
        || current.ownership_authority() != historical.ownership_authority()
        || current_assignment.desired_generation() < historical_assignment.desired_generation()
    {
        return false;
    }
    if current_assignment.desired_generation() > historical_assignment.desired_generation() {
        return true;
    }
    if current_assignment != historical_assignment
        || current.plan_digest() != historical.plan_digest()
    {
        return false;
    }

    let current_lease = current.local_lease_record();
    let historical_lease = historical.local_lease_record();
    current_lease.lease_generation() > historical_lease.lease_generation()
        || (current_lease.lease_generation() == historical_lease.lease_generation()
            && current_lease == historical_lease)
}

fn same_intent(
    left: &DurableNetworkLifecycleRecord,
    right: &DurableNetworkLifecycleRecord,
) -> bool {
    left.request_id == right.request_id
        && left.sandbox_id == right.sandbox_id
        && left.transport_digest == right.transport_digest
        && left.semantic_digest == right.semantic_digest
        && left.verb == right.verb
        && left.action == right.action
        && left.preparation_generation == right.preparation_generation
        && left.preparation_digest == right.preparation_digest
        && left.authority == right.authority
        && left.desired_state == right.desired_state
        && left.effect_digest == right.effect_digest
}

fn recovery_entry(record: &DurableNetworkLifecycleRecord) -> NetworkLifecycleRecoveryEntryV1 {
    NetworkLifecycleRecoveryEntryV1 {
        request_id: record.request_id,
        network_handle: record.authority.identity.network_handle(),
        action: record.action,
        phase: record.phase,
        effect_digest: record.effect_digest,
        prior_resource_digest: record.authority.resource_digest,
    }
}

pub(crate) fn lifecycle_effect_digest(
    request_id: [u8; 16],
    transport_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    action: NetworkNamespaceLifecycleActionV1,
    authority: NetworkNamespaceLifecycleAuthorityV1,
    desired_state: NetworkNamespaceObservedStateV1,
) -> ObjectDigest {
    let identity = authority.identity;
    let effect_domain = if authority.kernel_plan_digest.is_some() {
        EFFECT_DIGEST_DOMAIN
    } else {
        LEGACY_EFFECT_DIGEST_DOMAIN
    };
    let mut hasher = Sha256::new()
        .chain_update(effect_domain)
        .chain_update(request_id)
        .chain_update(transport_digest.as_bytes())
        .chain_update(semantic_digest.as_bytes())
        .chain_update([action_code(action)])
        .chain_update(identity.network_handle())
        .chain_update(identity.kernel_boot_id())
        .chain_update(identity.namespace_device().to_be_bytes())
        .chain_update(identity.namespace_inode().to_be_bytes())
        .chain_update(authority.resource_digest.as_bytes());
    if let Some(kernel_plan_digest) = authority.kernel_plan_digest {
        hasher = hasher.chain_update(kernel_plan_digest.as_bytes());
    }
    hasher = hasher
        .chain_update(authority.highest_lease_generation.to_be_bytes())
        .chain_update(authority.highest_lease_digest.as_bytes());
    encode_state_hash(&mut hasher, authority.observed_state);
    encode_state_hash(&mut hasher, desired_state);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn ambiguous_dispatch(
    record: &DurableNetworkLifecycleRecord,
) -> Result<AmbiguousNetworkLifecycleDispatchV1, NetworkLifecycleStateError> {
    if record.phase != DurableNetworkLifecyclePhase::Ambiguous
        || record
            .authority
            .kernel_plan_digest
            .is_none_or(|digest| digest.as_bytes() == &[0; 32])
        || record.result.is_some()
    {
        return Err(NetworkLifecycleStateError::InvalidTransition);
    }
    Ok(AmbiguousNetworkLifecycleDispatchV1 {
        request_id: record.request_id,
        sandbox_id: record.sandbox_id,
        transport_digest: record.transport_digest,
        semantic_digest: record.semantic_digest,
        verb: record.verb,
        action: record.action,
        preparation_generation: record.preparation_generation,
        preparation_digest: record.preparation_digest,
        authority: record.authority,
        desired_state: record.desired_state,
        effect_digest: record.effect_digest,
        current_fence: record.current_fence.clone(),
        operation_fence: record.operation_fence.clone(),
        effect: record.effect.clone(),
    })
}

fn encode_record(
    record: &DurableNetworkLifecycleRecord,
) -> Result<Vec<u8>, NetworkLifecycleStateError> {
    validate_record_shape(record, VERSION)?;
    let identity = record.authority.identity;
    let mut bytes = Vec::with_capacity(
        512 + record.current_fence.len() + record.operation_fence.len() + record.effect.len(),
    );
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(phase_code(record.phase));
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(record.transport_digest.as_bytes());
    bytes.extend_from_slice(record.semantic_digest.as_bytes());
    bytes.push(verb_code(record.verb)?);
    bytes.push(action_code(record.action));
    bytes.extend_from_slice(&record.preparation_generation.to_be_bytes());
    bytes.extend_from_slice(record.preparation_digest.as_bytes());
    bytes.extend_from_slice(
        record
            .authority
            .kernel_plan_digest
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?
            .as_bytes(),
    );
    bytes.extend_from_slice(&identity.network_handle());
    bytes.extend_from_slice(&identity.kernel_boot_id());
    bytes.extend_from_slice(&identity.namespace_device().to_be_bytes());
    bytes.extend_from_slice(&identity.namespace_inode().to_be_bytes());
    bytes.extend_from_slice(record.authority.resource_digest.as_bytes());
    bytes.extend_from_slice(&record.authority.highest_lease_generation.to_be_bytes());
    bytes.extend_from_slice(record.authority.highest_lease_digest.as_bytes());
    encode_state(&mut bytes, record.authority.observed_state);
    encode_state(&mut bytes, record.desired_state);
    bytes.extend_from_slice(record.effect_digest.as_bytes());
    push_blob(&mut bytes, &record.current_fence)?;
    push_blob(&mut bytes, &record.operation_fence)?;
    push_blob(&mut bytes, &record.effect)?;
    if let Some(result) = record.result {
        bytes.extend_from_slice(result.transition_digest.as_bytes());
        bytes.extend_from_slice(result.observation_digest.as_bytes());
    }
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
) -> Result<DurableNetworkLifecycleRecord, NetworkLifecycleStateError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>()? != *MAGIC {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    let version = u16::from_be_bytes(decoder.take()?);
    if !matches!(version, LEGACY_VERSION | VERSION) {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    let phase = decode_phase(decoder.byte()?)?;
    let request_id = decoder.take()?;
    let sandbox_id = decoder.take()?;
    let transport_digest = ObjectDigest::from_bytes(decoder.take()?);
    let semantic_digest = ObjectDigest::from_bytes(decoder.take()?);
    let verb = decode_verb(decoder.byte()?)?;
    let action = decode_action(decoder.byte()?)?;
    let preparation_generation = u64::from_be_bytes(decoder.take()?);
    let preparation_digest = ObjectDigest::from_bytes(decoder.take()?);
    let kernel_plan_digest = if version == VERSION {
        Some(ObjectDigest::from_bytes(decoder.take()?))
    } else {
        None
    };
    let identity = NetworkNamespaceIdentityV1::new(
        decoder.take()?,
        decoder.take()?,
        u64::from_be_bytes(decoder.take()?),
        u64::from_be_bytes(decoder.take()?),
    )
    .map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
    let resource_digest = ObjectDigest::from_bytes(decoder.take()?);
    let highest_lease_generation = u64::from_be_bytes(decoder.take()?);
    let highest_lease_digest = ObjectDigest::from_bytes(decoder.take()?);
    let observed_state = decode_state(&mut decoder)?;
    let desired_state = decode_state(&mut decoder)?;
    let effect_digest = ObjectDigest::from_bytes(decoder.take()?);
    let current_fence = decoder.blob()?.to_vec();
    let operation_fence = decoder.blob()?.to_vec();
    let effect = decoder.blob()?.to_vec();
    let result = if phase == DurableNetworkLifecyclePhase::Committed {
        Some(CommittedNetworkLifecycleResultV1 {
            request_id,
            network_handle: identity.network_handle(),
            action,
            transition_digest: ObjectDigest::from_bytes(decoder.take()?),
            observation_digest: ObjectDigest::from_bytes(decoder.take()?),
        })
    } else {
        None
    };
    if !decoder.finished() {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    let record = DurableNetworkLifecycleRecord {
        phase,
        request_id,
        sandbox_id,
        transport_digest,
        semantic_digest,
        verb,
        action,
        preparation_generation,
        preparation_digest,
        authority: NetworkNamespaceLifecycleAuthorityV1 {
            identity,
            observed_state,
            resource_digest,
            kernel_plan_digest,
            highest_lease_generation,
            highest_lease_digest,
        },
        desired_state,
        effect_digest,
        current_fence,
        operation_fence,
        effect,
        result,
    };
    validate_record_shape(&record, version)?;
    Ok(record)
}

fn validate_record_shape(
    record: &DurableNetworkLifecycleRecord,
    version: u16,
) -> Result<(), NetworkLifecycleStateError> {
    let result_shape = match (record.phase, record.result) {
        (DurableNetworkLifecyclePhase::Committed, Some(result)) => {
            result.request_id == record.request_id
                && result.network_handle == record.authority.identity.network_handle()
                && result.action == record.action
                && result.transition_digest.as_bytes() != &[0; 32]
                && result.observation_digest.as_bytes() != &[0; 32]
        }
        (
            DurableNetworkLifecyclePhase::Prepared | DurableNetworkLifecyclePhase::Ambiguous,
            None,
        ) => true,
        _ => false,
    };
    let high_water_shape = match record.authority.highest_lease_generation {
        0 => record.authority.highest_lease_digest.as_bytes() == &[0; 32],
        _ => record.authority.highest_lease_digest.as_bytes() != &[0; 32],
    };
    if record.request_id == [0; 16]
        || record.sandbox_id == [0; 16]
        || record.transport_digest.as_bytes() == &[0; 32]
        || record.semantic_digest.as_bytes() == &[0; 32]
        || record.preparation_generation == 0
        || record.preparation_digest.as_bytes() == &[0; 32]
        || record.authority.resource_digest.as_bytes() == &[0; 32]
        || (version == VERSION
            && record
                .authority
                .kernel_plan_digest
                .is_none_or(|digest| digest.as_bytes() == &[0; 32]))
        || (version == LEGACY_VERSION && record.authority.kernel_plan_digest.is_some())
        || record.effect_digest.as_bytes() == &[0; 32]
        || record.current_fence.is_empty()
        || record.operation_fence.is_empty()
        || record.effect.is_empty()
        || !result_shape
        || !high_water_shape
        || record.effect_digest
            != lifecycle_effect_digest(
                record.request_id,
                record.transport_digest,
                record.semantic_digest,
                record.action,
                record.authority,
                record.desired_state,
            )
    {
        return Err(NetworkLifecycleStateError::CorruptRecord);
    }
    Ok(())
}

fn encode_state(bytes: &mut Vec<u8>, state: NetworkNamespaceObservedStateV1) {
    bytes.push(state_code(state.kind()));
    if let Some((digest, generation, deadline)) = state.lease() {
        bytes.extend_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&deadline.to_be_bytes());
    } else {
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
    }
}

fn encode_state_hash(hasher: &mut Sha256, state: NetworkNamespaceObservedStateV1) {
    hasher.update([state_code(state.kind())]);
    if let Some((digest, generation, deadline)) = state.lease() {
        hasher.update(digest.as_bytes());
        hasher.update(generation.to_be_bytes());
        hasher.update(deadline.to_be_bytes());
    } else {
        hasher.update([0; 32]);
        hasher.update(0_u64.to_be_bytes());
        hasher.update(0_u64.to_be_bytes());
    }
}

fn decode_state(
    decoder: &mut Decoder<'_>,
) -> Result<NetworkNamespaceObservedStateV1, NetworkLifecycleStateError> {
    let kind = decoder.byte()?;
    let digest = ObjectDigest::from_bytes(decoder.take()?);
    let generation = u64::from_be_bytes(decoder.take()?);
    let deadline = u64::from_be_bytes(decoder.take()?);
    match kind {
        1 if digest.as_bytes() == &[0; 32] && generation == 0 && deadline == 0 => {
            Ok(NetworkNamespaceObservedStateV1::default_drop())
        }
        2 => NetworkNamespaceObservedStateV1::armed(digest, generation, deadline)
            .map_err(|_| NetworkLifecycleStateError::CorruptRecord),
        3 => NetworkNamespaceObservedStateV1::fenced(digest, generation, deadline)
            .map_err(|_| NetworkLifecycleStateError::CorruptRecord),
        4 if digest.as_bytes() == &[0; 32] && generation == 0 && deadline == 0 => {
            Ok(NetworkNamespaceObservedStateV1::absent())
        }
        _ => Err(NetworkLifecycleStateError::CorruptRecord),
    }
}

fn push_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), NetworkLifecycleStateError> {
    let length =
        u32::try_from(value.len()).map_err(|_| NetworkLifecycleStateError::CorruptRecord)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn phase_code(phase: DurableNetworkLifecyclePhase) -> u8 {
    match phase {
        DurableNetworkLifecyclePhase::Prepared => 1,
        DurableNetworkLifecyclePhase::Ambiguous => 2,
        DurableNetworkLifecyclePhase::Committed => 3,
    }
}

fn decode_phase(value: u8) -> Result<DurableNetworkLifecyclePhase, NetworkLifecycleStateError> {
    match value {
        1 => Ok(DurableNetworkLifecyclePhase::Prepared),
        2 => Ok(DurableNetworkLifecyclePhase::Ambiguous),
        3 => Ok(DurableNetworkLifecyclePhase::Committed),
        _ => Err(NetworkLifecycleStateError::CorruptRecord),
    }
}

fn action_code(action: NetworkNamespaceLifecycleActionV1) -> u8 {
    match action {
        NetworkNamespaceLifecycleActionV1::Arm => 1,
        NetworkNamespaceLifecycleActionV1::Renew => 2,
        NetworkNamespaceLifecycleActionV1::Disarm => 3,
        NetworkNamespaceLifecycleActionV1::Fence => 4,
        NetworkNamespaceLifecycleActionV1::Destroy => 5,
    }
}

fn decode_action(
    value: u8,
) -> Result<NetworkNamespaceLifecycleActionV1, NetworkLifecycleStateError> {
    match value {
        1 => Ok(NetworkNamespaceLifecycleActionV1::Arm),
        2 => Ok(NetworkNamespaceLifecycleActionV1::Renew),
        3 => Ok(NetworkNamespaceLifecycleActionV1::Disarm),
        4 => Ok(NetworkNamespaceLifecycleActionV1::Fence),
        5 => Ok(NetworkNamespaceLifecycleActionV1::Destroy),
        _ => Err(NetworkLifecycleStateError::CorruptRecord),
    }
}

fn state_code(state: NetworkNamespaceObservedStateKindV1) -> u8 {
    match state {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 1,
        NetworkNamespaceObservedStateKindV1::Armed => 2,
        NetworkNamespaceObservedStateKindV1::Fenced => 3,
        NetworkNamespaceObservedStateKindV1::Absent => 4,
    }
}

fn verb_code(verb: BrokerVerb) -> Result<u8, NetworkLifecycleStateError> {
    match verb {
        BrokerVerb::NetworkArmLease => Ok(1),
        BrokerVerb::NetworkRenewLease => Ok(2),
        BrokerVerb::NetworkDisarm => Ok(3),
        BrokerVerb::NetworkDestroy => Ok(4),
        _ => Err(NetworkLifecycleStateError::CorruptRecord),
    }
}

fn decode_verb(value: u8) -> Result<BrokerVerb, NetworkLifecycleStateError> {
    match value {
        1 => Ok(BrokerVerb::NetworkArmLease),
        2 => Ok(BrokerVerb::NetworkRenewLease),
        3 => Ok(BrokerVerb::NetworkDisarm),
        4 => Ok(BrokerVerb::NetworkDestroy),
        _ => Err(NetworkLifecycleStateError::CorruptRecord),
    }
}

fn transaction_id(label: &[u8], request_id: &[u8; 16]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(label)
        .chain_update(request_id)
        .finalize()
        .into();
    digest[..16].try_into().unwrap_or([1; 16])
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkLifecycleStateError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
        self.cursor = end;
        value
            .try_into()
            .map_err(|_| NetworkLifecycleStateError::CorruptRecord)
    }

    fn byte(&mut self) -> Result<u8, NetworkLifecycleStateError> {
        Ok(self.take::<1>()?[0])
    }

    fn blob(&mut self) -> Result<&'a [u8], NetworkLifecycleStateError> {
        let length = u32::from_be_bytes(self.take()?) as usize;
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(NetworkLifecycleStateError::CorruptRecord)?;
        self.cursor = end;
        Ok(value)
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
