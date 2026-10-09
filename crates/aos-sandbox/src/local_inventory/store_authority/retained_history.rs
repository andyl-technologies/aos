//! Canonical retained-store history and authenticated historical projections.
//!
//! This child owns bounded head encoding, commitment joins and reducer replay,
//! including the artifact-backed watch projection required by local cold open.
//! It reads the original owner's history/context without taking its Journal,
//! creating a live session or replacing the parent's exclusive custody.
//!
//! The existing durable head uses this canonical framing:
//!
//! ```text
//! AOSMPS01 | version:u16be | reserved[6] | storage-domain[32] | replay-fence[32]
//! base-generation:u64be | base-root[32] | entry-count:u32be
//! repeated entry: domain/kind/operation | canonical object | receipt/context links
//! domain-separated SHA-256 checksum[32]
//! ```
//!
//! Cold open, prospective append and current readback use the same decoder and
//! typed replay. Historical grants are reconstructed only at the original
//! authenticated-context joins; no byte decoder certifies a new durable write.

use std::collections::BTreeMap;

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use crate::local_inventory::assignment::NodeAssignmentObservationV1;
use crate::local_inventory::capability::{NodeBootLineageV1, NodeCapabilitySnapshotV1};
use crate::local_inventory::draining::DrainObservationV1;
use crate::local_inventory::journal::{
    MultiNodeJournalCheckpointV1, MultiNodeJournalDomainV1, MultiNodeJournalRecordV1,
    MultiNodeJournalReducerV1, ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};
use crate::local_inventory::protected_artifact_store::ProtectedArtifactKindV1;
use crate::local_inventory::protocol::{
    CanonicalNodeSemanticCodecV1, InvalidMultiNodeProtocol, NodeWatchEventBodyV1, ResyncInventoryV1,
};
use crate::local_inventory::reducer_state::{
    DurableAssignmentObservationV1, DurableDrainObservationV1, MultiNodeReducerStateV1,
    WatchJournalStateV1,
};

use super::{
    AuthenticatedEvidenceContextV1, InvalidMultiNodeJournal, MAXIMUM_PROTECTED_STORE_HISTORY_BYTES,
    ProtectedMultiNodeAuthorityOwnerV1, ProtectedStoreCommitGrantV1, ProtectedStoreHistoryDecoderV1,
    ProtectedStoreHistoryEntryV1, ProtectedStoreObjectKindV1,
};

const PROTECTED_STORE_HISTORY_MAGIC: &[u8; 8] = b"AOSMPS01";

#[allow(clippy::too_many_arguments)]
pub(super) fn protected_transaction_digest(
    domain: super::super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes_digest: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    storage_domain_digest: ObjectDigest,
    expected_generation: u64,
    expected_root_digest: ObjectDigest,
    next_generation: u64,
    replay_fence: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.protected-transaction.v1\0");
    digest.update([domain as u8]);
    digest.update([match kind {
        ProtectedStoreObjectKindV1::Record => 1,
        ProtectedStoreObjectKindV1::Checkpoint => 2,
    }]);
    match operation {
        Some(operation) => {
            digest.update([1]);
            digest.update(operation.as_bytes());
        }
        None => digest.update([0; 17]),
    }
    digest.update(canonical_bytes_digest.as_bytes());
    match authority_binding_digest {
        Some(binding) => {
            digest.update([1]);
            digest.update(binding.as_bytes());
        }
        None => digest.update([0; 33]),
    }
    digest.update(storage_domain_digest.as_bytes());
    digest.update(expected_generation.to_be_bytes());
    digest.update(expected_root_digest.as_bytes());
    digest.update(next_generation.to_be_bytes());
    digest.update(replay_fence.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn encode_protected_store_history(
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    base_generation: u64,
    base_root_digest: ObjectDigest,
    history: &[ProtectedStoreHistoryEntryV1],
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    if history.len() > super::super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let count = u32::try_from(history.len())
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROTECTED_STORE_HISTORY_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(storage_domain_digest.as_bytes());
    bytes.extend_from_slice(replay_fence.as_bytes());
    bytes.extend_from_slice(&base_generation.to_be_bytes());
    bytes.extend_from_slice(base_root_digest.as_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for entry in history {
        let canonical_length = u32::try_from(entry.canonical_bytes.len())
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        bytes.push(entry.domain as u8);
        bytes.push(match entry.kind {
            ProtectedStoreObjectKindV1::Record => 1,
            ProtectedStoreObjectKindV1::Checkpoint => 2,
        });
        match entry.operation {
            Some(operation) => {
                bytes.push(1);
                bytes.extend_from_slice(operation.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 16]);
            }
        }
        bytes.push(0);
        bytes.extend_from_slice(&canonical_length.to_be_bytes());
        bytes.extend_from_slice(&entry.canonical_bytes);
        bytes.extend_from_slice(entry.canonical_bytes_digest.as_bytes());
        match entry.authority_binding_digest {
            Some(binding) => {
                bytes.push(1);
                bytes.extend_from_slice(binding.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 32]);
            }
        }
        bytes.extend_from_slice(&entry.durability_generation.to_be_bytes());
        bytes.extend_from_slice(entry.predecessor_root_digest.as_bytes());
        bytes.extend_from_slice(entry.protected_root_digest.as_bytes());
        bytes.extend_from_slice(entry.transaction_digest.as_bytes());
        bytes.extend_from_slice(entry.opaque_receipt_commitment.as_bytes());
        bytes.extend_from_slice(entry.context_digest.as_bytes());
        bytes.extend_from_slice(&entry.verified_at_unix_seconds.to_be_bytes());
        if bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-store-history.v1\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(bytes)
}

pub(super) fn decode_protected_store_history(
    bytes: &[u8],
    expected_storage_domain_digest: ObjectDigest,
    expected_replay_fence: ObjectDigest,
    expected_base_generation: u64,
    expected_base_root_digest: ObjectDigest,
) -> Result<Vec<ProtectedStoreHistoryEntryV1>, InvalidMultiNodeJournal> {
    if bytes.len() < 156 || bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let (payload, retained_digest) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    );
    let expected_digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-store-history.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_digest != expected_digest {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let mut decoder = ProtectedStoreHistoryDecoderV1::new(payload)?;
    if decoder.read_exact(8)? != PROTECTED_STORE_HISTORY_MAGIC
        || decoder.read_u16()? != 1
        || decoder.read_exact(6)? != [0; 6]
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_storage_domain_digest
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_replay_fence
        || decoder.read_u64()? != expected_base_generation
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_base_root_digest
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let count = usize::try_from(decoder.read_u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if count > super::super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let mut history = Vec::with_capacity(count);
    let mut predecessor_generation = expected_base_generation;
    let mut predecessor_root = expected_base_root_digest;
    for _ in 0..count {
        let domain = match decoder.read_u8()? {
            0 => super::super::journal::MultiNodeJournalDomainV1::Capability,
            1 => super::super::journal::MultiNodeJournalDomainV1::Assignment,
            2 => super::super::journal::MultiNodeJournalDomainV1::Drain,
            3 => super::super::journal::MultiNodeJournalDomainV1::SnapshotTransfer,
            4 => super::super::journal::MultiNodeJournalDomainV1::Watch,
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let kind = match decoder.read_u8()? {
            1 => ProtectedStoreObjectKindV1::Record,
            2 => ProtectedStoreObjectKindV1::Checkpoint,
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let operation_present = decoder.read_u8()?;
        let operation_bytes = decoder.read_array()?;
        let operation = match operation_present {
            0 if operation_bytes == [0; 16] => None,
            1 if operation_bytes != [0; 16] => Some(OperationId::from_bytes(operation_bytes)),
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        if decoder.read_u8()? != 0 {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let canonical_length = usize::try_from(decoder.read_u32()?)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        if canonical_length == 0
            || canonical_length > super::super::journal::MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let canonical_bytes = decoder.read_exact(canonical_length)?.to_vec();
        let canonical_bytes_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let binding_present = decoder.read_u8()?;
        let binding_bytes = decoder.read_array()?;
        let authority_binding_digest = match binding_present {
            0 if binding_bytes == [0; 32] => None,
            1 if binding_bytes != [0; 32] => Some(ObjectDigest::from_bytes(binding_bytes)),
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let durability_generation = decoder.read_u64()?;
        let predecessor_root_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let protected_root_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let transaction_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let opaque_receipt_commitment = ObjectDigest::from_bytes(decoder.read_array()?);
        let context_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let verified_at_unix_seconds = decoder.read_u64()?;
        if ObjectDigest::from_bytes(Sha256::digest(&canonical_bytes).into())
            != canonical_bytes_digest
            || predecessor_generation.checked_add(1) != Some(durability_generation)
            || predecessor_root_digest != predecessor_root
            || protected_store_successor_root(
                predecessor_root_digest,
                transaction_digest,
                opaque_receipt_commitment,
            ) != protected_root_digest
            || protected_transaction_digest(
                domain,
                kind,
                operation,
                canonical_bytes_digest,
                authority_binding_digest,
                expected_storage_domain_digest,
                predecessor_generation,
                predecessor_root_digest,
                durability_generation,
                expected_replay_fence,
            ) != transaction_digest
            || context_digest.as_bytes() == &[0; 32]
            || verified_at_unix_seconds == 0
            || protected_receipt_commitment_from_context_digest(
                transaction_digest,
                context_digest,
                verified_at_unix_seconds,
            ) != opaque_receipt_commitment
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        match kind {
            ProtectedStoreObjectKindV1::Record => {
                let record = MultiNodeJournalRecordV1::decode_canonical(&canonical_bytes)?;
                if operation != Some(record.operation()) || domain != record.domain() {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
            }
            ProtectedStoreObjectKindV1::Checkpoint => {
                let checkpoint = MultiNodeJournalCheckpointV1::decode_canonical(&canonical_bytes)?;
                if operation.is_some() || domain != checkpoint.domain() {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
            }
        }
        history.push(ProtectedStoreHistoryEntryV1 {
            domain,
            kind,
            operation,
            canonical_bytes,
            canonical_bytes_digest,
            authority_binding_digest,
            durability_generation,
            predecessor_root_digest,
            protected_root_digest,
            transaction_digest,
            opaque_receipt_commitment,
            context_digest,
            verified_at_unix_seconds,
        });
        predecessor_generation = durability_generation;
        predecessor_root = protected_root_digest;
    }
    if !decoder.is_finished() {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    if encode_protected_store_history(
        expected_storage_domain_digest,
        expected_replay_fence,
        expected_base_generation,
        expected_base_root_digest,
        &history,
    )?
    .as_slice()
        != bytes
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(history)
}

/// Replays every retained object through the typed reducer before it is trusted.
///
/// Receipt reconstruction is confined to this protected-store module and uses
/// only the authenticated context supplied when the journal was claimed. This
/// makes cold open and prospective writes enforce the same transition and
/// checkpoint-floor rules as live reducer use.
pub(super) fn validate_protected_store_semantics(
    history: &[ProtectedStoreHistoryEntryV1],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    authenticated_context: AuthenticatedEvidenceContextV1,
) -> Result<(), InvalidMultiNodeJournal> {
    replay_protected_store_semantics(
        history,
        storage_domain_digest,
        replay_fence,
        authenticated_context,
    )?;
    Ok(())
}

pub(super) fn replay_protected_store_semantics(
    history: &[ProtectedStoreHistoryEntryV1],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    authenticated_context: AuthenticatedEvidenceContextV1,
) -> Result<BTreeMap<MultiNodeJournalDomainV1, MultiNodeJournalReducerV1>, InvalidMultiNodeJournal>
{
    if history.len() > super::super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }

    let context_digest = protected_context_digest(authenticated_context);
    let mut reducers = BTreeMap::<_, MultiNodeJournalReducerV1>::new();
    for entry in history {
        if entry.context_digest != context_digest
            || !authenticated_context.is_current_at(entry.verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }

        let grant = ProtectedStoreCommitGrantV1 {
            kind: entry.kind,
            canonical_bytes_digest: entry.canonical_bytes_digest,
            storage_domain_digest,
            durability_generation: entry.durability_generation,
            protected_root_digest: entry.protected_root_digest,
            opaque_receipt_commitment: entry.opaque_receipt_commitment,
            replay_fence,
            authority_binding_digest: entry.authority_binding_digest,
            context: authenticated_context,
        };
        match entry.kind {
            ProtectedStoreObjectKindV1::Record => {
                let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
                let domain = record.domain();
                let reducer = match reducers.entry(domain) {
                    std::collections::btree_map::Entry::Occupied(occupied) => occupied.into_mut(),
                    std::collections::btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(MultiNodeJournalReducerV1::new(
                            domain,
                            protected_domain_genesis_digest(
                                storage_domain_digest,
                                replay_fence,
                                domain,
                            ),
                        )?)
                    }
                };
                let protected = ProtectedJournalRecordV1::from_authority_commit(
                    &entry.canonical_bytes,
                    grant,
                    entry.verified_at_unix_seconds,
                )?;
                reducer.apply(protected, entry.verified_at_unix_seconds)?;
            }
            ProtectedStoreObjectKindV1::Checkpoint => {
                let checkpoint =
                    MultiNodeJournalCheckpointV1::decode_canonical(&entry.canonical_bytes)?;
                let reducer = reducers
                    .get_mut(&checkpoint.domain())
                    .ok_or(InvalidMultiNodeJournal::UnsafeCompaction)?;
                let protected = ProtectedJournalCheckpointV1::from_authority_commit(
                    &entry.canonical_bytes,
                    grant,
                    entry.verified_at_unix_seconds,
                )?;
                reducer.compact(protected, entry.verified_at_unix_seconds)?;
            }
        }
    }
    Ok(reducers)
}

pub(super) fn protected_context_digest(context: AuthenticatedEvidenceContextV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.protected-store-context.v1\0");
    digest.update(context.node().as_bytes());
    digest.update(context.lineage().boot().as_bytes());
    digest.update(context.lineage().generation().to_be_bytes());
    digest.update(context.audience_digest().as_bytes());
    digest.update(context.disclosure_domain_digest().as_bytes());
    digest.update(context.carrier_binding_digest().as_bytes());
    digest.update(context.canonical_frame_digest().as_bytes());
    digest.update(context.canonical_frame_bytes().to_be_bytes());
    digest.update(context.coordinator_epoch().to_be_bytes());
    digest.update(context.verified_at_unix_seconds().to_be_bytes());
    digest.update(context.valid_until_unix_seconds().to_be_bytes());
    digest.update(context.replay_fence().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn durable_assignment_matches_report(
    durable: &DurableAssignmentObservationV1,
    report: &NodeAssignmentObservationV1,
) -> bool {
    durable.sandbox == report.sandbox()
        && durable.incarnation == report.incarnation()
        && durable.epoch == report.epoch()
        && durable.desired_generation == report.desired_generation()
        && durable.assignment_digest == report.assignment_digest()
        && durable.sequence == report.sequence()
        && durable.phase == report.phase()
        && durable.realized_lifecycle == report.realized_lifecycle()
        && durable.reason == report.reason()
        && durable.observed_at_unix_seconds == report.observed_at_unix_seconds()
}

pub(super) fn durable_drain_matches_report(
    durable: &DurableDrainObservationV1,
    report: &DrainObservationV1,
) -> bool {
    durable.sequence() == report.sequence()
        && durable.phase() == report.phase()
        && durable.observed_at_unix_seconds() == report.observed_at_unix_seconds()
        && durable.assignments().len() == report.assignments().len()
        && durable
            .assignments()
            .iter()
            .zip(report.assignments())
            .all(|(left, right)| {
                left.sandbox == right.sandbox()
                    && left.incarnation == right.incarnation()
                    && left.epoch == right.epoch()
                    && left.desired_generation == right.desired_generation()
                    && left.assignment_digest == right.assignment_digest()
                    && left.progress == right.progress()
            })
}

pub(super) fn protected_domain_genesis_digest(
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    domain: MultiNodeJournalDomainV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-domain-genesis.v1\0")
            .chain_update(storage_domain_digest.as_bytes())
            .chain_update(replay_fence.as_bytes())
            .chain_update([domain as u8])
            .finalize()
            .into(),
    )
}

pub(super) fn protected_receipt_commitment(
    transaction_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    verified_at_unix_seconds: u64,
) -> ObjectDigest {
    protected_receipt_commitment_from_context_digest(
        transaction_digest,
        protected_context_digest(context),
        verified_at_unix_seconds,
    )
}

fn protected_receipt_commitment_from_context_digest(
    transaction_digest: ObjectDigest,
    context_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-receipt.v1\0")
            .chain_update(transaction_digest.as_bytes())
            .chain_update(context_digest.as_bytes())
            .chain_update(verified_at_unix_seconds.to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(super) fn protected_store_successor_root(
    predecessor_root: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_commitment: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-root.v1\0")
            .chain_update(predecessor_root.as_bytes())
            .chain_update(transaction_digest.as_bytes())
            .chain_update(receipt_commitment.as_bytes())
            .finalize()
            .into(),
    )
}

struct ProtectedWatchSemanticProjectionV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    capability: NodeCapabilitySnapshotV1,
    assignments: BTreeMap<aos_sandbox_core::SandboxId, NodeAssignmentObservationV1>,
    drain: Option<DrainObservationV1>,
}

impl ProtectedWatchSemanticProjectionV1 {
    fn from_inventory(inventory: ResyncInventoryV1) -> Result<Self, InvalidMultiNodeProtocol> {
        let cursor = inventory.cursor();
        let assignments = inventory
            .assignments()
            .iter()
            .cloned()
            .map(|observation| (observation.sandbox(), observation))
            .collect::<BTreeMap<_, _>>();
        if assignments.len() != inventory.assignments().len() {
            return Err(InvalidMultiNodeProtocol::InventoryNotCanonical);
        }
        Ok(Self {
            node: cursor.node(),
            lineage: cursor.lineage(),
            capability: inventory.capabilities().clone(),
            assignments,
            drain: None,
        })
    }

    fn apply(&mut self, body: NodeWatchEventBodyV1) -> Result<(), InvalidMultiNodeProtocol> {
        match body {
            NodeWatchEventBodyV1::Capability(next) => {
                if next.node() != self.node
                    || next.lineage() != self.lineage
                    || next.sequence() <= self.capability.sequence()
                {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                self.capability = *next;
            }
            NodeWatchEventBodyV1::Assignment(next) => {
                if next.node() != self.node || next.lineage() != self.lineage {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                if let Some(prior) = self.assignments.get(&next.sandbox()) {
                    if next.sequence() <= prior.sequence()
                        || next.epoch() < prior.epoch()
                        || (next.epoch() == prior.epoch()
                            && next.desired_generation() < prior.desired_generation())
                        || (next.epoch() == prior.epoch()
                            && next.desired_generation() == prior.desired_generation()
                            && (next.assignment_digest() != prior.assignment_digest()
                                || !prior.phase().can_transition_to(next.phase())))
                    {
                        return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                    }
                }
                self.assignments.insert(next.sandbox(), *next);
            }
            NodeWatchEventBodyV1::Drain(next) => {
                if next.node() != self.node || next.lineage() != self.lineage {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                if self.drain.as_ref().is_some_and(|prior| {
                    next.generation() < prior.generation()
                        || (next.generation() == prior.generation()
                            && (next.operation() != prior.operation()
                                || next.sequence() <= prior.sequence()
                                || !prior.phase().can_transition_to(next.phase())))
                }) {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                self.drain = Some(*next);
            }
        }
        Ok(())
    }
}

impl ProtectedMultiNodeAuthorityOwnerV1 {
    pub(super) fn validate_watch_artifacts_and_semantics(
        &self,
        state: &WatchJournalStateV1,
        history_prefix_len: usize,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let inventory_bytes = self.artifacts.exact_payload(
            ProtectedArtifactKindV1::WatchInventory,
            state.bootstrap_inventory_digest(),
            state.binding().bootstrap_watermark(),
        )?;
        let inventory_receipt = self.artifacts.exact_receipt(
            ProtectedArtifactKindV1::WatchInventory,
            state.bootstrap_inventory_digest(),
            state.binding().bootstrap_watermark(),
        )?;
        if inventory_receipt != state.bootstrap_inventory_receipt() {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let codec = CanonicalNodeSemanticCodecV1::new();
        let inventory = codec
            .decode_watch_inventory(inventory_bytes, self.store.backend.authenticated_context)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        if inventory.cursor().binding() != state.binding()
            || inventory.cursor().event_sequence() != state.binding().bootstrap_watermark()
            || !self
                .history_prefix_contains_capability(history_prefix_len, inventory.capabilities())?
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut projection = ProtectedWatchSemanticProjectionV1::from_inventory(inventory)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        for event in state.events() {
            let bytes = self.artifacts.exact_payload(
                ProtectedArtifactKindV1::WatchEvent,
                event.event_uid,
                event.sequence,
            )?;
            let receipt = self.artifacts.exact_receipt(
                ProtectedArtifactKindV1::WatchEvent,
                event.event_uid,
                event.sequence,
            )?;
            if receipt != event.protected_event_receipt
                || usize::try_from(event.canonical_event_bytes).ok() != Some(bytes.len())
                || ObjectDigest::from_bytes(Sha256::digest(bytes).into())
                    != event.canonical_event_digest
            {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            let body = codec
                .decode_watch_event_body(bytes, self.store.backend.authenticated_context)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            if !self.history_contains_watch_domain_event(
                history_prefix_len,
                event.carrier_frame_digest,
                &body,
            )? {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            if let NodeWatchEventBodyV1::Drain(report) = &body
                && report.assignments().iter().any(|assignment| {
                    matches!(
                        assignment.progress(),
                        super::super::draining::DrainAssignmentProgressV1::Contained
                            | super::super::draining::DrainAssignmentProgressV1::Released
                    )
                })
                && !self.history_contains_verified_drain_event(
                    history_prefix_len,
                    event.carrier_frame_digest,
                    report,
                )?
            {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            projection
                .apply(body)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        }
        Ok(())
    }

    fn history_prefix_contains_capability(
        &self,
        history_prefix_len: usize,
        snapshot: &NodeCapabilitySnapshotV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.domain != MultiNodeJournalDomainV1::Capability
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            let MultiNodeReducerStateV1::Capability(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            if state.snapshot() == snapshot {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn history_contains_watch_domain_event(
        &self,
        history_prefix_len: usize,
        carrier_frame_digest: ObjectDigest,
        body: &NodeWatchEventBodyV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        let mut matching_intent_exists = false;
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.kind != ProtectedStoreObjectKindV1::Record {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            match (body, record.state_payload().state()) {
                (
                    NodeWatchEventBodyV1::Capability(snapshot),
                    MultiNodeReducerStateV1::Capability(state),
                ) if record.effect_digest() == carrier_frame_digest
                    && state.snapshot() == snapshot.as_ref()
                    && state.evidence().canonical_frame_digest() == carrier_frame_digest =>
                {
                    return Ok(true);
                }
                (
                    NodeWatchEventBodyV1::Assignment(observation),
                    MultiNodeReducerStateV1::Assignment(state),
                ) => {
                    if observation.matches(state.intent()) {
                        matching_intent_exists = true;
                        if record.effect_digest() == carrier_frame_digest
                            && state.observation().is_some_and(|durable| {
                                durable_assignment_matches_report(durable, observation)
                            })
                        {
                            return Ok(true);
                        }
                    }
                }
                (NodeWatchEventBodyV1::Drain(report), MultiNodeReducerStateV1::Drain(state))
                    if report.matches(state.directive()) =>
                {
                    matching_intent_exists = true;
                    if record.effect_digest() == carrier_frame_digest
                        && state
                            .observation()
                            .is_some_and(|durable| durable_drain_matches_report(durable, report))
                    {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(match body {
            NodeWatchEventBodyV1::Capability(_) => false,
            NodeWatchEventBodyV1::Assignment(_) | NodeWatchEventBodyV1::Drain(_) => {
                !matching_intent_exists
            }
        })
    }

    fn history_contains_verified_drain_event(
        &self,
        history_prefix_len: usize,
        carrier_frame_digest: ObjectDigest,
        report: &DrainObservationV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.domain != MultiNodeJournalDomainV1::Drain
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            if record.effect_digest() != carrier_frame_digest {
                continue;
            }
            let MultiNodeReducerStateV1::Drain(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            if state.directive().operation() == report.operation()
                && state
                    .observation()
                    .is_some_and(|durable| durable_drain_matches_report(durable, report))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn validate_protected_watch_history(&self) -> Result<(), InvalidMultiNodeJournal> {
        let mut prior: Option<WatchJournalStateV1> = None;
        for (history_index, entry) in self.store.backend.history.iter().enumerate() {
            if entry.domain != MultiNodeJournalDomainV1::Watch
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            let MultiNodeReducerStateV1::Watch(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            let state = state.clone();
            self.validate_watch_artifacts_and_semantics(&state, history_index)?;
            match &prior {
                None => {
                    if !state.events().is_empty()
                        || state.bootstrap_inventory_digest() != record.effect_digest()
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
                Some(previous) if state.events().is_empty() => {
                    if state.binding().bootstrap_watermark() < previous.cursor().event_sequence()
                        || state.bootstrap_inventory_digest() != record.effect_digest()
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
                Some(previous) => {
                    if !state.events().starts_with(previous.events())
                        || state.events().len() <= previous.events().len()
                        || state.events()[previous.events().len()..]
                            .iter()
                            .any(|event| event.carrier_frame_digest != record.effect_digest())
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
            }
            prior = Some(state);
        }
        Ok(())
    }

    pub(super) fn current_domain_projection(
        &self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<Option<MultiNodeReducerStateV1>, InvalidMultiNodeJournal> {
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            self.store.backend.authenticated_context,
        )?;
        Ok(reducers
            .get(&domain)
            .and_then(MultiNodeJournalReducerV1::restored_projection)
            .cloned())
    }
}
