//! Authenticated crash-recoverable network transaction state.
//!
//! Each operation record is sealed by the shared node journal key and embeds
//! the exact sealed fence and effect with which it was atomically published:
//!
//! ```text
//! AOSNTX01 || phase || request-id || sandbox-id || request-digest ||
//! semantic-digest || NetworkPrepare || exact preparation resolution ||
//! effect-digest || sealed-current-fence || sealed-operation-fence ||
//! sealed-pending-effect || optional verified-result
//! ```
//!
//! The durable phase crosses to Ambiguous before a helper may attempt a kernel
//! effect. Recovery from that boundary can only re-observe; it cannot reissue
//! the effect. Committed results retain exact current-boot namespace identity
//! without claiming that the pin is still present. Authoritative inventory is
//! a later catalog concern.

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker::{
    BrokerAuthorizationFenceV1, BrokerEffectStatusV2, BrokerLocalRecordDomain,
};
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::catalog::{NetworkCatalogBindingV1, ResolvedEndpointV1, ResolvedNetworkPreparationV1};

const MAGIC: &[u8; 8] = b"AOSNTX01";
const VERSION: u16 = 2;
const LEGACY_VERSION: u16 = 1;
const EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.effect.v1\0";
const RESULT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.result.v1\0";
const MAXIMUM_OPERATIONS: usize = 256;
const MAXIMUM_RECORD_BYTES: usize = 96 * 1024;

fn record_domain() -> Result<BrokerLocalRecordDomain, NetworkStateError> {
    BrokerLocalRecordDomain::new(*b"AOSNETSTATEV0001").map_err(|_| NetworkStateError::CorruptRecord)
}

/// Identifies the durable crash boundary of one network transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableNetworkPhase {
    /// Intent is durable and no effect may have been attempted.
    Prepared,
    /// The effect may have happened and recovery must only re-observe it.
    Ambiguous,
    /// A complete typed kernel observation was durably committed.
    Committed,
}

/// Carries the exact physical identity committed for one preparation effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedNetworkResultV1 {
    request_id: [u8; 16],
    preparation: NetworkCatalogBindingV1,
    network_handle: [u8; 32],
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    result_digest: ObjectDigest,
}

impl CommittedNetworkResultV1 {
    /// Returns the exact request that committed this result.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the exact protected preparation binding.
    #[must_use]
    pub const fn preparation(self) -> NetworkCatalogBindingV1 {
        self.preparation
    }

    /// Returns the reserved opaque network handle.
    #[must_use]
    pub const fn network_handle(self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the Linux boot in which the namespace was observed.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the observed `nsfs` device identity.
    #[must_use]
    pub const fn namespace_device(self) -> u64 {
        self.namespace_device
    }

    /// Returns the observed `nsfs` inode identity.
    #[must_use]
    pub const fn namespace_inode(self) -> u64 {
        self.namespace_inode
    }

    /// Returns the commitment to the complete helper observation.
    #[must_use]
    pub const fn result_digest(self) -> ObjectDigest {
        self.result_digest
    }
}

/// Carries a mechanically transaction-bound namespace observation.
///
/// This value does not itself inspect Linux. A future privileged helper must
/// construct it from a freshly type-checked namespace descriptor and complete
/// policy postcondition after crossing the durable Ambiguous boundary.
pub struct VerifiedNetworkResultV1 {
    request_id: [u8; 16],
    transport_digest: ObjectDigest,
    effect_digest: ObjectDigest,
    preparation: NetworkCatalogBindingV1,
    network_handle: [u8; 32],
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    result_digest: ObjectDigest,
}

impl VerifiedNetworkResultV1 {
    /// Binds one observed default-drop namespace to its exact preparation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError::InvalidValue`] for a zero request,
    /// transport or observation digest, boot, or physical namespace identity.
    pub fn verify_preparation(
        request_id: [u8; 16],
        transport_digest: ObjectDigest,
        preparation: &ResolvedNetworkPreparationV1,
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
        observation_digest: ObjectDigest,
    ) -> Result<Self, NetworkStateError> {
        if request_id == [0; 16]
            || transport_digest.as_bytes() == &[0; 32]
            || kernel_boot_id == [0; 16]
            || namespace_device == 0
            || namespace_inode == 0
            || observation_digest.as_bytes() == &[0; 32]
        {
            return Err(NetworkStateError::InvalidValue);
        }
        let effect_digest = effect_digest(request_id, transport_digest, preparation);
        Ok(Self {
            request_id,
            transport_digest,
            effect_digest,
            preparation: preparation.binding(),
            network_handle: *preparation.reserved_network_handle(),
            kernel_boot_id,
            namespace_device,
            namespace_inode,
            result_digest: result_digest(
                request_id,
                transport_digest,
                effect_digest,
                preparation.binding(),
                *preparation.reserved_network_handle(),
                kernel_boot_id,
                namespace_device,
                namespace_inode,
                observation_digest,
            ),
        })
    }
}

/// Summarizes one complete authenticated durable operation for recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRecoveryEntry {
    request_id: [u8; 16],
    sandbox_id: [u8; 16],
    phase: DurableNetworkPhase,
    network_handle: [u8; 32],
    catalog: NetworkCatalogBindingV1,
    verb: BrokerVerb,
    effect_digest: ObjectDigest,
    catalog_resolution: ResolvedNetworkPreparationV1,
    result: Option<CommittedNetworkResultV1>,
}

impl NetworkRecoveryEntry {
    /// Returns the stable request identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the assignment location of the authorization fence.
    #[must_use]
    pub const fn sandbox_id(&self) -> [u8; 16] {
        self.sandbox_id
    }

    /// Returns the durable crash phase.
    #[must_use]
    pub const fn phase(&self) -> DurableNetworkPhase {
        self.phase
    }

    /// Returns the protected opaque network handle.
    #[must_use]
    pub const fn network_handle(&self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the exact node-local catalog binding.
    #[must_use]
    pub const fn catalog(&self) -> NetworkCatalogBindingV1 {
        self.catalog
    }

    /// Returns the exact closed action requiring reconciliation.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the deterministic identity of the one-shot effect.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the lossless protected resolution required for re-observation.
    #[must_use]
    pub const fn catalog_resolution(&self) -> &ResolvedNetworkPreparationV1 {
        &self.catalog_resolution
    }

    /// Returns the committed physical result, when observation completed.
    #[must_use]
    pub const fn result(&self) -> Option<CommittedNetworkResultV1> {
        self.result
    }
}

/// Carries a complete bounded snapshot of durable operation history.
///
/// This is not current kernel inventory, proof that a resource exists, or
/// broker readiness evidence. A future observer must reconcile every entry
/// against kernel state before publishing authoritative network inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRecoverySnapshotV1 {
    sequence: u64,
    entries: Vec<NetworkRecoveryEntry>,
}

/// Carries the exact authenticated records produced by one fresh ambiguity transition.
///
/// There is deliberately no recovery accessor for this value. A process that
/// loses it can only observe or clean up the recovered ambiguous operation;
/// it cannot reconstruct effect-dispatch authority from durable state.
pub(crate) struct AmbiguousNetworkDispatchV1 {
    pub(crate) request_id: [u8; 16],
    pub(crate) sandbox_id: [u8; 16],
    pub(crate) transport_digest: ObjectDigest,
    pub(crate) semantic_digest: ObjectDigest,
    pub(crate) effect_digest: ObjectDigest,
    pub(crate) catalog: ResolvedNetworkPreparationV1,
    pub(crate) current_fence: Vec<u8>,
    pub(crate) operation_fence: Vec<u8>,
    pub(crate) effect: Vec<u8>,
}

impl NetworkRecoverySnapshotV1 {
    /// Returns the journal snapshot boundary.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns every durable operation in bytewise request-ID order.
    #[must_use]
    pub fn entries(&self) -> &[NetworkRecoveryEntry] {
        &self.entries
    }
}

/// Reports durable network state failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkStateError {
    /// The production state directory is not an exact protected root directory.
    #[error("network state directory is not protected")]
    UnprotectedDirectory,
    /// The shared journal failed validation or durable publication.
    #[error("network journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// A sealed local record is malformed, unauthenticated, or misplaced.
    #[error("network transaction record is corrupt")]
    CorruptRecord,
    /// One request identity was reused with different semantics.
    #[error("network transaction identity equivocated")]
    Equivocation,
    /// An operation is missing or disagrees with its authenticated authority links.
    #[error("network authority cross-link is missing or inconsistent")]
    AuthorityLink,
    /// Multiple unfinished operations make the sandbox recovery order ambiguous.
    #[error("sandbox already has an unfinished network transaction")]
    PendingConflict,
    /// A protected generation is below the external rollback anchor.
    #[error("network catalog generation rolled back")]
    Rollback,
    /// The bounded epoch has no remaining operation slots.
    #[error("network durable operation epoch is exhausted")]
    ResourceExhausted,
    /// The requested crash-boundary transition is not valid from current state.
    #[error("network durable phase transition is invalid")]
    InvalidTransition,
    /// A request, digest, boot, or physical namespace identity is a sentinel.
    #[error("network durable transaction contains a reserved value")]
    InvalidValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableRecord {
    phase: DurableNetworkPhase,
    request_id: [u8; 16],
    sandbox_id: [u8; 16],
    transport_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    verb: BrokerVerb,
    catalog: ResolvedNetworkPreparationV1,
    effect_digest: ObjectDigest,
    current_fence: Vec<u8>,
    operation_fence: Option<Vec<u8>>,
    effect: Vec<u8>,
    result: Option<CommittedNetworkResultV1>,
}

/// Owns the exclusive journal lock and its authenticated materialized view.
pub struct NetworkStateStore {
    journal: Journal,
    records: BTreeMap<[u8; 16], DurableRecord>,
    minimum_generation: u64,
}

impl NetworkStateStore {
    /// Opens and authenticates all state in an exact protected root directory.
    ///
    /// The directory must be root-owned mode 0700. Journal and lock files are
    /// opened relative to its retained descriptor and must be root-owned
    /// regular single-link files with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError`] for filesystem protection, journal,
    /// authentication, cross-link, bounds, or rollback failure.
    pub fn open_root_owned(
        directory: &Path,
        authority: &NetworkAuthorityV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkStateError> {
        let (journal, _) =
            Journal::open_protected_at(directory, "network-state.journal", journal_limits())?;
        Self::from_journal(journal, authority, minimum_generation)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        directory: &Path,
        authority: &NetworkAuthorityV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkStateError> {
        let (journal, _) =
            Journal::open(directory.join("network-state.journal"), journal_limits())?;
        Self::from_journal(journal, authority, minimum_generation)
    }

    fn from_journal(
        journal: Journal,
        authority: &NetworkAuthorityV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkStateError> {
        let mut records = BTreeMap::new();
        for (key, sealed) in journal.records(RecordNamespace::Operation) {
            let request_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkStateError::CorruptRecord)?;
            let payload = authority
                .open_local(&request_id, record_domain()?, sealed)
                .map_err(|_| NetworkStateError::CorruptRecord)?;
            let record = decode_record(payload)?;
            if record.request_id != request_id {
                return Err(NetworkStateError::CorruptRecord);
            }
            validate_record_links(&journal, authority, &record)?;
            if records.insert(request_id, record).is_some() {
                return Err(NetworkStateError::CorruptRecord);
            }
        }
        for (key, value) in journal.records(RecordNamespace::Effect) {
            let request_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkStateError::AuthorityLink)?;
            if records
                .get(&request_id)
                .is_none_or(|record| record.effect != value)
            {
                return Err(NetworkStateError::AuthorityLink);
            }
        }
        for (key, value) in journal.records(RecordNamespace::DesiredState) {
            let sandbox_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkStateError::AuthorityLink)?;
            if !records
                .values()
                .any(|record| record.sandbox_id == sandbox_id && record.current_fence == value)
            {
                return Err(NetworkStateError::AuthorityLink);
            }
        }
        if records.values().any(|record| {
            journal
                .get(RecordNamespace::DesiredState, &record.sandbox_id)
                .is_none()
        }) {
            return Err(NetworkStateError::AuthorityLink);
        }
        for (key, value) in journal.records(RecordNamespace::AuthorityPublication) {
            let request_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkStateError::AuthorityLink)?;
            if records
                .get(&request_id)
                .and_then(|record| record.operation_fence.as_deref())
                != Some(value)
            {
                return Err(NetworkStateError::AuthorityLink);
            }
        }
        if records.len() > MAXIMUM_OPERATIONS
            || records
                .values()
                .map(|record| record.catalog.binding().generation())
                .max()
                .unwrap_or(0)
                < minimum_generation
        {
            return Err(NetworkStateError::Rollback);
        }
        validate_pending_uniqueness(&records)?;
        validate_resource_uniqueness(&records)?;
        validate_current_fence_heads(&journal, authority, &records)?;
        Ok(Self {
            journal,
            records,
            minimum_generation,
        })
    }

    /// Returns bounded durable history for startup reconciliation.
    ///
    /// The result makes no current-kernel existence or readiness claim.
    #[must_use]
    pub fn recovery_snapshot(&self) -> NetworkRecoverySnapshotV1 {
        NetworkRecoverySnapshotV1 {
            sequence: self.journal.snapshot_sequence(),
            entries: self.records.values().map(recovery_entry).collect(),
        }
    }

    /// Iterates the complete deterministic recovery set.
    pub fn recovery_entries(&self) -> impl Iterator<Item = NetworkRecoveryEntry> + '_ {
        self.records.values().map(recovery_entry)
    }

    /// Returns the durable phase for one request.
    #[must_use]
    pub fn phase(&self, request_id: [u8; 16]) -> Option<DurableNetworkPhase> {
        self.records.get(&request_id).map(|record| record.phase)
    }

    /// Reconstructs the exact protected preparation for a current recovery entry.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError::InvalidTransition`] when `entry` no longer
    /// names the exact current operation record.
    pub fn recover_preparation(
        &self,
        entry: &NetworkRecoveryEntry,
    ) -> Result<ResolvedNetworkPreparationV1, NetworkStateError> {
        self.records
            .get(&entry.request_id)
            .filter(|record| recovery_entry(record) == *entry)
            .map(|record| record.catalog.clone())
            .ok_or(NetworkStateError::InvalidTransition)
    }

    /// Returns the exact current recovery entry for one committed result.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError::InvalidTransition`] when the result was
    /// copied from another store or no longer identifies a committed record.
    pub fn committed_recovery_entry(
        &self,
        result: CommittedNetworkResultV1,
    ) -> Result<NetworkRecoveryEntry, NetworkStateError> {
        self.records
            .get(&result.request_id)
            .filter(|record| {
                record.phase == DurableNetworkPhase::Committed && record.result == Some(result)
            })
            .map(recovery_entry)
            .ok_or(NetworkStateError::InvalidTransition)
    }

    pub(crate) fn authority_record(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.journal.get(namespace, key)
    }

    #[cfg(test)]
    pub(crate) fn fill_epoch_for_test(&mut self) {
        let Some(seed) = self.records.values().next().cloned() else {
            return;
        };
        for value in 1_u16.. {
            if self.records.len() == MAXIMUM_OPERATIONS {
                break;
            }
            let mut key = [0; 16];
            key[14..].copy_from_slice(&value.to_be_bytes());
            self.records.entry(key).or_insert_with(|| {
                let mut record = seed.clone();
                record.request_id = key;
                record
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn rewrite_as_legacy_for_test(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
    ) -> Result<(), NetworkStateError> {
        let mut record = self
            .records
            .get(&request_id)
            .cloned()
            .ok_or(NetworkStateError::InvalidTransition)?;
        if record.phase != DurableNetworkPhase::Prepared {
            return Err(NetworkStateError::InvalidTransition);
        }
        record.operation_fence = None;
        let payload = encode_legacy_record(&record)?;
        let sealed_local = authority
            .seal_local(&request_id, record_domain()?, &payload)
            .map_err(|_| NetworkStateError::AuthorityLink)?;
        let transaction = JournalTransaction::new(
            transaction_id(b"legacy", &request_id),
            vec![
                JournalRecord::delete(RecordNamespace::AuthorityPublication, request_id.to_vec()),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    request_id.to_vec(),
                    sealed_local,
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(request_id, record);
        Ok(())
    }

    pub(crate) fn begin_authorized(
        &mut self,
        authority: &NetworkAuthorityV1,
        record: DurableRecord,
    ) -> Result<NetworkBeginOutcome, NetworkStateError> {
        if let Some(existing) = self.records.get(&record.request_id) {
            if existing.transport_digest != record.transport_digest
                || existing.semantic_digest != record.semantic_digest
                || existing.verb != record.verb
                || existing.catalog != record.catalog
                || existing.sandbox_id != record.sandbox_id
                || existing.effect_digest != record.effect_digest
            {
                return Err(NetworkStateError::Equivocation);
            }
            return Ok(match (existing.phase, existing.result) {
                (DurableNetworkPhase::Committed, Some(result)) => {
                    NetworkBeginOutcome::Replay(result)
                }
                (phase, _) => NetworkBeginOutcome::ObserveOnly {
                    phase,
                    effect_digest: existing.effect_digest,
                },
            });
        }
        if self.records.len() >= MAXIMUM_OPERATIONS {
            return Err(NetworkStateError::ResourceExhausted);
        }
        if record.catalog.binding().generation() < self.minimum_generation
            || record.catalog.binding().generation()
                < self
                    .records
                    .values()
                    .map(|value| value.catalog.binding().generation())
                    .max()
                    .unwrap_or(0)
        {
            return Err(NetworkStateError::Rollback);
        }
        if self.records.values().any(|existing| {
            existing.catalog.reserved_network_handle() == record.catalog.reserved_network_handle()
        }) {
            return Err(NetworkStateError::Equivocation);
        }
        if self.records.values().any(|existing| {
            existing.sandbox_id == record.sandbox_id
                && existing.phase != DurableNetworkPhase::Committed
        }) {
            return Err(NetworkStateError::PendingConflict);
        }
        let payload = encode_record(&record)?;
        let sealed_local = authority
            .seal_local(&record.request_id, record_domain()?, &payload)
            .map_err(|_| NetworkStateError::AuthorityLink)?;
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
                    record
                        .operation_fence
                        .clone()
                        .ok_or(NetworkStateError::AuthorityLink)?,
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    record.request_id.to_vec(),
                    sealed_local,
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        let effect_digest = record.effect_digest;
        self.records.insert(record.request_id, record);
        Ok(NetworkBeginOutcome::Prepared { effect_digest })
    }

    /// Durably crosses the point after which a network effect may have run.
    ///
    /// A privileged helper must call this and wait for its synchronous journal
    /// commit before creating a namespace, veth, or policy object.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError::InvalidTransition`] unless the exact
    /// prepared request and effect digest are current.
    pub(crate) fn mark_effect_ambiguous(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<AmbiguousNetworkDispatchV1, NetworkStateError> {
        let mut record = self.exact_current(request_id, effect_digest)?.clone();
        if record.phase != DurableNetworkPhase::Prepared || record.operation_fence.is_none() {
            return Err(NetworkStateError::InvalidTransition);
        }
        record.phase = DurableNetworkPhase::Ambiguous;
        self.publish(authority, record.clone())?;
        ambiguous_dispatch(record)
    }

    /// Commits a complete typed observation for one ambiguous preparation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkStateError::InvalidTransition`] unless the assertion is
    /// bound to the exact ambiguous request, transport, effect, catalog, and
    /// reserved handle. A physical namespace already committed to another
    /// request in the same boot is also rejected.
    pub(crate) fn commit_verified(
        &mut self,
        authority: &NetworkAuthorityV1,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        verified: VerifiedNetworkResultV1,
    ) -> Result<CommittedNetworkResultV1, NetworkStateError> {
        let mut record = self.exact_current(request_id, effect_digest)?.clone();
        if record.phase != DurableNetworkPhase::Ambiguous
            || record.operation_fence.is_none()
            || verified.request_id != record.request_id
            || verified.transport_digest != record.transport_digest
            || verified.effect_digest != record.effect_digest
            || verified.preparation != record.catalog.binding()
            || verified.network_handle != *record.catalog.reserved_network_handle()
            || self.records.values().any(|existing| {
                existing.request_id != request_id
                    && existing.result.is_some_and(|result| {
                        result.kernel_boot_id == verified.kernel_boot_id
                            && result.namespace_device == verified.namespace_device
                            && result.namespace_inode == verified.namespace_inode
                    })
            })
        {
            return Err(NetworkStateError::InvalidTransition);
        }
        let result = CommittedNetworkResultV1 {
            request_id,
            preparation: verified.preparation,
            network_handle: verified.network_handle,
            kernel_boot_id: verified.kernel_boot_id,
            namespace_device: verified.namespace_device,
            namespace_inode: verified.namespace_inode,
            result_digest: verified.result_digest,
        };
        record.phase = DurableNetworkPhase::Committed;
        record.result = Some(result);
        self.publish(authority, record)?;
        Ok(result)
    }

    fn exact_current(
        &self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<&DurableRecord, NetworkStateError> {
        self.records
            .get(&request_id)
            .filter(|record| record.effect_digest == effect_digest)
            .ok_or(NetworkStateError::InvalidTransition)
    }

    fn publish(
        &mut self,
        authority: &NetworkAuthorityV1,
        record: DurableRecord,
    ) -> Result<(), NetworkStateError> {
        let payload = encode_record(&record)?;
        let sealed_local = authority
            .seal_local(&record.request_id, record_domain()?, &payload)
            .map_err(|_| NetworkStateError::AuthorityLink)?;
        let transaction = JournalTransaction::new(
            transaction_id(phase_label(record.phase), &record.request_id),
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                record.request_id.to_vec(),
                sealed_local,
            )],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(record.request_id, record);
        Ok(())
    }
}

/// Classifies an idempotent durable admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkBeginOutcome {
    Prepared {
        effect_digest: ObjectDigest,
    },
    ObserveOnly {
        phase: DurableNetworkPhase,
        effect_digest: ObjectDigest,
    },
    Replay(CommittedNetworkResultV1),
}

pub(crate) struct PreparedNetworkRecordInput {
    pub request_id: [u8; 16],
    pub sandbox_id: [u8; 16],
    pub transport_digest: ObjectDigest,
    pub semantic_digest: ObjectDigest,
    pub verb: BrokerVerb,
    pub catalog: ResolvedNetworkPreparationV1,
    pub current_fence: Vec<u8>,
    pub operation_fence: Vec<u8>,
    pub effect: Vec<u8>,
}

pub(crate) fn prepared_record(input: PreparedNetworkRecordInput) -> DurableRecord {
    DurableRecord {
        phase: DurableNetworkPhase::Prepared,
        request_id: input.request_id,
        sandbox_id: input.sandbox_id,
        transport_digest: input.transport_digest,
        semantic_digest: input.semantic_digest,
        verb: input.verb,
        effect_digest: effect_digest(input.request_id, input.transport_digest, &input.catalog),
        catalog: input.catalog,
        current_fence: input.current_fence,
        operation_fence: Some(input.operation_fence),
        effect: input.effect,
        result: None,
    }
}

fn recovery_entry(record: &DurableRecord) -> NetworkRecoveryEntry {
    NetworkRecoveryEntry {
        request_id: record.request_id,
        sandbox_id: record.sandbox_id,
        phase: record.phase,
        network_handle: *record.catalog.reserved_network_handle(),
        catalog: record.catalog.binding(),
        verb: record.verb,
        effect_digest: record.effect_digest,
        catalog_resolution: record.catalog.clone(),
        result: record.result,
    }
}

fn ambiguous_dispatch(
    record: DurableRecord,
) -> Result<AmbiguousNetworkDispatchV1, NetworkStateError> {
    let operation_fence = record
        .operation_fence
        .ok_or(NetworkStateError::InvalidTransition)?;
    if record.phase != DurableNetworkPhase::Ambiguous
        || record.verb != BrokerVerb::NetworkPrepare
        || record.result.is_some()
    {
        return Err(NetworkStateError::InvalidTransition);
    }

    Ok(AmbiguousNetworkDispatchV1 {
        request_id: record.request_id,
        sandbox_id: record.sandbox_id,
        transport_digest: record.transport_digest,
        semantic_digest: record.semantic_digest,
        effect_digest: record.effect_digest,
        catalog: record.catalog,
        current_fence: record.current_fence,
        operation_fence,
        effect: record.effect,
    })
}

fn validate_record_links(
    journal: &Journal,
    authority: &NetworkAuthorityV1,
    record: &DurableRecord,
) -> Result<(), NetworkStateError> {
    let persisted_effect = journal
        .get(RecordNamespace::Effect, &record.request_id)
        .ok_or(NetworkStateError::AuthorityLink)?;
    if persisted_effect != record.effect {
        return Err(NetworkStateError::AuthorityLink);
    }
    let current_fence = authority
        .open_fence(&record.sandbox_id, &record.current_fence)
        .map_err(|_| NetworkStateError::AuthorityLink)?;
    let (effect, operation_fence) = if let Some(sealed) = &record.operation_fence {
        let persisted = journal
            .get(RecordNamespace::AuthorityPublication, &record.request_id)
            .ok_or(NetworkStateError::AuthorityLink)?;
        if persisted != sealed {
            return Err(NetworkStateError::AuthorityLink);
        }
        let effect = authority
            .validate_operation_links(
                &record.sandbox_id,
                &record.request_id,
                sealed,
                &record.effect,
            )
            .map_err(|_| NetworkStateError::AuthorityLink)?;
        let fence = authority
            .open_operation_fence(&record.request_id, sealed)
            .map_err(|_| NetworkStateError::AuthorityLink)?;
        (effect, fence)
    } else {
        let persisted = journal
            .get(RecordNamespace::DesiredState, &record.sandbox_id)
            .ok_or(NetworkStateError::AuthorityLink)?;
        if persisted != record.current_fence {
            return Err(NetworkStateError::AuthorityLink);
        }
        let effect = authority
            .validate_links(
                &record.sandbox_id,
                &record.request_id,
                &record.current_fence,
                &record.effect,
            )
            .map_err(|_| NetworkStateError::AuthorityLink)?;
        (effect, current_fence.clone())
    };
    let expected_target = BrokerGrantTarget::Assignment;
    if current_fence != operation_fence
        || effect.request_id() != &record.request_id
        || effect.transport_request_digest() != record.transport_digest
        || effect.request_digest() != record.semantic_digest
        || effect.verb() != record.verb
        || effect.target() != expected_target
        || effect.plan_digest() != operation_fence.plan_digest()
        || effect.status() != BrokerEffectStatusV2::Pending
        || record.effect_digest
            != effect_digest(record.request_id, record.transport_digest, &record.catalog)
    {
        return Err(NetworkStateError::AuthorityLink);
    }
    Ok(())
}

fn validate_pending_uniqueness(
    records: &BTreeMap<[u8; 16], DurableRecord>,
) -> Result<(), NetworkStateError> {
    let mut pending = BTreeMap::new();
    for record in records.values() {
        if record.phase != DurableNetworkPhase::Committed
            && pending
                .insert(record.sandbox_id, record.request_id)
                .is_some()
        {
            return Err(NetworkStateError::PendingConflict);
        }
    }
    Ok(())
}

fn validate_resource_uniqueness(
    records: &BTreeMap<[u8; 16], DurableRecord>,
) -> Result<(), NetworkStateError> {
    let mut handles = BTreeMap::new();
    let mut physical_namespaces = BTreeMap::new();
    for record in records.values() {
        if handles
            .insert(*record.catalog.reserved_network_handle(), record.request_id)
            .is_some()
        {
            return Err(NetworkStateError::Equivocation);
        }
        if let Some(result) = record.result
            && physical_namespaces
                .insert(
                    (
                        result.kernel_boot_id,
                        result.namespace_device,
                        result.namespace_inode,
                    ),
                    record.request_id,
                )
                .is_some()
        {
            return Err(NetworkStateError::Equivocation);
        }
    }
    Ok(())
}

fn validate_current_fence_heads(
    journal: &Journal,
    authority: &NetworkAuthorityV1,
    records: &BTreeMap<[u8; 16], DurableRecord>,
) -> Result<(), NetworkStateError> {
    for current_record in records.values() {
        let current_bytes = journal
            .get(RecordNamespace::DesiredState, &current_record.sandbox_id)
            .ok_or(NetworkStateError::AuthorityLink)?;
        let current = authority
            .open_fence(&current_record.sandbox_id, current_bytes)
            .map_err(|_| NetworkStateError::AuthorityLink)?;

        for historical_record in records
            .values()
            .filter(|record| record.sandbox_id == current_record.sandbox_id)
        {
            let historical = match &historical_record.operation_fence {
                Some(bytes) => authority
                    .open_operation_fence(&historical_record.request_id, bytes)
                    .map_err(|_| NetworkStateError::AuthorityLink)?,
                None => authority
                    .open_fence(
                        &historical_record.sandbox_id,
                        &historical_record.current_fence,
                    )
                    .map_err(|_| NetworkStateError::AuthorityLink)?,
            };
            if !fence_follows(&current, &historical) {
                return Err(NetworkStateError::AuthorityLink);
            }
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

fn encode_record(record: &DurableRecord) -> Result<Vec<u8>, NetworkStateError> {
    validate_record_shape(record, VERSION)?;
    let operation_fence = record
        .operation_fence
        .as_deref()
        .ok_or(NetworkStateError::CorruptRecord)?;
    let mut bytes = Vec::with_capacity(
        640 + record.current_fence.len() + operation_fence.len() + record.effect.len(),
    );
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(phase_code(record.phase));
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(record.transport_digest.as_bytes());
    bytes.extend_from_slice(record.semantic_digest.as_bytes());
    bytes.push(verb_code(record.verb)?);
    encode_catalog(&mut bytes, &record.catalog)?;
    bytes.extend_from_slice(record.effect_digest.as_bytes());
    push_blob(&mut bytes, &record.current_fence)?;
    push_blob(&mut bytes, operation_fence)?;
    push_blob(&mut bytes, &record.effect)?;
    if let Some(result) = record.result {
        encode_result(&mut bytes, result);
    }
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkStateError::CorruptRecord);
    }
    Ok(bytes)
}

#[cfg(test)]
fn encode_legacy_record(record: &DurableRecord) -> Result<Vec<u8>, NetworkStateError> {
    validate_record_shape(record, LEGACY_VERSION)?;
    let mut bytes = Vec::with_capacity(512 + record.current_fence.len() + record.effect.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    bytes.push(phase_code(record.phase));
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(record.transport_digest.as_bytes());
    bytes.extend_from_slice(record.semantic_digest.as_bytes());
    bytes.push(verb_code(record.verb)?);
    encode_catalog(&mut bytes, &record.catalog)?;
    push_blob(&mut bytes, &record.current_fence)?;
    push_blob(&mut bytes, &record.effect)?;
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkStateError::CorruptRecord);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<DurableRecord, NetworkStateError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkStateError::CorruptRecord);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>()? != *MAGIC {
        return Err(NetworkStateError::CorruptRecord);
    }
    let version = u16::from_be_bytes(decoder.take()?);
    if !matches!(version, LEGACY_VERSION | VERSION) {
        return Err(NetworkStateError::CorruptRecord);
    }
    let phase = decode_phase(decoder.byte()?)?;
    let request_id = decoder.take()?;
    let sandbox_id = decoder.take()?;
    let transport_digest = ObjectDigest::from_bytes(decoder.take()?);
    let semantic_digest = ObjectDigest::from_bytes(decoder.take()?);
    let verb = decode_verb(decoder.byte()?)?;
    let catalog = decode_catalog(&mut decoder)?;
    let effect_digest = if version == VERSION {
        ObjectDigest::from_bytes(decoder.take()?)
    } else {
        effect_digest(request_id, transport_digest, &catalog)
    };
    let current_fence = decoder.blob()?.to_vec();
    let operation_fence = if version == VERSION {
        Some(decoder.blob()?.to_vec())
    } else {
        None
    };
    let effect = decoder.blob()?.to_vec();
    let result = if phase == DurableNetworkPhase::Committed {
        Some(decode_result(&mut decoder, catalog.binding())?)
    } else {
        None
    };
    let record = DurableRecord {
        phase,
        request_id,
        sandbox_id,
        transport_digest,
        semantic_digest,
        verb,
        catalog,
        effect_digest,
        current_fence,
        operation_fence,
        effect,
        result,
    };
    if !decoder.finished() {
        return Err(NetworkStateError::CorruptRecord);
    }
    validate_record_shape(&record, version)?;
    Ok(record)
}

fn validate_record_shape(record: &DurableRecord, version: u16) -> Result<(), NetworkStateError> {
    let result_shape_valid = match (record.phase, record.result) {
        (DurableNetworkPhase::Committed, Some(result)) => {
            result.request_id == record.request_id
                && result.preparation == record.catalog.binding()
                && result.network_handle == *record.catalog.reserved_network_handle()
                && result.kernel_boot_id != [0; 16]
                && result.namespace_device != 0
                && result.namespace_inode != 0
                && result.result_digest.as_bytes() != &[0; 32]
        }
        (DurableNetworkPhase::Prepared | DurableNetworkPhase::Ambiguous, None) => true,
        _ => false,
    };
    let version_shape_valid = match version {
        LEGACY_VERSION => {
            record.phase == DurableNetworkPhase::Prepared
                && record.operation_fence.is_none()
                && record.result.is_none()
        }
        VERSION => record
            .operation_fence
            .as_ref()
            .is_some_and(|fence| !fence.is_empty()),
        _ => false,
    };
    if record.request_id == [0; 16]
        || record.sandbox_id == [0; 16]
        || record.transport_digest.as_bytes() == &[0; 32]
        || record.semantic_digest.as_bytes() == &[0; 32]
        || record.effect_digest.as_bytes() == &[0; 32]
        || record.current_fence.is_empty()
        || record.effect.is_empty()
        || record.effect_digest
            != effect_digest(record.request_id, record.transport_digest, &record.catalog)
        || !result_shape_valid
        || !version_shape_valid
    {
        return Err(NetworkStateError::CorruptRecord);
    }
    Ok(())
}

fn encode_result(bytes: &mut Vec<u8>, result: CommittedNetworkResultV1) {
    bytes.extend_from_slice(&result.request_id);
    bytes.extend_from_slice(&result.preparation.generation().to_be_bytes());
    bytes.extend_from_slice(result.preparation.digest().as_bytes());
    bytes.extend_from_slice(&result.network_handle);
    bytes.extend_from_slice(&result.kernel_boot_id);
    bytes.extend_from_slice(&result.namespace_device.to_be_bytes());
    bytes.extend_from_slice(&result.namespace_inode.to_be_bytes());
    bytes.extend_from_slice(result.result_digest.as_bytes());
}

fn decode_result(
    decoder: &mut Decoder<'_>,
    expected_preparation: NetworkCatalogBindingV1,
) -> Result<CommittedNetworkResultV1, NetworkStateError> {
    let request_id = decoder.take()?;
    let generation = u64::from_be_bytes(decoder.take()?);
    let digest = ObjectDigest::from_bytes(decoder.take()?);
    if generation != expected_preparation.generation() || digest != expected_preparation.digest() {
        return Err(NetworkStateError::CorruptRecord);
    }
    Ok(CommittedNetworkResultV1 {
        request_id,
        preparation: expected_preparation,
        network_handle: decoder.take()?,
        kernel_boot_id: decoder.take()?,
        namespace_device: u64::from_be_bytes(decoder.take()?),
        namespace_inode: u64::from_be_bytes(decoder.take()?),
        result_digest: ObjectDigest::from_bytes(decoder.take()?),
    })
}

fn push_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), NetworkStateError> {
    let length = u32::try_from(value.len()).map_err(|_| NetworkStateError::CorruptRecord)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn verb_code(verb: BrokerVerb) -> Result<u8, NetworkStateError> {
    match verb {
        BrokerVerb::NetworkPrepare => Ok(1),
        _ => Err(NetworkStateError::CorruptRecord),
    }
}

fn decode_verb(code: u8) -> Result<BrokerVerb, NetworkStateError> {
    match code {
        1 => Ok(BrokerVerb::NetworkPrepare),
        _ => Err(NetworkStateError::CorruptRecord),
    }
}

const fn phase_code(phase: DurableNetworkPhase) -> u8 {
    match phase {
        DurableNetworkPhase::Prepared => 1,
        DurableNetworkPhase::Ambiguous => 2,
        DurableNetworkPhase::Committed => 3,
    }
}

fn decode_phase(code: u8) -> Result<DurableNetworkPhase, NetworkStateError> {
    match code {
        1 => Ok(DurableNetworkPhase::Prepared),
        2 => Ok(DurableNetworkPhase::Ambiguous),
        3 => Ok(DurableNetworkPhase::Committed),
        _ => Err(NetworkStateError::CorruptRecord),
    }
}

const fn phase_label(phase: DurableNetworkPhase) -> &'static [u8] {
    match phase {
        DurableNetworkPhase::Prepared => b"prepared",
        DurableNetworkPhase::Ambiguous => b"ambiguous",
        DurableNetworkPhase::Committed => b"committed",
    }
}

pub(crate) fn effect_digest(
    request_id: [u8; 16],
    transport_digest: ObjectDigest,
    catalog: &ResolvedNetworkPreparationV1,
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(EFFECT_DIGEST_DOMAIN);
    hash.update(request_id);
    hash.update(transport_digest.as_bytes());
    hash.update(catalog.binding().generation().to_be_bytes());
    hash.update(catalog.binding().digest().as_bytes());
    hash.update(catalog.reserved_network_handle());
    hash.update(catalog.profile_digest().as_bytes());
    hash.update((catalog.endpoints().len() as u64).to_be_bytes());
    for endpoint in catalog.endpoints() {
        hash.update(endpoint.id());
        hash.update(endpoint.policy_digest().as_bytes());
    }
    ObjectDigest::from_bytes(hash.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn result_digest(
    request_id: [u8; 16],
    transport_digest: ObjectDigest,
    effect_digest: ObjectDigest,
    preparation: NetworkCatalogBindingV1,
    network_handle: [u8; 32],
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    observation_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(RESULT_DIGEST_DOMAIN);
    hash.update(request_id);
    hash.update(transport_digest.as_bytes());
    hash.update(effect_digest.as_bytes());
    hash.update(preparation.generation().to_be_bytes());
    hash.update(preparation.digest().as_bytes());
    hash.update(network_handle);
    hash.update(kernel_boot_id);
    hash.update(namespace_device.to_be_bytes());
    hash.update(namespace_inode.to_be_bytes());
    hash.update(observation_digest.as_bytes());
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn encode_catalog(
    bytes: &mut Vec<u8>,
    catalog: &ResolvedNetworkPreparationV1,
) -> Result<(), NetworkStateError> {
    bytes.extend_from_slice(&catalog.binding().generation().to_be_bytes());
    bytes.extend_from_slice(catalog.reserved_network_handle());
    bytes.extend_from_slice(catalog.profile_digest().as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(catalog.endpoints().len())
            .map_err(|_| NetworkStateError::CorruptRecord)?
            .to_be_bytes(),
    );
    for endpoint in catalog.endpoints() {
        bytes.extend_from_slice(endpoint.id());
        bytes.extend_from_slice(endpoint.policy_digest().as_bytes());
    }
    Ok(())
}

fn decode_catalog(
    decoder: &mut Decoder<'_>,
) -> Result<ResolvedNetworkPreparationV1, NetworkStateError> {
    let generation = u64::from_be_bytes(decoder.take()?);
    let handle = decoder.take()?;
    let policy = ObjectDigest::from_bytes(decoder.take()?);
    let count = usize::from(u16::from_be_bytes(decoder.take()?));
    if count > 256 {
        return Err(NetworkStateError::CorruptRecord);
    }
    let mut endpoints = Vec::with_capacity(count);
    for _ in 0..count {
        endpoints.push(
            ResolvedEndpointV1::new(decoder.take()?, ObjectDigest::from_bytes(decoder.take()?))
                .map_err(|_| NetworkStateError::CorruptRecord)?,
        );
    }
    ResolvedNetworkPreparationV1::new(generation, handle, policy, endpoints)
        .map_err(|_| NetworkStateError::CorruptRecord)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkStateError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(NetworkStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkStateError::CorruptRecord)?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| NetworkStateError::CorruptRecord)
    }

    fn byte(&mut self) -> Result<u8, NetworkStateError> {
        Ok(self.take::<1>()?[0])
    }

    fn blob(&mut self) -> Result<&'a [u8], NetworkStateError> {
        let length = usize::try_from(u32::from_be_bytes(self.take()?))
            .map_err(|_| NetworkStateError::CorruptRecord)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NetworkStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkStateError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn transaction_id(label: &[u8], request_id: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.network.transaction.v1\0")
        .chain_update(label)
        .chain_update(request_id)
        .finalize();
    digest[..16].try_into().unwrap_or([1; 16])
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 32,
        maximum_records_per_transaction: 4,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 4,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES * MAXIMUM_OPERATIONS * 4,
        maximum_materialized_records: MAXIMUM_OPERATIONS * 4,
    }
}
