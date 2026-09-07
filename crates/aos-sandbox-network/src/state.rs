//! Authenticated non-executing network transaction state.
//!
//! Each operation record is sealed by the shared node journal key and embeds
//! the exact sealed fence and effect with which it was atomically published:
//!
//! ```text
//! AOSNTX01 || phase || request-id || sandbox-id || request-digest ||
//! semantic-digest || NetworkPrepare || exact preparation resolution ||
//! sealed-fence || sealed-pending-effect
//! ```
//!
//! V1 accepts only Prepared NetworkPrepare intents: no helper may have run and
//! recovery may only observe. There is no effect or completion transition.

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker::{BrokerEffectStatusV2, BrokerLocalRecordDomain};
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::catalog::{NetworkCatalogBindingV1, ResolvedEndpointV1, ResolvedNetworkPreparationV1};

const MAGIC: &[u8; 8] = b"AOSNTX01";
const VERSION: u16 = 1;
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
    catalog_resolution: ResolvedNetworkPreparationV1,
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

    /// Returns the lossless protected resolution required for re-observation.
    #[must_use]
    pub const fn catalog_resolution(&self) -> &ResolvedNetworkPreparationV1 {
        &self.catalog_resolution
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
    fence: Vec<u8>,
    effect: Vec<u8>,
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
                .any(|record| record.sandbox_id == sandbox_id && record.fence == value)
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
            {
                return Err(NetworkStateError::Equivocation);
            }
            return Ok(NetworkBeginOutcome::AlreadyPrepared);
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
        if self
            .records
            .values()
            .any(|existing| existing.sandbox_id == record.sandbox_id)
        {
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
                    record.fence.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    record.request_id.to_vec(),
                    record.effect.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    record.request_id.to_vec(),
                    sealed_local,
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(record.request_id, record);
        Ok(NetworkBeginOutcome::Prepared)
    }
}

/// Classifies an idempotent durable admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkBeginOutcome {
    Prepared,
    AlreadyPrepared,
}

pub(crate) struct PreparedNetworkRecordInput {
    pub request_id: [u8; 16],
    pub sandbox_id: [u8; 16],
    pub transport_digest: ObjectDigest,
    pub semantic_digest: ObjectDigest,
    pub verb: BrokerVerb,
    pub catalog: ResolvedNetworkPreparationV1,
    pub fence: Vec<u8>,
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
        catalog: input.catalog,
        fence: input.fence,
        effect: input.effect,
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
        catalog_resolution: record.catalog.clone(),
    }
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
    let persisted_fence = journal
        .get(RecordNamespace::DesiredState, &record.sandbox_id)
        .ok_or(NetworkStateError::AuthorityLink)?;
    if persisted_fence != record.fence {
        return Err(NetworkStateError::AuthorityLink);
    }
    let effect = authority
        .validate_links(
            &record.sandbox_id,
            &record.request_id,
            &record.fence,
            &record.effect,
        )
        .map_err(|_| NetworkStateError::AuthorityLink)?;
    let expected_target = BrokerGrantTarget::Assignment;
    if effect.request_id() != &record.request_id
        || effect.transport_request_digest() != record.transport_digest
        || effect.request_digest() != record.semantic_digest
        || effect.verb() != record.verb
        || effect.target() != expected_target
        || effect.plan_digest()
            != authority
                .open_fence(&record.sandbox_id, &record.fence)
                .map_err(|_| NetworkStateError::AuthorityLink)?
                .plan_digest()
        || effect.status() != BrokerEffectStatusV2::Pending
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
        if pending
            .insert(record.sandbox_id, record.request_id)
            .is_some()
        {
            return Err(NetworkStateError::PendingConflict);
        }
    }
    Ok(())
}

fn encode_record(record: &DurableRecord) -> Result<Vec<u8>, NetworkStateError> {
    if record.request_id == [0; 16]
        || record.sandbox_id == [0; 16]
        || record.transport_digest.as_bytes() == &[0; 32]
        || record.semantic_digest.as_bytes() == &[0; 32]
        || record.fence.is_empty()
        || record.effect.is_empty()
    {
        return Err(NetworkStateError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(512 + record.fence.len() + record.effect.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(match record.phase {
        DurableNetworkPhase::Prepared => 1,
    });
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(record.transport_digest.as_bytes());
    bytes.extend_from_slice(record.semantic_digest.as_bytes());
    bytes.push(verb_code(record.verb)?);
    encode_catalog(&mut bytes, &record.catalog)?;
    push_blob(&mut bytes, &record.fence)?;
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
    if decoder.take::<8>()? != *MAGIC || u16::from_be_bytes(decoder.take()?) != VERSION {
        return Err(NetworkStateError::CorruptRecord);
    }
    let phase = match decoder.byte()? {
        1 => DurableNetworkPhase::Prepared,
        _ => return Err(NetworkStateError::CorruptRecord),
    };
    let request_id = decoder.take()?;
    let sandbox_id = decoder.take()?;
    let transport_digest = ObjectDigest::from_bytes(decoder.take()?);
    let semantic_digest = ObjectDigest::from_bytes(decoder.take()?);
    let verb = decode_verb(decoder.byte()?)?;
    let catalog = decode_catalog(&mut decoder)?;
    let fence = decoder.blob()?.to_vec();
    let effect = decoder.blob()?.to_vec();
    if !decoder.finished() || request_id == [0; 16] || sandbox_id == [0; 16] {
        return Err(NetworkStateError::CorruptRecord);
    }
    Ok(DurableRecord {
        phase,
        request_id,
        sandbox_id,
        transport_digest,
        semantic_digest,
        verb,
        catalog,
        fence,
        effect,
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
        maximum_records_per_transaction: 3,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 3,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES * MAXIMUM_OPERATIONS * 3,
        maximum_materialized_records: MAXIMUM_OPERATIONS * 3,
    }
}
