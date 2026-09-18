//! Protected current observation of the external durable publication catalog.
//!
//! Publisher state and catalog visibility are separate effects. This retained
//! sidecar journal records the exact catalog predecessor and successor after a
//! durable no-replace publication but before the publisher ledger settles. A
//! cold reopen can therefore distinguish a genuinely committed catalog entry
//! from a projection reconstructed from the still-prior publisher ledger.
//!
//! ```text
//! AOSPCO01 | v1 | predecessor-record | operation | prior-generation |
//! successor-generation | physical-effect | entry-length | entry | digest
//! ```

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::decision::CommittedCatalogObservation;
use super::read_authority::{
    CommittedReadEntryV1, decode_committed_read_entry_v1, encode_committed_read_entry_v1,
};
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const CURRENT_KEY: &[u8] = b"\0aos-publisher-durable-catalog-observation-v1\0current";
const MAGIC: &[u8; 8] = b"AOSPCO01";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"aos.sandbox.publisher.durable-catalog-observation.v1\0";
const PREFIX_BYTES: usize = 8 + 2 + 32 + 16 + 8 + 8 + 32 + 2;
const MAXIMUM_ENTRY_BYTES: usize = 512;
const FIXED_PUBLISHER_ROOT: &str = "/var/lib/aos/sandbox/publisher";
const CATALOG_OBSERVATION_JOURNAL: &str = "catalog-observation-v1.journal";
const MAXIMUM_RESOLUTION_ATTEMPTS: usize = 8;

/// Reports protected durable-catalog observation failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherDurableCatalogErrorV1 {
    /// The protected sidecar could not be replayed or committed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The observation is malformed, stale, conflicting, or noncanonical.
    #[error("publisher durable catalog observation is invalid or stale")]
    Invalid,
}

/// Retains one exact current durable-catalog observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedDurableCatalogObservationV1 {
    predecessor_record: ObjectDigest,
    operation: OperationId,
    observation: CommittedCatalogObservation,
    physical_effect_digest: ObjectDigest,
    record_digest: ObjectDigest,
}

/// Classifies one sidecar commit without releasing completion custody.
pub(super) enum PublisherDurableCatalogCommitOutcomeV1 {
    /// Exact transaction readback proves the intended head current.
    Applied(AuthenticatedDurableCatalogObservationV1),
    /// An append or synchronization error requires protected reopen.
    OutcomeUnknown(PublisherDurableCatalogOutcomeUnknownV1),
    /// A successful append did not yield the exact intended current readback.
    Conflict(PublisherDurableCatalogOutcomeUnknownV1),
}

/// Retains the exact transaction while its durable outcome is unknown.
#[must_use = "unknown catalog durability must be resolved under completion custody"]
pub(super) struct PublisherDurableCatalogOutcomeUnknownV1 {
    transaction: JournalTransaction,
    expected_previous: Option<AuthenticatedDurableCatalogObservationV1>,
    intended: AuthenticatedDurableCatalogObservationV1,
    attempts: usize,
}

/// Classifies fixed-root recovery of one unknown sidecar transaction.
pub(super) enum PublisherDurableCatalogRecoveryV1 {
    /// Exact protected readback proves the intended transaction current.
    Applied(AuthenticatedDurableCatalogObservationV1),
    /// Reopen remains unavailable or another append again became ambiguous.
    OutcomeUnknown(PublisherDurableCatalogOutcomeUnknownV1),
    /// Protected replay proves a different current head or transaction reuse.
    Conflict(PublisherDurableCatalogOutcomeUnknownV1),
}

impl AuthenticatedDurableCatalogObservationV1 {
    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn prior_generation(&self) -> u64 {
        self.observation.prior_generation()
    }

    pub(super) const fn generation(&self) -> u64 {
        self.observation.generation()
    }

    pub(super) const fn entry(&self) -> &CommittedReadEntryV1 {
        self.observation.entry()
    }

    pub(super) const fn physical_effect_digest(&self) -> ObjectDigest {
        self.physical_effect_digest
    }

    pub(super) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    pub(super) fn committed_observation(&self) -> CommittedCatalogObservation {
        self.observation.clone()
    }
}

/// Solely owns the protected catalog-observation sidecar journal.
pub(super) struct PublisherDurableCatalogOwnerV1 {
    journal: Option<Journal>,
    current: Option<AuthenticatedDurableCatalogObservationV1>,
}

impl PublisherDurableCatalogOwnerV1 {
    pub(super) fn open_fixed_protected()
    -> Result<(Self, crate::journal::RecoveryReport), PublisherDurableCatalogErrorV1> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(FIXED_PUBLISHER_ROOT),
            CATALOG_OBSERVATION_JOURNAL,
            catalog_observation_journal_limits(),
        )?;
        let current = read_current(&journal)?;
        Ok((
            Self {
                journal: Some(journal),
                current,
            },
            report,
        ))
    }

    pub(super) fn current(&self) -> Option<&AuthenticatedDurableCatalogObservationV1> {
        self.current.as_ref()
    }

    pub(super) fn current_for_recovery(
        &self,
        operation: OperationId,
        ledger_generation: u64,
        intended: &CommittedReadEntryV1,
    ) -> Result<Option<AuthenticatedDurableCatalogObservationV1>, PublisherDurableCatalogErrorV1>
    {
        let current = read_current(self.journal()?)?;
        if current != self.current {
            return Err(PublisherDurableCatalogErrorV1::Invalid);
        }
        Ok(current.filter(|observation| {
            observation.operation == operation
                && observation.prior_generation() == ledger_generation
                && ledger_generation.checked_add(1) == Some(observation.generation())
                && observation.entry() == intended
        }))
    }

    pub(super) fn commit_after_durable_publication(
        &mut self,
        operation: OperationId,
        prior_generation: u64,
        next_generation: u64,
        entry: CommittedReadEntryV1,
        physical_effect_digest: ObjectDigest,
    ) -> Result<PublisherDurableCatalogCommitOutcomeV1, PublisherDurableCatalogErrorV1> {
        let reread = read_current(self.journal()?)?;
        if reread != self.current
            || prior_generation.checked_add(1) != Some(next_generation)
            || physical_effect_digest.as_bytes() == &[0; 32]
        {
            return Err(PublisherDurableCatalogErrorV1::Invalid);
        }
        if let Some(current) = &self.current {
            if current.operation == operation
                && current.prior_generation() == prior_generation
                && current.generation() == next_generation
                && current.entry() == &entry
                && current.physical_effect_digest == physical_effect_digest
            {
                return Ok(PublisherDurableCatalogCommitOutcomeV1::Applied(
                    current.clone(),
                ));
            }
            if current.generation() > prior_generation {
                return Err(PublisherDurableCatalogErrorV1::Invalid);
            }
        }
        let predecessor = self
            .current
            .as_ref()
            .map_or(ObjectDigest::from_bytes([0; 32]), |current| {
                current.record_digest
            });
        let observation = AuthenticatedDurableCatalogObservationV1 {
            predecessor_record: predecessor,
            operation,
            observation: CommittedCatalogObservation::from_durable_adapter(
                prior_generation,
                next_generation,
                entry,
            ),
            physical_effect_digest,
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        let bytes = encode_observation(observation)?;
        let decoded = decode_observation(&bytes)?;
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&decoded.record_digest.as_bytes()[..16]);
        if transaction_id == [0; 16] {
            return Err(PublisherDurableCatalogErrorV1::Invalid);
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                CURRENT_KEY.to_vec(),
                bytes,
            )],
        )?;
        let pending = PublisherDurableCatalogOutcomeUnknownV1 {
            transaction,
            expected_previous: self.current.clone(),
            intended: decoded.clone(),
            attempts: 0,
        };
        match self.journal_mut()?.commit(&pending.transaction) {
            Ok(_) => match self.journal().and_then(read_current) {
                Ok(Some(readback)) if readback == decoded => {
                    self.current = Some(readback.clone());
                    Ok(PublisherDurableCatalogCommitOutcomeV1::Applied(readback))
                }
                _ => Ok(PublisherDurableCatalogCommitOutcomeV1::Conflict(pending)),
            },
            Err(_) => Ok(PublisherDurableCatalogCommitOutcomeV1::OutcomeUnknown(
                pending,
            )),
        }
    }

    pub(super) fn recover_outcome_unknown(
        &mut self,
        mut pending: PublisherDurableCatalogOutcomeUnknownV1,
    ) -> PublisherDurableCatalogRecoveryV1 {
        while pending.attempts < MAXIMUM_RESOLUTION_ATTEMPTS {
            pending.attempts += 1;
            if self.reopen_fixed().is_err() {
                continue;
            }
            let observed = match self.journal().and_then(read_current) {
                Ok(observed) => observed,
                Err(_) => continue,
            };
            if observed.as_ref() == Some(&pending.intended) {
                self.current = observed;
                return PublisherDurableCatalogRecoveryV1::Applied(pending.intended);
            }
            if observed != pending.expected_previous {
                return PublisherDurableCatalogRecoveryV1::Conflict(pending);
            }
            match self.journal_mut() {
                Ok(journal) => match journal.commit(&pending.transaction) {
                    Ok(_) => match read_current(journal) {
                        Ok(Some(readback)) if readback == pending.intended => {
                            self.current = Some(readback.clone());
                            return PublisherDurableCatalogRecoveryV1::Applied(readback);
                        }
                        _ => return PublisherDurableCatalogRecoveryV1::Conflict(pending),
                    },
                    Err(JournalError::DuplicateTransaction) => {
                        return PublisherDurableCatalogRecoveryV1::Conflict(pending);
                    }
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        }
        PublisherDurableCatalogRecoveryV1::OutcomeUnknown(pending)
    }

    fn reopen_fixed(&mut self) -> Result<(), PublisherDurableCatalogErrorV1> {
        drop(self.journal.take());
        let (journal, _) = Journal::open_protected_at(
            Path::new(FIXED_PUBLISHER_ROOT),
            CATALOG_OBSERVATION_JOURNAL,
            catalog_observation_journal_limits(),
        )?;
        self.journal = Some(journal);
        Ok(())
    }

    fn journal(&self) -> Result<&Journal, PublisherDurableCatalogErrorV1> {
        self.journal
            .as_ref()
            .ok_or(PublisherDurableCatalogErrorV1::Invalid)
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, PublisherDurableCatalogErrorV1> {
        self.journal
            .as_mut()
            .ok_or(PublisherDurableCatalogErrorV1::Invalid)
    }
}

fn read_current(
    journal: &Journal,
) -> Result<Option<AuthenticatedDurableCatalogObservationV1>, PublisherDurableCatalogErrorV1> {
    let mut current = None;
    for (namespace, key, bytes) in journal.all_records() {
        if namespace != RecordNamespace::PublisherAuthority
            || key != CURRENT_KEY
            || current.replace(decode_observation(bytes)?).is_some()
        {
            return Err(PublisherDurableCatalogErrorV1::Invalid);
        }
    }
    Ok(current)
}

fn encode_observation(
    observation: AuthenticatedDurableCatalogObservationV1,
) -> Result<Vec<u8>, PublisherDurableCatalogErrorV1> {
    let entry = encode_committed_read_entry_v1(observation.entry());
    if entry.len() > MAXIMUM_ENTRY_BYTES {
        return Err(PublisherDurableCatalogErrorV1::Invalid);
    }
    let mut bytes = Vec::with_capacity(PREFIX_BYTES + entry.len() + 32);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(observation.predecessor_record.as_bytes());
    bytes.extend_from_slice(observation.operation.as_bytes());
    bytes.extend_from_slice(&observation.prior_generation().to_be_bytes());
    bytes.extend_from_slice(&observation.generation().to_be_bytes());
    bytes.extend_from_slice(observation.physical_effect_digest.as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(entry.len())
            .map_err(|_| PublisherDurableCatalogErrorV1::Invalid)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&entry);
    let digest = digest(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    Ok(bytes)
}

fn decode_observation(
    bytes: &[u8],
) -> Result<AuthenticatedDurableCatalogObservationV1, PublisherDurableCatalogErrorV1> {
    if bytes.len() < PREFIX_BYTES + 32
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(PublisherDurableCatalogErrorV1::Invalid);
    }
    let predecessor_record = ObjectDigest::from_bytes(exact(&bytes[10..42])?);
    let operation = OperationId::from_bytes(exact(&bytes[42..58])?);
    let prior_generation = u64::from_be_bytes(exact(&bytes[58..66])?);
    let generation = u64::from_be_bytes(exact(&bytes[66..74])?);
    let physical_effect_digest = ObjectDigest::from_bytes(exact(&bytes[74..106])?);
    let entry_len = usize::from(u16::from_be_bytes(exact(&bytes[106..108])?));
    let end = PREFIX_BYTES
        .checked_add(entry_len)
        .ok_or(PublisherDurableCatalogErrorV1::Invalid)?;
    if operation.as_bytes() == &[0; 16]
        || prior_generation.checked_add(1) != Some(generation)
        || physical_effect_digest.as_bytes() == &[0; 32]
        || entry_len > MAXIMUM_ENTRY_BYTES
        || bytes.len() != end + 32
    {
        return Err(PublisherDurableCatalogErrorV1::Invalid);
    }
    let entry = decode_committed_read_entry_v1(&bytes[PREFIX_BYTES..end])
        .map_err(|_| PublisherDurableCatalogErrorV1::Invalid)?;
    if encode_committed_read_entry_v1(&entry) != bytes[PREFIX_BYTES..end] {
        return Err(PublisherDurableCatalogErrorV1::Invalid);
    }
    let record_digest = ObjectDigest::from_bytes(exact(&bytes[end..])?);
    if record_digest != digest(&bytes[..end]) {
        return Err(PublisherDurableCatalogErrorV1::Invalid);
    }
    Ok(AuthenticatedDurableCatalogObservationV1 {
        predecessor_record,
        operation,
        observation: CommittedCatalogObservation::from_durable_adapter(
            prior_generation,
            generation,
            entry,
        ),
        physical_effect_digest,
        record_digest,
    })
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublisherDurableCatalogErrorV1> {
    bytes
        .try_into()
        .map_err(|_| PublisherDurableCatalogErrorV1::Invalid)
}

const fn catalog_observation_journal_limits() -> crate::journal::JournalLimits {
    crate::journal::JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 16 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 8192,
        maximum_materialized_records: 2,
    }
}
