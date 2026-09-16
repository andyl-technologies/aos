//! Retained protected executor registry for fixed publisher recovery fences.
//!
//! The executor provisions this fixed, root-owned registry independently of
//! publisher state. The adapter accepts no caller-selected journal, operation,
//! instance, death fact, or incarnation. It validates a canonical bounded
//! snapshot and singular current head, retains the journal lock, and installs
//! every current fence through private one-shot grants.
//!
//! ```text
//! snapshot: AOSPES01 | v1 | generation | predecessor | count | rows | digest
//! current:  AOSPEH01 | v1 | generation | snapshot-digest | digest
//! row:      operation | publisher-instance | death/revocation | incarnation
//! ```

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId, PublisherInstanceId};
use sha2::{Digest as _, Sha256};

use super::RecoveryExecutorFenceV1;
use super::fixed_owner::{
    PublisherFixedInstallerV1, PublisherFixedProtectedOwnerErrorV1, PublisherFixedProtectedOwnerV1,
};
use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

const EXECUTOR_REGISTRY_ROOT: &str = "/var/lib/aos/sandbox/executor-registry";
const EXECUTOR_REGISTRY_JOURNAL: &str = "publisher-recovery-fences-v1.journal";
const CURRENT_KEY: &[u8] = b"\0aos-publisher-executor-registry-v1\0current";
const SNAPSHOT_KEY_PREFIX: &[u8] = b"\0aos-publisher-executor-registry-v1\0snapshot\0";
const SNAPSHOT_MAGIC: &[u8; 8] = b"AOSPES01";
const CURRENT_MAGIC: &[u8; 8] = b"AOSPEH01";
const VERSION: u16 = 1;
const MAXIMUM_FENCES: usize = 4096;
const ROW_BYTES: usize = 96;
const SNAPSHOT_DOMAIN: &[u8] = b"aos.sandbox.publisher.executor-registry.snapshot.v1\0";
const CURRENT_DOMAIN: &[u8] = b"aos.sandbox.publisher.executor-registry.current.v1\0";

/// Reports protected executor-registry failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherFixedExecutorRegistryErrorV1 {
    /// The fixed protected registry could not be opened or replayed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The snapshot, current head, or fence facts are invalid.
    #[error("fixed publisher executor registry is invalid or stale")]
    Registry,
    /// Fence installation into the fixed publisher failed.
    #[error(transparent)]
    Publisher(#[from] PublisherFixedProtectedOwnerErrorV1),
}

/// Reports protected executor-registry replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherFixedExecutorRegistryOpenReportV1 {
    /// Reports recovery of the fixed registry journal.
    pub recovery: RecoveryReport,
    /// Counts current canonical fence rows.
    pub current_fences: usize,
}

/// Reports installation of one complete current executor snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherFixedFenceSyncReportV1 {
    /// Counts exact fences installed or confirmed idempotently.
    pub installed_or_confirmed: usize,
}

/// Retains the protected executor registry and its exact current snapshot.
pub struct PublisherFixedExecutorRegistryOwnerV1 {
    journal: Journal,
    generation: u64,
    snapshot_digest: ObjectDigest,
    current_digest: ObjectDigest,
}

/// Carries one current registry row directly into the private installer.
#[must_use = "the executor grant must be consumed by fixed publisher fence installation"]
pub(super) struct PublisherFixedExecutorGrantV1 {
    operation: OperationId,
    fence: RecoveryExecutorFenceV1,
    _source_snapshot_digest: ObjectDigest,
    _source_current_digest: ObjectDigest,
}

impl PublisherFixedExecutorGrantV1 {
    fn issue_from_retained_owner(
        row: ExecutorFenceRowV1,
        source_snapshot_digest: ObjectDigest,
        source_current_digest: ObjectDigest,
    ) -> Result<Self, PublisherFixedExecutorRegistryErrorV1> {
        if source_snapshot_digest.as_bytes() == &[0; 32]
            || source_current_digest.as_bytes() == &[0; 32]
        {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
        let fence = RecoveryExecutorFenceV1::from_protected_executor_registry(
            row.publisher_instance,
            row.death_or_revocation_digest,
            row.recovery_incarnation,
        )
        .map_err(|_| PublisherFixedExecutorRegistryErrorV1::Registry)?;
        Ok(Self {
            operation: row.operation,
            fence,
            _source_snapshot_digest: source_snapshot_digest,
            _source_current_digest: source_current_digest,
        })
    }

    pub(super) fn into_parts(self) -> (OperationId, RecoveryExecutorFenceV1) {
        (self.operation, self.fence)
    }
}

impl PublisherFixedExecutorRegistryOwnerV1 {
    /// Opens and retains the internally fixed protected executor registry.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedExecutorRegistryErrorV1`] unless one bounded,
    /// canonical snapshot is selected by exactly one canonical current head.
    pub fn open_fixed_protected() -> Result<
        (Self, PublisherFixedExecutorRegistryOpenReportV1),
        PublisherFixedExecutorRegistryErrorV1,
    > {
        let (journal, recovery) = Journal::open_protected_at(
            Path::new(EXECUTOR_REGISTRY_ROOT),
            EXECUTOR_REGISTRY_JOURNAL,
            executor_registry_journal_limits(),
        )?;
        let current = read_current(&journal)?;
        let current_fences = current.rows.len();
        Ok((
            Self {
                journal,
                generation: current.generation,
                snapshot_digest: current.snapshot_digest,
                current_digest: current.current_digest,
            },
            PublisherFixedExecutorRegistryOpenReportV1 {
                recovery,
                current_fences,
            },
        ))
    }

    /// Installs every current executor fence into one fixed publisher owner.
    ///
    /// The source current head is reread immediately before grants are minted.
    /// Installation is idempotent per exact operation and fails closed on the
    /// first conflict; retrying the same retained snapshot is safe.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedExecutorRegistryErrorV1`] if currentness changed
    /// or any fence conflicts with protected publisher state.
    pub fn synchronize_fixed_publisher(
        &mut self,
        publisher: &mut PublisherFixedProtectedOwnerV1,
    ) -> Result<PublisherFixedFenceSyncReportV1, PublisherFixedExecutorRegistryErrorV1> {
        let current = read_current(&self.journal)?;
        if current.generation != self.generation
            || current.snapshot_digest != self.snapshot_digest
            || current.current_digest != self.current_digest
        {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
        let count = current.rows.len();
        let mut installer = PublisherFixedInstallerV1::new();
        for row in current.rows {
            let grant = PublisherFixedExecutorGrantV1::issue_from_retained_owner(
                row,
                current.snapshot_digest,
                current.current_digest,
            )?;
            installer.install_executor_fence(publisher, grant)?;
        }
        Ok(PublisherFixedFenceSyncReportV1 {
            installed_or_confirmed: count,
        })
    }
}

struct AuthenticatedExecutorSnapshotV1 {
    generation: u64,
    snapshot_digest: ObjectDigest,
    current_digest: ObjectDigest,
    rows: Vec<ExecutorFenceRowV1>,
}

struct ExecutorFenceRowV1 {
    operation: OperationId,
    publisher_instance: PublisherInstanceId,
    death_or_revocation_digest: ObjectDigest,
    recovery_incarnation: ObjectDigest,
}

fn read_current(
    journal: &Journal,
) -> Result<AuthenticatedExecutorSnapshotV1, PublisherFixedExecutorRegistryErrorV1> {
    let mut current = None;
    let mut snapshot = None;
    for (namespace, key, bytes) in journal.all_records() {
        if namespace != RecordNamespace::PublisherAuthority {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
        if key == CURRENT_KEY {
            if current.replace(decode_current(bytes)?).is_some() {
                return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
            }
        } else if key.starts_with(SNAPSHOT_KEY_PREFIX)
            && key.len() == SNAPSHOT_KEY_PREFIX.len() + 32
        {
            if snapshot.replace((key, bytes)).is_some() {
                return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
            }
        } else {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
    }
    let (generation, snapshot_digest, current_digest) =
        current.ok_or(PublisherFixedExecutorRegistryErrorV1::Registry)?;
    let (key, bytes) = snapshot.ok_or(PublisherFixedExecutorRegistryErrorV1::Registry)?;
    if &key[SNAPSHOT_KEY_PREFIX.len()..] != snapshot_digest.as_bytes() {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    let (snapshot_generation, rows) = decode_snapshot(bytes, snapshot_digest)?;
    if snapshot_generation != generation {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    Ok(AuthenticatedExecutorSnapshotV1 {
        generation,
        snapshot_digest,
        current_digest,
        rows,
    })
}

fn decode_snapshot(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<(u64, Vec<ExecutorFenceRowV1>), PublisherFixedExecutorRegistryErrorV1> {
    const PREFIX: usize = 8 + 2 + 8 + 32 + 4;
    if bytes.len() < PREFIX + 32
        || &bytes[..8] != SNAPSHOT_MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    let generation = u64::from_be_bytes(exact(&bytes[10..18])?);
    let predecessor = ObjectDigest::from_bytes(exact(&bytes[18..50])?);
    let count = usize::try_from(u32::from_be_bytes(exact(&bytes[50..54])?))
        .map_err(|_| PublisherFixedExecutorRegistryErrorV1::Registry)?;
    let rows_bytes = count
        .checked_mul(ROW_BYTES)
        .ok_or(PublisherFixedExecutorRegistryErrorV1::Registry)?;
    let end = PREFIX
        .checked_add(rows_bytes)
        .ok_or(PublisherFixedExecutorRegistryErrorV1::Registry)?;
    if generation == 0
        || (generation == 1) != (predecessor.as_bytes() == &[0; 32])
        || count > MAXIMUM_FENCES
        || bytes.len() != end + 32
    {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    let retained = ObjectDigest::from_bytes(exact(&bytes[end..])?);
    if retained != expected_digest || retained != digest(SNAPSHOT_DOMAIN, &bytes[..end]) {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    let mut rows = Vec::with_capacity(count);
    let mut prior_operation = None;
    for row in bytes[PREFIX..end].chunks_exact(ROW_BYTES) {
        let operation = OperationId::from_bytes(exact(&row[..16])?);
        if operation.as_bytes() == &[0; 16]
            || prior_operation.is_some_and(|prior: OperationId| prior >= operation)
        {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
        let publisher_instance = PublisherInstanceId::from_bytes(exact(&row[16..32])?);
        let death_or_revocation_digest = ObjectDigest::from_bytes(exact(&row[32..64])?);
        let recovery_incarnation = ObjectDigest::from_bytes(exact(&row[64..96])?);
        if publisher_instance.as_bytes() == &[0; 16]
            || death_or_revocation_digest.as_bytes() == &[0; 32]
            || recovery_incarnation.as_bytes() == &[0; 32]
        {
            return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
        }
        prior_operation = Some(operation);
        rows.push(ExecutorFenceRowV1 {
            operation,
            publisher_instance,
            death_or_revocation_digest,
            recovery_incarnation,
        });
    }
    Ok((generation, rows))
}

fn decode_current(
    bytes: &[u8],
) -> Result<(u64, ObjectDigest, ObjectDigest), PublisherFixedExecutorRegistryErrorV1> {
    if bytes.len() != 82 || &bytes[..8] != CURRENT_MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    let generation = u64::from_be_bytes(exact(&bytes[10..18])?);
    let snapshot_digest = ObjectDigest::from_bytes(exact(&bytes[18..50])?);
    let retained = ObjectDigest::from_bytes(exact(&bytes[50..82])?);
    if generation == 0
        || snapshot_digest.as_bytes() == &[0; 32]
        || retained != digest(CURRENT_DOMAIN, &bytes[..50])
    {
        return Err(PublisherFixedExecutorRegistryErrorV1::Registry);
    }
    Ok((generation, snapshot_digest, retained))
}

fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublisherFixedExecutorRegistryErrorV1> {
    bytes
        .try_into()
        .map_err(|_| PublisherFixedExecutorRegistryErrorV1::Registry)
}

const fn executor_registry_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 512 * 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 1024 * 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 1024 * 1024,
        maximum_materialized_records: 2,
    }
}
