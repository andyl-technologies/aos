//! Private protected-store authority boundary.
//!
//! This module is the sole home of the durable-store adapter and its session
//! constructor. Journal code receives only a consumed opaque commit grant;
//! ordinary siblings cannot implement the backend or manufacture durability
//! acknowledgements from scalar digests.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::evidence::AuthenticatedEvidenceContextV1;
use super::journal::{
    InvalidMultiNodeJournal, MultiNodeJournalCheckpointV1, MultiNodeJournalRecordV1,
    MultiNodeJournalReducerV1, ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedStoreObjectKindV1 {
    Record,
    Checkpoint,
}

mod sealed {
    pub trait Sealed {}
}

/// Describes one exact protected write without exposing an authority handle.
struct ProtectedWriteRequestV1<'a> {
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes: &'a [u8],
    canonical_bytes_digest: ObjectDigest,
}

/// Carries the protected backend's authenticated, nondeterministic receipt.
///
/// Construction is private to this authority module and its future child
/// integration. It is singular and cannot be cloned or copied.
struct ProtectedWriteResultV1 {
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    replay_fence: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
}

/// Defines the sole protected-store backend accepted by the authority.
trait ProtectedStoreBackendV1: sealed::Sealed {
    fn persist_once(
        &mut self,
        request: ProtectedWriteRequestV1<'_>,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedWriteResultV1, InvalidMultiNodeJournal>;
}

/// Owns exclusive access to one authenticated protected-store backend.
///
/// Its constructor is private and intended only for a future child integration
/// that performs actual storage authentication and replay-fence persistence.
struct ProtectedStoreAuthoritySessionV1<'a> {
    backend: &'a mut dyn ProtectedStoreBackendV1,
    storage_domain_digest: ObjectDigest,
    minimum_durability_generation: u64,
    replay_fence: ObjectDigest,
}

impl sealed::Sealed for ProtectedStoreAuthoritySessionV1<'_> {}

impl<'a> ProtectedStoreAuthoritySessionV1<'a> {
    fn from_verified_backend(
        backend: &'a mut dyn ProtectedStoreBackendV1,
        storage_domain_digest: ObjectDigest,
        minimum_durability_generation: u64,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if storage_domain_digest.as_bytes() == &[0; 32]
            || minimum_durability_generation == 0
            || replay_fence.as_bytes() == &[0; 32]
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(Self {
            backend,
            storage_domain_digest,
            minimum_durability_generation,
            replay_fence,
        })
    }

    /// Persists and issues one exact protected journal record.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when persistence, authentication,
    /// currentness, monotonic durability, byte binding, or replay fencing fails.
    fn commit_record_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedJournalRecordV1, InvalidMultiNodeJournal> {
        let canonical_bytes = record.encode_canonical();
        let grant = self.persist_once(
            ProtectedStoreObjectKindV1::Record,
            Some(record.operation()),
            &canonical_bytes,
            verified_at_unix_seconds,
        )?;
        ProtectedJournalRecordV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        )
    }

    /// Persists and issues one exact protected journal checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when persistence, authentication,
    /// currentness, monotonic durability, byte binding, or replay fencing fails.
    fn commit_checkpoint_once(
        &mut self,
        checkpoint: MultiNodeJournalCheckpointV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedJournalCheckpointV1, InvalidMultiNodeJournal> {
        let canonical_bytes = checkpoint.encode_canonical();
        let grant = self.persist_once(
            ProtectedStoreObjectKindV1::Checkpoint,
            None,
            &canonical_bytes,
            verified_at_unix_seconds,
        )?;
        ProtectedJournalCheckpointV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        )
    }

    /// Restores exact reducer and partial-effect state through this store session.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when the checkpoint or any successor
    /// belongs to another protected domain/replay fence, is stale, or breaks
    /// the canonical journal chain.
    fn restore_once(
        &mut self,
        checkpoint: ProtectedJournalCheckpointV1,
        records: Vec<ProtectedJournalRecordV1>,
        verified_at_unix_seconds: u64,
    ) -> Result<MultiNodeJournalReducerV1, InvalidMultiNodeJournal> {
        if checkpoint.storage_domain_digest() != self.storage_domain_digest
            || checkpoint.replay_fence() != self.replay_fence
            || checkpoint.durability_generation() < self.minimum_durability_generation
            || records.iter().any(|record| {
                record.storage_domain_digest() != self.storage_domain_digest
                    || record.replay_fence() != self.replay_fence
                    || record.durability_generation() < checkpoint.durability_generation()
            })
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let restored_generation = records
            .last()
            .map_or(checkpoint.durability_generation(), |record| {
                record.durability_generation()
            });
        let grant = ProtectedStoreRestoreGrantV1 {
            checkpoint,
            records,
            verified_at_unix_seconds,
            storage_domain_digest: self.storage_domain_digest,
            replay_fence: self.replay_fence,
        };
        let reducer = MultiNodeJournalReducerV1::restore_from_authority(grant)?;
        self.minimum_durability_generation = restored_generation
            .checked_add(1)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        Ok(reducer)
    }

    fn persist_once(
        &mut self,
        kind: ProtectedStoreObjectKindV1,
        operation: Option<OperationId>,
        canonical_bytes: &[u8],
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedStoreCommitGrantV1, InvalidMultiNodeJournal> {
        let canonical_bytes_digest =
            ObjectDigest::from_bytes(Sha256::digest(canonical_bytes).into());
        let result = self.backend.persist_once(
            ProtectedWriteRequestV1 {
                kind,
                operation,
                canonical_bytes,
                canonical_bytes_digest,
            },
            verified_at_unix_seconds,
        )?;
        if result.storage_domain_digest != self.storage_domain_digest
            || result.durability_generation < self.minimum_durability_generation
            || result.protected_root_digest.as_bytes() == &[0; 32]
            || result.opaque_receipt_commitment.as_bytes() == &[0; 32]
            || result.replay_fence != self.replay_fence
            || !result.context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        self.minimum_durability_generation = result
            .durability_generation
            .checked_add(1)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        Ok(ProtectedStoreCommitGrantV1 {
            kind,
            canonical_bytes_digest,
            storage_domain_digest: result.storage_domain_digest,
            durability_generation: result.durability_generation,
            protected_root_digest: result.protected_root_digest,
            opaque_receipt_commitment: result.opaque_receipt_commitment,
            replay_fence: result.replay_fence,
            context: result.context,
        })
    }
}

/// Carries one consumed protected restore decision into the journal reducer.
pub(super) struct ProtectedStoreRestoreGrantV1 {
    checkpoint: ProtectedJournalCheckpointV1,
    records: Vec<ProtectedJournalRecordV1>,
    verified_at_unix_seconds: u64,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
}

impl ProtectedStoreRestoreGrantV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        ProtectedJournalCheckpointV1,
        Vec<ProtectedJournalRecordV1>,
        u64,
        ObjectDigest,
        ObjectDigest,
    ) {
        (
            self.checkpoint,
            self.records,
            self.verified_at_unix_seconds,
            self.storage_domain_digest,
            self.replay_fence,
        )
    }
}

/// Carries one consumed protected-store commit decision into journal code.
pub(super) struct ProtectedStoreCommitGrantV1 {
    kind: ProtectedStoreObjectKindV1,
    canonical_bytes_digest: ObjectDigest,
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    replay_fence: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
}

impl ProtectedStoreCommitGrantV1 {
    pub(super) const fn kind(&self) -> ProtectedStoreObjectKindV1 {
        self.kind
    }
    pub(super) const fn canonical_bytes_digest(&self) -> ObjectDigest {
        self.canonical_bytes_digest
    }
    pub(super) const fn storage_domain_digest(&self) -> ObjectDigest {
        self.storage_domain_digest
    }
    pub(super) const fn durability_generation(&self) -> u64 {
        self.durability_generation
    }
    pub(super) const fn protected_root_digest(&self) -> ObjectDigest {
        self.protected_root_digest
    }
    pub(super) const fn opaque_receipt_commitment(&self) -> ObjectDigest {
        self.opaque_receipt_commitment
    }
    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }
    pub(super) const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}
