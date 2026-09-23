//! Replay-manifest publication for a new empty partition.
//!
//! The cache owner has already replayed its current state and proved that the
//! candidate partition has no records. This authority claim then checks the
//! checkpoint against a preexisting Replay record and publishes its manifest.

use sha2::{Digest as _, Sha256};

use crate::cache_residency::protected_owner::{
    CACHE_MANIFEST_KEY_PREFIX, MAXIMUM_CACHE_MANIFESTS, encode_cache_replay_manifest,
};
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::{
    CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheHistoryFloorV1, CacheRecoveryInventoryV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayPartitionEvidenceV1,
    PhysicalPartitionId, ProtectedCacheResidencyReplayAuthorityV1,
};

impl ProtectedCacheResidencyReplayAuthorityV1 {
    /// Publishes one authenticated empty-partition manifest into this owner.
    ///
    /// # Errors
    ///
    /// Rejects absent or stale Replay authority, a duplicate partition, an
    /// invalid checkpoint, or an unconfirmed protected append.
    pub(crate) fn install_replay_partition(
        &self,
        partition: PhysicalPartitionId,
        record_key: Vec<u8>,
        typed_checkpoint: Vec<u8>,
        floor: CacheHistoryFloorV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let now = self.current_time.current_unix_seconds()?;
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let owner =
            CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let capability = owner
            .verify_current_record_for_purpose(CacheAuthorityPurposeV1::Replay, &record_key)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &typed_checkpoint,
            None,
            floor,
            std::iter::empty(),
            self.limits,
            now,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let scope = capability.scope();
        let evidence = CacheResidencyReplayPartitionEvidenceV1 {
            partition,
            purpose: CacheAuthorityPurposeV1::Replay,
            scope,
            record_key,
            typed_checkpoint,
            prior_typed_checkpoint: None,
            floor,
        };
        let manifest = encode_cache_replay_manifest(&evidence, self.limits)?;
        let mut manifest_key = Vec::with_capacity(CACHE_MANIFEST_KEY_PREFIX.len() + 32);
        manifest_key.extend_from_slice(CACHE_MANIFEST_KEY_PREFIX);
        manifest_key.extend_from_slice(partition.digest().as_bytes());

        let mut partitions = self
            .partitions
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if partitions.len() >= MAXIMUM_CACHE_MANIFESTS
            || partitions.contains_key(&partition.digest())
            || authority.get(&manifest_key)?.is_some()
        {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed.into());
        }
        owner
            .validate_for_effect_at(
                &capability,
                CacheAuthorityPurposeV1::Replay,
                scope,
                self.current_time.current_unix_seconds()?,
            )
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;

        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.additional-replay-manifest.v1\0")
            .chain_update(&manifest)
            .finalize();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                manifest_key.clone(),
                manifest.clone(),
            )],
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        authority.commit(&transaction)?;
        if authority.get(&manifest_key)? != Some(manifest.as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::DivergentRecovery.into());
        }
        partitions.insert(partition.digest(), evidence);
        Ok(())
    }
}
