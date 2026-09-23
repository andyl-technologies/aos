//! Replay-manifest publication for a new empty partition.
//!
//! The cache owner has already replayed its current state and proved that the
//! candidate partition has no records. This authority claim then checks the
//! checkpoint against a preexisting Replay record and publishes its manifest.

use sha2::{Digest as _, Sha256};

use crate::cache_residency::protected_owner::{
    CACHE_MANIFEST_KEY_PREFIX, MAXIMUM_CACHE_MANIFESTS, encode_cache_replay_manifest,
};
use crate::cache_residency::CachePinV1;
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::{
    CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheHistoryFloorV1,
    CacheRecoveryInventoryV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyReplayPartitionEvidenceV1, PhysicalPartitionId,
    ProtectedCacheResidencyReplayAuthorityV1,
};

const LOGICAL_PIN_DRAIN_KEY_PREFIX: &[u8] = b"aos.cache.logical-pin-drain.v1/";
const LOGICAL_PIN_DRAIN_LIFETIME_SECONDS: u64 = 120;

impl ProtectedCacheResidencyReplayAuthorityV1 {
    /// Issues one short-lived, partition-scoped drain record for a checked logical pin.
    ///
    /// The caller must first match the pin against both the rechecked public
    /// consumer and the retained protected Cache projection. A single key per
    /// partition bounds the materialized authority journal and fences earlier
    /// drain issuances whenever another pin is selected.
    ///
    /// # Errors
    ///
    /// Rejects an invalid pin, stale protected time, conflicting authority,
    /// or an unconfirmed authority-journal append.
    pub(crate) fn issue_logical_pin_drain_record(
        &self,
        pin: &CachePinV1,
    ) -> Result<Vec<u8>, CacheResidencyProtectedJournalErrorV1> {
        let now = self.current_time.current_unix_seconds()?;
        let valid_until = now
            .checked_add(LOGICAL_PIN_DRAIN_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let scope = pin
            .logical_drain_scope(valid_until)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let mut record_key = Vec::with_capacity(LOGICAL_PIN_DRAIN_KEY_PREFIX.len() + 32);
        record_key.extend_from_slice(LOGICAL_PIN_DRAIN_KEY_PREFIX);
        record_key.extend_from_slice(pin.partition.digest().as_bytes());

        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let owner =
            CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let record = owner.canonical_record(CacheAuthorityPurposeV1::PinDrain, scope);
        let previous = authority.get(&record_key)?.map(ToOwned::to_owned);
        if previous.as_deref() == Some(record.as_slice()) {
            return Ok(record_key);
        }
        if previous.is_some()
            && owner
                .verify_current_record_for_purpose(CacheAuthorityPurposeV1::PinDrain, &record_key)
                .is_err()
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }

        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.logical-pin-drain-authority.v1\0")
            .chain_update(&record_key)
            .chain_update(previous.as_deref().unwrap_or_default())
            .chain_update(record)
            .finalize();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                record_key.clone(),
                record.to_vec(),
            )],
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        authority.commit(&transaction)?;
        if authority.get(&record_key)? != Some(record.as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::DivergentRecovery.into());
        }
        Ok(record_key)
    }

    /// Installs a Replay record supplied by the locked controller source.
    ///
    /// # Errors
    ///
    /// Rejects stale time, a conflicting record, or an unconfirmed append.
    pub(crate) fn install_controller_replay_record(
        &self,
        evidence: &CacheResidencyReplayPartitionEvidenceV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let now = self.current_time.current_unix_seconds()?;
        if now >= evidence.scope.valid_until() {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let owner =
            CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let record = owner.canonical_record(CacheAuthorityPurposeV1::Replay, evidence.scope);
        if let Some(existing) = authority.get(&evidence.record_key)? {
            if existing != record {
                return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed.into());
            }
            return Ok(());
        }
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.controller-replay-authority.v1\0")
            .chain_update(&evidence.record_key)
            .chain_update(record)
            .finalize();
        let transaction_id = digest[..16]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                evidence.record_key.clone(),
                record.to_vec(),
            )],
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        authority.commit(&transaction)?;
        if authority.get(&evidence.record_key)? != Some(record.as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::DivergentRecovery.into());
        }
        Ok(())
    }

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
