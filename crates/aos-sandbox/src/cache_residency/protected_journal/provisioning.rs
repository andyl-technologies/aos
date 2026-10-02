//! Replay-manifest publication for a new empty partition.
//!
//! The cache owner has already replayed its current state and proved that the
//! candidate partition has no records. This authority claim then checks the
//! checkpoint against a preexisting Replay record and publishes its manifest.

use sha2::{Digest as _, Sha256};

use crate::cache_residency::protected_owner::{
    CACHE_MANIFEST_KEY_PREFIX, MAXIMUM_CACHE_MANIFESTS, encode_cache_replay_manifest,
};
use crate::cache_residency::{CachePinId, CachePinV1, ValidatedPublicLogicalPinAcquisitionV1};
use crate::journal::{
    CacheMutationGateV1, CommitResult, JournalError, JournalRecord, JournalTransaction,
    ProtectedJournalAuthority, ProtectedJournalPreflight, RecordNamespace,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use aos_sandbox_core::ObjectDigest;

use super::{
    CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheHistoryFloorV1, CacheRecoveryInventoryV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayPartitionEvidenceV1,
    PhysicalPartitionId, ProtectedCacheResidencyReplayAuthorityV1,
};

const LOGICAL_PIN_ACQUIRE_KEY_PREFIX: &[u8] = b"aos.cache.logical-pin-acquire.v1/";
pub(crate) const LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS: u64 = 120;
const LOGICAL_PIN_DRAIN_KEY_PREFIX: &[u8] = b"aos.cache.logical-pin-drain.v1/";
pub(super) const LOGICAL_PIN_DRAIN_LIFETIME_SECONDS: u64 = 120;

/// Parks the exact authority append before any subsequent observation.
#[derive(Default)]
pub(in crate::cache_residency) struct ResidentPinAuthorityAppendV1 {
    pub(in crate::cache_residency) valid_until: Option<u64>,
    pub(in crate::cache_residency) record_key: Option<Vec<u8>>,
    pub(in crate::cache_residency) transaction: Option<JournalTransaction>,
    pub(in crate::cache_residency) preflight: Option<Result<ProtectedJournalPreflight, JournalError>>,
    pub(in crate::cache_residency) commit: Option<Result<CommitResult, JournalError>>,
    pub(in crate::cache_residency) preparation_failure: Option<CacheResidencyProtectedJournalErrorV1>,
    pub(in crate::cache_residency) postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
    pub(in crate::cache_residency) unchanged: bool,
}

impl ResidentPinAuthorityAppendV1 {
    pub(in crate::cache_residency) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.preparation_failure.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.preflight.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.commit.as_ref() {
            return Some(cause);
        }
        self.postcheck.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

fn canonical_record_transaction(
    record_key: &[u8],
    previous: Option<&[u8]>,
    record: &[u8],
    transaction_domain: &[u8],
) -> Result<JournalTransaction, CacheResidencyProtectedJournalErrorV1> {
    let digest = Sha256::new()
        .chain_update(transaction_domain)
        .chain_update(record_key)
        .chain_update(previous.unwrap_or_default())
        .chain_update(record)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16].try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    Ok(JournalTransaction::new(transaction_id, vec![JournalRecord::put(
        RecordNamespace::DesiredState,
        record_key.to_vec(),
        record.to_vec(),
    )])?)
}

/// Shares canonical single-record mechanics under an already borrowed claim.
///
/// Only existing proof-consuming issuers may call this. Its ordinary return
/// does not retain a failed transaction, so it is NOT a positive Read issuer or
/// a post-Root pending-custody contract.
///
/// # Errors
/// Returns canonical validation, gate, preflight, append or readback failure.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_canonical_record_under_claim_v1(
    authority: &mut ProtectedJournalAuthority<'_>,
    owner_scope: ObjectDigest,
    maximum_record_bytes: usize,
    purpose: CacheAuthorityPurposeV1,
    scope: super::CacheAuthorityScopeV1,
    record_key: Vec<u8>,
    transaction_domain: &[u8],
    mut gate: CacheMutationGateV1<'_>,
) -> Result<Vec<u8>, CacheResidencyProtectedJournalErrorV1> {
    if let CacheMutationGateV1::Retained(original) = &mut gate {
        authority.require_retained_cache_gate_v1(original)?;
    }
    let owner = CacheAuthorityOwner::new(authority, owner_scope, maximum_record_bytes)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let record = owner.canonical_record(purpose, scope);
    let previous = authority.get(&record_key)?.map(ToOwned::to_owned);
    if previous.as_deref() == Some(record.as_slice()) {
        if let CacheMutationGateV1::Retained(original) = &mut gate {
            authority.require_retained_cache_gate_v1(original)?;
        }
        return Ok(record_key);
    }
    if previous.is_some()
        && owner
            .verify_current_record_for_purpose(purpose, &record_key)
            .is_err()
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }

    let transaction = canonical_record_transaction(
        &record_key, previous.as_deref(), &record, transaction_domain,
    )?;
    let preflight = match &mut gate {
        CacheMutationGateV1::Ordinary => {
            authority.preflight_transactions(std::slice::from_ref(&transaction))?
        }
        CacheMutationGateV1::Retained(original) => authority
            .preflight_with_retained_cache_gate_v1(std::slice::from_ref(&transaction), original)?,
        resident @ CacheMutationGateV1::Resident(_, _) => authority
            .preflight_with_cache_gate(std::slice::from_ref(&transaction), resident.reborrow())?,
    };
    authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
    match &mut gate {
        CacheMutationGateV1::Ordinary => {
            authority.commit(&transaction)?;
        }
        CacheMutationGateV1::Retained(original) => {
            authority.commit_with_retained_cache_gate_v1(&preflight, &transaction, original)?;
        }
        resident @ CacheMutationGateV1::Resident(_, _) => {
            authority.commit_with_original_cache_gate_v1(
                &preflight, &transaction, resident.reborrow(),
            )?;
        }
    }
    if authority.get(&record_key)? != Some(record.as_slice()) {
        return Err(ProtectedDomainJournalErrorV1::DivergentRecovery);
    }
    Ok(record_key)
}

/// Drives the same canonical append with resident tokens and native causes.
///
/// Only the proof-consuming session's PinAcquire and PinDrain calls reach this
/// adapter. Its short refusal does not replace the parked first typed error.
#[allow(clippy::too_many_arguments)]
pub(super) fn append_resident_pin_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    owner_scope: ObjectDigest,
    maximum_record_bytes: usize,
    purpose: CacheAuthorityPurposeV1,
    scope: super::CacheAuthorityScopeV1,
    transaction_domain: &[u8],
    gate: &mut CacheMutationGateV1<'_>,
    progress: &mut ResidentPinAuthorityAppendV1,
    budget: &mut super::ResidentDomainPayloadBudgetV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    let prepared = (|| {
        authority.require_original_cache_gate_v1(gate)?;
        let record_key = progress.record_key.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let owner = CacheAuthorityOwner::new(authority, owner_scope, maximum_record_bytes)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let record = owner.canonical_record(purpose, scope);
        let previous = authority.get(record_key)?.map(ToOwned::to_owned);
        if previous.as_deref() == Some(record.as_slice()) {
            authority.require_original_cache_gate_v1(gate)?;
            progress.unchanged = true;
            return Ok(None);
        }
        if previous.is_some()
            && owner.verify_current_record_for_purpose(purpose, record_key).is_err()
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let bytes = record_key.len().checked_mul(2)
            .and_then(|keys| keys.checked_add(record.len()))
            .ok_or(JournalError::LimitExceeded("resident canonical payload bytes"))?;
        budget.reserve(bytes)?;
        canonical_record_transaction(record_key, previous.as_deref(), &record, transaction_domain)
            .map(Some)
    })();
    match prepared {
        Ok(transaction) => progress.transaction = transaction,
        Err(cause) => {
            progress.preparation_failure = Some(cause);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
    }
    if progress.unchanged {
        return Ok(());
    }

    let transaction = progress.transaction.as_ref()
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    progress.preflight = Some(authority.preflight_with_cache_gate(
        std::slice::from_ref(transaction), gate.reborrow(),
    ));
    let Some(Ok(preflight)) = progress.preflight.as_ref() else {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    };
    // The exact preflight is checked by the same commit adapter immediately
    // before its single append; the returned Result is parked before readback.
    progress.commit = Some(authority.commit_with_original_cache_gate_v1(
        preflight, transaction, gate.reborrow(),
    ));
    if !matches!(progress.commit.as_ref(), Some(Ok(_))) {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    let readback = (|| {
        let record_key = progress.record_key.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let owner = CacheAuthorityOwner::new(authority, owner_scope, maximum_record_bytes)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if authority.get(record_key)? != Some(owner.canonical_record(purpose, scope).as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::DivergentRecovery);
        }
        Ok(())
    })();
    if let Err(cause) = readback {
        progress.postcheck = Some(cause);
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    Ok(())
}

pub(super) fn logical_pin_record_key(prefix: &[u8], partition: PhysicalPartitionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(partition.digest().as_bytes());
    key
}

pub(super) fn acquire_record_key(partition: PhysicalPartitionId) -> Vec<u8> {
    logical_pin_record_key(LOGICAL_PIN_ACQUIRE_KEY_PREFIX, partition)
}

pub(super) fn drain_record_key(partition: PhysicalPartitionId) -> Vec<u8> {
    logical_pin_record_key(LOGICAL_PIN_DRAIN_KEY_PREFIX, partition)
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    // Read the protected clock floor before classifying same-tick renewals.
    pub(crate) fn current_unix_seconds(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        self.current_time.current_unix_seconds()
    }

    /// Issues short-lived acquisition authority only for a joined public source proof.
    ///
    /// A partition-local key fences an earlier acquisition whenever a new pin
    /// or renewal is selected. The protected Pin transaction must separately
    /// replay the catalog and retained pin ledger before it can commit.
    ///
    /// # Errors
    ///
    /// Rejects stale time, malformed pin scope, conflicting authority, or an
    /// unconfirmed authority-journal append.
    pub(crate) fn issue_logical_pin_acquire_record(
        &self,
        acquisition: &ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        pin: CachePinId,
    ) -> Result<(Vec<u8>, u64), CacheResidencyProtectedJournalErrorV1> {
        let now = self.current_time.current_unix_seconds()?;
        let valid_until = now
            .checked_add(LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let scope = acquisition
            .authority_scope(pin, valid_until)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let record_key = self.issue_logical_pin_record(
            CacheAuthorityPurposeV1::PinAcquire,
            scope,
            acquisition.partition(),
            LOGICAL_PIN_ACQUIRE_KEY_PREFIX,
            b"aos.sandbox.cache-residency.logical-pin-acquire-authority.v1\0",
        )?;
        Ok((record_key, valid_until))
    }

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
        self.issue_logical_pin_record(
            CacheAuthorityPurposeV1::PinDrain,
            scope,
            pin.partition,
            LOGICAL_PIN_DRAIN_KEY_PREFIX,
            b"aos.sandbox.cache-residency.logical-pin-drain-authority.v1\0",
        )
    }

    fn issue_logical_pin_record(
        &self,
        purpose: CacheAuthorityPurposeV1,
        scope: super::CacheAuthorityScopeV1,
        partition: PhysicalPartitionId,
        key_prefix: &[u8],
        transaction_domain: &[u8],
    ) -> Result<Vec<u8>, CacheResidencyProtectedJournalErrorV1> {
        let record_key = logical_pin_record_key(key_prefix, partition);
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        commit_canonical_record_under_claim_v1(
            &mut authority,
            self.owner_scope,
            self.maximum_record_bytes,
            purpose,
            scope,
            record_key,
            transaction_domain,
            CacheMutationGateV1::Ordinary,
        )
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
