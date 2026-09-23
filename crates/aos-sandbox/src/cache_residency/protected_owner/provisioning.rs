//! First-partition replay-manifest installation under preexisting authority.
//!
//! Bootstrap cannot infer replay authority from checkpoint bytes. The exact
//! protected Replay record must already exist, and the cache state journal
//! must have no committed history before the first manifest is published.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::cache_residency::format::CacheHistoryFloorV1;
use crate::cache_residency::recovery::CacheRecoveryInventoryV1;
use crate::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_MANIFEST_KEY_PREFIX, CACHE_STATE_JOURNAL, CacheAuthorityOwner,
    CacheAuthorityPurposeV1, CacheRecoveryLimitsV1, CacheResidencyCurrentTimeAuthorityV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1,
    CacheResidencyReplayPartitionEvidenceV1, MAXIMUM_AUTHORITY_RECORD_BYTES, PROTECTED_CACHE_ROOT,
    PhysicalPartitionId, ProtectedCacheClockV1, ProtectedDomainJournalErrorV1,
    cache_authority_journal_limits, cache_owner_scope, cache_state_journal_limits,
    decode_typed_checkpoint, encode_cache_replay_manifest,
};

impl CacheResidencyProtectedOwnerV1 {
    /// Installs the first replay manifest under an already-issued Replay record.
    ///
    /// The protected cache state journal must have no committed history. The
    /// supplied checkpoint must represent an empty object and operation state;
    /// its quota configuration is bound by the existing protected Replay record.
    /// This method does not issue that record or authorize a cache operation.
    ///
    /// # Errors
    ///
    /// Returns an error if protected state is nonempty, the Replay record is
    /// absent or stale, the checkpoint/floor does not match its exact scope, or
    /// a manifest append cannot be confirmed by readback.
    pub fn install_initial_replay_manifest(
        partition: PhysicalPartitionId,
        record_key: Vec<u8>,
        typed_checkpoint: Vec<u8>,
        floor: CacheHistoryFloorV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let limits = CacheRecoveryLimitsV1::default();
        let owner_scope = cache_owner_scope();
        let (clock, _) = ProtectedCacheClockV1::open(root, owner_scope)?;
        // Match the fixed owner's lock order: clock, authority, then state.
        let (mut authority_journal, _) = Journal::open_protected_at(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
        )?;
        let (mut state_journal, state_report) =
            Journal::open_protected_at(root, CACHE_STATE_JOURNAL, cache_state_journal_limits())?;
        let state_empty = state_journal
            .claim_protected_authority(RecordNamespace::DesiredState)?
            .is_materialized_empty()?;
        if state_report.committed_transactions != 0
            || state_report.truncated_bytes != 0
            || !state_empty
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }

        let checkpoint = decode_typed_checkpoint(partition, &typed_checkpoint, limits)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if checkpoint.checkpoint.sequence != 1
            || floor.first_retained_sequence != 2
            || floor.predecessor.as_bytes() != &[0; 32]
            || !checkpoint.baselines.is_empty()
            || !checkpoint.family_heads.is_empty()
            || !checkpoint.global.watermarks.is_empty()
            || !checkpoint.global.idempotency.is_empty()
            || checkpoint.global.pin_floor.is_some()
            || checkpoint.global.idempotency_floor.is_some()
            || !checkpoint.global.handoffs.is_empty()
            || !checkpoint.global.lookups.is_empty()
            || checkpoint.global.poison.is_some()
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }

        let mut manifest_key = Vec::with_capacity(CACHE_MANIFEST_KEY_PREFIX.len() + 32);
        manifest_key.extend_from_slice(CACHE_MANIFEST_KEY_PREFIX);
        manifest_key.extend_from_slice(partition.digest().as_bytes());

        let (scope, manifest) = {
            let authority =
                authority_journal.claim_protected_authority(RecordNamespace::DesiredState)?;
            let owner =
                CacheAuthorityOwner::new(&authority, owner_scope, MAXIMUM_AUTHORITY_RECORD_BYTES)
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let capability = owner
                .verify_current_record_for_purpose(CacheAuthorityPurposeV1::Replay, &record_key)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let now = clock.current_unix_seconds()?;
            CacheRecoveryInventoryV1::from_verified(
                &owner,
                &capability,
                partition,
                &typed_checkpoint,
                None,
                floor,
                std::iter::empty(),
                limits,
                now,
            )
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let scope = capability.scope();
            let evidence = CacheResidencyReplayPartitionEvidenceV1 {
                partition,
                purpose: CacheAuthorityPurposeV1::Replay,
                scope,
                record_key: record_key.clone(),
                typed_checkpoint,
                prior_typed_checkpoint: None,
                floor,
            };
            let manifest = encode_cache_replay_manifest(&evidence, limits)?;
            let existing = authority.get(&manifest_key)?.map(<[u8]>::to_vec);
            if let Some(existing) = existing {
                if existing != manifest {
                    return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed.into());
                }
                return Ok(());
            }
            owner
                .validate_for_effect_at(
                    &capability,
                    CacheAuthorityPurposeV1::Replay,
                    scope,
                    clock.current_unix_seconds()?,
                )
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            (scope, manifest)
        };

        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.initial-replay-manifest.v1\0")
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
        {
            let mut authority =
                authority_journal.claim_protected_authority(RecordNamespace::DesiredState)?;
            if authority.get(&manifest_key)?.is_some() {
                return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed.into());
            }
            let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
            authority
                .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
            let _attempt = authority.commit(&transaction);
        }
        drop(state_journal);
        drop(authority_journal);

        let (mut reopened, _) = Journal::open_protected_at(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
        )?;
        let authority = reopened.claim_protected_authority(RecordNamespace::DesiredState)?;
        let owner =
            CacheAuthorityOwner::new(&authority, owner_scope, MAXIMUM_AUTHORITY_RECORD_BYTES)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let capability = owner
            .verify_current_record(CacheAuthorityPurposeV1::Replay, scope, &record_key)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        owner
            .validate_for_effect_at(
                &capability,
                CacheAuthorityPurposeV1::Replay,
                scope,
                clock.current_unix_seconds()?,
            )
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if authority.get(&manifest_key)? == Some(manifest.as_slice()) {
            return Ok(());
        }
        Err(ProtectedDomainJournalErrorV1::DivergentRecovery.into())
    }
}
