//! Controller-authorized Replay bootstrap and manifest installation.
//!
//! Bootstrap cannot infer replay authority from checkpoint bytes. A separate
//! root-owned controller journal supplies the exact configuration and scope;
//! the cache state journal must have no committed history before its first
//! manifest is published.

use std::{collections::BTreeSet, path::Path};

use sha2::{Digest as _, Sha256};

use crate::cache_residency::format::CacheHistoryFloorV1;
use crate::cache_residency::recovery::CacheRecoveryInventoryV1;
use crate::cache_residency::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
};
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};

use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_MANIFEST_KEY_PREFIX, CACHE_STATE_JOURNAL, CacheAuthorityOwner,
    CacheAuthorityPurposeV1, CacheRecoveryLimitsV1, CacheResidencyCurrentTimeAuthorityV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOpenReportV1,
    CacheResidencyProtectedOwnerV1, CacheResidencyProtectedRecordKindV1,
    CacheResidencyReplayPartitionEvidenceV1, MAXIMUM_AUTHORITY_RECORD_BYTES, PROTECTED_CACHE_ROOT,
    PhysicalPartitionId, ProtectedCacheClockV1, ProtectedDomainJournalErrorV1,
    cache_authority_journal_limits, cache_owner_scope, cache_state_journal_limits,
    decode_typed_checkpoint, encode_cache_replay_manifest, open_cache_journal,
};

impl CacheReplayControllerBootstrapOwnerV1 {
    /// Reconciles all controller-custodied partitions with an open cache owner.
    ///
    /// Existing manifests must match the retained source byte-for-byte. Missing
    /// partitions are installed; extra target partitions fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] if either authority is
    /// stale, a partition differs, or a missing partition cannot be installed.
    pub fn reconcile_fixed_cache(
        &mut self,
        target: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        if target.owner_uid != self.owner_uid() {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        target.replay()?;
        let existing = target.authority.current_replay_partition_evidence()?;
        let mut installed = BTreeSet::new();
        for target_evidence in existing {
            let partition = target_evidence.partition.digest();
            let source_evidence = self.current_partition(partition)?;
            let limits = CacheRecoveryLimitsV1::default();
            if encode_cache_replay_manifest(&target_evidence, limits)?
                != encode_cache_replay_manifest(&source_evidence, limits)?
            {
                return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
            }
            installed.insert(partition);
        }
        for partition in self.partitions().collect::<Vec<_>>() {
            if !installed.contains(&partition) {
                self.add_partition_to_fixed_cache(target, partition)?;
            }
        }
        Ok(())
    }

    /// Installs controller-custodied Replay authority and opens the first cache partition.
    ///
    /// The source journal remains locked throughout the target append. A replay
    /// record can survive an interrupted manifest append, but only this exact
    /// source can complete the installation on retry.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] if source currentness,
    /// target emptiness, protected time, authority, or manifest readback fails.
    pub fn bootstrap_fixed_cache(
        &mut self,
        partition: aos_sandbox_core::ObjectDigest,
    ) -> Result<
        (
            CacheResidencyProtectedOwnerV1,
            CacheResidencyProtectedOpenReportV1,
        ),
        CacheReplayControllerBootstrapErrorV1,
    > {
        let evidence = self.current_partition(partition)?;
        install_controller_replay_record(&evidence, self.owner_uid())?;
        CacheResidencyProtectedOwnerV1::install_initial_replay_manifest_for_uid(
            evidence.partition,
            evidence.record_key,
            evidence.typed_checkpoint,
            evidence.floor,
            self.owner_uid(),
        )?;
        CacheResidencyProtectedOwnerV1::open_fixed_protected_for_uid(self.owner_uid())
            .map_err(Into::into)
    }

    /// Adds one empty partition to an already-open protected cache owner.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] unless the source is
    /// unchanged, the partition is empty, and the record and manifest commit.
    pub fn add_partition_to_fixed_cache(
        &mut self,
        target: &mut CacheResidencyProtectedOwnerV1,
        partition: aos_sandbox_core::ObjectDigest,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        if target.owner_uid != self.owner_uid() {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let evidence = self.current_partition(partition)?;
        let projection = target.replay()?;
        if projection.records().iter().any(|record| {
            record.key().kind() != CacheResidencyProtectedRecordKindV1::EffectObservation
                && record.key().identity().get(..32) == Some(partition.as_bytes())
        }) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        target
            .authority
            .install_controller_replay_record(&evidence)?;
        target.install_additional_replay_manifest(
            evidence.partition,
            evidence.record_key,
            evidence.typed_checkpoint,
            evidence.floor,
        )?;
        Ok(())
    }
}

fn install_controller_replay_record(
    evidence: &CacheResidencyReplayPartitionEvidenceV1,
    owner_uid: u32,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    let root = Path::new(PROTECTED_CACHE_ROOT);
    let owner_scope = cache_owner_scope();
    let (clock, _) = ProtectedCacheClockV1::open(root, owner_scope, owner_uid)?;
    let (mut journal, authority_report) = open_cache_journal(
        root,
        CACHE_AUTHORITY_JOURNAL,
        cache_authority_journal_limits(),
        owner_uid,
    )?;
    let (state_journal, state_report) = open_cache_journal(
        root,
        CACHE_STATE_JOURNAL,
        cache_state_journal_limits(),
        owner_uid,
    )?;
    if state_report.committed_transactions != 0
        || state_report.committed_records != 0
        || state_report.truncated_bytes != 0
        || state_journal.all_records().next().is_some()
        || authority_report.truncated_bytes != 0
        || authority_report.committed_transactions > 1
        || authority_report.committed_records > 1
        || journal.all_records().any(|(namespace, key, _)| {
            namespace != RecordNamespace::DesiredState || key != evidence.record_key
        })
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
    }
    let record = {
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let owner =
            CacheAuthorityOwner::new(&authority, owner_scope, MAXIMUM_AUTHORITY_RECORD_BYTES)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let record = owner.canonical_record(CacheAuthorityPurposeV1::Replay, evidence.scope);
        let existing = authority.get(&evidence.record_key)?;
        let expected_records = usize::from(existing.is_some());
        if authority_report.committed_transactions != expected_records
            || authority_report.committed_records != expected_records
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        if let Some(existing) = existing {
            if existing != record {
                return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed.into());
            }
            return Ok(());
        }
        if clock.current_unix_seconds()? >= evidence.scope.valid_until() {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
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
        let _attempt = authority.commit(&transaction);
        record
    };
    drop(state_journal);
    drop(journal);

    let (mut reopened, _) = open_cache_journal(
        root,
        CACHE_AUTHORITY_JOURNAL,
        cache_authority_journal_limits(),
        owner_uid,
    )?;
    let authority = reopened.claim_protected_authority(RecordNamespace::DesiredState)?;
    let owner = CacheAuthorityOwner::new(&authority, owner_scope, MAXIMUM_AUTHORITY_RECORD_BYTES)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let capability = owner
        .verify_current_record(
            CacheAuthorityPurposeV1::Replay,
            evidence.scope,
            &evidence.record_key,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::DivergentRecovery)?;
    owner
        .validate_for_effect_at(
            &capability,
            CacheAuthorityPurposeV1::Replay,
            evidence.scope,
            clock.current_unix_seconds()?,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if authority.get(&evidence.record_key)? != Some(record.as_slice()) {
        return Err(ProtectedDomainJournalErrorV1::DivergentRecovery.into());
    }
    Ok(())
}

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
        Self::install_initial_replay_manifest_for_uid(
            partition,
            record_key,
            typed_checkpoint,
            floor,
            0,
        )
    }

    /// Installs the first Replay manifest under an exact service-owned journal.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe ownership, nonempty state, stale Replay
    /// authority, or an unconfirmed protected manifest append.
    pub fn install_initial_replay_manifest_for_uid(
        partition: PhysicalPartitionId,
        record_key: Vec<u8>,
        typed_checkpoint: Vec<u8>,
        floor: CacheHistoryFloorV1,
        owner_uid: u32,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let limits = CacheRecoveryLimitsV1::default();
        let owner_scope = cache_owner_scope();
        let (clock, _) = ProtectedCacheClockV1::open(root, owner_scope, owner_uid)?;
        // Match the fixed owner's lock order: clock, authority, then state.
        let (mut authority_journal, _) = open_cache_journal(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            owner_uid,
        )?;
        let (mut state_journal, state_report) = open_cache_journal(
            root,
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
            owner_uid,
        )?;
        let state_empty = state_journal
            .claim_protected_authority(RecordNamespace::DesiredState)?
            .is_materialized_empty()?;
        if state_report.committed_transactions != 0
            || state_report.truncated_bytes != 0
            || !state_empty
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }

        validate_genesis_checkpoint(partition, &typed_checkpoint, floor, limits)?;

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

        let (mut reopened, _) = open_cache_journal(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            owner_uid,
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

    /// Adds an empty partition under a preexisting protected Replay record.
    ///
    /// Existing partitions and their state are replayed before the append. The
    /// new manifest becomes available to this owner only after exact readback.
    /// This method does not issue the Replay record or install cache policy.
    ///
    /// # Errors
    ///
    /// Returns an error if existing replay fails, the partition has records or
    /// a manifest, the Replay record mismatches, or the append is indeterminate.
    pub fn install_additional_replay_manifest(
        &mut self,
        partition: PhysicalPartitionId,
        record_key: Vec<u8>,
        typed_checkpoint: Vec<u8>,
        floor: CacheHistoryFloorV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let projection = self.replay()?;
        if projection.records().iter().any(|record| {
            record.key().kind() != CacheResidencyProtectedRecordKindV1::EffectObservation
                && record.key().identity().get(..32) == Some(partition.digest().as_bytes())
        }) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        validate_genesis_checkpoint(
            partition,
            &typed_checkpoint,
            floor,
            CacheRecoveryLimitsV1::default(),
        )?;
        self.authority
            .install_replay_partition(partition, record_key, typed_checkpoint, floor)?;
        self.replay()?;
        Ok(())
    }
}

pub(crate) fn validate_genesis_checkpoint(
    partition: PhysicalPartitionId,
    typed_checkpoint: &[u8],
    floor: CacheHistoryFloorV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    let checkpoint = decode_typed_checkpoint(partition, typed_checkpoint, limits)
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
    Ok(())
}
