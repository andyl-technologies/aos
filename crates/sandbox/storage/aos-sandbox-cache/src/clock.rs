//! Owns the actual Cache clock writer and its borrowed native readback fence.
//!
//! The same private original retains its journal, floor, native witness and
//! readback-held state across Controller/Source orchestration. The borrowed
//! fence cannot reopen a writer, release a policy hold or mint a Root phase.
//! Its returned commit and later independent readback remain distinct owning
//! slots; the first native cause is retained before any coarse stopping marker.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::cache_state::clock_floor::{
    CacheClockFloorDataV1 as CacheClockFloorV1,
    cache_clock_transaction_id_data_v1,
};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedWriterNameWitness,
    RecordNamespace, RecoveryReport, CacheHeldWriterShapeV1,
};
use crate::protected_transaction::ProtectedDomainJournalErrorV1;
use crate::{CacheResidencyProtectedJournalErrorV1};
use crate::protected_journal::CacheResidencyCurrentTimeAuthorityV1;
use crate::protected_owner::{
    CACHE_AUTHORITY_JOURNAL, CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY,
    CACHE_STATE_JOURNAL, PROTECTED_CACHE_ROOT, cache_clock_journal_limits,
    decode_cache_clock_floor, InitializerJournal,
    encode_cache_clock_floor, open_cache_journal, sample_wall_clock,
};

pub(crate) struct ProtectedCacheClockV1 {
    state: Mutex<ProtectedCacheClockStateV1>,
    root: PathBuf,
    owner_scope: ObjectDigest,
    owner_uid: u32,
}

struct ProtectedCacheClockStateV1 {
    journal: Option<Journal>,
    floor: CacheClockFloorV1,
    last_sampled_unix_seconds: u64,
    readback_held: bool,
}

/// Owns one selected in-place clock proposal and every returned native result.
/// The optional proposal distinguishes an unchanged actual floor from a write;
/// neither case manufactures a commit receipt or lends the clock authority.
#[derive(Default)]
pub(crate) struct CacheClockReadMetadataProgressV1 {
    prepared: Option<Result<Option<CacheClockReadMetadataStepV1>, CacheResidencyProtectedJournalErrorV1>>,
    preflight: Option<Result<(), crate::journal::JournalError>>,
    commit: Option<Result<crate::journal::CommitResult, crate::journal::JournalError>>,
    readback: Option<Result<(), CacheResidencyProtectedJournalErrorV1>>,
    attempted: bool,
    commit_attempted: bool,
}

struct CacheClockReadMetadataStepV1 {
    original: CacheClockFloorV1,
    proposed: CacheClockFloorV1,
    transaction: JournalTransaction,
    expected: Vec<u8>,
}

impl CacheClockReadMetadataProgressV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.prepared.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.preflight.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.commit.as_ref() {
            return Some(cause);
        }
        self.readback.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

pub(crate) struct CacheClockWriterReadbackGuard<'clock> {
    clock: &'clock ProtectedCacheClockV1,
    witness: ProtectedWriterNameWitness,
}

impl CacheClockWriterReadbackGuard<'_> {
    pub(crate) fn prepare_git_read_metadata(
        &self,
        destination: &mut CacheClockReadMetadataProgressV1,
        sampled_seconds: u64,
    ) -> Result<(), crate::protected_owner::initialization::CacheResidentUnavailableV1> {
        use crate::protected_owner::initialization::CacheResidentUnavailableV1;

        if destination.attempted {
            return Err(CacheResidentUnavailableV1);
        }
        destination.attempted = true;
        destination.prepared = Some((|| {
            self.revalidate()?;
            let current = self.current_unix_seconds()?;
            let state = self.clock.state.lock()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let journal = state.journal.as_ref()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            self.clock.check_named_journal(journal)?;
            journal.validate_protected_writer_name_witness(&self.witness)?;
            if !state.readback_held || sampled_seconds < state.floor.observed_unix_seconds
                || sampled_seconds > current
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            if sampled_seconds == state.floor.observed_unix_seconds {
                return Ok(None);
            }

            let proposed = CacheClockFloorV1 {
                owner_scope: state.floor.owner_scope,
                revision: state.floor.revision.checked_add(1)
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                observed_unix_seconds: sampled_seconds,
                predecessor_unix_seconds: state.floor.observed_unix_seconds,
            };
            let expected = encode_cache_clock_floor(proposed);
            let transaction = JournalTransaction::new(
                cache_clock_transaction_id_data_v1(&expected)
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState, CACHE_CLOCK_KEY.to_vec(), expected.clone(),
                )],
            ).map_err(crate::journal::JournalError::from)?;
            if journal.get(RecordNamespace::DesiredState, CACHE_CLOCK_KEY)
                != Some(encode_cache_clock_floor(state.floor).as_slice())
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            Ok(Some(CacheClockReadMetadataStepV1 {
                original: state.floor, proposed, transaction, expected,
            }))
        })());
        let step = destination.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheResidentUnavailableV1)?;
        if let Some(step) = step {
            let state = self.clock.state.lock().map_err(|_| CacheResidentUnavailableV1)?;
            let journal = state.journal.as_ref().ok_or(CacheResidentUnavailableV1)?;
            destination.preflight = Some(journal.preflight_transactions(
                std::slice::from_ref(&step.transaction),
            ));
            if !matches!(destination.preflight, Some(Ok(()))) {
                return Err(CacheResidentUnavailableV1);
            }
        }
        Ok(())
    }

    pub(crate) fn commit_git_read_metadata(
        &mut self,
        destination: &mut CacheClockReadMetadataProgressV1,
    ) -> Result<(), crate::protected_owner::initialization::CacheResidentUnavailableV1> {
        use crate::protected_owner::initialization::CacheResidentUnavailableV1;

        if destination.commit_attempted || destination.failure().is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        destination.commit_attempted = true;
        let step = destination.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheResidentUnavailableV1)?;
        let Some(step) = step else {
            destination.readback = Some(self.revalidate());
            return match destination.readback {
                Some(Ok(())) => Ok(()),
                _ => Err(CacheResidentUnavailableV1),
            };
        };

        let mut state = self.clock.state.lock().map_err(|_| CacheResidentUnavailableV1)?;
        let journal = state.journal.as_mut().ok_or(CacheResidentUnavailableV1)?;
        // Do not recursively acquire this mutex through guard.revalidate().
        destination.readback = Some((|| {
            self.clock.check_named_journal(journal)?;
            journal.validate_protected_writer_name_witness(&self.witness)?;
            if journal.get(RecordNamespace::DesiredState, CACHE_CLOCK_KEY)
                != Some(encode_cache_clock_floor(step.original).as_slice())
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            Ok(())
        })());
        if !matches!(destination.readback, Some(Ok(()))) {
            return Err(CacheResidentUnavailableV1);
        }
        destination.preflight = Some(journal.preflight_transactions(
            std::slice::from_ref(&step.transaction),
        ));
        if !matches!(destination.preflight, Some(Ok(()))) {
            return Err(CacheResidentUnavailableV1);
        }

        destination.commit = Some(journal.commit(&step.transaction));
        destination.readback = Some((|| {
            if journal.get(RecordNamespace::DesiredState, CACHE_CLOCK_KEY)
                != Some(step.expected.as_slice())
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            self.clock.check_named_journal(journal)?;
            Ok(())
        })());
        if !matches!(destination.commit, Some(Ok(_)))
            || !matches!(destination.readback, Some(Ok(())))
        {
            return Err(CacheResidentUnavailableV1);
        }
        // Only exact success advances the remembered floor and its witness.
        let witness = match journal.protected_writer_name_witness() {
            Ok(witness) => witness,
            Err(cause) => {
                destination.readback = Some(Err(cause.into()));
                return Err(CacheResidentUnavailableV1);
            }
        };
        state.floor = step.proposed;
        self.witness = witness;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn compare_fixed_git_coverage_catalog_v1(
        &self,
        catalog: &aos_sandbox_model::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<(), crate::protected_owner::initialization::InitializationCauseV1> {
        use crate::protected_owner::initialization::InitializationCauseV1;

        let state = self.clock.state.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !state.readback_held {
            return Err(InitializationCauseV1::Closed);
        }
        let journal = state.journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
        self.clock.check_named_journal(journal)?;
        journal.validate_protected_writer_name_witness(&self.witness)?;
        let encoded_floor = encode_cache_clock_floor(state.floor);
        let mut current = journal.all_records();
        let Some((namespace, key, value)) = current.next() else {
            return Err(InitializationCauseV1::Closed);
        };
        if namespace != RecordNamespace::DesiredState
            || key != CACHE_CLOCK_KEY
            || value != encoded_floor.as_slice()
            || current.next().is_some()
        {
            return Err(InitializationCauseV1::Closed);
        }
        let mut clock_prefix = journal.cache_clock_coverage_native_prefix_v1(&catalog)
            .map_err(|cause| crate::journal::JournalError::NativePrefix(Box::new(cause)))?;
        clock_prefix.recheck()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn capture_git_coverage_native_cut_v1(
        &self,
        catalog: &aos_sandbox_model::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<
        aos_sandbox_protocol::git_project_coverage::GitCoverageNativeCutDataV1,
        CacheResidencyProtectedJournalErrorV1,
    > {
        let held = self.clock.state.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !held.readback_held {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let journal = held.journal.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        self.clock.check_named_journal(journal)?;
        journal.validate_protected_writer_name_witness(&self.witness)?;
        let mut native = journal.cache_clock_coverage_native_prefix_v1(catalog)
            .map_err(|cause| crate::journal::JournalError::NativePrefix(Box::new(cause)))?;
        native.recheck()?;
        Ok(aos_sandbox_protocol::git_coverage_native_cut_data_v1! {
            profile: aos_sandbox_model::format::git_upload_enrollment::GitCoverageJournalProfileV1::CacheClock,
            loan: native
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn q04_prepare_coordinates(
        &self,
        hold: &Journal,
    ) -> Result<(crate::journal::ProtectedJournalNamesV1, u64), crate::error::CacheQ04ErrorV1> {
        self.revalidate()?;
        let state = self.clock.state.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let journal = state.journal.as_ref().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        self.clock.check_named_journal(journal)?;
        journal.validate_protected_writer_name_witness(&self.witness)?;
        journal.preflight_q04_cache_read_only_base_v1(hold)?;
        let coordinates = (journal.protected_writer_physical_names_v1()?, journal.snapshot_sequence());
        journal.validate_protected_writer_name_witness(&self.witness)?;
        Ok(coordinates)
    }

    /// Samples the original clock without reopening its held writer.
    ///
    /// # Errors
    /// Refuses changed protected clock identity or nonmonotonic time.
    pub(crate) fn current_unix_seconds(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        self.revalidate()?;
        let current = self.clock.current_unix_seconds()?;
        self.revalidate()?;
        Ok(current)
    }

    /// Requires the authority to own this same original clock allocation.
    ///
    /// # Errors
    /// Refuses a different clock or changed original writer witness.
    pub(crate) fn require_time_authority(
        &self,
        authority: &Arc<dyn CacheResidencyCurrentTimeAuthorityV1>,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.revalidate()?;
        if !std::ptr::addr_eq(
            Arc::as_ptr(authority),
            self.clock as *const ProtectedCacheClockV1,
        ) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    /// Checks both original Cache writers against this clock's protected root.
    ///
    /// # Errors
    /// Refuses changed clock or unsafe Cache names, UID, mode or limits.
    pub(crate) fn require_cache_targets(
        &self,
        state: &Journal,
        authority: &Journal,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.revalidate()?;
        for (journal, name) in [
            (state, CACHE_STATE_JOURNAL),
            (authority, CACHE_AUTHORITY_JOURNAL),
        ] {
            #[cfg(test)]
            journal.require_protected_named_location_at_uid_for_test(
                &self.clock.root,
                name,
                self.clock.owner_uid,
                journal.limits(),
            )?;
            #[cfg(not(test))]
            journal.require_protected_named_location(
                &self.clock.root,
                name,
                self.clock.owner_uid,
                journal.limits(),
            )?;
        }
        Ok(())
    }

    /// Rechecks the existing clock writer's complete original witness.
    ///
    /// # Errors
    /// Refuses a missing, released or changed original clock writer.
    pub(crate) fn revalidate(
        &self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let state = self
            .clock
            .state
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !state.readback_held {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let journal = state
            .journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        self.clock.check_named_journal(journal)?;
        journal.validate_protected_writer_name_witness(&self.witness)?;
        Ok(())
    }
}

impl Drop for CacheClockWriterReadbackGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.clock.state.lock() {
            state.readback_held = false;
        }
    }
}

impl ProtectedCacheClockV1 {
    pub(crate) fn hold_writer_for_readback(
        &self,
    ) -> Result<CacheClockWriterReadbackGuard<'_>, CacheResidencyProtectedJournalErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if state.readback_held {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let journal = state
            .journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        self.check_named_journal(journal)?;
        let witness = journal.protected_writer_name_witness()?;
        state.readback_held = true;
        Ok(CacheClockWriterReadbackGuard {
            clock: self,
            witness,
        })
    }

    pub(crate) fn check_named_journal(
        &self,
        journal: &Journal,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        #[cfg(test)]
        if self.root != Path::new(PROTECTED_CACHE_ROOT) {
            journal.require_protected_named_location_at_uid_for_test(
                &self.root,
                CACHE_CLOCK_JOURNAL,
                self.owner_uid,
                cache_clock_journal_limits(),
            )?;
            return Ok(());
        }

        journal.require_protected_named_location(
            &self.root,
            CACHE_CLOCK_JOURNAL,
            self.owner_uid,
            cache_clock_journal_limits(),
        )?;
        Ok(())
    }

    pub(crate) fn open(
        root: &Path,
        owner_scope: ObjectDigest,
        owner_uid: u32,
    ) -> Result<(Self, RecoveryReport), CacheResidencyProtectedJournalErrorV1> {
        let (mut journal, report) = open_cache_journal(
            root,
            CACHE_CLOCK_JOURNAL,
            cache_clock_journal_limits(),
            owner_uid,
        )?;
        let retained = read_cache_clock_floor(&mut journal)?;
        let sampled = sample_wall_clock()?;
        let floor = match retained {
            Some(floor)
                if floor.owner_scope == owner_scope && floor.observed_unix_seconds <= sampled =>
            {
                floor
            }
            Some(_) => return Err(ProtectedDomainJournalErrorV1::StaleAuthority),
            None => {
                let genesis = CacheClockFloorV1 {
                    owner_scope,
                    revision: 1,
                    observed_unix_seconds: sampled,
                    predecessor_unix_seconds: 0,
                };
                let (reopened, applied) = persist_cache_clock(journal, root, None, genesis, owner_uid)?;
                if !applied {
                    return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
                }
                journal = reopened;
                genesis
            }
        };
        Ok((
            Self::from_validated_floor(journal, root, owner_scope, owner_uid, floor),
            report,
        ))
    }

    pub(crate) fn from_validated_floor(
        journal: Journal,
        root: &Path,
        owner_scope: ObjectDigest,
        owner_uid: u32,
        floor: CacheClockFloorV1,
    ) -> Self {
        Self {
            state: Mutex::new(ProtectedCacheClockStateV1 {
                journal: Some(journal),
                floor,
                last_sampled_unix_seconds: floor.observed_unix_seconds,
                readback_held: false,
            }),
            root: root.to_path_buf(),
            owner_scope,
            owner_uid,
        }
    }
}

pub(crate) fn read_cache_clock_floor(
    journal: &mut Journal,
) -> Result<Option<CacheClockFloorV1>, CacheResidencyProtectedJournalErrorV1> {
    let authority = journal.claim_cache_authority_v1()?;
    authority
        .get(CACHE_CLOCK_KEY)?
        .map(decode_cache_clock_floor)
        .transpose()
}

impl CacheResidencyCurrentTimeAuthorityV1 for ProtectedCacheClockV1 {
    fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        let sampled = sample_wall_clock()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if state.floor.owner_scope != self.owner_scope || sampled < state.last_sampled_unix_seconds
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        state.last_sampled_unix_seconds = sampled;
        // A readback keeps the writer inode fixed; persisting the floor would
        // release and reopen it between the protected and physical checks.
        if state.readback_held {
            return Ok(sampled);
        }
        if sampled == state.floor.observed_unix_seconds {
            return Ok(sampled);
        }
        let successor = CacheClockFloorV1 {
            owner_scope: self.owner_scope,
            revision: state
                .floor
                .revision
                .checked_add(1)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
            observed_unix_seconds: sampled,
            predecessor_unix_seconds: state.floor.observed_unix_seconds,
        };
        let journal = state
            .journal
            .take()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let (reopened, applied) =
            persist_cache_clock(journal, &self.root, Some(state.floor), successor, self.owner_uid)?;
        state.journal = Some(reopened);
        if !applied {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
        }
        state.floor = successor;
        Ok(sampled)
    }
}

// Reopen beneath the original clock's root, not an unrelated fixed name. The
// production opener supplies the fixed root; private fixtures retain their own.
fn persist_cache_clock(
    mut journal: Journal,
    root: &Path,
    predecessor: Option<CacheClockFloorV1>,
    successor: CacheClockFloorV1,
    owner_uid: u32,
) -> Result<(Journal, bool), CacheResidencyProtectedJournalErrorV1> {
    let encoded = encode_cache_clock_floor(successor);
    let transaction_id = cache_clock_transaction_id_data_v1(&encoded)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            CACHE_CLOCK_KEY.to_vec(),
            encoded.clone(),
        )],
    )?;
    {
        let mut authority = journal.claim_cache_authority_v1()?;
        let current = authority.get(CACHE_CLOCK_KEY)?.map(<[u8]>::to_vec);
        let expected = predecessor.map(encode_cache_clock_floor);
        if current.as_deref() != expected.as_deref() {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
        }
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        let _attempt = authority.commit(&transaction);
    }
    drop(journal);

    let (mut reopened, _) = open_cache_journal(
        root,
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
        owner_uid,
    )?;
    let readback = {
        let authority = reopened.claim_cache_authority_v1()?;
        authority.get(CACHE_CLOCK_KEY)?.map(<[u8]>::to_vec)
    };
    if readback.as_deref() == Some(encoded.as_slice()) {
        return Ok((reopened, true));
    }
    let expected = predecessor.map(encode_cache_clock_floor);
    if readback.as_deref() == expected.as_deref() {
        return Ok((reopened, false));
    }
    Err(ProtectedDomainJournalErrorV1::DivergentRecovery)
}



impl ProtectedCacheClockV1 {
    pub(crate) fn hold_writer_for_create_storage_readback(
        &self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
    ) -> Result<CacheClockWriterReadbackGuard<'_>, CacheResidencyProtectedJournalErrorV1> {
        let mut state = self.state.lock().map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if state.readback_held || self.root != Path::new(PROTECTED_CACHE_ROOT) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let journal = state.journal.as_ref().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        original.capture_cache_once(journal, InitializerJournal::Clock, self.owner_uid);
        let witness = original.take_witness_once()?;
        state.readback_held = true;
        Ok(CacheClockWriterReadbackGuard { clock: self, witness })
    }
}

impl CacheClockWriterReadbackGuard<'_> {
    pub(crate) fn require_create_storage_shape_v1(
        &self,
        shape: &CacheHeldWriterShapeV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        shape.require_witness(&self.witness)?;
        Ok(())
    }

    pub(crate) fn require_create_storage_hold_v1(
        &self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let state = self.clock.state.lock().map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !state.readback_held || self.clock.root != Path::new(PROTECTED_CACHE_ROOT) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        state.journal.as_ref().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
            .require_cache_held_config_v1(InitializerJournal::Clock, self.clock.owner_uid)?;
        Ok(())
    }

    pub(crate) fn require_create_storage_time_authority_v1(
        &self,
        authority: &Arc<dyn CacheResidencyCurrentTimeAuthorityV1>,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        if !std::ptr::addr_eq(Arc::as_ptr(authority), self.clock as *const ProtectedCacheClockV1) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(crate) fn require_create_storage_targets_v1(
        &self,
        state: &Journal,
        authority: &Journal,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        state.require_cache_held_config_v1(InitializerJournal::State, self.clock.owner_uid)?;
        authority.require_cache_held_config_v1(InitializerJournal::Authority, self.clock.owner_uid)?;
        Ok(())
    }

    pub(crate) fn create_storage_unix_seconds_v1(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        // The actual guard keeps readback_held true. The existing clock owner
        // still checks owner scope, wall-clock monotonicity and its saved floor,
        // without persisting a new clock transaction during this held cut.
        let current = self.clock.current_unix_seconds()?;
        self.require_create_storage_hold_v1()?;
        Ok(current)
    }
}


impl ProtectedCacheClockV1 {
    pub(crate) fn capture_create_storage_shape_v1(
        &self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
    ) -> Result<CacheHeldWriterShapeV1, CacheResidencyProtectedJournalErrorV1> {
        let state = self.state.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let journal = state.journal.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        journal.capture_cache_held_shape_v1(original, InitializerJournal::Clock, self.owner_uid)
            .map_err(Into::into)
    }

    pub(crate) fn require_create_storage_readback_v1(
        &self,
        expected: &crate::journal::CacheHeldWriterShapeV1,
        readback: &mut crate::journal::ReadOnlyProtectedJournal,
    ) -> Result<(), crate::protected_owner::initialization::create_storage::CacheHeldErrorV1> {
        use crate::protected_owner::initialization::create_storage::CacheHeldErrorV1;

        let state = self.state.lock().map_err(|_| CacheHeldErrorV1::Order)?;
        state.journal.as_ref().ok_or(CacheHeldErrorV1::Order)?
            .require_cache_held_readback_v1(expected, readback)?;
        Ok(())
    }

    pub(crate) fn observe_create_storage_position_v1(
        &self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
        uid: u32,
        expected: Option<&crate::journal::CacheHeldWriterShapeV1>,
    ) -> Result<(), crate::protected_owner::initialization::create_storage::CacheHeldErrorV1> {
        use crate::protected_owner::initialization::create_storage::CacheHeldErrorV1;

        let state = self.state.lock().map_err(|_| CacheHeldErrorV1::Order)?;
        let journal = state.journal.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        original.capture_cache_once(journal, InitializerJournal::Clock, uid);
        original.position()?;
        if let Some(expected) = expected {
            expected.require_observed(journal, original)?;
        }
        Ok(())
    }

    pub(crate) fn create_storage_floor_data_v1(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        let state = self.state.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok(state.floor.observed_unix_seconds)
    }
}

#[cfg(test)]
mod owner_regressions {
    use super::*;
    use std::fs;
    use crate::protected_owner::{cache_owner_scope, tests::cache_hold_fixture};

    #[test]
    fn held_readback_clock_does_not_reopen_or_advance_its_writer() {
        let now = sample_wall_clock().expect("fixture time");
        let (directory, uid, _) = cache_hold_fixture(now + 86_400, now - 5);
        let (clock, _) = ProtectedCacheClockV1::open(directory.path(), cache_owner_scope(), uid)
            .expect("open held clock");
        let named = directory.path().join(CACHE_CLOCK_JOURNAL);
        let before = fs::metadata(&named).expect("clock metadata").len();

        let held = clock.hold_writer_for_readback().expect("hold clock writer");
        assert!(clock.current_unix_seconds().expect("sample time") >= now);
        assert_eq!(fs::metadata(&named).expect("clock metadata").len(), before);
        assert!(matches!(
            Journal::open_cache_ordinary_role_v1(
                directory.path(),
                CACHE_CLOCK_JOURNAL,
                cache_clock_journal_limits(),
                uid,
                crate::journal::CacheOrdinaryOpenV1::Creating,
            ),
            Err(crate::journal::JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::AlreadyLocked))
        ));
        held.revalidate().expect("same named clock writer");
        drop(held);
        assert!(!clock.state.lock().expect("clock state").readback_held);
    }

    #[test]
    fn clock_successor_reopens_its_original_private_root() {
        let now = sample_wall_clock().expect("fixture time");
        let observed = now.checked_sub(5).expect("older fixture floor");
        let (directory, uid, _) = cache_hold_fixture(now + 86_400, observed);
        let (clock, _) = ProtectedCacheClockV1::open(directory.path(), cache_owner_scope(), uid)
            .expect("open private clock");
        let named = directory.path().join(CACHE_CLOCK_JOURNAL);
        let before = fs::metadata(&named).expect("original clock metadata").len();

        let sampled = clock.current_unix_seconds().expect("persist real successor");

        assert!(sampled >= now);
        assert!(fs::metadata(&named).expect("successor clock metadata").len() > before);
        let mut state = clock.state.lock().expect("clock state");
        let journal = state.journal.as_mut().expect("reopened original clock");
        clock.check_named_journal(journal).expect("same protected root");
        let persisted = read_cache_clock_floor(journal)
            .expect("read persisted successor")
            .expect("successor floor");
        assert_eq!(persisted.owner_scope, cache_owner_scope());
        assert_eq!(persisted.revision, 2);
        assert_eq!(persisted.predecessor_unix_seconds, observed);
        assert_eq!(persisted.observed_unix_seconds, sampled);
        assert_eq!(state.floor.observed_unix_seconds, sampled);
    }
}
