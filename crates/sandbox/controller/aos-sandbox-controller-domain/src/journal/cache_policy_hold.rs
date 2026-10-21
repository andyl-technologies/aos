//! Durable Cache policy-state freeze for an inert Create binding cut.
//!
//! ```text
//! AOSCPH01 | version:u16 | phase:held|released | reserved:5 |
//! project:16 | partition:32 | cache-head:32 | binding:32 | epoch:u64 |
//! SHA-256(Cache-hold-domain || preceding 136 bytes):32
//! ```
//! V8 retirement also retains the prior held row's digest until Root records
//! the post-Controller settlement:
//!
//! ```text
//! AOSCPP08 | version=1 | phase=pending | reserved[5] |
//! binding[32] | epoch:u64 | SHA-256(held AOSCPH01)[32] |
//! SHA-256(released AOSCPH01)[32] |
//! SHA-256(Cache-V8-pending-domain || preceding 120 bytes)[32]
//! ```
//!
//! A separate protected journal lets Cache state and manifest commits hold its
//! writer lock through sync. The Cache clock may still advance its monotone
//! floor; it cannot change quota, domain, or replay head.

use aos_sandbox_ledger_replay::git_coverage_prefix::cache::policy_hold_transaction_data_v1;
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::cache_state::hold_state::{
    CachePolicyV8PendingSettlementDataV1 as CachePolicyV8PendingSettlementV1,
    CachePolicyHoldStateDataV1 as CachePolicyHoldStateV1,
    CachePolicyHoldReadbackDataV1 as CachePolicyHoldReadbackV1,
    CachePolicyDecodedStateDataV1 as CachePolicyDecodedStateV1,
};

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use aos_sandbox_model::{ObjectDigest, ProjectId};
#[cfg(target_os = "linux")]
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthFieldsV1, GitCoverageBirthV1, GitCoverageFenceFieldsV1,
    GitCoverageFenceV1,
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_protocol::root_settlement::RootV8SuccessorSettlementV1;

use super::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    RecordNamespace,
};

mod retained;
pub(crate) use retained::{
    BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1,
};

pub(crate) const NAME: &str = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_BASENAME_V1;
const GENESIS_KEY: &[u8] = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_GENESIS_KEY_V1;
const HOLD_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::HOLD_KEY;
const V8_PENDING_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::V8_PENDING_KEY;
const GENESIS: &[u8] = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_GENESIS_V1;
const V8_RELEASE_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-release.v1\0";
const V8_SETTLEMENT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-settlement.v1\0";
const V8_SETTLEMENT_PREFLIGHT_DOMAIN: &[u8] =
    b"aos.sandbox.cache-policy-v8-settlement-preflight.v1\0";

fn hold_limits() -> JournalLimits {
    aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::Hold.limits_v1()
}







// The ordinary state remains its exact prior type and decode path. Exclusive
// state carries bounded DATA coordinates, not an allocation or Read permit.
#[derive(Clone, Copy, Eq, PartialEq)]
enum CachePolicyGateStateV1 {
    Ordinary(CachePolicyHoldStateV1),
    #[cfg(target_os = "linux")]
    Exclusive(CacheGitCoverageObservationV1),
}

/// Retains parser-validated denial coordinates, not Cache allocation authority.
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg(target_os = "linux")]
pub(crate) struct CacheGitCoverageObservationV1 {
    birth: GitCoverageBirthFieldsV1,
    fence: GitCoverageFenceFieldsV1,
    prefix: [u8; 32],
    commit_sequence: u64,
}

#[cfg(target_os = "linux")]
impl CacheGitCoverageObservationV1 {
    pub(crate) fn enrollment(self) -> [u8; 32] {
        self.birth.enrollment
    }

    pub(crate) fn catalog(self) -> [u8; 32] {
        self.birth.catalog
    }

    pub(crate) fn original_coordinates(
        self,
    ) -> (GitCoverageBirthFieldsV1, GitCoverageFenceFieldsV1, [u8; 32], u64) {
        (self.birth, self.fence, self.prefix, self.commit_sequence)
    }
}

impl CachePolicyGateStateV1 {
    fn is_exclusive(self) -> bool {
        match self {
            Self::Ordinary(_) => false,
            #[cfg(target_os = "linux")]
            Self::Exclusive(_) => true,
        }
    }

    fn require_new_mutation(self) -> Result<(), JournalError> {
        match self {
            Self::Ordinary(state)
                if !state.hold.is_some_and(CachePolicyHoldV1::is_held)
                    && state.v8_pending.is_none() => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

fn v8_release_transaction(
    released: CachePolicyHoldV1,
    pending: CachePolicyV8PendingSettlementV1,
) -> Result<JournalTransaction, JournalError> {
    pending.validate_for(released)?;
    let hold_bytes = released.encode()?;
    let pending_bytes = pending.encode();
    let digest = Sha256::new()
        .chain_update(V8_RELEASE_TRANSACTION_DOMAIN)
        .chain_update(hold_bytes)
        .chain_update(pending_bytes)
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                V8_PENDING_KEY.to_vec(),
                pending_bytes.to_vec(),
            ),
        ],
    ).map_err(JournalError::from)
}

fn v8_settlement_transaction(
    grant: RootV8SuccessorSettlementV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(grant.predecessor().as_bytes())
        .chain_update(grant.epoch().to_be_bytes())
        .chain_update(grant.cache_released().as_bytes())
        .chain_update(grant.settlement().as_bytes())
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            V8_PENDING_KEY.to_vec(),
        )],
    ).map_err(JournalError::from)
}

fn v8_settlement_preflight_transaction(
    released: CachePolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_PREFLIGHT_DOMAIN)
        .chain_update(released.encode()?)
        .finalize();

    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            V8_PENDING_KEY.to_vec(),
        )],
    ).map_err(JournalError::from)
}



// The single fixed-state decoder distinguishes purpose DATA before any
// writer-only native loan. Ordinary Q04 and V8 adapters cannot ignore a fence.


#[cfg(target_os = "linux")]
fn require_no_cache_held_history(journal: &Journal) -> Result<(), JournalError> {
    if journal.records(RecordNamespace::CreateStorageHistory).next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn current_full_state(journal: &mut Journal) -> Result<CachePolicyHoldReadbackV1, JournalError> {
    #[cfg(target_os = "linux")]
    require_no_cache_held_history(journal)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    decode_full_state(authority.records()?)
}

fn decode_full_state<'records>(
    records: impl Iterator<Item = (&'records [u8], &'records [u8])>,
) -> Result<CachePolicyHoldReadbackV1, JournalError> {
    aos_sandbox_protocol::cache_state::hold_state::decode_full_state(records)
        .map_err(JournalError::from)
}

fn decode_gate_state<'records>(
    records: impl Iterator<Item = (&'records [u8], &'records [u8])>,
) -> Result<CachePolicyDecodedStateV1, JournalError> {
    aos_sandbox_protocol::cache_state::hold_state::decode_gate_state(records)
        .map_err(JournalError::from)
}

fn current_state(journal: &mut Journal) -> Result<CachePolicyHoldStateV1, JournalError> {
    let state = current_full_state(journal)?;
    #[cfg(target_os = "linux")]
    if state.q04_pending.is_some() {
        // All legacy/V8 mutation and settlement adapters stay closed to the
        // distinct Q04 purpose, including exact cold replay.
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(state.legacy)
}

fn current_gate_state(journal: &mut Journal) -> Result<CachePolicyGateStateV1, JournalError> {
    #[cfg(target_os = "linux")]
    require_no_cache_held_history(journal)?;
    let decoded = {
        let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        decode_gate_state(authority.records()?)?
    };
    match decoded {
        CachePolicyDecodedStateV1::Ordinary(state) => {
            #[cfg(target_os = "linux")]
            if state.q04_pending.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(CachePolicyGateStateV1::Ordinary(state.legacy))
        }
        #[cfg(target_os = "linux")]
        CachePolicyDecodedStateV1::Exclusive { birth, fence } => {
            // Original Genesis and paired birth must be replayed by the SAME
            // writer. Final-map absence is never a fresh-enrollment proof.
            let mut native = journal.cache_coverage_native_prefix_v1()
                .map_err(|error| JournalError::GitCoverageNativeHistory(Box::new(error)))?;
            let (transaction, commit_sequence) = native.last_commit()
                .ok_or(JournalError::ProtectedBoundary)?;
            if native.counts() != (2, 3)
                || transaction != fence.transaction
                || commit_sequence != birth.commit_sequence
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let prefix = native.prefix_digest();
            native.recheck()?;
            Ok(CachePolicyGateStateV1::Exclusive(CacheGitCoverageObservationV1 {
                birth, fence, prefix, commit_sequence,
            }))
        }
    }
}

// The durable node-cohort denial cannot be released through a generic hold,
// V8, Q04, delete, overwrite or another generic append after readback. This
// examines only the same fixed gate's existing materialization; it neither
// decodes a second schema nor supplies an append exception.
#[cfg(target_os = "linux")]
pub(super) fn require_no_exclusive_mutation_v1(
    journal: &Journal,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    require_no_exclusive_mutation_read_v1(journal.native.read_view(), state)
}

#[cfg(target_os = "linux")]
pub(super) fn require_no_exclusive_mutation_read_v1(
    read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, super::native_backing::Selection>,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
        read, state,
    ).map_err(JournalError::from)
}

fn current(journal: &mut Journal) -> Result<Option<CachePolicyHoldV1>, JournalError> {
    let state = current_full_state(journal)?;
    #[cfg(target_os = "linux")]
    if state.q04_pending.as_ref().is_some_and(|marker| !marker.is_held()) {
        // Ordinary unheld/mutation checks cannot ignore a released-pending
        // Q04 row. The held row remains observable by the existing signer.
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(state.legacy.hold)
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_ordinary_boundary(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_cache_q04_mutation_v1(state, transaction)
        .map_err(crate::journal::JournalError::from)
}

fn v8_released_pair(
    state: CachePolicyHoldStateV1,
) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
    let released = state.hold.ok_or(JournalError::ProtectedBoundary)?;
    let pending = state.v8_pending.ok_or(JournalError::ProtectedBoundary)?;
    pending.validate_for(released)?;
    Ok((
        (released).held_data(),
        released,
    ))
}

pub(super) fn require_valid_compaction(journal: &mut Journal) -> Result<(), JournalError> {
    if journal.native.protected_view()
        .is_some_and(|location| location.name() == NAME)
    {
        current_state(journal)?;
    }
    Ok(())
}


impl Journal {
    /// Reads an active Cache hold while retaining its protected writer lock.
    ///
    /// # Errors
    ///
    /// Rejects a foreign name, released or malformed hold, or lost named custody.
    pub(crate) fn held_cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        self.cache_policy_hold_for_writer()?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Compares original cleared hold DATA without starting another native check.
    ///
    /// The closed Cache selection loan separately retains the actual prior Q04
    /// owner, all five completed Native audits and independent named bookends.
    /// This passive comparison supplies no gate, mutation or currentness grant.
    ///
    /// # Errors
    /// Rejects held, pending, malformed, foreign, substituted or missing DATA.
    pub(crate) fn require_cache_cleared_comparison_data_v1(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        let current = current_state(self)?;
        if expected.is_held() || current.hold != Some(expected) || current.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        Ok(self.cache_policy_hold_state_for_writer()?.hold)
    }

    /// Reads an exact V8 pending release under retained writer custody.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, a missing marker, or a mismatched released row.
    pub(crate) fn v8_pending_cache_policy_release_for_writer(
        &mut self,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
        v8_released_pair(self.cache_policy_hold_state_for_writer()?)
    }

    fn v8_cache_policy_settlement_state_from_record(
        &mut self,
        grant: RootV8SuccessorSettlementV1,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1, bool), JournalError> {
        let state = self.cache_policy_hold_state_for_writer()?;
        let released = state.hold.ok_or(JournalError::ProtectedBoundary)?;
        if released.is_held()
            || released.binding() != grant.predecessor()
            || released.epoch() != grant.epoch()
            || released.record_digest()? != grant.cache_released()
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let held = (released).held_data();
        Ok((held, released, state.v8_pending.is_some()))
    }

    fn clear_v8_pending_cache_settlement_from_record(
        &mut self,
        grant: RootV8SuccessorSettlementV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        let (_, released, pending) = self.v8_cache_policy_settlement_state_from_record(grant)?;
        if pending {
            self.commit(&v8_settlement_transaction(grant)?)?;
        }
        let (_, readback, still_pending) =
            self.v8_cache_policy_settlement_state_from_record(grant)?;
        if still_pending || readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(readback)
    }

    fn cache_policy_hold_state_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldStateV1, JournalError> {
        let location = self
            .native.protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.name() != NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_protected_names_current()?;
        current_state(self)
    }
}

fn open(directory: &Path, uid: u32) -> Result<Journal, JournalError> {
    #[cfg(test)]
    let opened = Journal::open_protected_at_uid(directory, NAME, hold_limits(), uid);
    #[cfg(not(test))]
    let opened = Journal::open_protected_at_for_uid(directory, NAME, hold_limits(), uid);
    opened.map(|(journal, _)| journal)
}

pub(crate) fn initialize_fresh(directory: &Path, uid: u32) -> Result<(), JournalError> {
    let hold_path = directory.join(NAME);
    let existing = match fs::symlink_metadata(&hold_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(JournalError::Io(error)),
    };
    if !existing {
        for name in ["state.journal", "authority.journal", "clock.journal"] {
            for suffix in ["", ".lock", ".compact.tmp"] {
                match fs::symlink_metadata(directory.join(format!("{name}{suffix}"))) {
                    Ok(_) => return Err(JournalError::ProtectedBoundary),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(JournalError::Io(error)),
                }
            }
        }
    }
    let mut journal = open(directory, uid)?;
    if journal.all_records().next().is_none() && !existing {
        journal.commit(
            &policy_hold_transaction_data_v1(GENESIS_KEY, GENESIS).map_err(JournalError::from)?,
        )?;
    }
    current(&mut journal)?;
    Ok(())
}

pub(super) fn check_unheld(journal: &Journal) -> Result<(), JournalError> {
    let _guard = mutation_guard(journal)?;
    Ok(())
}

pub(super) fn mutation_guard(journal: &Journal) -> Result<Option<Journal>, JournalError> {
    let Some((directory, uid)) = &journal.cache_policy_gate else {
        return Ok(None);
    };
    #[cfg(not(test))]
    journal.require_protected_location(
        directory,
        journal.native.protected_view()
            .ok_or(JournalError::ProtectedBoundary)?
            .name(),
        *uid,
        journal.native.limits(),
    )?;
    let mut hold = open(directory, *uid)?;
    if current(&mut hold)?.is_some_and(CachePolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(hold))
}

impl Journal {
    /// Returns the fixed replay bounds for the protected Cache hold name.
    pub(crate) fn cache_policy_hold_limits() -> JournalLimits {
        hold_limits()
    }

    pub(crate) fn initialize_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        initialize_fresh(directory, uid)
    }

    pub(crate) fn enable_cache_policy_hold_gate(
        &mut self,
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self
            .native.protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.expected_uid() != uid
            || !matches!(location.name(), "state.journal" | "authority.journal")
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cache_policy_gate = Some((PathBuf::from(directory), uid));
        Ok(())
    }

    pub(crate) fn read_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        current(&mut open(directory, uid)?)
    }

    /// Recovers the exact held and released rows from a V8 pending marker.
    ///
    /// # Errors
    ///
    /// Rejects a missing marker, mismatched row, or stale protected name.
    pub(crate) fn read_v8_pending_cache_policy_release_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
        let state = current_state(&mut open(directory, uid)?)?;
        v8_released_pair(state)
    }

    pub(crate) fn acquire_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut journal = open(directory, uid)?;
        journal.acquire_cache_policy_hold_for_writer(hold)
    }

    fn acquire_cache_policy_hold_for_writer(
        &mut self,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        let state = self.cache_policy_hold_state_for_writer()?;
        if state.hold.is_some_and(CachePolicyHoldV1::is_held) || state.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = policy_hold_transaction_data_v1(HOLD_KEY, &hold.encode()?)
            .map_err(JournalError::from)?;
        let released = (hold).released_data();
        let legacy_release = policy_hold_transaction_data_v1(HOLD_KEY, &released.encode()?)
            .map_err(JournalError::from)?;
        let v8_pending = CachePolicyV8PendingSettlementV1::new(hold, released)?;
        let v8_release = v8_release_transaction(released, v8_pending)?;
        let v8_clear = v8_settlement_preflight_transaction(released)?;
        self.preflight_transactions(&[acquire.clone(), legacy_release])?;
        // The pending marker must be clearable without depending on future
        // compaction, even when this acquire reaches the journal capacity edge.
        self.preflight_transactions(&[acquire.clone(), v8_release, v8_clear])?;
        self.commit(&acquire)?;
        if current(self)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn release_cache_policy_hold_if_at<E>(
        directory: &Path,
        uid: u32,
        expected: CachePolicyHoldV1,
        verify_root: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<JournalError>,
    {
        let mut journal = open(directory, uid)?;
        if !expected.is_held() || current(&mut journal)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // No state or manifest writer can cross this check: each commit must
        // borrow this same hold-journal lock until its durable sync completes.
        verify_root()?;
        let released = (expected).released_data();
        journal.commit(
            &policy_hold_transaction_data_v1(
                HOLD_KEY,
                &released.encode().map_err(JournalError::from)?,
            )
            .map_err(JournalError::from)?,
        )?;
        if current(&mut journal)? != Some(released) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    /// Retires an exact Cache hold through its already retained writer.
    ///
    /// The caller must retain the other Cache writers and physical owner until
    /// its final cross-owner checks have completed. Opening this journal again
    /// would contend with the writer held by that same callback. The returned
    /// canonical released row is read back from this writer after durable sync;
    /// an exact cold replay returns the same row without another commit.
    ///
    /// # Errors
    ///
    /// Rejects foreign or stale writer custody, a different hold, or failed
    /// durable commit and readback.
    pub(crate) fn release_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }

        let released = (expected).released_data();
        match self.cache_policy_hold_state_for_writer()? {
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == expected => {
                self.commit(
                    &policy_hold_transaction_data_v1(HOLD_KEY, &released.encode()?)
                        .map_err(JournalError::from)?,
                )?;
            }
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == released => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        let readback = self
            .cache_policy_hold_for_writer()?
            .ok_or(JournalError::ProtectedBoundary)?;
        if readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(readback)
    }

    /// Retires a V8 Cache hold with its pending settlement in one transaction.
    ///
    /// The marker retains both canonical row digests until a future trusted
    /// Root successor settlement permits clearing it. Replaying the exact
    /// released pair through this writer performs no second commit.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, a different row, a missing marker on replay,
    /// or a failed durable transaction or readback.
    pub(crate) fn release_v8_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = (expected).released_data();
        let pending = CachePolicyV8PendingSettlementV1::new(expected, released)?;
        let state = self.cache_policy_hold_state_for_writer()?;
        match state {
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == expected => {
                self.commit(&v8_release_transaction(released, pending)?)?;
            }
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: Some(current_pending),
            } if current == released && current_pending == pending => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        let (held_readback, released_readback) =
            v8_released_pair(self.cache_policy_hold_state_for_writer()?)?;
        if held_readback != expected || released_readback != released {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(released_readback)
    }

}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn fixture() -> (tempfile::TempDir, u32) {
        let directory = tempfile::tempdir().expect("private Cache fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let uid = fs::metadata(directory.path())
            .expect("directory metadata")
            .uid();
        (directory, uid)
    }

    fn open_gated(directory: &Path, uid: u32, name: &str) -> Journal {
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory, name, JournalLimits::default(), uid)
                .expect("protected Cache journal");
        journal
            .enable_cache_policy_hold_gate(directory, uid)
            .expect("Cache gate");
        journal
    }

    fn put(id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![id],
                vec![id],
            )],
        )
        .expect("test transaction")
    }

    fn hold() -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("Cache hold")
    }

    fn settled_record(released: CachePolicyHoldV1) -> RootV8SuccessorSettlementV1 {
        let mut bytes = [0_u8; 256];
        bytes[..8].copy_from_slice(b"AOSPC88S");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(released.binding().as_bytes());
        bytes[48..56].copy_from_slice(&released.epoch().to_be_bytes());
        bytes[56..64].copy_from_slice(&(released.epoch() + 1).to_be_bytes());
        for (offset, value) in [(64, 6), (96, 7), (160, 8), (192, 9)] {
            bytes[offset..offset + 32].fill(value);
        }
        bytes[128..160].copy_from_slice(released.record_digest().unwrap().as_bytes());
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-successor-settlement.v1\0")
            .chain_update(&bytes[..224])
            .finalize();
        bytes[224..].copy_from_slice(&checksum);
        RootV8SuccessorSettlementV1::from_record_bytes(&bytes)
            .expect("canonical settled Root grant")
    }

    #[test]
    fn cleared_policy_comparison_keeps_exact_release_and_rejects_substitution() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).unwrap();
        let mut writer = open(directory.path(), uid).unwrap();
        writer.acquire_cache_policy_hold_for_writer(hold()).unwrap();
        let released = (hold()).released_data();

        assert!(writer.require_cache_cleared_comparison_data_v1(released).is_err());
        writer.release_held_cache_policy_hold_for_writer(hold()).unwrap();
        writer.require_cache_cleared_comparison_data_v1(released).unwrap();

        let changed = {
            let original = released;
            let changed = CachePolicyHoldV1::new(
                original.project(), original.partition(), original.cache_head(), original.binding(), released.epoch() + 1,
            ).expect("nonzero comparison fields");
            if original.is_held() { changed } else { changed.released_data() }
        };
        assert!(writer.require_cache_cleared_comparison_data_v1(changed).is_err());
        assert!(writer.require_cache_cleared_comparison_data_v1(hold()).is_err());
        assert_eq!(writer.cache_policy_hold_for_writer().unwrap(), Some(released));
    }

    #[test]
    fn cleared_policy_comparison_preserves_pending_v8_refusal() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).unwrap();
        let mut writer = open(directory.path(), uid).unwrap();
        writer.acquire_cache_policy_hold_for_writer(hold()).unwrap();
        writer.release_v8_held_cache_policy_hold_for_writer(hold()).unwrap();
        let released = (hold()).released_data();

        assert!(matches!(writer.require_cache_cleared_comparison_data_v1(released),
            Err(JournalError::ProtectedBoundary)));

        assert!(writer.v8_pending_cache_policy_release_for_writer().is_ok());
    }

    #[cfg(target_os = "linux")]
    fn passive_cache_pair() -> JournalTransaction {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
            association::AcceptedAssociationDataV1,
            cache_held::{CacheHeldBodyDataV1, CacheJournalDataV1, CachePhysicalDataV1,
                CACHE_HELD_RECORD_BYTES_V1},
        };
        let coordinate = CacheJournalDataV1 {
            names: super::super::ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            next: 1, end: 0,
        };
        let body = CacheHeldBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [1; 16], project: [2; 16], sandbox: [3; 16],
                accepted_request: [4; 32], coissuance_binding: [5; 32], seed: [6; 32],
                controller_nonce: [7; 16], boot: [8; 16], started: 9, cutoff: 10,
            },
            source_held: [11; 32], bootstrap: coordinate, hold: coordinate, state: coordinate,
            authority: coordinate, clock: coordinate,
            physical: CachePhysicalDataV1 {
                root: (12, 13), uid: 1000, mode: 0o700, lock: (12, 14), manifest: (0, 0),
                generation: 0, digest: [0; 32], limits: [15; 32],
            },
            selected_partition: [16; 32], selected_head: [17; 32], quota: [18; 32],
            disk_count: 0, negative_count: 0, pin_count: 0, clock_floor: 19,
        };
        let key = KeyV1::new([20; 16], OwnerV1::Cache, 1).unwrap();
        let phase = PhaseV1::new(OwnerV1::Cache, 1).unwrap();
        let mut record = [0; CACHE_HELD_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: [0; 32], correlation: body.association.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        super::super::create_storage_history::prepare_history_pair_v1(key, phase,
            &record, &LatestHeadV1::new(1, checksum).unwrap().encode()).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_cache_pair_fits_exact_native_record_and_transaction_boundaries() {
        let pair = passive_cache_pair();
        let limits = hold_limits();
        assert_eq!(limits.maximum_record_bytes, 998);
        assert_eq!(limits.maximum_transaction_bytes, 1088);
        super::super::validate_transaction(&pair, limits).unwrap();
        for narrowed in [
            JournalLimits { maximum_record_bytes: 997, ..limits },
            JournalLimits { maximum_transaction_bytes: 1087, ..limits },
        ] {
            assert!(super::super::validate_transaction(&pair, narrowed).is_err());
        }
        let shapes = pair.records().iter().map(|record| aos_sandbox_journal::geometry::RecordShape {
            key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
        });
        assert_eq!(aos_sandbox_journal::geometry::encoded_transaction_append_bytes(shapes).unwrap(), 1416);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_native_append_and_replay_keep_history_as_data_and_ordinary_gate_denied() {
        let (directory, uid) = fixture();
        let pair = passive_cache_pair();
        let (mut writer, _) = Journal::open_protected_at_uid(directory.path(), NAME, hold_limits(), uid).unwrap();
        super::super::validate_transaction(&pair, hold_limits()).unwrap();
        let frames = super::super::encode_transaction(&pair, writer.snapshot_sequence()).unwrap();
        let expected = writer.native.expected_append_length_for_fixture(&frames).unwrap();
        // Exercise the genuine native framing/storage/replay engine only.
        // This test-only mechanical write is no J/Cache original or effect
        // admission; the ordinary appender is separately required to refuse.
        assert_eq!(writer.native.append_exact(&frames, expected).unwrap(), 1416);
        drop(writer);

        let (mut replayed, report) = Journal::open_protected_at_uid(directory.path(), NAME, hold_limits(), uid).unwrap();
        assert_eq!(report.committed_transactions, 1);
        for record in pair.records() {
            assert_eq!(replayed.get(record.namespace(), record.key()), record.value());
        }
        assert!(matches!(current_full_state(&mut replayed), Err(JournalError::ProtectedBoundary)));
        assert!(matches!(replayed.commit(&put(89)), Err(JournalError::ProtectedBoundary)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_ordinary_hold_reader_denies_even_malformed_new_history() {
        let (directory, uid) = fixture();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(), NAME, hold_limits(), uid,
        ).unwrap();
        // This is deliberately unvalidated map DATA for a deny-only test. It
        // creates neither a durable record nor a paid actual Held producer.
        journal.native.apply_mutation(aos_sandbox_journal::materialized::RecordMutationRef {
            namespace: RecordNamespace::CreateStorageHistory,
            key: b"foreign", value: Some(b"malformed"),
        });

        assert!(matches!(current_full_state(&mut journal), Err(JournalError::ProtectedBoundary)));
        assert!(matches!(current_state(&mut journal), Err(JournalError::ProtectedBoundary)));
        assert!(matches!(current(&mut journal), Err(JournalError::ProtectedBoundary)));
        assert!(matches!(current_gate_state(&mut journal), Err(JournalError::ProtectedBoundary)));
        assert!(matches!(require_valid_compaction(&mut journal), Err(JournalError::ProtectedBoundary)));
    }

    #[test]
    fn held_cache_cuts_survive_reopen_and_fence_state_and_manifest_writes() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh hold genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut authority = open_gated(directory.path(), uid, "authority.journal");
        state.commit(&put(10)).expect("state before hold");

        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold())
            .expect("durable Cache freeze");
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );
        assert!(matches!(
            state.commit(&put(11)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.commit(&put(12)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            state.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.preflight_transactions(&[put(13)]),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(state);
        drop(authority);

        let mut reopened = open_gated(directory.path(), uid, "state.journal");
        assert!(matches!(
            reopened.commit(&put(14)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).is_err());
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                hold(),
                || Err(JournalError::ProtectedBoundary)
            )
            .is_err()
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );

        let wrong = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch(),
        )
        .expect("different root binding");
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                wrong,
                || Ok(())
            )
            .is_err()
        );
        Journal::release_cache_policy_hold_if_at::<JournalError>(
            directory.path(),
            uid,
            hold(),
            || Ok(()),
        )
        .expect("exact cold release");
        reopened.commit(&put(15)).expect("state after release");
        assert!(
            !Journal::read_cache_policy_hold_at(directory.path(), uid)
                .unwrap()
                .expect("released record")
                .is_held()
        );
    }

    #[test]
    fn retained_admission_denies_active_and_v8_pending_without_changing_ordinary_mutation() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).unwrap();
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let authority = open_gated(directory.path(), uid, "authority.journal");
        let mut gate = open(directory.path(), uid).unwrap();
        gate.acquire_cache_policy_hold_for_writer(hold()).unwrap();
        drop(gate);
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        assert!(state.commit(&put(81)).is_err());

        let mut gate = open(directory.path(), uid).unwrap();
        gate.release_v8_held_cache_policy_hold_for_writer(hold())
            .unwrap();
        drop(gate);
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        state
            .commit(&put(82))
            .expect("ordinary released+pending mutation remains allowed");
    }

    #[test]
    fn retained_writer_releases_only_its_exact_hold_and_replays_the_release() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh hold genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold())
            .expect("durable Cache freeze");

        let mut writer = open(directory.path(), uid).expect("retained hold writer");
        let wrong = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch(),
        )
        .expect("different binding");
        assert!(matches!(
            writer.release_held_cache_policy_hold_for_writer(wrong),
            Err(JournalError::ProtectedBoundary)
        ));
        assert_eq!(writer.held_cache_policy_hold_for_writer().unwrap(), hold());

        let first = writer
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("exact release through retained writer");
        assert!(!first.is_held());
        assert_eq!(first.project(), hold().project());
        assert_eq!(first.partition(), hold().partition());
        assert_eq!(first.cache_head(), hold().cache_head());
        assert_eq!(first.binding(), hold().binding());
        assert_eq!(first.epoch(), hold().epoch());
        assert_ne!(
            first.record_digest().unwrap(),
            hold().record_digest().unwrap()
        );
        assert!(writer.held_cache_policy_hold_for_writer().is_err());
        drop(writer);

        let mut reopened = open(directory.path(), uid).expect("cold retained writer");
        let released = reopened
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("exact cold release replay");
        assert_eq!(released, first);

        let changed = [
            CachePolicyHoldV1::new(
                ProjectId::from_bytes([9; 16]),
                hold().partition(),
                hold().cache_head(),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                ObjectDigest::from_bytes([9; 32]),
                hold().cache_head(),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                ObjectDigest::from_bytes([9; 32]),
                hold().binding(),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                hold().cache_head(),
                ObjectDigest::from_bytes([9; 32]),
                hold().epoch(),
            ),
            CachePolicyHoldV1::new(
                hold().project(),
                hold().partition(),
                hold().cache_head(),
                hold().binding(),
                hold().epoch() + 1,
            ),
        ];
        for mismatched in changed {
            assert!(matches!(
                reopened.release_held_cache_policy_hold_for_writer(mismatched.unwrap()),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert!(matches!(
            reopened.release_held_cache_policy_hold_for_writer(released),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(reopened);

        let replayed = Journal::read_cache_policy_hold_at(directory.path(), uid)
            .expect("cold replay")
            .expect("released record");
        assert_eq!(replayed, released);
        assert_eq!(
            replayed.record_digest().unwrap(),
            first.record_digest().unwrap()
        );
    }

    #[test]
    fn v8_pending_settlement_survives_compaction_and_fences_new_holds() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");

        let mut writer = open(directory.path(), uid).expect("retained Cache writer");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("atomic V8 release");
        assert!(!released.is_held());
        assert_eq!(
            writer
                .release_v8_held_cache_policy_hold_for_writer(hold())
                .expect("exact retained replay"),
            released
        );
        writer.compact().expect("validated compaction");
        drop(writer);

        assert_eq!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid)
                .expect("cold V8 row pair"),
            (hold(), released)
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("ordinary typed readback"),
            Some(released)
        );
        assert!(matches!(
            Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()),
            Err(JournalError::ProtectedBoundary)
        ));

        let mut reopened = open(directory.path(), uid).expect("cold writer");
        assert_eq!(
            reopened
                .release_v8_held_cache_policy_hold_for_writer(hold())
                .expect("cold exact replay"),
            released
        );
        assert!(matches!(
            reopened.release_held_cache_policy_hold_for_writer(hold()),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn cache_acquire_reserves_capacity_for_v8_marker_clear() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");

        let insufficient = JournalLimits {
            maximum_transactions: 3,
            ..hold_limits()
        };
        let (mut writer, _) =
            Journal::open_protected_at_uid(directory.path(), NAME, insufficient, uid)
                .expect("small Cache journal");
        assert!(matches!(
            writer.acquire_cache_policy_hold_for_writer(hold()),
            Err(JournalError::LimitExceeded(_))
        ));
        assert_eq!(writer.cache_policy_hold_for_writer().unwrap(), None);
        drop(writer);

        let exact = JournalLimits {
            maximum_transactions: 4,
            ..hold_limits()
        };
        let (mut writer, _) = Journal::open_protected_at_uid(directory.path(), NAME, exact, uid)
            .expect("four-transaction Cache journal");
        writer
            .acquire_cache_policy_hold_for_writer(hold())
            .expect("acquire reserves release and clear");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("reserved V8 release");
        let grant = settled_record(released);
        assert_eq!(
            writer
                .clear_v8_pending_cache_settlement_from_record(grant)
                .expect("reserved marker clear"),
            released
        );
        assert_eq!(
            writer.cache_policy_hold_for_writer().unwrap(),
            Some(released)
        );
    }

    #[test]
    fn v8_settlement_clears_only_matching_marker_and_replays_after_reopen() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");

        let mut writer = open(directory.path(), uid).expect("retained Cache writer");
        let released = writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("atomic V8 release");
        let grant = settled_record(released);
        let wrong_rows = [
            {
            let original = released;
            let changed = CachePolicyHoldV1::new(
                original.project(), original.partition(), ObjectDigest::from_bytes([9; 32]), original.binding(), original.epoch(),
            ).expect("nonzero comparison fields");
            if original.is_held() { changed } else { changed.released_data() }
        },
            {
            let original = released;
            let changed = CachePolicyHoldV1::new(
                original.project(), original.partition(), original.cache_head(), ObjectDigest::from_bytes([9; 32]), original.epoch(),
            ).expect("nonzero comparison fields");
            if original.is_held() { changed } else { changed.released_data() }
        },
            {
            let original = released;
            let changed = CachePolicyHoldV1::new(
                original.project(), original.partition(), original.cache_head(), original.binding(), released.epoch() + 1,
            ).expect("nonzero comparison fields");
            if original.is_held() { changed } else { changed.released_data() }
        },
        ];
        for wrong in wrong_rows {
            assert!(matches!(
                writer.clear_v8_pending_cache_settlement_from_record(settled_record(wrong)),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert_eq!(
            writer.v8_pending_cache_policy_release_for_writer().unwrap(),
            (hold(), released)
        );

        assert_eq!(
            writer
                .clear_v8_pending_cache_settlement_from_record(grant)
                .expect("Root settlement clears Cache fence"),
            released
        );
        assert!(writer.v8_pending_cache_policy_release_for_writer().is_err());
        assert_eq!(
            writer.cache_policy_hold_for_writer().unwrap(),
            Some(released)
        );
        writer.compact().expect("compaction preserves settled row");
        drop(writer);

        let mut reopened = open(directory.path(), uid).expect("cold Cache writer");
        assert_eq!(
            reopened
                .clear_v8_pending_cache_settlement_from_record(grant)
                .expect("exact cold replay"),
            released
        );
        for wrong in wrong_rows {
            assert!(matches!(
                reopened.clear_v8_pending_cache_settlement_from_record(settled_record(wrong)),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        drop(reopened);

        let next = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([10; 32]),
            hold().epoch() + 1,
        )
        .expect("next Cache hold");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, next)
            .expect("settled marker no longer fences next hold");
        let mut next_writer = open(directory.path(), uid).expect("next retained writer");
        assert!(matches!(
            next_writer.clear_v8_pending_cache_settlement_from_record(grant),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn v8_pending_settlement_rejects_orphan_and_mismatched_rows() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let released = (hold()).released_data();
        let pending =
            CachePolicyV8PendingSettlementV1::new(hold(), released).expect("canonical pending row");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .commit(
                &policy_hold_transaction_data_v1(V8_PENDING_KEY, &pending.encode())
                    .expect("orphan marker"),
            )
            .expect("fixture orphan commit");
        assert!(matches!(
            current_state(&mut writer),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            writer.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(writer);
        assert!(matches!(
            Journal::read_cache_policy_hold_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));

        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("V8 release");
        let mut changed = pending;
        changed.held_digest = ObjectDigest::from_bytes([9; 32]);
        writer
            .commit(
                &policy_hold_transaction_data_v1(V8_PENDING_KEY, &changed.encode())
                    .expect("changed marker"),
            )
            .expect("fixture mismatch commit");
        assert!(matches!(
            current_state(&mut writer),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(writer);
        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn torn_v8_release_retains_held_row_without_pending_marker() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let path = directory.path().join(NAME);
        let before = fs::metadata(&path).expect("held journal length").len();

        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_v8_held_cache_policy_hold_for_writer(hold())
            .expect("complete V8 release fixture");
        drop(writer);
        let after = fs::metadata(&path).expect("release journal length").len();
        assert!(after > before + 8);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open fixture journal")
            .set_len(after - 8)
            .expect("tear final commit frame");

        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("replay torn transaction"),
            Some(hold())
        );
        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn legacy_release_remains_reacquirable_without_v8_marker() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).expect("held cut");
        let mut writer = open(directory.path(), uid).expect("Cache writer");
        writer
            .release_held_cache_policy_hold_for_writer(hold())
            .expect("legacy release");
        drop(writer);

        assert!(matches!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
        let next = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch() + 1,
        )
        .expect("next hold");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, next)
            .expect("legacy released row permits next hold");
    }

    #[test]
    fn missing_hold_custody_never_reinitializes_existing_cache() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        state.commit(&put(20)).expect("Cache history");
        drop(state);
        fs::remove_file(directory.path().join(NAME)).expect("remove fixture hold");

        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            open_gated(directory.path(), uid, "state.journal").commit(&put(21)),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn malformed_hold_custody_fails_before_any_cache_mutation() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut hold_journal = open(directory.path(), uid).expect("hold journal");
        hold_journal
            .commit(
                &policy_hold_transaction_data_v1(HOLD_KEY, b"invalid")
                    .expect("malformed transaction"),
            )
            .expect("fixture corruption");
        drop(hold_journal);

        assert!(matches!(
            state.commit(&put(22)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn cache_commit_waits_for_the_same_lock_used_by_freeze() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let hold_writer = open(directory.path(), uid).expect("held freeze lock");

        assert!(matches!(
            state.commit(&put(30)),
            Err(JournalError::AlreadyLocked)
        ));
        drop(hold_writer);
        state
            .commit(&put(30))
            .expect("commit after freeze lock release");
    }
}
