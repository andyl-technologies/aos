//! Preserves fixed Cache Hold acquisition, release and V8 settlement.
//!
//! Every observation and append uses the same actual private Hold writer and
//! canonical row codecs. Root V8 clearing accepts only the existing genuine
//! Broker grant; rows and matching digests cannot construct that grant.

use std::{fs, io, path::Path};

use aos_sandbox_broker::root_settlement::RootV8SettledGrantV1;
use aos_sandbox_model::{ObjectDigest, ProjectId};
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthFieldsV1, GitCoverageFenceFieldsV1, GitCoverageOwnerKindV1,
};
use aos_sandbox_protocol::cache_state::hold_state::{
    CachePolicyV8PendingSettlementDataV1 as CachePolicyV8PendingSettlementV1,
    CachePolicyHoldStateDataV1 as CachePolicyHoldStateV1,
};
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::{
    cache_state::hold_state::q04_recipes::{
        Q04CacheTerminalPhaseV1, hold_recipe_bodies_data_v1,
    },
    domain_ledger::{
        create_q04_history::Q04CutIdentityV1,
        protected_names::ProtectedJournalNamesV1,
    },
};
use aos_sandbox_protocol::root_settlement::RootV8SuccessorSettlementV1;
use sha2::{Digest as _, Sha256};
use aos_sandbox_ledger_replay::git_coverage_prefix::cache::policy_hold_transaction_data_v1;

use super::{NAME, hold_limits};
use super::state::{CacheGitCoverageObservationV1, CachePolicyGateStateV1, current, current_gate_state, current_full_state, current_state};
use super::super::{Journal, JournalError, JournalRecord, JournalTransaction, ReadOnlyProtectedJournal, RecordNamespace};

const GENESIS_KEY: &[u8] = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_GENESIS_KEY_V1;
const GENESIS: &[u8] = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_GENESIS_V1;
const HOLD_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::HOLD_KEY;
const V8_PENDING_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::V8_PENDING_KEY;
const GIT_BIRTH_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::GIT_BIRTH_KEY;
const GIT_FENCE_KEY: &[u8] = aos_sandbox_protocol::cache_state::hold_state::GIT_FENCE_KEY;
const V8_RELEASE_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-release.v1\0";
const V8_SETTLEMENT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-settlement.v1\0";
const V8_SETTLEMENT_PREFLIGHT_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-v8-settlement-preflight.v1\0";

fn open(directory: &Path, uid: u32) -> Result<Journal, JournalError> {
    Journal::open_cache_hold_ordinary_v1(directory, uid)
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
            .map_err(|_| JournalError::boundary())?,
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
            .map_err(|_| JournalError::boundary())?,
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
            .map_err(|_| JournalError::boundary())?,
        vec![JournalRecord::delete(
            RecordNamespace::DesiredState,
            V8_PENDING_KEY.to_vec(),
        )],
    ).map_err(JournalError::from)
}

fn v8_released_pair(
    state: CachePolicyHoldStateV1,
) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
    let released = state.hold.ok_or(JournalError::boundary())?;
    let pending = state.v8_pending.ok_or(JournalError::boundary())?;
    pending.validate_for(released)?;
    Ok((
        (released).held_data(),
        released,
    ))
}

pub(crate) fn initialize_fresh(directory: &Path, uid: u32) -> Result<(), JournalError> {
    let hold_path = directory.join(NAME);
    let existing = match fs::symlink_metadata(&hold_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(JournalError::from(error)),
    };
    if !existing {
        for name in ["state.journal", "authority.journal", "clock.journal"] {
            for suffix in ["", ".lock", ".compact.tmp"] {
                match fs::symlink_metadata(directory.join(format!("{name}{suffix}"))) {
                    Ok(_) => return Err(JournalError::boundary()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(JournalError::from(error)),
                }
            }
        }
    }
    let mut journal = open(directory, uid)?;
    if journal.all_records().next().is_none() && !existing {
        journal.commit(&policy_hold_transaction_data_v1(GENESIS_KEY, GENESIS).map_err(JournalError::from)?)?;
    }
    current(&mut journal)?;
    Ok(())
}

impl Journal {
    pub(crate) fn cache_git_coverage_observation_for_writer_v1(
        &mut self,
    ) -> Result<Option<CacheGitCoverageObservationV1>, JournalError> {
        if self.read_view().protected_view().map(|location| location.name()) != Some(NAME) {
            return Err(JournalError::boundary());
        }
        self.require_protected_names_current()?;
        match current_gate_state(self)? {
            CachePolicyGateStateV1::Ordinary(state) => {
                if state.hold.is_some() || state.v8_pending.is_some() {
                    return Err(JournalError::boundary());
                }
                Ok(None)
            }
            CachePolicyGateStateV1::Exclusive(observed) => Ok(Some(observed)),
        }
    }

    pub(crate) fn prepare_cache_git_coverage_append_v1(
        &mut self,
        birth: GitCoverageBirthFieldsV1,
        fence: GitCoverageFenceFieldsV1,
    ) -> Result<JournalTransaction, JournalError> {
        if self.cache_git_coverage_observation_for_writer_v1()?.is_some() {
            return Err(JournalError::boundary());
        }
        let mut native = self.cache_coverage_native_prefix_v1()
            .map_err(|error| JournalError::NativePrefix(Box::new(error)))?;
        if native.counts() != (1, 1)
            || birth.owner != GitCoverageOwnerKindV1::CacheAuthority
            || birth.predecessor_prefix != native.prefix_digest()
            || fence.predecessor_prefix != native.prefix_digest()
            || birth.commit_sequence != self.snapshot_sequence().checked_add(3)
                .ok_or(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::SequenceExhausted)?
        {
            return Err(JournalError::boundary());
        }
        native.recheck()?;
        drop(native);

        let birth_bytes = birth.encode().map_err(|_| JournalError::boundary())?;
        let fence_bytes = fence.encode().map_err(|_| JournalError::boundary())?;
        let transaction = JournalTransaction::new(
            birth.transaction,
            vec![
                JournalRecord::put(RecordNamespace::DesiredState,
                    GIT_BIRTH_KEY.to_vec(), birth_bytes.to_vec()),
                JournalRecord::put(RecordNamespace::DesiredState,
                    GIT_FENCE_KEY.to_vec(), fence_bytes.to_vec()),
            ],
        )?;
        aos_sandbox_ledger_replay::git_coverage_prefix::cache::require_policy_native_transaction_v1(
            1, &transaction, birth.commit_sequence, birth.predecessor_prefix,
        )?;
        Ok(transaction)
    }

    pub(crate) fn require_q04_cache_prepare_v1(
        &self,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        let uid = self.protected_owner_uid()?;
        self.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT), NAME, uid, hold_limits(),
        )?;
        let state = aos_sandbox_protocol::cache_state::hold_state::decode_full_state(self.read_view().state().iter().map(|((namespace, key), value)| {
            (*namespace, key.as_slice(), value.as_slice())
        }).filter_map(|(namespace, key, value)| {
            (namespace == RecordNamespace::DesiredState).then_some((key, value))
        }))?;
        if self.read_view().state().keys().any(|(namespace, _)| *namespace != RecordNamespace::DesiredState)
            || state.legacy.hold.is_some_and(CachePolicyHoldV1::is_held)
            || state.legacy.v8_pending.is_some()
            || state.q04_pending.is_some()
        {
            return Err(JournalError::boundary());
        }
        Ok(state.legacy.hold)
    }

    pub(crate) fn held_cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        self.cache_policy_hold_for_writer()?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::boundary())
    }

    pub(crate) fn require_cache_cleared_comparison_data_v1(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        let current = current_state(self)?;
        if expected.is_held() || current.hold != Some(expected) || current.v8_pending.is_some() {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        Ok(self.cache_policy_hold_state_for_writer()?.hold)
    }

    pub(crate) fn v8_pending_cache_policy_release_for_writer(
        &mut self,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1), JournalError> {
        v8_released_pair(self.cache_policy_hold_state_for_writer()?)
    }

    pub(crate) fn v8_cache_policy_settlement_state_for_writer(
        &mut self,
        grant: RootV8SettledGrantV1,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1, bool), JournalError> {
        self.v8_cache_policy_settlement_state_from_record(grant.record_data())
    }

    fn v8_cache_policy_settlement_state_from_record(
        &mut self,
        grant: RootV8SuccessorSettlementV1,
    ) -> Result<(CachePolicyHoldV1, CachePolicyHoldV1, bool), JournalError> {
        let state = self.cache_policy_hold_state_for_writer()?;
        let released = state.hold.ok_or(JournalError::boundary())?;
        if released.is_held()
            || released.binding() != grant.predecessor()
            || released.epoch() != grant.epoch()
            || released.record_digest()? != grant.cache_released()
        {
            return Err(JournalError::boundary());
        }

        let held = (released).held_data();
        Ok((held, released, state.v8_pending.is_some()))
    }

    pub(crate) fn clear_v8_pending_cache_settlement_for_writer(
        &mut self,
        grant: RootV8SettledGrantV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        self.clear_v8_pending_cache_settlement_from_record(grant.record_data())
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
            return Err(JournalError::boundary());
        }
        Ok(readback)
    }

    fn cache_policy_hold_state_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldStateV1, JournalError> {
        let location = self
            .read_view().protected_view()
            .ok_or(JournalError::boundary())?;
        if location.name() != NAME {
            return Err(JournalError::boundary());
        }
        self.require_protected_names_current()?;
        current_state(self)
    }

    pub(crate) fn initialize_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        initialize_fresh(directory, uid)
    }

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
            return Err(JournalError::boundary());
        }
        let mut journal = open(directory, uid)?;
        journal.acquire_cache_policy_hold_for_writer(hold)
    }

    fn acquire_cache_policy_hold_for_writer(
        &mut self,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.is_held() {
            return Err(JournalError::boundary());
        }
        let state = self.cache_policy_hold_state_for_writer()?;
        if state.hold.is_some_and(CachePolicyHoldV1::is_held) || state.v8_pending.is_some() {
            return Err(JournalError::boundary());
        }
        let acquire = policy_hold_transaction_data_v1(HOLD_KEY, &hold.encode()?).map_err(JournalError::from)?;
        let released = (hold).released_data();
        let legacy_release = policy_hold_transaction_data_v1(HOLD_KEY, &released.encode()?).map_err(JournalError::from)?;
        let v8_pending = CachePolicyV8PendingSettlementV1::new(hold, released)?;
        let v8_release = v8_release_transaction(released, v8_pending)?;
        let v8_clear = v8_settlement_preflight_transaction(released)?;
        self.preflight_transactions(&[acquire.clone(), legacy_release])?;
        // The pending marker must be clearable without depending on future
        // compaction, even when this acquire reaches the journal capacity edge.
        self.preflight_transactions(&[acquire.clone(), v8_release, v8_clear])?;
        self.commit(&acquire)?;
        if current(self)? != Some(hold) {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn release_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::boundary());
        }

        let released = (expected).released_data();
        match self.cache_policy_hold_state_for_writer()? {
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == expected => {
                self.commit(&policy_hold_transaction_data_v1(HOLD_KEY, &released.encode()?).map_err(JournalError::from)?)?;
            }
            CachePolicyHoldStateV1 {
                hold: Some(current),
                v8_pending: None,
            } if current == released => {}
            _ => return Err(JournalError::boundary()),
        }

        let readback = self
            .cache_policy_hold_for_writer()?
            .ok_or(JournalError::boundary())?;
        if readback != released {
            return Err(JournalError::boundary());
        }
        Ok(readback)
    }

    pub(crate) fn release_v8_held_cache_policy_hold_for_writer(
        &mut self,
        expected: CachePolicyHoldV1,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        if !expected.is_held() {
            return Err(JournalError::boundary());
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
            _ => return Err(JournalError::boundary()),
        }

        let (held_readback, released_readback) =
            v8_released_pair(self.cache_policy_hold_state_for_writer()?)?;
        if held_readback != expected || released_readback != released {
            return Err(JournalError::boundary());
        }
        Ok(released_readback)
    }
}

impl Journal {
    pub(crate) fn require_no_cache_held_history_v1(&self) -> Result<(), JournalError> {
        if self.records(RecordNamespace::CreateStorageHistory).next().is_some() {
            return Err(JournalError::boundary());
        }
        Ok(())
    }
}

impl ReadOnlyProtectedJournal {
    // Compares the actual same-reader terminal suffix. The request supplies
    // historical coordinates only; no writer, phase or grant is adopted.
    #[cfg(target_os = "linux")]
    pub(crate) fn q04_terminal_cache_policy_hold(
        &mut self,
        identity: &Q04CutIdentityV1,
        phase: Q04CacheTerminalPhaseV1,
        original_names: ProtectedJournalNamesV1,
        original_next: u64,
        held: CachePolicyHoldV1,
        release_authorization: ObjectDigest,
    ) -> Result<CachePolicyHoldV1, crate::error::CacheQ04ErrorV1> {
        use crate::error::CacheQ04ErrorV1;

        if self.witness.name() != NAME || self.physical_names_v1() != original_names
            || matches!(phase, Q04CacheTerminalPhaseV1::Held)
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        self.check_named_currentness()?;
        let bodies = hold_recipe_bodies_data_v1(identity, original_names, held, release_authorization)?;
        let current = current_full_state(&mut self.journal)?;
        let released = (held).released_data();
        if current.legacy.v8_pending.is_some() || current.legacy.hold != Some(released)
            || match phase {
                Q04CacheTerminalPhaseV1::Released => {
                    current.q04_pending.as_ref() != Some(&bodies.released_marker)
                }
                Q04CacheTerminalPhaseV1::Cleared => current.q04_pending.is_some(),
                Q04CacheTerminalPhaseV1::Held => true,
            }
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        self.journal.require_q04_native_recipe_prefix_v1(
            &bodies.transactions[..phase.prefix()], original_next,
        )?;
        self.check_named_currentness()?;
        Ok(released)
    }

    pub(crate) fn held_cache_policy_hold(&mut self) -> Result<CachePolicyHoldV1, JournalError> {
        if self.witness.name() != NAME {
            return Err(JournalError::boundary());
        }
        current(&mut self.journal)?.filter(|hold| hold.is_held()).ok_or(JournalError::boundary())
    }
}

/// Retains the actual Hold writer through one existing finite observation.
pub(crate) struct HeldCachePolicyObservationV1<'path> {
    journal: Journal,
    expected: CachePolicyHoldV1,
    directory: &'path Path,
    uid: u32,
}

impl<'path> HeldCachePolicyObservationV1<'path> {
    pub(crate) fn capture_v1(directory: &'path Path, uid: u32, expected: CachePolicyHoldV1) -> Result<Self, JournalError> {
        let mut journal = open(directory, uid)?;
        if !expected.is_held() || current(&mut journal)? != Some(expected) {
            return Err(JournalError::boundary());
        }
        Ok(Self { journal, expected, directory, uid })
    }

    // The fixed upper coordinator runs its existing Root verification while
    // this SAME writer remains held. This consumes only Cache's actual writer;
    // it does not construct or attest a Root decision or financial capability.
    pub(crate) fn release_v1(mut self) -> Result<(), JournalError> {
        let released = self.expected.released_data();
        self.journal.commit(&policy_hold_transaction_data_v1(HOLD_KEY, &released.encode()?).map_err(JournalError::from)?)?;
        if current(&mut self.journal)? != Some(released) {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn recheck_v1(&mut self) -> Result<(), JournalError> {
        if current(&mut self.journal)? != Some(self.expected) {
            return Err(JournalError::boundary());
        }
        #[cfg(test)]
        self.journal.require_protected_names_current()?;
        #[cfg(not(test))]
        self.journal.require_protected_named_location(&self.directory, NAME, self.uid, hold_limits())?;
        Ok(())
    }
}
