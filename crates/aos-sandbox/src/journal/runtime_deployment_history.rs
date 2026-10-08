//! Closed observational audit of the original Host055 native journal history.
//!
//! The sole Journal parser calls this observer after validating each COMMIT.
//! Ordinary audit retains only a count and previous ten-byte phase key. The
//! genuine pair bridge may also retain bounded authenticated native TXs, never
//! full-map prefixes, a second materializer or phase reducer. The held writer
//! is reread with independent offsets and checked against its complete original
//! snapshot. Success establishes neither fresh NV nor live specimen custody.

#[cfg(test)]
use std::borrow::Borrow;
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub(super) use aos_sandbox_journal::storage::CapturedFileCursor as ReadAtCursorV1;

use aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1;
use aos_sandbox_protocol::runtime_deployment::canary::CanaryPurposeV2;
use ed25519_dalek::VerifyingKey;

use crate::runtime_deployment::{
    GENESIS_KEY, MAIN_DIRECTORY_V1, MAIN_LIMITS, MAIN_NAME, NAMESPACE,
    SIDECAR_NAME, VerifiedDeploymentGenesisV1, genesis_native_transaction_v1,
    require_deployment_row_bound_v1, require_native_step_binding_v1,
    require_native_canary_binding_v2,
};

use super::{
    BTreeMap, FileIdentity, Journal, JournalError, JournalTransaction,
    RecordNamespace, ReplayState, replay_observed,
};
use super::runtime_deployment_sidecar_history::RetainedDeploymentNativeHistoryV1;

/// Selects observation of this fixed main writer, never a caller-supplied policy.
#[derive(Clone, Copy)]
enum MainHistoryObservationV1 {
    AuditOnly,
    RetainNative,
}

impl Journal {
    /// Compares selected main COMMIT DATA through the same original replay.
    pub(crate) fn compare_canary_main_commit_v2(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        transaction: &JournalTransaction,
        returned: &super::CommitResult,
    ) -> Result<(), JournalError> {
        self.compare_canary_commit_inner_v2(owner, transaction, returned, CanaryCommitMemberV2::Main)
    }

    /// Compares selected sidecar COMMIT DATA through the same original replay.
    pub(crate) fn compare_canary_sidecar_commit_v2(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        transaction: &JournalTransaction,
        returned: &super::CommitResult,
    ) -> Result<(), JournalError> {
        self.compare_canary_commit_inner_v2(owner, transaction, returned, CanaryCommitMemberV2::Sidecar)
    }

    fn compare_canary_commit_inner_v2(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        transaction: &JournalTransaction,
        returned: &super::CommitResult,
        member: CanaryCommitMemberV2,
    ) -> Result<(), JournalError> {
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)?;
        if owner.canary_purpose().is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        let before = FileIdentity::of(self.native.file())?;
        let history = match member {
            CanaryCommitMemberV2::Main => self.capture_runtime_deployment_main_history_v1(owner)?,
            CanaryCommitMemberV2::Sidecar => self.capture_runtime_deployment_sidecar_history_v1(owner)?,
        };
        let last = history.transactions().last().ok_or(JournalError::ProtectedBoundary)?;
        let distance = u64::try_from(transaction.records().len()).ok()
            .and_then(|records| records.checked_add(1)).ok_or(JournalError::SequenceExhausted)?;
        if last.transaction() != transaction || last.commit_sequence() != returned.commit_sequence
            || last.begin_sequence().checked_add(distance) != Some(returned.commit_sequence)
            || returned.commit_sequence.checked_add(1) != Some(last.next_sequence())
            || last.next_sequence() != self.native.next_sequence() || returned.durable_bytes != before.size
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        // The capture above uses the sole ReadAt/native framing engine and
        // checks the complete replayed physical end against this SAME File.
        // No reopened File, second parser or caller-reconstructed cut is used.
        if FileIdentity::of(self.native.file())? != before {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)
    }

    /// Retains bounded native transactions under the unchanged main audit.
    pub(crate) fn capture_runtime_deployment_main_history_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<RetainedDeploymentNativeHistoryV1, JournalError> {
        // RetainNative can return success only with its finished collector.
        self.observe_runtime_deployment_main_history_v1(
            owner,
            MainHistoryObservationV1::RetainNative,
        )?
        .ok_or(JournalError::ProtectedBoundary)
    }

    /// Audits actual native associations on this original fixed main writer.
    ///
    /// The common physical owner must invoke the enclosing original-main guard
    /// on cold recovery and before prepare, NV extension and main commit. A
    /// materialized-map schema check alone cannot substitute for this audit.
    ///
    /// # Errors
    ///
    /// Rejects origin/name drift, wrong limits, historical row/UUID/order
    /// differences, incomplete tails or a change to the held physical cut.
    pub(crate) fn require_runtime_deployment_native_history_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<(), JournalError> {
        self.observe_runtime_deployment_main_history_v1(
            owner,
            MainHistoryObservationV1::AuditOnly,
        )
        .map(|_| ())
    }

    // Both closed modes observe the same original writer and physical cut.
    // AuditOnly must not allocate a collector or add the pair's extra checks.
    fn observe_runtime_deployment_main_history_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        observation: MainHistoryObservationV1,
    ) -> Result<Option<RetainedDeploymentNativeHistoryV1>, JournalError> {
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)?;
        let limits = owner.main_limits();
        self.require_protected_named_location(
            Path::new(MAIN_DIRECTORY_V1), MAIN_NAME, 0, limits,
        )?;
        require_deployment_row_bound_v1(self.native.state().len())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if self.native.committed_transactions() > limits.maximum_transactions {
            return Err(JournalError::LimitExceeded("deployment native transactions"));
        }

        let witness = self.protected_writer_name_witness()?;
        let physical = FileIdentity::of(self.native.file())?;
        if physical.size > limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }

        let result = (|| {
            let mut history = if owner.canary_purpose().is_some() {
                HistoryAuditV1::from_canary_bindings(self.native.state(), owner)?
            } else { HistoryAuditV1::from_bindings(
                self.native.state(),
                owner.exact_bytes(),
                owner.claims(),
                owner.publisher_verifier(),
            )? };
            if matches!(observation, MainHistoryObservationV1::RetainNative) {
                history.retained = Some(RetainedDeploymentNativeHistoryV1::new(physical.size)?);
            }

            let mut reader = ReadAtCursorV1::new(self.native.file(), physical.size);
            let replayed = replay_observed(&mut reader, limits, Some(&mut history))?;
            history.finish(&replayed)?;
            self.require_deployment_replayed_snapshot(&replayed, physical.size)?;

            match observation {
                MainHistoryObservationV1::AuditOnly => Ok(None),
                MainHistoryObservationV1::RetainNative => {
                    self.require_deployment_pair_replayed_snapshot_v1(&replayed, physical.size)?;
                    let retained = history.retained.take()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    retained.finish(&replayed)?;
                    Ok(Some(retained))
                }
            }
        })();

        // Recheck even after a failed parse/copy. No pathname is reopened, and no
        // seek on the append writer's shared open-file description occurs.
        self.require_protected_named_location(
            Path::new(MAIN_DIRECTORY_V1), MAIN_NAME, 0, limits,
        )?;
        self.validate_protected_writer_name_witness(&witness)?;
        if FileIdentity::of(self.native.file())? != physical {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)?;
        result
    }

    fn require_deployment_replayed_snapshot(
        &self,
        replayed: &ReplayState,
        physical_length: u64,
    ) -> Result<(), JournalError> {
        if replayed.durable_end != physical_length
            || replayed.next_sequence != self.native.next_sequence()
            || replayed.committed_transactions != self.native.committed_transactions()
            || replayed.committed_records != self.native.committed_transactions()
            || replayed.transaction_ids != *self.native.transaction_ids()
            || replayed.committed_namespaces != *self.native.committed_namespaces()
            || replayed.state != *self.native.state()
            || replayed.materialized_bytes != self.native.materialized_bytes()
            || replayed.idempotency != self.idempotency
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CanaryCommitMemberV2 {
    Main,
    Sidecar,
}

/// Retains an original-opener denial without granting path or currentness authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum OriginalCompactionSelectionV1 {
    /// Keeps every unrelated protected journal's existing compaction behavior.
    Other,
    /// Denies compaction of the original fixed deployment main, including orphans.
    DeploymentMain,
    /// Denies compaction of the original fixed deployment sidecar.
    DeploymentSidecar,
}

impl OriginalCompactionSelectionV1 {
    // Called only after the original protected opener has validated its actual
    // directory and named file. It is not a public flag or a currentness token.
    pub(super) fn capture(directory_path: &Path, name: &str) -> Self {
        if directory_path == Path::new(MAIN_DIRECTORY_V1) && name == MAIN_NAME {
            Self::DeploymentMain
        } else if directory_path == Path::new(MAIN_DIRECTORY_V1) && name == SIDECAR_NAME {
            Self::DeploymentSidecar
        } else {
            Self::Other
        }
    }
}

/// Refuses this closed original contract before any compaction write or rename.
///
/// This is defense in depth, not proof of an unmodified cold history. Other
/// Host catalogs are neither selected by namespace nor required to resolve the
/// deployment directory. Protected writers retain a basename, so their denial
/// is captured from the actual original opener rather than that basename.
pub(super) fn require_no_compaction(journal: &Journal) -> Result<(), JournalError> {
    if *journal.native.path() == Path::new(MAIN_DIRECTORY_V1).join(MAIN_NAME)
        || *journal.native.path() == Path::new(MAIN_DIRECTORY_V1).join(SIDECAR_NAME)
        || journal.protected.as_ref().is_some_and(|location| {
            matches!(
                location.original_compaction_selection,
                OriginalCompactionSelectionV1::DeploymentMain
                    | OriginalCompactionSelectionV1::DeploymentSidecar,
            )
        })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn deployment_original_compaction_selected_for_test(
    directory: &Path,
    name: &str,
) -> bool {
    OriginalCompactionSelectionV1::capture(directory, name) != OriginalCompactionSelectionV1::Other
}

pub(super) struct HistoryAuditV1<'data> {
    expected: &'data BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    exact_genesis: &'data [u8],
    genesis: &'data DeploymentGenesisV1,
    signer: VerifyingKey,
    genesis_transaction: [u8; 16],
    genesis_key: &'static [u8],
    limits: super::JournalLimits,
    canary_purpose: Option<&'data CanaryPurposeV2>,
    commits: usize,
    last_phase_key: Option<[u8; 10]>,
    retained: Option<RetainedDeploymentNativeHistoryV1>,
}

impl<'data> HistoryAuditV1<'data> {
    // Pure private observation inputs are not an origin/floor factory. Only
    // the actual writer entry point above supplies genuine admitted bindings.
    fn from_bindings(
        expected: &'data BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        exact_genesis: &'data [u8],
        genesis: &'data DeploymentGenesisV1,
        signer: VerifyingKey,
    ) -> Result<Self, JournalError> {
        require_deployment_row_bound_v1(expected.len())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let genesis_transaction = genesis_native_transaction_v1(exact_genesis)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(Self {
            expected,
            exact_genesis,
            genesis,
            signer,
            genesis_transaction,
            genesis_key: GENESIS_KEY,
            limits: MAIN_LIMITS,
            canary_purpose: None,
            commits: 0,
            last_phase_key: None,
            retained: None,
        })
    }

    /// Supplies selected DATA only from the same actual original owner.
    fn from_canary_bindings(
        expected: &'data BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        owner: &'data VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<Self, JournalError> {
        let limits = owner.main_limits();
        if expected.is_empty() || expected.len() > limits.maximum_materialized_records {
            return Err(JournalError::ProtectedBoundary);
        }
        let purpose = owner.canary_purpose().ok_or(JournalError::ProtectedBoundary)?;
        Ok(Self {
            expected,
            exact_genesis: owner.exact_bytes(),
            genesis: owner.claims(),
            signer: owner.publisher_verifier(),
            genesis_transaction: owner.native_genesis_transaction()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            genesis_key: owner.main_key(),
            limits,
            canary_purpose: Some(purpose),
            commits: 0,
            last_phase_key: None,
            retained: None,
        })
    }

    /// Checks one transaction supplied only by the existing validated COMMIT.
    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
    ) -> Result<(), JournalError> {
        let next_commits = self.commits
            .checked_add(1)
            .ok_or(JournalError::LimitExceeded("deployment native transactions"))?;
        if next_commits > self.limits.maximum_transactions
            || transaction.records().len() != 1
            || begin_sequence.checked_add(2) != Some(commit_sequence)
            || &transaction.id()[8..] == b"compact1"
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let record = &transaction.records()[0];
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        let expected_value = self.expected
            .get(&(NAMESPACE, record.key().to_vec()))
            .map(Vec::as_slice);
        if record.namespace() != NAMESPACE
            || expected_value != Some(value)
        {
            return Err(JournalError::ProtectedBoundary);
        }

        if self.commits == 0 {
            if begin_sequence != 1
                || commit_sequence != 3
                || record.key() != self.genesis_key
                || value != self.exact_genesis
                || *transaction.id() != self.genesis_transaction
            {
                return Err(JournalError::ProtectedBoundary);
            }
        } else {
            let key: [u8; 10] = record.key()
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if record.key() == self.genesis_key
                || self.last_phase_key.is_some_and(|previous| previous >= key)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            if let Some(purpose) = self.canary_purpose {
                require_native_canary_binding_v2(
                    &key, value, self.exact_genesis, self.genesis, self.signer, purpose,
                    *transaction.id(), begin_sequence,
                ).map_err(|_| JournalError::ProtectedBoundary)?;
            } else { require_native_step_binding_v1(
                &key, value, self.genesis, self.signer, *transaction.id(), begin_sequence,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?; }
            self.last_phase_key = Some(key);
        }

        if let Some(retained) = &mut self.retained {
            retained.observe(transaction, begin_sequence, commit_sequence)?;
        }
        self.commits = next_commits;
        Ok(())
    }

    fn finish(&self, replayed: &ReplayState) -> Result<(), JournalError> {
        if self.commits != self.expected.len()
            || self.commits != replayed.committed_transactions
            || self.commits != replayed.committed_records
            || replayed.state != *self.expected
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
