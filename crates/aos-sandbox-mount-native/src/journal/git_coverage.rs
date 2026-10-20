//! Rechecks Mount's fixed catalog through its actual held native prefix.
//!
//! The shared canonical cursor and full semantic driver observe every COMMIT
//! and EOF. The private loan retains the original Mount borrow and held-name
//! witness; catalog/hash DATA cannot construct it or authorize an append.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryRereadOriginalV1, coordinator::indexed_replay::CanonicalIndexedReplayErrorV1,
};
use aos_sandbox_broker::systemd_credentials::GitCoverageCredentialCustodyV1;
use aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1;
use aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness;
use aos_sandbox_ledger_replay::cold::{
    ColdReplayOriginalV1, git_prefix::MountGitPrefixReplayDataV1,
};
use aos_sandbox_ledger_replay::git_coverage_prefix::{
    has_durable_owner_fence_v1, provision_origin_digest_v1,
};

use super::*;

/// Keeps the actual first prefix refusal and independently reached bookend.
#[derive(Debug, thiserror::Error)]
#[error("Mount's original Git coverage history was refused: {first}")]
pub struct GitCoverageNativeHistoryErrorV1 {
    #[source]
    first: JournalError,
    final_bookend: Option<JournalError>,
}

impl GitCoverageNativeHistoryErrorV1 {
    /// Borrows the actual first prefix or bookend refusal.
    #[must_use]
    pub fn first(&self) -> &JournalError {
        &self.first
    }

    /// Borrows the independently reached final refusal, when one also failed.
    #[must_use]
    pub fn final_bookend(&self) -> Option<&JournalError> {
        self.final_bookend.as_ref()
    }
}

/// Retains an immutable original writer borrow and its actual physical witness.
pub struct GitCoverageNativePrefixLoanV1<'journal> {
    journal: &'journal MountJournalV1,
    witness: ProtectedWriterNameWitness,
    prefix: [u8; 32],
    transactions: usize,
    records: usize,
    last_commit: Option<([u8; 16], u64)>,
    ended: bool,
}

impl GitCoverageNativePrefixLoanV1<'_> {
    /// Returns the complete canonical prefix commitment as historical DATA.
    #[must_use]
    pub fn prefix_digest(&self) -> [u8; 32] {
        self.prefix
    }

    /// Commits the original name and three actual retained inode identities.
    #[must_use]
    pub fn provision_origin_digest(&self) -> [u8; 32] {
        provision_origin(self.journal, &self.witness)
    }

    /// Returns actual observed transaction and record counts rather than limits.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.transactions, self.records)
    }

    /// Returns the last actual transaction and COMMIT sequence, if present.
    #[must_use]
    pub fn last_commit(&self) -> Option<([u8; 16], u64)> {
        self.last_commit
    }

    /// Rechecks the same original native writer and held names while borrowed.
    ///
    /// # Errors
    /// Refuses a repeated failed recheck, poison, changed name or changed file.
    pub fn recheck(&mut self) -> Result<(), JournalError> {
        if self.ended {
            return Err(MechanicalError::StaleAuthoritySnapshot.into());
        }
        self.ended = true;
        require_bookend(self.journal, &self.witness)?;
        self.ended = false;
        Ok(())
    }
}

impl MountJournalV1 {
    pub(super) fn require_mount_git_transition_v1(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let durable = has_durable_owner_fence_v1(state);
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
            && (self.mount_git_coverage_denied || durable)
        {
            if durable {
                return Err(MechanicalError::ProtectedBoundary.into());
            }
            aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(
                transaction,
                self.native.read_view_v1().limits(),
            )?;
            aos_sandbox_ledger_replay::git_coverage_prefix::require_mount_original_source_cleanup_v1(
                state, transaction,
            )?;
        }
        // The fixed Mount first-profile fence admits no later mutation. The
        // independent Session outcome writer is a different native owner.
        if durable {
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    /// Retains the same fixed Mount recipe's monotone denial of new work.
    ///
    /// The credential reservoir may be partial or failed. This denial supplies
    /// neither successful enrollment nor native coverage or allocation proof.
    /// # Errors
    /// Refuses another recipe or unsafe/replaced original Mount storage.
    pub fn retain_mount_git_coverage_denial_v1(
        &mut self,
        inputs: &GitCoverageCredentialCustodyV1,
    ) -> Result<(), JournalError> {
        if !inputs.retains_mount_recipe_v1() {
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        self.mount_git_coverage_denied = true;
        self.validate_held_root_owned_at("/var/lib/aos/sandbox-mount", "mount.journal")
    }

    /// Reports only this original writer's monotone refusal disposition.
    #[must_use]
    pub fn mount_git_coverage_denies_new_v1(&self) -> bool {
        self.mount_git_coverage_denied
            || has_durable_owner_fence_v1(self.native.read_view_v1().state())
    }

    /// Compares the fixed catalog with every actual COMMIT and native EOF.
    ///
    /// Only this same fixed protected writer can lend the resulting native
    /// borrow. The signed catalog remains DATA; current role and policy checks
    /// and funding remain independently required by their actual callers.
    /// # Errors
    /// Preserves the first parser, semantic, catalog or physical refusal and
    /// independently attempts the final native bookend after entered replay.
    pub fn mount_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        let capture = (|| {
            self.validate_held_root_owned_at("/var/lib/aos/sandbox-mount", "mount.journal")?;
            self.require_protected_names_current()?;
            self.protected_writer_name_witness()
        })();
        let witness = capture.map_err(|first| GitCoverageNativeHistoryErrorV1 {
            first,
            final_bookend: None,
        })?;

        let result = self.compare_git_prefix(catalog, &witness);
        let bookend = require_bookend(self, &witness);
        let (prefix, transactions, records, last_commit) = match (result, bookend) {
            (Ok(data), Ok(())) => data,
            (Err(first), final_bookend) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first,
                    final_bookend: final_bookend.err(),
                });
            }
            (Ok(_), Err(first)) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first,
                    final_bookend: None,
                });
            }
        };
        Ok(GitCoverageNativePrefixLoanV1 {
            journal: self,
            witness,
            prefix,
            transactions,
            records,
            last_commit,
            ended: false,
        })
    }

    fn compare_git_prefix<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
        witness: &ProtectedWriterNameWitness,
    ) -> Result<([u8; 32], usize, usize, Option<([u8; 16], u64)>), JournalError> {
        let mut comparison = MountGitPrefixReplayDataV1::new(catalog)?;
        let mut native = CanonicalOrdinaryRereadOriginalV1::new();
        let mut semantic = ColdReplayOriginalV1::new();
        let result = (|| {
            let (identity, mut cursor) = self
                .native
                .begin_captured_ordinary_reread_once_v1(&mut native, witness.file().byte_len())?;
            semantic
                .observe_indexed_with_mount_git_prefix_once_v1(
                    &mut cursor,
                    identity,
                    self.native.read_view_v1().limits(),
                    &mut comparison,
                )
                .map_err(|_| JournalError::from(MechanicalError::ProtectedBoundary))?;
            drop(cursor);
            if !native.matches_held_data_v1(&self.native)
                || native.completed_end_data_v1() != Some(witness.file().byte_len())
            {
                return Err(MechanicalError::StaleAuthoritySnapshot.into());
            }
            let remainder = semantic
                .take_remainder_once()
                .ok_or(MechanicalError::ProtectedBoundary)?;
            if remainder.history_compacted
                || remainder.q04_lower_history_present != self.semantic.q04_lower_history_present
            {
                return Err(MechanicalError::StaleAuthoritySnapshot.into());
            }
            comparison.require_origin_v1(provision_origin(self, witness))?;
            let prefix = comparison.prefix_data_v1();
            let (transactions, records) = prefix.counts_v1();
            Ok((
                prefix.prefix_digest_v1(),
                transactions,
                records,
                prefix.last_commit_v1(),
            ))
        })();

        let comparison_selected = semantic.mount_git_prefix_failure_is_selected_v1();
        // Ordinary prospective/current/upper/pending/index/native disposal
        // retains the existing order; no retained failed prefix is extracted.
        semantic.dispose_ordinary_prospective_v1();
        let _ = native.dispose_ordinary_current_once_v1();
        let (stopped, semantic_cause) = semantic.into_ordinary_errors();
        let _ = native.dispose_ordinary_pending_once_v1();
        let (index_cause, native_cause) = match native.into_ordinary_errors_v1() {
            Ok(causes) => causes,
            Err(_original) => std::process::abort(),
        };
        if comparison_selected {
            return Err(comparison
                .into_ordinary_failure_v1()
                .unwrap_or(MechanicalError::ProtectedBoundary)
                .into());
        }
        match stopped {
            Some(CanonicalIndexedReplayErrorV1::Native(cause)) => return Err(cause.into()),
            Some(CanonicalIndexedReplayErrorV1::Closed) => {
                if let Some(cause) = index_cause {
                    return Err(MechanicalError::from(cause).into());
                }
                if let Some(cause) = native_cause {
                    return Err(cause.into());
                }
            }
            None => {
                if let Some(cause) = semantic_cause {
                    return Err(cause.into());
                }
                if let Some(cause) = index_cause {
                    return Err(MechanicalError::from(cause).into());
                }
                if let Some(cause) = native_cause {
                    return Err(cause.into());
                }
            }
        }
        result
    }
}

fn provision_origin(journal: &MountJournalV1, witness: &ProtectedWriterNameWitness) -> [u8; 32] {
    provision_origin_digest_v1(
        journal
            .native
            .read_view_v1()
            .protected_view()
            .map(|location| location.name()),
        [
            witness.directory().physical_pair(),
            witness.file().physical_pair(),
            witness.lock().physical_pair(),
        ],
    )
}

fn require_bookend(
    journal: &MountJournalV1,
    witness: &ProtectedWriterNameWitness,
) -> Result<(), JournalError> {
    journal.ensure_healthy()?;
    journal.require_protected_names_current()?;
    journal.validate_protected_writer_name_witness(witness)?;
    if journal
        .native
        .read_view_v1()
        .file_identity::<JournalError>()?
        != witness.file()
    {
        return Err(MechanicalError::StaleAuthoritySnapshot.into());
    }
    Ok(())
}
