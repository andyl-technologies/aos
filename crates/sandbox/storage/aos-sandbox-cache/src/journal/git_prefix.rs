//! Rechecks Cache's five fixed Git profiles through the same held native file.
//!
//! The sole indexed cursor and full ordinary Cold recipe observe every COMMIT
//! and EOF. This private borrower retains the actual writer and held-name
//! witness; catalog/hash DATA can neither construct it nor grant an append.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryRereadDataV1,
};
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageCatalogV1, GitCoverageJournalProfileV1,
};
use aos_sandbox_ledger_replay::cold::{
    ColdReplayRemainderDataV1,
    git_prefix::CacheGitPrefixReplayDataV1,
};

use super::{Journal, JournalError, ProtectedWriterNameWitness};
use crate::error::CacheNativePrefixErrorV1;

pub(crate) struct GitCoverageNativePrefixLoanV1<'journal> {
    journal: &'journal Journal,
    witness: ProtectedWriterNameWitness,
    prefix: [u8; 32],
    counts: (usize, usize),
    last_commit: Option<([u8; 16], u64)>,
    ended: bool,
}

impl GitCoverageNativePrefixLoanV1<'_> {
    pub(crate) fn prefix_digest(&self) -> [u8; 32] {
        self.prefix
    }

    pub(crate) fn provision_origin_digest(&self) -> [u8; 32] {
        provision_origin(self.journal, &self.witness)
    }

    pub(crate) fn counts(&self) -> (usize, usize) {
        self.counts
    }

    pub(crate) fn last_commit(&self) -> Option<([u8; 16], u64)> {
        self.last_commit
    }

    pub(crate) fn recheck(&mut self) -> Result<(), JournalError> {
        if self.ended {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        self.ended = true;
        require_bookend(self.journal, &self.witness)?;
        self.ended = false;
        Ok(())
    }
}

impl Journal {
    pub(crate) fn cache_coverage_native_prefix_v1(&self) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1(aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_BASENAME_V1, None)
    }

    pub(crate) fn cache_bootstrap_coverage_native_prefix_v1<'data>(&self, catalog: &'data GitCoverageCatalogV1<'data>) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1("bootstrap-v1.journal", Some((catalog, GitCoverageJournalProfileV1::CacheBootstrap)))
    }

    pub(crate) fn cache_clock_coverage_native_prefix_v1<'data>(&self, catalog: &'data GitCoverageCatalogV1<'data>) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1("clock.journal", Some((catalog, GitCoverageJournalProfileV1::CacheClock)))
    }

    pub(crate) fn cache_hold_coverage_native_prefix_v1<'data>(&self, catalog: &'data GitCoverageCatalogV1<'data>) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1(aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_BASENAME_V1, Some((catalog, GitCoverageJournalProfileV1::CachePolicyHold)))
    }

    pub(crate) fn cache_authority_coverage_native_prefix_v1<'data>(&self, catalog: &'data GitCoverageCatalogV1<'data>) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1("authority.journal", Some((catalog, GitCoverageJournalProfileV1::CacheAuthority)))
    }

    pub(crate) fn cache_state_coverage_native_prefix_v1<'data>(&self, catalog: &'data GitCoverageCatalogV1<'data>) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        self.capture_cache_git_prefix_v1("state.journal", Some((catalog, GitCoverageJournalProfileV1::CacheState)))
    }

    fn capture_cache_git_prefix_v1<'data>(
        &self,
        name: &'static str,
        catalog: Option<(&'data GitCoverageCatalogV1<'data>, GitCoverageJournalProfileV1)>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, CacheNativePrefixErrorV1> {
        if self.read_view().protected_name() != Some(name) {
            return Err(CacheNativePrefixErrorV1::new(JournalError::boundary(), None));
        }
        let witness = (|| {
            self.ensure_protected_authority()?;
            self.require_protected_names_current()?;
            self.protected_writer_name_witness()
        })().map_err(|first| CacheNativePrefixErrorV1::new(first, None))?;
        let result = (|| {
            let audit = match catalog {
                Some((catalog, profile)) => CacheGitPrefixReplayDataV1::with_catalog_v1(catalog, profile)?,
                None => CacheGitPrefixReplayDataV1::policy_native_prefix_v1(),
            };
            let (native, semantic, audit) = self.reread_native_audit_v1(
                witness.file().byte_len(), super::native_audit::CacheNativeAuditV1::Git(audit),
            )?;
            let super::native_audit::CacheNativeAuditV1::Git(audit) = audit else {
                return Err(JournalError::boundary());
            };
            require_same_replay(self, &native, &semantic, witness.file().byte_len())?;
            audit.require_origin_v1(provision_origin(self, &witness))?;
            Ok(audit)
        })();
        let bookend = require_bookend(self, &witness);
        let audit = match (result, bookend) {
            (Ok(value), Ok(())) => value,
            (Err(first), final_bookend) => {
                return Err(CacheNativePrefixErrorV1::new(first, final_bookend.err()));
            }
            (Ok(_), Err(first)) => return Err(CacheNativePrefixErrorV1::new(first, None)),
        };
        let prefix = audit.prefix_data_v1();
        Ok(GitCoverageNativePrefixLoanV1 {
            journal: self, witness, prefix: prefix.prefix_digest_v1(),
            counts: prefix.counts_v1(), last_commit: prefix.last_commit_v1(), ended: false,
        })
    }


}

fn provision_origin(journal: &Journal, witness: &ProtectedWriterNameWitness) -> [u8; 32] {
    aos_sandbox_ledger_replay::git_coverage_prefix::provision_origin_digest_v1(
        journal.read_view().protected_name(),
        [witness.directory().physical_pair(), witness.file().physical_pair(), witness.lock().physical_pair()],
    )
}

fn require_bookend(journal: &Journal, witness: &ProtectedWriterNameWitness) -> Result<(), JournalError> {
    journal.ensure_healthy()?;
    journal.require_protected_names_current()?;
    journal.validate_protected_writer_name_witness(witness)?;
    if journal.read_view().file_identity::<JournalError>()? != witness.file() {
        return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
    }
    Ok(())
}

fn require_same_replay(
    journal: &Journal,
    replayed: &CanonicalOrdinaryRereadDataV1,
    semantic: &ColdReplayRemainderDataV1,
    physical_bytes: u64,
) -> Result<(), JournalError> {
    let coordinates = replayed.coordinates_data_v1();
    let actual = journal.read_view();
    if coordinates.durable_end != physical_bytes
        || coordinates.durable_next_sequence != actual.next_sequence()
        || coordinates.committed_transactions != actual.committed_transactions()
        || replayed.transaction_ids_data_v1() != actual.transaction_ids()
        || replayed.committed_namespaces_data_v1() != actual.committed_namespaces()
        || replayed.state_data_v1() != actual.state()
        || replayed.materialized_bytes_data_v1() != actual.materialized_bytes()
        || replayed.idempotency_data_v1() != actual.idempotency_index()
        || semantic.q04_lower_history_present != journal.remainder.q04_lower_history_present
        || semantic.history_compacted
    {
        return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
    }
    Ok(())
}
