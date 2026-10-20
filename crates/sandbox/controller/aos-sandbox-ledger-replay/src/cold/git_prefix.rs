//! Compares Mount's fixed Git catalog inside the sole full semantic replay.
//!
//! This owner contains only the canonical prefix/catalog DATA and its first
//! comparison refusal. Its private cursor adapter observes actual COMMITs and
//! EOF; native files, bookends, admission and role authority stay with Mount.

/// Compares the five fixed Cache catalog profiles and original policy prefix.
pub mod cache;
pub use cache::CacheGitPrefixReplayDataV1;

#[cfg(test)]
mod tests;

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalJournalMechanicalErrorV1,
    CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageCatalogV1, GitCoverageJournalProfileV1,
};

use crate::git_coverage_prefix::{
    GitCoverageFixedCatalogDataV1, GitCoverageNativePrefixDataV1,
    require_owner_fence_transaction_v1,
};

/// Retains the fixed Mount catalog comparison and actual native-prefix hash.
///
/// Successful comparison provides historical DATA, never a Mount constructor,
/// append grant, physical-currentness witness or financial completion.
pub struct MountGitPrefixReplayDataV1<'data> {
    prefix: GitCoverageNativePrefixDataV1,
    catalog: GitCoverageFixedCatalogDataV1<'data>,
    owner_fence_seen: bool,
    complete: bool,
    failure: Option<CanonicalJournalMechanicalErrorV1>,
}

impl<'data> MountGitPrefixReplayDataV1<'data> {
    /// Constructs the fixed Mount comparison from the existing catalog DATA.
    ///
    /// # Errors
    /// Preserves the canonical catalog/profile and geometry refusals.
    pub fn new(
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<Self, CanonicalJournalMechanicalErrorV1> {
        Ok(Self {
            prefix: GitCoverageNativePrefixDataV1::new(),
            catalog: GitCoverageFixedCatalogDataV1::new(
                catalog, GitCoverageJournalProfileV1::Mount,
            )?,
            owner_fence_seen: false,
            complete: false,
            failure: None,
        })
    }

    pub(super) fn observe_commit_v1(
        &mut self,
        commit: CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), ()> {
        if self.failure.is_some() {
            return Err(());
        }
        let result = (|| {
            if self.complete {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            let transaction = commit.transaction();
            let (begin, offset) = commit.begin_position();
            let end = commit.coordinates().offset;
            self.prefix.validate_transaction_v1(
                transaction, begin, commit.commit_sequence(), offset, end,
            )?;
            if self.owner_fence_seen {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            let fence = transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && matches!(record.key(), b"z-git-birth-v1" | b"z-git-fence-v1")
            });
            if fence {
                require_owner_fence_transaction_v1(
                    GitCoverageJournalProfileV1::Mount, transaction,
                    commit.commit_sequence(), self.prefix.prefix_digest_v1(),
                    self.catalog.catalog_v1(),
                )?;
                self.owner_fence_seen = true;
            } else {
                self.catalog.observe_transaction_v1(transaction, begin)?;
            }
            self.prefix.finish_transaction_v1(
                transaction, begin, commit.commit_sequence(), end,
                if fence { None } else { Some(&mut self.catalog) },
            )
        })();
        self.retain(result)
    }

    pub(super) fn finish_prefix_v1(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), ()> {
        if self.failure.is_some() {
            return Err(());
        }
        let coordinates = prefix.coordinates();
        let result = (|| {
            if self.complete || coordinates.durable_end != captured_end {
                return Err(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot);
            }
            self.prefix.require_complete_v1(
                captured_end, coordinates.durable_next_sequence,
                coordinates.committed_transactions, coordinates.committed_records,
            )?;
            self.complete = true;
            Ok(())
        })();
        self.retain(result)
    }

    fn retain(&mut self, result: Result<(), CanonicalJournalMechanicalErrorV1>) -> Result<(), ()> {
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.failure.get_or_insert(cause);
                Err(())
            }
        }
    }

    /// Compares the catalog with the caller's actual held-name origin DATA.
    ///
    /// The native owner independently verifies those held names and identities.
    /// # Errors
    /// Refuses incomplete replay, an earlier comparison or a different origin.
    pub fn require_origin_v1(&self, origin: [u8; 32]) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        if !self.complete || self.failure.is_some() {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        self.catalog.require_complete_v1(origin)
    }

    /// Borrows the exact first comparison refusal without consuming its owner.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalJournalMechanicalErrorV1> {
        self.failure.as_ref()
    }

    /// Moves the actual ordinary comparison cause after the cursor is dropped.
    #[must_use]
    pub fn into_ordinary_failure_v1(self) -> Option<CanonicalJournalMechanicalErrorV1> {
        self.failure
    }

    /// Borrows the actual canonical prefix accumulator as historical DATA.
    #[must_use]
    pub fn prefix_data_v1(&self) -> &GitCoverageNativePrefixDataV1 {
        &self.prefix
    }
}
