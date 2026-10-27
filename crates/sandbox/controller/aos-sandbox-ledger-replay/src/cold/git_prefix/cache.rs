//! Compares Cache's finite Git prefixes without native or role authority.
//!
//! The same canonical cursor supplies actual COMMITs and complete EOF. The
//! genuine Cache owner retains its held writer, funding, full semantic replay
//! and independent native bookends. Catalogs and successful comparisons remain
//! historical DATA; neither can construct a Cache or Mount owner.

#[cfg(test)]
mod tests;

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalJournalMechanicalErrorV1, CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageCatalogV1, GitCoverageJournalProfileV1,
};
use aos_sandbox_model::{ObjectDigest, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::git_coverage_prefix::{
    GitCoverageFixedCatalogDataV1, GitCoverageNativePrefixDataV1,
    cache::{compare_clock_native_transaction_v1, require_policy_native_transaction_v1},
};

/// Retains the fixed Cache comparison and its first actual refusal.
///
/// This owner accepts only the five existing Cache catalog profiles or the
/// original policy-only prefix. It carries no writer, callback, grant or
/// financial original. Complete Cold replay and native currentness remain
/// independent requirements at its actual caller.
pub struct CacheGitPrefixReplayDataV1<'data> {
    prefix: GitCoverageNativePrefixDataV1,
    catalog: Option<GitCoverageFixedCatalogDataV1<'data>>,
    policy: bool,
    previous_clock: Option<(ObjectDigest, u64, u64)>,
    complete: bool,
    failure: Option<CanonicalJournalMechanicalErrorV1>,
}

impl<'data> CacheGitPrefixReplayDataV1<'data> {
    /// Constructs the original Genesis/paired-birth comparison without a catalog.
    #[must_use]
    pub fn policy_native_prefix_v1() -> Self {
        Self {
            prefix: GitCoverageNativePrefixDataV1::new(),
            catalog: None,
            policy: true,
            previous_clock: None,
            complete: false,
            failure: None,
        }
    }

    /// Constructs one of the five existing Cache catalog comparisons.
    ///
    /// # Errors
    /// Refuses every non-Cache profile and preserves fixed-member geometry
    /// or lookup failure from the existing catalog comparison.
    pub fn with_catalog_v1(
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
    ) -> Result<Self, CanonicalJournalMechanicalErrorV1> {
        if !matches!(
            profile,
            GitCoverageJournalProfileV1::CacheBootstrap
                | GitCoverageJournalProfileV1::CacheClock
                | GitCoverageJournalProfileV1::CachePolicyHold
                | GitCoverageJournalProfileV1::CacheAuthority
                | GitCoverageJournalProfileV1::CacheState
        ) {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        Ok(Self {
            prefix: GitCoverageNativePrefixDataV1::new(),
            catalog: Some(GitCoverageFixedCatalogDataV1::new(catalog, profile)?),
            policy: profile == GitCoverageJournalProfileV1::CachePolicyHold,
            previous_clock: None,
            complete: false,
            failure: None,
        })
    }

    /// Returns the actual inline owner and construction allowance as inert DATA.
    ///
    /// # Errors
    /// Refuses checked byte arithmetic overflow. Dynamic canonical frames and
    /// full semantic models remain separately priced by their genuine caller.
    pub fn fixed_demand_v1() -> Result<ResourceVector, CanonicalJournalMechanicalErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(CanonicalJournalMechanicalErrorV1::LimitExceeded(
                "Cache Git comparison geometry",
            ))?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }

    /// Observes the actual parsed COMMIT before ordinary semantic mutation.
    ///
    /// # Errors
    /// Retains the original prefix, policy, Clock or catalog refusal. Reentry
    /// after EOF and every call after a prior refusal remain closed.
    pub fn observe_commit_v1(
        &mut self,
        commit: CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        let (begin, offset) = commit.begin_position();
        self.observe_transaction_v1(
            commit.transaction(),
            begin,
            commit.commit_sequence(),
            offset,
            commit.coordinates().offset,
        )
    }

    /// Compares one existing parser's transaction and its actual coordinates.
    ///
    /// This is also the immediate adapter for the original Domain caller. It
    /// never parses bytes, opens a file or chooses a semantic/native policy.
    ///
    /// # Errors
    /// Retains the exact first ordering, catalog, Clock or encoding failure.
    pub fn observe_transaction_v1(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        if self.failure.is_some() {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        let result = (|| {
            if self.complete {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            self.prefix.validate_transaction_v1(
                transaction,
                begin_sequence,
                commit_sequence,
                begin_offset,
                end_offset,
            )?;

            // Policy Genesis/birth checking precedes catalog classification.
            // Only Genesis advances the policy catalog's pre-birth prefix.
            if self.policy {
                require_policy_native_transaction_v1(
                    self.prefix.counts_v1().0,
                    transaction,
                    commit_sequence,
                    self.prefix.prefix_digest_v1(),
                )?;
            }
            let mut catalog_transaction = !self.policy || self.prefix.counts_v1().0 == 0;
            if let Some(catalog) = self.catalog.as_mut() {
                if catalog_transaction {
                    if catalog.profile_v1() == GitCoverageJournalProfileV1::CacheClock {
                        let complete = catalog.catalogued_prefix_complete_v1();
                        self.previous_clock = Some(compare_clock_native_transaction_v1(
                            transaction,
                            self.previous_clock,
                        )?);
                        if complete {
                            catalog_transaction = false;
                        }
                    }
                    if catalog_transaction {
                        catalog.observe_transaction_v1(transaction, begin_sequence)?;
                    }
                }
            }
            self.prefix.finish_transaction_v1(
                transaction,
                begin_sequence,
                commit_sequence,
                end_offset,
                if catalog_transaction {
                    self.catalog.as_mut()
                } else {
                    None
                },
            )
        })();
        self.retain_v1(result)
    }

    /// Compares the same cursor's complete EOF after all Cold semantic checks.
    ///
    /// # Errors
    /// Retains a changed captured end or an incomplete native prefix. This
    /// historical comparison authenticates neither the supplied identity nor
    /// the caller's native bookends.
    pub fn finish_prefix_v1(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        let coordinates = prefix.coordinates();
        if coordinates.durable_end != captured_end {
            return self.retain_v1(Err(
                CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot,
            ));
        }
        self.finish_coordinates_v1(
            captured_end,
            coordinates.durable_next_sequence,
            coordinates.committed_transactions,
            coordinates.committed_records,
        )
    }

    /// Compares the original materializer's complete native EOF coordinates.
    ///
    /// The ordinary Domain adapter supplies its own fully replayed counters;
    /// the Cold adapter above borrows the canonical cursor's prefix directly.
    /// These coordinates cannot create a native or financial completion.
    ///
    /// # Errors
    /// Retains changed counts, incomplete prefix, repeated EOF or prior refusal.
    pub fn finish_coordinates_v1(
        &mut self,
        physical_bytes: u64,
        next_sequence: u64,
        transactions: usize,
        records: usize,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        if self.failure.is_some() {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        let result = (|| {
            if self.complete {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            self.prefix.require_complete_v1(
                physical_bytes,
                next_sequence,
                transactions,
                records,
            )?;
            self.complete = true;
            Ok(())
        })();
        self.retain_v1(result)
    }

    fn retain_v1(
        &mut self,
        result: Result<(), CanonicalJournalMechanicalErrorV1>,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.failure.get_or_insert(cause);
                Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)
            }
        }
    }

    /// Compares the catalog with actual held-name origin DATA after complete EOF.
    ///
    /// # Errors
    /// Refuses incomplete replay, a prior comparison failure or another origin.
    /// The original policy-only recipe has no catalog origin to compare.
    pub fn require_origin_v1(
        &self,
        origin: [u8; 32],
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        if !self.complete || self.failure.is_some() {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        match &self.catalog {
            Some(catalog) => catalog.require_complete_v1(origin),
            None => Ok(()),
        }
    }

    /// Borrows the actual first comparison refusal without consuming its owner.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalJournalMechanicalErrorV1> {
        self.failure.as_ref()
    }

    /// Moves the actual ordinary comparison cause after the cursor is dropped.
    #[must_use]
    pub fn into_ordinary_failure_v1(self) -> Option<CanonicalJournalMechanicalErrorV1> {
        self.failure
    }

    /// Borrows actual accumulated coordinates and prefix as historical DATA.
    #[must_use]
    pub fn prefix_data_v1(&self) -> &GitCoverageNativePrefixDataV1 {
        &self.prefix
    }
}
