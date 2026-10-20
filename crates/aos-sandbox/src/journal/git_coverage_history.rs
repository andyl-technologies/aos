//! Streaming Git-cohort native-prefix DATA from the original protected writer.
//!
//! The existing COMMIT parser and materializer validate every actual native
//! transaction. This child hashes their sole canonical frame encoding without
//! retaining a transaction forest, prefix maps or another replay reducer.
//!
//! ```text
//! SHA256("aos.sandbox.git-upload.native-prefix.v1\0" || canonical native frames)
//! ```
//!
//! The loan prevents writer mutation while borrowed. It establishes only a
//! parser-validated physical prefix; live role, clock, signature, catalog,
//! admission and physical residual checks belong to the genuine owners.

use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageCatalogV1, GitCoverageFenceV1,
    GitCoverageJournalProfileV1,
};

use aos_sandbox_ledger_replay::cold::git_prefix::CacheGitPrefixReplayDataV1;
use aos_sandbox_ledger_replay::git_coverage_prefix::{
    GitCoverageFixedCatalogDataV1, GitCoverageNativePrefixDataV1,
    has_durable_owner_fence_v1, provision_origin_digest_v1, require_owner_fence_transaction_v1,
};

use crate::publisher_admin::policy as provider_policy_data;
use crate::cli_model::authorization_adapter as provider_cli_floor_data;
use crate::public_capability_issuance as provider_initial_issuance_data;

use super::runtime_deployment_history::ReadAtCursorV1;
use super::{
    DeploymentHistoryObserverV1, FileIdentity, Journal, JournalError,
    JournalTransaction, ProtectedWriterNameWitness, RecordNamespace, ObservedReplayStateV1,
    replay_coordinator_observed_v1,
};


// Domain's remaining generic denial shares the same canonical DATA predicate.
// The actual native writer and retained denial stay with their role owner.
fn require_original_source_cleanup_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::git_coverage_prefix::require_mount_original_source_cleanup_v1(
        state, transaction,
    ).map_err(JournalError::from)
}

#[derive(Clone, Copy)]
enum NativePrefixRecipeV1 {
    Original,
    CachePolicy,
    OwnerCoverage(GitCoverageJournalProfileV1),
}

/// Retains the first actual parser/check error and independent final debt.
#[derive(Debug, thiserror::Error)]
#[error("Git coverage native prefix failed: {first}")]
pub struct GitCoverageNativeHistoryErrorV1 {
    #[source]
    first: JournalError,
    final_bookend: Option<JournalError>,
}

impl GitCoverageNativeHistoryErrorV1 {
    pub(crate) fn from_first(first: JournalError) -> Self {
        Self { first, final_bookend: None }
    }

    /// Borrows the unchanged first owning native cause.
    #[must_use]
    pub fn first_cause(&self) -> &JournalError {
        &self.first
    }

    /// Borrows later physical/name debt without replacing the first cause.
    #[must_use]
    pub fn final_bookend_cause(&self) -> Option<&JournalError> {
        self.final_bookend.as_ref()
    }
}

/// Borrows one original protected writer and its completely observed prefix.
///
/// This is DATA, not current role authority or an append/floor permit. No
/// method opens, clones, seeks, mutates or extracts the original Journal.
pub struct GitCoverageNativePrefixLoanV1<'journal> {
    journal: &'journal Journal,
    witness: ProtectedWriterNameWitness,
    prefix: [u8; 32],
    transactions: usize,
    records: usize,
    last_transaction: Option<[u8; 16]>,
    last_commit_sequence: Option<u64>,
    ended: bool,
    controller_account_seen: bool,
    controller_floor_seen: bool,
}

impl GitCoverageNativePrefixLoanV1<'_> {
    pub(crate) fn existing_controller_read_floor_v1(&self) -> Result<bool, JournalError> {
        if self.ended || !self.controller_account_seen {
            return Err(JournalError::ProtectedBoundary);
        }
        // False describes absence in this COMPLETE replay, not the current map.
        Ok(self.controller_floor_seen)
    }

    /// Returns the whole original native-prefix commitment as comparison DATA.
    #[must_use]
    pub fn prefix_digest(&self) -> [u8; 32] {
        self.prefix
    }

    /// Commits the original protected name and three retained inode identities.
    ///
    /// The separate prefix commits actual contents. This stable local-origin
    /// DATA excludes mutable lengths/timestamps and supplies no independent
    /// startup, role, project, policy, or physical-residual authority.
    #[must_use]
    pub fn provision_origin_digest(&self) -> [u8; 32] {
        provision_origin(self.journal, &self.witness)
    }

    /// Returns actual validated transaction and record counts, not quotas.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.transactions, self.records)
    }

    /// Returns the last actual UUID and COMMIT sequence, if a COMMIT exists.
    #[must_use]
    pub fn last_commit(&self) -> Option<([u8; 16], u64)> {
        self.last_transaction.zip(self.last_commit_sequence)
    }

    /// Rechecks the same original writer's physical/name cut while borrowed.
    ///
    /// # Errors
    /// Rejects poison, replaced names, changed file identity or sequence. This
    /// observational check grants no current policy or remote owner authority.
    pub fn recheck(&mut self) -> Result<(), JournalError> {
        if self.ended {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.ended = true;
        require_bookend(self.journal, &self.witness)?;
        self.ended = false;
        Ok(())
    }
}

pub(super) struct NativePrefixObserverV1<'data> {
    recipe: NativePrefixRecipeV1,
    fixed_cache_catalog: Option<GitCoverageFixedCatalogDataV1<'data>>,
    prefix: GitCoverageNativePrefixDataV1,
    cache: Option<CacheGitPrefixReplayDataV1<'data>>,
    owner_fence_seen: bool,
    publisher_account_seen: bool,
    controller_floor: Option<crate::cli_model::authorization_adapter::ProtectedTimeFloorRevisionV1>,
    initial_issuance: crate::public_capability_issuance::GitCoverageInitialIssuanceHistoryV1,
}

impl<'data> NativePrefixObserverV1<'data> {
    fn new(recipe: NativePrefixRecipeV1) -> Self {
        Self {
            recipe,
            fixed_cache_catalog: None,
            prefix: GitCoverageNativePrefixDataV1::new(),
            cache: matches!(recipe, NativePrefixRecipeV1::CachePolicy)
                .then(CacheGitPrefixReplayDataV1::policy_native_prefix_v1),
            owner_fence_seen: false,
            publisher_account_seen: false,
            controller_floor: None,
            initial_issuance: Default::default(),
        }
    }

    fn prefix_data_v1(&self) -> &GitCoverageNativePrefixDataV1 {
        match &self.cache {
            Some(cache) => cache.prefix_data_v1(),
            None => &self.prefix,
        }
    }

    // The existing ordinary caller moves the exact comparison error into its
    // owning error after the observer stops. Selected Cache callers retain
    // their separate DATA owner through every independently owed bookend.
    fn take_cache_error_v1(&mut self) -> JournalError {
        self.cache.take()
            .and_then(CacheGitPrefixReplayDataV1::into_ordinary_failure_v1)
            .map(JournalError::from)
            .unwrap_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        if let Some(cache) = self.cache.as_mut() {
            return match cache.observe_transaction_v1(transaction, begin_sequence,
                commit_sequence, begin_offset, end_offset) {
                Ok(()) => Ok(()),
                Err(_) => Err(self.take_cache_error_v1()),
            };
        }
        self.prefix.validate_transaction_v1(
            transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
        )?;

        let mut catalog_transaction = true;
        if let NativePrefixRecipeV1::OwnerCoverage(profile) = self.recipe {
            if self.owner_fence_seen {
                // Controller's first covered account is one subsequent
                // immutable three-PUT transaction. No later effect, overwrite
                // or retirement is classified by this bounded first profile.
                if profile != GitCoverageJournalProfileV1::Controller {
                    return Err(JournalError::ProtectedBoundary);
                }
                if !self.publisher_account_seen {
                    crate::publisher_admin::policy::require_coverage_native_account_transaction(transaction)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    self.publisher_account_seen = true;
                } else if transaction.records().first().is_some_and(|record| {
                    record.namespace() == RecordNamespace::CliAuthorizationTime
                }) {
                    self.controller_floor = Some(
                        crate::cli_model::authorization_adapter::require_git_coverage_floor_transaction_v1(
                            transaction, self.controller_floor,
                        ).map_err(|_| JournalError::ProtectedBoundary)?,
                    );
                } else {
                    if self.controller_floor.is_none() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    self.initial_issuance.observe(transaction)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                }
                catalog_transaction = false;
            } else if transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && matches!(record.key(), b"z-git-birth-v1" | b"z-git-fence-v1")
            }) {
                require_owner_fence_transaction_v1(
                    profile,
                    transaction,
                    commit_sequence,
                    self.prefix.prefix_digest_v1(),
                    self.fixed_cache_catalog.as_ref()
                        .ok_or(JournalError::ProtectedBoundary)?.catalog_v1(),
                )?;
                self.owner_fence_seen = true;
                catalog_transaction = false;
            }
        }
        if let Some(catalog) = self.fixed_cache_catalog.as_mut() {
            if catalog_transaction {
                catalog.observe_transaction_v1(transaction, begin_sequence)?;
            }
        }

        self.prefix.finish_transaction_v1(
            transaction, begin_sequence, commit_sequence, end_offset,
            if catalog_transaction { self.fixed_cache_catalog.as_mut() } else { None },
        )?;
        Ok(())
    }
}


impl Journal {
    /// Refuses a new admission under the original permanent Controller fence.
    ///
    /// This is a negative check on the same protected writer, not an empty
    /// domain proof or a permission when no row exists. The first-profile
    /// capture separately checks the complete native history before installing
    /// its fence. Original negative recovery remains outside this NEW boundary.
    ///
    /// # Errors
    /// Refuses either durable fence row, including a malformed partial pair.
    /// Absence does not replace the caller's independent physical currentness,
    /// protected writer/name, native preflight or commit checks.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn require_git_coverage_new_admission_v1(&self) -> Result<(), JournalError> {
        if !self.controller_git_coverage_fenced_v1(self.native.state()) {
            return Ok(());
        }
        Err(JournalError::ProtectedBoundary)
    }

    fn controller_git_coverage_fenced_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> bool {
        controller_fenced_read_v1(self.native.read_view(), state)
    }

    pub(super) fn require_owner_git_coverage_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        require_owner_transition_read_v1(self.native.read_view(), state, transaction)
    }

    pub(crate) fn controller_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::Controller,
            "/var/lib/aos/sandboxd", "controller.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::Controller),
        )
    }

    pub(crate) fn existing_controller_coverage_birth_nonce_v1(
        &self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<[u8; 16], GitCoverageNativeHistoryErrorV1> {
        let mut loan = self.controller_git_coverage_native_prefix_v1(catalog)?;
        loan.existing_controller_read_floor_v1()
            .map_err(GitCoverageNativeHistoryErrorV1::from_first)?;
        let nonce = (|| {
            let birth = GitCoverageBirthV1::decode(self.get(
                RecordNamespace::DesiredState, b"z-git-birth-v1",
            ).ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let fence = GitCoverageFenceV1::decode(self.get(
                RecordNamespace::DesiredState, b"z-git-fence-v1",
            ).ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            fence.compare_birth(&birth).map_err(|_| JournalError::ProtectedBoundary)?;
            Ok(fence.fields().prepare_nonce)
        })();
        let postchecked = loan.recheck();
        match (nonce, postchecked) {
            (Ok(nonce), Ok(())) => Ok(nonce),
            (Err(first), final_bookend) => Err(GitCoverageNativeHistoryErrorV1 {
                first, final_bookend: final_bookend.err(),
            }),
            (Ok(_), Err(first)) => Err(GitCoverageNativeHistoryErrorV1::from_first(first)),
        }
    }

    pub(crate) fn root_authority_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::RootAuthority,
            "/var/lib/aos/sandbox/policy-compiler", "authority.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::RootAuthority),
        )
    }

    pub(crate) fn root_state_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::RootPolicyState,
            "/var/lib/aos/sandbox/policy-compiler", "state.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::RootPolicyState),
        )
    }

    pub(crate) fn source_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::Source,
            "/var/lib/aos/sandbox/source-domains", "source-domains-v1.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    // Only the named purpose methods above select these fixed roots. The
    // original witness and complete parser/materializer bookends are shared;
    // no public path/profile/callback selector or Journal getter is exposed.
    fn capture_fixed_owner_catalog_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
        directory: &'static str,
        name: &'static str,
        recipe: NativePrefixRecipeV1,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if *self.native.path() != std::path::Path::new(directory).join(name) {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_fixed_cache_catalog_v1(catalog, profile, name, recipe)
    }

    pub(super) fn require_mount_git_coverage_source_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        require_mount_transition_read_v1(self.native.read_view(), false, state, transaction)
    }

    pub(super) fn require_storage_git_coverage_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        require_storage_transition_read_v1(self.native.read_view(), state, transaction)
    }

    /// Lends the completely observed native prefix of this original writer.
    ///
    /// Uses the same parser/materializer and a positioned original-file cursor;
    /// it never opens a name, changes the append OFD offset or copies histories.
    /// The caller's genuine owner remains responsible for retained failure and
    /// uncaught-unwind custody during ordinary parser/encoder allocation.
    ///
    /// # Errors
    /// Returns the first typed health/parser/shape/snapshot failure and any
    /// separate final bookend debt. Refuses compaction or incomplete tails.
    pub fn git_coverage_native_prefix_v1(
        &self,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_git_coverage_native_prefix_v1(NativePrefixRecipeV1::Original, None)
    }

    /// Compares the original fixed Storage catalog prefix with its signed input.
    ///
    /// Storage's existing configuration and catalog validators remain required;
    /// this loan supplies neither physical-empty nor allocation authority.
    ///
    /// # Errors
    /// Rejects a different protected name, foreign namespace, undeclared row,
    /// compaction, changed native identity or a malformed permanent fence pair.
    pub fn storage_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::StorageCatalog, "storage-state.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::StorageCatalog),
        )
    }

    /// Compares the original fixed native-issuance prefix with its signed member.
    ///
    /// This DATA loan does not issue or retire a consumer interest. The actual
    /// native owner independently requires its complete interest history empty.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_native_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageNative,
            "storage-native-issuance.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    /// Compares the original fixed workspace prefix with its signed member.
    ///
    /// The existing workspace owner separately checks the identity pool, head,
    /// plan and physical pin root. No allocation or inventory permit is lent.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_workspace_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageWorkspace,
            "storage-workspaces.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    /// Compares the original fixed output prefix with its signed member.
    ///
    /// The genuine output custody independently authenticates its configuration,
    /// MAC key and empty obligations; a catalog signature cannot replace them.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_output_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageOutput,
            "execution-output.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    // This closed recipe also checks the original Genesis and sole paired
    // birth/fence transaction. It cannot reinterpret an old released hold as
    // fresh enrollment, and opens no additional policy writer.
    pub(crate) fn cache_coverage_native_prefix_v1(
        &self,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.native.protected_view().map(|location| location.name())
            != Some(super::cache_policy_hold::NAME)
        {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(NativePrefixRecipeV1::CachePolicy, None)
    }

    pub(crate) fn cache_bootstrap_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.native.protected_view().map(|location| location.name()) != Some("bootstrap-v1.journal") {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(
            NativePrefixRecipeV1::Original,
            Some((catalog, GitCoverageJournalProfileV1::CacheBootstrap)),
        )
    }

    pub(crate) fn cache_clock_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheClock,
            "clock.journal", NativePrefixRecipeV1::Original,
        )
    }

    pub(crate) fn cache_hold_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CachePolicyHold,
            super::cache_policy_hold::NAME, NativePrefixRecipeV1::CachePolicy,
        )
    }

    pub(crate) fn cache_authority_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheAuthority,
            "authority.journal", NativePrefixRecipeV1::Original,
        )
    }

    pub(crate) fn cache_state_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheState,
            "state.journal", NativePrefixRecipeV1::Original,
        )
    }

    fn capture_fixed_cache_catalog_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
        name: &'static str,
        recipe: NativePrefixRecipeV1,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.native.protected_view().map(|location| location.name()) != Some(name) {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(recipe, Some((catalog, profile)))
    }

    fn capture_git_coverage_native_prefix_v1<'data>(
        &self,
        recipe: NativePrefixRecipeV1,
        fixed_cache_catalog: Option<(&'data GitCoverageCatalogV1<'data>, GitCoverageJournalProfileV1)>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        let capture = (|| {
            self.ensure_protected_authority()?;
            self.require_protected_names_current()?;
            self.protected_writer_name_witness()
        })();
        let witness = capture.map_err(|first| GitCoverageNativeHistoryErrorV1 {
            first, final_bookend: None,
        })?;

        let result = (|| {
            let mut observer = NativePrefixObserverV1::new(recipe);
            if let Some((catalog, profile)) = fixed_cache_catalog {
                if matches!(profile,
                    GitCoverageJournalProfileV1::CacheBootstrap
                        | GitCoverageJournalProfileV1::CacheClock
                        | GitCoverageJournalProfileV1::CachePolicyHold
                        | GitCoverageJournalProfileV1::CacheAuthority
                        | GitCoverageJournalProfileV1::CacheState)
                {
                    observer.cache = Some(CacheGitPrefixReplayDataV1::with_catalog_v1(catalog, profile)?);
                } else {
                    observer.fixed_cache_catalog = Some(GitCoverageFixedCatalogDataV1::new(catalog, profile)?);
                }
            }
            let cursor = self.native.captured_reader(witness.file().byte_len());
            let replayed = replay_coordinator_observed_v1(
                cursor,
                self.native.limits(),
                None,
                Some(DeploymentHistoryObserverV1::GitCoverage(&mut observer)),
            )?;
            require_replayed_snapshot(self, &replayed, &mut observer, witness.file().byte_len())?;
            if matches!(
                recipe,
                NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::Controller,)
            ) && observer.publisher_account_seen
            {
                crate::publisher_admin::policy::PublisherPolicyStore::require_complete_coverage_read_state_v1(
                    self.native.state(),
                ).map_err(|_| JournalError::ProtectedBoundary)?;
                crate::cli_model::authorization_adapter::compare_git_coverage_floor_history_v1(
                    self, observer.controller_floor,
                ).map_err(|_| JournalError::ProtectedBoundary)?;
                observer.initial_issuance.compare_final(self)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            if let Some(cache) = observer.cache.as_ref() {
                cache.require_origin_v1(provision_origin(self, &witness))?;
            } else if let Some(catalog) = observer.fixed_cache_catalog.as_ref() {
                catalog.require_complete_v1(provision_origin(self, &witness))?;
            }
            Ok(observer)
        })();
        let bookend = require_bookend(self, &witness);
        let observer = match (result, bookend) {
            (Ok(observer), Ok(())) => observer,
            (Err(first), final_bookend) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first, final_bookend: final_bookend.err(),
                });
            }
            (Ok(_), Err(first)) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first, final_bookend: None,
                });
            }
        };

        let (transactions, records) = observer.prefix_data_v1().counts_v1();
        let last_commit = observer.prefix_data_v1().last_commit_v1();
        Ok(GitCoverageNativePrefixLoanV1 {
            journal: self,
            witness,
            prefix: observer.prefix_data_v1().prefix_digest_v1(),
            transactions,
            records,
            last_transaction: last_commit.map(|(transaction, _)| transaction),
            last_commit_sequence: last_commit.map(|(_, sequence)| sequence),
            ended: false,
            controller_account_seen: observer.publisher_account_seen,
            controller_floor_seen: observer.controller_floor.is_some(),
        })
    }
}

fn provision_origin(journal: &Journal, witness: &ProtectedWriterNameWitness) -> [u8; 32] {
    provision_origin_digest_v1(
        journal.native.protected_view().map(|location| location.name()),
        [witness.directory().physical_pair(), witness.file().physical_pair(), witness.lock().physical_pair()],
    )
}

fn require_bookend(
    journal: &Journal,
    witness: &ProtectedWriterNameWitness,
) -> Result<(), JournalError> {
    journal.ensure_healthy()?;
    journal.require_protected_names_current()?;
    journal.validate_protected_writer_name_witness(witness)?;
    if journal.native.file_identity::<crate::journal::JournalError>()? != witness.file() {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

fn require_replayed_snapshot(
    journal: &Journal,
    replayed: &ObservedReplayStateV1,
    observer: &mut NativePrefixObserverV1<'_>,
    physical_bytes: u64,
) -> Result<(), JournalError> {
    if let Some(cache) = observer.cache.as_mut() {
        if cache.finish_coordinates_v1(physical_bytes, journal.native.next_sequence(),
            journal.native.committed_transactions(), replayed.committed_records).is_err()
        {
            return Err(observer.take_cache_error_v1());
        }
    } else {
        observer.prefix.require_complete_v1(
            physical_bytes, journal.native.next_sequence(),
            journal.native.committed_transactions(), replayed.committed_records,
        )?;
    }
    if replayed.durable_end != physical_bytes
        || replayed.next_sequence != journal.native.next_sequence()
        || replayed.committed_transactions != journal.native.committed_transactions()
        || replayed.native.transaction_ids_data_v1() != journal.native.transaction_ids()
        || replayed.native.committed_namespaces_data_v1() != journal.native.committed_namespaces()
        || replayed.native.state_data_v1() != journal.native.state()
        || replayed.native.materialized_bytes_data_v1() != journal.native.materialized_bytes()
        || replayed.native.idempotency_data_v1() != journal.native.idempotency()
        || replayed.q04_lower_history_present != journal.q04_lower_history_present
        || replayed.source_history_compacted
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{has_durable_owner_fence_v1, require_original_source_cleanup_v1};
    use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};

    #[test]
    fn partial_owner_pair_remains_a_denial_not_absence() {
        let mut records = BTreeMap::new();
        assert!(!has_durable_owner_fence_v1(&records));

        records.insert(
            (RecordNamespace::DesiredState, b"z-git-birth-v1".to_vec()),
            Vec::new(),
        );
        assert!(has_durable_owner_fence_v1(&records));

        records.clear();
        records.insert(
            (RecordNamespace::DesiredState, b"z-git-fence-v1".to_vec()),
            Vec::new(),
        );
        assert!(has_durable_owner_fence_v1(&records));
    }

    #[test]
    fn foreign_namespace_and_near_prefix_are_not_owner_fences() {
        let records = BTreeMap::from([
            ((RecordNamespace::Effect, b"z-git-fence-v1".to_vec()), Vec::new()),
            ((RecordNamespace::DesiredState, b"z-git-fence-v1-extra".to_vec()), Vec::new()),
        ]);

        assert!(!has_durable_owner_fence_v1(&records));
    }

    #[test]
    fn partial_source_cleanup_cannot_delete_or_create_malformed_history() {
        let original = BTreeMap::new();
        let deletion = JournalTransaction::new([1; 16], vec![JournalRecord::delete(
            RecordNamespace::MountSourceAcquisition, b"unknown".to_vec(),
        )]).unwrap();
        let malformed = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition, b"unknown".to_vec(), vec![1],
        )]).unwrap();

        assert!(require_original_source_cleanup_v1(&original, &deletion).is_err());
        assert!(require_original_source_cleanup_v1(&original, &malformed).is_err());
    }
}

// Shared semantic predicates borrow the original path/name, never a supplied
// location or a second Journal constructed from historical DATA.
aos_sandbox_ledger_replay::define_provider_git_ordinary_data_recipe_v1!();
