//! Spans upper Git programmes with the same actual Cache Clock and writers.
//!
//! Domain retains Controller, Source and request error ownership. This finite
//! borrower retains Cache's private Clock fence, its original four native cuts
//! and independent Cache posts at the original upper frontiers. No callback,
//! Journal, mutex, descriptor or replaceable Clock is exposed.

use aos_sandbox_protocol::git_project_coverage::GitCoverageNativeCutDataV1;

use super::*;

#[derive(Clone, Copy)]
enum GitOperation {
    ReadMetadata,
    CaptureAccount,
    CommitAccount,
}

/// Borrows the actual Cache originals across a fixed upper Git programme.
///
/// Construction is available only through the initialized native Cache owner.
/// The borrower cannot select a Root phase, mutate Source or grant funding.
pub struct CacheGitOperationOriginalV1<'cache, 'owner> {
    mode: GitOperation,
    clock: CacheClockWriterReadbackGuard<'cache>,
    owner: &'owner mut CacheResidencyProtectedOwnerV1,
    source: &'cache mut Option<CacheReplayControllerBootstrapOwnerV1>,
    hold: &'cache mut Option<(Journal, RecoveryReport)>,
    inputs: Option<CacheGitCoverageInputsV1>,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    original_coverage: Option<Option<CacheGitCoverageObservationV1>>,
    read_metadata: &'cache mut CacheClockReadMetadataProgressV1,
    read_metadata_active: &'cache mut bool,
    first: &'cache mut Option<InitializationCauseV1>,
    post: &'cache mut Option<InitializationCauseV1>,
    complete: &'cache mut bool,
}

impl CacheResidentInitializationV1 {
    /// Borrows the fixed native Cache interval for a metadata read crossing.
    ///
    /// # Errors
    /// Refuses earlier uncertainty, changed originals, residual state or a
    /// failed acquisition of this same initialized Clock's writer fence.
    pub fn begin_git_read_metadata_v1<'cache, 'owner>(
        &'cache mut self,
        owner: &'owner mut CacheResidencyProtectedOwnerV1,
        physical: &crate::DormantCacheOwnerV1,
        credentials: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<CacheGitOperationOriginalV1<'cache, 'owner>, CacheResidentUnavailableV1> {
        self.begin_git_operation_v1(owner, physical, credentials, GitOperation::ReadMetadata)
    }

    /// Borrows the once-only native Cache interval for account capture.
    ///
    /// # Errors
    /// Permanently refuses repeated capture, residual state, changed original
    /// writers or a failed acquisition of the same Clock fence.
    pub fn begin_git_account_capture_v1<'cache, 'owner>(
        &'cache mut self,
        owner: &'owner mut CacheResidencyProtectedOwnerV1,
        physical: &crate::DormantCacheOwnerV1,
        credentials: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<CacheGitOperationOriginalV1<'cache, 'owner>, CacheResidentUnavailableV1> {
        self.begin_git_operation_v1(owner, physical, credentials, GitOperation::CaptureAccount)
    }

    /// Borrows the native Cache interval for committing the original account.
    ///
    /// # Errors
    /// Refuses residual state, failed prior work, changed original writers or
    /// a failed acquisition of the same Clock fence.
    pub fn begin_git_account_commit_v1<'cache, 'owner>(
        &'cache mut self,
        owner: &'owner mut CacheResidencyProtectedOwnerV1,
        physical: &crate::DormantCacheOwnerV1,
        credentials: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<CacheGitOperationOriginalV1<'cache, 'owner>, CacheResidentUnavailableV1> {
        self.begin_git_operation_v1(owner, physical, credentials, GitOperation::CommitAccount)
    }

    fn begin_git_operation_v1<'cache, 'owner>(
        &'cache mut self,
        owner: &'owner mut CacheResidencyProtectedOwnerV1,
        physical: &crate::DormantCacheOwnerV1,
        credentials: &mut GitCoverageCredentialCustodyV1,
        mode: GitOperation,
    ) -> Result<CacheGitOperationOriginalV1<'cache, 'owner>, CacheResidentUnavailableV1> {
        match mode {
            GitOperation::ReadMetadata => {
                if self.read_metadata_active || self.read_metadata.failure().is_some()
                    || self.failure().is_some() || !self.complete
                {
                    return Err(CacheResidentUnavailableV1);
                }
            }
            GitOperation::CaptureAccount => {
                if self.coverage_account_capture_started {
                    self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
                    return Err(CacheResidentUnavailableV1);
                }
                self.coverage_account_capture_started = true;
            }
            GitOperation::CommitAccount => {}
        }
        self.audit_empty_git_coverage_v1(owner, physical, credentials)?;
        match mode {
            GitOperation::ReadMetadata => {
                self.read_metadata_active = true;
                self.read_metadata = CacheClockReadMetadataProgressV1::default();
            }
            GitOperation::CaptureAccount | GitOperation::CommitAccount => {
                self.complete = false;
            }
        }
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        Ok(CacheGitOperationOriginalV1 {
            mode,
            clock: guard,
            owner,
            source: &mut self.source,
            hold: &mut self.hold,
            inputs: self.coverage_inputs,
            original_hold: self.original_hold,
            original_coverage: self.original_coverage,
            read_metadata: &mut self.read_metadata,
            read_metadata_active: &mut self.read_metadata_active,
            first: &mut self.first_failure,
            post: &mut self.postcheck,
            complete: &mut self.complete,
        })
    }

    /// Reports whether this same initializer has entered account capture.
    ///
    /// This is a local programme disposition, not account or effect authority.
    #[must_use]
    pub const fn git_account_capture_started_v1(&self) -> bool {
        self.coverage_account_capture_started
    }

    /// Permanently records the upper Source/account programme's refusal.
    pub fn refuse_git_account_bookend_v1(&mut self) {
        self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
        self.complete = false;
    }
}

impl CacheGitOperationOriginalV1<'_, '_> {
    fn marker(&self) -> InitializationCauseV1 {
        match self.mode {
            GitOperation::ReadMetadata => InitializationCauseV1::ReadMetadata,
            GitOperation::CaptureAccount | GitOperation::CommitAccount => {
                InitializationCauseV1::CoverageAppend
            }
        }
    }

    fn primary<T>(
        &mut self,
        returned: Result<T, InitializationCauseV1>,
    ) -> Result<T, CacheResidentUnavailableV1> {
        returned.map_err(|cause| {
            self.first.get_or_insert(cause);
            *self.complete = false;
            CacheResidentUnavailableV1
        })
    }

    fn observe(
        &mut self,
        returned: Result<(), InitializationCauseV1>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        returned.map_err(|cause| {
            self.post.get_or_insert(cause);
            CacheResidentUnavailableV1
        })
    }

    /// Checks the same genuine Controller credential owner before an action.
    ///
    /// # Errors
    /// Retains changed role, named credential or signed input comparisons.
    pub fn require_credential_inputs_v1(
        &mut self,
        credentials: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let returned = CacheResidentInitializationV1::require_same_coverage_inputs(
            self.inputs, credentials,
        );
        self.primary(returned)
    }

    /// Records the independent original credential post at its upper frontier.
    ///
    /// # Errors
    /// Retains changed role, named credential or signed input comparisons.
    pub fn observe_credential_inputs_v1(
        &mut self,
        credentials: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let returned = CacheResidentInitializationV1::require_same_coverage_inputs(
            self.inputs, credentials,
        );
        self.observe(returned)
    }

    /// Preflights the fixed Clock proposal after Controller preparation.
    ///
    /// # Errors
    /// Retains invalid signed time bounds and the actual native Clock preflight.
    pub fn prepare_read_metadata_v1(
        &mut self,
        seconds: u64,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let bounded = self.inputs
            .filter(|inputs| seconds >= inputs.issued_seconds && seconds < inputs.expires_seconds)
            .ok_or(InitializationCauseV1::CoverageInputs).map(|_| ());
        self.primary(bounded)?;
        let returned = self.clock.prepare_git_read_metadata(self.read_metadata, seconds);
        if returned.is_err() {
            let marker = self.marker();
            self.first.get_or_insert(marker);
            *self.complete = false;
        }
        returned
    }

    /// Commits the original Clock proposal before Controller's durable crossing.
    ///
    /// # Errors
    /// Retains the actual native commit, exact readback and later witness.
    pub fn commit_read_metadata_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.clock.commit_git_read_metadata(self.read_metadata);
        if returned.is_err() {
            let marker = self.marker();
            self.first.get_or_insert(marker);
            *self.complete = false;
        }
        returned
    }

    /// Retains the original canonical Git input decoding cause.
    ///
    /// The upper programme supplies the actual decoding error, not a grant or
    /// success marker. The first native cause remains in this Cache original.
    pub fn reject_coverage_data_v1(&mut self, cause: GitCoverageDataErrorV1) {
        self.first.get_or_insert(InitializationCauseV1::CoverageData(cause));
        *self.complete = false;
    }

    /// Retains the independent original canonical Git input decoding refusal.
    pub fn reject_coverage_data_post_v1(&mut self, cause: GitCoverageDataErrorV1) {
        self.post.get_or_insert(InitializationCauseV1::CoverageData(cause));
    }

    /// Requires the original Bootstrap before entering an upper attempt step.
    ///
    /// # Errors
    /// Retains the same absent-original refusal before the upper phase check.
    pub fn require_bootstrap_available_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.source.as_ref().map(|_| ()).ok_or(InitializationCauseV1::Closed);
        self.primary(returned)
    }

    /// Requires the original Bootstrap at the independent upper post frontier.
    ///
    /// # Errors
    /// Retains the same absent-original refusal before the upper comparison.
    pub fn observe_bootstrap_available_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.source.as_ref().map(|_| ()).ok_or(InitializationCauseV1::Closed);
        self.observe(returned)
    }

    /// Permanently records an upper action refusal whose owner retains its cause.
    pub fn refuse_upper_primary_v1(&mut self) {
        let marker = self.marker();
        self.first.get_or_insert(marker);
        *self.complete = false;
    }

    /// Retains an independent upper post refusal without replacing the primary.
    pub fn refuse_upper_post_v1(&mut self) {
        let marker = self.marker();
        self.post.get_or_insert(marker);
    }

    /// Records a refused signed-input comparison owned by the upper programme.
    pub fn refuse_upper_input_primary_v1(&mut self) {
        self.first.get_or_insert(InitializationCauseV1::CoverageInputs);
        *self.complete = false;
    }

    /// Records an independent upper signed-input post refusal.
    pub fn refuse_upper_input_post_v1(&mut self) {
        self.post.get_or_insert(InitializationCauseV1::CoverageInputs);
    }

    /// Rechecks the original fixed CacheBootstrap writer independently.
    ///
    /// # Errors
    /// Retains its actual native/name refusal in the original Cache post slot.
    pub fn observe_bootstrap_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = match self.source.as_mut() {
            Some(source) => source.recheck_existing().map_err(Into::into),
            None => Ok(()),
        };
        self.observe(returned)
    }

    fn hold_result(&mut self) -> Result<(), InitializationCauseV1> {
        match self.hold.as_mut() {
            Some((hold, _)) => require_original_hold(
                hold, self.original_hold, self.inputs, self.original_coverage,
            ),
            None => Err(InitializationCauseV1::Closed),
        }
    }

    /// Checks the original Hold immediately before the fixed native cut.
    ///
    /// # Errors
    /// Retains the original hold, Git fence or native custody mismatch.
    pub fn require_original_hold_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.hold_result();
        self.primary(returned)
    }

    /// Records the independent original Hold observation.
    ///
    /// # Errors
    /// Retains changed held custody or the original Git denial fence.
    pub fn observe_original_hold_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = if self.hold.is_some() { self.hold_result() } else { Ok(()) };
        self.observe(returned)
    }

    /// Requires the original Hold within an ordered independent post group.
    ///
    /// # Errors
    /// Retains absent custody or the changed original Hold/Git comparison.
    pub fn observe_required_original_hold_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.hold_result();
        self.observe(returned)
    }

    /// Rechecks State and Authority names in their original order.
    ///
    /// # Errors
    /// Retains absent originals or changed native names, owner or limits.
    pub fn observe_native_names_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = (|| {
            let state = self.owner.state_journal.as_ref()
                .ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(
                state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                self.owner.owner_uid, cache_state_journal_limits(),
            )?;
            self.owner.authority.check_named_location(|journal| {
                require_cache_named_writer(
                    journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                    self.owner.owner_uid, cache_authority_journal_limits(),
                )
            })?;
            Ok(())
        })();
        self.observe(returned)
    }

    /// Samples the same private Clock without reopening it.
    ///
    /// # Errors
    /// Retains changed original custody or nonmonotone protected time.
    pub fn current_seconds_v1(&mut self) -> Result<u64, CacheResidentUnavailableV1> {
        let returned = self.clock.current_unix_seconds().map_err(Into::into);
        self.primary(returned)
    }

    /// Compares a sampled time with the original signed credential interval.
    ///
    /// # Errors
    /// Refuses missing input custody or a sample outside the original interval.
    pub fn require_signed_time_v1(&mut self, seconds: u64) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.inputs
            .filter(|inputs| seconds >= inputs.issued_seconds && seconds < inputs.expires_seconds)
            .ok_or(InitializationCauseV1::CoverageInputs).map(|_| ());
        self.primary(returned)
    }

    /// Samples the same private Clock within an ordered independent post group.
    ///
    /// # Errors
    /// Retains changed original custody or nonmonotone protected time.
    pub fn observe_seconds_v1(&mut self) -> Result<u64, CacheResidentUnavailableV1> {
        self.clock.current_unix_seconds().map_err(|cause| {
            self.post.get_or_insert(cause.into());
            CacheResidentUnavailableV1
        })
    }

    /// Compares the original signed interval within an independent post group.
    ///
    /// # Errors
    /// Retains missing original inputs or an out-of-interval post sample.
    pub fn observe_signed_time_v1(&mut self, seconds: u64) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.inputs
            .filter(|inputs| seconds >= inputs.issued_seconds && seconds < inputs.expires_seconds)
            .ok_or(InitializationCauseV1::CoverageInputs).map(|_| ());
        self.observe(returned)
    }

    /// Records the independent same-Clock signed-time observation.
    ///
    /// # Errors
    /// Retains changed original Clock custody or an expired signed interval.
    pub fn observe_current_time_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.clock.current_unix_seconds().and_then(|seconds| {
            let inputs = self.inputs.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if seconds < inputs.issued_seconds || seconds >= inputs.expires_seconds {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            Ok(())
        }).map_err(Into::into);
        self.observe(returned)
    }

    /// Records the independently owed final original Clock witness.
    ///
    /// # Errors
    /// Retains changed protected names, native identity or the same writer fence.
    pub fn observe_clock_witness_v1(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let returned = self.clock.revalidate().map_err(Into::into);
        self.observe(returned)
    }

    /// Observes the fixed CacheBootstrap cut under this same native interval.
    ///
    /// # Errors
    /// Returns the actual Bootstrap primary and independent native/name debt.
    pub fn capture_bootstrap_cut_v1(
        &mut self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<GitCoverageNativeCutDataV1, CacheReplayControllerBootstrapErrorV1> {
        self.source.as_mut().ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?
            .capture_git_coverage_native_cut_v1(catalog)
    }

    /// Observes Authority, State, Hold and Clock in their original cut order.
    ///
    /// # Errors
    /// Returns the actual first native failure with its separate owed bookend.
    pub fn capture_native_cuts_v1(
        &mut self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<Vec<GitCoverageNativeCutDataV1>, CacheResidencyProtectedJournalErrorV1> {
        let hold = self.hold.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let state = self.owner.state_journal.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        require_cache_named_writer(
            state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
            self.owner.owner_uid, cache_state_journal_limits(),
        )?;
        let mut cuts = Vec::with_capacity(4);
        self.owner.authority.check_named_location(|journal| {
            require_cache_named_writer(
                journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                self.owner.owner_uid, cache_authority_journal_limits(),
            )?;
            let mut native = journal.cache_authority_coverage_native_prefix_v1(catalog)
                .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
            native.recheck()?;
            cuts.push(aos_sandbox_protocol::git_coverage_native_cut_data_v1! {
                profile: GitCoverageJournalProfileV1::CacheAuthority,
                loan: native
            });
            Ok(())
        })?;
        let mut native = state.cache_state_coverage_native_prefix_v1(catalog)
            .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
        native.recheck()?;
        cuts.push(aos_sandbox_protocol::git_coverage_native_cut_data_v1! {
            profile: GitCoverageJournalProfileV1::CacheState,
            loan: native
        });
        drop(native);

        let mut native = hold.0.cache_hold_coverage_native_prefix_v1(catalog)
            .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
        native.recheck()?;
        cuts.push(aos_sandbox_protocol::git_coverage_native_cut_data_v1! {
            profile: GitCoverageJournalProfileV1::CachePolicyHold,
            loan: native
        });
        drop(native);
        cuts.push(self.clock.capture_git_coverage_native_cut_v1(catalog)?);
        Ok(cuts)
    }

    /// Releases the same Clock fence before updating completion disposition.
    ///
    /// # Errors
    /// Permanently refuses any retained primary or independent post failure.
    /// This does not perform the upper programme's final empty-owner audit.
    pub fn finish_v1(self) -> Result<(), CacheResidentUnavailableV1> {
        let Self {
            mode, clock, read_metadata_active, first, post, complete, ..
        } = self;
        drop(clock);
        if first.is_some() || post.is_some() {
            *complete = false;
            if matches!(mode, GitOperation::CaptureAccount) {
                post.get_or_insert(InitializationCauseV1::CoverageAppend);
            }
            return Err(CacheResidentUnavailableV1);
        }
        match mode {
            GitOperation::ReadMetadata => *read_metadata_active = false,
            GitOperation::CaptureAccount | GitOperation::CommitAccount => *complete = true,
        }
        Ok(())
    }
}
