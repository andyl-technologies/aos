//! Orchestrates Git Controller/Source work around genuine native Cache loans.
//!
//! Cache owns its writers, Clock, native cuts and independent native posts.
//! This upper programme retains the actual Controller/Source operation and
//! policy attempt, including their owning failures and precise effect order.

use aos_sandbox_broker::systemd_credentials::{
    GitCoverageCredentialCustodyV1, PublisherPolicyBootstrapCredentialCustodyV1,
};
use aos_sandbox_cache::{
    CacheGitOperationOriginalV1, CacheResidentInitializationV1 as NativeCacheInitializationV1, CacheResidentUnavailableV1,
    CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
};
use aos_sandbox_model::format::git_upload_enrollment::GitCoverageCatalogV1;

use crate::Journal;
use crate::policy_compiler::GitCoverageAccountAttemptV1;
use crate::publisher_admin::policy::{
    GitUploadBootstrapAppendV1, VerifiedPublisherPolicySourceV1,
};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

/// Runs upper Git programmes while the native Cache original remains borrowed.
pub trait CacheResidentGitCoverageExtV1 {
    /// Runs Controller metadata and the fixed Cache Clock commit in order.
    ///
    /// # Errors
    /// Preserves original native/operation causes and independent Source,
    /// credential, Cache names, Clock and Controller post failures.
    fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        operation: &mut crate::reconciler::GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), CacheResidentUnavailableV1>;

    /// Captures the original Source, native Cache and Controller account cut.
    ///
    /// # Errors
    /// Preserves genuine Source, Bootstrap, Cache and Controller cut failures
    /// before every independently owed post observation.
    fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &GitUploadBootstrapAppendV1,
        original_source: &VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1>;

    /// Commits the covered successor under the same native Cache Clock fence.
    ///
    /// # Errors
    /// Preserves changed originals, failed exact predecessors and every
    /// independent Source, Cache, credential and Clock post failure.
    fn commit_existing_git_coverage_account_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &GitUploadBootstrapAppendV1,
        original_source: &VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1>;

    /// Bookends an existing read with its same completed Source/account attempt.
    ///
    /// # Errors
    /// Retains failed Source comparison before independent native Cache and
    /// credential posts, and refuses missing account custody after capture.
    fn bookend_existing_git_coverage_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_account: Option<&mut GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(), CacheResidentUnavailableV1>;
}

#[derive(Clone, Copy)]
enum InputFrontier {
    Primary,
    Post,
}

fn catalog<'inputs>(
    loan: &mut CacheGitOperationOriginalV1<'_, '_>,
    inputs: &'inputs GitCoverageCredentialCustodyV1,
    frontier: InputFrontier,
) -> Result<GitCoverageCatalogV1<'inputs>, CacheResidentUnavailableV1> {
    let Some(data) = inputs.ready() else {
        match frontier {
            InputFrontier::Primary => loan.refuse_upper_input_primary_v1(),
            InputFrontier::Post => loan.refuse_upper_input_post_v1(),
        }
        return Err(CacheResidentUnavailableV1);
    };
    GitCoverageCatalogV1::decode(data.catalog()).map_err(|cause| {
        match frontier {
            InputFrontier::Primary => loan.reject_coverage_data_v1(cause),
            InputFrontier::Post => loan.reject_coverage_data_post_v1(cause),
        }
        CacheResidentUnavailableV1
    })
}

impl CacheResidentGitCoverageExtV1 for NativeCacheInitializationV1 {
    fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        operation: &mut crate::reconciler::GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let mut loan = self.begin_git_read_metadata_v1(owner, physical, original_inputs)?;
        let returned = (|| {
            loan.require_credential_inputs_v1(original_inputs)?;
            operation.compare_source(source_domains, original_inputs)
                .map_err(|_| CacheResidentUnavailableV1)?;
            let catalog = catalog(&mut loan, original_inputs, InputFrontier::Primary)?;
            let sampled = match operation.prepare(controller, &catalog) {
                Ok(Some(sampled)) => sampled,
                Ok(None) => return Ok(()),
                Err(cause) => {
                    operation.refuse(cause);
                    return Err(CacheResidentUnavailableV1);
                }
            };
            let seconds = u64::try_from(sampled.wall_seconds())
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.prepare_read_metadata_v1(seconds)?;
            operation.compare_source(source_domains, original_inputs)
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.require_credential_inputs_v1(original_inputs)?;
            if let Err(cause) = operation.check_original_crossing() {
                operation.refuse(cause);
                return Err(CacheResidentUnavailableV1);
            }
            loan.commit_read_metadata_v1()?;
            if let Err(cause) = operation.commit_and_evaluate(controller) {
                operation.refuse(cause);
                return Err(CacheResidentUnavailableV1);
            }
            Ok(())
        })();
        if returned.is_err() {
            loan.refuse_upper_primary_v1();
        }

        if operation.compare_source(source_domains, original_inputs).is_err() {
            loan.refuse_upper_post_v1();
        }
        let _ = loan.observe_credential_inputs_v1(original_inputs);
        let _ = loan.observe_bootstrap_v1();
        let _ = loan.observe_original_hold_v1();
        let _ = loan.observe_native_names_v1();
        let _ = loan.observe_current_time_v1();
        let _ = loan.observe_clock_witness_v1();
        if operation.postcheck().is_err() {
            loan.refuse_upper_post_v1();
        }
        loan.finish_v1()
    }

    fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &GitUploadBootstrapAppendV1,
        original_source: &VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let mut loan = self.begin_git_account_capture_v1(owner, physical, original_inputs)?;
        let returned = (|| {
            loan.require_credential_inputs_v1(original_inputs)?;
            if original_bootstrap_credentials.recheck().is_err() {
                loan.refuse_upper_input_primary_v1();
                return Err(CacheResidentUnavailableV1);
            }
            let catalog = catalog(&mut loan, original_inputs, InputFrontier::Primary)?;
            attempt.capture_original_source_cut_v1(source_domains, original_inputs)
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.require_bootstrap_available_v1()?;
            attempt.capture_cache_bootstrap_cut(&mut loan, &catalog)
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.require_original_hold_v1()?;
            attempt.park_original_cache_cuts(loan.capture_native_cuts_v1(&catalog))
                .map_err(|_| CacheResidentUnavailableV1)?;
            let seconds = loan.current_seconds_v1()?;
            loan.require_signed_time_v1(seconds)?;
            let now = i64::try_from(seconds).map_err(|_| {
                loan.refuse_upper_input_primary_v1();
                CacheResidentUnavailableV1
            })?;
            attempt.capture_controller_account_cut(
                controller, original_inputs, original_bootstrap, original_source,
                original_capacity, original_bootstrap_credentials, now,
            ).map_err(|_| CacheResidentUnavailableV1)
        })();
        if returned.is_err() {
            loan.refuse_upper_primary_v1();
        }

        if attempt.compare_original_source_cut(source_domains, original_inputs).is_err() {
            loan.refuse_upper_post_v1();
        }
        let _ = loan.observe_bootstrap_v1();
        let local_post = (|| {
            loan.observe_credential_inputs_v1(original_inputs)?;
            loan.observe_required_original_hold_v1()?;
            loan.observe_native_names_v1()?;
            original_bootstrap_credentials.recheck().map_err(|_| {
                loan.refuse_upper_input_post_v1();
                CacheResidentUnavailableV1
            })?;
            Ok::<(), CacheResidentUnavailableV1>(())
        })();
        let _ = local_post;
        let _ = loan.observe_current_time_v1();
        let _ = loan.observe_clock_witness_v1();
        loan.finish_v1()?;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)
    }

    fn commit_existing_git_coverage_account_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &DormantCacheOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &GitUploadBootstrapAppendV1,
        original_source: &VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let mut loan = self.begin_git_account_commit_v1(owner, physical, original_inputs)?;
        let returned = (|| {
            loan.require_credential_inputs_v1(original_inputs)?;
            if original_bootstrap_credentials.recheck().is_err() {
                loan.refuse_upper_input_primary_v1();
                return Err(CacheResidentUnavailableV1);
            }
            let catalog = catalog(&mut loan, original_inputs, InputFrontier::Primary)?;
            attempt.compare_original_source_cut(source_domains, original_inputs)
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.require_bootstrap_available_v1()?;
            attempt.compare_cache_bootstrap_cut(&mut loan, &catalog)
                .map_err(|_| CacheResidentUnavailableV1)?;
            loan.require_original_hold_v1()?;
            attempt.compare_original_cache_cuts(loan.capture_native_cuts_v1(&catalog))
                .map_err(|_| CacheResidentUnavailableV1)?;
            let seconds = loan.current_seconds_v1()?;
            loan.require_signed_time_v1(seconds)?;
            let now = i64::try_from(seconds).map_err(|_| {
                loan.refuse_upper_input_primary_v1();
                CacheResidentUnavailableV1
            })?;
            attempt.commit_controller_account(
                controller, original_inputs, original_bootstrap, original_source,
                original_capacity, original_bootstrap_credentials, now,
            ).map_err(|_| CacheResidentUnavailableV1)
        })();
        if returned.is_err() {
            loan.refuse_upper_primary_v1();
        }

        if attempt.compare_original_source_cut(source_domains, original_inputs).is_err() {
            loan.refuse_upper_post_v1();
        }
        let local_post = (|| {
            loan.observe_credential_inputs_v1(original_inputs)?;
            let catalog = catalog(&mut loan, original_inputs, InputFrontier::Post)?;
            loan.observe_bootstrap_available_v1()?;
            attempt.compare_cache_bootstrap_cut(&mut loan, &catalog)
                .map_err(|_| {
                    loan.refuse_upper_post_v1();
                    CacheResidentUnavailableV1
                })?;
            loan.observe_required_original_hold_v1()?;
            attempt.compare_original_cache_cuts(loan.capture_native_cuts_v1(&catalog))
                .map_err(|_| {
                    loan.refuse_upper_post_v1();
                    CacheResidentUnavailableV1
                })?;
            original_bootstrap_credentials.recheck().map_err(|_| {
                loan.refuse_upper_input_post_v1();
                CacheResidentUnavailableV1
            })?;
            let seconds = loan.observe_seconds_v1()?;
            loan.observe_signed_time_v1(seconds)?;
            Ok::<(), CacheResidentUnavailableV1>(())
        })();
        let _ = local_post;
        let _ = loan.observe_clock_witness_v1();
        loan.finish_v1()?;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)
    }

    fn bookend_existing_git_coverage_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_account: Option<&mut GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let source_checked = match original_account {
            Some(attempt) if self.git_account_capture_started_v1() => {
                attempt.compare_completed_original_source_cut(source_domains, original_inputs)
            }
            None if !self.git_account_capture_started_v1() => Ok(()),
            _ => Err(()),
        };
        let cache_checked = self.recheck_git_coverage(owner, original_inputs);
        if source_checked.is_err() {
            self.refuse_git_account_bookend_v1();
        }
        source_checked.map_err(|_| CacheResidentUnavailableV1)?;
        cache_checked
    }
}

pub(crate) mod initialization;
pub use initialization::{CacheResidentInitializationV1, CacheDeleteInventoryOriginalV1, CacheDeleteInventoryQueryV1};

#[cfg(target_os = "linux")]
pub(crate) use initialization::original_q04::{OriginalQ04CacheClearanceLoanV1, OriginalQ04CacheOwnerCutV1};
#[cfg(target_os = "linux")]
pub(crate) use initialization::q04_capture_pricing::{OriginalQ04CachePreflightLoanV1, OriginalQ04CacheCaptureShapeV1};

#[cfg(target_os = "linux")]
pub(crate) use initialization::create_storage::{OriginalCreateStorageCacheLoanV1, CacheReleasedOriginalsV1, CacheReleasedCurrentnessSiteV1};
