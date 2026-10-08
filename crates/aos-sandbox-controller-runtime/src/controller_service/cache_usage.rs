//! Installed selected Cache initialization and borrowed project observations.
//!
//! This shares the existing executor and worker; it neither admits Git nor
//! fills the other project-account dimensions with zero.

use aos_sandbox::cache_residency::{CacheProjectUsageLoanV1, CacheResidentUnavailableV1};
use aos_sandbox_core::ProjectId;

use super::{ProductionController, ProductionEffectExecutor};
use super::publisher_policy_source::PublisherPolicyBootstrapAttemptV1;

impl ProductionEffectExecutor {
    #[cfg(target_os = "linux")]
    pub(super) fn capture_existing_git_coverage_account_cut(
        &mut self,
        journal: &mut aos_sandbox::Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let physical = self.cache_physical.as_ref().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.capture_existing_git_coverage_account_cut_v1(
            protected, physical, &mut self.source_domains, journal,
            original_inputs, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    pub(super) fn commit_existing_git_coverage_account(
        &mut self,
        journal: &mut aos_sandbox::Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let physical = self.cache_physical.as_ref().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.commit_existing_git_coverage_account_v1(
            protected, physical, &mut self.source_domains, journal,
            original_inputs, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    pub(super) fn compare_existing_cache_git_coverage(
        &mut self,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        flight: aos_sandbox_core::format::git_upload_enrollment::GitCoverageFlightV1,
        original_nonce: [u8; 16],
        mut original_account: Option<&mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), CacheResidentUnavailableV1> {
        use aos_sandbox_core::format::git_upload_enrollment::GitCoverageFlightV1;

        self.cache_mutation.require_completed_or_empty()?;
        if !self.cache_resident_usage.started() {
            self.cache_resident_usage.initialize_git_coverage_once(
                &mut self.cache_inventory, self.controller_uid, original_inputs,
            )?;
        }

        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        if original_account.is_some() {
            if !matches!(flight, GitCoverageFlightV1::Read) {
                return Err(CacheResidentUnavailableV1);
            }
            // The completed attempt is borrowed on both sides of every later
            // Read. None is never a fallback after its capture has started.
            // A failed Source comparison is already parked before this real
            // initializer performs its independent name/hold/clock checks.
            self.cache_resident_usage.bookend_existing_git_coverage_v1(
                protected, &mut self.source_domains, original_inputs,
                original_account.as_deref_mut(),
            )?;
        }
        let returned = (|| {
            self.cache_resident_usage.prepare_existing_physical_owner(
                protected, &mut self.cache_physical, self.node,
                super::CACHE_OWNER_MEMORY_BYTES,
            )?;
            let physical = self.cache_physical.as_ref().ok_or(CacheResidentUnavailableV1)?;

            match flight {
                GitCoverageFlightV1::Prepare => {
                    self.cache_resident_usage.enroll_empty_git_coverage_once_v1(
                        protected, physical, original_inputs, original_nonce,
                    )?;
                }
                GitCoverageFlightV1::Read => {}
            }
            self.cache_resident_usage.current_git_coverage_coordinates_v1(
                protected, physical, original_inputs,
            )
        })();

        // Actual action causes and native Results are resident before this
        // independent same-input/source/hold/clock bookend; debt stays distinct.
        let postchecked = self.cache_resident_usage.bookend_existing_git_coverage_v1(
            protected, &mut self.source_domains, original_inputs, original_account,
        );
        let coordinates = returned?;
        postchecked?;
        Ok(coordinates)
    }

    pub(super) fn observe_existing_cache_usage(
        &mut self,
        project: ProjectId,
    ) -> Result<CacheProjectUsageLoanV1<'_>, CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        if !self.cache_resident_usage.started() {
            self.cache_resident_usage.initialize_once(&mut self.cache_inventory, self.controller_uid)?;
        }
        let owner = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.recheck(owner)?;
        owner.observe_project_usage(project).map_err(|_| CacheResidentUnavailableV1)
    }
}

/// Bookends the real executor loan with the same original signed bootstrap.
pub(super) fn selected_bookend(
    controller: &mut ProductionController,
    bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
) -> Result<(), ()> {
    let project = bootstrap.current_cache_project(controller)?;
    let observed = {
        let returned = controller.existing_cache_project_usage_v1(project);
        // Borrowing ends before the Controller policy writer is borrowed again.
        // The checked quantities and actual replay failures stay in its owner.
        match returned {
            Ok(loan) => loan.partitions().is_some(),
            Err(_) => false,
        }
    };
    // The executor has already parked any actual action cause. Even failure
    // receives the independent original policy/time postcheck before return.
    let cache_postcheck = controller.recheck_existing_cache_project_usage_v1();
    let policy_postcheck = bootstrap.current_cache_project(controller);
    if !observed || cache_postcheck.is_err() || policy_postcheck != Ok(project) {
        return Err(());
    }
    Ok(())
}
