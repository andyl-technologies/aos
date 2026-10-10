//! Imports authenticated artifacts and creates campaigns through the same service.
//!
//! Each effect uses the retained repository, deployment policy and service mode.
//! A fixed original failure owner is admitted before the operation. Returned
//! identity values can be ambiguous on a late inner refusal; actual repository
//! publication remains retained by the enclosing service instead of being lost.

use super::*;

impl OriginalPreparedCampaignServiceOwner {
    pub(crate) fn verify_artifact_input(
        &self,
        decoder: &crucible_qemu::OriginalActorDecodeOwner,
        bytes: &[u8],
    ) -> Result<(), crucible_qemu::OriginalActorAccountError> {
        match &self.original {
            ServiceOriginal::Genuine(declaration) => {
                declaration.verify_decoder(decoder)?;
                declaration.verify_workflow_bytes(bytes)
            }
            #[cfg(test)]
            ServiceOriginal::Fixture(_) => {
                Err(crucible_qemu::OriginalActorAccountError::Unavailable)
            }
        }
    }

    pub(crate) fn verify_original(
        &self,
    ) -> Result<(), crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.original.verify()
    }

    /// Prepares the genuine factory from this retained service and external issuer.
    ///
    /// # Errors
    /// Preserves typed factory preparation failure before independent original
    /// posts. A late refusal drops the facade, whose Drop retains actual factory
    /// and external native custody rather than claiming physical cleanup.
    pub(crate) fn prepare_packaged_executor<'actor>(
        &self,
        issuer: &'actor mut crate::private_measurement_runtime::OriginalActorRoleIssuer,
        config: crate::PackagedQemuExecutorConfig,
    ) -> Result<
        crate::private_measurement_runtime::OriginalPreparedPackagedExecutor<'actor>,
        OriginalPreparedServiceError,
    > {
        self.artifact_operation(|service| {
            issuer
                .prepare_genuine_packaged_executor(service, config)
                .map_err(Into::into)
        })
    }

    pub(crate) fn import_configuration(
        &self,
        scenario: &crucible::ScenarioDefForm,
        schedule: &crucible::Schedule,
    ) -> Result<crucible_campaign::ConfigurationArtifactId, OriginalPreparedServiceError> {
        self.artifact_operation(|service| {
            service
                .import_configuration(scenario, schedule)
                .map_err(Into::into)
        })
    }

    pub(crate) fn import_generator(
        &self,
        generator: &crucible_campaign::CandidateGeneratorSpec,
    ) -> Result<crucible_campaign::CandidateGeneratorSpecId, OriginalPreparedServiceError> {
        self.artifact_operation(|service| service.import_generator(generator).map_err(Into::into))
    }

    pub(crate) fn create_campaign(
        &self,
        request: &crucible_campaign::CreateCampaignRequest,
    ) -> Result<crucible_campaign::CreateCampaignResponse, OriginalPreparedServiceError> {
        self.artifact_operation(|service| {
            // Use this actor's real inherited effective identity, rather than
            // constructing a peer credential or selecting a request principal.
            let identity = UnixPeerCampaignIdentity::new(
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            );
            if !service
                .policy
                .matches_identity(identity, request.principal())
            {
                return Err(CampaignAuthorizationError::Unauthorized.into());
            }
            let direct = crucible_campaign::RepositoryCampaignService::new(
                service.repository.as_ref(),
                CampaignLocalAuthorizer {
                    policy: Arc::clone(&service.policy),
                    mode: service.mode,
                },
            );
            let response = crucible_campaign::CampaignService::create_campaign(&direct, request)?;
            response.validate_for(request)?;
            Ok(response)
        })
    }

    fn artifact_operation<T>(
        &self,
        operation: impl FnOnce(&PreparedCampaignLocalService) -> Result<T, PreparedCause>,
    ) -> Result<T, OriginalPreparedServiceError> {
        let failure =
            PreparedFailurePurpose::prepare(&self.budget, || self.original.verify().err())?;
        let work = (|| {
            self.original.verify()?;
            self.budget.verify_live()?;
            let service = self.service.as_ref().ok_or(PreparedCause::Configuration)?;
            let _scope = self.budget.enter();
            let result = operation(service)?;
            self.budget.verify_live()?;
            Ok(result)
        })();
        reconcile(&self.original, failure, work)
    }
}
