//! Assembles the actual prepared service from its already-owned original parts.
//!
//! Construction never reopens state, policy, retention or journal namespaces.
//! Actual endpoint and identity buffers are admitted before allocation. The
//! original control loan remains outside the prepared service and every parent
//! owner retains its own control through final alias retirement. This stage
//! does not bind a socket or start workers.

use std::ffi::OsString;
use std::time::Duration;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};
use crucible_qemu::OriginalActorServiceLaunchPurpose;

use super::*;

mod artifacts;

#[cfg(test)]
mod tests;

const ENDPOINT: &str = "/run/crucible/measurement.sock";

pub(crate) struct OriginalPreparedCampaignServiceOwner {
    original: ServiceOriginal,
    service: Option<PreparedCampaignLocalService>,
    controls: Option<DecodeScratch>,
    budget: DecodeBudget,
    custody: DecodeCustody,
    closed: bool,
}

enum ServiceOriginal {
    Genuine(OriginalActorServiceLaunchPurpose),
    #[cfg(test)]
    Fixture(Arc<crucible_linux_resource::host_supervision::HostOperationGuard>),
}

impl ServiceOriginal {
    fn verify(
        &self,
    ) -> Result<(), crucible_linux_resource::host_supervision::HostSupervisionError> {
        match self {
            Self::Genuine(declaration) => declaration.verify_original(),
            #[cfg(test)]
            Self::Fixture(original) => original.wait_slice().map(|_| ()),
        }
    }
}

/// Retains a typed preparation refusal and its independently observed original cut.
#[derive(Debug, thiserror::Error)]
#[error("original prepared service refused: {failure}")]
pub struct OriginalPreparedServiceError {
    #[source]
    failure: PreparedFailure,
}

#[derive(Debug, thiserror::Error)]
enum PreparedFailure {
    #[error("failure storage admission refused: {source}; original: {original_after:?}")]
    Admission {
        #[source]
        source: DecodeAdmissionError,
        original_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
    #[error(transparent)]
    Retained(PreparedFailurePurpose),
}

// Storage is born before the operation. Declaration order frees its actual
// body before the external scratch receipt and original account custody.
struct PreparedFailurePurpose {
    data: Box<PreparedFailureData>,
    _credit: DecodeScratch,
    _custody: DecodeCustody,
}

#[derive(Debug)]
struct PreparedFailureData {
    source: Option<PreparedCause>,
    original_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
}

impl std::fmt::Debug for PreparedFailurePurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.data.fmt(formatter)
    }
}

impl std::fmt::Display for PreparedFailurePurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?}; original: {:?}",
            self.data.source, self.data.original_after
        )
    }
}

impl std::error::Error for PreparedFailurePurpose {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.data
            .source
            .as_ref()
            .map(|cause| cause as &dyn std::error::Error)
    }
}

impl PreparedFailurePurpose {
    fn prepare(
        budget: &DecodeBudget,
        original_after: impl FnOnce() -> Option<
            crucible_linux_resource::host_supervision::HostSupervisionError,
        >,
    ) -> Result<Self, OriginalPreparedServiceError> {
        let credit = budget
            .reserve_scratch_array::<PreparedFailureData>(1)
            .map_err(|source| OriginalPreparedServiceError {
                failure: PreparedFailure::Admission {
                    source,
                    original_after: original_after(),
                },
            })?;
        Ok(Self {
            data: Box::new(PreparedFailureData {
                source: None,
                original_after: None,
            }),
            _credit: credit,
            _custody: budget.custody(),
        })
    }

    fn refuse(
        mut self,
        source: PreparedCause,
        original_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    ) -> OriginalPreparedServiceError {
        self.data.source = Some(source);
        self.data.original_after = original_after;
        OriginalPreparedServiceError {
            failure: PreparedFailure::Retained(self),
        }
    }
}

impl OriginalPreparedServiceError {
    #[cfg(test)]
    fn is_admission(&self) -> bool {
        match &self.failure {
            PreparedFailure::Admission { .. } => true,
            PreparedFailure::Retained(purpose) => {
                matches!(purpose.data.source, Some(PreparedCause::Admission(_)))
            }
        }
    }

    #[cfg(test)]
    fn original_after(
        &self,
    ) -> Option<crucible_linux_resource::host_supervision::HostSupervisionError> {
        match &self.failure {
            PreparedFailure::Admission { original_after, .. } => *original_after,
            PreparedFailure::Retained(purpose) => purpose.data.original_after,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum PreparedCause {
    #[error("original service declaration refused: {0}")]
    Declaration(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
    #[error("original service credit refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    #[error("original prepared service refused: {0}")]
    Service(#[from] CampaignLocalServiceError),
    #[error("original packaged factory refused: {0}")]
    Packaged(#[from] crate::private_measurement_runtime::OriginalPackagedPreparationError),
    #[error("original repository refused: {0}")]
    Repository(#[from] StoreError),
    #[error("campaign request authorization refused: {0}")]
    Authorization(#[from] CampaignAuthorizationError),
    #[error("campaign creation refused: {0}")]
    Creation(#[from] crucible_campaign::RepositoryCampaignServiceError),
    #[error("canonical campaign response refused: {0}")]
    Codec(#[from] crucible_campaign::CampaignCodecError),
    #[error("original service allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("authenticated server configuration refused: {0}")]
    Server(#[from] crate::CampaignLoopbackServerConfigError),
    #[error("authenticated exchange timeout refused: {0}")]
    Timeout(#[from] crate::LoopbackCampaignProtocolError),
    #[error("authenticated endpoint refused: {0}")]
    Endpoint(#[from] LocalComponentEndpointError),
    #[error("authenticated service configuration is invalid")]
    Configuration,
}

impl OriginalPreparedCampaignServiceOwner {
    pub(crate) fn prepare(
        declaration: OriginalActorServiceLaunchPurpose,
        repository: &mut OriginalCampaignRepositoryBootstrap,
        state: PreparedCampaignStateOwner,
        policy: Arc<UnixPeerCampaignPolicy>,
        retention: Arc<crate::DirectoryHotCheckpointFallbackRetentionStore>,
        transfers: crate::DirectoryCampaignTransferJournal,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalPreparedServiceError> {
        let (server, mode) = configuration(&declaration, budget)?;
        Self::prepare_configured(
            (server, mode, ServiceOriginal::Genuine(declaration)),
            repository,
            state,
            policy,
            retention,
            transfers,
            budget,
        )
    }

    pub(crate) fn verify_declaration(
        declaration: &OriginalActorServiceLaunchPurpose,
        budget: &DecodeBudget,
    ) -> Result<(), OriginalPreparedServiceError> {
        configuration(declaration, budget).map(|_| ())
    }

    fn prepare_configured(
        (server, mode, original): (
            CampaignLoopbackServerConfig,
            CampaignLocalServiceMode,
            ServiceOriginal,
        ),
        repository: &mut OriginalCampaignRepositoryBootstrap,
        state: PreparedCampaignStateOwner,
        policy: Arc<UnixPeerCampaignPolicy>,
        retention: Arc<crate::DirectoryHotCheckpointFallbackRetentionStore>,
        transfers: crate::DirectoryCampaignTransferJournal,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalPreparedServiceError> {
        let failure = PreparedFailurePurpose::prepare(budget, || original.verify().err())?;
        let mut owner = Self {
            original,
            service: None,
            controls: None,
            budget: budget.clone(),
            custody: budget.custody(),
            closed: false,
        };
        let work = (|| {
            budget.verify_live()?;
            let identity = state.transfer_identity()?;
            let bytes = ENDPOINT
                .len()
                .checked_add(identity.len())
                .ok_or(PreparedCause::Configuration)?;
            owner.controls = Some(budget.reserve_scratch_bytes(bytes as u64)?);
            let mut endpoint = OsString::new();
            endpoint.try_reserve_exact(ENDPOINT.len())?;
            endpoint.push(ENDPOINT);
            let endpoint =
                CampaignLoopbackEndpointConfig::new(PathBuf::from(endpoint), 0, 0, 0o600)?;
            let mut transfer_identity = String::new();
            transfer_identity.try_reserve_exact(identity.len())?;
            transfer_identity.push_str(identity);
            let (repository, maintenance, planner_authority) = repository.share_for_service()?;
            // Move all actual aliases into accessible ownership before the
            // fallible original postcut. No namespace or socket is reopened.
            owner.service = Some(PreparedCampaignLocalService {
                endpoint,
                server,
                repository,
                planner_authority,
                policy,
                mode,
                state,
                maintenance,
                maintenance_config: None,
                runtime_control_planner: None,
                campaign_debug_lifecycle: None,
                hot_fork_retention: retention,
                transfer_journal: transfers,
                transfer_identity,
            });
            #[cfg(test)]
            tests::after_publication();
            budget.verify_live()?;
            Ok(())
        })();
        reconcile(&owner.original, failure, work)?;
        Ok(owner)
    }

    pub(crate) fn try_close(&mut self) -> Result<(), OriginalPreparedServiceError> {
        if self.closed {
            return Ok(());
        }
        let failure =
            PreparedFailurePurpose::prepare(&self.budget, || self.original.verify().err())?;
        let work = (|| {
            self.budget.check()?;
            self.budget.verify_live()?;
            drop(self.service.take());
            self.budget.verify_live()?;
            Ok(())
        })();
        reconcile(&self.original, failure, work)?;
        drop(self.controls.take());
        self.closed = true;
        Ok(())
    }
}

impl Drop for OriginalPreparedCampaignServiceOwner {
    fn drop(&mut self) {
        if !self.closed {
            // An error or unwind cannot refund buffers while the actual
            // prepared owner or any of its authority aliases may survive.
            std::mem::forget(self.service.take());
            std::mem::forget(self.controls.take());
            std::mem::forget(self.budget.clone());
            std::mem::forget(self.custody.clone());
        }
    }
}

fn reconcile<T>(
    original: &ServiceOriginal,
    failure: PreparedFailurePurpose,
    work: Result<T, PreparedCause>,
) -> Result<T, OriginalPreparedServiceError> {
    let after = original.verify();
    match (work, after) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(source), after) => Err(failure.refuse(source, after.err())),
        (Ok(_), Err(source)) => Err(failure.refuse(PreparedCause::Declaration(source), None)),
    }
}

fn configuration(
    declaration: &OriginalActorServiceLaunchPurpose,
    budget: &DecodeBudget,
) -> Result<(CampaignLoopbackServerConfig, CampaignLocalServiceMode), OriginalPreparedServiceError>
{
    let failure = PreparedFailurePurpose::prepare(budget, || declaration.verify_original().err())?;
    let configuration = (|| {
        budget.verify_live()?;
        declaration.verify_original()?;
        let (workers, pending, requests, poll, read, write) = declaration.server_declarations();
        let timeouts = crate::LoopbackCampaignTimeouts::new(
            Duration::from_millis(read),
            Duration::from_millis(write),
        )?;
        let server = CampaignLoopbackServerConfig::new(
            workers,
            pending,
            requests,
            Duration::from_millis(poll),
            timeouts,
        )?;
        let mode = if declaration.is_read_only() {
            CampaignLocalServiceMode::ReadOnly
        } else {
            CampaignLocalServiceMode::ReadWrite
        };
        Ok((server, mode))
    })();
    match configuration {
        Ok(configuration) => Ok(configuration),
        Err(source) => Err(failure.refuse(source, declaration.verify_original().err())),
    }
}
