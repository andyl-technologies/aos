//! Authorization and runtime-control doubles shared by loopback tests.

use super::*;

pub(super) struct DenyAll;

impl CampaignPrincipalAuthorizer for DenyAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Err(crucible_campaign::CampaignAuthorizationError::Unauthorized)
    }
}

pub(super) struct AllowAll;

impl CampaignPrincipalAuthorizer for AllowAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Ok(())
    }
}

pub(super) struct RecordingPeerResolver {
    pub(super) observed: mpsc::Sender<UnixPeerCampaignCredentials>,
}

pub(super) struct RecordingRuntimeControl {
    pub(super) calls: Arc<AtomicUsize>,
}

impl CampaignRuntimeControlService for RecordingRuntimeControl {
    fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, CampaignServiceFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        AttachCampaignRuntimeResponse::new(
            request,
            CampaignRuntimeAttachmentDisposition::Attached,
            1,
        )
        .map_err(|_| CampaignServiceFailure::IntegrityFailure)
    }
}

impl UnixPeerCampaignPrincipalResolver for RecordingPeerResolver {
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, crucible_campaign::CampaignAuthorizationError> {
        self.observed
            .send(credentials)
            .map_err(|_| crucible_campaign::CampaignAuthorizationError::Unavailable)?;
        CampaignPrincipal::new("operator:alice")
            .map_err(|_| crucible_campaign::CampaignAuthorizationError::Unavailable)
    }
}
