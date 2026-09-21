//! Authenticated repository-backed campaign connection serving.

use super::*;

/// Serves one authenticated repository connection with bounded controls.
///
/// Peer credentials are resolved once before request decoding. Each request is
/// bound to that principal, the repository authorization policy, and the
/// supplied runtime and status capabilities.
///
/// # Errors
///
/// Returns [`LoopbackCampaignServerError`] when peer authentication,
/// authorization, framing, canonical validation, response binding, request
/// limits, or bounded socket I/O fails.
pub(crate) struct CampaignConnectionControls<'a> {
    pub(crate) runtime: Option<&'a dyn CampaignRuntimeControlService>,
    pub(crate) debug: Option<&'a dyn CampaignDebugControlService>,
    pub(crate) status: Option<&'a dyn CampaignOperationalStatusProvider>,
    pub(crate) timeouts: LoopbackCampaignTimeouts,
    pub(crate) maximum_requests: usize,
}

pub(crate) fn serve_authenticated_repository_campaign_connection_with_controls_limits<R, A>(
    stream: &mut UnixStream,
    repository: &CampaignRepository,
    principal_resolver: &R,
    authorizer: &A,
    controls: CampaignConnectionControls<'_>,
) -> Result<(), LoopbackCampaignServerError>
where
    R: UnixPeerCampaignPrincipalResolver + ?Sized,
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    if controls.maximum_requests == 0
        || controls.maximum_requests > MAX_CAMPAIGN_REQUESTS_PER_CONNECTION
    {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(LoopbackCampaignProtocolError::InvalidRequestLimit.into());
    }
    let result = (|| {
        let peer = rustix::net::sockopt::socket_peercred(&*stream)
            .map_err(|error| LoopbackCampaignProtocolError::Io(std::io::Error::from(error)))?;
        let credentials = UnixPeerCampaignCredentials {
            process_id: peer.pid.as_raw_pid(),
            user_id: peer.uid.as_raw(),
            group_id: peer.gid.as_raw(),
        };
        let principal = principal_resolver.resolve_campaign_principal(credentials)?;
        let peer_authorizer = PeerBoundCampaignAuthorizer {
            principal: principal.clone(),
            inner: authorizer,
        };
        let service = RepositoryCampaignService::new(repository, peer_authorizer);
        let service = match controls.status {
            Some(provider) => service.with_operational_status(provider),
            None => service,
        };
        let runtime_dispatch = AuthorizedRuntimeControlDispatch {
            principal: &principal,
            authorizer,
            service: controls.runtime,
        };
        let debug_dispatch = AuthorizedDebugControlDispatch {
            principal: &principal,
            authorizer,
            service: controls.debug,
        };

        for _ in 0..controls.maximum_requests {
            match serve_loopback_campaign_inner_with_controls(
                stream,
                &service,
                Some(&runtime_dispatch),
                Some(&debug_dispatch),
                controls.timeouts,
            ) {
                Ok(()) => {}
                Err(LoopbackCampaignServerError::Protocol(
                    LoopbackCampaignProtocolError::ConnectionClosed,
                )) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    })();
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}
