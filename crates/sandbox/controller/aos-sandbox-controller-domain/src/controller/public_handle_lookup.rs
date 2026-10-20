//! Shares the protected public capability-handle lookup with selected custody.
//!
//! A handle lookup returns target DATA only. The native-retaining Delete caller
//! still obtains the ordinary current protected authorization on its C17 loan.
//! Ordinary lookup has identical peer/registry/holder/project check order.

use super::{ControllerServiceError, OperationCompilationError,
    PublisherAuthorityLimits, PublisherCapabilityRegistry};

// Same protected handle lookup for ordinary admission and the C17-paid Delete
// prefix. The optional destination changes native custody only; a successful
// lookup remains target DATA and never replaces current policy authorization.
pub(super) fn resolve_public_capability_target_inner_v1(
    journal: &mut crate::Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    handle: &[u8],
    mut native: Option<&mut [crate::public_api_session::PublicApiPeerRecheckV1; 2]>,
) -> Result<aos_sandbox_model::CapabilityId, ControllerServiceError> {
    match native.as_deref_mut() {
        Some(native) => peer.recheck_retaining_v1(&mut native[0]),
        None => peer.recheck(),
    }.map_err(|_| OperationCompilationError::Rejected)?;
    let registry = PublisherCapabilityRegistry::load(
        journal,
        PublisherAuthorityLimits::default(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let resolved = registry
        .resolve_holder_handle(handle, peer.principal(), peer.key_binding())
        .map_err(|_| OperationCompilationError::Rejected)?;
    if peer.project()
        != registry
            .resolve_current(resolved)
            .map_err(|_| OperationCompilationError::Rejected)?
            .claims()
            .project
    {
        return Err(OperationCompilationError::Rejected.into());
    }
    match native.as_deref_mut() {
        Some(native) => peer.recheck_retaining_v1(&mut native[1]),
        None => peer.recheck(),
    }.map_err(|_| OperationCompilationError::Rejected)?;
    Ok(resolved)
}

pub(crate) fn resolve_delete_capability_handle_retaining_v1(
    journal: &mut crate::Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    claimed_uid: aos_sandbox_model::CapabilityId,
    handle: &[u8],
    native: &mut [crate::public_api_session::PublicApiPeerRecheckV1; 2],
) -> Result<aos_sandbox_model::CapabilityId, ControllerServiceError> {
    let resolved = resolve_public_capability_target_inner_v1(journal, peer, handle, Some(native))?;
    if resolved != claimed_uid {
        return Err(OperationCompilationError::Rejected.into());
    }
    Ok(resolved)
}
