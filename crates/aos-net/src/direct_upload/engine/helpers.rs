//! Closed response correlation and stable operation commitments.

use aos_proto_types::direct_upload::*;
use sha2::{Digest as _, Sha256};

use super::{DirectClientError, DirectUploadControl};

pub(super) fn operation(domain: &str, members: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos.direct.client-operation.v1\0");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain.as_bytes());
    for member in members {
        hash.update((member.len() as u64).to_be_bytes());
        hash.update(member.as_bytes());
    }
    hex::encode(hash.finalize())
}

pub(super) fn request_operation(request: &DirectUploadRequest) -> &str {
    match request {
        DirectUploadRequest::BeginBatch(batch) => &batch.operation_id,
        DirectUploadRequest::StatusBatch(batch) => &batch.operation_id,
        DirectUploadRequest::GrantPartsBatch(batch) => &batch.operation_id,
        DirectUploadRequest::ReportPartsBatch(batch) => &batch.operation_id,
        DirectUploadRequest::CompleteBatch(batch) => &batch.operation_id,
        DirectUploadRequest::Abort(batch) => &batch.operation_id,
    }
}

pub(super) async fn control<C: DirectUploadControl>(
    control: &C,
    request: &DirectUploadRequest,
) -> Result<DirectUploadResponse, DirectClientError> {
    request.validate().map_err(|_| DirectClientError::Invalid)?;
    // Lost control replies replay the same exact retained operations. A retry
    // cannot renew a capability or start a new provider-control effect.
    let mut response = Err(DirectClientError::ControlUnavailable);
    for _ in 0..3 {
        response = control.execute(request).await;
        if response != Err(DirectClientError::ControlUnavailable) {
            break;
        }
    }
    let response = response?;
    response
        .validate()
        .map_err(|_| DirectClientError::Invalid)?;
    if response.operation_id != request_operation(request) {
        return Err(DirectClientError::Invalid);
    }
    if let Some(error) = response.errors.first() {
        return Err(match error.code {
            DirectItemErrorCode::Denied => DirectClientError::Denied,
            DirectItemErrorCode::BlockedUnknown => DirectClientError::Blocked,
            DirectItemErrorCode::Unavailable => DirectClientError::ControlUnavailable,
            _ => DirectClientError::Invalid,
        });
    }
    Ok(response)
}

pub(super) fn active_or_verified(state: DirectSessionState) -> Result<(), DirectClientError> {
    match state {
        DirectSessionState::Active
        | DirectSessionState::StagedVerified
        | DirectSessionState::Committed => Ok(()),
        DirectSessionState::Creating
        | DirectSessionState::Freezing
        | DirectSessionState::CompletingStaging
        | DirectSessionState::Promoting
        | DirectSessionState::BlockedUnknown
        | DirectSessionState::CleanupPending => Err(DirectClientError::Blocked),
        DirectSessionState::Aborting | DirectSessionState::Aborted => {
            Err(DirectClientError::Denied)
        }
    }
}

/// Applies independently authenticated discovery limits to every control hop.
pub(super) struct LimitedControl<'a, C> {
    pub(super) inner: &'a C,
    pub(super) bytes: usize,
    pub(super) items: usize,
    pub(super) parts: usize,
}

pub(super) fn request_bytes(request: &DirectUploadRequest) -> Result<usize, DirectClientError> {
    let bytes = match request {
        DirectUploadRequest::BeginBatch(value) => encode_direct_control(value),
        DirectUploadRequest::StatusBatch(value) => encode_direct_control(value),
        DirectUploadRequest::GrantPartsBatch(value) => encode_direct_control(value),
        DirectUploadRequest::ReportPartsBatch(value) => encode_direct_control(value),
        DirectUploadRequest::CompleteBatch(value) => encode_direct_control(value),
        DirectUploadRequest::Abort(value) => encode_direct_control(value),
    }
    .map_err(|_| DirectClientError::Invalid)?;
    Ok(bytes.len())
}

#[async_trait::async_trait]
impl<C: DirectUploadControl> DirectUploadControl for LimitedControl<'_, C> {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let count = match request {
            DirectUploadRequest::BeginBatch(value) => value.items.len(),
            DirectUploadRequest::StatusBatch(value) => value.items.len(),
            DirectUploadRequest::GrantPartsBatch(value) => value.items.len(),
            DirectUploadRequest::ReportPartsBatch(value) => value.items.len(),
            DirectUploadRequest::CompleteBatch(value) => value.items.len(),
            DirectUploadRequest::Abort(value) => value.items.len(),
        };
        let maximum = if matches!(
            request,
            DirectUploadRequest::GrantPartsBatch(_) | DirectUploadRequest::ReportPartsBatch(_)
        ) {
            self.parts
        } else {
            self.items
        };
        if count > maximum || request_bytes(request)? > self.bytes {
            return Err(DirectClientError::Invalid);
        }
        let response = self.inner.execute(request).await?;
        let bytes = encode_direct_control(&response).map_err(|_| DirectClientError::Invalid)?;
        if bytes.len() > self.bytes
            || response.sessions.len() + response.errors.len() > self.items
            || response.grants.len() > self.parts
            || response
                .sessions
                .iter()
                .map(|status| status.parts.len())
                .sum::<usize>()
                > self.parts
        {
            return Err(DirectClientError::Invalid);
        }
        Ok(response)
    }
}

pub(super) fn discovery_target(
    capabilities: &DirectUploadCapabilities,
) -> DirectCapabilitiesTarget {
    capabilities.requested_delivery_url.as_ref().map_or_else(
        || capabilities.target.clone(),
        |delivery_url| DirectCapabilitiesTarget::CacheDelivery {
            delivery_url: delivery_url.clone(),
        },
    )
}
