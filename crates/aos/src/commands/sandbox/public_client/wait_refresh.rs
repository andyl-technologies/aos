//! Fresh public resource reads after a mutation's operation becomes terminal.
//!
//! An admission response is not a final resource snapshot. Each implementation
//! reuses the authenticated public endpoint, requests the admitted identity,
//! and rejects a substituted identity before checked rendering.

use anyhow::{Context as _, Result, bail};
use aos_proto::aos::sandbox::v1::{
    CapabilityServiceClient, ExecutionServiceClient, FilesystemViewServiceClient,
    GetAttachmentRequest, GetExecutionRequest, GetSandboxRequest, GetSnapshotRequest,
    GetViewRequest, InspectCapabilityRequest, SandboxServiceClient, SnapshotServiceClient,
};
use aos_sandbox::cli_model::EstablishedProtoJson;
use aos_sandbox::controller_query::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedOperationResourceV1, CheckedSandboxResourceV1,
    CheckedSnapshotResourceV1,
};

use super::AuthorizedEndpoint;

/// Re-reads one admitted resource through its exact public Get method.
pub(super) trait WaitRefreshResource: EstablishedProtoJson + Sized {
    /// Returns the checked current projection for the admitted identity.
    ///
    /// # Errors
    ///
    /// Rejects transport failure, missing or substituted identity, or an
    /// invalid public resource projection.
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self>;
}

impl WaitRefreshResource for CheckedOperationResourceV1 {
    async fn refresh_after_terminal(&self, _endpoint: &AuthorizedEndpoint) -> Result<Self> {
        // Operation-only callers pass no resource. A future mistaken Some must
        // fail instead of rendering the admission-time operation as current.
        bail!("operation-only mutation has no final resource to refresh")
    }
}

impl WaitRefreshResource for CheckedSandboxResourceV1 {
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self> {
        let expected_id = self.sandbox_id();
        let response = SandboxServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
            .get_sandbox(GetSandboxRequest {
                sandbox_id: expected_id.to_vec(),
                ..Default::default()
            })
            .await
            .context("controller rejected final sandbox lookup")?
            .into_owned();
        let resource = response
            .sandbox
            .into_option()
            .context("controller omitted the final sandbox")?;
        require_same_identity(&expected_id, &resource.sandbox_id, "sandbox")?;

        Self::try_from(resource).context("controller returned an invalid final sandbox")
    }
}

impl WaitRefreshResource for CheckedExecutionResourceV1 {
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self> {
        let expected_id = self.as_proto().execution_id.clone();
        let response = ExecutionServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
            .get_execution(GetExecutionRequest {
                execution_id: expected_id.clone(),
                ..Default::default()
            })
            .await
            .context("controller rejected final execution lookup")?
            .into_owned();
        let resource = response
            .execution
            .into_option()
            .context("controller omitted the final execution")?;
        require_same_identity(&expected_id, &resource.execution_id, "execution")?;

        Self::try_from(resource).context("controller returned an invalid final execution")
    }
}

impl WaitRefreshResource for CheckedFilesystemViewResourceV1 {
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self> {
        let expected_id = self.as_proto().view_id.clone();
        let response =
            FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                .get_view(GetViewRequest {
                    view_id: expected_id.clone(),
                    ..Default::default()
                })
                .await
                .context("controller rejected final filesystem-view lookup")?
                .into_owned();
        let resource = response
            .view
            .into_option()
            .context("controller omitted the final filesystem view")?;
        require_same_identity(&expected_id, &resource.view_id, "filesystem-view")?;

        Self::try_from(resource).context("controller returned an invalid final filesystem view")
    }
}

impl WaitRefreshResource for CheckedAttachmentResourceV1 {
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self> {
        let expected_id = self.as_proto().attachment_id.clone();
        let response =
            FilesystemViewServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
                .get_attachment(GetAttachmentRequest {
                    attachment_id: expected_id.clone(),
                    ..Default::default()
                })
                .await
                .context("controller rejected final attachment lookup")?
                .into_owned();
        let resource = response
            .attachment
            .into_option()
            .context("controller omitted the final attachment")?;
        require_same_identity(&expected_id, &resource.attachment_id, "attachment")?;

        Self::try_from(resource).context("controller returned an invalid final attachment")
    }
}

impl WaitRefreshResource for CheckedSnapshotResourceV1 {
    async fn refresh_after_terminal(&self, endpoint: &AuthorizedEndpoint) -> Result<Self> {
        let expected_id = self.as_proto().snapshot_id.clone();
        let response = SnapshotServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
            .get_snapshot(GetSnapshotRequest {
                snapshot_id: expected_id.clone(),
                ..Default::default()
            })
            .await
            .context("controller rejected final snapshot lookup")?
            .into_owned();
        let resource = response
            .snapshot
            .into_option()
            .context("controller omitted the final snapshot")?;
        require_same_identity(&expected_id, &resource.snapshot_id, "snapshot")?;

        Self::try_from(resource).context("controller returned an invalid final snapshot")
    }
}

/// Re-reads a renewed capability through the holder's returned lookup handle.
///
/// # Errors
///
/// Rejects transport failure, an omitted or substituted capability, or an
/// invalid current capability projection.
pub(super) async fn refresh_renewed_capability(
    endpoint: &AuthorizedEndpoint,
    expected_id: &[u8],
    handle: &[u8],
) -> Result<CheckedCapabilityResourceV1> {
    let response = CapabilityServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
        .inspect(InspectCapabilityRequest {
            capability_handle: handle.to_vec(),
            ..Default::default()
        })
        .await
        .context("controller rejected final capability inspection")?
        .into_owned();
    let resource = response
        .capability
        .into_option()
        .context("controller omitted the final capability")?;
    require_same_identity(expected_id, &resource.capability_id, "capability")?;

    CheckedCapabilityResourceV1::try_from(resource)
        .context("controller returned an invalid final capability")
}

fn require_same_identity(expected: &[u8], observed: &[u8], resource: &str) -> Result<()> {
    if observed != expected {
        bail!("controller substituted the final {resource} identity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_same_identity;

    #[test]
    fn final_lookup_rejects_substituted_resource_identity() {
        let expected = [0x11; 16];
        assert!(require_same_identity(&expected, &expected, "sandbox").is_ok());
        assert!(require_same_identity(&expected, &[0x22; 16], "sandbox").is_err());
        assert!(require_same_identity(&expected, &expected[..15], "sandbox").is_err());
    }
}
