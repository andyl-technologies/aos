//! Selects explicit Direct publication journal, policy, and renewable credentials.

use anyhow::Result;
use aos_hub_client::{DirectUploadOptions, HubClient};

use crate::cli::HubAccessArgs;

struct PublicationAuthentication(HubAccessArgs);

impl std::fmt::Debug for PublicationAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicationAuthentication([redacted])")
    }
}

#[async_trait::async_trait]
impl aos_hub_client::DirectHubAuthentication for PublicationAuthentication {
    async fn authenticate(
        &self,
        canonical_hub: &str,
    ) -> Result<HubClient, aos_transfer::direct_upload::DirectClientError> {
        crate::commands::hub::client::hub_client(canonical_hub, self.0.token.as_deref())
            .await
            .map_err(|_| aos_transfer::direct_upload::DirectClientError::Denied)
    }
}

pub(super) fn options(access: &HubAccessArgs) -> DirectUploadOptions {
    DirectUploadOptions {
        authentication: Some(std::sync::Arc::new(PublicationAuthentication(
            access.clone(),
        ))),
        journal: access.direct_upload_journal.clone(),
        provider_policy: access.direct_provider_policy.clone(),
        new_run: access.new_direct_upload_run,
        ..DirectUploadOptions::default()
    }
}
