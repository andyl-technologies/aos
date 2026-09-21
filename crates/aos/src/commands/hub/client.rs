//! Resolves hub profiles and credentials into public API clients.

use crate::cli::HubAccessArgs;
use anyhow::Result;
use aos_remote::HubClient;

/// Builds a hub client: token-authenticated when a JWT is supplied, else
/// anonymous (public reads only).
pub(super) trait HubArgument {
    fn as_optional_hub(&self) -> Option<&str>;
}

impl HubArgument for Option<String> {
    fn as_optional_hub(&self) -> Option<&str> {
        self.as_deref()
    }
}

impl HubArgument for String {
    fn as_optional_hub(&self) -> Option<&str> {
        Some(self)
    }
}

impl HubArgument for str {
    fn as_optional_hub(&self) -> Option<&str> {
        Some(self)
    }
}

/// Resolves the active profile and constructs a client with the selected credentials.
///
/// # Errors
///
/// Returns an error if credential resolution or client construction fails.
pub(super) async fn hub_client<H: HubArgument + ?Sized>(
    hub: &H,
    token: Option<&str>,
) -> Result<HubClient> {
    crate::commands::hub_auth::prepare_hub_access(hub.as_optional_hub(), token).await?;
    let (hub, token) = crate::commands::hub_auth::resolve_access(hub.as_optional_hub(), token)?;
    match token {
        Some(token) => HubClient::connect_with_token(&hub, &token),
        None => HubClient::connect_anonymous(&hub),
    }
}

/// Resolves the Hub endpoint and credential for one container-admin command.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands) async fn container_hub_client(access: &HubAccessArgs) -> Result<HubClient> {
    hub_client(&access.hub, access.token.as_deref()).await
}
