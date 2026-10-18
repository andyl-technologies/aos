//! Resolves hub profiles and credentials into public API clients.

use crate::cli::HubAccessArgs;
use anyhow::Result;
use aos_hub_client::HubClient;

/// Resolves authenticated renewable credentials for a pinned release destination.
///
/// # Errors
///
/// Returns an error when no explicit token or matching profile is available,
/// or when credential refresh or client configuration fails.
pub(in crate::commands) async fn release_hub_client(
    origin: &str,
    token: Option<&str>,
) -> Result<HubClient> {
    aos_registry_client::hub_auth::authenticated_hub_client(origin, token).await
}

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
    aos_registry_client::hub_auth::hub_client(hub.as_optional_hub(), token).await
}

/// Resolves the Hub endpoint and credential for one container-admin command.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands) async fn container_hub_client(access: &HubAccessArgs) -> Result<HubClient> {
    hub_client(&access.hub, access.token.as_deref()).await
}
