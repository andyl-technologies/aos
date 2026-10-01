//! Resolves hub profiles and credentials into public API clients.

use crate::cli::HubAccessArgs;
use anyhow::Result;
use aos_remote::HubClient;

// A concurrent object queue must not consume one rotating refresh credential
// more than once or resolve another request's active profile between steps.
static PROFILE_RESOLUTION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Resolves renewable profile credentials for one pinned release destination.
///
/// # Errors
///
/// Returns an error when credentials cannot be refreshed or when the selected
/// destination has no authenticated profile or explicit access token.
pub(in crate::commands) async fn release_hub_client(
    origin: &str,
    token: Option<&str>,
) -> Result<HubClient> {
    let (hub, token) = resolve_credentials(Some(origin), token).await?;
    let token = token.ok_or_else(|| {
        anyhow::anyhow!("release publication requires authenticated Hub credentials")
    })?;
    HubClient::connect_with_token(&hub, &token)
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
    let (hub, token) = resolve_credentials(hub.as_optional_hub(), token).await?;
    match token {
        Some(token) => HubClient::connect_with_token(&hub, &token),
        None => HubClient::connect_anonymous(&hub),
    }
}

async fn resolve_credentials(
    origin: Option<&str>,
    token: Option<&str>,
) -> Result<(String, Option<String>)> {
    let _guard = PROFILE_RESOLUTION.lock().await;
    crate::commands::hub_auth::prepare_hub_access(origin, token).await?;
    crate::commands::hub_auth::resolve_access(origin, token)
}

/// Resolves the Hub endpoint and credential for one container-admin command.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands) async fn container_hub_client(access: &HubAccessArgs) -> Result<HubClient> {
    hub_client(&access.hub, access.token.as_deref()).await
}
