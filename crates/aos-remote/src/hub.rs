//! A ConnectRPC client for the AOS registry hub.
//!
//! Where [`AosClient`](crate::AosClient) talks to an `aos-server` (cache /
//! build / GC / auth), this talks to an **`aos-registry-hub`** — the
//! multi-tenant registry control plane (RFC-0004). It is the client the `aos
//! hub …` CLI subcommands use so the CLI interacts with a hub purely through
//! its public API, never by touching the hub's database directly.
//!
//! Construct one with [`RegistryHubClient::connect_anonymous`] for public reads
//! (listing public registries, reading a public registry's releases), or
//! [`RegistryHubClient::connect_with_token`] to attach a hub access JWT for
//! authenticated calls. The provisioning-token → JWT exchange (the hub's
//! `POST /oauth2/token`) and the write-path service clients are layered on in
//! later RFC-0004 Phase 5 increments.

use anyhow::Result;
use connectrpc::client::{ClientConfig, HttpClient};

use aos_proto::aos::registry::v1::{
    GetRegistryRequest, ListRegistriesRequest, ListReleasesRequest, Registry, RegistryServiceClient,
    Release,
};

use crate::client::{make_http_client, validate_base_url};

/// Default per-request timeout for hub RPC calls.
const HUB_TIMEOUT_SECS: u64 = 30;

/// A ConnectRPC client for an `aos-registry-hub`'s read services.
///
/// Cheap to clone (the inner service client and HTTP client are reference
/// counted). Anonymous instances see only public registries; a token-bearing
/// instance (see [`RegistryHubClient::connect_with_token`]) additionally sees
/// what the token's scope/permissions allow.
#[derive(Clone)]
pub struct RegistryHubClient {
    registry: RegistryServiceClient<HttpClient>,
}

impl RegistryHubClient {
    /// Connects to a hub for **unauthenticated** public reads.
    ///
    /// No credential is attached, so calls see only public registries and
    /// their public data — exactly the anonymous browse surface. Use
    /// [`connect_with_token`](Self::connect_with_token) for authenticated
    /// access.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a valid `http://`/`https://` URL.
    pub fn connect_anonymous(base_url: &str) -> Result<Self> {
        Self::build(base_url, None)
    }

    /// Connects to a hub with a hub access JWT attached as `Bearer`.
    ///
    /// The token is sent on every call; the hub authorizes each request against
    /// the token's scope and permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a valid `http://`/`https://` URL.
    pub fn connect_with_token(base_url: &str, access_token: &str) -> Result<Self> {
        Self::build(base_url, Some(access_token))
    }

    /// Builds the service client, optionally attaching a bearer token.
    fn build(base_url: &str, access_token: Option<&str>) -> Result<Self> {
        let base_uri = validate_base_url(base_url)?;
        let http = make_http_client(base_url);
        let mut config = ClientConfig::new(base_uri)
            .default_timeout(std::time::Duration::from_secs(HUB_TIMEOUT_SECS));
        if let Some(token) = access_token {
            config = config.default_header("authorization", format!("Bearer {token}"));
        }
        Ok(Self {
            registry: RegistryServiceClient::new(http, config),
        })
    }

    /// Lists the registries visible to this client (public ones when anonymous).
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_registries(&self) -> Result<Vec<Registry>> {
        let response = self
            .registry
            .list_registries(ListRegistriesRequest::default())
            .await
            .map_err(|e| anyhow::anyhow!("listing registries: {e}"))?;
        Ok(response.into_owned().registries)
    }

    /// Fetches one registry by slug, or `None` when it does not exist or is not
    /// visible to this client.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails for a reason
    /// other than "not found".
    pub async fn get_registry(&self, slug: &str) -> Result<Option<Registry>> {
        let response = self
            .registry
            .get_registry(GetRegistryRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("fetching registry '{slug}': {e}"))?;
        Ok(response.into_owned().registry.into_option())
    }

    /// Lists a registry's verified releases (newest first), for a public
    /// registry when anonymous.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_releases(&self, slug: &str) -> Result<Vec<Release>> {
        let response = self
            .registry
            .list_releases(ListReleasesRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing releases for '{slug}': {e}"))?;
        Ok(response.into_owned().releases)
    }
}
