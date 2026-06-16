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

use anyhow::{Context, Result};
use connectrpc::client::{ClientConfig, HttpClient};

use aos_proto::aos::registry::v1::{
    AuditEntry, AuditServiceClient, Binding, Changeset, Channel, ChannelServiceClient,
    ConfigServiceClient, CreateBindingRequest, CreateOrgRequest, CreateProjectRequest,
    GetRegistryRequest, ListAuditRequest, ListBindingsRequest, ListChangesetsRequest,
    ListChannelsRequest, ListOrgsRequest, ListPackagesRequest, ListProjectsRequest,
    ListRegistriesRequest, ListReleasesRequest, Org, OrgServiceClient, PackageServiceClient,
    PackageSummary, Project, ProjectServiceClient, Registry, RegistryServiceClient, Release,
    StorageServiceClient,
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
    packages: PackageServiceClient<HttpClient>,
    channels: ChannelServiceClient<HttpClient>,
    orgs: OrgServiceClient<HttpClient>,
    projects: ProjectServiceClient<HttpClient>,
    bindings: StorageServiceClient<HttpClient>,
    audit: AuditServiceClient<HttpClient>,
    config: ConfigServiceClient<HttpClient>,
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
            registry: RegistryServiceClient::new(http.clone(), config.clone()),
            packages: PackageServiceClient::new(http.clone(), config.clone()),
            channels: ChannelServiceClient::new(http.clone(), config.clone()),
            orgs: OrgServiceClient::new(http.clone(), config.clone()),
            projects: ProjectServiceClient::new(http.clone(), config.clone()),
            bindings: StorageServiceClient::new(http.clone(), config.clone()),
            audit: AuditServiceClient::new(http.clone(), config.clone()),
            config: ConfigServiceClient::new(http, config),
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

    /// Lists a registry's published packages (the verified index), for a public
    /// registry when anonymous.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_packages(&self, slug: &str) -> Result<Vec<PackageSummary>> {
        let response = self
            .packages
            .list_packages(ListPackagesRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing packages for '{slug}': {e}"))?;
        Ok(response.into_owned().packages)
    }

    /// Lists a registry's rollout channels, for a public registry when
    /// anonymous.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_channels(&self, slug: &str) -> Result<Vec<Channel>> {
        let response = self
            .channels
            .list_channels(ListChannelsRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing channels for '{slug}': {e}"))?;
        Ok(response.into_owned().channels)
    }

    /// Lists the organizations visible to this client.
    ///
    /// Orgs are a tenant boundary, so this needs an authenticated client (see
    /// [`connect_with_token`](Self::connect_with_token)); an anonymous client
    /// sees none.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_orgs(&self) -> Result<Vec<Org>> {
        let response = self
            .orgs
            .list_orgs(ListOrgsRequest::default())
            .await
            .map_err(|e| anyhow::anyhow!("listing orgs: {e}"))?;
        Ok(response.into_owned().orgs)
    }

    /// Lists the projects under an org.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_projects(&self, org_slug: &str) -> Result<Vec<Project>> {
        let response = self
            .projects
            .list_projects(ListProjectsRequest {
                org_slug: org_slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing projects for org '{org_slug}': {e}"))?;
        Ok(response.into_owned().projects)
    }

    /// Lists the storage bindings under an org.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_bindings(&self, org_slug: &str) -> Result<Vec<Binding>> {
        let response = self
            .bindings
            .list_bindings(ListBindingsRequest {
                org_slug: org_slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing bindings for org '{org_slug}': {e}"))?;
        Ok(response.into_owned().bindings)
    }

    /// Lists audit-log entries at a scope (the root scope `""` is instance-wide),
    /// newest first.
    ///
    /// Requires an authenticated client with `audit.read` on the scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_audit(&self, scope: &str) -> Result<Vec<AuditEntry>> {
        let response = self
            .audit
            .list_audit(ListAuditRequest {
                scope: scope.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing audit entries for scope '{scope}': {e}"))?;
        Ok(response.into_owned().entries)
    }

    /// Lists configuration change-sets at a scope (the root scope `""` is
    /// instance-wide), newest first.
    ///
    /// Requires an authenticated client with `audit.read` on the scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_changesets(&self, scope: &str) -> Result<Vec<Changeset>> {
        let response = self
            .config
            .list_changesets(ListChangesetsRequest {
                scope: scope.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing change-sets for scope '{scope}': {e}"))?;
        Ok(response.into_owned().changesets)
    }

    /// Creates an organization; the authenticated caller becomes its Owner.
    ///
    /// Requires an authenticated client (see
    /// [`connect_with_token`](Self::connect_with_token)).
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. the slug
    /// is taken or the caller is unauthenticated), or the response omits the
    /// created org.
    pub async fn create_org(&self, slug: &str, name: &str) -> Result<Org> {
        let response = self
            .orgs
            .create_org(CreateOrgRequest {
                slug: slug.into(),
                name: name.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("creating org '{slug}': {e}"))?;
        response
            .into_owned()
            .org
            .into_option()
            .context("hub returned no org for the create request")
    }

    /// Creates a project at a materialized path under an org.
    ///
    /// Requires `registry.configure` on the org scope. The `path` is the
    /// materialized path within the org (`""` for an org-root project).
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or a duplicate path), or the response omits the created
    /// project.
    pub async fn create_project(&self, org_slug: &str, path: &str, name: &str) -> Result<Project> {
        let response = self
            .projects
            .create_project(CreateProjectRequest {
                org_slug: org_slug.into(),
                path: path.into(),
                name: name.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("creating project '{name}' in org '{org_slug}': {e}"))?;
        response
            .into_owned()
            .project
            .into_option()
            .context("hub returned no project for the create request")
    }

    /// Creates a storage binding under an org.
    ///
    /// Requires `registry.configure` on the org scope. Only the `local_fs` kind
    /// is supported this phase; `root` is the backend root path.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or a duplicate name), or the response omits the created
    /// binding.
    pub async fn create_binding(
        &self,
        org_slug: &str,
        name: &str,
        kind: &str,
        root: &str,
    ) -> Result<Binding> {
        let response = self
            .bindings
            .create_binding(CreateBindingRequest {
                org_slug: org_slug.into(),
                name: name.into(),
                kind: kind.into(),
                root: root.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("creating binding '{name}' in org '{org_slug}': {e}"))?;
        response
            .into_owned()
            .binding
            .into_option()
            .context("hub returned no binding for the create request")
    }
}
