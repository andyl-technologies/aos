//! A Connect-JSON client for the AOS registry hub.
//!
//! Where [`AosClient`](crate::AosClient) talks to an `aos-server` (cache /
//! build / GC / auth) over ConnectRPC, this talks to an **`aos-hub`** —
//! the multi-tenant registry control plane (RFC-0004). It is the client the
//! `aos hub …` CLI subcommands use so the CLI interacts with a hub purely
//! through its public API, never by touching the hub's database directly.
//!
//! RFC-0004 Phase 5 unifies the native hub and the Cloudflare Worker on one
//! transport: **Connect-JSON** — plain JSON over HTTP. Each method is one POST
//! route, `POST {base}/aos.registry.v1.{Service}/{Method}`, with the
//! JSON-encoded request message as the body and the JSON-encoded response
//! message as a `200` body. Errors are the Connect error envelope with a
//! matching non-2xx status:
//!
//! ```text
//! POST /aos.registry.v1.RegistryService/GetRegistry
//! Content-Type: application/json
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```
//!
//! This client speaks that transport directly with `reqwest`, exchanging the
//! [`aos_proto_types`] message structs as JSON. Construct one with
//! [`RegistryHubClient::connect_anonymous`] for public reads, or
//! [`RegistryHubClient::connect_with_token`] to attach a hub access JWT for
//! authenticated calls.

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

use aos_proto_types::{
    AuditEntry, Binding, ChangeCacheStorageRequest, ChangeCacheStorageResponse,
    ChangeRegistryStorageRequest, ChangeRegistryStorageResponse, ChangeRequest, Changeset, Channel,
    CreateBindingRequest, CreateBindingResponse, CreateOrgRequest, CreateOrgResponse,
    CreateProjectRequest, CreateProjectResponse, CreateRegistryRequest, CreateRegistryResponse,
    CreateWebhookRequest, CreateWebhookResponse, DeleteWebhookRequest, GetChannelRequest,
    GetChannelResponse, GetInstanceSettingsRequest, GetInstanceSettingsResponse, GetPackageRequest,
    GetPackageResponse, GetRegistryRequest, GetRegistryResponse, GitCommit, GitDiffRequest,
    GitDiffResponse, GitLogRequest, GitLogResponse, InstanceSettings, LinkCacheRequest,
    LinkCacheResponse, ListAuditRequest, ListAuditResponse, ListBindingsRequest,
    ListBindingsResponse, ListChangeRequestsRequest, ListChangeRequestsResponse,
    ListChangesetsRequest, ListChangesetsResponse, ListChannelsRequest, ListChannelsResponse,
    ListOrgsRequest, ListOrgsResponse, ListPackagesRequest, ListPackagesResponse,
    ListProjectsRequest, ListProjectsResponse, ListRegistriesRequest, ListRegistriesResponse,
    ListReleasesRequest, ListReleasesResponse, ListWebhooksRequest, ListWebhooksResponse,
    MintUploadCredentialsRequest, MintUploadCredentialsResponse, Org, Package, PackageSummary,
    Project, Registry, Release, RevertChangesetRequest, RevertChangesetResponse,
    UnlinkCacheRequest, UnlinkCacheResponse, UpdateInstanceSettingsRequest,
    UpdateInstanceSettingsResponse, Webhook,
};

use crate::client::validate_base_url;

/// The endpoint, region, access mode, and credentials for an `s3`/`r2` storage
/// binding, passed to [`HubClient::create_binding`].
///
/// All fields are ignored for a `local_fs` binding; pass
/// [`BindingOrigin::default`] in that case.
#[derive(Debug, Clone, Copy, Default)]
pub struct BindingOrigin<'a> {
    /// Access mode: `private` (credentialed, read/write) or `public`
    /// (credential-less, read-only). Empty defaults to `private` on the hub.
    pub access: &'a str,
    /// Endpoint origin URL (e.g. `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: &'a str,
    /// Signing region (`auto` for R2, e.g. `us-east-1` for S3). Empty defaults to
    /// `auto`.
    pub region: &'a str,
    /// Access key id (required for a private binding).
    pub access_key_id: &'a str,
    /// Secret access key (required for a private binding); sealed at rest.
    pub secret_access_key: &'a str,
}

/// Default per-request timeout for hub RPC calls.
const HUB_TIMEOUT_SECS: u64 = 30;

/// A Connect-JSON client for an `aos-hub`'s services.
///
/// Cheap to clone (the inner `reqwest` client is reference counted). Anonymous
/// instances see only public registries; a token-bearing instance (see
/// [`RegistryHubClient::connect_with_token`]) additionally sees what the
/// token's scope/permissions allow.
#[derive(Clone)]
pub struct RegistryHubClient {
    /// The shared `reqwest` client (rustls TLS for `https://`).
    http: reqwest::Client,
    /// The hub root with a single trailing slash, e.g. `https://hub.example/`.
    base: String,
    /// The hub access JWT to send as `Authorization: Bearer …`, when present.
    token: Option<String>,
}

/// A short-lived, registry-scoped upload credential minted by the hub.
///
/// Returned by [`RegistryHubClient::mint_upload_credentials`]; the `token` is
/// shown exactly once.
#[derive(Debug, Clone)]
pub struct UploadCredentials {
    /// The provisioning-token secret (`aos_`-prefixed), shown exactly once.
    pub token: String,
    /// The canonical facade base URL to upload the registry surface to.
    pub upload_url: String,
    /// Unix seconds at which the credential expires.
    pub expires_at: i64,
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
    /// Returns an error if `base_url` is not a valid `http://`/`https://` URL,
    /// or if the underlying HTTP client cannot be built.
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
    /// Returns an error if `base_url` is not a valid `http://`/`https://` URL,
    /// or if the underlying HTTP client cannot be built.
    pub fn connect_with_token(base_url: &str, access_token: &str) -> Result<Self> {
        Self::build(base_url, Some(access_token))
    }

    /// Builds the client, optionally retaining a bearer token.
    fn build(base_url: &str, access_token: Option<&str>) -> Result<Self> {
        // Reuse the shared base-URL validation (http(s) scheme, parseable) so a
        // typo fails fast with the same message as the other clients.
        let base = validate_base_url(base_url)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HUB_TIMEOUT_SECS))
            .build()
            .context("building the hub HTTP client")?;
        Ok(Self {
            http,
            base: ensure_trailing_slash(&base.to_string()),
            token: access_token.map(str::to_owned),
        })
    }

    /// Performs one unary Connect-JSON call against the hub.
    ///
    /// POSTs `req` as a JSON body to `{base}{full_method}` (e.g.
    /// `aos.registry.v1.RegistryService/ListRegistries`), attaching the bearer
    /// token when one is set, and decodes the JSON response message. A non-2xx
    /// status is parsed as the Connect error envelope `{ code, message }`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the request cannot be
    /// serialized, the hub returns a non-2xx status (the envelope's `code` and
    /// `message` are surfaced), or the success body cannot be decoded as `Resp`.
    async fn call<Req, Resp>(&self, full_method: &str, req: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = format!("{}{full_method}", self.base);
        let mut request = self.http.post(&url).json(req);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("contacting the hub at {url}"))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .with_context(|| format!("reading the hub response from {url}"))?;

        if !status.is_success() {
            // Connect's error envelope is `{ "code": "...", "message": "..." }`.
            // Surface its message (and code) when present; otherwise fall back
            // to the HTTP status and any raw body text.
            if let Ok(envelope) = serde_json::from_slice::<ConnectError>(&body) {
                anyhow::bail!("hub error [{}]: {}", envelope.code, envelope.message);
            }
            let detail = String::from_utf8_lossy(&body);
            let detail = detail.trim();
            anyhow::bail!(
                "hub request to {url} failed ({status}){}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }

        serde_json::from_slice(&body)
            .with_context(|| format!("decoding the hub response from {url}"))
    }

    /// Lists the registries visible to this client (public ones when anonymous).
    ///
    /// Calls `aos.registry.v1.RegistryService/ListRegistries`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_registries(&self) -> Result<Vec<Registry>> {
        let resp: ListRegistriesResponse = self
            .call(
                "aos.registry.v1.RegistryService/ListRegistries",
                &ListRegistriesRequest::default(),
            )
            .await
            .context("listing registries")?;
        Ok(resp.registries)
    }

    /// Fetches one registry by slug, or `None` when it does not exist or is not
    /// visible to this client.
    ///
    /// Calls `aos.registry.v1.RegistryService/GetRegistry`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails for a reason
    /// other than "not found".
    pub async fn get_registry(&self, slug: &str) -> Result<Option<Registry>> {
        let resp: GetRegistryResponse = self
            .call(
                "aos.registry.v1.RegistryService/GetRegistry",
                &GetRegistryRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("fetching registry '{slug}'"))?;
        Ok(resp.registry)
    }

    /// Lists a registry's verified releases (newest first), for a public
    /// registry when anonymous.
    ///
    /// Calls `aos.registry.v1.RegistryService/ListReleases`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_releases(&self, slug: &str) -> Result<Vec<Release>> {
        let resp: ListReleasesResponse = self
            .call(
                "aos.registry.v1.RegistryService/ListReleases",
                &ListReleasesRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing releases for '{slug}'"))?;
        Ok(resp.releases)
    }

    /// Lists a registry's published packages (the verified index), for a public
    /// registry when anonymous.
    ///
    /// Calls `aos.registry.v1.PackageService/ListPackages`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_packages(&self, slug: &str) -> Result<Vec<PackageSummary>> {
        let resp: ListPackagesResponse = self
            .call(
                "aos.registry.v1.PackageService/ListPackages",
                &ListPackagesRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing packages for '{slug}'"))?;
        Ok(resp.packages)
    }

    /// Lists a registry's rollout channels, for a public registry when
    /// anonymous.
    ///
    /// Calls `aos.registry.v1.ChannelService/ListChannels`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_channels(&self, slug: &str) -> Result<Vec<Channel>> {
        let resp: ListChannelsResponse = self
            .call(
                "aos.registry.v1.ChannelService/ListChannels",
                &ListChannelsRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing channels for '{slug}'"))?;
        Ok(resp.channels)
    }

    /// Lists the organizations visible to this client.
    ///
    /// Orgs are a tenant boundary, so this needs an authenticated client (see
    /// [`connect_with_token`](Self::connect_with_token)); an anonymous client
    /// sees none. Calls `aos.registry.v1.OrgService/ListOrgs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_orgs(&self) -> Result<Vec<Org>> {
        let resp: ListOrgsResponse = self
            .call(
                "aos.registry.v1.OrgService/ListOrgs",
                &ListOrgsRequest::default(),
            )
            .await
            .context("listing orgs")?;
        Ok(resp.orgs)
    }

    /// Lists the projects under an org.
    ///
    /// Calls `aos.registry.v1.ProjectService/ListProjects`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_projects(&self, org_slug: &str) -> Result<Vec<Project>> {
        let resp: ListProjectsResponse = self
            .call(
                "aos.registry.v1.ProjectService/ListProjects",
                &ListProjectsRequest {
                    org_slug: org_slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing projects for org '{org_slug}'"))?;
        Ok(resp.projects)
    }

    /// Lists the storage bindings under an org.
    ///
    /// Calls `aos.registry.v1.StorageService/ListBindings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_bindings(&self, org_slug: &str) -> Result<Vec<Binding>> {
        let resp: ListBindingsResponse = self
            .call(
                "aos.registry.v1.StorageService/ListBindings",
                &ListBindingsRequest {
                    org_slug: org_slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing bindings for org '{org_slug}'"))?;
        Ok(resp.bindings)
    }

    /// Lists audit-log entries at a scope (the root scope `""` is instance-wide),
    /// newest first.
    ///
    /// Requires an authenticated client with `audit.read` on the scope. Calls
    /// `aos.registry.v1.AuditService/ListAudit`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_audit(&self, scope: &str) -> Result<Vec<AuditEntry>> {
        let resp: ListAuditResponse = self
            .call(
                "aos.registry.v1.AuditService/ListAudit",
                &ListAuditRequest {
                    scope: scope.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing audit entries for scope '{scope}'"))?;
        Ok(resp.entries)
    }

    /// Fetches the full editable instance-settings bundle.
    ///
    /// Requires an authenticated client with `iam.admin` at the instance root.
    /// Calls `aos.registry.v1.InstanceService/GetInstanceSettings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the caller is not an instance
    /// admin, or the response omits the settings payload.
    pub async fn get_instance_settings(&self) -> Result<InstanceSettings> {
        let resp: GetInstanceSettingsResponse = self
            .call(
                "aos.registry.v1.InstanceService/GetInstanceSettings",
                &GetInstanceSettingsRequest {},
            )
            .await
            .context("fetching instance settings")?;
        resp.settings
            .context("hub returned no instance settings payload")
    }

    /// Applies a set of instance-settings changes and returns the updated bundle.
    ///
    /// Each `(key, value)` in `values` is set (a blank value clears the key to
    /// its default); each key in `clear` is reset to its default. Requires an
    /// authenticated client with `iam.admin` at the instance root. Calls
    /// `aos.registry.v1.InstanceService/UpdateInstanceSettings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the caller is not an instance
    /// admin, a key is unknown, a value is invalid, or the response omits the
    /// settings payload.
    pub async fn update_instance_settings(
        &self,
        values: std::collections::HashMap<String, String>,
        clear: Vec<String>,
    ) -> Result<InstanceSettings> {
        let resp: UpdateInstanceSettingsResponse = self
            .call(
                "aos.registry.v1.InstanceService/UpdateInstanceSettings",
                &UpdateInstanceSettingsRequest { values, clear },
            )
            .await
            .context("updating instance settings")?;
        resp.settings
            .context("hub returned no instance settings payload")
    }

    /// Lists configuration change-sets at a scope (the root scope `""` is
    /// instance-wide), newest first.
    ///
    /// Requires an authenticated client with `audit.read` on the scope. Calls
    /// `aos.registry.v1.ConfigService/ListChangesets`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_changesets(&self, scope: &str) -> Result<Vec<Changeset>> {
        let resp: ListChangesetsResponse = self
            .call(
                "aos.registry.v1.ConfigService/ListChangesets",
                &ListChangesetsRequest {
                    scope: scope.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing change-sets for scope '{scope}'"))?;
        Ok(resp.changesets)
    }

    /// Creates an organization; the authenticated caller becomes its Owner.
    ///
    /// Requires an authenticated client (see
    /// [`connect_with_token`](Self::connect_with_token)). Calls
    /// `aos.registry.v1.OrgService/CreateOrg`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. the slug
    /// is taken or the caller is unauthenticated), or the response omits the
    /// created org.
    pub async fn create_org(&self, slug: &str, name: &str) -> Result<Org> {
        let resp: CreateOrgResponse = self
            .call(
                "aos.registry.v1.OrgService/CreateOrg",
                &CreateOrgRequest {
                    slug: slug.into(),
                    name: name.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("creating org '{slug}'"))?;
        resp.org
            .context("hub returned no org for the create request")
    }

    /// Creates a project at a materialized path under an org.
    ///
    /// Requires `registry.configure` on the org scope. The `path` is the
    /// materialized path within the org (`""` for an org-root project). Calls
    /// `aos.registry.v1.ProjectService/CreateProject`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or a duplicate path), or the response omits the created
    /// project.
    pub async fn create_project(&self, org_slug: &str, path: &str, name: &str) -> Result<Project> {
        let resp: CreateProjectResponse = self
            .call(
                "aos.registry.v1.ProjectService/CreateProject",
                &CreateProjectRequest {
                    org_slug: org_slug.into(),
                    path: path.into(),
                    name: name.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("creating project '{name}' in org '{org_slug}'"))?;
        resp.project
            .context("hub returned no project for the create request")
    }

    /// Creates a storage binding under an org.
    ///
    /// Requires `registry.configure` on the org scope. `kind` is `local_fs`,
    /// `s3`, or `r2`; `root` is the backend root (a host path for `local_fs`, or
    /// the bucket for `s3`/`r2`). For an `s3`/`r2` binding, `origin` carries the
    /// endpoint, region, access mode, and (for a private binding) credentials.
    /// Calls `aos.registry.v1.StorageService/CreateBinding`.
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
        origin: BindingOrigin<'_>,
    ) -> Result<Binding> {
        let resp: CreateBindingResponse = self
            .call(
                "aos.registry.v1.StorageService/CreateBinding",
                &CreateBindingRequest {
                    org_slug: org_slug.into(),
                    name: name.into(),
                    kind: kind.into(),
                    root: root.into(),
                    access: origin.access.into(),
                    endpoint: origin.endpoint.into(),
                    region: origin.region.into(),
                    access_key_id: origin.access_key_id.into(),
                    secret_access_key: origin.secret_access_key.into(),
                },
            )
            .await
            .with_context(|| format!("creating binding '{name}' in org '{org_slug}'"))?;
        resp.binding
            .context("hub returned no binding for the create request")
    }

    /// Migrates a registry's surface to a different storage backend.
    ///
    /// An empty `binding_name` targets the deployment default store. Returns the
    /// `(objects, bytes)` copied. Calls
    /// `aos.registry.v1.RegistryService/ChangeRegistryStorage`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the migration RPC fails
    /// (unknown registry/binding, a no-op move, or a copy failure).
    pub async fn change_registry_storage(
        &self,
        slug: &str,
        binding_name: &str,
    ) -> Result<(u64, u64)> {
        let resp: ChangeRegistryStorageResponse = self
            .call(
                "aos.registry.v1.RegistryService/ChangeRegistryStorage",
                &ChangeRegistryStorageRequest {
                    slug: slug.into(),
                    binding_name: binding_name.into(),
                },
            )
            .await
            .with_context(|| format!("changing storage for registry '{slug}'"))?;
        Ok((resp.objects, resp.bytes))
    }

    /// Migrates a cache's surface to a different storage backend.
    ///
    /// An empty `binding_name` targets the deployment default store. Returns the
    /// `(objects, bytes)` copied. Calls
    /// `aos.registry.v1.CacheService/ChangeCacheStorage`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the migration RPC fails.
    pub async fn change_cache_storage(
        &self,
        cache_slug: &str,
        binding_name: &str,
    ) -> Result<(u64, u64)> {
        let resp: ChangeCacheStorageResponse = self
            .call(
                "aos.registry.v1.CacheService/ChangeCacheStorage",
                &ChangeCacheStorageRequest {
                    cache_slug: cache_slug.into(),
                    binding_name: binding_name.into(),
                },
            )
            .await
            .with_context(|| format!("changing storage for cache '{cache_slug}'"))?;
        Ok((resp.objects, resp.bytes))
    }

    /// Links (or updates) a managed cache to a registry.
    ///
    /// `advertised` puts the cache in the registry's consumer-facing cache list
    /// by write-through to its committed `registry.toml` `[[caches]]`;
    /// `roots_packages` pins the registry's packages as GC roots in the cache.
    /// Requires `registry.configure` on the registry. Returns the id of the
    /// proposed advertise change request (empty when none was needed — promote
    /// it with `apr change merge`). Calls
    /// `aos.registry.v1.CacheService/LinkCache`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the link RPC fails (unknown
    /// cache/registry, insufficient authority, or a cross-visibility rejection).
    pub async fn link_cache(
        &self,
        cache_slug: &str,
        registry_slug: &str,
        advertised: bool,
        roots_packages: bool,
    ) -> Result<String> {
        let resp: LinkCacheResponse = self
            .call(
                "aos.registry.v1.CacheService/LinkCache",
                &LinkCacheRequest {
                    cache_slug: cache_slug.into(),
                    registry_slug: registry_slug.into(),
                    roots_packages,
                    advertised,
                },
            )
            .await
            .with_context(|| {
                format!("linking cache '{cache_slug}' to registry '{registry_slug}'")
            })?;
        Ok(resp.change_id)
    }

    /// Removes a managed cache's link to a registry.
    ///
    /// De-advertises the cache from the registry's committed `[[caches]]` (if it
    /// was advertised) via a change request. Requires `registry.configure` on the
    /// registry. Returns `(removed, change_id)` — whether a link row was deleted
    /// and the id of any proposed de-advertise change request. Calls
    /// `aos.registry.v1.CacheService/UnlinkCache`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the unlink RPC fails.
    pub async fn unlink_cache(
        &self,
        cache_slug: &str,
        registry_slug: &str,
    ) -> Result<(bool, String)> {
        let resp: UnlinkCacheResponse = self
            .call(
                "aos.registry.v1.CacheService/UnlinkCache",
                &UnlinkCacheRequest {
                    cache_slug: cache_slug.into(),
                    registry_slug: registry_slug.into(),
                },
            )
            .await
            .with_context(|| {
                format!("unlinking cache '{cache_slug}' from registry '{registry_slug}'")
            })?;
        Ok((resp.removed, resp.change_id))
    }

    /// Creates an org-owned, storage-bound managed registry.
    ///
    /// Requires `registry.configure` on the org scope. `project_path` is the
    /// owning project's materialized path (`""` for an org-root registry);
    /// `visibility` is `public`/`internal`/`private`; `binding_name` and `prefix`
    /// place the surface in a storage binding (an empty `binding_name` leaves the
    /// registry unbound); `trust_keys` are pinned anchors in
    /// `name:Ed25519:<base64>` form. Calls
    /// `aos.registry.v1.RegistryService/CreateRegistry`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission, a duplicate canonical path, or an unknown binding), or the
    /// response omits the created registry.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_registry(
        &self,
        org_slug: &str,
        project_path: &str,
        name: &str,
        visibility: &str,
        binding_name: &str,
        prefix: &str,
        trust_keys: Vec<String>,
    ) -> Result<Registry> {
        let resp: CreateRegistryResponse = self
            .call(
                "aos.registry.v1.RegistryService/CreateRegistry",
                &CreateRegistryRequest {
                    org_slug: org_slug.into(),
                    project_path: project_path.into(),
                    name: name.into(),
                    visibility: visibility.into(),
                    binding_name: binding_name.into(),
                    prefix: prefix.into(),
                    trust_keys,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("creating registry '{name}' in org '{org_slug}'"))?;
        resp.registry
            .context("hub returned no registry for the create request")
    }

    /// Lists an org's webhook subscriptions (secrets are never returned).
    ///
    /// Requires `members.manage` on the org scope. Calls
    /// `aos.registry.v1.WebhookService/ListWebhooks`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_webhooks(&self, org_slug: &str) -> Result<Vec<Webhook>> {
        let resp: ListWebhooksResponse = self
            .call(
                "aos.registry.v1.WebhookService/ListWebhooks",
                &ListWebhooksRequest {
                    org_slug: org_slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing webhooks for org '{org_slug}'"))?;
        Ok(resp.webhooks)
    }

    /// Creates a webhook under an org, returning the subscription and its
    /// HMAC-SHA256 signing secret (shown exactly once).
    ///
    /// Requires `members.manage` on the org scope. `events` is the set of
    /// subscribed event types (empty subscribes to all); an empty `secret` asks
    /// the hub to generate one. Calls
    /// `aos.registry.v1.WebhookService/CreateWebhook`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or an unsafe URL), or the response omits the created webhook.
    pub async fn create_webhook(
        &self,
        org_slug: &str,
        url: &str,
        events: Vec<String>,
        secret: &str,
    ) -> Result<(Webhook, String)> {
        let resp: CreateWebhookResponse = self
            .call(
                "aos.registry.v1.WebhookService/CreateWebhook",
                &CreateWebhookRequest {
                    org_slug: org_slug.into(),
                    url: url.into(),
                    events,
                    secret: secret.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("creating webhook in org '{org_slug}'"))?;
        let secret = resp.secret;
        let webhook = resp
            .webhook
            .context("hub returned no webhook for the create request")?;
        Ok((webhook, secret))
    }

    /// Deletes a webhook by id, returning whether one was removed.
    ///
    /// Requires `members.manage` on the owning org's scope. Calls
    /// `aos.registry.v1.WebhookService/DeleteWebhook`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn delete_webhook(&self, id: i64) -> Result<bool> {
        let resp: aos_proto_types::DeleteWebhookResponse = self
            .call(
                "aos.registry.v1.WebhookService/DeleteWebhook",
                &DeleteWebhookRequest {
                    id,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("deleting webhook {id}"))?;
        Ok(resp.deleted)
    }

    /// Mints a short-lived, registry-scoped upload credential for one registry.
    ///
    /// Requires `publish` on the registry's canonical scope. The returned
    /// [`UploadCredentials::token`] is a provisioning secret shown exactly once;
    /// hand it to `apr origin upload --token` or exchange it at `/oauth2/token`.
    /// Calls `aos.registry.v1.PublishService/MintUploadCredentials`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails (e.g. missing
    /// the `publish` permission, or no such registry).
    pub async fn mint_upload_credentials(&self, slug: &str) -> Result<UploadCredentials> {
        let resp: MintUploadCredentialsResponse = self
            .call(
                "aos.registry.v1.PublishService/MintUploadCredentials",
                &MintUploadCredentialsRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("minting upload credentials for '{slug}'"))?;
        Ok(UploadCredentials {
            token: resp.token,
            upload_url: resp.upload_url,
            expires_at: resp.expires_at,
        })
    }

    /// Lists a registry's committed commit log (newest first), the first page.
    ///
    /// Requires `read` on the registry scope (follows registry visibility).
    /// Calls `aos.registry.v1.GitService/GitLog`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_log(&self, slug: &str) -> Result<Vec<GitCommit>> {
        let resp: GitLogResponse = self
            .call(
                "aos.registry.v1.GitService/GitLog",
                &GitLogRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("reading git log for '{slug}'"))?;
        Ok(resp.commits)
    }

    /// Returns a textual diff of a registry's committed config files between two
    /// commits.
    ///
    /// An empty `from_oid` diffs the whole tree as additions; an empty `to_oid`
    /// defaults to the current HEAD. Requires `read` on the registry scope.
    /// Calls `aos.registry.v1.GitService/GitDiff`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_diff(&self, slug: &str, from_oid: &str, to_oid: &str) -> Result<String> {
        let resp: GitDiffResponse = self
            .call(
                "aos.registry.v1.GitService/GitDiff",
                &GitDiffRequest {
                    slug: slug.into(),
                    from_oid: from_oid.into(),
                    to_oid: to_oid.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("diffing '{slug}'"))?;
        Ok(resp.diff)
    }

    /// Lists a registry's draft git-backed change requests.
    ///
    /// Requires `audit.read` on the registry scope. Calls
    /// `aos.registry.v1.GitService/ListChangeRequests`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_change_requests(&self, slug: &str) -> Result<Vec<ChangeRequest>> {
        let resp: ListChangeRequestsResponse = self
            .call(
                "aos.registry.v1.GitService/ListChangeRequests",
                &ListChangeRequestsRequest {
                    slug: slug.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("listing change requests for '{slug}'"))?;
        Ok(resp.change_requests)
    }

    /// Fetches full detail for one package (every version and platform artifact),
    /// or `None` when it does not exist or is not visible to this client.
    ///
    /// Calls `aos.registry.v1.PackageService/GetPackage`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_package(&self, slug: &str, name: &str) -> Result<Option<Package>> {
        let resp: GetPackageResponse = self
            .call(
                "aos.registry.v1.PackageService/GetPackage",
                &GetPackageRequest {
                    slug: slug.into(),
                    name: name.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("fetching package '{name}' in '{slug}'"))?;
        Ok(resp.package)
    }

    /// Fetches one rollout channel with its partition map, or `None` when it does
    /// not exist or is not visible to this client.
    ///
    /// Calls `aos.registry.v1.ChannelService/GetChannel`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_channel(&self, slug: &str, name: &str) -> Result<Option<Channel>> {
        let resp: GetChannelResponse = self
            .call(
                "aos.registry.v1.ChannelService/GetChannel",
                &GetChannelRequest {
                    slug: slug.into(),
                    name: name.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("fetching channel '{name}' in '{slug}'"))?;
        Ok(resp.channel)
    }

    /// Drafts and applies a forward revert of a change-set, returning the new
    /// revert change-set.
    ///
    /// Requires `registry.configure` on the change-set's scope. Calls
    /// `aos.registry.v1.ConfigService/RevertChangeset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or an unknown change-set), or the response omits the revert.
    pub async fn revert_changeset(&self, change_id: &str) -> Result<Changeset> {
        let resp: RevertChangesetResponse = self
            .call(
                "aos.registry.v1.ConfigService/RevertChangeset",
                &RevertChangesetRequest {
                    change_id: change_id.into(),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("reverting change-set '{change_id}'"))?;
        resp.changeset
            .context("hub returned no change-set for the revert request")
    }
}

/// The Connect-JSON error envelope: a stable error `code` and human `message`.
///
/// Returned with a non-2xx HTTP status on failure; see the hub's
/// `aos-hub-core` `RpcError`.
#[derive(serde::Deserialize)]
struct ConnectError {
    /// The Connect error code (e.g. `not_found`, `permission_denied`).
    code: String,
    /// The human-readable error message.
    message: String,
}

/// Returns `s` with a single trailing slash so `format!("{base}{method}")`
/// joins cleanly whether or not the parsed URL already ended in `/`.
fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}
