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
    AuditEntry, AuditServiceClient, Binding, ChangeRequest, Changeset, Channel,
    ChannelServiceClient, ConfigServiceClient, CreateBindingRequest, CreateOrgRequest,
    CreateProjectRequest, CreateRegistryRequest, CreateWebhookRequest, DeleteWebhookRequest,
    GetChannelRequest, GetPackageRequest, GetRegistryRequest, GitCommit, GitDiffRequest,
    GitLogRequest, GitServiceClient, ListAuditRequest, ListBindingsRequest,
    ListChangeRequestsRequest, ListChangesetsRequest, ListChannelsRequest, ListOrgsRequest,
    ListPackagesRequest, ListProjectsRequest, ListRegistriesRequest, ListReleasesRequest,
    ListWebhooksRequest, MintUploadCredentialsRequest, Org, OrgServiceClient, Package,
    PackageServiceClient, PackageSummary, Project, ProjectServiceClient, PublishServiceClient,
    Registry, RegistryServiceClient, Release, RevertChangesetRequest, StorageServiceClient,
    Webhook, WebhookServiceClient,
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
    webhooks: WebhookServiceClient<HttpClient>,
    publish: PublishServiceClient<HttpClient>,
    git: GitServiceClient<HttpClient>,
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
            config: ConfigServiceClient::new(http.clone(), config.clone()),
            webhooks: WebhookServiceClient::new(http.clone(), config.clone()),
            publish: PublishServiceClient::new(http.clone(), config.clone()),
            git: GitServiceClient::new(http, config),
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

    /// Creates an org-owned, storage-bound managed registry.
    ///
    /// Requires `registry.configure` on the org scope. `project_path` is the
    /// owning project's materialized path (`""` for an org-root registry);
    /// `visibility` is `public`/`internal`/`private`; `binding_name` and `prefix`
    /// place the surface in a storage binding (an empty `binding_name` leaves the
    /// registry unbound); `trust_keys` are pinned anchors in
    /// `name:Ed25519:<base64>` form.
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
        let response = self
            .registry
            .create_registry(CreateRegistryRequest {
                org_slug: org_slug.into(),
                project_path: project_path.into(),
                name: name.into(),
                visibility: visibility.into(),
                binding_name: binding_name.into(),
                prefix: prefix.into(),
                trust_keys,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("creating registry '{name}' in org '{org_slug}': {e}"))?;
        response
            .into_owned()
            .registry
            .into_option()
            .context("hub returned no registry for the create request")
    }

    /// Lists an org's webhook subscriptions (secrets are never returned).
    ///
    /// Requires `members.manage` on the org scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_webhooks(&self, org_slug: &str) -> Result<Vec<Webhook>> {
        let response = self
            .webhooks
            .list_webhooks(ListWebhooksRequest {
                org_slug: org_slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing webhooks for org '{org_slug}': {e}"))?;
        Ok(response.into_owned().webhooks)
    }

    /// Creates a webhook under an org, returning the subscription and its
    /// HMAC-SHA256 signing secret (shown exactly once).
    ///
    /// Requires `members.manage` on the org scope. `events` is the set of
    /// subscribed event types (empty subscribes to all); an empty `secret` asks
    /// the hub to generate one.
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
        let response = self
            .webhooks
            .create_webhook(CreateWebhookRequest {
                org_slug: org_slug.into(),
                url: url.into(),
                events,
                secret: secret.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("creating webhook in org '{org_slug}': {e}"))?;
        let response = response.into_owned();
        let secret = response.secret;
        let webhook = response
            .webhook
            .into_option()
            .context("hub returned no webhook for the create request")?;
        Ok((webhook, secret))
    }

    /// Deletes a webhook by id, returning whether one was removed.
    ///
    /// Requires `members.manage` on the owning org's scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn delete_webhook(&self, id: i64) -> Result<bool> {
        let response = self
            .webhooks
            .delete_webhook(DeleteWebhookRequest {
                id,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("deleting webhook {id}: {e}"))?;
        Ok(response.into_owned().deleted)
    }

    /// Mints a short-lived, registry-scoped upload credential for one registry.
    ///
    /// Requires `publish` on the registry's canonical scope. The returned
    /// [`UploadCredentials::token`] is a provisioning secret shown exactly once;
    /// hand it to `apr origin upload --token` or exchange it at `/oauth2/token`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails (e.g. missing
    /// the `publish` permission, or no such registry).
    pub async fn mint_upload_credentials(&self, slug: &str) -> Result<UploadCredentials> {
        let response = self
            .publish
            .mint_upload_credentials(MintUploadCredentialsRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("minting upload credentials for '{slug}': {e}"))?;
        let response = response.into_owned();
        Ok(UploadCredentials {
            token: response.token,
            upload_url: response.upload_url,
            expires_at: response.expires_at,
        })
    }

    /// Lists a registry's committed commit log (newest first), the first page.
    ///
    /// Requires `read` on the registry scope (follows registry visibility).
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_log(&self, slug: &str) -> Result<Vec<GitCommit>> {
        let response = self
            .git
            .git_log(GitLogRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("reading git log for '{slug}': {e}"))?;
        Ok(response.into_owned().commits)
    }

    /// Returns a textual diff of a registry's committed config files between two
    /// commits.
    ///
    /// An empty `from_oid` diffs the whole tree as additions; an empty `to_oid`
    /// defaults to the current HEAD. Requires `read` on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_diff(&self, slug: &str, from_oid: &str, to_oid: &str) -> Result<String> {
        let response = self
            .git
            .git_diff(GitDiffRequest {
                slug: slug.into(),
                from_oid: from_oid.into(),
                to_oid: to_oid.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("diffing '{slug}': {e}"))?;
        Ok(response.into_owned().diff)
    }

    /// Lists a registry's draft git-backed change requests.
    ///
    /// Requires `audit.read` on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_change_requests(&self, slug: &str) -> Result<Vec<ChangeRequest>> {
        let response = self
            .git
            .list_change_requests(ListChangeRequestsRequest {
                slug: slug.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("listing change requests for '{slug}': {e}"))?;
        Ok(response.into_owned().change_requests)
    }

    /// Fetches full detail for one package (every version and platform artifact),
    /// or `None` when it does not exist or is not visible to this client.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_package(&self, slug: &str, name: &str) -> Result<Option<Package>> {
        let response = self
            .packages
            .get_package(GetPackageRequest {
                slug: slug.into(),
                name: name.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("fetching package '{name}' in '{slug}': {e}"))?;
        Ok(response.into_owned().package.into_option())
    }

    /// Fetches one rollout channel with its partition map, or `None` when it does
    /// not exist or is not visible to this client.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_channel(&self, slug: &str, name: &str) -> Result<Option<Channel>> {
        let response = self
            .channels
            .get_channel(GetChannelRequest {
                slug: slug.into(),
                name: name.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("fetching channel '{name}' in '{slug}': {e}"))?;
        Ok(response.into_owned().channel.into_option())
    }

    /// Drafts and applies a forward revert of a change-set, returning the new
    /// revert change-set.
    ///
    /// Requires `registry.configure` on the change-set's scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or an unknown change-set), or the response omits the revert.
    pub async fn revert_changeset(&self, change_id: &str) -> Result<Changeset> {
        let response = self
            .config
            .revert_changeset(RevertChangesetRequest {
                change_id: change_id.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("reverting change-set '{change_id}': {e}"))?;
        response
            .into_owned()
            .changeset
            .into_option()
            .context("hub returned no change-set for the revert request")
    }
}
