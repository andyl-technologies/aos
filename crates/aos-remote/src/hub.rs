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
//! route, `POST {base}/aos.hub.v1.{Service}/{Method}`, with the
//! JSON-encoded request message as the body and the JSON-encoded response
//! message as a `200` body. Errors are the Connect error envelope with a
//! matching non-2xx status:
//!
//! ```text
//! POST /aos.hub.v1.RegistryService/GetRegistry
//! Content-Type: application/json
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```
//!
//! This client speaks that transport directly with `reqwest`, exchanging the
//! [`aos_proto_types`] message structs as JSON. Construct one with
//! [`HubClient::connect_anonymous`] for public reads, or
//! [`HubClient::connect_with_token`] to attach a hub access JWT for private
//! inventory and authorized placement lifecycle calls.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use aos_proto_types::{
    AuditEntry, Binding, ChangeCacheStorageRequest, ChangeCacheStorageResponse,
    ChangeRegistryStorageRequest, ChangeRegistryStorageResponse, ChangeRequest, Changeset, Channel,
    CreateBindingRequest, CreateBindingResponse, CreateOrgRequest, CreateOrgResponse,
    CreatePlacementRequest, CreatePlacementResponse, CreateProjectRequest, CreateProjectResponse,
    CreateRegistryRequest, CreateRegistryResponse, CreateWebhookRequest, CreateWebhookResponse,
    DeletePlacementRequest, DeletePlacementResponse, DeleteWebhookRequest, DrainPlacementRequest,
    DrainPlacementResponse, GetChannelRequest, GetChannelResponse, GetInstanceSettingsRequest,
    GetInstanceSettingsResponse, GetPackageRequest, GetPackageResponse, GetPlacementRequest,
    GetPlacementResponse, GetRegistryRequest, GetRegistryResponse, GetWriteAuthorityRequest,
    GetWriteAuthorityResponse, GitCommit, GitDiffRequest, GitDiffResponse, GitLogRequest,
    GitLogResponse, InstanceSettings, LinkCacheRequest, LinkCacheResponse, ListAuditRequest,
    ListAuditResponse, ListBindingsRequest, ListBindingsResponse, ListChangeRequestsRequest,
    ListChangeRequestsResponse, ListChangesetsRequest, ListChangesetsResponse, ListChannelsRequest,
    ListChannelsResponse, ListOrgsRequest, ListOrgsResponse, ListPackagesRequest,
    ListPackagesResponse, ListPlacementsRequest, ListPlacementsResponse, ListProjectsRequest,
    ListProjectsResponse, ListRegistriesRequest, ListRegistriesResponse, ListReleasesRequest,
    ListReleasesResponse, ListWebhooksRequest, ListWebhooksResponse, MintUploadCredentialsRequest,
    MintUploadCredentialsResponse, Org, Package, PackageSummary, Placement, PlacementHashRange,
    PlacementPromotionPlan, PlanPromotePlacementRequest, PlanPromotePlacementResponse,
    PlanRemoveWriteAuthorityRequest, PlanRemoveWriteAuthorityResponse, Project,
    PromotePlacementRequest, PromotePlacementResponse, ReconcileWriteAuthorityRequest,
    ReconcileWriteAuthorityResponse, Registry, Release, RemoveWriteAuthorityRequest,
    RemoveWriteAuthorityResponse, RevertChangesetRequest, RevertChangesetResponse, SurfaceRef,
    SurfaceWriteAuthority, UnlinkCacheRequest, UnlinkCacheResponse, UpdateInstanceSettingsRequest,
    UpdateInstanceSettingsResponse, UpdatePlacementRequest, UpdatePlacementResponse, Webhook,
};

use crate::client::validate_base_url;

/// Defensive bound for automatically traversing an untrusted Hub's pages.
const MAX_PLACEMENT_PAGES: usize = 10_000;

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
/// [`HubClient::connect_with_token`]) additionally sees what the
/// token's scope/permissions allow.
#[derive(Clone)]
pub struct HubClient {
    /// The shared `reqwest` client (rustls TLS for `https://`).
    http: reqwest::Client,
    /// The hub root with a single trailing slash, e.g. `https://hub.example/`.
    base: String,
    /// The hub access JWT to send as `Authorization: Bearer …`, when present.
    token: Option<String>,
}

/// A short-lived, registry-scoped upload credential minted by the hub.
///
/// Returned by [`HubClient::mint_upload_credentials`]; the `token` is
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

/// A typed registry or binary-cache surface accepted by Hub topology APIs.
///
/// The command-line spelling is `registry:<slug>` or `cache:<slug>`. Keeping
/// the kind explicit prevents a same-looking slug from being resolved against
/// the wrong resource namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubSurfaceRef {
    /// A registry addressed by its canonical slug.
    Registry(String),
    /// A managed binary cache addressed by its slug.
    Cache(String),
}

/// Explicit fields for creating one registry or binary-cache placement.
///
/// Creation never grants write authority. The server owns observations and
/// initializes them to `provisioning`/`unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePlacementInput {
    /// Stable placement name within the surface.
    pub name: String,
    /// Stable storage-binding name in the surface's organization.
    pub storage_binding_name: String,
    /// Binding-relative object prefix.
    pub prefix: String,
    /// Placement kind: `complete`, `shard`, or `archive`.
    pub kind: String,
    /// Desired lifecycle: `active` or `offline`.
    pub desired_state: String,
    /// Whether read policy selection may use the placement.
    pub desired_read_enabled: bool,
    /// Lower values are preferred for reads.
    pub read_order: i64,
    /// Half-open 16-bit shard range; required exactly for a shard.
    pub hash_range: Option<(u32, u32)>,
    /// Whether the writer contract requires conditional object writes.
    pub requires_conditional_writes: bool,
}

/// Explicit desired selection fields for a version-checked placement update.
///
/// Observations and write authority are not generic placement fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlacementInput {
    /// Opaque resource version returned by a preceding placement read.
    pub expected_resource_version: String,
    /// Desired lifecycle: `active` or `offline`.
    pub desired_state: String,
    /// Whether read policy selection may use the placement.
    pub desired_read_enabled: bool,
    /// Lower values are preferred for reads.
    pub read_order: i64,
}

impl HubSurfaceRef {
    /// Converts the ergonomic reference into the public protobuf oneof.
    fn to_message(&self) -> SurfaceRef {
        let target = match self {
            Self::Registry(slug) => {
                aos_proto_types::surface_ref::Target::RegistrySlug(slug.clone())
            }
            Self::Cache(slug) => aos_proto_types::surface_ref::Target::CacheSlug(slug.clone()),
        };
        SurfaceRef {
            target: Some(target),
        }
    }
}

impl fmt::Display for HubSurfaceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(slug) => write!(formatter, "registry:{slug}"),
            Self::Cache(slug) => write!(formatter, "cache:{slug}"),
        }
    }
}

impl FromStr for HubSurfaceRef {
    type Err = anyhow::Error;

    /// Parses `registry:<slug>` or `cache:<slug>` into a typed surface.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown kind or an empty slug.
    fn from_str(value: &str) -> Result<Self> {
        let (kind, slug) = value.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("invalid surface '{value}': expected registry:<slug> or cache:<slug>")
        })?;
        if slug.is_empty() {
            anyhow::bail!("invalid surface '{value}': slug must not be empty");
        }
        match kind {
            "registry" => Ok(Self::Registry(slug.to_string())),
            "cache" => Ok(Self::Cache(slug.to_string())),
            _ => {
                anyhow::bail!("invalid surface '{value}': expected registry:<slug> or cache:<slug>")
            }
        }
    }
}

/// Accepts an unseen continuation token or reports that pagination is done.
fn accept_next_page_token(
    seen_tokens: &mut HashSet<String>,
    next_page_token: String,
    surface: &HubSurfaceRef,
) -> Result<Option<String>> {
    if next_page_token.is_empty() {
        return Ok(None);
    }
    if !seen_tokens.insert(next_page_token.clone()) {
        anyhow::bail!(
            "listing placements for '{surface}': the hub returned a repeated placement page token"
        );
    }
    Ok(Some(next_page_token))
}

impl HubClient {
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
    /// `aos.hub.v1.RegistryService/ListRegistries`), attaching the bearer
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
    /// Calls `aos.hub.v1.RegistryService/ListRegistries`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_registries(&self) -> Result<Vec<Registry>> {
        let resp: ListRegistriesResponse = self
            .call(
                "aos.hub.v1.RegistryService/ListRegistries",
                &ListRegistriesRequest::default(),
            )
            .await
            .context("listing registries")?;
        Ok(resp.registries)
    }

    /// Lists the physical placements of one registry or binary-cache surface.
    ///
    /// Calls `aos.hub.v1.TopologyService/ListPlacements`. Public surfaces may
    /// be read anonymously; private surfaces require an appropriately scoped
    /// bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, an RPC fails, the hub
    /// repeats a continuation token, or traversal exceeds the defensive page
    /// limit.
    pub async fn list_placements(&self, surface: &HubSurfaceRef) -> Result<Vec<Placement>> {
        let mut placements = Vec::new();
        let mut page_token = String::new();
        let mut seen_tokens = HashSet::new();
        for _ in 0..MAX_PLACEMENT_PAGES {
            let resp: ListPlacementsResponse = self
                .call(
                    "aos.hub.v1.TopologyService/ListPlacements",
                    &ListPlacementsRequest {
                        surface: Some(surface.to_message()),
                        page_size: 100,
                        page_token,
                    },
                )
                .await
                .with_context(|| format!("listing placements for '{surface}'"))?;
            placements.extend(resp.placements);
            let Some(next_page_token) =
                accept_next_page_token(&mut seen_tokens, resp.next_page_token, surface)?
            else {
                return Ok(placements);
            };
            page_token = next_page_token;
        }
        anyhow::bail!("listing placements for '{surface}' exceeded {MAX_PLACEMENT_PAGES} pages")
    }

    /// Fetches one placement by its stable surface-local name.
    ///
    /// Calls `aos.hub.v1.TopologyService/GetPlacement`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_placement(&self, surface: &HubSurfaceRef, name: &str) -> Result<Placement> {
        let resp: GetPlacementResponse = self
            .call(
                "aos.hub.v1.TopologyService/GetPlacement",
                &GetPlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.to_string(),
                },
            )
            .await
            .with_context(|| format!("fetching placement '{name}' from '{surface}'"))?;
        resp.placement
            .context("the hub returned GetPlacement without a placement")
    }

    /// Creates one placement on a typed registry or binary-cache surface.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid request, insufficient topology/storage
    /// authority, a conflicting placement, or a transport/protocol failure.
    pub async fn create_placement(
        &self,
        surface: &HubSurfaceRef,
        input: &CreatePlacementInput,
    ) -> Result<Placement> {
        let resp: CreatePlacementResponse = self
            .call(
                "aos.hub.v1.TopologyService/CreatePlacement",
                &CreatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: input.name.clone(),
                    storage_binding_name: input.storage_binding_name.clone(),
                    prefix: input.prefix.clone(),
                    kind: input.kind.clone(),
                    desired_state: input.desired_state.clone(),
                    desired_read_enabled: Some(input.desired_read_enabled),
                    read_order: Some(input.read_order),
                    hash_range: input
                        .hash_range
                        .map(|(start, end)| PlacementHashRange { start, end }),
                    requires_conditional_writes: input.requires_conditional_writes,
                },
            )
            .await
            .with_context(|| format!("creating placement '{}' on '{surface}'", input.name))?;
        resp.placement
            .context("the hub returned CreatePlacement without a placement")
    }

    /// Replaces all publicly mutable fields of one placement under a CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid desired selection, a stale resource
    /// version, insufficient authority, or a transport/protocol failure.
    pub async fn update_placement(
        &self,
        surface: &HubSurfaceRef,
        name: &str,
        input: &UpdatePlacementInput,
    ) -> Result<Placement> {
        let resp: UpdatePlacementResponse = self
            .call(
                "aos.hub.v1.TopologyService/UpdatePlacement",
                &UpdatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.to_string(),
                    expected_resource_version: input.expected_resource_version.clone(),
                    desired_state: input.desired_state.clone(),
                    desired_read_enabled: Some(input.desired_read_enabled),
                    read_order: Some(input.read_order),
                },
            )
            .await
            .with_context(|| format!("updating placement '{name}' on '{surface}'"))?;
        resp.placement
            .context("the hub returned UpdatePlacement without a placement")
    }

    /// Fetches the desired and observed writer for a surface.
    ///
    /// A successful `None` means the surface is explicitly read-only.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_write_authority(
        &self,
        surface: &HubSurfaceRef,
    ) -> Result<Option<SurfaceWriteAuthority>> {
        let response: GetWriteAuthorityResponse = self
            .call(
                "aos.hub.v1.TopologyService/GetWriteAuthority",
                &GetWriteAuthorityRequest {
                    surface: Some(surface.to_message()),
                },
            )
            .await
            .with_context(|| format!("fetching write authority for '{surface}'"))?;
        Ok(response.authority)
    }

    /// Creates an immutable impact plan for initial authority or promotion.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate is ineligible, authority is already
    /// reconciling, or transport/protocol handling fails.
    pub async fn plan_promote_placement(
        &self,
        surface: &HubSurfaceRef,
        candidate_name: &str,
    ) -> Result<PlacementPromotionPlan> {
        let response: PlanPromotePlacementResponse = self
            .call(
                "aos.hub.v1.TopologyService/PlanPromotePlacement",
                &PlanPromotePlacementRequest {
                    surface: Some(surface.to_message()),
                    candidate_placement_name: candidate_name.to_string(),
                },
            )
            .await
            .with_context(|| {
                format!("planning promotion of placement '{candidate_name}' on '{surface}'")
            })?;
        response
            .plan
            .context("the hub returned PlanPromotePlacement without a plan")
    }

    /// Applies one immutable placement-promotion plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is stale, expired, consumed, belongs to
    /// another actor/surface, or transport/protocol handling fails.
    pub async fn promote_placement(
        &self,
        surface: &HubSurfaceRef,
        plan_id: &str,
    ) -> Result<SurfaceWriteAuthority> {
        let response: PromotePlacementResponse = self
            .call(
                "aos.hub.v1.TopologyService/PromotePlacement",
                &PromotePlacementRequest {
                    surface: Some(surface.to_message()),
                    plan_id: plan_id.to_string(),
                },
            )
            .await
            .with_context(|| format!("applying placement promotion plan '{plan_id}'"))?;
        response
            .authority
            .context("the hub returned PromotePlacement without authority")
    }

    /// Records a service-account controller result for one desired generation.
    ///
    /// `state` is `ready` or `failed`; `error` is required exactly for a failed
    /// result. The authority resource version and generation prevent stale
    /// retries from observing a newer promotion.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, invalid state/error fields, lost
    /// candidate eligibility, or transport/protocol failure.
    pub async fn reconcile_write_authority(
        &self,
        surface: &HubSurfaceRef,
        expected_resource_version: &str,
        desired_generation: i64,
        state: &str,
        error: Option<&str>,
    ) -> Result<SurfaceWriteAuthority> {
        let response: ReconcileWriteAuthorityResponse = self
            .call(
                "aos.hub.v1.TopologyService/ReconcileWriteAuthority",
                &ReconcileWriteAuthorityRequest {
                    surface: Some(surface.to_message()),
                    expected_resource_version: expected_resource_version.to_string(),
                    desired_generation,
                    state: state.to_string(),
                    error: error.unwrap_or_default().to_string(),
                },
            )
            .await
            .with_context(|| {
                format!("reconciling write authority generation {desired_generation}")
            })?;
        response
            .authority
            .context("the hub returned ReconcileWriteAuthority without authority")
    }

    /// Creates an immutable plan to make a surface explicitly read-only.
    ///
    /// # Errors
    ///
    /// Returns an error unless authority is fully reconciled, or when the RPC
    /// transport fails.
    pub async fn plan_remove_write_authority(
        &self,
        surface: &HubSurfaceRef,
    ) -> Result<aos_proto_types::RemoveWriteAuthorityPlan> {
        let response: PlanRemoveWriteAuthorityResponse = self
            .call(
                "aos.hub.v1.TopologyService/PlanRemoveWriteAuthority",
                &PlanRemoveWriteAuthorityRequest {
                    surface: Some(surface.to_message()),
                },
            )
            .await
            .with_context(|| format!("planning read-only transition for '{surface}'"))?;
        response
            .plan
            .context("the hub returned PlanRemoveWriteAuthority without a plan")
    }

    /// Applies one immutable read-only transition plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is stale, expired, or consumed, or when
    /// transport/protocol handling fails.
    pub async fn remove_write_authority(
        &self,
        surface: &HubSurfaceRef,
        plan_id: &str,
    ) -> Result<()> {
        let response: RemoveWriteAuthorityResponse = self
            .call(
                "aos.hub.v1.TopologyService/RemoveWriteAuthority",
                &RemoveWriteAuthorityRequest {
                    surface: Some(surface.to_message()),
                    plan_id: plan_id.to_string(),
                },
            )
            .await
            .with_context(|| format!("applying read-only transition plan '{plan_id}'"))?;
        if !response.removed {
            anyhow::bail!("the hub did not remove write authority");
        }
        Ok(())
    }

    /// Plans or applies a non-authority placement drain under a CAS.
    ///
    /// Apply revalidates the version and route pins before mutating.
    ///
    /// # Errors
    ///
    /// Returns an error for an authority-owned placement, stale resource version,
    /// insufficient authority, or a transport/protocol failure.
    pub async fn drain_placement(
        &self,
        surface: &HubSurfaceRef,
        name: &str,
        expected_resource_version: &str,
        apply: bool,
    ) -> Result<DrainPlacementResponse> {
        self.call(
            "aos.hub.v1.TopologyService/DrainPlacement",
            &DrainPlacementRequest {
                surface: Some(surface.to_message()),
                name: name.to_string(),
                expected_resource_version: expected_resource_version.to_string(),
                apply,
            },
        )
        .await
        .with_context(|| format!("draining placement '{name}' on '{surface}'"))
    }

    /// Plans or applies placement metadata deletion under a CAS.
    ///
    /// Apply revalidates the version and all dependent references before
    /// deleting metadata; backing storage objects are not removed.
    ///
    /// # Errors
    ///
    /// Returns an error when deletion is unsafe, the resource version is stale,
    /// authority is insufficient, or transport/protocol handling fails.
    pub async fn delete_placement(
        &self,
        surface: &HubSurfaceRef,
        name: &str,
        expected_resource_version: &str,
        apply: bool,
    ) -> Result<DeletePlacementResponse> {
        self.call(
            "aos.hub.v1.TopologyService/DeletePlacement",
            &DeletePlacementRequest {
                surface: Some(surface.to_message()),
                name: name.to_string(),
                expected_resource_version: expected_resource_version.to_string(),
                apply,
            },
        )
        .await
        .with_context(|| format!("deleting placement '{name}' on '{surface}'"))
    }

    /// Fetches one registry by slug, or `None` when it does not exist or is not
    /// visible to this client.
    ///
    /// Calls `aos.hub.v1.RegistryService/GetRegistry`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails for a reason
    /// other than "not found".
    pub async fn get_registry(&self, slug: &str) -> Result<Option<Registry>> {
        let resp: GetRegistryResponse = self
            .call(
                "aos.hub.v1.RegistryService/GetRegistry",
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
    /// Calls `aos.hub.v1.RegistryService/ListReleases`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_releases(&self, slug: &str) -> Result<Vec<Release>> {
        let resp: ListReleasesResponse = self
            .call(
                "aos.hub.v1.RegistryService/ListReleases",
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
    /// Calls `aos.hub.v1.PackageService/ListPackages`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_packages(&self, slug: &str) -> Result<Vec<PackageSummary>> {
        let resp: ListPackagesResponse = self
            .call(
                "aos.hub.v1.PackageService/ListPackages",
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
    /// Calls `aos.hub.v1.ChannelService/ListChannels`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_channels(&self, slug: &str) -> Result<Vec<Channel>> {
        let resp: ListChannelsResponse = self
            .call(
                "aos.hub.v1.ChannelService/ListChannels",
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
    /// sees none. Calls `aos.hub.v1.OrganizationService/ListOrgs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_orgs(&self) -> Result<Vec<Org>> {
        let resp: ListOrgsResponse = self
            .call(
                "aos.hub.v1.OrganizationService/ListOrgs",
                &ListOrgsRequest::default(),
            )
            .await
            .context("listing orgs")?;
        Ok(resp.orgs)
    }

    /// Lists the projects under an org.
    ///
    /// Calls `aos.hub.v1.ProjectService/ListProjects`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_projects(&self, org_slug: &str) -> Result<Vec<Project>> {
        let resp: ListProjectsResponse = self
            .call(
                "aos.hub.v1.ProjectService/ListProjects",
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
    /// Calls `aos.hub.v1.StorageBindingService/ListBindings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_bindings(&self, org_slug: &str) -> Result<Vec<Binding>> {
        let resp: ListBindingsResponse = self
            .call(
                "aos.hub.v1.StorageBindingService/ListBindings",
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
    /// `aos.hub.v1.AuditService/ListAudit`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_audit(&self, scope: &str) -> Result<Vec<AuditEntry>> {
        let resp: ListAuditResponse = self
            .call(
                "aos.hub.v1.AuditService/ListAudit",
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
    /// Calls `aos.hub.v1.InstanceService/GetInstanceSettings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the caller is not an instance
    /// admin, or the response omits the settings payload.
    pub async fn get_instance_settings(&self) -> Result<InstanceSettings> {
        let resp: GetInstanceSettingsResponse = self
            .call(
                "aos.hub.v1.InstanceService/GetInstanceSettings",
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
    /// `aos.hub.v1.InstanceService/UpdateInstanceSettings`.
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
                "aos.hub.v1.InstanceService/UpdateInstanceSettings",
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
    /// `aos.hub.v1.RegistryConfigurationService/ListChangesets`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_changesets(&self, scope: &str) -> Result<Vec<Changeset>> {
        let resp: ListChangesetsResponse = self
            .call(
                "aos.hub.v1.RegistryConfigurationService/ListChangesets",
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
    /// `aos.hub.v1.OrganizationService/CreateOrg`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. the slug
    /// is taken or the caller is unauthenticated), or the response omits the
    /// created org.
    pub async fn create_org(&self, slug: &str, name: &str) -> Result<Org> {
        let resp: CreateOrgResponse = self
            .call(
                "aos.hub.v1.OrganizationService/CreateOrg",
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
    /// `aos.hub.v1.ProjectService/CreateProject`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or a duplicate path), or the response omits the created
    /// project.
    pub async fn create_project(&self, org_slug: &str, path: &str, name: &str) -> Result<Project> {
        let resp: CreateProjectResponse = self
            .call(
                "aos.hub.v1.ProjectService/CreateProject",
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
    /// Calls `aos.hub.v1.StorageBindingService/CreateBinding`.
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
                "aos.hub.v1.StorageBindingService/CreateBinding",
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
    /// `aos.hub.v1.RegistryService/ChangeRegistryStorage`.
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
                "aos.hub.v1.RegistryService/ChangeRegistryStorage",
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
    /// `aos.hub.v1.BinaryCacheService/ChangeCacheStorage`.
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
                "aos.hub.v1.BinaryCacheService/ChangeCacheStorage",
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
    /// `aos.hub.v1.BinaryCacheService/LinkCache`.
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
                "aos.hub.v1.BinaryCacheService/LinkCache",
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
    /// `aos.hub.v1.BinaryCacheService/UnlinkCache`.
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
                "aos.hub.v1.BinaryCacheService/UnlinkCache",
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
    /// `aos.hub.v1.RegistryService/CreateRegistry`.
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
                "aos.hub.v1.RegistryService/CreateRegistry",
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
    /// `aos.hub.v1.WebhookService/ListWebhooks`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_webhooks(&self, org_slug: &str) -> Result<Vec<Webhook>> {
        let resp: ListWebhooksResponse = self
            .call(
                "aos.hub.v1.WebhookService/ListWebhooks",
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
    /// `aos.hub.v1.WebhookService/CreateWebhook`.
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
                "aos.hub.v1.WebhookService/CreateWebhook",
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
    /// `aos.hub.v1.WebhookService/DeleteWebhook`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn delete_webhook(&self, id: i64) -> Result<bool> {
        let resp: aos_proto_types::DeleteWebhookResponse = self
            .call(
                "aos.hub.v1.WebhookService/DeleteWebhook",
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
    /// Calls `aos.hub.v1.PublishService/MintUploadCredentials`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails (e.g. missing
    /// the `publish` permission, or no such registry).
    pub async fn mint_upload_credentials(&self, slug: &str) -> Result<UploadCredentials> {
        let resp: MintUploadCredentialsResponse = self
            .call(
                "aos.hub.v1.PublishService/MintUploadCredentials",
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
    /// Calls `aos.hub.v1.GitService/GitLog`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_log(&self, slug: &str) -> Result<Vec<GitCommit>> {
        let resp: GitLogResponse = self
            .call(
                "aos.hub.v1.GitService/GitLog",
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
    /// Calls `aos.hub.v1.GitService/GitDiff`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn git_diff(&self, slug: &str, from_oid: &str, to_oid: &str) -> Result<String> {
        let resp: GitDiffResponse = self
            .call(
                "aos.hub.v1.GitService/GitDiff",
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
    /// `aos.hub.v1.GitService/ListChangeRequests`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn list_change_requests(&self, slug: &str) -> Result<Vec<ChangeRequest>> {
        let resp: ListChangeRequestsResponse = self
            .call(
                "aos.hub.v1.GitService/ListChangeRequests",
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
    /// Calls `aos.hub.v1.PackageService/GetPackage`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_package(&self, slug: &str, name: &str) -> Result<Option<Package>> {
        let resp: GetPackageResponse = self
            .call(
                "aos.hub.v1.PackageService/GetPackage",
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
    /// Calls `aos.hub.v1.ChannelService/GetChannel`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable or the RPC fails.
    pub async fn get_channel(&self, slug: &str, name: &str) -> Result<Option<Channel>> {
        let resp: GetChannelResponse = self
            .call(
                "aos.hub.v1.ChannelService/GetChannel",
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
    /// `aos.hub.v1.RegistryConfigurationService/RevertChangeset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the RPC fails (e.g. missing
    /// permission or an unknown change-set), or the response omits the revert.
    pub async fn revert_changeset(&self, change_id: &str) -> Result<Changeset> {
        let resp: RevertChangesetResponse = self
            .call(
                "aos.hub.v1.RegistryConfigurationService/RevertChangeset",
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

#[cfg(test)]
mod tests {
    use super::{accept_next_page_token, HubSurfaceRef};
    use aos_proto_types::surface_ref::Target;
    use aos_proto_types::{CreatePlacementRequest, UpdatePlacementRequest};
    use std::collections::HashSet;
    use std::str::FromStr as _;

    #[test]
    fn surface_ref_parser_preserves_kind_and_nested_slug() {
        assert_eq!(
            HubSurfaceRef::from_str("registry:andyl/infra/main").unwrap(),
            HubSurfaceRef::Registry("andyl/infra/main".to_string())
        );
        assert_eq!(
            HubSurfaceRef::from_str("cache:release-cache").unwrap(),
            HubSurfaceRef::Cache("release-cache".to_string())
        );
    }

    #[test]
    fn surface_ref_parser_rejects_ambiguous_or_empty_values() {
        for value in ["andyl/main", "registry:", "cache:", "bucket:main"] {
            assert!(HubSurfaceRef::from_str(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn surface_refs_round_trip_as_canonical_oneofs() {
        for (surface, key, slug) in [
            (
                HubSurfaceRef::Registry("andyl/main".to_string()),
                "registrySlug",
                "andyl/main",
            ),
            (
                HubSurfaceRef::Cache("release-cache".to_string()),
                "cacheSlug",
                "release-cache",
            ),
        ] {
            let json = serde_json::to_value(surface.to_message()).unwrap();
            assert_eq!(json[key], slug);
            assert!(json.get("target").is_none());
            let decoded: aos_proto_types::SurfaceRef = serde_json::from_value(json).unwrap();
            let expected = match surface {
                HubSurfaceRef::Registry(slug) => Target::RegistrySlug(slug),
                HubSurfaceRef::Cache(slug) => Target::CacheSlug(slug),
            };
            assert_eq!(decoded.target, Some(expected));
        }
    }

    #[test]
    fn placement_mutations_serialize_normalized_specs_and_camel_case_fields() {
        let surface = Some(HubSurfaceRef::Cache("nix".to_string()).to_message());
        let create = serde_json::to_value(CreatePlacementRequest {
            surface: surface.clone(),
            name: "replica".to_string(),
            storage_binding_name: "origin".to_string(),
            prefix: "cache/replica".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            desired_read_enabled: Some(true),
            read_order: Some(10),
            hash_range: None,
            requires_conditional_writes: false,
        })
        .unwrap();
        assert_eq!(create["surface"]["cacheSlug"], "nix");
        assert_eq!(create["storageBindingName"], "origin");
        assert_eq!(create["kind"], "complete");
        assert_eq!(create["desiredReadEnabled"], true);
        assert!(create.get("writeEnabled").is_none());
        assert!(create.get("writeOrder").is_none());
        assert!(create.get("storage_binding_name").is_none());
        assert!(create.get("state").is_none());
        assert!(create.get("completeness").is_none());

        let update = serde_json::to_value(UpdatePlacementRequest {
            surface,
            name: "replica".to_string(),
            expected_resource_version: "7".to_string(),
            desired_state: "active".to_string(),
            desired_read_enabled: Some(true),
            read_order: Some(30),
        })
        .unwrap();
        assert_eq!(update["expectedResourceVersion"], "7");
        assert_eq!(update["desiredReadEnabled"], true);
        assert!(update.get("writeEnabled").is_none());
        assert!(update.get("state").is_none());
        assert!(update.get("completeness").is_none());
    }

    #[test]
    fn placement_pagination_stops_and_reports_surface_on_token_cycles() {
        let mut seen = HashSet::new();
        let surface = HubSurfaceRef::Cache("release-cache".to_string());
        assert_eq!(
            accept_next_page_token(&mut seen, "page-2".to_string(), &surface).unwrap(),
            Some("page-2".to_string())
        );
        let error = accept_next_page_token(&mut seen, "page-2".to_string(), &surface)
            .unwrap_err()
            .to_string();
        assert!(error.contains("listing placements for 'cache:release-cache'"));
        assert_eq!(
            accept_next_page_token(&mut seen, String::new(), &surface).unwrap(),
            None
        );
    }
}
