//! The dependency bundle and platform ports the shared console handlers run on.
//!
//! The producer-console handlers ([`super`]) are transport- and runtime-neutral
//! HTTP handlers: they speak [`axum`] *types* (never an HTTP server), read and
//! write the shared [`Database`](crate::db::Database), and reach every
//! platform-specific capability through a *port* — a trait each deployment
//! satisfies with its own concrete type. That keeps the handlers
//! `wasm32-unknown-unknown`-clean (RFC-0004 Phase 5, console-dedup stage B) so
//! the native hub and the Cloudflare Worker mount the same console.
//!
//! [`ConsoleDeps`] is the bundle a handler's `axum` `State` carries. It holds:
//!
//! - the shared [`Database`](crate::db::Database) and the HS256
//!   [`JwtKeys`](crate::auth::jwt::JwtKeys);
//! - the externally reachable base URL and the `--dev` flag (which surfaces the
//!   magic-link URL on the "check your email" page);
//! - the three abstractions core already owns — the
//!   [`RateLimiter`](crate::ratelimit::RateLimiter) abuse bound, the
//!   [`Mailer`](crate::auth::magic::Mailer) magic-link sender, and the
//!   [`SecretSealer`](crate::auth::seal::SecretSealer) that unseals an OIDC
//!   client secret;
//! - and the [`HttpClient`] port defined here for the OIDC flow's outbound HTTP.
//!
//! Mutations with topology or publication impact are never performed directly
//! through runtime adapters. They first enter a normalized service plan/apply
//! operation; read-only pages may still use the surface ports below.
//!
//! The native hub satisfies [`HttpClient`] with its hardened [`reqwest`] client;
//! the Worker satisfies it through the fixed authenticated egress gateway.

use std::sync::Arc;

use crate::auth::jwt::JwtKeys;
use crate::auth::magic::Mailer;
use crate::auth::seal::SecretSealer;
use crate::backend::BackendBounds;
use crate::db::Database;
use crate::fetch::SurfaceProvider;
use crate::ratelimit::RateLimiter;
use crate::reindex::Reindexer;
use crate::surface_write::SurfaceWriteProvider;

/// The dependency bundle the shared console handlers carry as `axum` `State`.
///
/// A clone is cheap: every field is an [`Arc`], a small `Copy` flag, or a
/// `String`/[`JwtKeys`] that clones shallowly. The native hub builds one from
/// its `AppState`; the Worker (stage C) builds one from its request-scoped
/// environment.
#[derive(Clone)]
pub struct ConsoleDeps {
    /// The shared hub database (one implementation over the async backend).
    pub db: Arc<Database>,
    /// HS256 keys minting and verifying the bearer JWTs the console issues for
    /// device-grant approval and token operations.
    pub jwt_keys: JwtKeys,
    /// The externally reachable base URL, used to build magic-link and OIDC
    /// redirect URLs and the WebAuthn relying-party id.
    pub external_url: String,
    /// Whether the hub runs in `--dev` mode; when set, the "check your email"
    /// page surfaces the magic-link URL directly (no real mail is sent).
    pub dev: bool,
    /// The abuse-bound rate limiter (the [`RateLimiter`] port), metering the
    /// pre-auth login paths and the device-approval surface.
    pub ratelimit: Arc<dyn RateLimiter>,
    /// The magic-link email sender (the [`Mailer`] port).
    pub mailer: Arc<dyn Mailer>,
    /// The at-rest secret sealer (the [`SecretSealer`] port), used to unseal an
    /// org's OIDC client secret at the token exchange.
    pub sealer: Arc<dyn SecretSealer>,
    /// Outbound HTTP for the OIDC flow (the [`HttpClient`] port).
    pub http: Arc<dyn HttpClient>,
    /// Per-registry surface **read** access (the [`SurfaceProvider`] port),
    /// used by the git-backed config/change-request flow to read the base
    /// commit's `registry.toml` and the committed history.
    pub surface: Arc<dyn SurfaceProvider>,
    /// Per-registry surface **write** access (the [`SurfaceWriteProvider`]
    /// port), used by the git-backed config-change-request flow to write the
    /// draft commit's loose objects and ref.
    pub surface_write: Arc<dyn SurfaceWriteProvider>,
    /// Per-registry re-index (the [`Reindexer`] port), run after reviewed
    /// publication writes land; the Worker also has its Cron indexer as a
    /// backstop.
    pub reindexer: Arc<dyn Reindexer>,
    /// Human-readable location of the deployment-provisioned default binding.
    ///
    /// This is display metadata for the instance-settings page, not an implicit
    /// write destination. Registries and caches use storage only through
    /// explicit placements. `None` means the deployment did not advertise a
    /// display location, so the UI falls back to "configured at deploy time".
    pub default_storage_location: Option<String>,
    /// The hot-state key-value store ([`KvStore`](crate::kv::KvStore)) for
    /// read-through caching (RFC-0004 ch.14 Phase C). `None` disables caching
    /// (the database is authoritative). The console uses it to **invalidate** the
    /// token cache on retirement (a `tokrev:` tombstone) so a retired token is
    /// rejected immediately rather than after the cache TTL.
    pub kv: Option<Arc<dyn crate::kv::KvStore>>,
    /// Typed topology mutation port shared with the Connect-JSON API.
    ///
    /// Implementations delegate to [`crate::service::RpcService`], preserving
    /// the same authorization, immutable-plan, staleness, and apply semantics
    /// used by the CLI and API.
    pub topology: Arc<dyn TopologyConsole>,
}

impl ConsoleDeps {
    /// Tombstones a token id in KV so any cached resolution for it is rejected
    /// (call on revoke/rotate). A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached. Mirrors
    /// [`RpcService::invalidate_token_cache`](crate::service::RpcService::invalidate_token_cache).
    pub async fn invalidate_token_cache(&self, token_id: &str) {
        if let Some(kv) = &self.kv {
            let ttl = crate::cache::HOT_TTL_SECS * 10;
            let _ = kv.put(&format!("tokrev:{token_id}"), b"1", Some(ttl)).await;
        }
    }
}

/// A human-facing reference to one topology-owning surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologySurface {
    /// A registry addressed by its canonical nested slug.
    Registry(String),
    /// A binary cache addressed by its organization-scoped canonical slug.
    Cache(String),
}

/// Stable-identity projection of creation-time topology defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopologyDefaultsOverview {
    /// Canonical owner scope.
    pub scope_key: String,
    /// Default storage binding stable id.
    pub storage_binding_id: String,
    /// Default delivery-domain stable id.
    pub domain_id: String,
    /// Default delivery endpoint stable id.
    pub delivery_endpoint_id: String,
    /// Exact default endpoint generation.
    pub delivery_endpoint_generation: i64,
    /// Default storage gateway stable id.
    pub storage_gateway_id: String,
    /// Exact default gateway generation.
    pub storage_gateway_generation: i64,
    /// Optimistic concurrency version.
    pub resource_version: String,
}

impl TopologySurface {
    fn into_proto(self) -> aos_proto_types::SurfaceRef {
        use aos_proto_types::surface_ref::Target;
        aos_proto_types::SurfaceRef {
            target: Some(match self {
                Self::Registry(slug) => Target::RegistrySlug(slug),
                Self::Cache(slug) => Target::CacheSlug(slug),
            }),
        }
    }
}

/// An immutable topology plan rendered for explicit human review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedPlan {
    /// Opaque server-issued plan identifier consumed by apply.
    pub plan_id: String,
    /// Unix timestamp after which apply must reject the plan.
    pub expires_at: i64,
    /// Ordered concrete effects the apply will perform.
    pub effects: Vec<String>,
    /// Warnings that require attention before apply.
    pub warnings: Vec<String>,
    /// Confirmation hash required by destructive operations, when any.
    pub confirmation_hash: Option<String>,
}

/// The observed write-authority state returned after a successful apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteAuthorityOutcome {
    /// Desired writer placement name.
    pub desired_placement_name: String,
    /// Observed writer placement name, empty while reconciliation is pending.
    pub observed_placement_name: String,
    /// Reconciliation state reported by the control plane.
    pub reconciliation_state: String,
    /// Desired authority generation.
    pub desired_generation: i64,
}

/// One reviewed placement lifecycle transition exposed by the Web adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementLifecycleAction {
    /// Stops selecting a placement for reads and schedules a durable drain.
    Drain,
    /// Deletes placement metadata after all authority and route pins are gone.
    Delete,
}

/// Desired fields accepted by the placement-creation review form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementCreateSpec {
    /// Stable name within the surface.
    pub name: String,
    /// Stable identity of the storage binding to use.
    pub storage_binding_id: String,
    /// Surface-relative object prefix within the binding.
    pub prefix: String,
    /// Complete, shard, or archive placement shape.
    pub kind: String,
    /// Initial active, draining, or offline desired lifecycle.
    pub desired_state: String,
    /// Whether read selection may choose this placement.
    pub desired_read_enabled: bool,
    /// Lower-priority read ordering value.
    pub read_order: i64,
    /// Half-open 16-bit range required exactly for a shard.
    pub hash_range: Option<(u32, u32)>,
    /// Whether the writer contract requires conditional object writes.
    pub requires_conditional_writes: bool,
}

/// Mutable desired fields accepted by the placement-update review form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementUpdateSpec {
    /// New active or offline desired lifecycle.
    pub desired_state: String,
    /// Whether read selection may choose this placement.
    pub desired_read_enabled: bool,
    /// Lower-priority read ordering value.
    pub read_order: i64,
}

/// Typed topology control-plane operations available to Web settings pages.
///
/// The Web layer passes a short-lived bearer token representing the resolved
/// session actor. Implementations MUST use the same service methods exposed by
/// Connect-JSON; direct database mutation is outside this port's contract.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait TopologyConsole: BackendBounds {
    /// Lists retained signing-key identities for one owner scope.
    async fn signing_keys(
        &self,
        bearer: &str,
        scope_key: String,
    ) -> Result<Vec<aos_proto_types::SigningKey>, crate::service::RpcError>;

    /// Plans enrollment of one external signing-key generation.
    async fn plan_signing_key_enrollment(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed signing-key enrollment.
    async fn apply_signing_key_enrollment(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError>;

    /// Plans appending one external public generation to a signing-key identity.
    async fn plan_signing_key_rotation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed signing-key rotation.
    async fn apply_signing_key_rotation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError>;

    /// Plans retirement of the current signing-key generation.
    async fn plan_signing_key_retirement(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanRetireSigningKeyRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed signing-key retirement.
    async fn apply_signing_key_retirement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError>;

    /// Plans replacement of one typed surface signing-key usage.
    async fn plan_signing_key_usage(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyUsageRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed surface signing-key usage.
    async fn apply_signing_key_usage(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyUsageResponse, crate::service::RpcError>;

    /// Plans creation of one organization and its initial owner grant.
    async fn plan_create_organization(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCreateOrganizationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed organization-creation plan.
    async fn apply_create_organization(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::OrganizationResponse, crate::service::RpcError>;

    /// Plans deletion of one exact organization revision.
    async fn plan_delete_organization(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanDeleteOrganizationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed organization-deletion plan.
    async fn apply_delete_organization(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError>;

    /// Reads one direct membership and its exact resource version.
    async fn membership(
        &self,
        bearer: &str,
        request: aos_proto_types::GetMembershipRequest,
    ) -> Result<aos_proto_types::MembershipResponse, crate::service::RpcError>;

    /// Plans replacement or removal of one direct membership.
    async fn plan_membership(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSetMembershipRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed direct-membership replacement.
    async fn apply_membership(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::MembershipResponse, crate::service::RpcError>;

    /// Lists invitation history visible to an organization member manager.
    async fn invitations(
        &self,
        bearer: &str,
        org_slug: String,
    ) -> Result<Vec<aos_proto_types::Invitation>, crate::service::RpcError>;

    /// Plans creation of one pending organization invitation.
    async fn plan_invitation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCreateInvitationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed invitation-creation plan.
    async fn apply_invitation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::InvitationResponse, crate::service::RpcError>;

    /// Plans cancellation of one pending organization invitation.
    async fn plan_invitation_cancellation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCancelInvitationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed invitation-cancellation plan.
    async fn apply_invitation_cancellation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::InvitationResponse, crate::service::RpcError>;

    /// Accepts one invitation as the authenticated matching user.
    async fn accept_invitation(
        &self,
        bearer: &str,
        request: aos_proto_types::AcceptInvitationRequest,
    ) -> Result<aos_proto_types::AcceptInvitationResponse, crate::service::RpcError>;

    /// Reads the full effective instance-settings bundle and exact revision.
    async fn instance_settings(
        &self,
        bearer: &str,
    ) -> Result<aos_proto_types::GetInstanceSettingsResponse, crate::service::RpcError>;

    /// Plans an exact-version replacement of selected instance settings.
    async fn plan_instance_settings(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSetInstanceSettingsRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one immutable instance-settings plan.
    async fn apply_instance_settings(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::GetInstanceSettingsResponse, crate::service::RpcError>;

    /// Plans issuance of one scoped access-token generation.
    async fn plan_access_token_issue(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanIssueAccessTokenRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed access-token issuance plan.
    async fn apply_access_token_issue(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::AccessTokenResponse, crate::service::RpcError>;

    /// Plans retirement of one exact active access-token generation.
    async fn plan_access_token_retirement(
        &self,
        bearer: &str,
        token_id: String,
        expected_resource_version: String,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one reviewed access-token retirement plan.
    async fn apply_access_token_retirement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;

    /// Reads organization creation defaults through the normalized service contract.
    async fn organization_topology_defaults(
        &self,
        bearer: &str,
        org_slug: String,
    ) -> Result<TopologyDefaultsOverview, crate::service::RpcError>;

    /// Plans creation of one immutable storage-binding identity.
    async fn plan_create_storage_binding(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanStorageBindingMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed storage-binding creation.
    async fn apply_create_storage_binding(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<String, crate::service::RpcError>;

    /// Plans deletion of one unreferenced storage-binding identity.
    async fn plan_delete_storage_binding(
        &self,
        bearer: &str,
        stable_id: String,
        expected_resource_version: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed storage-binding deletion.
    async fn apply_delete_storage_binding(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError>;

    /// Plans deletion of one dependency-free binary-cache identity.
    async fn plan_delete_binary_cache(
        &self,
        bearer: &str,
        stable_id: String,
        expected_resource_version: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed binary-cache deletion.
    async fn apply_delete_binary_cache(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError>;

    /// Plans a version-checked binary-cache identity and protocol-policy update.
    async fn plan_update_binary_cache(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanBinaryCacheMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed binary-cache identity and protocol-policy update.
    async fn apply_update_binary_cache(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;

    /// Plans promotion of one placement to single-writer authority.
    async fn plan_promote_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        candidate_placement_name: String,
        expected_resource_version: String,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a previously reviewed placement-promotion plan.
    async fn promote_placement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<WriteAuthorityOutcome, crate::service::RpcError>;

    /// Plans removal of write authority, leaving the surface read-only.
    async fn plan_remove_write_authority(
        &self,
        bearer: &str,
        surface: TopologySurface,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a previously reviewed write-authority removal plan.
    async fn remove_write_authority(
        &self,
        bearer: &str,
        surface: TopologySurface,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError>;

    /// Plans a drain or deletion against an exact placement version.
    async fn plan_placement_lifecycle(
        &self,
        bearer: &str,
        surface: TopologySurface,
        placement_name: String,
        expected_resource_version: String,
        action: PlacementLifecycleAction,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies one previously reviewed placement drain or deletion.
    async fn apply_placement_lifecycle(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: PlacementLifecycleAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;

    /// Plans creation of one placement without mutating topology.
    async fn plan_create_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        spec: PlacementCreateSpec,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Plans an update of one placement's mutable desired fields.
    async fn plan_update_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        placement_name: String,
        expected_resource_version: String,
        spec: PlacementUpdateSpec,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Plans cancellation of an in-flight authority promotion.
    async fn plan_cancel_placement_promotion(
        &self,
        bearer: &str,
        surface: TopologySurface,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed create, update, or promotion-cancel plan.
    async fn apply_placement_plan(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        operation: PlacementPlanOperation,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;

    /// Plans setting or rotating one purpose-scoped binding credential.
    async fn plan_storage_binding_credential(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanStorageBindingCredentialRequest,
        action: StorageCredentialAction,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed purpose-scoped binding credential plan.
    async fn apply_storage_binding_credential(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: StorageCredentialAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;

    /// Plans granting or revoking binding access for one consumer scope.
    async fn plan_storage_binding_grant(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanConsumerScopeGrantRequest,
        action: ConsumerGrantAction,
    ) -> Result<ReviewedPlan, crate::service::RpcError>;

    /// Applies a reviewed binding consumer-scope grant transition.
    async fn apply_storage_binding_grant(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: ConsumerGrantAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError>;
}

/// Apply method selected for a reviewed placement plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementPlanOperation {
    /// Creates a placement.
    Create,
    /// Updates mutable desired placement fields.
    Update,
    /// Cancels an in-flight promotion.
    CancelPromotion,
}

/// Credential mutation selected for one binding purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageCredentialAction {
    /// Sets the initial credential generation for a purpose.
    Set,
    /// Rotates an existing purpose to a new immutable secret version.
    Rotate,
}

/// Consumer-scope grant transition selected for a storage binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerGrantAction {
    /// Creates a new active grant generation.
    Grant,
    /// Revokes the current active grant generation.
    Revoke,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TopologyConsole for crate::service::RpcService {
    async fn signing_keys(
        &self,
        bearer: &str,
        scope_key: String,
    ) -> Result<Vec<aos_proto_types::SigningKey>, crate::service::RpcError> {
        Ok(self
            .list_signing_keys(
                Some(bearer),
                aos_proto_types::ListSigningKeysRequest {
                    scope_key,
                    page_size: 1000,
                    page_token: String::new(),
                },
            )
            .await?
            .signing_keys)
    }

    async fn plan_signing_key_enrollment(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_enroll_signing_key(Some(bearer), request).await?,
            "signing-key enrollment",
        )
    }

    async fn apply_signing_key_enrollment(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError> {
        self.apply_enroll_signing_key(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_signing_key_rotation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_rotate_signing_key(Some(bearer), request).await?,
            "signing-key rotation",
        )
    }

    async fn apply_signing_key_rotation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError> {
        self.apply_rotate_signing_key(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_signing_key_retirement(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanRetireSigningKeyRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_retire_signing_key(Some(bearer), request).await?,
            "signing-key retirement",
        )
    }

    async fn apply_signing_key_retirement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyResponse, crate::service::RpcError> {
        self.apply_retire_signing_key(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_signing_key_usage(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSigningKeyUsageRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_set_signing_key_usage(Some(bearer), request)
                .await?,
            "signing-key usage",
        )
    }

    async fn apply_signing_key_usage(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::SigningKeyUsageResponse, crate::service::RpcError> {
        self.apply_set_signing_key_usage(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_create_organization(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCreateOrganizationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_create_organization(Some(bearer), request).await?,
            "organization creation",
        )
    }

    async fn apply_create_organization(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::OrganizationResponse, crate::service::RpcError> {
        self.apply_create_organization(
            Some(bearer),
            aos_proto_types::ApplyOrganizationMutationRequest {
                plan_id,
                idempotency_key,
                confirmation_hash,
            },
        )
        .await
    }

    async fn plan_delete_organization(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanDeleteOrganizationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_delete_organization(Some(bearer), request).await?,
            "organization deletion",
        )
    }

    async fn apply_delete_organization(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError> {
        Ok(self
            .apply_delete_organization(
                Some(bearer),
                aos_proto_types::ApplyOrganizationMutationRequest {
                    plan_id,
                    idempotency_key,
                    confirmation_hash,
                },
            )
            .await?
            .deleted)
    }

    async fn membership(
        &self,
        bearer: &str,
        request: aos_proto_types::GetMembershipRequest,
    ) -> Result<aos_proto_types::MembershipResponse, crate::service::RpcError> {
        self.get_membership(Some(bearer), request).await
    }

    async fn plan_membership(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSetMembershipRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_set_membership(Some(bearer), request).await?,
            "membership replacement",
        )
    }

    async fn apply_membership(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::MembershipResponse, crate::service::RpcError> {
        self.apply_set_membership(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                idempotency_key,
                confirmation_hash,
            },
        )
        .await
    }

    async fn invitations(
        &self,
        bearer: &str,
        org_slug: String,
    ) -> Result<Vec<aos_proto_types::Invitation>, crate::service::RpcError> {
        Ok(self
            .list_invitations(
                Some(bearer),
                aos_proto_types::ListInvitationsRequest {
                    org_slug,
                    page_size: 1_000,
                    page_token: String::new(),
                },
            )
            .await?
            .invitations)
    }

    async fn plan_invitation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCreateInvitationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_create_invitation(Some(bearer), request).await?,
            "invitation creation",
        )
    }

    async fn apply_invitation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::InvitationResponse, crate::service::RpcError> {
        self.apply_create_invitation(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                idempotency_key,
                confirmation_hash,
            },
        )
        .await
    }

    async fn plan_invitation_cancellation(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanCancelInvitationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_cancel_invitation(Some(bearer), request).await?,
            "invitation cancellation",
        )
    }

    async fn apply_invitation_cancellation(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::InvitationResponse, crate::service::RpcError> {
        self.apply_cancel_invitation(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                idempotency_key,
                confirmation_hash,
            },
        )
        .await
    }

    async fn accept_invitation(
        &self,
        bearer: &str,
        request: aos_proto_types::AcceptInvitationRequest,
    ) -> Result<aos_proto_types::AcceptInvitationResponse, crate::service::RpcError> {
        crate::service::RpcService::accept_invitation(self, Some(bearer), request).await
    }

    async fn instance_settings(
        &self,
        bearer: &str,
    ) -> Result<aos_proto_types::GetInstanceSettingsResponse, crate::service::RpcError> {
        self.get_instance_settings(Some(bearer), aos_proto_types::GetInstanceSettingsRequest {})
            .await
    }

    async fn plan_instance_settings(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanSetInstanceSettingsRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_set_instance_settings(Some(bearer), request)
                .await?,
            "instance settings",
        )
    }

    async fn apply_instance_settings(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::GetInstanceSettingsResponse, crate::service::RpcError> {
        self.apply_set_instance_settings(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_access_token_issue(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanIssueAccessTokenRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_issue_access_token(Some(bearer), request).await?,
            "access token issuance",
        )
    }

    async fn apply_access_token_issue(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<aos_proto_types::AccessTokenResponse, crate::service::RpcError> {
        self.apply_issue_access_token(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await
    }

    async fn plan_access_token_retirement(
        &self,
        bearer: &str,
        token_id: String,
        expected_resource_version: String,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_retire_access_token(
                Some(bearer),
                aos_proto_types::PlanRetireAccessTokenRequest {
                    token_id,
                    expected_resource_version,
                    idempotency_key,
                },
            )
            .await?,
            "access token retirement",
        )
    }

    async fn apply_access_token_retirement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        self.apply_retire_access_token(
            Some(bearer),
            aos_proto_types::ApplyTopologyPlanRequest {
                plan_id,
                confirmation_hash,
                idempotency_key,
            },
        )
        .await?;
        Ok(())
    }

    async fn organization_topology_defaults(
        &self,
        bearer: &str,
        org_slug: String,
    ) -> Result<TopologyDefaultsOverview, crate::service::RpcError> {
        let response = self
            .get_organization_topology_defaults(
                Some(bearer),
                aos_proto_types::GetOrganizationTopologyDefaultsRequest { org_slug },
            )
            .await?;
        let defaults = response.defaults.ok_or_else(|| {
            crate::service::RpcError::internal(anyhow::anyhow!(
                "topology-defaults response omitted defaults"
            ))
        })?;
        Ok(TopologyDefaultsOverview {
            scope_key: defaults.scope_key,
            storage_binding_id: defaults.storage_binding_id,
            domain_id: defaults.domain_id,
            delivery_endpoint_id: defaults.delivery_endpoint_id,
            delivery_endpoint_generation: defaults.delivery_endpoint_generation,
            storage_gateway_id: defaults.storage_gateway_id,
            storage_gateway_generation: defaults.storage_gateway_generation,
            resource_version: defaults.resource_version,
        })
    }

    async fn plan_create_storage_binding(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanStorageBindingMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_create_storage_binding(Some(bearer), request)
                .await?,
            "storage-binding create",
        )
    }

    async fn apply_create_storage_binding(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<String, crate::service::RpcError> {
        let response = self
            .apply_create_storage_binding(
                Some(bearer),
                aos_proto_types::ApplyStorageBindingMutationRequest {
                    plan_id,
                    idempotency_key,
                    confirmation_hash,
                },
            )
            .await?;
        response
            .storage_binding
            .map(|binding| binding.stable_id)
            .ok_or_else(|| {
                crate::service::RpcError::internal(anyhow::anyhow!(
                    "storage-binding create response omitted the binding"
                ))
            })
    }

    async fn plan_delete_storage_binding(
        &self,
        bearer: &str,
        stable_id: String,
        expected_resource_version: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_delete_storage_binding(
                Some(bearer),
                aos_proto_types::PlanDeleteTopologyResourceRequest {
                    stable_id,
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: format!(
                        "console-plan-delete-binding-{}",
                        uuid::Uuid::new_v4()
                    ),
                },
            )
            .await?,
            "storage-binding delete",
        )
    }

    async fn apply_delete_storage_binding(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError> {
        Ok(self
            .apply_delete_storage_binding(
                Some(bearer),
                aos_proto_types::ApplyDeleteTopologyResourceRequest {
                    plan_id,
                    idempotency_key,
                    confirmation_hash,
                },
            )
            .await?
            .deleted)
    }

    async fn plan_delete_binary_cache(
        &self,
        bearer: &str,
        stable_id: String,
        expected_resource_version: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_delete_binary_cache(
                Some(bearer),
                aos_proto_types::PlanDeleteTopologyResourceRequest {
                    stable_id,
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: format!("console-plan-delete-cache-{}", uuid::Uuid::new_v4()),
                },
            )
            .await?,
            "binary-cache delete",
        )
    }

    async fn apply_delete_binary_cache(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError> {
        Ok(self
            .delete_binary_cache(
                Some(bearer),
                aos_proto_types::ApplyDeleteTopologyResourceRequest {
                    plan_id,
                    idempotency_key,
                    confirmation_hash,
                },
            )
            .await?
            .deleted)
    }

    async fn plan_update_binary_cache(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanBinaryCacheMutationRequest,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        reviewed_plan(
            self.plan_update_binary_cache(Some(bearer), request).await?,
            "binary-cache policy update",
        )
    }

    async fn apply_update_binary_cache(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        crate::service::RpcService::update_binary_cache(
            self,
            Some(bearer),
            aos_proto_types::ApplyBinaryCacheMutationRequest {
                plan_id,
                idempotency_key,
                confirmation_hash,
            },
        )
        .await?;
        Ok(())
    }

    async fn plan_promote_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        candidate_placement_name: String,
        expected_resource_version: String,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = self
            .plan_promote_placement(
                Some(bearer),
                aos_proto_types::PlacementMutationRequest {
                    surface: Some(surface.into_proto()),
                    placement_name: candidate_placement_name,
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key,
                },
            )
            .await?;
        let plan = response.plan.ok_or_else(|| {
            crate::service::RpcError::internal(anyhow::anyhow!(
                "promotion plan response omitted its plan"
            ))
        })?;
        Ok(ReviewedPlan {
            plan_id: plan.plan_id,
            expires_at: plan.expires_at,
            effects: plan.effects,
            warnings: plan.warnings,
            confirmation_hash: Some(plan.confirmation_hash),
        })
    }

    async fn promote_placement(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<WriteAuthorityOutcome, crate::service::RpcError> {
        let response = self
            .promote_placement(
                Some(bearer),
                aos_proto_types::ApplyTopologyPlanRequest {
                    plan_id,
                    confirmation_hash,
                    idempotency_key,
                },
            )
            .await?;
        let authority = response.authority.ok_or_else(|| {
            crate::service::RpcError::internal(anyhow::anyhow!(
                "promotion response omitted write authority"
            ))
        })?;
        Ok(WriteAuthorityOutcome {
            desired_placement_name: authority.desired_placement_name,
            observed_placement_name: authority.observed_placement_name,
            reconciliation_state: authority.reconciliation_state,
            desired_generation: authority.desired_generation,
        })
    }

    async fn plan_remove_write_authority(
        &self,
        bearer: &str,
        surface: TopologySurface,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = self
            .plan_remove_write_authority(
                Some(bearer),
                aos_proto_types::SurfaceMutationRequest {
                    surface: Some(surface.into_proto()),
                    expected_resource_version: None,
                    idempotency_key: format!("console-remove-authority-{}", uuid::Uuid::new_v4()),
                },
            )
            .await?;
        let plan = response.plan.ok_or_else(|| {
            crate::service::RpcError::internal(anyhow::anyhow!(
                "write-authority removal response omitted its plan"
            ))
        })?;
        Ok(ReviewedPlan {
            plan_id: plan.plan_id,
            expires_at: plan.expires_at,
            effects: plan.effects,
            warnings: plan.warnings,
            confirmation_hash: Some(plan.confirmation_hash),
        })
    }

    async fn remove_write_authority(
        &self,
        bearer: &str,
        _surface: TopologySurface,
        plan_id: String,
        confirmation_hash: String,
        idempotency_key: String,
    ) -> Result<bool, crate::service::RpcError> {
        Ok(self
            .remove_write_authority(
                Some(bearer),
                aos_proto_types::ApplyTopologyPlanRequest {
                    plan_id,
                    confirmation_hash,
                    idempotency_key,
                },
            )
            .await?
            .removed)
    }

    async fn plan_placement_lifecycle(
        &self,
        bearer: &str,
        surface: TopologySurface,
        placement_name: String,
        expected_resource_version: String,
        action: PlacementLifecycleAction,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let request = aos_proto_types::PlacementMutationRequest {
            surface: Some(surface.into_proto()),
            placement_name,
            expected_resource_version: Some(expected_resource_version),
            idempotency_key,
        };
        let response = match action {
            PlacementLifecycleAction::Drain => {
                self.plan_drain_placement(Some(bearer), request).await?
            }
            PlacementLifecycleAction::Delete => {
                self.plan_delete_placement(Some(bearer), request).await?
            }
        };
        let plan = response.plan.ok_or_else(|| {
            crate::service::RpcError::internal(anyhow::anyhow!(
                "placement lifecycle response omitted its plan"
            ))
        })?;
        Ok(ReviewedPlan {
            plan_id: plan.plan_id,
            expires_at: plan.expires_at,
            effects: plan.effects,
            warnings: plan.warnings,
            confirmation_hash: Some(plan.confirmation_hash),
        })
    }

    async fn apply_placement_lifecycle(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: PlacementLifecycleAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        let request = aos_proto_types::ApplyTopologyPlanRequest {
            plan_id,
            confirmation_hash,
            idempotency_key,
        };
        match action {
            PlacementLifecycleAction::Drain => {
                self.drain_placement(Some(bearer), request).await?;
            }
            PlacementLifecycleAction::Delete => {
                self.apply_delete_placement(Some(bearer), request).await?;
            }
        }
        Ok(())
    }

    async fn plan_create_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        spec: PlacementCreateSpec,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = self
            .plan_create_placement(
                Some(bearer),
                aos_proto_types::PlanCreatePlacementRequest {
                    surface: Some(surface.into_proto()),
                    name: spec.name,
                    storage_binding_id: spec.storage_binding_id,
                    prefix: spec.prefix,
                    kind: spec.kind,
                    desired_state: spec.desired_state,
                    desired_read_enabled: Some(spec.desired_read_enabled),
                    read_order: Some(spec.read_order),
                    hash_range: spec
                        .hash_range
                        .map(|(start, end)| aos_proto_types::HashRangeV1 { start, end }),
                    requires_conditional_writes: spec.requires_conditional_writes,
                    idempotency_key,
                    expected_resource_version: String::new(),
                },
            )
            .await?;
        reviewed_plan(response, "placement-create")
    }

    async fn plan_update_placement(
        &self,
        bearer: &str,
        surface: TopologySurface,
        placement_name: String,
        expected_resource_version: String,
        spec: PlacementUpdateSpec,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = self
            .plan_update_placement(
                Some(bearer),
                aos_proto_types::PlanUpdatePlacementRequest {
                    surface: Some(surface.into_proto()),
                    name: placement_name,
                    expected_resource_version,
                    desired_state: spec.desired_state,
                    desired_read_enabled: Some(spec.desired_read_enabled),
                    read_order: Some(spec.read_order),
                    update_mask: vec![
                        "desired_state".to_string(),
                        "desired_read_enabled".to_string(),
                        "read_order".to_string(),
                    ],
                    idempotency_key,
                },
            )
            .await?;
        reviewed_plan(response, "placement-update")
    }

    async fn plan_cancel_placement_promotion(
        &self,
        bearer: &str,
        surface: TopologySurface,
        idempotency_key: String,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let surface_ref = surface.into_proto();
        let authority = self
            .get_write_authority(
                Some(bearer),
                aos_proto_types::GetWriteAuthorityRequest {
                    surface: Some(surface_ref.clone()),
                },
            )
            .await?
            .authority
            .ok_or_else(|| {
                crate::service::RpcError::FailedPrecondition(
                    "surface has no write authority to cancel".to_string(),
                )
            })?;
        let response = self
            .plan_cancel_placement_promotion(
                Some(bearer),
                aos_proto_types::SurfaceMutationRequest {
                    surface: Some(surface_ref),
                    expected_resource_version: Some(authority.resource_version),
                    idempotency_key,
                },
            )
            .await?;
        reviewed_plan(response, "placement-promotion cancellation")
    }

    async fn apply_placement_plan(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        operation: PlacementPlanOperation,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        let request = aos_proto_types::ApplyTopologyPlanRequest {
            plan_id,
            confirmation_hash,
            idempotency_key,
        };
        match operation {
            PlacementPlanOperation::Create => {
                self.apply_create_placement(Some(bearer), request).await?;
            }
            PlacementPlanOperation::Update => {
                self.apply_update_placement(Some(bearer), request).await?;
            }
            PlacementPlanOperation::CancelPromotion => {
                self.cancel_placement_promotion(Some(bearer), request)
                    .await?;
            }
        }
        Ok(())
    }

    async fn plan_storage_binding_credential(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanStorageBindingCredentialRequest,
        action: StorageCredentialAction,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = match action {
            StorageCredentialAction::Set => {
                self.plan_set_storage_binding_credential(Some(bearer), request)
                    .await?
            }
            StorageCredentialAction::Rotate => {
                self.plan_rotate_storage_binding_credential(Some(bearer), request)
                    .await?
            }
        };
        reviewed_plan(response, "storage-binding credential")
    }

    async fn apply_storage_binding_credential(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: StorageCredentialAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        let request = aos_proto_types::ApplyStorageBindingCredentialRequest {
            plan_id,
            idempotency_key,
            confirmation_hash,
        };
        match action {
            StorageCredentialAction::Set => {
                self.apply_set_storage_binding_credential(Some(bearer), request)
                    .await?;
            }
            StorageCredentialAction::Rotate => {
                self.apply_rotate_storage_binding_credential(Some(bearer), request)
                    .await?;
            }
        }
        Ok(())
    }

    async fn plan_storage_binding_grant(
        &self,
        bearer: &str,
        request: aos_proto_types::PlanConsumerScopeGrantRequest,
        action: ConsumerGrantAction,
    ) -> Result<ReviewedPlan, crate::service::RpcError> {
        let response = match action {
            ConsumerGrantAction::Grant => {
                self.plan_grant_storage_binding_scope(Some(bearer), request)
                    .await?
            }
            ConsumerGrantAction::Revoke => {
                self.plan_revoke_storage_binding_scope(Some(bearer), request)
                    .await?
            }
        };
        reviewed_plan(response, "storage-binding consumer grant")
    }

    async fn apply_storage_binding_grant(
        &self,
        bearer: &str,
        plan_id: String,
        confirmation_hash: String,
        action: ConsumerGrantAction,
        idempotency_key: String,
    ) -> Result<(), crate::service::RpcError> {
        let request = aos_proto_types::ApplyConsumerScopeGrantRequest {
            plan_id,
            idempotency_key,
            confirmation_hash,
        };
        match action {
            ConsumerGrantAction::Grant => {
                self.apply_grant_storage_binding_scope(Some(bearer), request)
                    .await?;
            }
            ConsumerGrantAction::Revoke => {
                self.apply_revoke_storage_binding_scope(Some(bearer), request)
                    .await?;
            }
        }
        Ok(())
    }
}

fn reviewed_plan(
    response: aos_proto_types::TopologyPlanResponse,
    operation: &str,
) -> Result<ReviewedPlan, crate::service::RpcError> {
    let plan = response.plan.ok_or_else(|| {
        crate::service::RpcError::internal(anyhow::anyhow!("{operation} response omitted its plan"))
    })?;
    Ok(ReviewedPlan {
        plan_id: plan.plan_id,
        expires_at: plan.expires_at,
        effects: plan.effects,
        warnings: plan.warnings,
        confirmation_hash: Some(plan.confirmation_hash),
    })
}

/// A minimal outbound HTTP client for the OIDC authorization-code flow.
///
/// The OIDC callback exchanges an authorization code at the IdP's
/// `token_endpoint` (an HTTP `POST` of a `application/x-www-form-urlencoded`
/// body) and fetches the IdP's JWKS document from its `jwks_uri` (an HTTP
/// `GET`). Both endpoints come from *tenant-admin-controlled* IdP configuration,
/// so an implementation MUST treat them as untrusted:
///
/// - **SSRF.** A native implementation routes the request through a resolver
///   that refuses private, loopback, and link-local addresses, so a hostile
///   IdP config cannot turn the multi-tenant hub into an SSRF proxy against its
///   own metadata service or internal network.
/// - **Body cap.** A response body MUST be read with a hard size cap (a token
///   response and a JWKS document are KB-scale by nature) so a hostile endpoint
///   cannot stream an unbounded body and OOM the hub. Implementations should cap
///   at roughly 1 MiB.
/// - **Timeout.** Both calls MUST carry a bounded request timeout so a slow or
///   hung endpoint cannot pin a request future indefinitely.
///
/// Returning the decoded body bytes (rather than a streaming response) lets the
/// handler share one cap-and-decode path across both targets. The native hub
/// implements this over its hardened [`reqwest`] client; the Worker implements
/// it through its fixed authenticated egress gateway.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HttpClient: BackendBounds {
    /// `POST url` with a form-urlencoded body, returning the response body
    /// bytes.
    ///
    /// `form` is the unencoded `(key, value)` pairs; the implementation
    /// percent-encodes them into an `application/x-www-form-urlencoded` body.
    /// The returned bytes are the response body, already read under the
    /// implementation's size cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be sent, the endpoint resolves
    /// to a blocked address, the endpoint returns a non-success status, the
    /// response exceeds the body cap, or the request times out.
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> anyhow::Result<Vec<u8>>;

    /// `GET url`, returning the response body bytes.
    ///
    /// The returned bytes are the response body, already read under the
    /// implementation's size cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be sent, the endpoint resolves
    /// to a blocked address, the endpoint returns a non-success status, the
    /// response exceeds the body cap, or the request times out.
    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>>;

    /// Performs an HTTPS request whose response status/body are irrelevant.
    ///
    /// A successful result proves that the runtime completed normal TLS
    /// certificate-chain, validity, and hostname verification. Implementations
    /// must not disable certificate verification or follow a redirect to a
    /// different authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not safe HTTPS, DNS resolution or the
    /// TLS handshake fails, or the bounded request times out.
    async fn probe_https(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        self.get(url).await
    }
}
