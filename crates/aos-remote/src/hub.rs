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
//! POST /aos.hub.v1.TopologyService/GetSurfaceTopology
//! Content-Type: application/json
//! Connect-Protocol-Version: 1
//! { "surface": { "registrySlug": "acme/cdn" } }
//!   -> 200 { "surface": { "registrySlug": "acme/cdn" }, "placements": [] }
//!   -> 404 { "code": "not_found", "message": "surface not found" }
//! ```
//!
//! This client speaks that transport directly with `reqwest`, exchanging the
//! [`aos_proto_types`] message structs as JSON. Construct one with
//! [`HubClient::connect_anonymous`] for public reads, or
//! [`HubClient::connect_with_token`] to attach a hub access JWT for private
//! inventory and authorized placement lifecycle calls.

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use aos_proto_types::SurfaceRef;

use crate::client::validate_base_url;

/// Default per-request timeout for hub RPC calls.
const HUB_TIMEOUT_SECS: u64 = 30;

/// Connect unary protocol-version request header.
const CONNECT_PROTOCOL_VERSION_HEADER: &str = "Connect-Protocol-Version";

/// Required Connect unary protocol version.
const CONNECT_PROTOCOL_VERSION: &str = "1";

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
    /// Streaming transfer client without the unary RPC deadline.
    upload_http: reqwest::Client,
    /// The hub root with a single trailing slash, e.g. `https://hub.example/`.
    base: String,
    /// The hub access JWT to send as `Authorization: Bearer …`, when present.
    token: Option<String>,
}

/// Selects one normalized topology, cache, or operation RPC.
///
/// Keeping the service and method pairing closed prevents callers from
/// constructing legacy or misspelled Connect paths while still allowing the
/// CLI to exchange the generated request and response messages directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubTopologyMethod {
    /// Selects the normalized `PlanUpdateOrganization` Connect operation.
    PlanUpdateOrganization,
    /// Selects the normalized `UpdateOrganization` Connect operation.
    UpdateOrganization,
    /// Selects the normalized `ListStorageBindings` Connect operation.
    ListStorageBindings,
    /// Selects the normalized `GetStorageBinding` Connect operation.
    GetStorageBinding,
    /// Selects the normalized `PlanCreateStorageBinding` Connect operation.
    PlanCreateStorageBinding,
    /// Selects the normalized `CreateStorageBinding` Connect operation.
    CreateStorageBinding,
    /// Selects the normalized `PlanSetStorageBindingCredential` Connect operation.
    PlanSetStorageBindingCredential,
    /// Selects the normalized `SetStorageBindingCredential` Connect operation.
    SetStorageBindingCredential,
    /// Selects the normalized `PlanRotateStorageBindingCredential` Connect operation.
    PlanRotateStorageBindingCredential,
    /// Selects the normalized `RotateStorageBindingCredential` Connect operation.
    RotateStorageBindingCredential,
    PlanValidateStorageBindingCredential,
    /// Selects the normalized `ValidateStorageBindingCredential` Connect operation.
    ValidateStorageBindingCredential,
    /// Selects the normalized `PlanGrantStorageBindingScope` Connect operation.
    PlanGrantStorageBindingScope,
    /// Selects the normalized `GrantStorageBindingScope` Connect operation.
    GrantStorageBindingScope,
    /// Selects the normalized `PlanRevokeStorageBindingScope` Connect operation.
    PlanRevokeStorageBindingScope,
    /// Selects the normalized `RevokeStorageBindingScope` Connect operation.
    RevokeStorageBindingScope,
    /// Selects the normalized `ListStorageBindingWriteRevisions` Connect operation.
    ListStorageBindingWriteRevisions,
    /// Selects the normalized `GetStorageBindingWriteRevision` Connect operation.
    GetStorageBindingWriteRevision,
    /// Selects the fenced storage-binding controller observation.
    ReportStorageBindingWriteRevision,
    /// Selects the normalized `PlanDeleteStorageBinding` Connect operation.
    PlanDeleteStorageBinding,
    /// Selects the normalized `DeleteStorageBinding` Connect operation.
    DeleteStorageBinding,
    /// Selects the normalized `GetInstanceTopologyDefaults` Connect operation.
    GetInstanceTopologyDefaults,
    /// Selects the normalized `PlanSetInstanceTopologyDefaults` Connect operation.
    PlanSetInstanceTopologyDefaults,
    /// Selects the normalized `SetInstanceTopologyDefaults` Connect operation.
    SetInstanceTopologyDefaults,
    /// Selects the normalized `GetOrganizationTopologyDefaults` Connect operation.
    GetOrganizationTopologyDefaults,
    /// Selects the normalized `PlanSetOrganizationTopologyDefaults` Connect operation.
    PlanSetOrganizationTopologyDefaults,
    /// Selects the normalized `SetOrganizationTopologyDefaults` Connect operation.
    SetOrganizationTopologyDefaults,
    /// Selects the normalized `ListDomains` Connect operation.
    ListDomains,
    /// Selects the normalized `GetDomain` Connect operation.
    GetDomain,
    /// Selects the normalized `PlanCreateDomain` Connect operation.
    PlanCreateDomain,
    /// Selects the normalized `CreateDomain` Connect operation.
    CreateDomain,
    /// Selects the normalized `PlanConfigureDomainDns` Connect operation.
    PlanConfigureDomainDns,
    /// Selects the normalized `ConfigureDomainDns` Connect operation.
    ConfigureDomainDns,
    /// Selects the normalized `PlanConfigureDomainCertificate` Connect operation.
    PlanConfigureDomainCertificate,
    /// Selects the normalized `ConfigureDomainCertificate` Connect operation.
    ConfigureDomainCertificate,
    PlanVerifyDomain,
    /// Selects the normalized `VerifyDomain` Connect operation.
    VerifyDomain,
    /// Selects the normalized `PlanDeleteDomain` Connect operation.
    PlanDeleteDomain,
    /// Selects the normalized `DeleteDomain` Connect operation.
    DeleteDomain,
    /// Selects the normalized `ListNetworkBoundaries` Connect operation.
    ListNetworkBoundaries,
    /// Selects the normalized `GetNetworkBoundary` Connect operation.
    GetNetworkBoundary,
    /// Selects the normalized `PlanCreateNetworkBoundary` Connect operation.
    PlanCreateNetworkBoundary,
    /// Selects the normalized `CreateNetworkBoundary` Connect operation.
    CreateNetworkBoundary,
    /// Selects the normalized `ListNetworkBoundaryRevisions` Connect operation.
    ListNetworkBoundaryRevisions,
    /// Selects the normalized `GetNetworkBoundaryRevision` Connect operation.
    GetNetworkBoundaryRevision,
    /// Selects the normalized `PlanReviseNetworkBoundary` Connect operation.
    PlanReviseNetworkBoundary,
    /// Selects the normalized `ReviseNetworkBoundary` Connect operation.
    ReviseNetworkBoundary,
    CompleteNetworkBoundaryRevisionProbe,
    ReportNetworkBoundaryRevision,
    /// Selects the normalized `PlanActivateNetworkBoundaryRevision` Connect operation.
    PlanActivateNetworkBoundaryRevision,
    /// Selects the normalized `ActivateNetworkBoundaryRevision` Connect operation.
    ActivateNetworkBoundaryRevision,
    /// Selects the normalized `PlanRetireNetworkBoundaryRevision` Connect operation.
    PlanRetireNetworkBoundaryRevision,
    /// Selects the normalized `RetireNetworkBoundaryRevision` Connect operation.
    RetireNetworkBoundaryRevision,
    /// Selects the normalized `PlanGrantNetworkBoundaryScope` Connect operation.
    PlanGrantNetworkBoundaryScope,
    /// Selects the normalized `GrantNetworkBoundaryScope` Connect operation.
    GrantNetworkBoundaryScope,
    /// Selects the normalized `PlanRevokeNetworkBoundaryScope` Connect operation.
    PlanRevokeNetworkBoundaryScope,
    /// Selects the normalized `RevokeNetworkBoundaryScope` Connect operation.
    RevokeNetworkBoundaryScope,
    /// Selects the normalized `PlanDeleteNetworkBoundary` Connect operation.
    PlanDeleteNetworkBoundary,
    /// Selects the normalized `DeleteNetworkBoundary` Connect operation.
    DeleteNetworkBoundary,
    /// Selects the normalized `ListDeliveryEndpoints` Connect operation.
    ListDeliveryEndpoints,
    /// Selects the normalized `GetDeliveryEndpoint` Connect operation.
    GetDeliveryEndpoint,
    /// Selects the normalized `PlanCreateDeliveryEndpoint` Connect operation.
    PlanCreateDeliveryEndpoint,
    /// Selects the normalized `CreateDeliveryEndpoint` Connect operation.
    CreateDeliveryEndpoint,
    /// Selects the normalized `ListDeliveryEndpointGenerations` Connect operation.
    ListDeliveryEndpointGenerations,
    /// Selects the normalized `GetDeliveryEndpointGeneration` Connect operation.
    GetDeliveryEndpointGeneration,
    /// Selects the normalized `PlanStageDeliveryEndpointGeneration` Connect operation.
    PlanStageDeliveryEndpointGeneration,
    /// Selects the normalized `StageDeliveryEndpointGeneration` Connect operation.
    StageDeliveryEndpointGeneration,
    /// Selects the normalized `PlanActivateDeliveryEndpointGeneration` Connect operation.
    PlanActivateDeliveryEndpointGeneration,
    /// Selects the normalized `ActivateDeliveryEndpointGeneration` Connect operation.
    ActivateDeliveryEndpointGeneration,
    /// Selects the normalized `PlanGrantDeliveryEndpointScope` Connect operation.
    PlanGrantDeliveryEndpointScope,
    /// Selects the normalized `GrantDeliveryEndpointScope` Connect operation.
    GrantDeliveryEndpointScope,
    /// Selects the normalized `PlanRevokeDeliveryEndpointScope` Connect operation.
    PlanRevokeDeliveryEndpointScope,
    /// Selects the normalized `RevokeDeliveryEndpointScope` Connect operation.
    RevokeDeliveryEndpointScope,
    CompleteDeliveryEndpointProbe,
    ReportDeliveryEndpoint,
    /// Selects the normalized `PlanDeleteDeliveryEndpoint` Connect operation.
    PlanDeleteDeliveryEndpoint,
    /// Selects the normalized `DeleteDeliveryEndpoint` Connect operation.
    DeleteDeliveryEndpoint,
    /// Selects the normalized `ListStorageGateways` Connect operation.
    ListStorageGateways,
    /// Selects the normalized `GetStorageGateway` Connect operation.
    GetStorageGateway,
    /// Selects the normalized `PlanCreateStorageGateway` Connect operation.
    PlanCreateStorageGateway,
    /// Selects the normalized `CreateStorageGateway` Connect operation.
    CreateStorageGateway,
    /// Selects the normalized `PlanUpdateStorageGateway` Connect operation.
    PlanUpdateStorageGateway,
    /// Selects the normalized `UpdateStorageGateway` Connect operation.
    UpdateStorageGateway,
    /// Selects the normalized `PlanGrantStorageGatewayScope` Connect operation.
    PlanGrantStorageGatewayScope,
    /// Selects the normalized `GrantStorageGatewayScope` Connect operation.
    GrantStorageGatewayScope,
    /// Selects the normalized `PlanRevokeStorageGatewayScope` Connect operation.
    PlanRevokeStorageGatewayScope,
    /// Selects the normalized `RevokeStorageGatewayScope` Connect operation.
    RevokeStorageGatewayScope,
    /// Selects the normalized `PreviewGatewayRoutes` Connect operation.
    PreviewGatewayRoutes,
    ReportStorageGateway,
    /// Selects the normalized `PlanEnableStorageGateway` Connect operation.
    PlanEnableStorageGateway,
    /// Selects the normalized `EnableStorageGateway` Connect operation.
    EnableStorageGateway,
    /// Selects the normalized `PlanDisableStorageGateway` Connect operation.
    PlanDisableStorageGateway,
    /// Selects the normalized `DisableStorageGateway` Connect operation.
    DisableStorageGateway,
    /// Selects the normalized `PlanDeleteStorageGateway` Connect operation.
    PlanDeleteStorageGateway,
    /// Selects the normalized `DeleteStorageGateway` Connect operation.
    DeleteStorageGateway,
    /// Selects the normalized `ListRoutes` Connect operation.
    ListRoutes,
    /// Selects the normalized `GetRoute` Connect operation.
    GetRoute,
    /// Selects the normalized `PlanCreateRoute` Connect operation.
    PlanCreateRoute,
    /// Selects the normalized `CreateRoute` Connect operation.
    CreateRoute,
    /// Selects the normalized `PlanUpdateRoute` Connect operation.
    PlanUpdateRoute,
    /// Selects the normalized `UpdateRoute` Connect operation.
    UpdateRoute,
    /// Selects the normalized `PlanReplaceRoute` Connect operation.
    PlanReplaceRoute,
    /// Selects the normalized `ReplaceRoute` Connect operation.
    ReplaceRoute,
    /// Selects the normalized `PlanEnableRoute` Connect operation.
    PlanEnableRoute,
    /// Selects the normalized `EnableRoute` Connect operation.
    EnableRoute,
    /// Selects the normalized `PlanDisableRoute` Connect operation.
    PlanDisableRoute,
    /// Selects the normalized `DisableRoute` Connect operation.
    DisableRoute,
    /// Selects the normalized `PlanDeleteRoute` Connect operation.
    PlanDeleteRoute,
    /// Selects the normalized `DeleteRoute` Connect operation.
    DeleteRoute,
    /// Selects the normalized `PlanSetCanonicalRoute` Connect operation.
    PlanSetCanonicalRoute,
    /// Selects the normalized `SetCanonicalRoute` Connect operation.
    SetCanonicalRoute,
    CompleteRouteProbe,
    /// Selects the normalized `ExplainRoute` Connect operation.
    ExplainRoute,
    /// Selects the normalized `GetSurfaceTopology` Connect operation.
    GetSurfaceTopology,
    /// Selects the normalized `ExplainSurfaceRequest` Connect operation.
    ExplainSurfaceRequest,
    /// Selects the normalized `ListBinaryCaches` Connect operation.
    ListBinaryCaches,
    /// Selects the normalized `GetBinaryCache` Connect operation.
    GetBinaryCache,
    /// Selects the normalized `PlanCreateBinaryCache` Connect operation.
    PlanCreateBinaryCache,
    /// Selects the normalized `CreateBinaryCache` Connect operation.
    CreateBinaryCache,
    /// Selects the normalized `PlanUpdateBinaryCache` Connect operation.
    PlanUpdateBinaryCache,
    /// Selects the normalized `UpdateBinaryCache` Connect operation.
    UpdateBinaryCache,
    /// Selects the normalized `PlanDeleteBinaryCache` Connect operation.
    PlanDeleteBinaryCache,
    /// Selects the normalized `DeleteBinaryCache` Connect operation.
    DeleteBinaryCache,
    /// Selects the normalized `GetCacheGcPolicy` Connect operation.
    GetCacheGcPolicy,
    /// Selects the normalized `PlanSetCacheGcPolicy` Connect operation.
    PlanSetCacheGcPolicy,
    /// Selects the normalized `SetCacheGcPolicy` Connect operation.
    SetCacheGcPolicy,
    /// Selects the normalized cache-GC execution planning operation.
    PlanRunCacheGc,
    /// Selects the normalized `RunCacheGc` Connect operation.
    RunCacheGc,
    /// Selects the normalized `PlanAcknowledgeCacheGcFirstSweep` Connect operation.
    PlanAcknowledgeCacheGcFirstSweep,
    /// Selects the normalized `AcknowledgeCacheGcFirstSweep` Connect operation.
    AcknowledgeCacheGcFirstSweep,
    /// Selects the normalized `GetCacheGcPlan` Connect operation.
    GetCacheGcPlan,
    /// Selects the normalized `GetCacheGcRun` Connect operation.
    GetCacheGcRun,
    /// Selects the normalized `SearchCache` Connect operation.
    SearchCache,
    /// Selects the normalized `GetCacheObject` Connect operation.
    GetCacheObject,
    /// Selects the normalized `ListCacheGcRuns` Connect operation.
    ListCacheGcRuns,
    /// Selects the normalized `GetCacheGcDeletionJob` Connect operation.
    GetCacheGcDeletionJob,
    /// Selects the normalized `ListCacheGcDeletionJobs` Connect operation.
    ListCacheGcDeletionJobs,
    PlanRetryCacheGcDeletionJob,
    /// Selects the normalized `RetryCacheGcDeletionJob` Connect operation.
    RetryCacheGcDeletionJob,
    /// Selects the normalized `PlanAbandonCacheGcDeletionJob` Connect operation.
    PlanAbandonCacheGcDeletionJob,
    /// Selects the normalized `AbandonCacheGcDeletionJob` Connect operation.
    AbandonCacheGcDeletionJob,
    /// Selects the normalized `ListRootReasons` Connect operation.
    ListRootReasons,
    /// Selects the normalized `GetRetentionRoot` Connect operation.
    GetRetentionRoot,
    /// Selects the normalized `ListRetentionRoots` Connect operation.
    ListRetentionRoots,
    /// Selects the normalized `PlanCreateManualRetentionRoot` Connect operation.
    PlanCreateManualRetentionRoot,
    /// Selects the normalized `CreateManualRetentionRoot` Connect operation.
    CreateManualRetentionRoot,
    /// Selects the normalized `PlanRenewRetentionLease` Connect operation.
    PlanRenewRetentionLease,
    /// Selects the normalized `RenewRetentionLease` Connect operation.
    RenewRetentionLease,
    /// Selects the normalized `PlanRevokeRetentionLease` Connect operation.
    PlanRevokeRetentionLease,
    /// Selects the normalized `RevokeRetentionLease` Connect operation.
    RevokeRetentionLease,
    /// Selects the normalized `PlanDeleteManualRetentionRoot` Connect operation.
    PlanDeleteManualRetentionRoot,
    /// Selects the normalized `DeleteManualRetentionRoot` Connect operation.
    DeleteManualRetentionRoot,
    PlanRefreshAllRetention,
    /// Selects the normalized `RefreshAllRetention` Connect operation.
    RefreshAllRetention,
    /// Selects the normalized placement-eviction execution planning operation.
    PlanRunPlacementEviction,
    /// Selects the normalized `RunPlacementEviction` Connect operation.
    RunPlacementEviction,
    /// Selects the normalized `CacheClosure` Connect operation.
    CacheClosure,
    /// Selects the normalized `CreateCacheObjectUploads` Connect operation.
    CreateCacheObjectUploads,
    /// Selects typed cache multipart admission.
    BeginCacheMultipartUpload,
    /// Selects typed cache multipart completion.
    CompleteCacheMultipartUpload,
    /// Selects typed cache multipart abort.
    AbortCacheMultipartUpload,
    ReportCacheUpload,
    ReportCacheNarinfos,
    /// Selects the normalized `ListRegistryCacheIntegrations` Connect operation.
    ListRegistryCacheIntegrations,
    /// Selects the normalized `ListCacheRegistryIntegrations` Connect operation.
    ListCacheRegistryIntegrations,
    /// Selects the normalized `GetCacheRegistryIntegration` Connect operation.
    GetCacheRegistryIntegration,
    /// Selects the normalized `PreviewCacheIntegration` Connect operation.
    PreviewCacheIntegration,
    /// Selects the normalized `GetConsumerCacheStack` Connect operation.
    GetConsumerCacheStack,
    /// Selects the normalized `ValidateConsumerCacheStack` Connect operation.
    ValidateConsumerCacheStack,
    /// Selects the normalized consumer cache change-set planning operation.
    PlanCreateConsumerCacheChangeset,
    /// Selects the normalized `CreateConsumerCacheChangeset` Connect operation.
    CreateConsumerCacheChangeset,
    /// Selects the normalized `GetRetentionSubscription` Connect operation.
    GetRetentionSubscription,
    /// Selects the normalized `ListRetentionSubscriptions` Connect operation.
    ListRetentionSubscriptions,
    /// Selects the normalized `PlanSetRetentionSubscription` Connect operation.
    PlanSetRetentionSubscription,
    /// Selects the normalized `SetRetentionSubscription` Connect operation.
    SetRetentionSubscription,
    /// Selects the normalized `PlanDeleteRetentionSubscription` Connect operation.
    PlanDeleteRetentionSubscription,
    /// Selects the normalized `DeleteRetentionSubscription` Connect operation.
    DeleteRetentionSubscription,
    PlanRefreshRetentionSubscription,
    /// Selects the normalized `RefreshRetentionSubscription` Connect operation.
    RefreshRetentionSubscription,
    /// Selects the normalized `ExplainRetention` Connect operation.
    ExplainRetention,
    /// Selects the normalized `GetPopulationTarget` Connect operation.
    GetPopulationTarget,
    /// Selects the normalized `ListPopulationTargets` Connect operation.
    ListPopulationTargets,
    /// Selects the normalized `PlanSetPopulationTarget` Connect operation.
    PlanSetPopulationTarget,
    /// Selects the normalized `SetPopulationTarget` Connect operation.
    SetPopulationTarget,
    /// Selects the normalized `PlanDeletePopulationTarget` Connect operation.
    PlanDeletePopulationTarget,
    /// Selects the normalized `DeletePopulationTarget` Connect operation.
    DeletePopulationTarget,
    PlanRunPopulation,
    /// Selects the normalized `RunPopulation` Connect operation.
    RunPopulation,
    /// Selects the normalized `GetCoverage` Connect operation.
    GetCoverage,
    PlanRunCoverageValidation,
    /// Selects the normalized `RunCoverageValidation` Connect operation.
    RunCoverageValidation,
    PlanRunCoverageRepair,
    /// Selects the normalized `RunCoverageRepair` Connect operation.
    RunCoverageRepair,
    /// Selects the normalized `GetOperation` Connect operation.
    GetOperation,
    /// Selects the normalized `ListOperations` Connect operation.
    ListOperations,
    /// Selects the normalized `WatchOperation` Connect operation.
    WatchOperation,
    /// Selects the normalized `CancelOperation` Connect operation.
    CancelOperation,
    /// Selects the normalized `RetryOperation` Connect operation.
    RetryOperation,
    PlanCreatePlacement,
    CreatePlacement,
    PlanUpdatePlacement,
    UpdatePlacement,
    PlanCancelPlacementPromotion,
    CancelPlacementPromotion,
    PlanPromotePlacement,
    PromotePlacement,
    PlanDrainPlacement,
    DrainPlacement,
    PlanCancelPlacementDrain,
    CancelPlacementDrain,
    PlanDeletePlacement,
    DeletePlacement,
    PlanScanPlacement,
    ScanPlacement,
    PlanReplicatePlacement,
    ReplicatePlacement,
    PlanRepairPlacement,
    RepairPlacement,
    ListObjectPresence,
    ListPlacementPolicies,
    GetPlacementPolicy,
    ListPlacementPolicyRevisions,
    GetPlacementPolicyRevision,
    PlanCreatePlacementPolicy,
    CreatePlacementPolicy,
    PlanRevisePlacementPolicy,
    RevisePlacementPolicy,
    TestPlacementPolicyRevision,
    ListPlacementEquivalences,
    PlanConfirmPlacementEquivalence,
    ConfirmPlacementEquivalence,
    PlanDeletePlacementEquivalence,
    DeletePlacementEquivalence,
    GetRegistryMirror,
    PlanSetRegistryMirror,
    SetRegistryMirror,
    PlanDeleteRegistryMirror,
    DeleteRegistryMirror,
    PlanSyncRegistryMirror,
    SyncRegistryMirror,
    ListPlacements,
    GetPlacement,
    /// Selects the normalized `ListRegistries` Connect operation.
    ListRegistries,
    /// Selects the normalized `GetRegistry` Connect operation.
    GetRegistry,
    /// Selects the normalized `ListReleases` Connect operation.
    ListReleases,
    /// Selects the normalized `PlanCreateRegistry` Connect operation.
    PlanCreateRegistry,
    /// Selects the normalized `CreateRegistry` Connect operation.
    CreateRegistry,
    /// Selects the normalized `PlanUpdateRegistry` Connect operation.
    PlanUpdateRegistry,
    /// Selects the normalized `UpdateRegistry` Connect operation.
    UpdateRegistry,
    /// Selects the normalized `PlanDeleteRegistry` Connect operation.
    PlanDeleteRegistry,
    /// Selects the normalized `DeleteRegistry` Connect operation.
    DeleteRegistry,
    /// Selects the normalized `ListOrganizations` Connect operation.
    ListOrganizations,
    /// Selects the normalized `GetOrganization` Connect operation.
    GetOrganization,
    /// Selects the normalized `PlanCreateOrganization` Connect operation.
    PlanCreateOrganization,
    /// Selects the normalized `CreateOrganization` Connect operation.
    CreateOrganization,
    /// Selects the normalized `PlanDeleteOrganization` Connect operation.
    PlanDeleteOrganization,
    /// Selects the normalized `DeleteOrganization` Connect operation.
    DeleteOrganization,
    /// Selects the normalized `ListSigningKeys` Connect operation.
    ListSigningKeys,
    /// Selects the normalized `GetSigningKey` Connect operation.
    GetSigningKey,
    /// Selects the normalized `PlanEnrollSigningKey` Connect operation.
    PlanEnrollSigningKey,
    /// Selects the normalized `EnrollSigningKey` Connect operation.
    EnrollSigningKey,
    /// Selects the normalized `PlanRotateSigningKey` Connect operation.
    PlanRotateSigningKey,
    /// Selects the normalized `RotateSigningKey` Connect operation.
    RotateSigningKey,
    /// Selects the normalized `PlanRetireSigningKey` Connect operation.
    PlanRetireSigningKey,
    /// Selects the normalized `RetireSigningKey` Connect operation.
    RetireSigningKey,
    /// Selects the normalized `PlanSetSigningKeyUsage` Connect operation.
    PlanSetSigningKeyUsage,
    /// Selects the normalized `SetSigningKeyUsage` Connect operation.
    SetSigningKeyUsage,
    /// Selects the normalized `ListProjects` Connect operation.
    ListProjects,
    /// Selects the normalized `GetProject` Connect operation.
    GetProject,
    /// Selects the normalized `PlanCreateProject` Connect operation.
    PlanCreateProject,
    /// Selects the normalized `CreateProject` Connect operation.
    CreateProject,
    /// Selects the normalized `PlanDeleteProject` Connect operation.
    PlanDeleteProject,
    /// Selects the normalized `DeleteProject` Connect operation.
    DeleteProject,
    /// Selects the normalized `GetInstanceDefaultStorageBinding` Connect operation.
    GetInstanceDefaultStorageBinding,
    /// Selects the normalized `GetWriteAuthority` Connect operation.
    GetWriteAuthority,
    /// Selects the fenced write-authority controller observation.
    ReportWriteAuthority,
    /// Selects the normalized `PlanRemoveWriteAuthority` Connect operation.
    PlanRemoveWriteAuthority,
    /// Selects the normalized `RemoveWriteAuthority` Connect operation.
    RemoveWriteAuthority,
    /// Selects the normalized `ListAudit` Connect operation.
    ListAudit,
    /// Selects the normalized `GetInstanceSettings` Connect operation.
    GetInstanceSettings,
    /// Selects the normalized instance-settings planning operation.
    PlanSetInstanceSettings,
    /// Selects the normalized instance-settings apply operation.
    SetInstanceSettings,
    /// Selects the normalized `ListChangesets` Connect operation.
    ListChangesets,
    /// Selects the normalized `GetChangeset` Connect operation.
    GetChangeset,
    /// Selects the normalized `ListPackages` Connect operation.
    ListPackages,
    /// Selects the normalized `GetPackage` Connect operation.
    GetPackage,
    /// Selects the normalized `ListChannels` Connect operation.
    ListChannels,
    /// Selects the normalized `GetChannel` Connect operation.
    GetChannel,
    /// Selects signed system-image listing.
    ListImages,
    /// Selects exact signed system-image inspection.
    GetImage,
    /// Selects signed system-image resolution.
    ResolveImage,
    /// Selects placement-aware publication admission.
    BeginRegistryPublication,
    /// Selects publication status inspection.
    GetRegistryPublication,
    /// Selects exact publication promotion.
    CommitRegistryPublication,
    /// Selects explicit incomplete-publication retirement.
    AbortRegistryPublication,
    /// Selects the normalized `GitLog` Connect operation.
    GitLog,
    /// Selects the normalized `GitDiff` Connect operation.
    GitDiff,
    /// Selects the normalized `ListChangeRequests` Connect operation.
    ListChangeRequests,
    /// Selects the normalized `ListWebhooks` Connect operation.
    ListWebhooks,
    /// Selects the normalized `PlanCreateWebhook` Connect operation.
    PlanCreateWebhook,
    /// Selects the normalized `CreateWebhook` Connect operation.
    CreateWebhook,
    /// Selects the normalized `PlanDeleteWebhook` Connect operation.
    PlanDeleteWebhook,
    /// Selects the normalized `DeleteWebhook` Connect operation.
    DeleteWebhook,
    PlanCreateAutomationPrincipal,
    CreateAutomationPrincipal,
    GetMembership,
    PlanSetMembership,
    SetMembership,
    PlanIssueRegistryToken,
    IssueRegistryToken,
    PlanRetireRegistryToken,
    RetireRegistryToken,
    /// Selects the normalized `ListTokens` Connect operation.
    ListTokens,
}

impl HubTopologyMethod {
    /// Returns the canonical `aos.hub.v1` Connect method path.
    fn path(self) -> &'static str {
        use HubTopologyMethod::*;
        match self {
            PlanUpdateOrganization => "aos.hub.v1.OrganizationService/PlanUpdateOrganization",
            UpdateOrganization => "aos.hub.v1.OrganizationService/UpdateOrganization",
            ListStorageBindings => "aos.hub.v1.StorageBindingService/ListStorageBindings",
            GetStorageBinding => "aos.hub.v1.StorageBindingService/GetStorageBinding",
            PlanCreateStorageBinding => "aos.hub.v1.StorageBindingService/PlanCreateStorageBinding",
            CreateStorageBinding => "aos.hub.v1.StorageBindingService/CreateStorageBinding",
            PlanSetStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/PlanSetStorageBindingCredential"
            }
            SetStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/SetStorageBindingCredential"
            }
            PlanRotateStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/PlanRotateStorageBindingCredential"
            }
            RotateStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/RotateStorageBindingCredential"
            }
            PlanValidateStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/PlanValidateStorageBindingCredential"
            }
            ValidateStorageBindingCredential => {
                "aos.hub.v1.StorageBindingService/ValidateStorageBindingCredential"
            }
            PlanGrantStorageBindingScope => {
                "aos.hub.v1.StorageBindingService/PlanGrantStorageBindingScope"
            }
            GrantStorageBindingScope => "aos.hub.v1.StorageBindingService/GrantStorageBindingScope",
            PlanRevokeStorageBindingScope => {
                "aos.hub.v1.StorageBindingService/PlanRevokeStorageBindingScope"
            }
            RevokeStorageBindingScope => {
                "aos.hub.v1.StorageBindingService/RevokeStorageBindingScope"
            }
            ListStorageBindingWriteRevisions => {
                "aos.hub.v1.StorageBindingService/ListStorageBindingWriteRevisions"
            }
            GetStorageBindingWriteRevision => {
                "aos.hub.v1.StorageBindingService/GetStorageBindingWriteRevision"
            }
            ReportStorageBindingWriteRevision => {
                "aos.hub.v1.StorageBindingControllerService/ReportStorageBindingWriteRevision"
            }
            PlanDeleteStorageBinding => "aos.hub.v1.StorageBindingService/PlanDeleteStorageBinding",
            DeleteStorageBinding => "aos.hub.v1.StorageBindingService/DeleteStorageBinding",
            GetInstanceTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/GetInstanceTopologyDefaults"
            }
            PlanSetInstanceTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/PlanSetInstanceTopologyDefaults"
            }
            SetInstanceTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/SetInstanceTopologyDefaults"
            }
            GetOrganizationTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/GetOrganizationTopologyDefaults"
            }
            PlanSetOrganizationTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/PlanSetOrganizationTopologyDefaults"
            }
            SetOrganizationTopologyDefaults => {
                "aos.hub.v1.StorageBindingService/SetOrganizationTopologyDefaults"
            }
            ListDomains => "aos.hub.v1.DomainService/ListDomains",
            GetDomain => "aos.hub.v1.DomainService/GetDomain",
            PlanCreateDomain => "aos.hub.v1.DomainService/PlanCreateDomain",
            CreateDomain => "aos.hub.v1.DomainService/CreateDomain",
            PlanConfigureDomainDns => "aos.hub.v1.DomainService/PlanConfigureDomainDns",
            ConfigureDomainDns => "aos.hub.v1.DomainService/ConfigureDomainDns",
            PlanConfigureDomainCertificate => {
                "aos.hub.v1.DomainService/PlanConfigureDomainCertificate"
            }
            ConfigureDomainCertificate => "aos.hub.v1.DomainService/ConfigureDomainCertificate",
            PlanVerifyDomain => "aos.hub.v1.DomainService/PlanVerifyDomain",
            VerifyDomain => "aos.hub.v1.DomainService/VerifyDomain",
            PlanDeleteDomain => "aos.hub.v1.DomainService/PlanDeleteDomain",
            DeleteDomain => "aos.hub.v1.DomainService/DeleteDomain",
            ListNetworkBoundaries => "aos.hub.v1.NetworkBoundaryService/ListNetworkBoundaries",
            GetNetworkBoundary => "aos.hub.v1.NetworkBoundaryService/GetNetworkBoundary",
            PlanCreateNetworkBoundary => {
                "aos.hub.v1.NetworkBoundaryService/PlanCreateNetworkBoundary"
            }
            CreateNetworkBoundary => "aos.hub.v1.NetworkBoundaryService/CreateNetworkBoundary",
            ListNetworkBoundaryRevisions => {
                "aos.hub.v1.NetworkBoundaryService/ListNetworkBoundaryRevisions"
            }
            GetNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryService/GetNetworkBoundaryRevision"
            }
            PlanReviseNetworkBoundary => {
                "aos.hub.v1.NetworkBoundaryService/PlanReviseNetworkBoundary"
            }
            ReviseNetworkBoundary => "aos.hub.v1.NetworkBoundaryService/ReviseNetworkBoundary",
            CompleteNetworkBoundaryRevisionProbe => {
                "aos.hub.v1.NetworkBoundaryControllerService/CompleteNetworkBoundaryRevisionProbe"
            }
            ReportNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryControllerService/ReportNetworkBoundaryRevision"
            }
            PlanActivateNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryService/PlanActivateNetworkBoundaryRevision"
            }
            ActivateNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryService/ActivateNetworkBoundaryRevision"
            }
            PlanRetireNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryService/PlanRetireNetworkBoundaryRevision"
            }
            RetireNetworkBoundaryRevision => {
                "aos.hub.v1.NetworkBoundaryService/RetireNetworkBoundaryRevision"
            }
            PlanGrantNetworkBoundaryScope => {
                "aos.hub.v1.NetworkBoundaryService/PlanGrantNetworkBoundaryScope"
            }
            GrantNetworkBoundaryScope => {
                "aos.hub.v1.NetworkBoundaryService/GrantNetworkBoundaryScope"
            }
            PlanRevokeNetworkBoundaryScope => {
                "aos.hub.v1.NetworkBoundaryService/PlanRevokeNetworkBoundaryScope"
            }
            RevokeNetworkBoundaryScope => {
                "aos.hub.v1.NetworkBoundaryService/RevokeNetworkBoundaryScope"
            }
            PlanDeleteNetworkBoundary => {
                "aos.hub.v1.NetworkBoundaryService/PlanDeleteNetworkBoundary"
            }
            DeleteNetworkBoundary => "aos.hub.v1.NetworkBoundaryService/DeleteNetworkBoundary",
            ListDeliveryEndpoints => "aos.hub.v1.DeliveryService/ListDeliveryEndpoints",
            GetDeliveryEndpoint => "aos.hub.v1.DeliveryService/GetDeliveryEndpoint",
            PlanCreateDeliveryEndpoint => "aos.hub.v1.DeliveryService/PlanCreateDeliveryEndpoint",
            CreateDeliveryEndpoint => "aos.hub.v1.DeliveryService/CreateDeliveryEndpoint",
            ListDeliveryEndpointGenerations => {
                "aos.hub.v1.DeliveryService/ListDeliveryEndpointGenerations"
            }
            GetDeliveryEndpointGeneration => {
                "aos.hub.v1.DeliveryService/GetDeliveryEndpointGeneration"
            }
            PlanStageDeliveryEndpointGeneration => {
                "aos.hub.v1.DeliveryService/PlanStageDeliveryEndpointGeneration"
            }
            StageDeliveryEndpointGeneration => {
                "aos.hub.v1.DeliveryService/StageDeliveryEndpointGeneration"
            }
            PlanActivateDeliveryEndpointGeneration => {
                "aos.hub.v1.DeliveryService/PlanActivateDeliveryEndpointGeneration"
            }
            ActivateDeliveryEndpointGeneration => {
                "aos.hub.v1.DeliveryService/ActivateDeliveryEndpointGeneration"
            }
            PlanGrantDeliveryEndpointScope => {
                "aos.hub.v1.DeliveryService/PlanGrantDeliveryEndpointScope"
            }
            GrantDeliveryEndpointScope => "aos.hub.v1.DeliveryService/GrantDeliveryEndpointScope",
            PlanRevokeDeliveryEndpointScope => {
                "aos.hub.v1.DeliveryService/PlanRevokeDeliveryEndpointScope"
            }
            RevokeDeliveryEndpointScope => "aos.hub.v1.DeliveryService/RevokeDeliveryEndpointScope",
            CompleteDeliveryEndpointProbe => {
                "aos.hub.v1.DeliveryControllerService/CompleteDeliveryEndpointProbe"
            }
            ReportDeliveryEndpoint => "aos.hub.v1.DeliveryControllerService/ReportDeliveryEndpoint",
            PlanDeleteDeliveryEndpoint => "aos.hub.v1.DeliveryService/PlanDeleteDeliveryEndpoint",
            DeleteDeliveryEndpoint => "aos.hub.v1.DeliveryService/DeleteDeliveryEndpoint",
            ListStorageGateways => "aos.hub.v1.DeliveryService/ListStorageGateways",
            GetStorageGateway => "aos.hub.v1.DeliveryService/GetStorageGateway",
            PlanCreateStorageGateway => "aos.hub.v1.DeliveryService/PlanCreateStorageGateway",
            CreateStorageGateway => "aos.hub.v1.DeliveryService/CreateStorageGateway",
            PlanUpdateStorageGateway => "aos.hub.v1.DeliveryService/PlanUpdateStorageGateway",
            UpdateStorageGateway => "aos.hub.v1.DeliveryService/UpdateStorageGateway",
            PlanGrantStorageGatewayScope => {
                "aos.hub.v1.DeliveryService/PlanGrantStorageGatewayScope"
            }
            GrantStorageGatewayScope => "aos.hub.v1.DeliveryService/GrantStorageGatewayScope",
            PlanRevokeStorageGatewayScope => {
                "aos.hub.v1.DeliveryService/PlanRevokeStorageGatewayScope"
            }
            RevokeStorageGatewayScope => "aos.hub.v1.DeliveryService/RevokeStorageGatewayScope",
            PreviewGatewayRoutes => "aos.hub.v1.DeliveryService/PreviewGatewayRoutes",
            ReportStorageGateway => "aos.hub.v1.DeliveryControllerService/ReportStorageGateway",
            PlanEnableStorageGateway => "aos.hub.v1.DeliveryService/PlanEnableStorageGateway",
            EnableStorageGateway => "aos.hub.v1.DeliveryService/EnableStorageGateway",
            PlanDisableStorageGateway => "aos.hub.v1.DeliveryService/PlanDisableStorageGateway",
            DisableStorageGateway => "aos.hub.v1.DeliveryService/DisableStorageGateway",
            PlanDeleteStorageGateway => "aos.hub.v1.DeliveryService/PlanDeleteStorageGateway",
            DeleteStorageGateway => "aos.hub.v1.DeliveryService/DeleteStorageGateway",
            ListRoutes => "aos.hub.v1.RouteService/ListRoutes",
            GetRoute => "aos.hub.v1.RouteService/GetRoute",
            PlanCreateRoute => "aos.hub.v1.RouteService/PlanCreateRoute",
            CreateRoute => "aos.hub.v1.RouteService/CreateRoute",
            PlanUpdateRoute => "aos.hub.v1.RouteService/PlanUpdateRoute",
            UpdateRoute => "aos.hub.v1.RouteService/UpdateRoute",
            PlanReplaceRoute => "aos.hub.v1.RouteService/PlanReplaceRoute",
            ReplaceRoute => "aos.hub.v1.RouteService/ReplaceRoute",
            PlanEnableRoute => "aos.hub.v1.RouteService/PlanEnableRoute",
            EnableRoute => "aos.hub.v1.RouteService/EnableRoute",
            PlanDisableRoute => "aos.hub.v1.RouteService/PlanDisableRoute",
            DisableRoute => "aos.hub.v1.RouteService/DisableRoute",
            PlanDeleteRoute => "aos.hub.v1.RouteService/PlanDeleteRoute",
            DeleteRoute => "aos.hub.v1.RouteService/DeleteRoute",
            PlanSetCanonicalRoute => "aos.hub.v1.RouteService/PlanSetCanonicalRoute",
            SetCanonicalRoute => "aos.hub.v1.RouteService/SetCanonicalRoute",
            CompleteRouteProbe => "aos.hub.v1.RouteControllerService/CompleteRouteProbe",
            ExplainRoute => "aos.hub.v1.RouteService/ExplainRoute",
            GetSurfaceTopology => "aos.hub.v1.TopologyService/GetSurfaceTopology",
            ExplainSurfaceRequest => "aos.hub.v1.TopologyService/ExplainSurfaceRequest",
            ListBinaryCaches => "aos.hub.v1.BinaryCacheService/ListBinaryCaches",
            GetBinaryCache => "aos.hub.v1.BinaryCacheService/GetBinaryCache",
            PlanCreateBinaryCache => "aos.hub.v1.BinaryCacheService/PlanCreateBinaryCache",
            CreateBinaryCache => "aos.hub.v1.BinaryCacheService/CreateBinaryCache",
            PlanUpdateBinaryCache => "aos.hub.v1.BinaryCacheService/PlanUpdateBinaryCache",
            UpdateBinaryCache => "aos.hub.v1.BinaryCacheService/UpdateBinaryCache",
            PlanDeleteBinaryCache => "aos.hub.v1.BinaryCacheService/PlanDeleteBinaryCache",
            DeleteBinaryCache => "aos.hub.v1.BinaryCacheService/DeleteBinaryCache",
            GetCacheGcPolicy => "aos.hub.v1.BinaryCacheService/GetCacheGcPolicy",
            PlanSetCacheGcPolicy => "aos.hub.v1.BinaryCacheService/PlanSetCacheGcPolicy",
            SetCacheGcPolicy => "aos.hub.v1.BinaryCacheService/SetCacheGcPolicy",
            PlanRunCacheGc => "aos.hub.v1.BinaryCacheService/PlanRunCacheGc",
            RunCacheGc => "aos.hub.v1.BinaryCacheService/RunCacheGc",
            PlanAcknowledgeCacheGcFirstSweep => {
                "aos.hub.v1.BinaryCacheService/PlanAcknowledgeCacheGcFirstSweep"
            }
            AcknowledgeCacheGcFirstSweep => {
                "aos.hub.v1.BinaryCacheService/AcknowledgeCacheGcFirstSweep"
            }
            GetCacheGcPlan => "aos.hub.v1.BinaryCacheService/GetCacheGcPlan",
            GetCacheGcRun => "aos.hub.v1.BinaryCacheService/GetCacheGcRun",
            SearchCache => "aos.hub.v1.BinaryCacheService/SearchCache",
            GetCacheObject => "aos.hub.v1.BinaryCacheService/GetCacheObject",
            ListCacheGcRuns => "aos.hub.v1.BinaryCacheService/ListCacheGcRuns",
            GetCacheGcDeletionJob => "aos.hub.v1.BinaryCacheService/GetCacheGcDeletionJob",
            ListCacheGcDeletionJobs => "aos.hub.v1.BinaryCacheService/ListCacheGcDeletionJobs",
            PlanRetryCacheGcDeletionJob => {
                "aos.hub.v1.BinaryCacheService/PlanRetryCacheGcDeletionJob"
            }
            RetryCacheGcDeletionJob => "aos.hub.v1.BinaryCacheService/RetryCacheGcDeletionJob",
            PlanAbandonCacheGcDeletionJob => {
                "aos.hub.v1.BinaryCacheService/PlanAbandonCacheGcDeletionJob"
            }
            AbandonCacheGcDeletionJob => "aos.hub.v1.BinaryCacheService/AbandonCacheGcDeletionJob",
            ListRootReasons => "aos.hub.v1.BinaryCacheService/ListRootReasons",
            GetRetentionRoot => "aos.hub.v1.BinaryCacheService/GetRetentionRoot",
            ListRetentionRoots => "aos.hub.v1.BinaryCacheService/ListRetentionRoots",
            PlanCreateManualRetentionRoot => {
                "aos.hub.v1.BinaryCacheService/PlanCreateManualRetentionRoot"
            }
            CreateManualRetentionRoot => "aos.hub.v1.BinaryCacheService/CreateManualRetentionRoot",
            PlanRenewRetentionLease => "aos.hub.v1.BinaryCacheService/PlanRenewRetentionLease",
            RenewRetentionLease => "aos.hub.v1.BinaryCacheService/RenewRetentionLease",
            PlanRevokeRetentionLease => "aos.hub.v1.BinaryCacheService/PlanRevokeRetentionLease",
            RevokeRetentionLease => "aos.hub.v1.BinaryCacheService/RevokeRetentionLease",
            PlanDeleteManualRetentionRoot => {
                "aos.hub.v1.BinaryCacheService/PlanDeleteManualRetentionRoot"
            }
            DeleteManualRetentionRoot => "aos.hub.v1.BinaryCacheService/DeleteManualRetentionRoot",
            PlanRefreshAllRetention => "aos.hub.v1.BinaryCacheService/PlanRefreshAllRetention",
            RefreshAllRetention => "aos.hub.v1.BinaryCacheService/RefreshAllRetention",
            PlanRunPlacementEviction => "aos.hub.v1.BinaryCacheService/PlanRunPlacementEviction",
            RunPlacementEviction => "aos.hub.v1.BinaryCacheService/RunPlacementEviction",
            CacheClosure => "aos.hub.v1.BinaryCacheService/CacheClosure",
            CreateCacheObjectUploads => "aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
            BeginCacheMultipartUpload => "aos.hub.v1.BinaryCacheService/BeginCacheMultipartUpload",
            CompleteCacheMultipartUpload => {
                "aos.hub.v1.BinaryCacheService/CompleteCacheMultipartUpload"
            }
            AbortCacheMultipartUpload => "aos.hub.v1.BinaryCacheService/AbortCacheMultipartUpload",
            ReportCacheUpload => "aos.hub.v1.BinaryCacheUploadControllerService/ReportCacheUpload",
            ReportCacheNarinfos => {
                "aos.hub.v1.BinaryCacheUploadControllerService/ReportCacheNarinfos"
            }
            ListRegistryCacheIntegrations => {
                "aos.hub.v1.CacheIntegrationService/ListRegistryCacheIntegrations"
            }
            ListCacheRegistryIntegrations => {
                "aos.hub.v1.CacheIntegrationService/ListCacheRegistryIntegrations"
            }
            GetCacheRegistryIntegration => {
                "aos.hub.v1.CacheIntegrationService/GetCacheRegistryIntegration"
            }
            PreviewCacheIntegration => "aos.hub.v1.CacheIntegrationService/PreviewCacheIntegration",
            GetConsumerCacheStack => "aos.hub.v1.CacheIntegrationService/GetConsumerCacheStack",
            ValidateConsumerCacheStack => {
                "aos.hub.v1.CacheIntegrationService/ValidateConsumerCacheStack"
            }
            PlanCreateConsumerCacheChangeset => {
                "aos.hub.v1.CacheIntegrationService/PlanCreateConsumerCacheChangeset"
            }
            CreateConsumerCacheChangeset => {
                "aos.hub.v1.CacheIntegrationService/CreateConsumerCacheChangeset"
            }
            GetRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/GetRetentionSubscription"
            }
            ListRetentionSubscriptions => {
                "aos.hub.v1.CacheIntegrationService/ListRetentionSubscriptions"
            }
            PlanSetRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/PlanSetRetentionSubscription"
            }
            SetRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/SetRetentionSubscription"
            }
            PlanDeleteRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/PlanDeleteRetentionSubscription"
            }
            DeleteRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/DeleteRetentionSubscription"
            }
            PlanRefreshRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/PlanRefreshRetentionSubscription"
            }
            RefreshRetentionSubscription => {
                "aos.hub.v1.CacheIntegrationService/RefreshRetentionSubscription"
            }
            ExplainRetention => "aos.hub.v1.CacheIntegrationService/ExplainRetention",
            GetPopulationTarget => "aos.hub.v1.CacheIntegrationService/GetPopulationTarget",
            ListPopulationTargets => "aos.hub.v1.CacheIntegrationService/ListPopulationTargets",
            PlanSetPopulationTarget => "aos.hub.v1.CacheIntegrationService/PlanSetPopulationTarget",
            SetPopulationTarget => "aos.hub.v1.CacheIntegrationService/SetPopulationTarget",
            PlanDeletePopulationTarget => {
                "aos.hub.v1.CacheIntegrationService/PlanDeletePopulationTarget"
            }
            DeletePopulationTarget => "aos.hub.v1.CacheIntegrationService/DeletePopulationTarget",
            PlanRunPopulation => "aos.hub.v1.CacheIntegrationService/PlanRunPopulation",
            RunPopulation => "aos.hub.v1.CacheIntegrationService/RunPopulation",
            GetCoverage => "aos.hub.v1.CacheIntegrationService/GetCoverage",
            PlanRunCoverageValidation => {
                "aos.hub.v1.CacheIntegrationService/PlanRunCoverageValidation"
            }
            RunCoverageValidation => "aos.hub.v1.CacheIntegrationService/RunCoverageValidation",
            PlanRunCoverageRepair => "aos.hub.v1.CacheIntegrationService/PlanRunCoverageRepair",
            RunCoverageRepair => "aos.hub.v1.CacheIntegrationService/RunCoverageRepair",
            GetOperation => "aos.hub.v1.OperationService/GetOperation",
            ListOperations => "aos.hub.v1.OperationService/ListOperations",
            WatchOperation => "aos.hub.v1.OperationService/WatchOperation",
            CancelOperation => "aos.hub.v1.OperationService/CancelOperation",
            RetryOperation => "aos.hub.v1.OperationService/RetryOperation",
            PlanCreatePlacement => "aos.hub.v1.TopologyService/PlanCreatePlacement",
            CreatePlacement => "aos.hub.v1.TopologyService/CreatePlacement",
            PlanUpdatePlacement => "aos.hub.v1.TopologyService/PlanUpdatePlacement",
            UpdatePlacement => "aos.hub.v1.TopologyService/UpdatePlacement",
            PlanCancelPlacementPromotion => {
                "aos.hub.v1.TopologyService/PlanCancelPlacementPromotion"
            }
            CancelPlacementPromotion => "aos.hub.v1.TopologyService/CancelPlacementPromotion",
            PlanPromotePlacement => "aos.hub.v1.TopologyService/PlanPromotePlacement",
            PromotePlacement => "aos.hub.v1.TopologyService/PromotePlacement",
            PlanDrainPlacement => "aos.hub.v1.TopologyService/PlanDrainPlacement",
            DrainPlacement => "aos.hub.v1.TopologyService/DrainPlacement",
            PlanCancelPlacementDrain => "aos.hub.v1.TopologyService/PlanCancelPlacementDrain",
            CancelPlacementDrain => "aos.hub.v1.TopologyService/CancelPlacementDrain",
            PlanDeletePlacement => "aos.hub.v1.TopologyService/PlanDeletePlacement",
            DeletePlacement => "aos.hub.v1.TopologyService/DeletePlacement",
            PlanScanPlacement => "aos.hub.v1.TopologyService/PlanScanPlacement",
            ScanPlacement => "aos.hub.v1.TopologyService/ScanPlacement",
            PlanReplicatePlacement => "aos.hub.v1.TopologyService/PlanReplicatePlacement",
            ReplicatePlacement => "aos.hub.v1.TopologyService/ReplicatePlacement",
            PlanRepairPlacement => "aos.hub.v1.TopologyService/PlanRepairPlacement",
            RepairPlacement => "aos.hub.v1.TopologyService/RepairPlacement",
            ListObjectPresence => "aos.hub.v1.TopologyService/ListObjectPresence",
            ListPlacementPolicies => "aos.hub.v1.TopologyService/ListPlacementPolicies",
            GetPlacementPolicy => "aos.hub.v1.TopologyService/GetPlacementPolicy",
            ListPlacementPolicyRevisions => {
                "aos.hub.v1.TopologyService/ListPlacementPolicyRevisions"
            }
            GetPlacementPolicyRevision => "aos.hub.v1.TopologyService/GetPlacementPolicyRevision",
            PlanCreatePlacementPolicy => "aos.hub.v1.TopologyService/PlanCreatePlacementPolicy",
            CreatePlacementPolicy => "aos.hub.v1.TopologyService/CreatePlacementPolicy",
            PlanRevisePlacementPolicy => "aos.hub.v1.TopologyService/PlanRevisePlacementPolicy",
            RevisePlacementPolicy => "aos.hub.v1.TopologyService/RevisePlacementPolicy",
            TestPlacementPolicyRevision => "aos.hub.v1.TopologyService/TestPlacementPolicyRevision",
            ListPlacementEquivalences => "aos.hub.v1.TopologyService/ListPlacementEquivalences",
            PlanConfirmPlacementEquivalence => {
                "aos.hub.v1.TopologyService/PlanConfirmPlacementEquivalence"
            }
            ConfirmPlacementEquivalence => "aos.hub.v1.TopologyService/ConfirmPlacementEquivalence",
            PlanDeletePlacementEquivalence => {
                "aos.hub.v1.TopologyService/PlanDeletePlacementEquivalence"
            }
            DeletePlacementEquivalence => "aos.hub.v1.TopologyService/DeletePlacementEquivalence",
            GetRegistryMirror => "aos.hub.v1.RegistryMirrorService/GetRegistryMirror",
            PlanSetRegistryMirror => "aos.hub.v1.RegistryMirrorService/PlanSetRegistryMirror",
            SetRegistryMirror => "aos.hub.v1.RegistryMirrorService/SetRegistryMirror",
            PlanDeleteRegistryMirror => "aos.hub.v1.RegistryMirrorService/PlanDeleteRegistryMirror",
            DeleteRegistryMirror => "aos.hub.v1.RegistryMirrorService/DeleteRegistryMirror",
            PlanSyncRegistryMirror => "aos.hub.v1.RegistryMirrorService/PlanSyncRegistryMirror",
            SyncRegistryMirror => "aos.hub.v1.RegistryMirrorService/SyncRegistryMirror",
            ListPlacements => "aos.hub.v1.TopologyService/ListPlacements",
            GetPlacement => "aos.hub.v1.TopologyService/GetPlacement",
            ListRegistries => "aos.hub.v1.RegistryService/ListRegistries",
            GetRegistry => "aos.hub.v1.RegistryService/GetRegistry",
            ListReleases => "aos.hub.v1.RegistryService/ListReleases",
            PlanCreateRegistry => "aos.hub.v1.RegistryService/PlanCreateRegistry",
            CreateRegistry => "aos.hub.v1.RegistryService/CreateRegistry",
            PlanUpdateRegistry => "aos.hub.v1.RegistryService/PlanUpdateRegistry",
            UpdateRegistry => "aos.hub.v1.RegistryService/UpdateRegistry",
            PlanDeleteRegistry => "aos.hub.v1.RegistryService/PlanDeleteRegistry",
            DeleteRegistry => "aos.hub.v1.RegistryService/DeleteRegistry",
            ListOrganizations => "aos.hub.v1.OrganizationService/ListOrganizations",
            GetOrganization => "aos.hub.v1.OrganizationService/GetOrganization",
            PlanCreateOrganization => "aos.hub.v1.OrganizationService/PlanCreateOrganization",
            CreateOrganization => "aos.hub.v1.OrganizationService/CreateOrganization",
            PlanDeleteOrganization => "aos.hub.v1.OrganizationService/PlanDeleteOrganization",
            DeleteOrganization => "aos.hub.v1.OrganizationService/DeleteOrganization",
            ListSigningKeys => "aos.hub.v1.SigningKeyService/ListSigningKeys",
            GetSigningKey => "aos.hub.v1.SigningKeyService/GetSigningKey",
            PlanEnrollSigningKey => "aos.hub.v1.SigningKeyService/PlanEnrollSigningKey",
            EnrollSigningKey => "aos.hub.v1.SigningKeyService/EnrollSigningKey",
            PlanRotateSigningKey => "aos.hub.v1.SigningKeyService/PlanRotateSigningKey",
            RotateSigningKey => "aos.hub.v1.SigningKeyService/RotateSigningKey",
            PlanRetireSigningKey => "aos.hub.v1.SigningKeyService/PlanRetireSigningKey",
            RetireSigningKey => "aos.hub.v1.SigningKeyService/RetireSigningKey",
            PlanSetSigningKeyUsage => "aos.hub.v1.SigningKeyService/PlanSetSigningKeyUsage",
            SetSigningKeyUsage => "aos.hub.v1.SigningKeyService/SetSigningKeyUsage",
            ListProjects => "aos.hub.v1.ProjectService/ListProjects",
            GetProject => "aos.hub.v1.ProjectService/GetProject",
            PlanCreateProject => "aos.hub.v1.ProjectService/PlanCreateProject",
            CreateProject => "aos.hub.v1.ProjectService/CreateProject",
            PlanDeleteProject => "aos.hub.v1.ProjectService/PlanDeleteProject",
            DeleteProject => "aos.hub.v1.ProjectService/DeleteProject",
            GetInstanceDefaultStorageBinding => {
                "aos.hub.v1.StorageBindingService/GetInstanceDefaultStorageBinding"
            }
            GetWriteAuthority => "aos.hub.v1.TopologyService/GetWriteAuthority",
            ReportWriteAuthority => "aos.hub.v1.TopologyControllerService/ReportWriteAuthority",
            PlanRemoveWriteAuthority => "aos.hub.v1.TopologyService/PlanRemoveWriteAuthority",
            RemoveWriteAuthority => "aos.hub.v1.TopologyService/RemoveWriteAuthority",
            ListAudit => "aos.hub.v1.AuditService/ListAudit",
            GetInstanceSettings => "aos.hub.v1.InstanceService/GetInstanceSettings",
            PlanSetInstanceSettings => "aos.hub.v1.InstanceService/PlanSetInstanceSettings",
            SetInstanceSettings => "aos.hub.v1.InstanceService/SetInstanceSettings",
            ListChangesets => "aos.hub.v1.RegistryConfigurationService/ListChangesets",
            GetChangeset => "aos.hub.v1.RegistryConfigurationService/GetChangeset",
            ListPackages => "aos.hub.v1.PackageService/ListPackages",
            GetPackage => "aos.hub.v1.PackageService/GetPackage",
            ListChannels => "aos.hub.v1.ChannelService/ListChannels",
            GetChannel => "aos.hub.v1.ChannelService/GetChannel",
            ListImages => "aos.hub.v1.ImageService/ListImages",
            GetImage => "aos.hub.v1.ImageService/GetImage",
            ResolveImage => "aos.hub.v1.ImageService/ResolveImage",
            BeginRegistryPublication => "aos.hub.v1.PublishService/BeginRegistryPublication",
            GetRegistryPublication => "aos.hub.v1.PublishService/GetRegistryPublication",
            CommitRegistryPublication => "aos.hub.v1.PublishService/CommitRegistryPublication",
            AbortRegistryPublication => "aos.hub.v1.PublishService/AbortRegistryPublication",
            GitLog => "aos.hub.v1.GitService/GitLog",
            GitDiff => "aos.hub.v1.GitService/GitDiff",
            ListChangeRequests => "aos.hub.v1.GitService/ListChangeRequests",
            ListWebhooks => "aos.hub.v1.WebhookService/ListWebhooks",
            PlanCreateWebhook => "aos.hub.v1.WebhookService/PlanCreateWebhook",
            CreateWebhook => "aos.hub.v1.WebhookService/CreateWebhook",
            PlanDeleteWebhook => "aos.hub.v1.WebhookService/PlanDeleteWebhook",
            DeleteWebhook => "aos.hub.v1.WebhookService/DeleteWebhook",
            PlanCreateAutomationPrincipal => {
                "aos.hub.v1.IdentityService/PlanCreateAutomationPrincipal"
            }
            CreateAutomationPrincipal => "aos.hub.v1.IdentityService/CreateAutomationPrincipal",
            GetMembership => "aos.hub.v1.IdentityService/GetMembership",
            PlanSetMembership => "aos.hub.v1.IdentityService/PlanSetMembership",
            SetMembership => "aos.hub.v1.IdentityService/SetMembership",
            PlanIssueRegistryToken => "aos.hub.v1.IdentityService/PlanIssueRegistryToken",
            IssueRegistryToken => "aos.hub.v1.IdentityService/IssueRegistryToken",
            PlanRetireRegistryToken => "aos.hub.v1.IdentityService/PlanRetireRegistryToken",
            RetireRegistryToken => "aos.hub.v1.IdentityService/RetireRegistryToken",
            ListTokens => "aos.hub.v1.IdentityService/ListTokens",
        }
    }
}

mod sealed {
    pub trait Sealed {
        fn method() -> &'static str;
    }
}

/// Describes one closed, request/response-typed Hub Connect operation.
///
/// The trait is sealed. Callers select one of the zero-sized markers in
/// [`hub_rpc`], so a request can never be paired with another method's path or
/// response type.
pub trait HubRpc: sealed::Sealed {
    /// Generated protobuf request accepted by this operation.
    type Request: Serialize;
    /// Generated protobuf response returned by this operation.
    type Response: DeserializeOwned;
}

macro_rules! typed_hub_rpcs {
    ($($name:ident: $request:ident => $response:ident;)*) => {
        $(
            #[doc = concat!("Selects the typed `", stringify!($name), "` Hub operation.")]
            #[derive(Debug, Clone, Copy)]
            pub struct $name;

            impl super::sealed::Sealed for $name {
                fn method() -> &'static str {
                    super::HubTopologyMethod::$name.path()
                }
            }

            impl super::HubRpc for $name {
                type Request = aos_proto_types::$request;
                type Response = aos_proto_types::$response;
            }
        )*
    };
}

/// Closed typed selectors for normalized Hub Connect operations.
pub mod hub_rpc {
    typed_hub_rpcs! {
        PlanUpdateOrganization: PlanUpdateOrganizationRequest => TopologyPlanResponse;
        UpdateOrganization: ApplyOrganizationMutationRequest => OrganizationResponse;
        ListStorageBindings: ListStorageBindingsRequest => ListStorageBindingsResponse;
        GetStorageBinding: GetStorageBindingRequest => GetStorageBindingResponse;
        PlanCreateStorageBinding: PlanStorageBindingMutationRequest => TopologyPlanResponse;
        CreateStorageBinding: ApplyStorageBindingMutationRequest => StorageBindingResponse;
        PlanSetStorageBindingCredential: PlanStorageBindingCredentialRequest => TopologyPlanResponse;
        SetStorageBindingCredential: ApplyStorageBindingCredentialRequest => StorageBindingCredentialResponse;
        PlanRotateStorageBindingCredential: PlanStorageBindingCredentialRequest => TopologyPlanResponse;
        RotateStorageBindingCredential: ApplyStorageBindingCredentialRequest => StorageBindingCredentialResponse;
        PlanValidateStorageBindingCredential: PlanValidateStorageBindingCredentialRequest => TopologyPlanResponse;
        ValidateStorageBindingCredential: ApplyTopologyPlanRequest => OperationResponse;
        PlanGrantStorageBindingScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        GrantStorageBindingScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PlanRevokeStorageBindingScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        RevokeStorageBindingScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        ListStorageBindingWriteRevisions: ListStorageBindingWriteRevisionsRequest => ListStorageBindingWriteRevisionsResponse;
        GetStorageBindingWriteRevision: GetStorageBindingWriteRevisionRequest => StorageBindingWriteRevisionResponse;
        ReportStorageBindingWriteRevision: ReportStorageBindingWriteRevisionRequest => StorageBindingWriteRevisionResponse;
        PlanDeleteStorageBinding: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteStorageBinding: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        GetInstanceTopologyDefaults: GetInstanceTopologyDefaultsRequest => TopologyDefaultsResponse;
        PlanSetInstanceTopologyDefaults: PlanSetTopologyDefaultsRequest => TopologyPlanResponse;
        SetInstanceTopologyDefaults: ApplySetTopologyDefaultsRequest => TopologyDefaultsResponse;
        GetOrganizationTopologyDefaults: GetOrganizationTopologyDefaultsRequest => TopologyDefaultsResponse;
        PlanSetOrganizationTopologyDefaults: PlanSetTopologyDefaultsRequest => TopologyPlanResponse;
        SetOrganizationTopologyDefaults: ApplySetTopologyDefaultsRequest => TopologyDefaultsResponse;
        ListDomains: ListDomainsRequest => ListDomainsResponse;
        GetDomain: GetTopologyResourceRequest => DomainResponse;
        PlanCreateDomain: PlanDomainMutationRequest => TopologyPlanResponse;
        CreateDomain: ApplyDomainMutationRequest => DomainResponse;
        PlanConfigureDomainDns: PlanDomainDnsRequest => TopologyPlanResponse;
        ConfigureDomainDns: ApplyDomainConfigurationRequest => DomainResponse;
        PlanConfigureDomainCertificate: PlanDomainCertificateRequest => TopologyPlanResponse;
        ConfigureDomainCertificate: ApplyDomainConfigurationRequest => DomainResponse;
        PlanVerifyDomain: PlanVerifyDomainRequest => TopologyPlanResponse;
        VerifyDomain: ApplyTopologyPlanRequest => OperationResponse;
        PlanDeleteDomain: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteDomain: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        ListNetworkBoundaries: ListTopologyResourcesRequest => ListNetworkBoundariesResponse;
        GetNetworkBoundary: GetTopologyResourceRequest => NetworkBoundaryResponse;
        PlanCreateNetworkBoundary: PlanNetworkBoundaryMutationRequest => TopologyPlanResponse;
        CreateNetworkBoundary: ApplyNetworkBoundaryMutationRequest => NetworkBoundaryResponse;
        ListNetworkBoundaryRevisions: ListNetworkBoundaryRevisionsRequest => ListNetworkBoundaryRevisionsResponse;
        GetNetworkBoundaryRevision: GetNetworkBoundaryRevisionRequest => NetworkBoundaryRevisionResponse;
        PlanReviseNetworkBoundary: PlanNetworkBoundaryRevisionRequest => TopologyPlanResponse;
        ReviseNetworkBoundary: ApplyNetworkBoundaryRevisionRequest => NetworkBoundaryRevisionResponse;
        CompleteNetworkBoundaryRevisionProbe: CompleteNetworkBoundaryRevisionProbeRequest => NetworkBoundaryRevisionResponse;
        ReportNetworkBoundaryRevision: ReportNetworkBoundaryRevisionRequest => NetworkBoundaryRevisionResponse;
        PlanActivateNetworkBoundaryRevision: PlanNetworkBoundaryLifecycleRequest => TopologyPlanResponse;
        ActivateNetworkBoundaryRevision: ApplyNetworkBoundaryLifecycleRequest => NetworkBoundaryRevisionResponse;
        PlanRetireNetworkBoundaryRevision: PlanNetworkBoundaryLifecycleRequest => TopologyPlanResponse;
        RetireNetworkBoundaryRevision: ApplyNetworkBoundaryLifecycleRequest => NetworkBoundaryRevisionResponse;
        PlanGrantNetworkBoundaryScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        GrantNetworkBoundaryScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PlanRevokeNetworkBoundaryScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        RevokeNetworkBoundaryScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PlanDeleteNetworkBoundary: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteNetworkBoundary: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        ListDeliveryEndpoints: ListTopologyResourcesRequest => ListDeliveryEndpointsResponse;
        GetDeliveryEndpoint: GetTopologyResourceRequest => DeliveryEndpointResponse;
        PlanCreateDeliveryEndpoint: PlanDeliveryEndpointMutationRequest => TopologyPlanResponse;
        CreateDeliveryEndpoint: ApplyDeliveryEndpointMutationRequest => DeliveryEndpointResponse;
        ListDeliveryEndpointGenerations: ListDeliveryEndpointGenerationsRequest => ListDeliveryEndpointGenerationsResponse;
        GetDeliveryEndpointGeneration: GetDeliveryEndpointGenerationRequest => DeliveryEndpointGenerationResponse;
        PlanStageDeliveryEndpointGeneration: PlanStageDeliveryEndpointGenerationRequest => TopologyPlanResponse;
        StageDeliveryEndpointGeneration: ApplyDeliveryEndpointGenerationRequest => DeliveryEndpointGenerationResponse;
        PlanActivateDeliveryEndpointGeneration: PlanActivateDeliveryEndpointGenerationRequest => TopologyPlanResponse;
        ActivateDeliveryEndpointGeneration: ApplyDeliveryEndpointGenerationRequest => DeliveryEndpointResponse;
        PlanGrantDeliveryEndpointScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        GrantDeliveryEndpointScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PlanRevokeDeliveryEndpointScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        RevokeDeliveryEndpointScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        CompleteDeliveryEndpointProbe: CompleteDeliveryEndpointProbeRequest => DeliveryEndpointResponse;
        ReportDeliveryEndpoint: ReportDeliveryEndpointRequest => DeliveryEndpointResponse;
        PlanDeleteDeliveryEndpoint: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteDeliveryEndpoint: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        ListStorageGateways: ListStorageGatewaysRequest => ListStorageGatewaysResponse;
        GetStorageGateway: GetTopologyResourceRequest => StorageGatewayResponse;
        PlanCreateStorageGateway: PlanStorageGatewayMutationRequest => TopologyPlanResponse;
        CreateStorageGateway: ApplyStorageGatewayMutationRequest => StorageGatewayResponse;
        PlanUpdateStorageGateway: PlanStorageGatewayMutationRequest => TopologyPlanResponse;
        UpdateStorageGateway: ApplyStorageGatewayMutationRequest => StorageGatewayResponse;
        PlanGrantStorageGatewayScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        GrantStorageGatewayScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PlanRevokeStorageGatewayScope: PlanConsumerScopeGrantRequest => TopologyPlanResponse;
        RevokeStorageGatewayScope: ApplyConsumerScopeGrantRequest => ConsumerScopeGrantResponse;
        PreviewGatewayRoutes: GetTopologyResourceRequest => GatewayRoutePreviewResponse;
        ReportStorageGateway: ReportStorageGatewayRequest => StorageGatewayResponse;
        PlanEnableStorageGateway: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        EnableStorageGateway: ApplyDeleteTopologyResourceRequest => StorageGatewayResponse;
        PlanDisableStorageGateway: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DisableStorageGateway: ApplyDeleteTopologyResourceRequest => StorageGatewayResponse;
        PlanDeleteStorageGateway: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteStorageGateway: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        ListRoutes: ListRoutesRequest => ListRoutesResponse;
        GetRoute: GetTopologyResourceRequest => DeliveryRouteResponse;
        PlanCreateRoute: PlanRouteMutationRequest => TopologyPlanResponse;
        CreateRoute: ApplyRouteMutationRequest => DeliveryRouteResponse;
        PlanUpdateRoute: PlanRouteMutationRequest => TopologyPlanResponse;
        UpdateRoute: ApplyRouteMutationRequest => DeliveryRouteResponse;
        PlanReplaceRoute: PlanReplaceRouteRequest => TopologyPlanResponse;
        ReplaceRoute: ApplyRouteMutationRequest => DeliveryRouteResponse;
        PlanEnableRoute: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        EnableRoute: ApplyDeleteTopologyResourceRequest => DeliveryRouteResponse;
        PlanDisableRoute: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DisableRoute: ApplyDeleteTopologyResourceRequest => DeliveryRouteResponse;
        PlanDeleteRoute: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteRoute: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        PlanSetCanonicalRoute: PlanCanonicalRouteRequest => TopologyPlanResponse;
        SetCanonicalRoute: ApplyCanonicalRouteRequest => CanonicalRouteResponse;
        CompleteRouteProbe: CompleteRouteProbeRequest => OperationResponse;
        ExplainRoute: ExplainRouteRequest => ExplainRouteResponse;
        GetSurfaceTopology: GetSurfaceTopologyRequest => GetSurfaceTopologyResponse;
        ExplainSurfaceRequest: ExplainSurfaceRequestRequest => ExplainSurfaceRequestResponse;
        ListBinaryCaches: ListBinaryCachesRequest => ListBinaryCachesResponse;
        GetBinaryCache: GetBinaryCacheRequest => BinaryCacheResponse;
        PlanCreateBinaryCache: PlanBinaryCacheMutationRequest => TopologyPlanResponse;
        CreateBinaryCache: ApplyBinaryCacheMutationRequest => BinaryCacheResponse;
        PlanUpdateBinaryCache: PlanBinaryCacheMutationRequest => TopologyPlanResponse;
        UpdateBinaryCache: ApplyBinaryCacheMutationRequest => BinaryCacheResponse;
        PlanDeleteBinaryCache: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteBinaryCache: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        GetCacheGcPolicy: GetCacheGcPolicyRequest => GetCacheGcPolicyResponse;
        PlanSetCacheGcPolicy: PlanSetCacheGcPolicyRequest => TopologyPlanResponse;
        SetCacheGcPolicy: ApplyCachePlanRequest => GetCacheGcPolicyResponse;
        PlanRunCacheGc: PlanRunCacheGcRequest => TopologyPlanResponse;
        RunCacheGc: ApplyCachePlanRequest => OperationResponse;
        PlanAcknowledgeCacheGcFirstSweep: PlanAcknowledgeCacheGcFirstSweepRequest => TopologyPlanResponse;
        AcknowledgeCacheGcFirstSweep: ApplyCachePlanRequest => CacheGcGenerationResponse;
        GetCacheGcPlan: GetCacheGcPlanRequest => CacheGcPlanResponse;
        GetCacheGcRun: GetCacheOperationRequest => CacheGcRunResponse;
        ListCacheGcRuns: ListCacheGcRunsRequest => ListCacheGcRunsResponse;
        GetCacheGcDeletionJob: GetCacheGcDeletionJobRequest => CacheGcDeletionJobResponse;
        ListCacheGcDeletionJobs: ListCacheGcDeletionJobsRequest => ListCacheGcDeletionJobsResponse;
        PlanRetryCacheGcDeletionJob: PlanRetryCacheGcDeletionJobRequest => TopologyPlanResponse;
        RetryCacheGcDeletionJob: ApplyTopologyPlanRequest => OperationResponse;
        PlanAbandonCacheGcDeletionJob: PlanAbandonCacheGcDeletionJobRequest => TopologyPlanResponse;
        AbandonCacheGcDeletionJob: ApplyCachePlanRequest => CacheGcDeletionJobResponse;
        ListRootReasons: ListRootReasonsRequest => ListRootReasonsResponse;
        PlanCreateManualRetentionRoot: PlanManualRetentionRootRequest => TopologyPlanResponse;
        CreateManualRetentionRoot: ApplyCachePlanRequest => RetentionRootResponse;
        PlanRenewRetentionLease: PlanRetentionLeaseRequest => TopologyPlanResponse;
        RenewRetentionLease: ApplyCachePlanRequest => RetentionLeaseResponse;
        PlanRevokeRetentionLease: PlanRevokeRetentionLeaseRequest => TopologyPlanResponse;
        RevokeRetentionLease: ApplyCachePlanRequest => RetentionLeaseResponse;
        PlanDeleteManualRetentionRoot: PlanDeleteManualRetentionRootRequest => TopologyPlanResponse;
        DeleteManualRetentionRoot: ApplyCachePlanRequest => DeleteTopologyResourceResponse;
        PlanRefreshAllRetention: PlanRefreshAllRetentionRequest => TopologyPlanResponse;
        RefreshAllRetention: ApplyTopologyPlanRequest => OperationResponse;
        PlanRunPlacementEviction: PlanRunPlacementEvictionRequest => TopologyPlanResponse;
        RunPlacementEviction: ApplyTopologyPlanRequest => OperationResponse;
        ListRegistryCacheIntegrations: ListRegistryCacheIntegrationsRequest => ListCacheIntegrationsResponse;
        ListCacheRegistryIntegrations: ListCacheRegistryIntegrationsRequest => ListCacheIntegrationsResponse;
        GetCacheRegistryIntegration: GetCacheRegistryIntegrationRequest => CacheIntegrationResponse;
        PreviewCacheIntegration: PreviewCacheIntegrationRequest => PreviewCacheIntegrationResponse;
        GetConsumerCacheStack: GetConsumerCacheStackRequest => ConsumerCacheStackResponse;
        ValidateConsumerCacheStack: GetConsumerCacheStackRequest => ConsumerCacheStackValidationResponse;
        PlanCreateConsumerCacheChangeset: PlanCreateConsumerCacheChangesetRequest => TopologyPlanResponse;
        CreateConsumerCacheChangeset: ApplyTopologyPlanRequest => ConsumerCacheChangesetResponse;
        ListRetentionSubscriptions: ListRetentionSubscriptionsRequest => ListRetentionSubscriptionsResponse;
        PlanSetRetentionSubscription: PlanRetentionSubscriptionRequest => TopologyPlanResponse;
        SetRetentionSubscription: ApplyCachePlanRequest => RetentionSubscriptionResponse;
        PlanDeleteRetentionSubscription: PlanDeleteRetentionSubscriptionRequest => TopologyPlanResponse;
        DeleteRetentionSubscription: ApplyCachePlanRequest => DeleteTopologyResourceResponse;
        PlanRefreshRetentionSubscription: PlanRefreshRetentionSubscriptionRequest => TopologyPlanResponse;
        RefreshRetentionSubscription: ApplyTopologyPlanRequest => OperationResponse;
        ExplainRetention: ExplainRetentionRequest => ExplainRetentionResponse;
        ListPopulationTargets: ListPopulationTargetsRequest => ListPopulationTargetsResponse;
        PlanSetPopulationTarget: PlanPopulationTargetRequest => TopologyPlanResponse;
        SetPopulationTarget: ApplyCachePlanRequest => PopulationTargetResponse;
        PlanDeletePopulationTarget: PlanDeletePopulationTargetRequest => TopologyPlanResponse;
        DeletePopulationTarget: ApplyCachePlanRequest => DeleteTopologyResourceResponse;
        PlanRunPopulation: PlanRunPopulationRequest => TopologyPlanResponse;
        RunPopulation: ApplyTopologyPlanRequest => OperationResponse;
        GetCoverage: GetPopulationTargetRequest => CoverageResponse;
        PlanRunCoverageValidation: PlanCoverageOperationRequest => TopologyPlanResponse;
        RunCoverageValidation: ApplyTopologyPlanRequest => OperationResponse;
        PlanRunCoverageRepair: PlanCoverageOperationRequest => TopologyPlanResponse;
        RunCoverageRepair: ApplyTopologyPlanRequest => OperationResponse;
        GetOperation: GetOperationRequest => OperationDetailResponse;
        ListOperations: ListOperationsRequest => ListOperationsResponse;
        WatchOperation: WatchOperationRequest => WatchOperationResponse;
        CancelOperation: MutateOperationRequest => OperationDetailResponse;
        RetryOperation: MutateOperationRequest => OperationDetailResponse;
        PlanCreatePlacement: PlanCreatePlacementRequest => TopologyPlanResponse;
        CreatePlacement: ApplyTopologyPlanRequest => PlacementResponse;
        PlanUpdatePlacement: PlanUpdatePlacementRequest => TopologyPlanResponse;
        UpdatePlacement: ApplyTopologyPlanRequest => PlacementResponse;
        PlanCancelPlacementPromotion: SurfaceMutationRequest => TopologyPlanResponse;
        CancelPlacementPromotion: ApplyTopologyPlanRequest => GetWriteAuthorityResponse;
        PlanPromotePlacement: PlacementMutationRequest => TopologyPlanResponse;
        PromotePlacement: ApplyTopologyPlanRequest => GetWriteAuthorityResponse;
        PlanDrainPlacement: PlacementMutationRequest => TopologyPlanResponse;
        DrainPlacement: ApplyTopologyPlanRequest => OperationResponse;
        PlanCancelPlacementDrain: PlacementMutationRequest => TopologyPlanResponse;
        CancelPlacementDrain: ApplyTopologyPlanRequest => PlacementResponse;
        PlanDeletePlacement: PlacementMutationRequest => TopologyPlanResponse;
        DeletePlacement: ApplyTopologyPlanRequest => DeleteTopologyResourceResponse;
        PlanScanPlacement: PlanScanPlacementRequest => TopologyPlanResponse;
        ScanPlacement: ApplyTopologyPlanRequest => OperationResponse;
        PlanReplicatePlacement: PlanReplicatePlacementRequest => TopologyPlanResponse;
        ReplicatePlacement: ApplyTopologyPlanRequest => OperationResponse;
        PlanRepairPlacement: PlanRepairPlacementRequest => TopologyPlanResponse;
        RepairPlacement: ApplyTopologyPlanRequest => OperationResponse;
        ListObjectPresence: ListObjectPresenceRequest => ListObjectPresenceResponse;
        ListPlacementPolicies: SurfaceListRequest => ListPlacementPoliciesResponse;
        GetPlacementPolicy: GetPlacementPolicyRequest => PlacementPolicyResponse;
        ListPlacementPolicyRevisions: ListPlacementPolicyRevisionsRequest => ListPlacementPolicyRevisionsResponse;
        GetPlacementPolicyRevision: GetPlacementPolicyRevisionRequest => PlacementPolicyRevisionResponse;
        PlanCreatePlacementPolicy: PlanPlacementPolicyMutationRequest => TopologyPlanResponse;
        CreatePlacementPolicy: ApplyTopologyPlanRequest => PlacementPolicyResponse;
        PlanRevisePlacementPolicy: PlanPlacementPolicyMutationRequest => TopologyPlanResponse;
        RevisePlacementPolicy: ApplyTopologyPlanRequest => PlacementPolicyRevisionResponse;
        TestPlacementPolicyRevision: TestPlacementPolicyRevisionRequest => TestPlacementPolicyRevisionResponse;
        ListPlacementEquivalences: SurfaceListRequest => ListPlacementEquivalencesResponse;
        PlanConfirmPlacementEquivalence: PlanPlacementEquivalenceRequest => TopologyPlanResponse;
        ConfirmPlacementEquivalence: ApplyTopologyPlanRequest => PlacementEquivalenceResponse;
        PlanDeletePlacementEquivalence: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeletePlacementEquivalence: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        GetRegistryMirror: GetRegistryMirrorRequest => RegistryMirrorResponse;
        PlanSetRegistryMirror: PlanRegistryMirrorMutationRequest => TopologyPlanResponse;
        SetRegistryMirror: ApplyTopologyPlanRequest => RegistryMirrorResponse;
        PlanDeleteRegistryMirror: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteRegistryMirror: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        PlanSyncRegistryMirror: PlanSyncRegistryMirrorRequest => TopologyPlanResponse;
        SyncRegistryMirror: ApplyTopologyPlanRequest => OperationResponse;
        ListPlacements: ListPlacementsRequest => ListPlacementsResponse;
        GetPlacement: GetPlacementRequest => GetPlacementResponse;
        ListRegistries: ListRegistriesRequest => ListRegistriesResponse;
        GetRegistry: GetRegistryRequest => GetRegistryResponse;
        ListReleases: ListReleasesRequest => ListReleasesResponse;
        PlanCreateRegistry: PlanCreateRegistryRequest => TopologyPlanResponse;
        CreateRegistry: ApplyRegistryMutationRequest => RegistryResponse;
        PlanUpdateRegistry: PlanUpdateRegistryRequest => TopologyPlanResponse;
        UpdateRegistry: ApplyRegistryMutationRequest => RegistryResponse;
        PlanDeleteRegistry: PlanDeleteTopologyResourceRequest => TopologyPlanResponse;
        DeleteRegistry: ApplyDeleteTopologyResourceRequest => DeleteTopologyResourceResponse;
        ListOrganizations: ListOrganizationsRequest => ListOrganizationsResponse;
        GetOrganization: GetOrganizationRequest => OrganizationResponse;
        PlanCreateOrganization: PlanCreateOrganizationRequest => TopologyPlanResponse;
        CreateOrganization: ApplyOrganizationMutationRequest => OrganizationResponse;
        PlanDeleteOrganization: PlanDeleteOrganizationRequest => TopologyPlanResponse;
        DeleteOrganization: ApplyOrganizationMutationRequest => DeleteTopologyResourceResponse;
        ListSigningKeys: ListSigningKeysRequest => ListSigningKeysResponse;
        GetSigningKey: GetSigningKeyRequest => SigningKeyResponse;
        PlanEnrollSigningKey: PlanSigningKeyMutationRequest => TopologyPlanResponse;
        EnrollSigningKey: ApplyTopologyPlanRequest => SigningKeyResponse;
        PlanRotateSigningKey: PlanSigningKeyMutationRequest => TopologyPlanResponse;
        RotateSigningKey: ApplyTopologyPlanRequest => SigningKeyResponse;
        PlanRetireSigningKey: PlanRetireSigningKeyRequest => TopologyPlanResponse;
        RetireSigningKey: ApplyTopologyPlanRequest => SigningKeyResponse;
        PlanSetSigningKeyUsage: PlanSigningKeyUsageRequest => TopologyPlanResponse;
        SetSigningKeyUsage: ApplyTopologyPlanRequest => SigningKeyUsageResponse;
        ListProjects: ListProjectsRequest => ListProjectsResponse;
        GetProject: GetProjectRequest => ProjectResponse;
        PlanCreateProject: PlanCreateProjectRequest => TopologyPlanResponse;
        CreateProject: ApplyProjectMutationRequest => ProjectResponse;
        PlanDeleteProject: PlanDeleteProjectRequest => TopologyPlanResponse;
        DeleteProject: ApplyProjectMutationRequest => DeleteTopologyResourceResponse;
        GetInstanceDefaultStorageBinding: GetInstanceTopologyDefaultsRequest => GetStorageBindingResponse;
        GetWriteAuthority: GetWriteAuthorityRequest => GetWriteAuthorityResponse;
        ReportWriteAuthority: ReportWriteAuthorityRequest => WriteAuthorityObservationResponse;
        PlanRemoveWriteAuthority: SurfaceMutationRequest => TopologyPlanResponse;
        RemoveWriteAuthority: ApplyTopologyPlanRequest => RemoveWriteAuthorityResponse;
        ListAudit: ListAuditRequest => ListAuditResponse;
        GetInstanceSettings: GetInstanceSettingsRequest => GetInstanceSettingsResponse;
        PlanSetInstanceSettings: PlanSetInstanceSettingsRequest => TopologyPlanResponse;
        SetInstanceSettings: ApplyTopologyPlanRequest => GetInstanceSettingsResponse;
        ListChangesets: ListChangesetsRequest => ListChangesetsResponse;
        GetChangeset: GetChangesetRequest => GetChangesetResponse;
        ListPackages: ListPackagesRequest => ListPackagesResponse;
        GetPackage: GetPackageRequest => GetPackageResponse;
        ListChannels: ListChannelsRequest => ListChannelsResponse;
        GetChannel: GetChannelRequest => GetChannelResponse;
        ListImages: ListImagesRequest => ListImagesResponse;
        GetImage: GetImageRequest => GetImageResponse;
        ResolveImage: ResolveImageRequest => GetImageResponse;
        BeginRegistryPublication: BeginRegistryPublicationRequest => RegistryPublication;
        GetRegistryPublication: GetRegistryPublicationRequest => RegistryPublication;
        CommitRegistryPublication: CommitRegistryPublicationRequest => RegistryPublication;
        AbortRegistryPublication: AbortRegistryPublicationRequest => RegistryPublication;
        GitLog: GitLogRequest => GitLogResponse;
        GitDiff: GitDiffRequest => GitDiffResponse;
        ListChangeRequests: ListChangeRequestsRequest => ListChangeRequestsResponse;
        ListWebhooks: ListWebhooksRequest => ListWebhooksResponse;
        PlanCreateWebhook: PlanCreateWebhookRequest => TopologyPlanResponse;
        CreateWebhook: ApplyWebhookMutationRequest => CreateWebhookResponse;
        PlanDeleteWebhook: PlanDeleteWebhookRequest => TopologyPlanResponse;
        DeleteWebhook: ApplyWebhookMutationRequest => DeleteTopologyResourceResponse;
        SearchCache: SearchCacheRequest => SearchCacheResponse;
        GetCacheObject: GetCacheObjectRequest => GetCacheObjectResponse;
        GetRetentionRoot: GetRetentionRootRequest => RetentionRootResponse;
        ListRetentionRoots: ListRetentionRootsRequest => ListRetentionRootsResponse;
        CacheClosure: CacheClosureRequest => CacheClosureResponse;
        CreateCacheObjectUploads: CreateCacheObjectUploadsRequest => CreateCacheObjectUploadsResponse;
        BeginCacheMultipartUpload: BeginCacheMultipartUploadRequest => BeginCacheMultipartUploadResponse;
        CompleteCacheMultipartUpload: CompleteCacheMultipartUploadRequest => CacheMultipartUploadResponse;
        AbortCacheMultipartUpload: AbortCacheMultipartUploadRequest => CacheMultipartUploadResponse;
        ReportCacheUpload: ReportCacheUploadRequest => CacheUploadObservationResponse;
        ReportCacheNarinfos: ReportCacheNarinfosRequest => CacheNarinfoRegistrationResponse;
        GetRetentionSubscription: GetRetentionSubscriptionRequest => RetentionSubscriptionResponse;
        GetPopulationTarget: GetPopulationTargetRequest => PopulationTargetResponse;
        PlanCreateAutomationPrincipal: PlanCreateAutomationPrincipalRequest => TopologyPlanResponse;
        CreateAutomationPrincipal: ApplyTopologyPlanRequest => AutomationPrincipalResponse;
        GetMembership: GetMembershipRequest => MembershipResponse;
        PlanSetMembership: PlanSetMembershipRequest => TopologyPlanResponse;
        SetMembership: ApplyTopologyPlanRequest => MembershipResponse;
        PlanIssueRegistryToken: PlanIssueRegistryTokenRequest => TopologyPlanResponse;
        IssueRegistryToken: ApplyTopologyPlanRequest => RegistryTokenResponse;
        PlanRetireRegistryToken: PlanRetireRegistryTokenRequest => TopologyPlanResponse;
        RetireRegistryToken: ApplyTopologyPlanRequest => RegistryTokenRetirementResponse;
        ListTokens: ListTokensRequest => ListTokensResponse;
    }
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

impl HubSurfaceRef {
    /// Converts the ergonomic reference into the public protobuf oneof.
    #[must_use]
    pub fn to_message(&self) -> SurfaceRef {
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
            "cache" => {
                let (org, name) = slug.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!("invalid cache surface '{value}': expected cache:<org>/<cache>")
                })?;
                if org.is_empty() || name.is_empty() || name.contains('/') {
                    anyhow::bail!("invalid cache surface '{value}': expected cache:<org>/<cache>");
                }
                Ok(Self::Cache(slug.to_string()))
            }
            _ => {
                anyhow::bail!("invalid surface '{value}': expected registry:<slug> or cache:<slug>")
            }
        }
    }
}

impl HubClient {
    /// Calls one normalized storage or delivery topology method.
    ///
    /// Request and response types should be the generated
    /// [`aos_proto_types`] messages declared by the selected method. The closed
    /// [`HubRpc`] selector owns the Connect service path and its generated
    /// request/response pair, so callers cannot combine an operation with the
    /// wrong message types or reach a removed legacy descriptor accidentally.
    ///
    /// # Errors
    ///
    /// Returns an error if the Hub is unreachable, rejects the request, or
    /// returns a response that does not decode as the selected response type.
    pub async fn call_topology<M>(&self, _method: M, request: &M::Request) -> Result<M::Response>
    where
        M: HubRpc,
    {
        self.call(M::method(), request).await
    }

    /// Streams one declared publication object to its exact Hub upload URL.
    ///
    /// The URL must share the configured Hub origin and use the typed
    /// `PublishService/UploadObject` namespace. This prevents a malicious or
    /// corrupted response from redirecting the bearer credential elsewhere.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-Hub URL, unreadable input, transport failure,
    /// or a non-success response from the Hub.
    pub async fn upload_publication_object(&self, upload_url: &str, path: &Path) -> Result<()> {
        let base = url::Url::parse(&self.base).context("parsing configured Hub URL")?;
        let target = url::Url::parse(upload_url).context("parsing publication upload URL")?;
        anyhow::ensure!(
            target.scheme() == base.scheme()
                && target.host_str() == base.host_str()
                && target.port_or_known_default() == base.port_or_known_default()
                && target.query().is_none()
                && target.fragment().is_none()
                && target
                    .path()
                    .starts_with("/aos.hub.v1.PublishService/UploadObject/"),
            "publication upload URL is outside the configured Hub origin"
        );
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("opening publication object {}", path.display()))?;
        let size = file
            .metadata()
            .await
            .with_context(|| format!("reading publication object metadata {}", path.display()))?
            .len();
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        let mut request = self
            .upload_http
            .put(target.clone())
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("uploading publication object to {target}"))?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "publication upload to {target} failed ({status}){}",
                if detail.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", detail.trim())
                }
            );
        }
        Ok(())
    }

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
        let upload_http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(HUB_TIMEOUT_SECS))
            .build()
            .context("building the hub upload HTTP client")?;
        Ok(Self {
            http,
            upload_http,
            base: ensure_trailing_slash(&base.to_string()),
            token: access_token.map(str::to_owned),
        })
    }

    /// Performs one unary Connect-JSON call against the hub.
    ///
    /// POSTs `req` as a JSON body to `{base}{full_method}` (e.g.
    /// `aos.hub.v1.TopologyService/GetSurfaceTopology`), attaching the bearer
    /// token and required `Connect-Protocol-Version: 1` header, then decodes the
    /// JSON response message. A non-2xx status is parsed as the Connect error
    /// envelope `{ code, message }`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub is unreachable, the request cannot be
    /// serialized, the hub returns a non-2xx status (the envelope's `code` and
    /// `message` are surfaced), or the success body cannot be decoded as `Resp`.
    async fn call<Req, Resp>(&self, full_method: &str, req: &Req) -> Result<Resp>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        let url = format!("{}{full_method}", self.base);
        let response = self
            .connect_json_request(&url, req)
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

    /// Builds one conforming Connect unary JSON request.
    fn connect_json_request<Req>(&self, url: &str, req: &Req) -> reqwest::RequestBuilder
    where
        Req: Serialize + ?Sized,
    {
        let mut request = self
            .http
            .post(url)
            .header(CONNECT_PROTOCOL_VERSION_HEADER, CONNECT_PROTOCOL_VERSION)
            .json(req);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
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
    use super::{CONNECT_PROTOCOL_VERSION_HEADER, HubClient, HubSurfaceRef, HubTopologyMethod};
    use aos_proto_types::surface_ref::Target;
    use aos_proto_types::{PlanCreatePlacementRequest, PlanUpdatePlacementRequest};
    use std::str::FromStr as _;

    #[test]
    fn requests_include_connect_protocol_and_json_headers() {
        let client = HubClient::connect_anonymous("https://hub.example").unwrap();
        let request = client
            .connect_json_request(
                "https://hub.example/aos.hub.v1.RegistryService/ListRegistries",
                &serde_json::json!({}),
            )
            .build()
            .unwrap();
        assert_eq!(request.headers()[CONNECT_PROTOCOL_VERSION_HEADER], "1");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/json"
        );
    }

    #[test]
    fn surface_ref_parser_preserves_kind_and_nested_slug() {
        assert_eq!(
            HubSurfaceRef::from_str("registry:andyl/infra/main").unwrap(),
            HubSurfaceRef::Registry("andyl/infra/main".to_string())
        );
        assert_eq!(
            HubSurfaceRef::from_str("cache:andyl/release-cache").unwrap(),
            HubSurfaceRef::Cache("andyl/release-cache".to_string())
        );
    }

    #[test]
    fn surface_ref_parser_rejects_ambiguous_or_empty_values() {
        for value in [
            "andyl/main",
            "registry:",
            "cache:",
            "cache:release-cache",
            "bucket:main",
        ] {
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
                HubSurfaceRef::Cache("andyl/release-cache".to_string()),
                "cacheSlug",
                "andyl/release-cache",
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
        let surface = Some(HubSurfaceRef::Cache("andyl/nix".to_string()).to_message());
        let create = serde_json::to_value(PlanCreatePlacementRequest {
            surface: surface.clone(),
            name: "replica".to_string(),
            storage_binding_id: "origin".to_string(),
            prefix: "cache/replica".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            desired_read_enabled: Some(true),
            read_order: Some(10),
            hash_range: None,
            requires_conditional_writes: false,
            idempotency_key: "create-1".into(),
            expected_resource_version: String::new(),
        })
        .unwrap();
        assert_eq!(create["surface"]["cacheSlug"], "andyl/nix");
        assert_eq!(create["storageBindingId"], "origin");
        assert_eq!(create["kind"], "complete");
        assert_eq!(create["desiredReadEnabled"], true);
        assert!(create.get("writeEnabled").is_none());
        assert!(create.get("writeOrder").is_none());
        assert!(create.get("storage_binding_id").is_none());
        assert!(create.get("state").is_none());
        assert!(create.get("completeness").is_none());

        let update = serde_json::to_value(PlanUpdatePlacementRequest {
            surface,
            name: "replica".to_string(),
            expected_resource_version: "7".to_string(),
            desired_state: "active".to_string(),
            desired_read_enabled: Some(true),
            read_order: Some(30),
            update_mask: vec!["desired_read_enabled".into(), "read_order".into()],
            idempotency_key: "update-1".into(),
        })
        .unwrap();
        assert_eq!(update["expectedResourceVersion"], "7");
        assert_eq!(update["desiredReadEnabled"], true);
        assert!(update.get("writeEnabled").is_none());
        assert!(update.get("state").is_none());
        assert!(update.get("completeness").is_none());
    }

    #[test]
    fn cache_and_operation_methods_use_only_the_cutover_package() {
        assert_eq!(
            HubTopologyMethod::PlanSetRetentionSubscription.path(),
            "aos.hub.v1.CacheIntegrationService/PlanSetRetentionSubscription"
        );
        assert_eq!(
            HubTopologyMethod::RunCacheGc.path(),
            "aos.hub.v1.BinaryCacheService/RunCacheGc"
        );
        assert_eq!(
            HubTopologyMethod::WatchOperation.path(),
            "aos.hub.v1.OperationService/WatchOperation"
        );
    }
}
