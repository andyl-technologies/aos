//! Shared Hub RPC orchestration and service composition.
//!
//! [`RpcService`] holds the `aos.hub.v1` method bodies once, decoupled
//! from either deployment runtime. Both deployment targets call it:
//!
//! - the **native hub** mounts it behind `axum` (served via `axum::serve`);
//! - the **Cloudflare Worker** mounts the *same* handlers via
//!   `axum-cloudflare-adapter`.
//!
//! Because the `connectrpc` server runtime cannot target `wasm32`, the hub does
//! not run it; instead these methods are served as **Connect-JSON** — plain
//! JSON over HTTP, `POST /aos.hub.v1.{Service}/{Method}` — by a thin `axum`
//! layer (see the Worker/native shells). RPC methods accept the caller's raw
//! `Authorization` header (so
//! the JWT is verified once, here, against [`JwtKeys`]) plus a request struct
//! from [`aos_hub_api`], and return a response struct or an [`RpcError`].
//! Capability methods live under `operations`; sealed plan inputs, failure
//! codes and reservation keys have separate modules. Streaming object methods
//! additionally use shared HTTP body types without owning an HTTP server.
//!
//! # Error model
//!
//! [`RpcError`] carries a Connect error code; the transport maps it to the
//! Connect-JSON envelope `{ "code": …, "message": … }` and the matching HTTP
//! status (see [`RpcError::code`] / [`RpcError::http_status`]).
//!
//! ```text
//! POST /aos.hub.v1.RegistryService/GetRegistry
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", "index_state": "fresh", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```

mod error;
mod plan_inputs;
mod reservation_keys;

pub use error::RpcError;
use plan_inputs::*;
pub use reservation_keys::{
    ConfiguredRouteReservationKeyring, RouteReservationKey, RouteReservationKeyring,
};

mod container;
mod container_admin;
mod delivery_workflow;
#[cfg(test)]
mod delivery_workflow_tests;
mod instance_settings;
mod oci_namespaces;
mod publication_manifest;
mod registry_delete;
mod registry_metadata;
mod registry_policy;
mod release_publication;
#[cfg(test)]
mod release_publication_tests;
mod staged_releases;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod staged_releases_tests;
mod surface_topology;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use anyhow::Context as _;
use aos_hub_api as pb;
use aos_registry_format::manifest::{ImageCompression, ImageTarget};
use aos_registry_format::object::Oid;
use base64::Engine as _;
use futures_util::{StreamExt as _, TryStreamExt as _};
use sha2::{Digest as _, Sha256};

use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::jobs::Job;
use crate::lease::PublishLease;
use crate::placement_read::{self, PlacementReadOutcome};
use crate::ratelimit::{RateClass, RateDecision, RateLimiter, MAX_ORGS_PER_OWNER};
use crate::reindex::Reindexer;
use crate::storage_credential::{DatabaseStorageCredentialResolver, StorageCredentialResolver};
use crate::surface_write::{PartTag, SurfaceWrite, SurfaceWriteProvider};
use crate::topology_probe::TopologyProbeScheduler;
use aos_hub_db::db::{
    Database, IndexStatus, PlacementReadRequirement, RegistryRecord, SurfaceTarget,
};
use aos_hub_model::auth::jwt::{Claims, JwtKeys};
use aos_hub_model::clock;
use aos_hub_model::domain::iam::{self, claims_principal, token_allows};
use aos_hub_model::domain::{Permission, Principal, PrincipalKind, Role, Scope};
use aos_hub_model::keymap;

/// Default page size when a list request leaves `page_size` at zero.
const DEFAULT_PAGE_SIZE: u32 = 500;
/// Maximum bounded documentation projection considered by one search request.
const MAX_DOCUMENTATION_RESULTS: usize = 10_000;
/// Hard ceiling on page size.
const MAX_PAGE_SIZE: u32 = 1000;
/// Maximum accepted reporter clock lead over Hub receipt time.
const ABILITY_DEPLOYMENT_MAX_FUTURE_SKEW_SECS: i64 = 30;

/// Default lifetime of an internal cache-upload authorization (1 hour).
pub const INTERNAL_UPLOAD_AUTH_TTL_SECS: i64 = 3600;
/// Exclusive provider-creation lease for one cache multipart upload.
const CACHE_MULTIPART_CREATE_LEASE_SECS: i64 = 60;
const CACHE_MULTIPART_CREATE_TIMEOUT_SECS: u64 = 45;

/// Lifetime of an immutable topology impact plan (15 minutes).
const TOPOLOGY_PLAN_TTL_SECS: i64 = 15 * 60;
const ACCESS_TOKEN_DEFAULT_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const ACCESS_TOKEN_MAX_TTL_SECS: i64 = 90 * 24 * 60 * 60;
const INVITATION_DEFAULT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const INVITATION_MAX_TTL_SECS: i64 = 30 * 24 * 60 * 60;
/// Organization offboarding grace before separately scheduled hard purge.
const ORGANIZATION_DELETE_GRACE_SECS: i64 = 30 * 24 * 60 * 60;

/// Maximum stored controller diagnostic size.
const RECONCILIATION_ERROR_MAX_BYTES: usize = 4 * 1024;

/// Settles a cache ticket after a write-flow failure.
async fn settle_cache_write_failure(
    db: &Database,
    ticket_id: &str,
    resource_version: i64,
    backend_mutation_attempted: bool,
    now: i64,
) {
    if backend_mutation_attempted {
        // Backend errors are not proof of nonapplication: an atomic PUT may
        // have committed before its response was lost. Convert the ticket to
        // an inventory-uncovered terminal delta immediately so expiry recovery
        // can never release quota or a GC fence from later negative evidence.
        let _ = db
            .mark_cache_write_ticket_uncertain(ticket_id, resource_version, now)
            .await;
    } else {
        let _ = db
            .abort_cache_write_ticket(ticket_id, resource_version, "failed", now)
            .await;
    }
}

/// Collects reviewed concurrency inputs from a serialized plan payload.
fn collect_plan_input_versions(value: &serde_json::Value, path: &str, versions: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                let concurrency_field = name.contains("resource_version")
                    || name.ends_with("_revision")
                    || name.ends_with("_generation")
                    || name == "incarnation_id";
                if concurrency_field && !value.is_null() {
                    match value {
                        serde_json::Value::String(text) if !text.is_empty() => {
                            versions.push(format!("{child}={text}"));
                        }
                        serde_json::Value::Number(number) => {
                            versions.push(format!("{child}={number}"));
                        }
                        _ => collect_plan_input_versions(value, &child, versions),
                    }
                } else {
                    collect_plan_input_versions(value, &child, versions);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_plan_input_versions(item, &format!("{path}[{index}]"), versions);
            }
        }
        _ => {}
    }
}

/// Collects exact, typed pin impacts from plan-sealed resolution records.
fn collect_plan_pin_impacts(
    value: &serde_json::Value,
    impacts: &mut BTreeMap<String, pb::TopologyPinImpact>,
) {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.contains_key("action_kind") {
                if let Some(source) = fields.get("source").and_then(serde_json::Value::as_object) {
                    let text = |name: &str| {
                        source
                            .get(name)
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .to_string()
                    };
                    let number = |name: &str| {
                        source
                            .get(name)
                            .and_then(serde_json::Value::as_i64)
                            .unwrap_or_default()
                    };
                    let pin_id = text("pin_id");
                    let target_kind = text("target_kind");
                    if !pin_id.is_empty() && !target_kind.is_empty() {
                        let source_version = fields
                            .get("source_resource_version")
                            .and_then(serde_json::Value::as_i64)
                            .or_else(|| {
                                source
                                    .get("target_resource_version")
                                    .and_then(serde_json::Value::as_i64)
                            })
                            .unwrap_or_default();
                        let allowed_actions = match target_kind.as_str() {
                            "endpoint" | "listener" => vec![
                                pb::PinResolutionAction::MoveEndpoint as i32,
                                pb::PinResolutionAction::Release as i32,
                            ],
                            "route" => vec![
                                pb::PinResolutionAction::ReplaceRoute as i32,
                                pb::PinResolutionAction::Release as i32,
                            ],
                            "placement" => vec![pb::PinResolutionAction::Release as i32],
                            _ => {
                                for child in fields.values() {
                                    collect_plan_pin_impacts(child, impacts);
                                }
                                return;
                            }
                        };
                        impacts.insert(
                            pin_id.clone(),
                            pb::TopologyPinImpact {
                                pin_id,
                                target_kind,
                                target_stable_id: text("target_stable_id"),
                                target_generation: number("target_generation_key"),
                                configuration_digest: text("target_configuration_digest"),
                                expected_source_resource_version: source_version.to_string(),
                                allowed_actions,
                            },
                        );
                    }
                }
            }
            for child in fields.values() {
                collect_plan_pin_impacts(child, impacts);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_plan_pin_impacts(item, impacts);
            }
        }
        _ => {}
    }
}

/// Projects authenticated native locator coordinates into the release identity envelope.
fn native_documentation_identity(
    locator: &aos_hub_db::db::NativeDocumentationLocator,
) -> pb::PackageDocumentationIdentity {
    pb::PackageDocumentationIdentity {
        registry_commit: locator.commit.clone(),
        package: locator.package.clone(),
        version: locator.version.clone(),
        platform: locator.platform.clone(),
        format: aos_module_docs::runtime::MODULE_DOCUMENTATION_SCHEMA.into(),
        store_path: locator.artifact.store_path.clone(),
        nar_hash: locator.artifact.nar_hash.clone(),
        nar_size: locator.artifact.nar_size,
        document_sha256: locator.artifact.document_sha256.clone(),
        document_size: locator.artifact.document_size,
        release: locator.release.clone(),
        verified_tag_oid: locator.tag_oid.clone(),
        release_snapshot_id: locator.snapshot_id.clone(),
    }
}

fn package_ability_reference_identity(
    locator: &aos_hub_db::db::NativeDocumentationLocator,
) -> pb::PackageAbilityReferenceIdentity {
    pb::PackageAbilityReferenceIdentity {
        registry_commit: locator.commit.clone(),
        package: locator.package.clone(),
        version: locator.version.clone(),
        platform: locator.platform.clone(),
        document_sha256: locator.artifact.document_sha256.clone(),
        release: locator.release.clone(),
        verified_tag_oid: locator.tag_oid.clone(),
        release_snapshot_id: locator.snapshot_id.clone(),
    }
}

fn stored_ability_deployment_response(
    stored: aos_hub_db::db::StoredAbilityDeploymentOverlay,
) -> pb::PackageAbilityDeploymentResponse {
    pb::PackageAbilityDeploymentResponse {
        canonical_json: stored.canonical_json,
        authority: format!(
            "reporter-bearer:{}:{}",
            stored.principal_kind, stored.principal_ref
        ),
        received_at: stored.received_at,
        expires_at: stored.expires_at,
        reporter_resource_version: stored.reporter_resource_version,
    }
}

fn decode_stored_package_ability_deployment(
    stored: &aos_hub_db::db::StoredAbilityDeploymentOverlay,
    reference: &aos_module_docs::runtime::deployment::ReleasedReference,
) -> anyhow::Result<aos_module_docs::runtime::deployment::NativeDeploymentReport> {
    let report = aos_module_docs::runtime::deployment::NativeDeploymentReport::decode(
        &stored.canonical_json,
    )?;
    anyhow::ensure!(
        report.deployment == stored.deployment && report.sequence == stored.sequence,
        "stored native report identity differs"
    );
    let validity = i64::try_from(report.valid_for_seconds)?;
    let reported_at = i64::try_from(report.reported_at_unix_seconds)?;
    anyhow::ensure!(
        stored.expires_at
            == stored
                .received_at
                .saturating_add(validity)
                .min(reported_at.saturating_add(validity))
            && reported_at
                <= stored
                    .received_at
                    .saturating_add(ABILITY_DEPLOYMENT_MAX_FUTURE_SKEW_SECS),
        "stored native report freshness differs from its assertion and receipt"
    );
    report.validate_reference(reference)?;
    Ok(report)
}

fn native_option_view(
    identity: &pb::PackageDocumentationIdentity,
    option: &aos_module_docs::runtime::NativeOption,
) -> anyhow::Result<pb::PackageOptionView> {
    Ok(pb::PackageOptionView {
        identity: Some(identity.clone()),
        path: option
            .path
            .iter()
            .map(|value| pb::DocumentationPathSegment {
                segment: Some(pb::documentation_path_segment::Segment::Literal(
                    value.clone(),
                )),
            })
            .collect(),
        display_path: option.path.join("."),
        r#type: aos_module_docs::runtime::type_signature(&option.option_type)?,
        owner_package: option.owner.clone(),
        owner_root: String::new(),
        extensible: option.extensible,
        canonical_option_json: serde_json::to_vec(option)?,
    })
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Slice one page out of `items` using an opaque versioned offset token.
///
/// Returns the page plus the `next_page_token` (empty once exhausted). The
/// The offset is wrapped in a versioned payload and base64url-encoded. Callers
/// must treat it as opaque; malformed or unknown-version tokens are rejected.
///
/// # Errors
///
/// Returns [`RpcError::InvalidArgument`] when `token` is non-empty and does not
/// parse as an offset.
fn paginate<T>(items: Vec<T>, page_size: u32, token: &str) -> Result<(Vec<T>, String), RpcError> {
    let offset: usize = if token.is_empty() {
        0
    } else {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| RpcError::invalid("invalid page_token"))?;
        let payload =
            std::str::from_utf8(&decoded).map_err(|_| RpcError::invalid("invalid page_token"))?;
        payload
            .strip_prefix("v1:")
            .ok_or_else(|| RpcError::invalid("invalid page_token"))?
            .parse()
            .map_err(|_| RpcError::invalid("invalid page_token"))?
    };
    let size = match page_size {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    } as usize;
    let end = offset.saturating_add(size).min(items.len());
    let next = if end < items.len() {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("v1:{end}"))
    } else {
        String::new()
    };
    let page = items
        .into_iter()
        .skip(offset)
        .take(end.saturating_sub(offset))
        .collect();
    Ok((page, next))
}

/// Project a [`ChannelSummary`](aos_hub_db::db::ChannelSummary) onto the wire
/// [`pb::Channel`], dropping empty partition buckets and tagging each present
/// bucket with its index.
fn channel_message(channel: aos_hub_db::db::ChannelSummary) -> pb::Channel {
    pb::Channel {
        name: channel.name,
        frontier: channel.frontier.unwrap_or_default(),
        partitions: channel
            .partitions
            .iter()
            .enumerate()
            .filter_map(|(bucket, release)| {
                release.as_ref().map(|release| pb::Partition {
                    bucket: bucket as u32,
                    release: release.clone(),
                })
            })
            .collect(),
    }
}

fn image_target_name(target: ImageTarget) -> &'static str {
    match target {
        ImageTarget::BareMetal => "bare-metal",
        ImageTarget::QemuKvm => "qemu-kvm",
        ImageTarget::Openstack => "openstack",
        ImageTarget::Vmware => "vmware",
        ImageTarget::HyperV => "hyper-v",
    }
}

fn parse_image_target(value: &str) -> Result<Option<ImageTarget>, RpcError> {
    match value {
        "" => Ok(None),
        "bare-metal" => Ok(Some(ImageTarget::BareMetal)),
        "qemu-kvm" => Ok(Some(ImageTarget::QemuKvm)),
        "openstack" => Ok(Some(ImageTarget::Openstack)),
        "vmware" => Ok(Some(ImageTarget::Vmware)),
        "hyper-v" => Ok(Some(ImageTarget::HyperV)),
        _ => Err(RpcError::invalid("unknown image target")),
    }
}

fn image_compression_name(compression: ImageCompression) -> &'static str {
    match compression {
        ImageCompression::None => "none",
        ImageCompression::Zstd => "zstd",
    }
}

fn canonical_git_object_id(
    value: &str,
) -> anyhow::Result<aos_hub_model::retention::CanonicalGitObjectId> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("verified tag object id must be 40 or 64 lowercase hexadecimal characters");
    }
    let digest = hex::decode(value)?;
    let algorithm = match digest.len() {
        20 => aos_hub_model::retention::GitObjectIdAlgorithm::Sha1,
        32 => aos_hub_model::retention::GitObjectIdAlgorithm::Sha256,
        length => anyhow::bail!("verified tag object id has invalid {length}-byte length"),
    };
    Ok(aos_hub_model::retention::CanonicalGitObjectId::new(
        algorithm, digest,
    )?)
}

fn add_release_retention_reasons(
    reasons: &mut BTreeMap<String, aos_hub_db::db::RetentionRefreshReason>,
    selector_term: &str,
    release: &aos_hub_db::db::RetentionReleaseSnapshotRecord,
) {
    for artifact in &release.artifacts {
        insert_retention_reason(
            reasons,
            "release",
            format!(
                "{selector_term}:{}@{}:{}/{}/{}/{}",
                release.tag,
                release.snapshot_id,
                artifact.package_name,
                artifact.package_version,
                artifact.platform,
                artifact.artifact_kind
            ),
            artifact.store_hash.clone(),
            Some(release.release_id),
            Some(release.snapshot_id.clone()),
            None,
            None,
        );
    }
}

fn insert_retention_reason(
    reasons: &mut BTreeMap<String, aos_hub_db::db::RetentionRefreshReason>,
    source_kind: &str,
    source_ref: String,
    store_hash: String,
    release_id: Option<i64>,
    release_snapshot_id: Option<String>,
    channel_id: Option<i64>,
    partition_bucket: Option<i64>,
) {
    let digest = hex::encode(Sha256::digest(
        format!("{source_kind}\0{source_ref}\0{store_hash}").as_bytes(),
    ));
    let reason_key = format!("{source_kind}:{digest}");
    reasons
        .entry(reason_key.clone())
        .or_insert_with(|| aos_hub_db::db::RetentionRefreshReason {
            reason_id: digest.clone(),
            reason_key,
            store_hash,
            source_kind: source_kind.to_string(),
            source_ref: bounded_retention_source_ref(&source_ref, &digest),
            release_id,
            release_snapshot_id,
            channel_id,
            partition_bucket,
            expires_at: None,
            refreshed_at: 0,
        });
}

fn retention_refresh_reason_id(refresh_id: &str, reason_key: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{refresh_id}\0{reason_key}").as_bytes(),
    ))
}

fn bounded_retention_source_ref(value: &str, digest: &str) -> String {
    if value.len() <= 255 {
        return value.to_string();
    }
    let suffix = format!("...#{digest}");
    let byte_budget = 255usize.saturating_sub(suffix.len());
    let mut prefix = String::new();
    for character in value.chars() {
        if prefix.len() + character.len_utf8() > byte_budget {
            break;
        }
        prefix.push(character);
    }
    prefix.push_str(&suffix);
    prefix
}

use aos_hub_model::cache::parse_cache_narinfo;

/// Render a `nix-cache-info` body for a managed cache.
///
/// The three-line file a Nix substituter reads to learn the store directory,
/// whether it answers mass `?path-info` queries, and its substituter priority.
fn render_nix_cache_info(want_mass_query: bool, priority: i64) -> String {
    format!(
        "StoreDir: /nix/store\nWantMassQuery: {}\nPriority: {}\n",
        u8::from(want_mass_query),
        priority,
    )
}

/// Parse a `Range: bytes=START-END` header into an inclusive `(start, end)`.
///
/// Only a single `bytes=` range is supported (the substituter case). An
/// open-ended `bytes=START-` yields `(start, u64::MAX)`, which the streaming
/// fetcher clamps to the object's last byte. Returns `None` for an absent,
/// malformed, multi-range, or suffix (`bytes=-N`) header — the caller then
/// serves the whole object.
fn parse_byte_range(header: Option<&str>) -> Option<(u64, u64)> {
    let spec = header?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = end.trim();
    let end: u64 = if end.is_empty() {
        u64::MAX
    } else {
        end.parse().ok()?
    };
    (start <= end).then_some((start, end))
}

/// Wraps one placement body with an exact signed byte-count contract.
pub(crate) fn exact_image_body(body: axum::body::Body, remaining: u64) -> axum::body::Body {
    use futures_util::StreamExt as _;

    axum::body::Body::from_stream(futures_util::stream::unfold(
        (body.into_data_stream(), remaining, false),
        |(mut stream, remaining, failed)| async move {
            if failed {
                return None;
            }
            match stream.next().await {
                Some(Ok(chunk)) => {
                    let Ok(len) = u64::try_from(chunk.len()) else {
                        return Some((
                            Err(std::io::Error::other("image response chunk is too large")),
                            (stream, remaining, true),
                        ));
                    };
                    if len > remaining {
                        return Some((
                            Err(std::io::Error::other(
                                "stored image body exceeded signed response length",
                            )),
                            (stream, remaining, true),
                        ));
                    }
                    Some((Ok(chunk), (stream, remaining - len, false)))
                }
                Some(Err(error)) => {
                    Some((Err(std::io::Error::other(error)), (stream, remaining, true)))
                }
                None if remaining > 0 => Some((
                    Err(std::io::Error::other(
                        "stored image body ended before signed response length",
                    )),
                    (stream, remaining, true),
                )),
                None => None,
            }
        },
    ))
}

/// Projects a normalized logical cache object onto the wire contract.
fn cache_object_message(o: aos_hub_db::db::CacheObjectRecord) -> pb::CacheObject {
    pb::CacheObject {
        store_hash: o.store_hash,
        store_name: o.store_name,
        nar_url: o.nar_url,
        nar_hash: o.nar_hash,
        nar_size: u64::try_from(o.nar_size).unwrap_or_default(),
        file_hash: o.file_hash,
        file_size: u64::try_from(o.file_size).unwrap_or_default(),
        compression: o.compression,
        deriver: o.deriver.unwrap_or_default(),
        refs: o.references,
        signature: o.signature.unwrap_or_default(),
        content_address: o.content_address.unwrap_or_default(),
        uploaded_at: o.published_at,
    }
}

/// Projects an organization without exposing its database identity.
fn organization_message(org: &aos_hub_db::db::OrgRecord) -> pb::Organization {
    pb::Organization {
        stable_id: org.stable_id.clone(),
        slug: org.slug.clone(),
        display_name: org.name.clone(),
        owner_scope_key: org.stable_id.clone(),
        resource_version: org.resource_version.to_string(),
        created_at: org.created_at,
        updated_at: org.updated_at,
        authorization_scope_key: org.stable_id.clone(),
    }
}

fn delivery_dns_spec(
    configuration: pb::DnsConfiguration,
) -> Result<aos_hub_db::db::DeliveryDnsConfigurationSpec, RpcError> {
    match configuration.configuration {
        Some(pb::dns_configuration::Configuration::HubManaged(value)) => {
            Ok(aos_hub_db::db::DeliveryDnsConfigurationSpec::HubManaged {
                provider: value.provider,
                zone_id: value.zone_id,
                record_mode: value.record_mode,
                target: value.target,
                ttl_seconds: value.ttl_seconds,
            })
        }
        Some(pb::dns_configuration::Configuration::External(value)) => {
            Ok(aos_hub_db::db::DeliveryDnsConfigurationSpec::External {
                expected_target: value.expected_target,
            })
        }
        None => Err(RpcError::invalid("DNS configuration is required")),
    }
}

fn delivery_certificate_spec(
    configuration: pb::CertificateConfiguration,
) -> Result<aos_hub_db::db::DeliveryCertificateConfigurationSpec, RpcError> {
    match configuration.configuration {
        Some(pb::certificate_configuration::Configuration::HubManaged(value)) => Ok(
            aos_hub_db::db::DeliveryCertificateConfigurationSpec::HubManaged {
                issuer: value.issuer,
                dns_challenge_provider: value.dns_challenge_provider,
            },
        ),
        Some(pb::certificate_configuration::Configuration::External(value)) => Ok(
            aos_hub_db::db::DeliveryCertificateConfigurationSpec::External {
                certificate_secret_ref: value.certificate_secret_ref,
            },
        ),
        None => Err(RpcError::invalid("certificate configuration is required")),
    }
}

fn delivery_dns_message(
    value: aos_hub_db::db::DeliveryDnsConfigurationSpec,
) -> pb::DnsConfiguration {
    let configuration = match value {
        aos_hub_db::db::DeliveryDnsConfigurationSpec::HubManaged {
            provider,
            zone_id,
            record_mode,
            target,
            ttl_seconds,
        } => pb::dns_configuration::Configuration::HubManaged(pb::HubManagedDnsConfiguration {
            provider,
            zone_id,
            record_mode,
            target,
            ttl_seconds,
        }),
        aos_hub_db::db::DeliveryDnsConfigurationSpec::External { expected_target } => {
            pb::dns_configuration::Configuration::External(pb::ExternalDnsConfiguration {
                expected_target,
            })
        }
    };
    pb::DnsConfiguration {
        configuration: Some(configuration),
    }
}

fn delivery_certificate_message(
    value: aos_hub_db::db::DeliveryCertificateConfigurationSpec,
) -> pb::CertificateConfiguration {
    let configuration = match value {
        aos_hub_db::db::DeliveryCertificateConfigurationSpec::HubManaged {
            issuer,
            dns_challenge_provider,
        } => pb::certificate_configuration::Configuration::HubManaged(
            pb::HubManagedCertificateConfiguration {
                issuer,
                dns_challenge_provider,
            },
        ),
        aos_hub_db::db::DeliveryCertificateConfigurationSpec::External {
            certificate_secret_ref,
        } => pb::certificate_configuration::Configuration::External(
            pb::ExternalCertificateConfiguration {
                certificate_secret_ref,
            },
        ),
    };
    pb::CertificateConfiguration {
        configuration: Some(configuration),
    }
}

/// Build the wire [`pb::Project`] for a project at `path`/`name` under `org_slug`.
fn project_message(org_slug: String, project: aos_hub_db::db::ProjectRecord) -> pb::Project {
    pb::Project {
        org_slug,
        path: project.path,
        name: project.name,
        stable_id: project.stable_id,
        authorization_scope_key: project.scope_key,
        resource_version: project.resource_version.to_string(),
        created_at: project.created_at,
        updated_at: project.updated_at,
    }
}

/// The canonical instance-settings keys editable over the API/CLI.
///
/// This is the wire/CLI surface — the same keys the `/-/instance` console
/// writes. Storage topology is configured through bindings and
/// placements, not instance key/value settings.
const INSTANCE_KEYS: &[&str] = &[
    "site_title",
    "tagline",
    "announcement",
    "tos_url",
    "privacy_url",
    "support_url",
    "signup_policy",
    "signup_domains",
    "password_login",
    "caches_public",
    "session_lifetime_secs",
    "default_crawl_policy",
    "max_upload_bytes",
];

/// Whether `key` is a recognized instance-settings key.
fn is_instance_key(key: &str) -> bool {
    INSTANCE_KEYS.contains(&key)
}

/// Validate and normalize an instance-settings value for `key`, returning the
/// stored form (or `None` to clear the key when the value is blank).
///
/// Free-text keys pass through trimmed; the enum and numeric keys are checked so
/// an invalid value is rejected before any write.
///
/// # Errors
///
/// Returns [`RpcError::InvalidArgument`] for an unknown key or a value that does
/// not satisfy that key's constraint.
fn normalize_instance_value(key: &str, value: &str) -> Result<Option<String>, RpcError> {
    if !is_instance_key(key) {
        return Err(RpcError::invalid(format!(
            "unknown instance setting: {key}"
        )));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match key {
        "signup_policy" => {
            // Round-trip through the parser so only the two canonical strings
            // store; anything else is a client error rather than a silent
            // fail-closed to invite_only.
            if trimmed != "open" && trimmed != "invite_only" {
                return Err(RpcError::invalid(
                    "signup_policy must be 'open' or 'invite_only'",
                ));
            }
            Ok(Some(trimmed.to_string()))
        }
        "default_crawl_policy" => {
            let policy = aos_hub_model::crawl::CrawlPolicy::parse(trimmed)
                .map_err(|e| RpcError::invalid(e.to_string()))?;
            Ok(Some(policy.as_str().to_string()))
        }
        "password_login" | "caches_public" => {
            let on = match trimmed {
                "on" | "true" | "1" | "yes" => true,
                "off" | "false" | "0" | "no" => false,
                _ => {
                    return Err(RpcError::invalid(format!(
                        "{key} must be one of on, off, true, false, 1, 0, yes, or no"
                    )));
                }
            };
            Ok(Some(if on { "on" } else { "off" }.to_string()))
        }
        "tos_url" | "privacy_url" | "support_url" => {
            aos_hub_model::url_guard::require_http_scheme(trimmed)
                .map_err(|_| RpcError::invalid(format!("{key} must be an http(s) URL")))?;
            Ok(Some(trimmed.to_string()))
        }
        "signup_domains" => {
            // Normalize to a lowercased, comma-joined allowlist.
            let domains: Vec<String> = trimmed
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
                .collect();
            if domains.is_empty() {
                Ok(None)
            } else {
                Ok(Some(domains.join(",")))
            }
        }
        "session_lifetime_secs" | "max_upload_bytes" => {
            let n: i64 = trimmed
                .parse()
                .map_err(|_| RpcError::invalid(format!("{key} must be a non-negative integer")))?;
            if n < 0 {
                return Err(RpcError::invalid(format!("{key} must be non-negative")));
            }
            Ok(Some(n.to_string()))
        }
        _ => Ok(Some(trimmed.to_string())),
    }
}

/// Build the wire [`pb::InstanceSettings`] from the loaded settings bundle.
///
/// Unset optionals (`session_lifetime_secs`/`max_upload_bytes`) map to `0`,
/// which the wire contract documents as "use the built-in default".
fn instance_settings_to_pb(s: &aos_hub_db::db::InstanceSettings) -> pb::InstanceSettings {
    pb::InstanceSettings {
        site_title: s.site_title.clone().unwrap_or_default(),
        tagline: s.tagline.clone().unwrap_or_default(),
        announcement: s.announcement.clone().unwrap_or_default(),
        tos_url: s.tos_url.clone().unwrap_or_default(),
        privacy_url: s.privacy_url.clone().unwrap_or_default(),
        support_url: s.support_url.clone().unwrap_or_default(),
        signup_policy: s.signup_policy.as_str().to_string(),
        signup_domains: s.signup_domains.clone(),
        password_login: s.password_login,
        session_lifetime_secs: s.session_lifetime_secs.unwrap_or(0),
        default_crawl_policy: s.default_crawl_policy.clone(),
        max_upload_bytes: s.max_upload_bytes.unwrap_or(0),
        caches_public: s.caches_public,
    }
}

/// Returns the canonical content revision for one effective settings bundle.
fn instance_settings_digest(s: &aos_hub_db::db::InstanceSettings) -> Result<String, RpcError> {
    let message = instance_settings_to_pb(s);
    let canonical = serde_json::to_vec(&message).map_err(RpcError::internal)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn service_account_resource_version(
    record: &aos_hub_db::db::ServiceAccountRecord,
) -> Result<String, RpcError> {
    let canonical =
        serde_json::to_vec(&(record.id, record.org_id, &record.name, record.created_at))
            .map_err(RpcError::internal)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn service_account_message(
    org_slug: &str,
    record: aos_hub_db::db::ServiceAccountRecord,
) -> Result<pb::ServiceAccount, RpcError> {
    let resource_version = service_account_resource_version(&record)?;
    Ok(pb::ServiceAccount {
        id: record.id,
        org_slug: org_slug.to_string(),
        name: record.name,
        created_at: record.created_at,
        resource_version,
    })
}

fn invitation_resource_version(
    record: &aos_hub_db::db::InvitationRecord,
) -> Result<String, RpcError> {
    let canonical = serde_json::to_vec(&(
        record.id,
        record.org_id,
        &record.email,
        &record.scope,
        &record.role,
        record.created_at,
        record.accepted_at,
        record.cancelled_at,
        record.expires_at,
    ))
    .map_err(RpcError::internal)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn invitation_message(
    org_slug: &str,
    record: aos_hub_db::db::InvitationRecord,
) -> Result<pb::Invitation, RpcError> {
    let resource_version = invitation_resource_version(&record)?;
    let state = if record.accepted_at.is_some() {
        "accepted"
    } else if record.cancelled_at.is_some() {
        "cancelled"
    } else if record.expires_at <= clock::now_unix_secs() {
        "expired"
    } else {
        "pending"
    };
    Ok(pb::Invitation {
        invitation_id: record.id,
        org_slug: org_slug.to_string(),
        email: record.email,
        scope: record.scope,
        role: record.role,
        state: state.to_string(),
        created_at: record.created_at,
        accepted_at: record.accepted_at.unwrap_or_default(),
        cancelled_at: record.cancelled_at.unwrap_or_default(),
        expires_at: record.expires_at,
        resource_version,
    })
}

fn identity_provider_message(
    org_slug: &str,
    record: aos_hub_db::db::IdpConfigRecord,
) -> pb::IdentityProvider {
    pb::IdentityProvider {
        org_slug: org_slug.to_string(),
        issuer: record.issuer,
        authorization_endpoint: record.authorization_endpoint,
        token_endpoint: record.token_endpoint,
        jwks_uri: record.jwks_uri,
        client_id: record.client_id,
        client_secret_configured: record.client_secret_enc.is_some(),
        scopes: record.scopes,
        groups_claim: record.groups_claim.unwrap_or_default(),
        role_map_json: record.role_map_json,
        allow_jit: record.allow_jit,
        enforce_sso: record.enforce_sso,
        default_role: record.default_role,
        resource_version: identity_resource_version(
            record.resource_version,
            record.incarnation_id.as_deref(),
        ),
    }
}

fn organization_domain_message(
    org_slug: &str,
    record: aos_hub_db::db::OrgDomainRecord,
) -> pb::OrganizationDomain {
    pb::OrganizationDomain {
        org_slug: org_slug.to_string(),
        domain: record.domain,
        state: if record.verified_at.is_some() {
            "verified".to_string()
        } else {
            "pending".to_string()
        },
        txt_challenge: record.txt_challenge,
        verified_at: record.verified_at.unwrap_or_default(),
        resource_version: identity_resource_version(
            record.resource_version,
            record.incarnation_id.as_deref(),
        ),
    }
}

fn normalize_invitation_email(value: &str) -> Result<String, RpcError> {
    let email = value.trim().to_ascii_lowercase();
    if email.len() > 254 {
        return Err(RpcError::invalid("email address is too long"));
    }
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    let valid_local = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte)
        });
    let valid_domain = matches!(url::Host::parse(domain), Ok(url::Host::Domain(parsed)) if parsed == domain)
        && domain.contains('.')
        && !domain.ends_with('.');
    if parts.next().is_some() || !valid_local || !valid_domain {
        return Err(RpcError::invalid(
            "email must use canonical lowercase dot-atom syntax and an ASCII DNS domain",
        ));
    }
    Ok(email)
}

fn normalize_service_account_name(value: &str) -> Result<String, RpcError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RpcError::invalid(
            "service-account name must contain 1..=64 letters, digits, '-', '_', or '.'",
        ));
    }
    Ok(value.to_string())
}

/// Build the wire [`pb::Webhook`] for a webhook subscription under `org_slug`.
fn webhook_message(
    id: i64,
    org_slug: String,
    url: String,
    events: Vec<String>,
    active: bool,
    created_at: i64,
    resource_version: i64,
    updated_at: i64,
    secret_version_ref: String,
    credential_fingerprint: String,
) -> pb::Webhook {
    pb::Webhook {
        id,
        org_slug,
        url,
        events,
        active,
        created_at,
        resource_version: resource_version.to_string(),
        updated_at,
        secret_version_ref,
        credential_fingerprint,
    }
}

/// Project a [`ChangesetRow`](aos_hub_db::db::ChangesetRow) onto the wire
/// [`pb::Changeset`], flattening its optional summary/applied/revert fields.
fn changeset_message(row: aos_hub_db::db::ChangesetRow) -> pb::Changeset {
    pb::Changeset {
        change_id: row.change_id,
        actor_label: row.actor_label,
        scope: row.scope,
        status: row.status,
        summary: row.summary.unwrap_or_default(),
        created_at: row.created_at,
        applied_at: row.applied_at.unwrap_or_default(),
        reverted_by_change_id: row.reverted_by_change_id.unwrap_or_default(),
    }
}

/// A buffered compatibility payload for an internal machine-surface lookup.
///
/// [`RpcService::surface_fetch`] remains for bounded internal browse lookups and
/// nested-resolution compatibility. Public registry/cache machine routes use
/// [`RpcService::registry_serve`] / [`RpcService::cache_serve`] so large objects
/// stream. The fixed header values still come from runtime-neutral [`keymap`].
#[derive(Debug)]
pub struct SurfaceObjectResponse {
    /// The object's bytes, read from the registry's surface store. Empty when
    /// [`redirect`](Self::redirect) is set.
    pub bytes: Vec<u8>,
    /// The `Content-Type` header value for the requested machine path.
    pub content_type: &'static str,
    /// The `Cache-Control` header value for the requested machine path.
    pub cache_control: &'static str,
    /// When `Some`, the object is not served inline but as a temporary (`302`)
    /// redirect to this presigned origin URL — the authenticated-origin read of
    /// a private external binding (RFC-0004 "presigned GET → 302"). `302`
    /// (temporary), never a cacheable permanent redirect, since the URL expires.
    pub redirect: Option<String>,
}

/// Result of the placement-aware registry streaming path.
pub enum RegistryServeOutcome {
    /// A streamed response was opened from the selected backend.
    Response(axum::response::Response),
    /// Topology was configured, but the path was not servable.
    NotFound,
}

/// Authorization evidence accepted by the shared machine-surface streamers.
///
/// Worker and other transport-neutral callers pass their raw authorization
/// header so [`RpcService`] remains the authorization boundary. The native
/// transport may instead pass [`PreauthorizedSession`](Self::PreauthorizedSession)
/// only after its session-aware registry/cache gate has validated the cookie
/// against the requested surface. The service still checks resource liveness
/// for both variants, so org suspension and cache deletion take effect between
/// the transport gate and placement selection.
#[derive(Clone, Copy, Debug)]
pub enum ReadAuthorization<'a> {
    /// A raw `Authorization` header, or `None` for an anonymous request.
    AuthorizationHeader(Option<&'a str>),
    /// A raw Hub browser-session cookie secret resolved at the shared service
    /// boundary. This is used by both native and Worker machine routes.
    SessionCookie(&'a str),
    /// A native browser session already authorized for this exact surface.
    PreauthorizedSession,
}

/// Maximum body accepted by one buffered object or multipart-part request.
///
/// Single-object PUTs, multipart parts, and multipart completion documents use
/// this identical limit through native flat/nested routes and Worker
/// flat/nested routes. Larger objects use multipart or direct-origin upload.
pub const MAX_UPLOAD_BYTES: usize = 20 * 1024 * 1024;

/// Maximum number of objects admitted by one registry publication manifest.
pub const MAX_REGISTRY_PUBLICATION_OBJECTS: usize = 50_000;

/// Maximum narinfos accepted by one cache-upload completion request.
pub const MAX_CACHE_NARINFO_REGISTRATION_BATCH: usize = 256;
/// Maximum independent narinfo registrations in flight within one bulk RPC.
const CACHE_NARINFO_REGISTRATION_CONCURRENCY: usize = 8;
/// Maximum object-upload admissions accepted by one bulk cache request.
pub const MAX_CACHE_UPLOAD_ADMISSION_BATCH: usize =
    aos_hub_db::db::MAX_CACHE_WRITE_TICKET_ADMISSION_BATCH;

/// Maximum encoded length of one registry publication object key.
pub const MAX_REGISTRY_PUBLICATION_PATH_BYTES: usize = 512;

/// Maximum number of components in one registry publication object key.
pub const MAX_REGISTRY_PUBLICATION_PATH_COMPONENTS: usize = 33;

/// Bounded part size used by typed registry publication uploads.
///
/// Eight MiB exceeds the five-MiB minimum imposed by S3-compatible stores and
/// remains below the request-memory ceilings of both supported Hub runtimes.
const REGISTRY_PUBLICATION_PART_BYTES: usize = 8 * 1024 * 1024;

fn complete_upload_bytes(configured_limit: usize) -> usize {
    configured_limit.min(crate::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES)
}

struct RegistryPublicationUploadPlacement {
    placement: aos_hub_db::db::SurfacePlacementRecord,
    writer: Box<dyn SurfaceWrite>,
}

const REGISTRY_PUBLICATION_UPLOAD_TTL_SECS: i64 = 86_400;
const MAX_REGISTRY_PUBLICATION_MULTIPART_PARTS: u64 = 10_000;
const REGISTRY_PUBLICATION_PART_CLAIM_SECS: i64 = 300;
const REGISTRY_PUBLICATION_GIT_PACK_OPERATION_TIMEOUT_SECS: u64 = 120;

fn pack_validation_gate() -> Arc<futures_util::lock::Mutex<()>> {
    static GATE: std::sync::OnceLock<Arc<futures_util::lock::Mutex<()>>> =
        std::sync::OnceLock::new();
    Arc::clone(GATE.get_or_init(|| Arc::new(futures_util::lock::Mutex::new(()))))
}

fn multipart_next_part(
    upload: &aos_hub_db::db::RegistryPublicationMultipartUploadRecord,
    expected_size: u64,
) -> Result<u32, RpcError> {
    if upload.state == "completing" {
        return Ok(0);
    }
    let hashed_size = u64::try_from(upload.hashed_size)
        .map_err(|_| RpcError::internal(anyhow::anyhow!("multipart hash progress is negative")))?;
    if hashed_size > expected_size
        || (hashed_size < expected_size
            && hashed_size % REGISTRY_PUBLICATION_PART_BYTES as u64 != 0)
    {
        return Err(RpcError::internal(anyhow::anyhow!(
            "multipart hash progress is invalid"
        )));
    }
    let next = if hashed_size == expected_size {
        expected_size.div_ceil(REGISTRY_PUBLICATION_PART_BYTES as u64) + 1
    } else {
        hashed_size / REGISTRY_PUBLICATION_PART_BYTES as u64 + 1
    };
    u32::try_from(next).map_err(RpcError::internal)
}

fn advance_multipart_sha256(
    encoded_state: &str,
    body: &[u8],
    total_size: u64,
    final_part: bool,
) -> anyhow::Result<String> {
    let state_bytes = hex::decode(encoded_state).context("decoding multipart SHA-256 state")?;
    anyhow::ensure!(
        state_bytes.len() == 32,
        "multipart SHA-256 state is invalid"
    );
    let mut state = [0_u32; 8];
    for (word, bytes) in state.iter_mut().zip(state_bytes.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into()?);
    }

    let complete = body.len() / 64 * 64;
    for chunk in body[..complete].chunks_exact(64) {
        let block = sha2::digest::generic_array::GenericArray::clone_from_slice(chunk);
        sha2::compress256(&mut state, std::slice::from_ref(&block));
    }
    if final_part {
        let mut tail = body[complete..].to_vec();
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(
            &total_size
                .checked_mul(8)
                .context("multipart SHA-256 bit length overflowed")?
                .to_be_bytes(),
        );
        for chunk in tail.chunks_exact(64) {
            let block = sha2::digest::generic_array::GenericArray::clone_from_slice(chunk);
            sha2::compress256(&mut state, std::slice::from_ref(&block));
        }
    } else {
        anyhow::ensure!(
            complete == body.len(),
            "non-final multipart part is not block aligned"
        );
    }
    Ok(state.iter().map(|word| format!("{word:08x}")).collect())
}

#[cfg(test)]
mod multipart_digest_tests {
    use super::{advance_multipart_sha256, multipart_next_part, REGISTRY_PUBLICATION_PART_BYTES};
    use aos_hub_db::db::RegistryPublicationMultipartUploadRecord;
    use sha2::{Digest as _, Sha256};

    const INITIAL_STATE: &str = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

    #[test]
    fn portable_sha256_state_matches_whole_object_digest() {
        let first = vec![b'a'; 64];
        let state = advance_multipart_sha256(INITIAL_STATE, &first, 64, false).unwrap();
        let digest = advance_multipart_sha256(&state, b"bc", 66, true).unwrap();

        let mut whole = first;
        whole.extend_from_slice(b"bc");
        assert_eq!(digest, hex::encode(Sha256::digest(whole)));
    }

    #[test]
    fn portable_sha256_state_matches_short_final_object() {
        let digest = advance_multipart_sha256(INITIAL_STATE, b"abc", 3, true).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(b"abc")));
    }

    #[test]
    fn fully_uploaded_non_aligned_object_resumes_at_completion() {
        let expected_size = REGISTRY_PUBLICATION_PART_BYTES as u64 + 7;
        let upload = RegistryPublicationMultipartUploadRecord {
            upload_id: "upload".into(),
            publication_id: "publication".into(),
            registry_id: 1,
            surface_object_id: 2,
            state: "active".into(),
            expires_at: i64::MAX,
            hashed_size: expected_size as i64,
            sha256_state: "0".repeat(64),
            pending_part: None,
            pending_hash: None,
            pending_token: None,
            pending_since: None,
            completion_token: None,
            completion_since: None,
        };

        assert_eq!(multipart_next_part(&upload, expected_size).unwrap(), 3);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RegistryPublicationMultipartBackend {
    placement_id: i64,
    placement_resource_version: i64,
    backend_upload_id: String,
    completion_etag: Option<String>,
}

async fn collect_exact_publication_body(
    body: axum::body::Body,
    expected_size: usize,
) -> Result<Vec<u8>, RpcError> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::with_capacity(expected_size.min(MAX_UPLOAD_BYTES));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| RpcError::Unavailable(error.to_string()))?;
        let next_size = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| RpcError::invalid("publication object size overflowed"))?;
        if next_size > expected_size {
            return Err(RpcError::invalid(
                "upload body exceeds the declared byte size",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != expected_size {
        return Err(RpcError::invalid(
            "upload body does not match the declared byte size",
        ));
    }
    Ok(bytes)
}

fn verify_publication_bytes(
    object: &aos_hub_db::db::RegistryPublicationUploadObjectRecord,
    bytes: &[u8],
) -> Result<(), RpcError> {
    if bytes.len() as i64 != object.expected_size
        || hex::encode(Sha256::digest(bytes)) != object.expected_hash
    {
        return Err(RpcError::invalid(
            "upload bytes do not match the declared size and SHA-256",
        ));
    }
    verify_loose_publication_bytes(&object.object_key, bytes)?;
    verify_pack_index_publication_bytes(&object.object_key, bytes)?;
    Ok(())
}

/// Verifies the semantic content address before replaceable loose bytes reach
/// any placement. This permits migration between equivalent zlib encodings
/// without allowing a publisher to corrupt an existing Git object path.
fn verify_loose_publication_bytes(path: &str, bytes: &[u8]) -> Result<(), RpcError> {
    if !keymap::is_loose_git_object_path(path) {
        return Ok(());
    }
    let rest = path
        .strip_prefix("objects/")
        .and_then(|value| value.split_once('/'))
        .map(|(directory, filename)| format!("{directory}{filename}"))
        .ok_or_else(|| RpcError::invalid("loose Git object path is invalid"))?;
    let oid =
        Oid::from_hex(&rest).map_err(|_| RpcError::invalid("loose Git object path is invalid"))?;
    aos_registry_format::object::decode_loose(bytes, Some(oid))
        .map_err(|_| RpcError::invalid("loose Git object bytes do not match their object id"))?;
    Ok(())
}

/// Verifies Git pack payloads and replaceable indexes before placement writes.
fn verify_pack_index_publication_bytes(path: &str, bytes: &[u8]) -> Result<(), RpcError> {
    if keymap::is_git_pack_path(path) {
        return aos_registry_format::pack_index::validate_pack(path, bytes)
            .map_err(|_| RpcError::invalid("Git pack bytes do not match their stable path"));
    }
    if !keymap::is_git_pack_index_path(path) {
        return Ok(());
    }
    aos_registry_format::pack_index::validate(path, bytes)
        .map_err(|_| RpcError::invalid("pack index bytes do not match their companion pack"))
}

/// Upper bound on nodes returned by `CacheClosure`, so a pathological closure
/// cannot produce an unbounded response.
const MAX_CLOSURE_NODES: usize = 10_000;

/// Validity window for a presigned cache-read URL. Long enough for a client to
/// follow the `302` and complete the origin fetch, short enough that a leaked
/// URL is useless within minutes.
const PRESIGN_EXPIRES_SECS: u32 = 300;
/// Additional server-side fence after the origin capability's advertised expiry.
const PRESIGN_WRITE_FENCE_GRACE_SECS: i64 = 60;

/// Internal result of a typed cache object or multipart write.
#[derive(Debug)]
pub enum SurfaceWriteOutcome {
    /// The write created a new object: `201 Created`.
    Created,
    /// The write overwrote an existing object: `200 OK`.
    Overwritten,
    /// The cache identity is unknown or soft-deleted.
    NotFound,
    /// The cache has no effective writable placement.
    NotWritable(&'static str),
    /// The path is not a machine path or escapes the surface root: `400 Bad
    /// Request`, with a reason.
    BadPath(&'static str),
    /// No, or an invalid, bearer JWT: `401 Unauthorized`, with a reason.
    Unauthorized(&'static str),
    /// A valid token lacks cache write authority.
    Forbidden,
    /// The body exceeds [`MAX_UPLOAD_BYTES`]: `413 Payload Too Large`.
    TooLarge,
    /// The org's storage quota would be exceeded: `507 Insufficient Storage`.
    QuotaExceeded,
    /// An internal IO/database failure (already logged): `500`.
    Internal,
}

/// Whether a surface-relative path is a *mutable pointer* (vs. an immutable
/// content-addressed object).
///
/// This derives directly from [`keymap::cache_control`], the shared serving
/// contract. Only pointer writes take the publish lease and trigger a re-index.
fn is_mutable_pointer(path: &str) -> bool {
    keymap::cache_control(path) == keymap::MUTABLE_CACHE_CONTROL
}

/// Returns a stable media type for a declared registry object.
fn publication_media_type(path: &str) -> &'static str {
    keymap::content_type(path)
}

/// Returns whether a NAR object key identifies the exact declared wire bytes.
fn publication_nar_path_matches_sha256(path: &str, sha256: &str) -> bool {
    if !path.starts_with("nar/") {
        return true;
    }
    ["nar", "nar.zst", "nar.xz"].iter().any(|extension| {
        path.strip_suffix(&format!(".{extension}"))
            .and_then(|stem| stem.strip_suffix(&format!("-sha256-{sha256}")))
            .is_some_and(|prefix| {
                prefix
                    .strip_prefix("nar/")
                    .is_some_and(|store_hash| !store_hash.is_empty() && !store_hash.contains('/'))
            })
    })
}

/// The shared, transport-free implementation of the `aos.hub.v1` services.
///
/// Holds only data the method bodies need — the [`Database`], the [`JwtKeys`]
/// that verify (and mint) bearer tokens, and the externally reachable base URL
/// used to build canonical upload URLs. The rate limiter and other
/// platform-specific seams arrive as ports as the write path is folded in.
pub struct RpcService {
    /// The hub database (one implementation over the async `Backend`).
    pub db: Arc<Database>,
    /// HS256 keys verifying the bearer JWT on authenticated calls.
    pub jwt_keys: JwtKeys,
    /// Externally reachable base URL, used to build the canonical upload URL.
    pub external_url: String,
    /// Cache-specific Nix public keys published in each registry's setup instructions.
    pub(crate) registry_cache_public_keys: BTreeMap<String, Vec<String>>,
    /// Public base URL exposing the instance-default storage binding directly.
    ///
    /// When configured, public registries on a reconciled complete placement
    /// inherit a canonical Git URL from this origin unless an explicit Git
    /// route advertisement exists. This is the common object-store CDN path;
    /// explicit topology remains authoritative for custom deployments.
    pub default_public_delivery_url: Option<String>,
    /// Independent, fail-closed OCI capability rollout policy.
    pub container_rollout: crate::container_rollout::ContainerRollout,
    /// The abuse-bound rate limiter (the [`RateLimiter`] port), metering
    /// `CreateOrg` per principal.
    pub ratelimit: Arc<dyn RateLimiter>,
    /// The per-registry surface-read port (the [`SurfaceProvider`]), resolving a
    /// [`SurfaceFetch`](crate::fetch::SurfaceFetch) for the `GitService` reads.
    ///
    /// The native hub resolves a filesystem or HTTP fetcher per the registry's
    /// binding; the Worker returns an R2-backed fetcher scoped to the
    /// registry's prefix.
    pub surface: Arc<dyn SurfaceProvider>,
    /// The placement surface-write port used by typed cache uploads and
    /// placement-aware registry publications.
    ///
    /// The native hub returns a filesystem writer rooted at the registry's
    /// binding (atomic temp-file + rename, symlink-contained); the Worker
    /// returns an R2-backed writer scoped to the registry's prefix.
    pub surface_write: Arc<dyn SurfaceWriteProvider>,
    /// The publish lease ([`PublishLease`]), serializing a registry's
    /// mutable-pointer flips across concurrent publishers.
    ///
    /// The native hub uses an in-memory lease
    /// ([`InMemoryLease`](crate::lease::InMemoryLease)); the Worker uses a
    /// coordinator-backed lease shared across isolates.
    pub lease: Arc<dyn PublishLease>,
    /// The post-publication reindexer ([`Reindexer`]), run after an atomic
    /// registry publication commits its mutable pointers.
    ///
    /// The native hub re-indexes synchronously from the local surface; the Worker
    /// defers to its Cron-trigger indexer (a logged no-op).
    pub reindexer: Arc<dyn Reindexer>,
    /// Durable typed queue for domain, boundary, endpoint, and route probes.
    pub topology_probes: Arc<dyn TopologyProbeScheduler>,
    /// The secret sealer ([`SecretSealer`](aos_hub_model::auth::seal::SecretSealer)) used
    /// to unseal a cache's hosted Ed25519 key for server-side narinfo signing.
    ///
    /// `None` disables hub-side signing — a key-bearing cache then relies on the
    /// uploader's own `Sig:` lines (BYO signing). Both shells wire their sealer
    /// (the native `HUB_SEAL_KEY` sealer; the Worker's `HUB_SEAL_KEY` binding).
    pub sealer: Option<Arc<dyn aos_hub_model::auth::seal::SecretSealer>>,
    /// Runtime provider for immutable secret-version references.
    pub secret_versions: Option<Arc<dyn aos_hub_model::secret_version::SecretVersionResolver>>,
    /// The authenticated-origin proxy-read fetcher
    /// ([`OriginFetch`](crate::fetch::OriginFetch)), used to stream a private
    /// external origin's bytes through the hub instead of `302`-redirecting the
    /// client to a presigned URL.
    ///
    /// `None` (the default) disables hub-side proxying: a private-origin cache
    /// then always serves a presigned `302`. Wired per shell via
    /// [`with_origin_fetch`](Self::with_origin_fetch) — the native hub a
    /// `reqwest` streamer, the Worker a Fetch-API streamer. Streamed proxying is
    /// Delivery-route mode and policy decide whether Hub streams or redirects.
    pub origin_fetch: Option<Arc<dyn crate::fetch::OriginFetch>>,
    /// The hot-state key-value store ([`KvStore`](crate::kv::KvStore)) for
    /// read-through caching of point-key lookups — sessions, tokens, instance
    /// config and trust rosters (RFC-0004 ch.14 Phase C).
    ///
    /// `None` (the default) routes every such read straight to the database, the
    /// pre-Phase-C behavior; wired per shell via [`with_kv`](Self::with_kv) — the
    /// Worker a Workers KV store (`WorkerKv`), the native hub an in-process or
    /// embedded store. When present, the cache-aside read path
    /// ([`crate::cache::read_through`]) serves hot keys off KV with a short TTL
    /// and invalidates on write, keeping these reads off the relational session cost.
    pub kv: Option<Arc<dyn crate::kv::KvStore>>,
    /// TLS-terminator signing material available to the well-known domain
    /// ownership responder. Absent material makes the route fail closed.
    pub domain_probe_terminator:
        Option<Arc<dyn crate::topology_probe::DomainProbeTerminatorProvider>>,
    /// Runtime DNS verifier for organization email-domain ownership challenges.
    pub identity_domain_verifier: Option<Arc<dyn crate::topology_probe::IdentityDomainVerifier>>,
    /// Runtime-owned active and retained route-reservation HMAC keys.
    pub route_reservation_keyring: Option<Arc<dyn RouteReservationKeyring>>,
    /// Durable queue that runs scheduled maintenance jobs on demand.
    ///
    /// `None` (the default) makes `TriggerContainerMaintenance` unavailable;
    /// the Worker wires its Cloudflare queue so operators can run the OCI
    /// probe, inventory, and GC jobs without waiting for the cron schedule.
    pub maintenance_jobs: Option<Arc<dyn crate::jobs::Queue>>,
    /// Restricted deployment authority for release and channel evidence.
    pub release_evidence: Option<Arc<dyn crate::release_evidence::ReleaseEvidenceAuthority>>,
    /// Serializes memory-bounded Git pack/index verification within the process or Worker isolate.
    pack_validation: Arc<futures_util::lock::Mutex<()>>,
}

macro_rules! reviewed_external_operation {
    ($plan:ident, $apply:ident, $execute:ident, $request:path, $kind:literal) => {
        /// Persists a reviewed plan without initiating external work.
        pub async fn $plan(
            &self,
            auth: Option<&str>,
            req: $request,
        ) -> Result<pb::TopologyPlanResponse, RpcError> {
            self.plan_external_operation(auth, $kind, &req, &req.idempotency_key)
                .await
        }

        /// Applies one reviewed plan exactly once and returns its durable operation.
        pub async fn $apply(
            &self,
            auth: Option<&str>,
            req: pb::ApplyTopologyPlanRequest,
        ) -> Result<pb::OperationResponse, RpcError> {
            if let Some(response) = self
                .replayed_control_result(
                    auth,
                    &req.plan_id,
                    $kind,
                    Some(&req.confirmation_hash),
                    &req.idempotency_key,
                )
                .await?
            {
                return Ok(response);
            }
            self.begin_control_plan_apply(
                auth,
                &req.plan_id,
                $kind,
                &req.idempotency_key,
                Some(&req.confirmation_hash),
            )
            .await?;
            let (plan, input): (_, $request) = self
                .load_control_plan(auth, &req.plan_id, $kind, Some(&req.confirmation_hash))
                .await?;
            let response = self.$execute(auth, input).await?;
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            Ok(response)
        }
    };
}

/// The KV key a session resolution is cached under: `sess:` + the SHA-256 hex of
/// the cookie secret (never the raw secret, which must not appear in a key).
fn session_cache_key(secret: &str) -> String {
    format!("sess:{}", aos_hub_model::auth::token::sha256_hex(secret))
}

/// The serializable projection of a [`ResolvedSession`](crate::web::session::ResolvedSession)
/// stored in KV (RFC-0004 ch.14 Phase C).
///
/// Mirrors `SessionAuth`'s integer fields plus the user's email — everything the
/// resolution carries except the secret (re-attached on read). Kept local to the
/// service so the `db` types need no serde derives.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedSession {
    user_id: i64,
    auth_level: i64,
    last_authenticated_at: i64,
    expires_at: i64,
    email: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlannedConsumerCacheChange {
    request: pb::PlanCreateConsumerCacheChangesetRequest,
    ready_routes:
        std::collections::BTreeMap<String, aos_hub_db::db::ReadyRouteAdvertisementIdentity>,
}

impl CachedSession {
    /// Projects a freshly-resolved session into its cacheable form.
    fn from_resolved(rs: &crate::web::session::ResolvedSession) -> CachedSession {
        CachedSession {
            user_id: rs.auth.user_id,
            auth_level: rs.auth.auth_level,
            last_authenticated_at: rs.auth.last_authenticated_at,
            expires_at: rs.auth.expires_at,
            email: rs.email.clone(),
        }
    }

    /// Rebuilds a [`ResolvedSession`](crate::web::session::ResolvedSession) from a
    /// cached projection, or `None` when it has expired as of `now`.
    ///
    /// The expiry recheck makes the short cache TTL safe: an entry that expires
    /// mid-window is never served, exactly as `validate_session` would reject it.
    fn into_resolved(self, secret: &str, now: i64) -> Option<crate::web::session::ResolvedSession> {
        if self.expires_at <= now {
            return None;
        }
        Some(crate::web::session::ResolvedSession {
            secret: secret.to_string(),
            auth: aos_hub_db::db::SessionAuth {
                user_id: self.user_id,
                auth_level: self.auth_level,
                last_authenticated_at: self.last_authenticated_at,
                expires_at: self.expires_at,
            },
            email: self.email,
        })
    }
}

impl RpcService {
    reviewed_external_operation!(
        plan_validate_binding_credential,
        validate_binding_credential,
        execute_validate_binding_credential,
        pb::PlanValidateBindingCredentialRequest,
        "validate_binding_credential"
    );
    reviewed_external_operation!(
        plan_verify_domain,
        verify_domain,
        execute_verify_domain,
        pb::PlanVerifyDomainRequest,
        "verify_domain"
    );
    reviewed_external_operation!(
        plan_scan_placement,
        scan_placement,
        execute_scan_placement,
        pb::PlanScanPlacementRequest,
        "scan_placement"
    );
    reviewed_external_operation!(
        plan_replicate_placement,
        replicate_placement,
        execute_replicate_placement,
        pb::PlanReplicatePlacementRequest,
        "replicate_placement"
    );
    reviewed_external_operation!(
        plan_repair_placement,
        repair_placement,
        execute_repair_placement,
        pb::PlanRepairPlacementRequest,
        "repair_placement"
    );
    reviewed_external_operation!(
        plan_sync_registry_mirror,
        sync_registry_mirror,
        execute_sync_registry_mirror,
        pb::PlanSyncRegistryMirrorRequest,
        "sync_registry_mirror"
    );
    reviewed_external_operation!(
        plan_retry_cache_gc_deletion_job,
        retry_cache_gc_deletion_job,
        execute_retry_cache_gc_deletion_job,
        pb::PlanRetryCacheGcDeletionJobRequest,
        "retry_cache_gc_deletion_job"
    );
    reviewed_external_operation!(
        plan_refresh_all_retention,
        refresh_all_retention,
        execute_refresh_all_retention,
        pb::PlanRefreshAllRetentionRequest,
        "refresh_all_retention"
    );
    reviewed_external_operation!(
        plan_refresh_retention_subscription,
        refresh_retention_subscription,
        execute_refresh_retention_subscription,
        pb::PlanRefreshRetentionSubscriptionRequest,
        "refresh_retention_subscription"
    );
    reviewed_external_operation!(
        plan_run_population,
        run_population,
        execute_run_population,
        pb::PlanRunPopulationRequest,
        "run_population"
    );
    reviewed_external_operation!(
        plan_run_coverage_validation,
        run_coverage_validation,
        execute_run_coverage_validation,
        pb::PlanCoverageOperationRequest,
        "run_coverage_validation"
    );
    reviewed_external_operation!(
        plan_run_coverage_repair,
        run_coverage_repair,
        execute_run_coverage_repair,
        pb::PlanCoverageOperationRequest,
        "run_coverage_repair"
    );
}

fn control_confirmation_hash(value: &impl serde::Serialize) -> Result<String, RpcError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(RpcError::internal)?,
    )))
}

fn normalize_signing_key_mutation(
    request: &mut pb::PlanSigningKeyMutationRequest,
) -> Result<(), RpcError> {
    request.name = request.name.trim().to_string();
    request.public_key = request.public_key.trim().to_string();
    request.public_key_fingerprint = request.public_key_fingerprint.trim().to_lowercase();
    request.custody = request.custody.trim().to_lowercase();
    if request.name.is_empty()
        || request.name.len() > 64
        || !request
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RpcError::invalid(
            "signing-key name must contain 1..=64 letters, digits, '-', '_', or '.'",
        ));
    }
    if request.custody != "external" {
        return Err(RpcError::invalid(
            "custody must be 'external'; secret-provider custody requires immutable provider-resolution proof",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&request.public_key)
        .map_err(|_| RpcError::invalid("public_key must be canonical unpadded base64"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RpcError::invalid("Ed25519 public_key must contain 32 bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| RpcError::invalid("public_key is not a valid Ed25519 key"))?;
    if base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes) != request.public_key {
        return Err(RpcError::invalid(
            "public_key must use canonical unpadded base64",
        ));
    }
    let expected_fingerprint = hex::encode(Sha256::digest(bytes));
    if request.public_key_fingerprint != expected_fingerprint {
        return Err(RpcError::invalid(
            "public_key_fingerprint does not match public_key",
        ));
    }
    Ok(())
}

fn validate_signing_usage_request(
    request: &pb::PlanSigningKeyUsageRequest,
) -> Result<(), RpcError> {
    validate_signing_usage_identity(&request.consumer_stable_id, &request.purpose)?;
    if !matches!(request.state.as_str(), "active" | "detached") {
        return Err(RpcError::invalid("usage state must be active or detached"));
    }
    if request.signing_key_generation == 0 {
        return Err(RpcError::invalid(
            "signing_key_generation must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_signing_usage_identity(
    consumer_stable_id: &str,
    purpose: &str,
) -> Result<(), RpcError> {
    if consumer_stable_id.is_empty()
        || !matches!(
            purpose,
            "registry_publication" | "narinfo" | "channel_frontier"
        )
    {
        return Err(RpcError::invalid(
            "consumer_stable_id and a supported signing purpose are required",
        ));
    }
    Ok(())
}

/// Requires a signing key to be owned by either the consumer or its infrastructure owner.
fn validate_signing_key_consumer_compatibility(
    key: &aos_hub_db::db::SigningKeyRecord,
    consumer: &aos_hub_db::db::SigningKeyConsumerRecord,
) -> Result<(), RpcError> {
    if key.scope_key == consumer.scope_key || key.scope_key == consumer.owner_scope_key {
        Ok(())
    } else {
        Err(RpcError::PermissionDenied(
            "signing key and consumer must share a resource or owner scope".into(),
        ))
    }
}

fn signing_key_message(record: aos_hub_db::db::SigningKeyRecord) -> pb::SigningKey {
    pb::SigningKey {
        stable_id: record.stable_id,
        scope_key: record.scope_key,
        name: record.name,
        resource_version: record.resource_version.to_string(),
        latest_generation: Some(pb::SigningKeyGeneration {
            generation: u64::try_from(record.generation).unwrap_or_default(),
            algorithm: record.algorithm,
            public_key: record.public_key,
            public_key_fingerprint: record.public_key_fingerprint,
            custody: record.custody,
            state: record.state,
            created_at: record.generation_created_at,
            retired_at: record.retired_at.unwrap_or_default(),
        }),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn signing_key_usage_message(record: aos_hub_db::db::SigningKeyUsageRecord) -> pb::SigningKeyUsage {
    pb::SigningKeyUsage {
        stable_id: record.stable_id,
        consumer_stable_id: record.consumer_stable_id,
        purpose: record.purpose,
        signing_key_stable_id: record.signing_key_id,
        signing_key_generation: u64::try_from(record.signing_key_generation).unwrap_or_default(),
        state: record.state,
        resource_version: record.resource_version.to_string(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        consumer_kind: record.consumer_kind,
        consumer_scope_key: record.consumer_scope_key,
        consumer_name: record.consumer_name.unwrap_or_default(),
    }
}

fn parse_authorization_scope(value: &str) -> Result<Scope, RpcError> {
    if !Scope::is_canonical(value) {
        return Err(RpcError::invalid(
            "scope must be instance, org:<stable-id>, or an immutable project scope",
        ));
    }
    Ok(Scope::parse(value))
}

fn topology_target_read_permission(target_kind: &str) -> Permission {
    match target_kind {
        "placement" => Permission::PlacementRead,
        "placement_policy" => Permission::PlacementPolicyRead,
        "domain" => Permission::DomainRead,
        "network_policy" => Permission::NetworkPolicyRead,
        "endpoint" => Permission::EndpointRead,
        "gateway" => Permission::GatewayRead,
        "binding" => Permission::BindingRead,
        "route" => Permission::RouteRead,
        _ => Permission::Read,
    }
}

fn parse_resource_version(value: &str, default: i64) -> Result<i64, RpcError> {
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse::<i64>()
        .map_err(|_| RpcError::invalid("expected_resource_version must be an integer"))
}

fn identity_resource_version(version: i64, incarnation_id: Option<&str>) -> String {
    format!("{version}@{}", incarnation_id.unwrap_or("legacy"))
}

fn require_exact_identity_version(
    supplied: &str,
    current: Option<(i64, Option<&str>)>,
) -> Result<Option<i64>, RpcError> {
    match current {
        None if supplied == "absent" => Ok(None),
        None => Err(RpcError::FailedPrecondition(
            "new resource requires expected_resource_version=absent".into(),
        )),
        Some((version, incarnation_id)) => {
            if supplied == identity_resource_version(version, incarnation_id) {
                Ok(Some(version))
            } else {
                Err(RpcError::FailedPrecondition(
                    "resource revision changed".into(),
                ))
            }
        }
    }
}

fn canonical_identity_domain(value: &str) -> Result<String, RpcError> {
    aos_hub_db::db::canonical_delivery_hostname(value.trim())
        .map_err(|error| RpcError::invalid(format!("invalid organization domain: {error:#}")))
}

fn idp_record_from_plan(
    input: &IdentityProviderSetPlanInput,
    resource_version: i64,
) -> aos_hub_db::db::IdpConfigRecord {
    aos_hub_db::db::IdpConfigRecord {
        org_id: input.org_id,
        issuer: input.issuer.clone(),
        authorization_endpoint: input.authorization_endpoint.clone(),
        token_endpoint: input.token_endpoint.clone(),
        jwks_uri: input.jwks_uri.clone(),
        client_id: input.client_id.clone(),
        client_secret_enc: input.client_secret_enc.clone(),
        scopes: input.scopes.clone(),
        groups_claim: input.groups_claim.clone(),
        role_map_json: input.role_map_json.clone(),
        allow_jit: input.allow_jit,
        enforce_sso: input.enforce_sso,
        default_role: input.default_role.clone(),
        resource_version,
        incarnation_id: Some(input.incarnation_id.clone()),
        mutation_plan_id: None,
    }
}

fn control_audit_event_id(kind: &str, plan_id: &str) -> String {
    hex::encode(Sha256::digest(format!("{kind}:{plan_id}").as_bytes()))
}

fn require_absent_resource_version(value: &str) -> Result<(), RpcError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(RpcError::FailedPrecondition(
            "new resource requires an empty expected_resource_version".to_string(),
        ))
    }
}

/// Validates the exact trust-anchor representation persisted by registries.
fn validate_registry_trust_keys(keys: &[String]) -> Result<(), RpcError> {
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err(RpcError::invalid("trustKeys must be unique"));
    }
    for key in keys {
        let (name, _) = aos_registry_format::sshsig::trusted_key_ed25519(key)
            .map_err(|error| RpcError::invalid(format!("invalid registry trust key: {error:#}")))?;
        if name.is_empty() {
            return Err(RpcError::invalid(
                "registry trust keys require name:Ed25519:<base64> form",
            ));
        }
    }
    Ok(())
}

/// Verifies completion names every confirmed durable part and exactly the declared bytes.
fn multipart_completion_matches(
    durable: &[aos_hub_db::db::WriteTicketPartRecord],
    requested: &[crate::surface_write::PartTag],
    declared_size: i64,
) -> bool {
    if durable.len() != requested.len()
        || durable.iter().any(|part| part.state != "confirmed")
        || durable
            .iter()
            .enumerate()
            .any(|(index, part)| part.part_number != u32::try_from(index + 1).unwrap_or(u32::MAX))
    {
        return false;
    }
    let Some(confirmed_size) = durable
        .iter()
        .try_fold(0i64, |total, part| total.checked_add(part.admitted_size))
    else {
        return false;
    };
    if confirmed_size != declared_size {
        return false;
    }
    let requested = requested
        .iter()
        .map(|part| (part.part_number, part.etag.as_str()))
        .collect::<BTreeMap<_, _>>();
    requested.len() == durable.len()
        && durable
            .iter()
            .all(|part| requested.get(&part.part_number).copied() == part.etag.as_deref())
}

/// Verifies that placement evidence is the exact deterministic multipart result.
fn cache_multipart_evidence_matches(
    evidence: &crate::fetch::SurfaceObjectEvidence,
    ticket: &aos_hub_db::db::CacheWriteTicketRecord,
    expected_etag: &str,
) -> bool {
    let observed_etag = evidence
        .strong_etag
        .as_deref()
        .and_then(|etag| crate::surface_write::strong_if_match_etag(etag).ok());
    evidence.size == ticket.declared_size
        && observed_etag.as_deref() == Some(expected_etag)
        && ticket
            .intended_object_hash
            .as_deref()
            .is_none_or(|expected| hex::encode(evidence.sha256) == expected)
}

fn write_object_identity(
    evidence: crate::fetch::SurfaceObjectEvidence,
) -> aos_hub_db::db::WriteObjectIdentity {
    aos_hub_db::db::WriteObjectIdentity {
        size: evidence.size,
        sha256: hex::encode(evidence.sha256),
        strong_etag: evidence.strong_etag,
    }
}

/// Logs an internal error and maps it to [`SurfaceWriteOutcome::Internal`] (`500`).
fn internal_write(err: anyhow::Error) -> SurfaceWriteOutcome {
    tracing::error!(error = %format!("{err:#}"), "surface write failed");
    SurfaceWriteOutcome::Internal
}

fn write_outcome_error(outcome: SurfaceWriteOutcome) -> RpcError {
    match outcome {
        SurfaceWriteOutcome::NotFound => RpcError::not_found("cache upload"),
        SurfaceWriteOutcome::NotWritable(reason) => RpcError::FailedPrecondition(reason.into()),
        SurfaceWriteOutcome::BadPath(reason) => RpcError::invalid(reason),
        SurfaceWriteOutcome::Unauthorized(reason) => RpcError::Unauthenticated(reason.into()),
        SurfaceWriteOutcome::Forbidden => {
            RpcError::PermissionDenied("cache write permission required".into())
        }
        SurfaceWriteOutcome::TooLarge => {
            RpcError::ResourceExhausted("upload part exceeds the configured body limit".into())
        }
        SurfaceWriteOutcome::QuotaExceeded => {
            RpcError::ResourceExhausted("organization storage quota exceeded".into())
        }
        SurfaceWriteOutcome::Internal => RpcError::Internal,
        SurfaceWriteOutcome::Created | SurfaceWriteOutcome::Overwritten => RpcError::Internal,
    }
}

fn write_outcome_result(outcome: SurfaceWriteOutcome) -> Result<(), RpcError> {
    match outcome {
        SurfaceWriteOutcome::Created | SurfaceWriteOutcome::Overwritten => Ok(()),
        other => Err(write_outcome_error(other)),
    }
}

/// Resolves the CLI's zero-generation sentinel to the endpoint's current target.
fn resolve_endpoint_grant_generation(
    requested_generation: i64,
    desired_generation: i64,
) -> Result<i64, RpcError> {
    if requested_generation == 0 || requested_generation == desired_generation {
        Ok(desired_generation)
    } else {
        Err(RpcError::FailedPrecondition(
            "endpoint generation is stale".to_string(),
        ))
    }
}

#[cfg(test)]
mod endpoint_grant_generation_tests {
    use super::{resolve_endpoint_grant_generation, RpcError};

    #[test]
    fn resolves_cli_sentinel_and_preserves_stale_generation_fence() {
        assert_eq!(resolve_endpoint_grant_generation(0, 2).unwrap(), 2);
        assert_eq!(resolve_endpoint_grant_generation(2, 2).unwrap(), 2);
        assert!(matches!(
            resolve_endpoint_grant_generation(1, 2),
            Err(RpcError::FailedPrecondition(message)) if message == "endpoint generation is stale"
        ));
    }
}

/// Maps a cache-write authorization denial onto the internal write outcome.
fn auth_denial_to_write_outcome(err: RpcError) -> SurfaceWriteOutcome {
    match err {
        RpcError::Unauthenticated(_) => {
            SurfaceWriteOutcome::Unauthorized("authentication required")
        }
        RpcError::PermissionDenied(_) => SurfaceWriteOutcome::Forbidden,
        RpcError::NotFound(_) => SurfaceWriteOutcome::NotFound,
        // require_cache_admin only yields the three denials above plus Internal.
        _ => SurfaceWriteOutcome::Internal,
    }
}

#[cfg(test)]
mod route_reservation_keyring_tests {
    use base64::Engine as _;

    use super::{ConfiguredRouteReservationKeyring, RouteReservationKeyring};

    fn encoded(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn accepts_one_active_key_and_retained_rotation_history() {
        let manifest = format!(
            r#"{{"activeVersion":2,"keys":[{{"version":1,"keyBase64":"{}"}},{{"version":2,"keyBase64":"{}"}}]}}"#,
            encoded(1),
            encoded(2)
        );
        let keyring = ConfiguredRouteReservationKeyring::from_json(&manifest).unwrap();
        let keys = keyring.snapshot().unwrap();
        assert_eq!(
            keys.iter().map(|key| key.version).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(keys.iter().filter(|key| key.active).count(), 1);
        assert!(keys[1].active);
    }

    #[test]
    fn rejects_missing_active_duplicate_and_short_keys() {
        let missing = format!(
            r#"{{"activeVersion":2,"keys":[{{"version":1,"keyBase64":"{}"}}]}}"#,
            encoded(1)
        );
        assert!(ConfiguredRouteReservationKeyring::from_json(&missing).is_err());
        let duplicate = format!(
            r#"{{"activeVersion":1,"keys":[{{"version":1,"keyBase64":"{}"}},{{"version":1,"keyBase64":"{}"}}]}}"#,
            encoded(1),
            encoded(2)
        );
        assert!(ConfiguredRouteReservationKeyring::from_json(&duplicate).is_err());
        let short = base64::engine::general_purpose::STANDARD.encode([3_u8; 16]);
        let short =
            format!(r#"{{"activeVersion":1,"keys":[{{"version":1,"keyBase64":"{short}"}}]}}"#);
        assert!(ConfiguredRouteReservationKeyring::from_json(&short).is_err());
    }

    #[test]
    fn detects_a_persisted_version_removed_before_rotation_is_safe() {
        let manifest = format!(
            r#"{{"activeVersion":2,"keys":[{{"version":2,"keyBase64":"{}"}}]}}"#,
            encoded(2)
        );
        let keyring = ConfiguredRouteReservationKeyring::from_json(&manifest).unwrap();
        assert_eq!(keyring.missing_referenced_versions(&[1, 2]), [1]);
        assert!(keyring.missing_referenced_versions(&[2]).is_empty());
    }
}

#[cfg(test)]
mod image_body_tests {
    use super::exact_image_body;
    use axum::body::{to_bytes, Body, Bytes};

    #[tokio::test]
    async fn exact_signed_full_and_range_bodies_complete() {
        assert_eq!(
            to_bytes(exact_image_body(Body::from("raw-image"), 9), 32)
                .await
                .unwrap(),
            Bytes::from_static(b"raw-image")
        );
        assert_eq!(
            to_bytes(exact_image_body(Body::from("ange"), 4), 32)
                .await
                .unwrap(),
            Bytes::from_static(b"ange")
        );
    }

    #[tokio::test]
    async fn truncated_and_overlong_full_or_range_bodies_fail_closed() {
        for (body, signed_length) in [("short", 9), ("too-long", 4), ("x", 2), ("range", 3)] {
            assert!(
                to_bytes(exact_image_body(Body::from(body), signed_length), 32)
                    .await
                    .is_err(),
                "body={body:?}, signed_length={signed_length}"
            );
        }
    }
}

#[cfg(test)]
mod publication_upload_limit_tests {
    use super::{
        complete_upload_bytes, is_mutable_pointer, publication_media_type,
        publication_nar_path_matches_sha256, verify_loose_publication_bytes,
        verify_pack_index_publication_bytes,
    };
    use crate::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES;

    #[test]
    fn complete_upload_admission_never_exceeds_the_shared_transport_limit() {
        assert_eq!(
            complete_upload_bytes(20 * 1024 * 1024),
            CONNECT_REQUEST_BODY_LIMIT_BYTES
        );
        assert!(
            aos_registry_format::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize
                <= CONNECT_REQUEST_BODY_LIMIT_BYTES
        );
        assert_eq!(complete_upload_bytes(1024), 1024);
    }

    #[test]
    fn publication_metadata_uses_the_delivery_path_contract() {
        for path in [
            "hash.narinfo",
            "nix-cache-info",
            "index.html",
            "objects/info/packs",
            "objects/ab/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "releases/1/0/0/objects/info/packs",
            "objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.idx",
            "releases/1/0/0/objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.idx",
            "web/config.json",
            "web/index.json",
            "web/packages/aos.json",
        ] {
            assert!(is_mutable_pointer(path), "{path}");
        }
        for path in [
            "objects/aa/object",
            "releases/aos.json",
            "releases/1/0/0/objects/pack/pack-demo.pack",
            "nar/hash.nar.zst",
            "images/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/disk.qcow2",
        ] {
            assert!(!is_mutable_pointer(path), "{path}");
        }
        assert_eq!(publication_media_type("hash.narinfo"), "text/x-nix-narinfo");
        assert_eq!(
            publication_media_type("images/disk.qcow2"),
            "application/vnd.aos.disk-image.qcow2"
        );
    }

    #[test]
    fn publication_nar_paths_are_bound_to_wire_digest() {
        let digest = "a".repeat(64);
        assert!(publication_nar_path_matches_sha256(
            &format!("nar/storehash-sha256-{digest}.nar.zst"),
            &digest
        ));
        assert!(!publication_nar_path_matches_sha256(
            "nar/storehash-sha256-old.nar.zst",
            &digest
        ));
        assert!(publication_nar_path_matches_sha256(
            "images/disk.qcow2",
            &digest
        ));
    }

    #[test]
    fn pack_index_uploads_are_semantically_validated() {
        let basename = format!("objects/pack/pack-{}", "42".repeat(32));
        assert!(
            verify_pack_index_publication_bytes(&format!("{basename}.idx"), b"not an index")
                .is_err()
        );
        assert!(
            verify_pack_index_publication_bytes(&format!("{basename}.pack"), b"not a pack")
                .is_err()
        );
        assert!(verify_pack_index_publication_bytes("objects/info/packs", b"P pack\n").is_ok());
    }

    #[test]
    fn replaceable_loose_object_bytes_must_match_their_git_identity() {
        use aos_registry_format::object::{encode_loose, hash_object, ObjectKind};

        let content = b"canonical registry object";
        let oid = hash_object(ObjectKind::Blob, content);
        let path = oid.loose_path();
        let encoded = encode_loose(ObjectKind::Blob, content).unwrap();

        verify_loose_publication_bytes(&path, &encoded).unwrap();
        assert!(verify_loose_publication_bytes(&path, b"not zlib").is_err());

        let other = hash_object(ObjectKind::Blob, b"other").loose_path();
        assert!(verify_loose_publication_bytes(&other, &encoded).is_err());
    }
}

#[cfg(test)]
#[path = "service/tests/mod.rs"]
pub(crate) mod cache_upload_tests;

mod operations;
