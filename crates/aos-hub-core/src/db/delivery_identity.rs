//! Domain, network-boundary, and delivery-endpoint persistence.
//!
//! These resources separate immutable identity from mutable controller state.
//! Domains have immutable hostnames, network policies have immutable typed
//! identities plus append-only protection revisions, and endpoints have an
//! immutable origin plus append-only listener generations. All mutable heads,
//! observations, and lifecycle transitions use resource-version compare and
//! swap (CAS).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::backend::Statement;
use crate::endpoint::{DeliveryHost, EndpointOrigin};
use crate::value::Row;

use super::{unix_now, Database};

fn endpoint_ready_route_probe_operation_id(
    domain_operation_id: &str,
    route_id: &str,
    generation: i64,
    digest: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!(
            "delivery-route-endpoint-ready-v1\0{domain_operation_id}\0{route_id}\0{generation}\0{digest}"
        )
        .as_bytes(),
    ))
}

/// Canonicalizes and validates a public delivery hostname.
///
/// # Errors
///
/// Returns an error for a port, trailing dot, IP literal, non-ASCII/IDNA input,
/// empty label, or label outside DNS length and character constraints.
pub fn canonical_delivery_hostname(hostname: &str) -> Result<String> {
    normalize_hostname(hostname)
}

const DOMAIN_COLUMNS: &str = "d.id, d.stable_id, d.org_id, d.owner_scope_key, d.hostname,
    d.dns_configuration_json, d.dns_state,
    d.certificate_configuration_json, d.certificate_state,
    d.verified_at, d.observed_at, d.observation_error, d.observation_digest,
    d.probe_location, d.resource_version, d.created_at, d.updated_at";

const BOUNDARY_COLUMNS: &str = "b.id, b.org_id, b.owner_scope_key, b.name, b.kind,
    b.identity_spec_json, b.identity_fingerprint, nd.revision, nd.state,
    b.resource_version, b.created_at, b.updated_at";

const BOUNDARY_REVISION_COLUMNS: &str = "r.boundary_id, r.revision,
    r.protected_transport_required, r.trusted_ingress_kind,
    r.trusted_ingress_configuration, r.source_allowlist_cidrs,
    r.probe_location_configuration, r.content_digest, r.created_by, r.created_at,
    o.state, o.protected_transport_observed, o.trusted_ingress_observed,
    o.observed_at, o.error, l.state, l.activation_mode, l.consumer_version,
    l.activated_at, l.retired_at, l.resource_version";

const ENDPOINT_COLUMNS: &str = "e.id, e.org_id, e.owner_scope_key, e.scheme,
    e.domain_id, d.stable_id, e.ipv4_bytes, e.ipv6_bytes, e.effective_port,
    e.network_policy_id, e.cleartext_acknowledged_at, e.desired_generation,
    e.endpoint_identity_digest, e.resource_version, e.created_at, e.updated_at";

const ENDPOINT_REVISION_COLUMNS: &str = "r.endpoint_id, r.generation,
    r.network_policy_id, r.boundary_revision, r.ingress_kind,
    r.listener_configuration, r.tls_configuration, r.probe_configuration,
    r.content_digest, r.created_by, r.created_at";

const PIN_RESOLUTION_JOB_COLUMNS: &str = "operation_id, pin_id, action_kind,
    source_boundary_id, source_boundary_revision, source_consumer_scope_key,
    source_grant_generation, source_usage_kind, source_target_kind,
    source_target_stable_id, source_target_generation_key,
    source_target_configuration_digest, source_target_resource_version,
    replacement_target_kind, replacement_target_stable_id,
    replacement_target_generation_key, replacement_target_configuration_digest,
    replacement_target_resource_version, state, attempt, error, resource_version";

/// One stable page of database records and its exclusive continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryIdentityPage<T> {
    /// Records in deterministic key order.
    pub records: Vec<T>,
    /// Exclusive cursor for the next page, or `None` at the end.
    pub next_cursor: Option<String>,
}

/// A DNS hostname with independent desired and observed posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryDomainRecord {
    /// Internal database key used by composite foreign keys.
    pub id: i64,
    /// Stable public identifier.
    pub stable_id: String,
    /// Owning organization database id, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Exact owner scope.
    pub owner_scope_key: String,
    /// Immutable IDNA-ASCII hostname.
    pub hostname: String,
    /// Lossless canonical typed desired DNS configuration.
    pub dns_configuration_json: Option<String>,
    /// Observed DNS state.
    pub dns_state: String,
    /// Lossless canonical typed desired certificate configuration.
    pub certificate_configuration_json: Option<String>,
    /// Observed certificate state.
    pub certificate_state: String,
    /// Time at which DNS and certificate posture were both verified.
    pub verified_at: Option<i64>,
    /// Time of the latest controller observation.
    pub observed_at: Option<i64>,
    /// Redacted controller error.
    pub observation_error: Option<String>,
    /// Digest of the canonical measured evidence behind the observation.
    pub observation_digest: Option<String>,
    /// Controller probe location or vantage identifier.
    pub probe_location: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last desired or observed change in Unix seconds.
    pub updated_at: i64,
}

/// Lossless desired DNS configuration stored on a delivery domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeliveryDnsConfigurationSpec {
    /// Hub reconciles the provider record to the configured target.
    HubManaged {
        /// Provider implementation identifier.
        provider: String,
        /// Provider-qualified zone identifier.
        zone_id: String,
        /// Provider record-management mode.
        record_mode: String,
        /// Exact desired DNS target.
        target: String,
        /// Desired record lifetime in seconds.
        ttl_seconds: u32,
    },
    /// An external controller owns DNS and Hub verifies this target.
    External {
        /// Exact target the external record must resolve to.
        expected_target: String,
    },
}

/// Lossless desired certificate configuration stored on a delivery domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeliveryCertificateConfigurationSpec {
    /// Hub obtains and renews the certificate.
    HubManaged {
        /// Certificate issuer implementation identifier.
        issuer: String,
        /// DNS challenge provider implementation identifier.
        dns_challenge_provider: String,
    },
    /// An external controller provides a versioned secret reference.
    External {
        /// Secret-manager reference containing the certificate material.
        certificate_secret_ref: String,
    },
}

impl DeliveryDnsConfigurationSpec {
    fn validate(&self) -> Result<()> {
        match self {
            Self::HubManaged {
                provider,
                zone_id,
                record_mode,
                target,
                ttl_seconds,
            } => {
                validate_provider_token(provider)?;
                validate_identity_string(zone_id, "DNS zone id")?;
                if record_mode != "managed" {
                    bail!("DNS record mode must be 'managed'");
                }
                validate_identity_string(target, "DNS target")?;
                if *ttl_seconds == 0 {
                    bail!("DNS TTL must be greater than zero");
                }
            }
            Self::External { expected_target } => {
                validate_identity_string(expected_target, "expected DNS target")?;
            }
        }
        Ok(())
    }
}

impl DeliveryCertificateConfigurationSpec {
    fn validate(&self) -> Result<()> {
        match self {
            Self::HubManaged {
                issuer,
                dns_challenge_provider,
            } => {
                validate_provider_token(issuer)?;
                validate_provider_token(dns_challenge_provider)?;
            }
            Self::External {
                certificate_secret_ref,
            } => {
                validate_identity_string(certificate_secret_ref, "certificate secret reference")?;
            }
        }
        Ok(())
    }
}

/// An immutable, closed network-realm identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkPolicyIdentitySpec {
    /// The deployment-owned public network singleton.
    Public,
    /// A provider-qualified VPN identity.
    Vpn {
        /// Lowercase provider kind.
        provider: String,
        /// Provider account or tenant.
        account_or_tenant: String,
        /// Globally qualified provider resource id.
        resource_id: String,
    },
    /// A provider-qualified VPC or equivalent private network.
    Vpc {
        /// Lowercase provider kind.
        provider: String,
        /// Provider account or tenant.
        account_or_tenant: String,
        /// Globally qualified provider network id.
        resource_id: String,
    },
    /// A provider-qualified tunnel identity.
    Tunnel {
        /// Lowercase provider kind.
        provider: String,
        /// Provider account or tenant.
        account_or_tenant: String,
        /// Globally qualified provider resource id.
        resource_id: String,
    },
    /// An owner-scoped logical source-allowlist identity.
    SourceAllowlist {
        /// Stable logical id within the owner scope.
        logical_id: String,
    },
    /// A provider-qualified trusted layer-7 ingress listener.
    TrustedIngress {
        /// Lowercase provider kind.
        provider: String,
        /// Provider account or tenant.
        account_or_tenant: String,
        /// Globally qualified provider listener id.
        listener_id: String,
    },
}

impl NetworkPolicyIdentitySpec {
    /// Returns the canonical RFC-0012 kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Vpn { .. } => "vpn",
            Self::Vpc { .. } => "vpc",
            Self::Tunnel { .. } => "tunnel",
            Self::SourceAllowlist { .. } => "source_allowlist",
            Self::TrustedIngress { .. } => "trusted_ingress",
        }
    }

    fn validate(&self, owner_scope_key: &str) -> Result<()> {
        match self {
            Self::Public => Ok(()),
            Self::Vpn {
                provider,
                account_or_tenant,
                resource_id,
            }
            | Self::Vpc {
                provider,
                account_or_tenant,
                resource_id,
            }
            | Self::Tunnel {
                provider,
                account_or_tenant,
                resource_id,
            } => {
                validate_provider_token(provider)?;
                validate_account_or_tenant_token(account_or_tenant)?;
                validate_identity_string(resource_id, "provider resource id")
            }
            Self::SourceAllowlist { logical_id } => {
                validate_scope(owner_scope_key)?;
                validate_identity_string(logical_id, "source allowlist id")
            }
            Self::TrustedIngress {
                provider,
                account_or_tenant,
                listener_id,
            } => {
                validate_provider_token(provider)?;
                validate_account_or_tenant_token(account_or_tenant)?;
                validate_identity_string(listener_id, "provider listener id")
            }
        }
    }

    fn fingerprint(&self, owner_scope_key: &str) -> Result<[u8; 32]> {
        self.validate(owner_scope_key)?;
        let mut hasher = Sha256::new();
        hasher.update(b"aos-hub-network-boundary-v1\0");
        match self {
            Self::Public => hasher.update([0x00]),
            Self::Vpn {
                provider,
                account_or_tenant,
                resource_id,
            } => {
                hasher.update([0x01]);
                hash_string(&mut hasher, provider);
                hash_string(&mut hasher, account_or_tenant);
                hash_string(&mut hasher, resource_id);
            }
            Self::Vpc {
                provider,
                account_or_tenant,
                resource_id,
            } => {
                hasher.update([0x02]);
                hash_string(&mut hasher, provider);
                hash_string(&mut hasher, account_or_tenant);
                hash_string(&mut hasher, resource_id);
            }
            Self::Tunnel {
                provider,
                account_or_tenant,
                resource_id,
            } => {
                hasher.update([0x03]);
                hash_string(&mut hasher, provider);
                hash_string(&mut hasher, account_or_tenant);
                hash_string(&mut hasher, resource_id);
            }
            Self::SourceAllowlist { logical_id } => {
                hasher.update([0x04]);
                hash_string(&mut hasher, owner_scope_key);
                hash_string(&mut hasher, logical_id);
            }
            Self::TrustedIngress {
                provider,
                account_or_tenant,
                listener_id,
            } => {
                hasher.update([0x05]);
                hash_string(&mut hasher, provider);
                hash_string(&mut hasher, account_or_tenant);
                hash_string(&mut hasher, listener_id);
            }
        }
        Ok(hasher.finalize().into())
    }
}

/// A stable typed network-realm identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyRecord {
    /// Stable public id.
    pub id: String,
    /// Owning organization database id, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Exact owner scope.
    pub owner_scope_key: String,
    /// Owner-local display name.
    pub name: String,
    /// Closed identity kind.
    pub kind: String,
    /// Canonical non-secret typed identity JSON.
    pub identity_spec_json: String,
    /// RFC-0012 identity fingerprint.
    pub identity_fingerprint: String,
    /// Default active revision for new plans.
    pub default_revision: Option<i64>,
    /// State asserted by the composite default-revision foreign key.
    pub default_revision_state: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last pointer or metadata update in Unix seconds.
    pub updated_at: i64,
}

/// Desired immutable protection configuration for a boundary revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyRevisionSpec {
    /// Whether protected transport is mandatory.
    pub protected_transport_required: bool,
    /// `none`, `mtls`, or `signed_assertion`.
    pub trusted_ingress_kind: String,
    /// Canonical typed trusted-ingress configuration.
    pub trusted_ingress_configuration: String,
    /// Canonical CIDR list, serialized as a JSON array.
    pub source_allowlist_cidrs: Option<String>,
    /// Canonical probe-location configuration reference.
    pub probe_location_configuration: String,
}

/// One immutable boundary revision with independent observation and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyRevisionRecord {
    /// Stable boundary id.
    pub boundary_id: String,
    /// Monotonic boundary-local revision.
    pub revision: i64,
    /// Immutable desired configuration.
    pub spec: NetworkPolicyRevisionSpec,
    /// Immutable content digest.
    pub content_digest: String,
    /// Actor that created the revision.
    pub created_by: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Observation state.
    pub observation_state: String,
    /// Whether protected transport was observed.
    pub protected_transport_observed: bool,
    /// Observed trusted-ingress posture.
    pub trusted_ingress_observed: String,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
    /// Redacted observation error.
    pub observation_error: Option<String>,
    /// `staged`, `activating`, `active`, `retiring`, or `retired`.
    pub lifecycle_state: String,
    /// `overlap`, `coordinated`, or `system`.
    pub activation_mode: String,
    /// Monotonic live-consumer fence.
    pub consumer_version: i64,
    /// Activation time in Unix seconds.
    pub activated_at: Option<i64>,
    /// Retirement time in Unix seconds.
    pub retired_at: Option<i64>,
    /// Lifecycle optimistic-concurrency version.
    pub resource_version: i64,
}

/// Plan-sealed state required to change a boundary's default revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyDefaultCas {
    /// Boundary resource version observed by the plan.
    pub boundary_resource_version: i64,
    /// Previous default revision observed by the plan, if one existed.
    pub previous_revision: Option<i64>,
    /// Previous default-pointer resource version, paired with `previous_revision`.
    pub previous_resource_version: Option<i64>,
}

/// A typed endpoint host supplied to endpoint creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHostInput {
    /// Stable delivery-domain id.
    Domain(String),
    /// Canonical four-byte IPv4 address.
    Ipv4([u8; 4]),
    /// Canonical sixteen-byte IPv6 address.
    Ipv6([u8; 16]),
}

/// Typed endpoint identity and desired generation pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    /// Stable public id.
    pub id: String,
    /// Owning organization database id, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Exact owner scope.
    pub owner_scope_key: String,
    /// `http` or `https`.
    pub scheme: String,
    /// Internal DNS-domain database id.
    pub domain_id: Option<i64>,
    /// Stable DNS-domain id exposed by the API.
    pub domain_stable_id: Option<String>,
    /// Canonical four-byte IPv4 address.
    pub ipv4_bytes: Option<Vec<u8>>,
    /// Canonical sixteen-byte IPv6 address.
    pub ipv6_bytes: Option<Vec<u8>>,
    /// Effective port, including scheme defaults.
    pub effective_port: i64,
    /// Stable boundary identity.
    pub network_policy_id: String,
    /// Durable cleartext acknowledgement time.
    pub cleartext_acknowledged_at: Option<i64>,
    /// Desired immutable generation.
    pub desired_generation: Option<i64>,
    /// Digest of immutable endpoint identity.
    pub endpoint_identity_digest: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last desired-generation or observation change in Unix seconds.
    pub updated_at: i64,
}

/// Desired immutable listener configuration for an endpoint generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRevisionSpec {
    /// Exact boundary revision.
    pub boundary_revision: i64,
    /// `hub`, `external`, or `layer7`.
    pub ingress_kind: String,
    /// Canonical listener configuration reference.
    pub listener_configuration: String,
    /// Canonical typed TLS configuration.
    pub tls_configuration: String,
    /// Canonical probe configuration reference.
    pub probe_configuration: String,
}

/// Immutable signing identity installed at one endpoint generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProbeSigningIdentity {
    /// Closed secret-provider implementation (`native_file`, `worker_secret`, or `external`).
    pub provider: String,
    /// Provider-owned opaque reference to the generation's private signing seed.
    pub signer_secret_ref: String,
    /// Base64url-no-padding Ed25519 public key pinned by the control plane.
    pub public_key: String,
}

/// One immutable endpoint generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRevisionRecord {
    /// Stable endpoint id.
    pub endpoint_id: String,
    /// Monotonic endpoint-local generation.
    pub generation: i64,
    /// Stable boundary id.
    pub network_policy_id: String,
    /// Exact boundary revision.
    pub boundary_revision: i64,
    /// Immutable desired configuration.
    pub spec: EndpointRevisionSpec,
    /// Immutable content digest.
    pub content_digest: String,
    /// Actor that created the generation.
    pub created_by: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
}

/// One sealed grant copied from the previous endpoint generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointGrantCarryForward {
    /// Exact non-owner consumer scope to copy.
    pub consumer_scope_key: String,
    /// Grant generation observed on the previous endpoint generation.
    pub grant_generation: i64,
    /// Resource version observed on the previous endpoint generation grant.
    pub resource_version: i64,
}

/// One exact dependent resource pinned to an endpoint generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointImpactRecord {
    /// Closed dependent kind: `route`, `gateway`, or `topology_default`.
    pub resource_kind: String,
    /// Stable dependent identity or scope key.
    pub stable_id: String,
    /// Exact dependent/endpoint generation.
    pub generation: i64,
    /// Optimistic-concurrency version of the dependent identity.
    pub resource_version: i64,
}

/// The latest endpoint-controller observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointObservationRecord {
    /// Stable endpoint id.
    pub endpoint_id: String,
    /// Exact observed generation, or `None` while unknown.
    pub observed_generation: Option<i64>,
    /// Stable boundary id.
    pub boundary_id: String,
    /// Exact observed boundary revision, or `None` while unknown.
    pub boundary_revision: Option<i64>,
    /// `unknown`, `declared`, `probing`, `healthy`, `degraded`, or `failed`.
    pub state: String,
    /// Whether the listener was observed.
    pub listener_observed: bool,
    /// Whether exact TLS endpoint identity was observed.
    pub tls_observed: bool,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
    /// Redacted controller error.
    pub error: Option<String>,
}

/// One live pin preventing a boundary revision from retiring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyServingPinRecord {
    /// Stable pin id.
    pub pin_id: String,
    /// Boundary id.
    pub boundary_id: String,
    /// Exact boundary revision.
    pub revision: i64,
    /// Authorized consuming scope.
    pub consumer_scope_key: String,
    /// Exact grant generation.
    pub grant_generation: i64,
    /// Typed use of the boundary.
    pub usage_kind: String,
    /// Typed consumer resource.
    pub target_kind: String,
    /// Stable target id.
    pub target_stable_id: String,
    /// Exact target generation, or zero for stable targets.
    pub target_generation_key: i64,
    /// Immutable target configuration digest.
    pub target_configuration_digest: String,
    /// Actor that acquired the pin.
    pub acquired_by: String,
    /// Acquisition time in Unix seconds.
    pub acquired_at: i64,
}

/// One exact, plan-sealed action for a live boundary serving pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyPinResolutionSeal {
    /// Full immutable source-pin identity observed while planning.
    pub source: NetworkPolicyServingPinRecord,
    /// `move_endpoint`, `replace_route`, or `release`.
    pub action_kind: String,
    /// Exact optimistic-concurrency version of the source target.
    pub source_resource_version: i64,
    /// Replacement target kind when the action moves traffic.
    pub replacement_target_kind: Option<String>,
    /// Replacement stable identity when the action moves traffic.
    pub replacement_target_stable_id: Option<String>,
    /// Exact immutable replacement generation.
    pub replacement_target_generation_key: Option<i64>,
    /// Exact immutable replacement configuration digest.
    pub replacement_target_configuration_digest: Option<String>,
    /// Exact optimistic-concurrency version of the replacement target.
    pub replacement_resource_version: Option<i64>,
}

/// One durable controller job resolving an exact coordinated-activation pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPinResolutionJobRecord {
    /// Parent topology operation.
    pub operation_id: String,
    /// Exact source pin.
    pub pin_id: String,
    /// `move_endpoint`, `replace_route`, or `release`.
    pub action_kind: String,
    /// Exact source boundary identity.
    pub source_boundary_id: String,
    /// Exact source boundary revision.
    pub source_boundary_revision: i64,
    /// Consumer scope authorized by the source grant.
    pub source_consumer_scope_key: String,
    /// Exact source grant generation.
    pub source_grant_generation: i64,
    /// Typed boundary use.
    pub source_usage_kind: String,
    /// `endpoint` or `route`.
    pub source_target_kind: String,
    /// Stable source target id.
    pub source_target_stable_id: String,
    /// Exact immutable source generation.
    pub source_target_generation_key: i64,
    /// Exact immutable source digest.
    pub source_target_configuration_digest: String,
    /// Source target optimistic-concurrency version.
    pub source_target_resource_version: i64,
    /// Replacement kind, when present.
    pub replacement_target_kind: Option<String>,
    /// Replacement id, when present.
    pub replacement_target_stable_id: Option<String>,
    /// Replacement generation, when present.
    pub replacement_target_generation_key: Option<i64>,
    /// Replacement digest, when present.
    pub replacement_target_configuration_digest: Option<String>,
    /// Replacement optimistic-concurrency version, when present.
    pub replacement_target_resource_version: Option<i64>,
    /// Durable job state.
    pub state: String,
    /// Number of controller claims.
    pub attempt: i64,
    /// Redacted terminal error.
    pub error: Option<String>,
    /// Job optimistic-concurrency version.
    pub resource_version: i64,
}

/// Exact old-revision lifecycle state fenced by coordinated activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyCoordinationRevisionSeal {
    /// Old boundary revision containing live consumers.
    pub revision: i64,
    /// Lifecycle state observed by the plan.
    pub lifecycle_state: String,
    /// Exact lifecycle resource version.
    pub resource_version: i64,
    /// Exact consumer-acquisition fence version.
    pub consumer_version: i64,
    /// Immutable old-revision configuration digest.
    pub content_digest: String,
}

fn validate_stable_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        bail!("{field} must contain 1..=64 bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        bail!("{field} contains an unsupported character");
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    if crate::domain::Scope::is_canonical(scope) {
        Ok(())
    } else {
        bail!("scope must be an immutable instance, organization, or project scope")
    }
}

fn validate_provider_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!("provider kind must be a lowercase ASCII token");
    }
    Ok(())
}

fn validate_account_or_tenant_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        bail!("provider account or tenant must be a lowercase ASCII token");
    }
    Ok(())
}

fn validate_identity_string(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        bail!("{field} must contain 1..=512 non-control UTF-8 bytes");
    }
    if value.nfc().collect::<String>() != value {
        bail!("{field} must use NFC normalization");
    }
    Ok(())
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("serializing canonical delivery identity")
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn normalize_hostname(hostname: &str) -> Result<String> {
    if hostname.contains(':') {
        bail!("delivery domain hostname must not include an explicit port");
    }
    let origin = EndpointOrigin::parse(&format!("https://{hostname}"))
        .context("normalizing delivery domain hostname")?;
    match origin.host() {
        DeliveryHost::Dns(name) => Ok(name.clone()),
        DeliveryHost::Ipv4(_) | DeliveryHost::Ipv6(_) => {
            bail!("delivery domain hostname must be DNS, not an IP literal")
        }
    }
}

fn normalize_page_size(page_size: u32) -> i64 {
    i64::from(page_size.clamp(1, 200))
}

fn row_to_domain(row: &Row) -> Result<DeliveryDomainRecord> {
    Ok(DeliveryDomainRecord {
        id: row.get(0)?,
        stable_id: row.get(1)?,
        org_id: row.get(2)?,
        owner_scope_key: row.get(3)?,
        hostname: row.get(4)?,
        dns_configuration_json: row.get(5)?,
        dns_state: row.get(6)?,
        certificate_configuration_json: row.get(7)?,
        certificate_state: row.get(8)?,
        verified_at: row.get(9)?,
        observed_at: row.get(10)?,
        observation_error: row.get(11)?,
        observation_digest: row.get(12)?,
        probe_location: row.get(13)?,
        resource_version: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

fn row_to_boundary(row: &Row) -> Result<NetworkPolicyRecord> {
    Ok(NetworkPolicyRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        owner_scope_key: row.get(2)?,
        name: row.get(3)?,
        kind: row.get(4)?,
        identity_spec_json: row.get(5)?,
        identity_fingerprint: row.get(6)?,
        default_revision: row.get(7)?,
        default_revision_state: row.get(8)?,
        resource_version: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn row_to_boundary_revision(row: &Row) -> Result<NetworkPolicyRevisionRecord> {
    Ok(NetworkPolicyRevisionRecord {
        boundary_id: row.get(0)?,
        revision: row.get(1)?,
        spec: NetworkPolicyRevisionSpec {
            protected_transport_required: row.get(2)?,
            trusted_ingress_kind: row.get(3)?,
            trusted_ingress_configuration: row.get(4)?,
            source_allowlist_cidrs: row.get(5)?,
            probe_location_configuration: row.get(6)?,
        },
        content_digest: row.get(7)?,
        created_by: row.get(8)?,
        created_at: row.get(9)?,
        observation_state: row.get(10)?,
        protected_transport_observed: row.get(11)?,
        trusted_ingress_observed: row.get(12)?,
        observed_at: row.get(13)?,
        observation_error: row.get(14)?,
        lifecycle_state: row.get(15)?,
        activation_mode: row.get(16)?,
        consumer_version: row.get(17)?,
        activated_at: row.get(18)?,
        retired_at: row.get(19)?,
        resource_version: row.get(20)?,
    })
}

fn row_to_endpoint(row: &Row) -> Result<EndpointRecord> {
    Ok(EndpointRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        owner_scope_key: row.get(2)?,
        scheme: row.get(3)?,
        domain_id: row.get(4)?,
        domain_stable_id: row.get(5)?,
        ipv4_bytes: row.get(6)?,
        ipv6_bytes: row.get(7)?,
        effective_port: row.get(8)?,
        network_policy_id: row.get(9)?,
        cleartext_acknowledged_at: row.get(10)?,
        desired_generation: row.get(11)?,
        endpoint_identity_digest: row.get(12)?,
        resource_version: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn row_to_endpoint_revision(row: &Row) -> Result<EndpointRevisionRecord> {
    let ingress_kind = row.get(4)?;
    Ok(EndpointRevisionRecord {
        endpoint_id: row.get(0)?,
        generation: row.get(1)?,
        network_policy_id: row.get(2)?,
        boundary_revision: row.get(3)?,
        spec: EndpointRevisionSpec {
            boundary_revision: row.get(3)?,
            ingress_kind,
            listener_configuration: row.get(5)?,
            tls_configuration: row.get(6)?,
            probe_configuration: row.get(7)?,
        },
        content_digest: row.get(8)?,
        created_by: row.get(9)?,
        created_at: row.get(10)?,
    })
}

fn row_to_pin_resolution_job(row: &Row) -> Result<TopologyPinResolutionJobRecord> {
    Ok(TopologyPinResolutionJobRecord {
        operation_id: row.get(0)?,
        pin_id: row.get(1)?,
        action_kind: row.get(2)?,
        source_boundary_id: row.get(3)?,
        source_boundary_revision: row.get(4)?,
        source_consumer_scope_key: row.get(5)?,
        source_grant_generation: row.get(6)?,
        source_usage_kind: row.get(7)?,
        source_target_kind: row.get(8)?,
        source_target_stable_id: row.get(9)?,
        source_target_generation_key: row.get(10)?,
        source_target_configuration_digest: row.get(11)?,
        source_target_resource_version: row.get(12)?,
        replacement_target_kind: row.get(13)?,
        replacement_target_stable_id: row.get(14)?,
        replacement_target_generation_key: row.get(15)?,
        replacement_target_configuration_digest: row.get(16)?,
        replacement_target_resource_version: row.get(17)?,
        state: row.get(18)?,
        attempt: row.get(19)?,
        error: row.get(20)?,
        resource_version: row.get(21)?,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MtlsTrustedIngressConfiguration {
    ca_secret_ref: String,
    client_sans: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAssertionTrustedIngressConfiguration {
    issuer: String,
    audience: String,
    verification_key_secret_ref: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointTlsConfiguration {
    provider: String,
    certificate_ref: String,
    require_client_certificate: bool,
}

fn validate_boundary_revision_spec(spec: &NetworkPolicyRevisionSpec) -> Result<()> {
    if !matches!(
        spec.trusted_ingress_kind.as_str(),
        "none" | "mtls" | "signed_assertion"
    ) {
        bail!("invalid trusted-ingress kind");
    }
    match spec.trusted_ingress_kind.as_str() {
        "none" if spec.trusted_ingress_configuration == "{}" => {}
        "none" => bail!("trusted-ingress kind 'none' requires an empty configuration object"),
        "mtls" => {
            let configuration: MtlsTrustedIngressConfiguration =
                serde_json::from_str(&spec.trusted_ingress_configuration)
                    .context("mTLS configuration has an invalid or unknown field")?;
            validate_identity_string(&configuration.ca_secret_ref, "mTLS CA secret reference")?;
            for san in &configuration.client_sans {
                validate_identity_string(san, "mTLS client SAN")?;
            }
            if canonical_json(&configuration)? != spec.trusted_ingress_configuration {
                bail!("mTLS configuration must use the exact canonical field projection");
            }
        }
        "signed_assertion" => {
            let configuration: SignedAssertionTrustedIngressConfiguration =
                serde_json::from_str(&spec.trusted_ingress_configuration)
                    .context("signed-assertion configuration has an invalid or unknown field")?;
            validate_identity_string(&configuration.issuer, "signed-assertion issuer")?;
            validate_identity_string(&configuration.audience, "signed-assertion audience")?;
            validate_identity_string(
                &configuration.verification_key_secret_ref,
                "signed-assertion verification-key secret reference",
            )?;
            if canonical_json(&configuration)? != spec.trusted_ingress_configuration {
                bail!(
                    "signed-assertion configuration must use the exact canonical field projection"
                );
            }
        }
        _ => bail!("invalid trusted-ingress kind"),
    }
    validate_identity_string(
        &spec.probe_location_configuration,
        "probe-location configuration reference",
    )?;
    if let Some(cidrs) = &spec.source_allowlist_cidrs {
        let values: Vec<String> =
            serde_json::from_str(cidrs).context("source allowlist must be a JSON string array")?;
        let canonical = canonicalize_cidrs(&values)?;
        if canonical_json(&canonical)? != *cidrs {
            bail!("source allowlist CIDRs must use canonical sorted JSON spelling");
        }
    }
    Ok(())
}

fn canonicalize_cidrs(values: &[String]) -> Result<Vec<String>> {
    Ok(parse_cidrs(values)?
        .into_iter()
        .map(|cidr| cidr.rendered)
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalCidr {
    family: u8,
    network_bytes: Vec<u8>,
    prefix_length: u8,
    rendered: String,
}

fn parse_cidrs(values: &[String]) -> Result<Vec<CanonicalCidr>> {
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        let (address, prefix) = value
            .split_once('/')
            .context("source allowlist CIDR requires a prefix length")?;
        let address: IpAddr = address
            .parse()
            .context("invalid source allowlist address")?;
        let prefix: u8 = prefix.parse().context("invalid source allowlist prefix")?;
        let normalized = match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                let network = Ipv4Addr::from(u32::from(address) & mask);
                CanonicalCidr {
                    family: 0x04,
                    network_bytes: network.octets().to_vec(),
                    prefix_length: prefix,
                    rendered: format!("{network}/{prefix}"),
                }
            }
            IpAddr::V6(address) if prefix <= 128 && address.to_ipv4_mapped().is_none() => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                let network = Ipv6Addr::from(u128::from(address) & mask);
                CanonicalCidr {
                    family: 0x06,
                    network_bytes: network.octets().to_vec(),
                    prefix_length: prefix,
                    rendered: format!("{network}/{prefix}"),
                }
            }
            IpAddr::V4(_) | IpAddr::V6(_) => bail!("invalid or mapped source allowlist CIDR"),
        };
        canonical.push(normalized);
    }
    canonical.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.network_bytes.cmp(&right.network_bytes))
            .then_with(|| left.prefix_length.cmp(&right.prefix_length))
    });
    canonical.dedup_by(|left, right| {
        left.family == right.family
            && left.network_bytes == right.network_bytes
            && left.prefix_length == right.prefix_length
    });
    Ok(canonical)
}

fn network_policy_revision_digest(
    boundary_fingerprint: &[u8; 32],
    spec: &NetworkPolicyRevisionSpec,
) -> Result<String> {
    validate_boundary_revision_spec(spec)?;
    let cidrs = match &spec.source_allowlist_cidrs {
        Some(value) => {
            let values: Vec<String> = serde_json::from_str(value)
                .context("source allowlist must be a JSON string array")?;
            parse_cidrs(&values)?
        }
        None => Vec::new(),
    };
    let trusted_ingress_tag = match spec.trusted_ingress_kind.as_str() {
        "none" => 0x00,
        "mtls" => 0x01,
        "signed_assertion" => 0x02,
        _ => bail!("invalid trusted-ingress kind"),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"aos-hub-network-boundary-revision-v1\0");
    hasher.update(boundary_fingerprint);
    hasher.update([u8::from(spec.protected_transport_required)]);
    hasher.update([trusted_ingress_tag]);
    hash_string(&mut hasher, &spec.trusted_ingress_configuration);
    hasher.update((cidrs.len() as u32).to_be_bytes());
    for cidr in cidrs {
        hasher.update([cidr.family, cidr.prefix_length]);
        hasher.update(cidr.network_bytes);
    }
    hash_string(&mut hasher, &spec.probe_location_configuration);
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn validate_endpoint_revision_spec(spec: &EndpointRevisionSpec) -> Result<()> {
    if spec.boundary_revision <= 0 {
        bail!("endpoint boundary revision must be positive");
    }
    if !matches!(spec.ingress_kind.as_str(), "hub" | "external" | "layer7") {
        bail!("invalid endpoint ingress kind");
    }
    validate_identity_string(
        &spec.listener_configuration,
        "listener configuration reference",
    )?;
    let probe: EndpointProbeSigningIdentity = serde_json::from_str(&spec.probe_configuration)
        .context("probe configuration has an invalid, missing, or unknown field")?;
    if !matches!(
        probe.provider.as_str(),
        "native_file" | "worker_secret" | "external"
    ) {
        bail!("invalid endpoint probe signer provider");
    }
    validate_identity_string(&probe.signer_secret_ref, "probe signer secret reference")?;
    let public_key = URL_SAFE_NO_PAD
        .decode(&probe.public_key)
        .context("endpoint probe public key is not base64url")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("endpoint probe public key must contain 32 bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .context("endpoint probe public key is invalid")?;
    if canonical_json(&probe)? != spec.probe_configuration {
        bail!("probe configuration must use the exact canonical field projection");
    }
    if spec.tls_configuration != "{}" {
        let tls: EndpointTlsConfiguration = serde_json::from_str(&spec.tls_configuration)
            .context("TLS configuration has an invalid, missing, or unknown field")?;
        validate_provider_token(&tls.provider)?;
        validate_identity_string(&tls.certificate_ref, "TLS certificate reference")?;
        if canonical_json(&tls)? != spec.tls_configuration {
            bail!("TLS configuration must use the exact canonical field projection");
        }
    }
    Ok(())
}

impl Database {
    /// Resolves the one HTTPS/443 terminator identity pinned for a domain.
    ///
    /// # Errors
    ///
    /// Returns an error when zero or multiple desired terminators exist, the
    /// immutable probe configuration is malformed, or persistence fails.
    pub async fn domain_probe_signing_identity(
        &self,
        domain_id: i64,
    ) -> Result<(String, i64, EndpointProbeSigningIdentity)> {
        let rows = self
            .backend
            .query(
                "SELECT endpoint.id, revision.generation, revision.probe_configuration
               FROM endpoints endpoint
               JOIN endpoint_revisions revision
                 ON revision.endpoint_id = endpoint.id
                AND revision.generation = endpoint.desired_generation
              WHERE endpoint.domain_id = ?1 AND endpoint.scheme = 'https'
                AND endpoint.effective_port = 443",
                &vals![domain_id],
            )
            .await?;
        if rows.len() != 1 {
            bail!("domain verification requires exactly one desired HTTPS/443 terminator");
        }
        let endpoint_id: String = rows[0].get(0)?;
        let generation: i64 = rows[0].get(1)?;
        let configuration: String = rows[0].get(2)?;
        let identity = serde_json::from_str(&configuration)
            .context("endpoint probe signing identity is malformed")?;
        Ok((endpoint_id, generation, identity))
    }

    /// Issues or recovers one random, durable probe challenge.
    ///
    /// The operation/generation/attempt tuple is the idempotency key. A retry
    /// after a controller crash recovers the same unexpired challenge, while a
    /// later attempt receives independent randomness. No challenge is derived
    /// from replayable topology state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid attempt, a missing endpoint generation,
    /// inconsistent persisted state, or database failure.
    pub async fn issue_domain_probe_challenge(
        &self,
        operation_id: &str,
        target_generation: i64,
        attempt: u8,
        endpoint_id: &str,
        endpoint_generation: i64,
        now: i64,
    ) -> Result<String> {
        if operation_id.is_empty() || target_generation <= 0 || endpoint_generation <= 0 {
            bail!("domain probe challenge identity is invalid");
        }
        if attempt >= 3 {
            bail!("domain probe attempt must be less than three");
        }
        self.backend
            .execute(
                "DELETE FROM domain_probe_challenges WHERE expires_at <= ?1",
                &vals![now],
            )
            .await?;
        let random: [u8; 32] = rand::rng().random();
        let candidate = URL_SAFE_NO_PAD.encode(random);
        self.backend
            .execute(
                "INSERT INTO domain_probe_challenges
                 (operation_id, target_generation, attempt, nonce, endpoint_id,
                  endpoint_generation, issued_at, expires_at)
                 SELECT ?1, ?2, ?3, ?4, revision.endpoint_id, revision.generation, ?7, ?8
                   FROM endpoint_revisions revision
                  WHERE revision.endpoint_id = ?5 AND revision.generation = ?6
                 ON CONFLICT(operation_id, target_generation, attempt) DO NOTHING",
                &vals![
                    operation_id,
                    target_generation,
                    i64::from(attempt),
                    candidate,
                    endpoint_id,
                    endpoint_generation,
                    now,
                    now + 120
                ],
            )
            .await?;
        let row = self
            .backend
            .query_opt(
                "SELECT nonce, endpoint_id, endpoint_generation, expires_at
                   FROM domain_probe_challenges
                  WHERE operation_id = ?1 AND target_generation = ?2 AND attempt = ?3",
                &vals![operation_id, target_generation, i64::from(attempt)],
            )
            .await?
            .context("domain probe endpoint generation does not exist")?;
        let persisted_endpoint_id: String = row.get(1)?;
        let persisted_endpoint_generation: i64 = row.get(2)?;
        let expires_at: i64 = row.get(3)?;
        if persisted_endpoint_id != endpoint_id
            || persisted_endpoint_generation != endpoint_generation
            || expires_at <= now
        {
            bail!("persisted domain probe challenge does not match current desired state");
        }
        row.get(0)
    }

    /// Consumes one controller-issued challenge exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn consume_domain_probe_nonce(
        &self,
        nonce: &str,
        endpoint_id: &str,
        endpoint_generation: i64,
        now: i64,
    ) -> Result<bool> {
        self.backend
            .execute(
                "DELETE FROM domain_probe_challenges WHERE expires_at <= ?1",
                &vals![now],
            )
            .await?;
        let changed = self
            .backend
            .execute(
                "DELETE FROM domain_probe_challenges
                  WHERE nonce = ?1 AND endpoint_id = ?2 AND endpoint_generation = ?3
                    AND expires_at > ?4",
                &vals![nonce, endpoint_id, endpoint_generation, now],
            )
            .await?;
        Ok(changed == 1)
    }

    async fn validate_owner_scope_binding(
        &self,
        owner_scope_key: &str,
        org_id: Option<i64>,
    ) -> Result<()> {
        validate_scope(owner_scope_key)?;
        match (owner_scope_key, org_id) {
            ("instance", None) => Ok(()),
            ("instance", Some(_)) | (_, None) => {
                bail!("instance scope cannot have an org id and organization scope requires one")
            }
            (scope, Some(org_id)) => {
                let scope_exists = self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM authorization_scopes a JOIN orgs o ON o.id = a.org_id
                         WHERE a.scope_key = ?1 AND a.org_id = ?2 AND o.deleted_at IS NULL",
                        &vals![scope, org_id],
                    )
                    .await?;
                if scope_exists.is_none() {
                    bail!(
                        "owner scope does not identify a live scope in the supplied organization"
                    );
                }
                Ok(())
            }
        }
    }

    async fn verified_active_boundary_consumer_version(
        &self,
        boundary_id: &str,
        revision: i64,
    ) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT l.consumer_version FROM network_policy_revision_lifecycle l
                 JOIN network_policy_observations o
                   ON o.boundary_id = l.boundary_id AND o.revision = l.revision
                 JOIN network_policy_revisions r
                   ON r.boundary_id = l.boundary_id AND r.revision = l.revision
                 WHERE l.boundary_id = ?1 AND l.revision = ?2
                   AND l.state = 'active' AND o.state = 'verified'
                   AND o.protected_transport_observed = r.protected_transport_required
                   AND o.trusted_ingress_observed = r.trusted_ingress_kind",
                &vals![boundary_id, revision],
            )
            .await?
            .context("boundary revision is not active and verified")?
            .get(0)
    }

    async fn releasable_boundary_consumer_version(
        &self,
        boundary_id: &str,
        revision: i64,
    ) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT consumer_version FROM network_policy_revision_lifecycle
                 WHERE boundary_id = ?1 AND revision = ?2
                   AND state IN ('active', 'retiring')",
                &vals![boundary_id, revision],
            )
            .await?
            .context("boundary revision is not active or retiring")?
            .get(0)
    }

    /// Creates an immutable-hostname delivery domain.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid owner/hostname, a duplicate hostname,
    /// or a database failure.
    pub async fn create_delivery_domain(
        &self,
        owner_scope_key: &str,
        org_id: Option<i64>,
        hostname: &str,
        creation_plan_id: &str,
    ) -> Result<DeliveryDomainRecord> {
        self.validate_owner_scope_binding(owner_scope_key, org_id)
            .await?;
        let hostname = normalize_hostname(hostname)?;
        validate_identity_string(creation_plan_id, "domain creation plan id")?;
        let stable_id = format!("domain:{}", Uuid::new_v4().simple());
        let now = unix_now();
        let id = self
            .backend
            .execute_insert(
                "INSERT INTO domains (stable_id, org_id, owner_scope_key, hostname,
                 creation_plan_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                &vals![
                    stable_id,
                    org_id,
                    owner_scope_key,
                    hostname,
                    creation_plan_id,
                    now
                ],
            )
            .await?;
        self.delivery_domain_by_database_id(id)
            .await?
            .context("created domain disappeared")
    }

    /// Finds the exact domain created by one immutable control plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname or database failure.
    pub async fn delivery_domain_created_by_plan(
        &self,
        creation_plan_id: &str,
        owner_scope_key: &str,
        org_id: Option<i64>,
        hostname: &str,
    ) -> Result<Option<DeliveryDomainRecord>> {
        let hostname = normalize_hostname(hostname)?;
        self.backend
            .query_opt(
                &format!(
                    "SELECT {DOMAIN_COLUMNS} FROM domains d
                     WHERE d.creation_plan_id = ?1 AND d.owner_scope_key = ?2
                       AND (d.org_id = ?3 OR (d.org_id IS NULL AND ?3 IS NULL))
                       AND d.hostname = ?4"
                ),
                &vals![creation_plan_id, owner_scope_key, org_id, hostname],
            )
            .await?
            .as_ref()
            .map(row_to_domain)
            .transpose()
    }

    /// Returns a delivery domain by stable id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_domain(&self, stable_id: &str) -> Result<Option<DeliveryDomainRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {DOMAIN_COLUMNS} FROM domains d WHERE d.stable_id = ?1"),
                &vals![stable_id],
            )
            .await?
            .as_ref()
            .map(row_to_domain)
            .transpose()
    }

    /// Returns a delivery domain by its globally unique canonical hostname.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname or database failure.
    pub async fn delivery_domain_by_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<DeliveryDomainRecord>> {
        let hostname = normalize_hostname(hostname)?;
        self.backend
            .query_opt(
                &format!("SELECT {DOMAIN_COLUMNS} FROM domains d WHERE d.hostname = ?1"),
                &vals![hostname],
            )
            .await?
            .as_ref()
            .map(row_to_domain)
            .transpose()
    }

    async fn delivery_domain_by_database_id(
        &self,
        id: i64,
    ) -> Result<Option<DeliveryDomainRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {DOMAIN_COLUMNS} FROM domains d WHERE d.id = ?1"),
                &vals![id],
            )
            .await?
            .as_ref()
            .map(row_to_domain)
            .transpose()
    }

    /// Lists a stable page of domains in one exact owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid scope or database failure.
    pub async fn list_delivery_domains_page(
        &self,
        owner_scope_key: &str,
        page_size: u32,
        after_stable_id: Option<&str>,
    ) -> Result<DeliveryIdentityPage<DeliveryDomainRecord>> {
        validate_scope(owner_scope_key)?;
        let limit = normalize_page_size(page_size);
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {DOMAIN_COLUMNS} FROM domains d
                     WHERE d.owner_scope_key = ?1 AND d.stable_id > ?2
                     ORDER BY d.stable_id LIMIT ?3"
                ),
                &vals![owner_scope_key, after_stable_id.unwrap_or(""), limit + 1],
            )
            .await?;
        let mut records: Vec<_> = rows.iter().map(row_to_domain).collect::<Result<_>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.stable_id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Lists all domains in one exact owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid scope or database failure.
    pub async fn list_delivery_domains(
        &self,
        owner_scope_key: &str,
    ) -> Result<Vec<DeliveryDomainRecord>> {
        validate_scope(owner_scope_key)?;
        self.backend
            .query(
                &format!(
                    "SELECT {DOMAIN_COLUMNS} FROM domains d
                     WHERE d.owner_scope_key = ?1 ORDER BY d.stable_id"
                ),
                &vals![owner_scope_key],
            )
            .await?
            .iter()
            .map(row_to_domain)
            .collect()
    }

    /// Replaces desired DNS configuration under a resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for empty configuration, a stale/missing domain, or a
    /// database failure.
    pub async fn configure_delivery_domain_dns(
        &self,
        stable_id: &str,
        configuration: &DeliveryDnsConfigurationSpec,
        expected_version: i64,
        mutation_plan_id: &str,
    ) -> Result<DeliveryDomainRecord> {
        configuration.validate()?;
        validate_identity_string(mutation_plan_id, "domain mutation plan id")?;
        let configuration_json = canonical_json(configuration)?;
        let changed = self
            .backend
            .execute(
                "UPDATE domains SET dns_configuration_json = ?2,
                 dns_state = 'pending', verified_at = NULL, observed_at = NULL,
                 observation_error = NULL, observation_digest = NULL,
                 probe_location = NULL, resource_version = resource_version + 1,
                 last_mutation_plan_id = ?5,
                 updated_at = ?4 WHERE stable_id = ?1 AND resource_version = ?3",
                &vals![
                    stable_id,
                    configuration_json,
                    expected_version,
                    unix_now(),
                    mutation_plan_id
                ],
            )
            .await?;
        if changed != 1 {
            bail!("domain is missing or stale");
        }
        self.delivery_domain(stable_id)
            .await?
            .context("updated domain disappeared")
    }

    /// Replaces desired certificate configuration under a resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for empty configuration, a stale/missing domain, or a
    /// database failure.
    pub async fn configure_delivery_domain_certificate(
        &self,
        stable_id: &str,
        configuration: &DeliveryCertificateConfigurationSpec,
        expected_version: i64,
        mutation_plan_id: &str,
    ) -> Result<DeliveryDomainRecord> {
        configuration.validate()?;
        validate_identity_string(mutation_plan_id, "domain mutation plan id")?;
        let configuration_json = canonical_json(configuration)?;
        let changed = self
            .backend
            .execute(
                "UPDATE domains SET certificate_configuration_json = ?2,
                 certificate_state = 'pending',
                 verified_at = NULL, observed_at = NULL, observation_error = NULL,
                 observation_digest = NULL, probe_location = NULL,
                 resource_version = resource_version + 1, last_mutation_plan_id = ?5,
                 updated_at = ?4
                 WHERE stable_id = ?1 AND resource_version = ?3",
                &vals![
                    stable_id,
                    configuration_json,
                    expected_version,
                    unix_now(),
                    mutation_plan_id
                ],
            )
            .await?;
        if changed != 1 {
            bail!("domain is missing or stale");
        }
        self.delivery_domain(stable_id)
            .await?
            .context("updated domain disappeared")
    }

    /// Checks exact recovery state for a DNS or certificate configuration plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid desired configuration or database failure.
    pub async fn delivery_domain_matches_configuration_plan(
        &self,
        stable_id: &str,
        resulting_resource_version: i64,
        mutation_plan_id: &str,
        dns: Option<&DeliveryDnsConfigurationSpec>,
        certificate: Option<&DeliveryCertificateConfigurationSpec>,
    ) -> Result<bool> {
        if dns.is_some() == certificate.is_some() {
            bail!("exactly one domain configuration family is required");
        }
        let (column, configuration_json) = match (dns, certificate) {
            (Some(configuration), None) => {
                configuration.validate()?;
                ("dns_configuration_json", canonical_json(configuration)?)
            }
            (None, Some(configuration)) => {
                configuration.validate()?;
                (
                    "certificate_configuration_json",
                    canonical_json(configuration)?,
                )
            }
            _ => bail!("exactly one domain configuration family is required"),
        };
        Ok(self
            .backend
            .query_opt(
                &format!(
                    "SELECT 1 FROM domains WHERE stable_id = ?1
                     AND resource_version = ?2 AND last_mutation_plan_id = ?3
                     AND {column} = ?4"
                ),
                &vals![
                    stable_id,
                    resulting_resource_version,
                    mutation_plan_id,
                    configuration_json
                ],
            )
            .await?
            .is_some())
    }

    /// Completes a domain probe and promotes its exact responding endpoint.
    ///
    /// The domain observation, endpoint observation, endpoint resource-version
    /// advance, and any route-probe retries are committed in one checked batch.
    /// This keeps signed evidence bound to the endpoint generation that
    /// produced it and prevents a domain from becoming verified against stale
    /// topology.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, an operation/target mismatch, a
    /// stale domain or endpoint generation, a replayed operation, an outbox
    /// conflict, or a database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_delivery_domain_probe(
        &self,
        operation_id: &str,
        expected_operation_version: i64,
        stable_id: &str,
        dns_state: &str,
        certificate_state: &str,
        error: Option<&str>,
        expected_version: i64,
        evidence_json: &str,
        evidence_digest: &str,
        probe_location: &str,
        observed_at: i64,
        endpoint_id: &str,
        endpoint_generation: i64,
    ) -> Result<DeliveryDomainRecord> {
        if !matches!(
            dns_state,
            "unconfigured" | "pending" | "verified" | "failed"
        ) || !matches!(
            certificate_state,
            "unconfigured" | "pending" | "active" | "failed"
        ) {
            bail!("invalid domain observation state");
        }
        let failed = dns_state == "failed" || certificate_state == "failed";
        if failed != error.is_some() {
            bail!("domain failures require an error and non-failures reject one");
        }
        validate_identity_string(operation_id, "domain probe operation id")?;
        validate_identity_string(probe_location, "domain probe location")?;
        if evidence_digest.len() != 64
            || !evidence_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("domain probe evidence digest must be SHA-256 hex");
        }
        let _: serde_json::Value = serde_json::from_str(evidence_json)
            .context("domain probe evidence must be valid JSON")?;
        if observed_at <= 0 {
            bail!("domain probe observed_at must be positive");
        }
        let current = self
            .delivery_domain(stable_id)
            .await?
            .context("domain does not exist")?;
        if current.resource_version != expected_version {
            bail!("domain is stale");
        }
        let endpoint = self
            .endpoint(endpoint_id)
            .await?
            .context("domain probe endpoint does not exist")?;
        if endpoint.domain_id != Some(current.id)
            || endpoint.desired_generation != Some(endpoint_generation)
        {
            bail!("domain probe endpoint is no longer the desired terminator");
        }
        let endpoint_revision = self
            .endpoint_revision(endpoint_id, endpoint_generation)
            .await?
            .context("domain probe endpoint generation does not exist")?;
        let endpoint_observation = self.endpoint_observation(endpoint_id).await?;
        let promote_endpoint = !endpoint_observation.as_ref().is_some_and(|observation| {
            observation.observed_generation == Some(endpoint_generation)
                && observation.boundary_revision == Some(endpoint_revision.boundary_revision)
                && observation.state == "healthy"
                && observation.listener_observed
                && observation.tls_observed
        });
        let dependent_routes = if promote_endpoint {
            self.backend
                .query(
                    "SELECT r.id, h.configuration_generation, h.configuration_digest,
                            h.access_policy_digest
                       FROM routes r
                       JOIN route_heads h ON h.route_id = r.id
                      WHERE r.endpoint_id = ?1 AND r.endpoint_generation = ?2
                        AND r.enabled = 1
                      ORDER BY r.id",
                    &vals![endpoint_id, endpoint_generation],
                )
                .await?
                .iter()
                .map(|row| {
                    Ok((
                        row.get::<String>(0)?,
                        row.get::<i64>(1)?,
                        row.get::<String>(2)?,
                        row.get::<String>(3)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let now = unix_now();
        let verified_at = if dns_state == "verified" && certificate_state == "active" {
            current.verified_at.or(Some(observed_at))
        } else {
            None
        };
        let endpoint_version_after = endpoint.resource_version + i64::from(promote_endpoint);
        let mut statements = vec![Statement::new(
            "UPDATE topology_operations SET state = 'running'
                 WHERE operation_id = ?1 AND operation_kind = 'domain_probe'
                   AND state = 'running' AND resource_version = ?4
                   AND primary_target_kind = 'domain'
                   AND primary_target_stable_id = ?2
                   AND primary_target_generation_key = ?3",
            vals![
                operation_id,
                stable_id,
                expected_version,
                expected_operation_version
            ],
        )
        .expecting(1)];
        if promote_endpoint {
            let endpoint_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
            let endpoint_event_payload = serde_json::to_string(&serde_json::json!({
                "type": "topology.endpoint.reconciled",
                "resource_kind": "endpoint",
                "resource_stable_id": endpoint_id,
                "resource_generation": endpoint_generation,
                "resource_version": endpoint_version_after,
                "state": "healthy",
            }))?;
            statements.extend([
                Statement::new(
                    "INSERT INTO endpoint_generation_observations
                     (endpoint_id, observed_generation, boundary_id, boundary_revision,
                      state, listener_observed, tls_observed, observed_at, error)
                     SELECT e.id, ?2, e.network_policy_id, ?3, 'healthy', 1, 1, ?4, NULL
                     FROM endpoints e
                     JOIN endpoint_revisions r ON r.endpoint_id = e.id
                       AND r.generation = ?2 AND r.boundary_revision = ?3
                     WHERE e.id = ?1 AND e.resource_version = ?5
                       AND e.domain_id = ?6 AND e.desired_generation = ?2
                     ON CONFLICT(endpoint_id, observed_generation) DO UPDATE SET
                       boundary_id = excluded.boundary_id,
                       boundary_revision = excluded.boundary_revision,
                       state = excluded.state,
                       listener_observed = excluded.listener_observed,
                       tls_observed = excluded.tls_observed,
                       observed_at = CASE
                         WHEN endpoint_generation_observations.observed_at
                           >= excluded.observed_at
                         THEN endpoint_generation_observations.observed_at + 1
                         ELSE excluded.observed_at END,
                       error = NULL",
                    vals![
                        endpoint_id,
                        endpoint_generation,
                        endpoint_revision.boundary_revision,
                        observed_at,
                        endpoint.resource_version,
                        current.id
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoint_observations
                     SET observed_generation = ?2, boundary_revision = ?3,
                         state = 'healthy', listener_observed = 1, tls_observed = 1,
                         observed_at = CASE WHEN observed_at >= ?4
                           THEN observed_at + 1 ELSE ?4 END, error = NULL
                     WHERE endpoint_id = ?1 AND EXISTS (
                       SELECT 1 FROM endpoints e
                       JOIN endpoint_revisions r ON r.endpoint_id = e.id
                         AND r.generation = ?2 AND r.boundary_revision = ?3
                       WHERE e.id = ?1 AND e.resource_version = ?5
                         AND e.domain_id = ?6 AND e.desired_generation = ?2)",
                    vals![
                        endpoint_id,
                        endpoint_generation,
                        endpoint_revision.boundary_revision,
                        observed_at,
                        endpoint.resource_version,
                        current.id
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoints
                     SET resource_version = resource_version + 1, updated_at = ?3
                     WHERE id = ?1 AND resource_version = ?2
                       AND domain_id = ?4 AND desired_generation = ?5",
                    vals![
                        endpoint_id,
                        endpoint.resource_version,
                        now,
                        current.id,
                        endpoint_generation
                    ],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &endpoint_event_id,
                    event_name: "topology.endpoint.reconciled",
                    owner_scope_key: &endpoint.owner_scope_key,
                    resource_kind: "endpoint",
                    resource_stable_id: endpoint_id,
                    resource_generation_key: endpoint_generation,
                    actor_kind: "system",
                    actor_id: None,
                    actor_label: "domain-probe-controller",
                    payload_json: &endpoint_event_payload,
                    occurred_at: now,
                }),
            ]);
            for (route_id, generation, digest, access_policy_digest) in &dependent_routes {
                let route_operation_id = endpoint_ready_route_probe_operation_id(
                    operation_id,
                    route_id,
                    *generation,
                    digest,
                );
                let route_detail = serde_json::json!({
                    "trigger": "endpoint_ready",
                    "deliveryRouteId": route_id,
                    "generation": generation,
                    "configurationDigest": digest,
                    "accessPolicyDigest": access_policy_digest,
                    "endpointId": endpoint_id,
                    "endpointGeneration": endpoint_generation,
                })
                .to_string();
                statements.push(
                    Statement::new(
                        "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind,
                      primary_target_stable_id, primary_target_generation_key,
                      primary_target_configuration_digest, state, progress_total,
                      detail_json, created_at)
                     SELECT ?1, 'route_probe', e.owner_scope_key,
                       'route.manage', 'route', r.id,
                       h.configuration_generation, h.configuration_digest,
                       'pending', 1, ?2, ?3
                     FROM routes r
                     JOIN route_heads h ON h.route_id = r.id
                     JOIN endpoints e ON e.id = r.endpoint_id
                     WHERE r.id = ?4 AND r.enabled = 1
                       AND r.endpoint_id = ?5 AND r.endpoint_generation = ?6
                       AND h.configuration_generation = ?7
                       AND h.configuration_digest = ?8
                       AND e.resource_version = ?9 AND e.desired_generation = ?6",
                        vals![
                            route_operation_id,
                            route_detail,
                            now,
                            route_id,
                            endpoint_id,
                            endpoint_generation,
                            generation,
                            digest,
                            endpoint_version_after
                        ],
                    )
                    .unchecked(),
                );
            }
        }
        statements.extend([
            Statement::new(
                "UPDATE endpoints SET updated_at = updated_at
                 WHERE id = ?1 AND resource_version = ?2
                   AND domain_id = ?3 AND desired_generation = ?4",
                vals![
                    endpoint_id,
                    endpoint_version_after,
                    current.id,
                    endpoint_generation
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO domain_probe_observations
                 (operation_id, domain_id, desired_resource_version, evidence_json,
                  evidence_digest, probe_location, observed_at)
                 SELECT ?1, id, ?3, ?4, ?5, ?6, ?7 FROM domains
                  WHERE stable_id = ?2 AND resource_version = ?3",
                vals![
                    operation_id,
                    stable_id,
                    expected_version,
                    evidence_json,
                    evidence_digest,
                    probe_location,
                    observed_at
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE domains SET dns_state = ?3, certificate_state = ?4,
                   verified_at = ?5, observed_at = ?6, observation_error = ?7,
                   observation_digest = ?8, probe_location = ?9,
                   resource_version = resource_version + 1, updated_at = ?10
                 WHERE stable_id = ?2 AND resource_version = ?1",
                vals![
                    expected_version,
                    stable_id,
                    dns_state,
                    certificate_state,
                    verified_at,
                    observed_at,
                    error,
                    evidence_digest,
                    probe_location,
                    now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE topology_operations SET state = 'succeeded',
                   progress_current = 1, progress_total = 1, detail_json = ?2,
                   finished_at = ?3, resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND state = 'running'
                   AND resource_version = ?4",
                vals![operation_id, evidence_json, now, expected_operation_version],
            )
            .expecting(1),
        ]);
        self.backend.checked_batch(&statements).await?;
        self.delivery_domain(stable_id)
            .await?
            .context("reconciled domain disappeared")
    }

    /// Deletes an unreferenced domain under a resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, missing, or referenced domain, or a
    /// database failure.
    pub async fn delete_delivery_domain(
        &self,
        stable_id: &str,
        expected_version: i64,
    ) -> Result<()> {
        let changed = self
            .backend
            .execute(
                "DELETE FROM domains WHERE stable_id = ?1 AND resource_version = ?2
                   AND NOT EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.state IN ('pending', 'running') AND (
                       (o.primary_target_kind = 'domain'
                         AND o.primary_target_stable_id = ?1)
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                         WHERE t.operation_id = o.operation_id
                           AND t.target_kind = 'domain' AND t.stable_id = ?1)))",
                &vals![stable_id, expected_version],
            )
            .await?;
        if changed != 1 {
            bail!("domain is missing or stale");
        }
        Ok(())
    }

    /// Creates a stable boundary and staged revision one atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid typed identity/revision fields, duplicate
    /// identity, an invalid owner, or a database failure.
    pub async fn create_network_policy(
        &self,
        id: &str,
        owner_scope_key: &str,
        org_id: Option<i64>,
        name: &str,
        identity: &NetworkPolicyIdentitySpec,
        revision: &NetworkPolicyRevisionSpec,
        actor: &str,
        request_id: &str,
    ) -> Result<NetworkPolicyRecord> {
        validate_stable_id(id, "boundary id")?;
        self.validate_owner_scope_binding(owner_scope_key, org_id)
            .await?;
        validate_identity_string(name, "boundary name")?;
        validate_boundary_revision_spec(revision)?;
        if id == "instance:public" {
            bail!("the public boundary singleton is deployment-owned");
        }
        if matches!(identity, NetworkPolicyIdentitySpec::Public) {
            bail!("the public boundary singleton is deployment-owned");
        }
        let identity_json = canonical_json(identity)?;
        let fingerprint = identity.fingerprint(owner_scope_key)?;
        let fingerprint_hex = hex::encode(fingerprint);
        let revision_digest = network_policy_revision_digest(&fingerprint, revision)?;
        let now = unix_now();
        let grant_event_id = format!("grant-event:{}", Uuid::new_v4().simple());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO network_policies (id, org_id, owner_scope_key, name, kind,
                     identity_spec_json, identity_fingerprint, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                    vals![id, org_id, owner_scope_key, name, identity.kind(), identity_json, fingerprint_hex, now],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_revisions (boundary_id, revision,
                     protected_transport_required, trusted_ingress_kind,
                     trusted_ingress_configuration, source_allowlist_cidrs,
                     probe_location_configuration, content_digest, created_by, created_at)
                     VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    vals![id, revision.protected_transport_required, revision.trusted_ingress_kind,
                        revision.trusted_ingress_configuration, revision.source_allowlist_cidrs,
                        revision.probe_location_configuration, revision_digest, actor, now],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_revision_lifecycle
                     (boundary_id, revision, state, activation_mode, consumer_version, resource_version)
                     VALUES (?1, 1, 'staged', 'overlap', 0, 1)",
                    vals![id],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_observations
                     (boundary_id, revision, state, protected_transport_observed,
                      trusted_ingress_observed, observed_at)
                     VALUES (?1, 1, 'unknown', 0, 'none', ?2)",
                    vals![id, now],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_consumer_scopes
                     (boundary_id, consumer_scope_key, grant_generation, grant_kind, state,
                      granted_by, granted_at, resource_version)
                     VALUES (?1, ?2, 1, 'owner', 'active', ?3, ?4, 1)",
                    vals![id, owner_scope_key, actor, now],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id,
                      resource_generation_key, consumer_scope_key, grant_generation,
                      transition, previous_state, resulting_state, actor_id,
                      occurred_at, request_id)
                     SELECT ?1, 'network_policy', ?2, 0, ?3, 1, 'granted',
                       NULL, 'active', ?4, ?5, ?6 WHERE EXISTS (
                         SELECT 1 FROM network_policy_consumer_scopes
                         WHERE boundary_id = ?2 AND consumer_scope_key = ?3
                           AND grant_generation = 1 AND state = 'active')",
                    vals![
                        grant_event_id,
                        id,
                        owner_scope_key,
                        actor,
                        now,
                        request_id
                    ],
                ).expecting(1),
            ])
            .await?;
        self.network_policy(id)
            .await?
            .context("created boundary disappeared")
    }

    /// Returns a stable boundary identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn network_policy(&self, id: &str) -> Result<Option<NetworkPolicyRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {BOUNDARY_COLUMNS} FROM network_policies b
                     LEFT JOIN network_policy_defaults nd ON nd.boundary_id = b.id
                     WHERE b.id = ?1"
                ),
                &vals![id],
            )
            .await?
            .as_ref()
            .map(row_to_boundary)
            .transpose()
    }

    /// Returns the exact boundary/default-pointer state sealed by activation plans.
    ///
    /// A missing pointer is represented by paired `None` fields while the
    /// boundary resource version still fences concurrent pointer creation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn network_policy_default_cas(
        &self,
        id: &str,
    ) -> Result<Option<NetworkPolicyDefaultCas>> {
        self.backend
            .query_opt(
                "SELECT b.resource_version, d.revision, d.resource_version
                   FROM network_policies b
                   LEFT JOIN network_policy_defaults d ON d.boundary_id = b.id
                  WHERE b.id = ?1",
                &vals![id],
            )
            .await?
            .map(|row| {
                Ok(NetworkPolicyDefaultCas {
                    boundary_resource_version: row.get(0)?,
                    previous_revision: row.get(1)?,
                    previous_resource_version: row.get(2)?,
                })
            })
            .transpose()
    }

    /// Lists a stable page of boundaries in one owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid scope or database failure.
    pub async fn list_network_policies_page(
        &self,
        owner_scope_key: &str,
        page_size: u32,
        after_id: Option<&str>,
        include_granted: bool,
    ) -> Result<DeliveryIdentityPage<NetworkPolicyRecord>> {
        validate_scope(owner_scope_key)?;
        let limit = normalize_page_size(page_size);
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BOUNDARY_COLUMNS} FROM network_policies b
                     LEFT JOIN network_policy_defaults nd ON nd.boundary_id = b.id
                     WHERE (b.owner_scope_key = ?1 OR (?4 AND EXISTS (
                         SELECT 1 FROM network_policy_consumer_scopes grant_record
                         WHERE grant_record.boundary_id = b.id
                           AND grant_record.consumer_scope_key = ?1
                           AND grant_record.state = 'active'
                     ))) AND b.id > ?2
                     ORDER BY b.id LIMIT ?3"
                ),
                &vals![
                    owner_scope_key,
                    after_id.unwrap_or(""),
                    limit + 1,
                    include_granted
                ],
            )
            .await?;
        let mut records: Vec<_> = rows.iter().map(row_to_boundary).collect::<Result<_>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Appends a staged immutable boundary revision under a boundary CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid content, a stale/missing boundary, or a
    /// database failure.
    pub async fn revise_network_policy(
        &self,
        boundary_id: &str,
        spec: &NetworkPolicyRevisionSpec,
        actor: &str,
        expected_boundary_version: i64,
    ) -> Result<NetworkPolicyRevisionRecord> {
        if boundary_id == "instance:public" {
            bail!("the public boundary singleton cannot be revised");
        }
        validate_boundary_revision_spec(spec)?;
        let boundary = self
            .network_policy(boundary_id)
            .await?
            .context("network policy does not exist")?;
        if boundary.resource_version != expected_boundary_version {
            bail!("network policy is stale");
        }
        let next: i64 = self
            .backend
            .query_opt(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM network_policy_revisions
                 WHERE boundary_id = ?1",
                &vals![boundary_id],
            )
            .await?
            .context("boundary revision query returned no row")?
            .get(0)?;
        let fingerprint: [u8; 32] = hex::decode(&boundary.identity_fingerprint)
            .context("decoding boundary identity fingerprint")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("boundary identity fingerprint must contain 32 bytes"))?;
        let digest = network_policy_revision_digest(&fingerprint, spec)?;
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO network_policy_revisions (boundary_id, revision,
                     protected_transport_required, trusted_ingress_kind,
                     trusted_ingress_configuration, source_allowlist_cidrs,
                     probe_location_configuration, content_digest, created_by, created_at)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                     FROM network_policies WHERE id = ?1 AND resource_version = ?11",
                    vals![boundary_id, next, spec.protected_transport_required,
                        spec.trusted_ingress_kind, spec.trusted_ingress_configuration,
                        spec.source_allowlist_cidrs, spec.probe_location_configuration,
                        digest, actor, now, expected_boundary_version],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_revision_lifecycle
                     (boundary_id, revision, state, activation_mode, consumer_version, resource_version)
                     SELECT ?1, ?2, 'staged', 'overlap', 0, 1 WHERE EXISTS (
                       SELECT 1 FROM network_policy_revisions WHERE boundary_id = ?1 AND revision = ?2)",
                    vals![boundary_id, next],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_observations
                     (boundary_id, revision, state, protected_transport_observed,
                      trusted_ingress_observed, observed_at)
                     SELECT ?1, ?2, 'unknown', 0, 'none', ?3 WHERE EXISTS (
                       SELECT 1 FROM network_policy_revisions WHERE boundary_id = ?1 AND revision = ?2)",
                    vals![boundary_id, next, now],
                ).expecting(1),
                Statement::new(
                    "UPDATE network_policies SET resource_version = resource_version + 1,
                     updated_at = ?3 WHERE id = ?1 AND resource_version = ?2",
                    vals![boundary_id, expected_boundary_version, now],
                ).expecting(1),
            ])
            .await?;
        let updated = self
            .network_policy(boundary_id)
            .await?
            .context("network policy disappeared")?;
        if updated.resource_version != expected_boundary_version + 1 {
            bail!("network policy is stale");
        }
        self.network_policy_revision(boundary_id, next)
            .await?
            .context("created boundary revision disappeared")
    }

    /// Returns one immutable boundary revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn network_policy_revision(
        &self,
        boundary_id: &str,
        revision: i64,
    ) -> Result<Option<NetworkPolicyRevisionRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {BOUNDARY_REVISION_COLUMNS}
                     FROM network_policy_revisions r
                     JOIN network_policy_observations o
                       ON o.boundary_id = r.boundary_id AND o.revision = r.revision
                     JOIN network_policy_revision_lifecycle l
                       ON l.boundary_id = r.boundary_id AND l.revision = r.revision
                     WHERE r.boundary_id = ?1 AND r.revision = ?2"
                ),
                &vals![boundary_id, revision],
            )
            .await?
            .as_ref()
            .map(row_to_boundary_revision)
            .transpose()
    }

    /// Returns the highest immutable revision of a network policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn latest_network_policy_revision(
        &self,
        boundary_id: &str,
    ) -> Result<Option<NetworkPolicyRevisionRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {BOUNDARY_REVISION_COLUMNS}
                       FROM network_policy_revisions r
                       JOIN network_policy_observations o
                         ON o.boundary_id = r.boundary_id AND o.revision = r.revision
                       JOIN network_policy_revision_lifecycle l
                         ON l.boundary_id = r.boundary_id AND l.revision = r.revision
                      WHERE r.boundary_id = ?1 ORDER BY r.revision DESC LIMIT 1"
                ),
                &vals![boundary_id],
            )
            .await?
            .as_ref()
            .map(row_to_boundary_revision)
            .transpose()
    }

    /// Lists a stable page of one boundary's immutable revisions.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_network_policy_revisions_page(
        &self,
        boundary_id: &str,
        page_size: u32,
        after_revision: i64,
    ) -> Result<DeliveryIdentityPage<NetworkPolicyRevisionRecord>> {
        let limit = normalize_page_size(page_size);
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BOUNDARY_REVISION_COLUMNS}
                     FROM network_policy_revisions r
                     JOIN network_policy_observations o
                       ON o.boundary_id = r.boundary_id AND o.revision = r.revision
                     JOIN network_policy_revision_lifecycle l
                       ON l.boundary_id = r.boundary_id AND l.revision = r.revision
                     WHERE r.boundary_id = ?1 AND r.revision > ?2
                     ORDER BY r.revision LIMIT ?3"
                ),
                &vals![boundary_id, after_revision, limit + 1],
            )
            .await?;
        let mut records: Vec<_> = rows
            .iter()
            .map(row_to_boundary_revision)
            .collect::<Result<_>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.revision.to_string())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Records one exact boundary-revision observation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid observation shape, a stale/missing
    /// lifecycle row, or a database failure.
    pub async fn reconcile_network_policy_revision(
        &self,
        boundary_id: &str,
        revision: i64,
        state: &str,
        protected_transport_observed: bool,
        trusted_ingress_observed: &str,
        error: Option<&str>,
        expected_version: i64,
    ) -> Result<NetworkPolicyRevisionRecord> {
        if !matches!(
            state,
            "unknown" | "declared" | "probing" | "verified" | "degraded" | "failed"
        ) {
            bail!("invalid network-boundary observation state");
        }
        if (state == "failed") != error.is_some() {
            bail!("failed observations require an error and non-failures reject one");
        }
        if !matches!(
            trusted_ingress_observed,
            "none" | "mtls" | "signed_assertion"
        ) {
            bail!("invalid observed trusted-ingress kind");
        }
        let current = self
            .network_policy_revision(boundary_id, revision)
            .await?
            .context("boundary revision does not exist")?;
        if current.resource_version != expected_version {
            bail!("boundary revision is stale");
        }
        if state == "verified"
            && (protected_transport_observed != current.spec.protected_transport_required
                || trusted_ingress_observed != current.spec.trusted_ingress_kind)
        {
            bail!("verified observation must exactly match the desired boundary posture");
        }
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE network_policy_observations SET state = ?3,
                     protected_transport_observed = ?4, trusted_ingress_observed = ?5,
                     observed_at = CASE WHEN observed_at >= ?6 THEN observed_at + 1 ELSE ?6 END,
                     error = ?7 WHERE boundary_id = ?1 AND revision = ?2
                       AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                         WHERE boundary_id = ?1 AND revision = ?2 AND resource_version = ?8)",
                    vals![
                        boundary_id,
                        revision,
                        state,
                        protected_transport_observed,
                        trusted_ingress_observed,
                        now,
                        error,
                        expected_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET resource_version = resource_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2 AND resource_version = ?3",
                    vals![boundary_id, revision, expected_version],
                )
                .expecting(1),
            ])
            .await?;
        let observed = self
            .network_policy_revision(boundary_id, revision)
            .await?
            .context("boundary revision does not exist")?;
        if observed.resource_version != expected_version + 1 || observed.observation_state != state
        {
            bail!("boundary revision is stale");
        }
        Ok(observed)
    }

    /// Activates a verified staged boundary revision.
    ///
    /// `default_cas = None` leaves the default pointer unchanged. `Some` moves
    /// it only from the exact boundary/default versions sealed by the plan;
    /// `previous_revision = None` represents sealed pointer absence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid activation mode, unverified/stale state,
    /// an invalid or changed default-pointer seal, or a database failure.
    pub async fn activate_network_policy_revision(
        &self,
        boundary_id: &str,
        revision: i64,
        activation_mode: &str,
        default_cas: Option<&NetworkPolicyDefaultCas>,
        expected_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        coordination_operation_id: Option<&str>,
        coordination_impacts: &[NetworkPolicyServingPinRecord],
        coordination_revisions: &[NetworkPolicyCoordinationRevisionSeal],
        coordination_resolutions: &[NetworkPolicyPinResolutionSeal],
    ) -> Result<NetworkPolicyRevisionRecord> {
        if boundary_id == "instance:public" {
            bail!("the public boundary singleton cannot be activated");
        }
        if !matches!(activation_mode, "overlap" | "coordinated") {
            bail!("invalid activation mode");
        }
        if (activation_mode == "coordinated") != coordination_operation_id.is_some() {
            bail!("coordinated activation requires exactly one coordination operation");
        }
        if activation_mode != "coordinated" && !coordination_impacts.is_empty() {
            bail!("overlap activation cannot carry coordination impacts");
        }
        if activation_mode != "coordinated"
            && (!coordination_revisions.is_empty() || !coordination_resolutions.is_empty())
        {
            bail!("overlap activation cannot carry coordination state");
        }
        if activation_mode == "coordinated"
            && coordination_impacts.len() != coordination_resolutions.len()
        {
            bail!("coordinated activation requires exactly one resolution per live pin");
        }
        let current = self
            .network_policy_revision(boundary_id, revision)
            .await?
            .context("boundary revision does not exist")?;
        let boundary = self
            .network_policy(boundary_id)
            .await?
            .context("network policy does not exist")?;
        if current.resource_version != expected_version || current.lifecycle_state != "staged" {
            bail!("boundary revision is stale or not staged");
        }
        if let Some(default_cas) = default_cas {
            if default_cas.boundary_resource_version <= 0
                || (default_cas.previous_revision.is_some()
                    != default_cas.previous_resource_version.is_some())
                || default_cas
                    .previous_revision
                    .is_some_and(|revision| revision <= 0)
                || default_cas
                    .previous_resource_version
                    .is_some_and(|version| version <= 0)
            {
                bail!("invalid plan-sealed boundary default CAS");
            }
        }
        let now = unix_now();
        let target_state = if activation_mode == "coordinated" {
            "activating"
        } else {
            "active"
        };
        let mut statements = vec![Statement::new(
            "UPDATE network_policy_revision_lifecycle SET state = ?3,
                 activation_mode = ?4,
                 activated_at = CASE WHEN ?3 = 'active' THEN ?5 ELSE NULL END,
                 resource_version = resource_version + 1
                 WHERE boundary_id = ?1 AND revision = ?2 AND state = 'staged'
                   AND resource_version = ?6 AND EXISTS (
                     SELECT 1 FROM network_policy_observations o
                     JOIN network_policy_revisions r
                       ON r.boundary_id = o.boundary_id AND r.revision = o.revision
                     WHERE o.boundary_id = ?1 AND o.revision = ?2 AND o.state = 'verified'
                       AND o.protected_transport_observed = r.protected_transport_required
                       AND o.trusted_ingress_observed = r.trusted_ingress_kind)
                   AND (?7 = 0 OR EXISTS (SELECT 1 FROM network_policies
                     WHERE id = ?1 AND resource_version = ?8))",
            vals![
                boundary_id,
                revision,
                target_state,
                activation_mode,
                now,
                expected_version,
                default_cas.is_some(),
                default_cas.map_or(0, |seal| seal.boundary_resource_version)
            ],
        )
        .expecting(1)];

        if let Some(operation_id) = coordination_operation_id {
            let mut impact_ids = BTreeSet::new();
            let mut resolution_ids = BTreeSet::new();
            for impact in coordination_impacts {
                if impact.boundary_id != boundary_id
                    || impact.revision == revision
                    || !matches!(impact.target_kind.as_str(), "endpoint" | "route")
                    || !impact_ids.insert(impact.pin_id.as_str())
                {
                    bail!("invalid or duplicate coordinated activation impact");
                }
            }
            for resolution in coordination_resolutions {
                if !resolution_ids.insert(resolution.source.pin_id.as_str())
                    || !coordination_impacts.contains(&resolution.source)
                    || !matches!(
                        (
                            resolution.source.target_kind.as_str(),
                            resolution.action_kind.as_str()
                        ),
                        ("endpoint", "move_endpoint" | "release")
                            | ("route", "replace_route" | "release")
                    )
                {
                    bail!("invalid or duplicate coordinated pin resolution");
                }
                let has_replacement = resolution.replacement_target_kind.is_some()
                    && resolution.replacement_target_stable_id.is_some()
                    && resolution.replacement_target_generation_key.is_some()
                    && resolution.replacement_target_configuration_digest.is_some()
                    && resolution.replacement_resource_version.is_some();
                if (resolution.action_kind == "release") == has_replacement
                    || resolution.source_resource_version <= 0
                {
                    bail!("invalid coordinated pin resolution target seal");
                }
            }
            if impact_ids != resolution_ids {
                bail!("coordinated pin resolutions do not exactly cover the live pin set");
            }
            for old in coordination_revisions {
                if old.revision == revision
                    || !matches!(old.lifecycle_state.as_str(), "active" | "retiring")
                    || !coordination_impacts
                        .iter()
                        .any(|impact| impact.revision == old.revision)
                {
                    bail!("invalid coordinated old-revision seal");
                }
            }
            let operation_detail = serde_json::to_string(&serde_json::json!({
                "boundary_id": boundary_id,
                "target_revision": revision,
                "target_content_digest": current.content_digest,
                "old_revisions": coordination_revisions,
                "default_cas": default_cas.map(|seal| serde_json::json!({
                    "boundary_resource_version": seal.boundary_resource_version,
                    "previous_revision": seal.previous_revision,
                    "previous_resource_version": seal.previous_resource_version,
                })),
                "actor_kind": actor_kind,
                "actor_id": actor_id,
                "actor_label": actor_label,
            }))?;
            statements.push(
                Statement::new(
                    "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind,
                      primary_target_stable_id, primary_target_generation_key,
                      primary_target_configuration_digest, state, progress_total,
                      detail_json, created_at)
                     SELECT ?1, 'network_policy_coordinated_activation',
                       boundary.owner_scope_key, 'network_policy.manage',
                       'network_policy', revision.boundary_id, revision.revision,
                       revision.content_digest, 'pending', ?2, ?3, ?4
                     FROM network_policies boundary
                     JOIN network_policy_revisions revision
                       ON revision.boundary_id = boundary.id
                     WHERE boundary.id = ?5 AND revision.revision = ?6
                       AND revision.content_digest = ?7",
                    vals![
                        operation_id,
                        i64::try_from(coordination_impacts.len())?,
                        operation_detail,
                        now,
                        boundary_id,
                        revision,
                        current.content_digest
                    ],
                )
                .expecting(1),
            );
            let mut operation_targets = BTreeSet::new();
            for resolution in coordination_resolutions {
                let impact = &resolution.source;
                let (target_kind, control_permission, identity_from, revision_guard) =
                    match impact.target_kind.as_str() {
                        "endpoint" => (
                            "endpoint",
                            "endpoint.manage",
                            "endpoints identity
                              ON identity.id = pin.target_stable_id",
                            "EXISTS (SELECT 1 FROM endpoint_revisions revision
                              WHERE revision.endpoint_id = pin.target_stable_id
                                AND revision.generation = pin.target_generation_key
                                AND revision.content_digest = pin.target_configuration_digest)",
                        ),
                        "route" => (
                            "route",
                            "route.manage",
                            "routes route ON route.id = pin.target_stable_id
                             JOIN endpoints identity
                              ON identity.id = route.endpoint_id",
                            "EXISTS (SELECT 1 FROM route_heads head
                              WHERE head.route_id = pin.target_stable_id
                                AND head.configuration_generation = pin.target_generation_key
                                AND head.configuration_digest = pin.target_configuration_digest)",
                        ),
                        _ => bail!("unsupported coordinated activation target"),
                    };
                let new_source_target =
                    operation_targets.insert((target_kind, impact.target_stable_id.as_str()));
                if !new_source_target {
                    statements.push(
                        Statement::new(
                            "UPDATE topology_operations SET resource_version = resource_version
                             WHERE operation_id = ?1 AND EXISTS (
                               SELECT 1 FROM network_policy_serving_pins pin
                               WHERE pin.pin_id = ?2 AND pin.boundary_id = ?3
                                 AND pin.revision = ?4 AND pin.consumer_scope_key = ?5
                                 AND pin.grant_generation = ?6 AND pin.target_kind = ?7
                                 AND pin.target_stable_id = ?8
                                 AND pin.target_generation_key = ?9
                                 AND pin.target_configuration_digest = ?10)",
                            vals![
                                operation_id,
                                impact.pin_id,
                                impact.boundary_id,
                                impact.revision,
                                impact.consumer_scope_key,
                                impact.grant_generation,
                                impact.target_kind,
                                impact.target_stable_id,
                                impact.target_generation_key,
                                impact.target_configuration_digest
                            ],
                        )
                        .expecting(1),
                    );
                }
                if new_source_target {
                    statements.push(
                        Statement::new(
                            format!(
                                "INSERT INTO operation_secondary_targets
                             (operation_id, role, target_kind, stable_id,
                              authorization_scope_key, control_permission,
                              generation_key, configuration_digest)
                             SELECT ?1, 'source', ?2, pin.target_stable_id,
                               identity.owner_scope_key, ?3, pin.target_generation_key,
                               pin.target_configuration_digest
                             FROM network_policy_serving_pins pin
                             JOIN {identity_from}
                             WHERE pin.pin_id = ?4 AND pin.boundary_id = ?5
                               AND pin.revision = ?6 AND pin.consumer_scope_key = ?7
                               AND pin.grant_generation = ?8 AND pin.target_kind = ?9
                               AND pin.target_stable_id = ?10
                               AND pin.target_generation_key = ?11
                               AND pin.target_configuration_digest = ?12
                               AND {revision_guard}"
                            ),
                            vals![
                                operation_id,
                                target_kind,
                                control_permission,
                                impact.pin_id,
                                impact.boundary_id,
                                impact.revision,
                                impact.consumer_scope_key,
                                impact.grant_generation,
                                impact.target_kind,
                                impact.target_stable_id,
                                impact.target_generation_key,
                                impact.target_configuration_digest
                            ],
                        )
                        .expecting(1),
                    );
                }
                let source_guard = match impact.target_kind.as_str() {
                    "endpoint" => {
                        "EXISTS (SELECT 1 FROM endpoints source
                       WHERE source.id = pin.target_stable_id
                         AND source.desired_generation = pin.target_generation_key
                         AND source.resource_version = ?13)"
                    }
                    "route" => {
                        "EXISTS (SELECT 1 FROM routes source
                       JOIN route_heads source_head
                         ON source_head.route_id = source.id
                       WHERE source.id = pin.target_stable_id
                         AND source.resource_version = ?13
                         AND source_head.configuration_generation = pin.target_generation_key
                         AND source_head.configuration_digest = pin.target_configuration_digest)"
                    }
                    _ => bail!("unsupported coordinated activation target"),
                };
                statements.push(
                    Statement::new(
                        format!(
                            "INSERT INTO topology_pin_resolution_jobs
                             (operation_id, pin_id, action_kind, source_boundary_id,
                              source_boundary_revision, source_consumer_scope_key,
                              source_grant_generation, source_usage_kind, source_target_kind,
                              source_target_stable_id, source_target_generation_key,
                              source_target_configuration_digest, source_target_resource_version,
                              replacement_target_kind, replacement_target_stable_id,
                              replacement_target_generation_key,
                              replacement_target_configuration_digest,
                              replacement_target_resource_version)
                             SELECT ?1, pin.pin_id, ?2, pin.boundary_id, pin.revision,
                               pin.consumer_scope_key, pin.grant_generation, pin.usage_kind,
                               pin.target_kind, pin.target_stable_id, pin.target_generation_key,
                               pin.target_configuration_digest, ?13, ?14, ?15, ?16, ?17, ?18
                             FROM network_policy_serving_pins pin
                             WHERE pin.pin_id = ?3 AND pin.boundary_id = ?4
                               AND pin.revision = ?5 AND pin.consumer_scope_key = ?6
                               AND pin.grant_generation = ?7 AND pin.usage_kind = ?8
                               AND pin.target_kind = ?9 AND pin.target_stable_id = ?10
                               AND pin.target_generation_key = ?11
                               AND pin.target_configuration_digest = ?12
                               AND {source_guard}"
                        ),
                        vals![
                            operation_id,
                            resolution.action_kind.as_str(),
                            impact.pin_id,
                            impact.boundary_id,
                            impact.revision,
                            impact.consumer_scope_key,
                            impact.grant_generation,
                            impact.usage_kind,
                            impact.target_kind,
                            impact.target_stable_id,
                            impact.target_generation_key,
                            impact.target_configuration_digest,
                            resolution.source_resource_version,
                            resolution.replacement_target_kind.as_deref(),
                            resolution.replacement_target_stable_id.as_deref(),
                            resolution.replacement_target_generation_key,
                            resolution
                                .replacement_target_configuration_digest
                                .as_deref(),
                            resolution.replacement_resource_version,
                        ],
                    )
                    .expecting(1),
                );
                if let (
                    Some(replacement_kind),
                    Some(replacement_id),
                    Some(replacement_generation),
                    Some(replacement_digest),
                ) = (
                    resolution.replacement_target_kind.as_deref(),
                    resolution.replacement_target_stable_id.as_deref(),
                    resolution.replacement_target_generation_key,
                    resolution
                        .replacement_target_configuration_digest
                        .as_deref(),
                ) {
                    let (target_kind, permission, scope_join, target_guard) = match replacement_kind
                    {
                        "endpoint" => (
                            "endpoint",
                            "endpoint.manage",
                            "endpoints identity",
                            "EXISTS (SELECT 1 FROM endpoint_revisions r
                                  WHERE r.endpoint_id = ?3 AND r.generation = ?4
                                    AND r.content_digest = ?5)
                                  AND identity.id = ?3",
                        ),
                        "route" => (
                            "route",
                            "route.manage",
                            "routes route ON route.id = ?3
                                 JOIN endpoints identity ON identity.id = route.endpoint_id",
                            "EXISTS (SELECT 1 FROM route_heads h
                                  WHERE h.route_id = ?3
                                    AND h.configuration_generation = ?4
                                    AND h.configuration_digest = ?5)",
                        ),
                        _ => bail!("unsupported replacement target kind"),
                    };
                    if operation_targets.insert((target_kind, replacement_id)) {
                        statements.push(
                            Statement::new(
                                format!(
                                    "INSERT INTO operation_secondary_targets
                                     (operation_id, role, target_kind, stable_id,
                                      authorization_scope_key, control_permission,
                                      generation_key, configuration_digest)
                                     SELECT ?1, 'destination', ?2, ?3,
                                       identity.owner_scope_key, ?6, ?4, ?5
                                     FROM {scope_join} WHERE {target_guard}"
                                ),
                                vals![
                                    operation_id,
                                    target_kind,
                                    replacement_id,
                                    replacement_generation,
                                    replacement_digest,
                                    permission
                                ],
                            )
                            .expecting(1),
                        );
                    }
                }
            }
        } else if let Some(default_cas) = default_cas {
            statements.push(
                Statement::new(
                    "UPDATE network_policies
                     SET resource_version = resource_version + 1, updated_at = ?2
                     WHERE id = ?1 AND resource_version = ?3",
                    vals![boundary_id, now, default_cas.boundary_resource_version],
                )
                .expecting(1),
            );
            match (
                default_cas.previous_revision,
                default_cas.previous_resource_version,
            ) {
                (Some(previous_revision), Some(previous_resource_version)) => statements.push(
                    Statement::new(
                        "UPDATE network_policy_defaults
                         SET revision = ?2, state = 'active',
                             resource_version = resource_version + 1, updated_at = ?3
                         WHERE boundary_id = ?1 AND revision = ?4 AND state = 'active'
                           AND resource_version = ?6
                           AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                             WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active'
                               AND resource_version = ?5)",
                        vals![
                            boundary_id,
                            revision,
                            now,
                            previous_revision,
                            expected_version + 1,
                            previous_resource_version
                        ],
                    )
                    .expecting(1),
                ),
                (None, None) => statements.push(
                    Statement::new(
                        "INSERT INTO network_policy_defaults
                         (boundary_id, revision, state, resource_version, updated_at)
                         SELECT ?1, ?2, 'active', 1, ?3 WHERE EXISTS (
                           SELECT 1 FROM network_policy_revision_lifecycle
                           WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active'
                             AND resource_version = ?4)
                           AND NOT EXISTS (SELECT 1 FROM network_policy_defaults
                             WHERE boundary_id = ?1)",
                        vals![boundary_id, revision, now, expected_version + 1],
                    )
                    .expecting(1),
                ),
                _ => bail!("invalid plan-sealed boundary default CAS"),
            }
        }
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let event_name = if activation_mode == "coordinated" {
            "topology.network_policy.activation_started"
        } else {
            "topology.network_policy.activated"
        };
        let event_payload = serde_json::to_string(&serde_json::json!({
            "type": event_name,
            "resource_kind": "network_policy",
            "resource_stable_id": boundary_id,
            "resource_generation": revision,
            "resource_version": expected_version + 1,
            "activation_mode": activation_mode,
            "default_for_new_plans": default_cas.is_some(),
            "coordination_operation_id": coordination_operation_id,
        }))?;
        statements.push(Database::topology_event_statement(
            &crate::db::NewTopologyEvent {
                event_id: &event_id,
                event_name,
                owner_scope_key: &boundary.owner_scope_key,
                resource_kind: "network_policy",
                resource_stable_id: boundary_id,
                resource_generation_key: revision,
                actor_kind,
                actor_id,
                actor_label,
                payload_json: &event_payload,
                occurred_at: now,
            },
        ));
        self.backend.checked_batch(&statements).await?;
        let record = self
            .network_policy_revision(boundary_id, revision)
            .await?
            .context("boundary revision does not exist")?;
        if record.lifecycle_state != target_state || record.resource_version != expected_version + 1
        {
            bail!("boundary revision is stale, not staged, or not verified");
        }
        Ok(record)
    }

    /// Lists the exact child jobs of one coordinated boundary activation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_pin_resolution_jobs(
        &self,
        operation_id: &str,
    ) -> Result<Vec<TopologyPinResolutionJobRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {PIN_RESOLUTION_JOB_COLUMNS}
                     FROM topology_pin_resolution_jobs
                     WHERE operation_id = ?1 ORDER BY pin_id"
                ),
                &vals![operation_id],
            )
            .await?
            .iter()
            .map(row_to_pin_resolution_job)
            .collect()
    }

    /// Claims one pending or failed pin-resolution child under a job CAS.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn claim_topology_pin_resolution_job(
        &self,
        operation_id: &str,
        pin_id: &str,
        expected_version: i64,
    ) -> Result<Option<TopologyPinResolutionJobRecord>> {
        let now = unix_now();
        let changed = self
            .backend
            .execute(
                "UPDATE topology_pin_resolution_jobs
                 SET state = 'running', attempt = attempt + 1, error = NULL,
                     started_at = ?4, finished_at = NULL,
                     resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND pin_id = ?2 AND resource_version = ?3
                   AND state IN('pending', 'failed')",
                &vals![operation_id, pin_id, expected_version, now],
            )
            .await?;
        if changed == 0 {
            return Ok(None);
        }
        self.backend
            .query_opt(
                &format!(
                    "SELECT {PIN_RESOLUTION_JOB_COLUMNS}
                     FROM topology_pin_resolution_jobs
                     WHERE operation_id = ?1 AND pin_id = ?2"
                ),
                &vals![operation_id, pin_id],
            )
            .await?
            .as_ref()
            .map(row_to_pin_resolution_job)
            .transpose()
    }

    /// Moves an endpoint listener pin to its sealed replacement generation.
    ///
    /// The source pin, desired-generation pointer, target listener grant pin,
    /// and target-boundary pin change in one checked transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when any source or target seal is stale or on database
    /// failure.
    pub async fn execute_endpoint_pin_move(
        &self,
        job: &TopologyPinResolutionJobRecord,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<()> {
        if job.action_kind != "move_endpoint" || job.source_target_kind != "endpoint" {
            bail!("pin-resolution job is not an endpoint move");
        }
        let replacement_id = job
            .replacement_target_stable_id
            .as_deref()
            .context("endpoint move has no replacement id")?;
        let replacement_generation = job
            .replacement_target_generation_key
            .context("endpoint move has no replacement generation")?;
        let replacement_digest = job
            .replacement_target_configuration_digest
            .as_deref()
            .context("endpoint move has no replacement digest")?;
        let replacement_version = job
            .replacement_target_resource_version
            .context("endpoint move has no replacement resource version")?;
        if replacement_id != job.source_target_stable_id {
            bail!("endpoint move must preserve stable endpoint identity");
        }
        let target = self
            .endpoint_revision(replacement_id, replacement_generation)
            .await?
            .context("replacement endpoint generation does not exist")?;
        let endpoint_owner_scope = self
            .endpoint(replacement_id)
            .await?
            .context("endpoint disappeared before activation")?
            .owner_scope_key;
        let old_pin_id = format!("endpoint-pin:{}", Uuid::new_v4().simple());
        let new_boundary_pin_id = format!("boundary-pin:{}", Uuid::new_v4().simple());
        let now = unix_now();
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.endpoint.generation_activated",
            "resource_kind": "endpoint",
            "resource_stable_id": replacement_id,
            "resource_generation": replacement_generation,
            "resource_version": replacement_version + 1,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM endpoint_scope_grant_pins
                     WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                       AND consumer_scope_key = ?3 AND target_kind = 'listener'
                       AND target_stable_id = ?1 AND target_generation_key = ?2
                       AND target_configuration_digest = ?4
                       AND (?5 = '' OR EXISTS (SELECT 1 FROM topology_pin_resolution_jobs job
                         WHERE job.operation_id = ?5 AND job.pin_id = ?6
                           AND job.state = 'running' AND job.resource_version = ?7))",
                    vals![
                        job.source_target_stable_id,
                        job.source_target_generation_key,
                        job.source_consumer_scope_key,
                        job.source_target_configuration_digest,
                        job.operation_id,
                        job.pin_id,
                        job.resource_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM network_policy_serving_pins
                     WHERE pin_id = ?1 AND boundary_id = ?2 AND revision = ?3
                       AND consumer_scope_key = ?4 AND grant_generation = ?5
                       AND usage_kind = ?6 AND target_kind = 'endpoint'
                       AND target_stable_id = ?7 AND target_generation_key = ?8
                       AND target_configuration_digest = ?9",
                    vals![
                        job.pin_id,
                        job.source_boundary_id,
                        job.source_boundary_revision,
                        job.source_consumer_scope_key,
                        job.source_grant_generation,
                        job.source_usage_kind,
                        job.source_target_stable_id,
                        job.source_target_generation_key,
                        job.source_target_configuration_digest
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoints
                     SET desired_generation = ?2, resource_version = resource_version + 1,
                         updated_at = ?3
                     WHERE id = ?1 AND desired_generation = ?4 AND resource_version = ?5
                       AND ?5 = ?6
                       AND EXISTS (SELECT 1 FROM endpoint_revisions revision
                         WHERE revision.endpoint_id = ?1 AND revision.generation = ?2
                           AND revision.content_digest = ?7)",
                    vals![
                        replacement_id,
                        replacement_generation,
                        now,
                        job.source_target_generation_key,
                        job.source_target_resource_version,
                        replacement_version,
                        replacement_digest
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoint_observations
                     SET observed_generation = NULL, boundary_revision = NULL,
                         state = 'unknown', listener_observed = 0, tls_observed = 0,
                         observed_at = ?2, error = NULL
                     WHERE endpoint_id = ?1",
                    vals![replacement_id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO endpoint_scope_grant_pins
                     (pin_id, endpoint_id, endpoint_generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest)
                     SELECT ?1, grant.endpoint_id, grant.endpoint_generation,
                       grant.consumer_scope_key, grant.grant_generation, grant.state,
                       'listener', grant.endpoint_id, grant.endpoint_generation, ?5
                     FROM endpoint_route_scopes grant
                     WHERE grant.endpoint_id = ?2 AND grant.endpoint_generation = ?3
                       AND grant.consumer_scope_key = ?4 AND grant.state = 'active'",
                    vals![
                        old_pin_id,
                        replacement_id,
                        replacement_generation,
                        job.source_consumer_scope_key,
                        replacement_digest
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key,
                      grant_generation, grant_state, usage_kind, target_kind,
                      target_stable_id, target_generation_key,
                      target_configuration_digest, acquired_by, acquired_at)
                     SELECT ?1, revision.network_policy_id, revision.boundary_revision,
                       grant.consumer_scope_key, boundary_grant.grant_generation,
                       boundary_grant.state, 'endpoint_listener', 'endpoint',
                       revision.endpoint_id, revision.generation, revision.content_digest,
                       'system:boundary-coordination', ?6
                     FROM endpoint_revisions revision
                     JOIN endpoint_route_scopes grant
                       ON grant.endpoint_id = revision.endpoint_id
                      AND grant.endpoint_generation = revision.generation
                      AND grant.consumer_scope_key = ?4 AND grant.state = 'active'
                     JOIN network_policy_consumer_scopes boundary_grant
                       ON boundary_grant.boundary_id = revision.network_policy_id
                      AND boundary_grant.consumer_scope_key = ?4
                      AND boundary_grant.state = 'active'
                     WHERE revision.endpoint_id = ?2 AND revision.generation = ?3
                       AND revision.content_digest = ?5",
                    vals![
                        new_boundary_pin_id,
                        replacement_id,
                        replacement_generation,
                        job.source_consumer_scope_key,
                        replacement_digest,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET consumer_version = consumer_version + 1
                     WHERE (boundary_id = ?1 AND revision = ?2)
                        OR (boundary_id = ?3 AND revision = ?4)",
                    vals![
                        job.source_boundary_id,
                        job.source_boundary_revision,
                        target.network_policy_id,
                        target.boundary_revision
                    ],
                )
                .expecting(
                    if job.source_boundary_revision == target.boundary_revision {
                        1
                    } else {
                        2
                    },
                ),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.endpoint.generation_activated",
                    owner_scope_key: &endpoint_owner_scope,
                    resource_kind: "endpoint",
                    resource_stable_id: replacement_id,
                    resource_generation_key: replacement_generation,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await
    }

    /// Selects one exact previously staged endpoint generation.
    ///
    /// Public activation requires an active boundary. The coordinated boundary
    /// controller sets `allow_activating_boundary` and uses the same exact CAS
    /// while its target boundary remains non-servable.
    ///
    /// # Errors
    ///
    /// Returns an error for stale source/target state, dependent source uses,
    /// an ineligible boundary lifecycle, or database failure.
    pub async fn activate_staged_endpoint_generation(
        &self,
        endpoint_id: &str,
        generation: i64,
        expected_version: i64,
        allow_activating_boundary: bool,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<EndpointRecord> {
        let endpoint = self
            .endpoint(endpoint_id)
            .await?
            .context("endpoint does not exist")?;
        if endpoint.resource_version != expected_version {
            bail!("endpoint resource version is stale");
        }
        let previous = endpoint
            .desired_generation
            .context("endpoint has no selected generation")?;
        if previous == generation {
            bail!("endpoint generation is already selected");
        }
        let source = self
            .endpoint_revision(endpoint_id, previous)
            .await?
            .context("selected endpoint generation is missing")?;
        let target = self
            .endpoint_revision(endpoint_id, generation)
            .await?
            .context("staged endpoint generation is missing")?;
        let lifecycle = self
            .network_policy_revision(&target.network_policy_id, target.boundary_revision)
            .await?
            .context("target boundary revision is missing")?;
        if lifecycle.observation_state != "verified"
            || !(lifecycle.lifecycle_state == "active"
                || allow_activating_boundary && lifecycle.lifecycle_state == "activating")
        {
            bail!("target boundary revision is not eligible for endpoint activation");
        }
        let impacts = self
            .endpoint_generation_impacts(endpoint_id, previous)
            .await?;
        if !impacts.is_empty() {
            bail!("move dependent routes, gateways, and defaults before selecting the generation");
        }
        let pin = self
            .backend
            .query_opt(
                "SELECT pin_id, boundary_id, revision, consumer_scope_key,
                        grant_generation, usage_kind, target_kind, target_stable_id,
                        target_generation_key, target_configuration_digest,
                        acquired_by, acquired_at
                   FROM network_policy_serving_pins
                  WHERE target_kind = 'endpoint' AND target_stable_id = ?1
                    AND target_generation_key = ?2
                    AND target_configuration_digest = ?3
                    AND usage_kind = 'endpoint_listener'",
                &vals![endpoint_id, previous, source.content_digest],
            )
            .await?
            .context("selected endpoint generation has no exact boundary pin")?;
        let job = TopologyPinResolutionJobRecord {
            operation_id: String::new(),
            pin_id: pin.get(0)?,
            action_kind: "move_endpoint".to_string(),
            source_boundary_id: pin.get(1)?,
            source_boundary_revision: pin.get(2)?,
            source_consumer_scope_key: pin.get(3)?,
            source_grant_generation: pin.get(4)?,
            source_usage_kind: pin.get(5)?,
            source_target_kind: pin.get(6)?,
            source_target_stable_id: pin.get(7)?,
            source_target_generation_key: pin.get(8)?,
            source_target_configuration_digest: pin.get(9)?,
            source_target_resource_version: expected_version,
            replacement_target_kind: Some("endpoint".to_string()),
            replacement_target_stable_id: Some(endpoint_id.to_string()),
            replacement_target_generation_key: Some(generation),
            replacement_target_configuration_digest: Some(target.content_digest),
            replacement_target_resource_version: Some(expected_version),
            state: "running".to_string(),
            attempt: 1,
            error: None,
            resource_version: 1,
        };
        self.execute_endpoint_pin_move(&job, actor_kind, actor_id, actor_label)
            .await?;
        self.endpoint(endpoint_id)
            .await?
            .context("activated endpoint disappeared")
    }

    /// Atomically acknowledges a child job only after its exact postcondition.
    ///
    /// # Errors
    ///
    /// Returns an error when the action postcondition is not true or on
    /// database failure.
    pub async fn acknowledge_topology_pin_resolution_job(
        &self,
        job: &TopologyPinResolutionJobRecord,
    ) -> Result<()> {
        let now = unix_now();
        let postcondition = match (job.source_target_kind.as_str(), job.action_kind.as_str()) {
            ("endpoint", "move_endpoint") => {
                "EXISTS (SELECT 1 FROM endpoints target
                 JOIN endpoint_revisions revision
                   ON revision.endpoint_id = target.id
                  AND revision.generation = target.desired_generation
                 WHERE target.id = replacement_target_stable_id
                   AND target.desired_generation = replacement_target_generation_key
                   AND target.resource_version = replacement_target_resource_version + 1
                   AND revision.content_digest = replacement_target_configuration_digest)"
            }
            ("endpoint", "release") => {
                "NOT EXISTS (SELECT 1 FROM endpoints
                 WHERE id = source_target_stable_id)"
            }
            ("route", "replace_route") => {
                "EXISTS (SELECT 1 FROM routes source
                 WHERE source.id = source_target_stable_id AND source.enabled = 0
                   AND source.resource_version = source_target_resource_version + 1)
               AND EXISTS (SELECT 1 FROM routes replacement
                 JOIN route_heads head ON head.route_id = replacement.id
                 WHERE replacement.id = replacement_target_stable_id
                   AND replacement.enabled = 1
                   AND replacement.resource_version = replacement_target_resource_version
                   AND head.configuration_generation = replacement_target_generation_key
                   AND head.configuration_digest = replacement_target_configuration_digest)"
            }
            ("route", "release") => {
                "EXISTS (SELECT 1 FROM routes source
                 WHERE source.id = source_target_stable_id AND source.enabled = 0
                   AND source.resource_version = source_target_resource_version + 1)"
            }
            _ => bail!("unsupported pin-resolution acknowledgement"),
        };
        self.backend
            .checked_batch(&[Statement::new(
                format!(
                    "UPDATE topology_pin_resolution_jobs
                     SET state = 'succeeded', finished_at = ?4,
                         resource_version = resource_version + 1
                     WHERE operation_id = ?1 AND pin_id = ?2 AND resource_version = ?3
                       AND state = 'running'
                       AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins pin
                         WHERE pin.pin_id = topology_pin_resolution_jobs.pin_id)
                       AND {postcondition}"
                ),
                vals![job.operation_id, job.pin_id, job.resource_version, now],
            )
            .expecting(1)])
            .await
    }

    /// Records one failed child attempt for explicit operation retry.
    ///
    /// # Errors
    ///
    /// Returns an error on stale job state or database failure.
    pub async fn fail_topology_pin_resolution_job(
        &self,
        job: &TopologyPinResolutionJobRecord,
        error: &str,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE topology_pin_resolution_jobs
                 SET state = 'failed', error = ?4, finished_at = ?5,
                     resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND pin_id = ?2 AND resource_version = ?3
                   AND state = 'running'",
                vals![
                    job.operation_id,
                    job.pin_id,
                    job.resource_version,
                    error,
                    unix_now()
                ],
            )
            .expecting(1)])
            .await
    }

    /// Publishes a coordinated boundary revision after every child ack.
    ///
    /// Target activation, default-pointer movement, old-revision fencing,
    /// operation completion, and the audit/webhook outbox event commit in one
    /// checked transaction. Any unplanned late pin makes the transaction fail.
    ///
    /// # Errors
    ///
    /// Returns an error for stale operation/default/lifecycle seals, incomplete
    /// child jobs, late pins, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_network_policy_coordination(
        &self,
        operation_id: &str,
        expected_operation_version: i64,
        boundary_id: &str,
        target_revision: i64,
        target_content_digest: &str,
        old_revisions: &[NetworkPolicyCoordinationRevisionSeal],
        default_cas: Option<&NetworkPolicyDefaultCas>,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<()> {
        let boundary = self
            .network_policy(boundary_id)
            .await?
            .context("coordinated boundary no longer exists")?;
        let now = unix_now();
        let mut statements = vec![Statement::new(
            "UPDATE network_policy_revision_lifecycle
             SET state = 'active', activated_at = ?4,
                 resource_version = resource_version + 1
             WHERE boundary_id = ?1 AND revision = ?2 AND state = 'activating'
               AND EXISTS (SELECT 1 FROM network_policy_revisions revision
                 WHERE revision.boundary_id = ?1 AND revision.revision = ?2
                   AND revision.content_digest = ?3)
               AND EXISTS (SELECT 1 FROM topology_operations operation
                 WHERE operation.operation_id = ?5
                   AND operation.operation_kind = 'network_policy_coordinated_activation'
                   AND operation.state = 'running' AND operation.resource_version = ?6)
               AND NOT EXISTS (SELECT 1 FROM topology_pin_resolution_jobs job
                 WHERE job.operation_id = ?5 AND job.state <> 'succeeded')",
            vals![
                boundary_id,
                target_revision,
                target_content_digest,
                now,
                operation_id,
                expected_operation_version
            ],
        )
        .expecting(1)];
        if let Some(default_cas) = default_cas {
            statements.push(
                Statement::new(
                    "UPDATE network_policies
                     SET resource_version = resource_version + 1, updated_at = ?2
                     WHERE id = ?1 AND resource_version = ?3",
                    vals![boundary_id, now, default_cas.boundary_resource_version],
                )
                .expecting(1),
            );
            match (
                default_cas.previous_revision,
                default_cas.previous_resource_version,
            ) {
                (Some(previous_revision), Some(previous_version)) => statements.push(
                    Statement::new(
                        "UPDATE network_policy_defaults
                         SET revision = ?2, resource_version = resource_version + 1,
                             updated_at = ?3
                         WHERE boundary_id = ?1 AND revision = ?4 AND state = 'active'
                           AND resource_version = ?5
                           AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                             WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active')",
                        vals![
                            boundary_id,
                            target_revision,
                            now,
                            previous_revision,
                            previous_version
                        ],
                    )
                    .expecting(1),
                ),
                (None, None) => statements.push(
                    Statement::new(
                        "INSERT INTO network_policy_defaults
                         (boundary_id, revision, state, resource_version, updated_at)
                         SELECT ?1, ?2, 'active', 1, ?3
                         WHERE NOT EXISTS (SELECT 1 FROM network_policy_defaults
                           WHERE boundary_id = ?1)
                           AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                             WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active')",
                        vals![boundary_id, target_revision, now],
                    )
                    .expecting(1),
                ),
                _ => bail!("invalid coordinated default seal"),
            }
        }
        let mut seen_revisions = BTreeSet::new();
        for old in old_revisions {
            if old.revision == target_revision || !seen_revisions.insert(old.revision) {
                bail!("invalid duplicate coordinated old revision");
            }
            let statement = match old.lifecycle_state.as_str() {
                "active" => Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET state = 'retiring', consumer_version = consumer_version + 1,
                         resource_version = resource_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active'
                       AND resource_version = ?3
                       AND NOT EXISTS (SELECT 1 FROM network_policy_defaults
                         WHERE boundary_id = ?1 AND revision = ?2)
                       AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins
                         WHERE boundary_id = ?1 AND revision = ?2)
                       AND EXISTS (SELECT 1 FROM network_policy_revisions
                         WHERE boundary_id = ?1 AND revision = ?2
                           AND content_digest = ?4)",
                    vals![
                        boundary_id,
                        old.revision,
                        old.resource_version,
                        old.content_digest
                    ],
                ),
                "retiring" => Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET resource_version = resource_version
                     WHERE boundary_id = ?1 AND revision = ?2 AND state = 'retiring'
                       AND resource_version = ?3
                       AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins
                         WHERE boundary_id = ?1 AND revision = ?2)
                       AND EXISTS (SELECT 1 FROM network_policy_revisions
                         WHERE boundary_id = ?1 AND revision = ?2
                           AND content_digest = ?4)",
                    vals![
                        boundary_id,
                        old.revision,
                        old.resource_version,
                        old.content_digest
                    ],
                ),
                _ => bail!("invalid coordinated old revision state"),
            };
            statements.push(statement.expecting(1));
        }
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.network_policy.activated",
            "resource_kind": "network_policy",
            "resource_stable_id": boundary_id,
            "resource_generation": target_revision,
            "activation_mode": "coordinated",
            "coordination_operation_id": operation_id,
        }))?;
        statements.push(Database::topology_event_statement(
            &crate::db::NewTopologyEvent {
                event_id: &event_id,
                event_name: "topology.network_policy.activated",
                owner_scope_key: &boundary.owner_scope_key,
                resource_kind: "network_policy",
                resource_stable_id: boundary_id,
                resource_generation_key: target_revision,
                actor_kind,
                actor_id,
                actor_label,
                payload_json: &event_payload,
                occurred_at: now,
            },
        ));
        statements.push(
            Statement::new(
                "UPDATE topology_operations
                 SET state = 'succeeded', progress_current = progress_total,
                     finished_at = ?3, error = NULL,
                     resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND resource_version = ?2 AND state = 'running'
                   AND NOT EXISTS (SELECT 1 FROM topology_pin_resolution_jobs job
                     WHERE job.operation_id = ?1 AND job.state <> 'succeeded')",
                vals![operation_id, expected_operation_version, now],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await
    }

    /// Advances an active boundary revision to retiring and then retired.
    ///
    /// Active-to-retiring increments `consumer_version`, fencing new pins.
    /// Retiring-to-retired requires the exact consumer version and zero pins.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale lifecycle, live pins, the public singleton,
    /// or a database failure.
    pub async fn retire_network_policy_revision(
        &self,
        boundary_id: &str,
        revision: i64,
        expected_version: i64,
        expected_consumer_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<NetworkPolicyRevisionRecord> {
        if boundary_id == "instance:public" {
            bail!("the public boundary revision cannot retire");
        }
        let current = self
            .network_policy_revision(boundary_id, revision)
            .await?
            .context("boundary revision does not exist")?;
        let boundary = self
            .network_policy(boundary_id)
            .await?
            .context("network policy does not exist")?;
        let now = unix_now();
        let (resulting_state, sql, params) = match current.lifecycle_state.as_str() {
            "active" => (
                "retiring",
                "UPDATE network_policy_revision_lifecycle
                     SET state = 'retiring', consumer_version = consumer_version + 1,
                         resource_version = resource_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active'
                       AND resource_version = ?3 AND consumer_version = ?4
                       AND NOT EXISTS (SELECT 1 FROM network_policy_defaults
                         WHERE boundary_id = ?1 AND revision = ?2)",
                vals![
                    boundary_id,
                    revision,
                    expected_version,
                    expected_consumer_version
                ],
            ),
            "retiring" => (
                "retired",
                "UPDATE network_policy_revision_lifecycle
                     SET state = 'retired', retired_at = ?5,
                         resource_version = resource_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2 AND state = 'retiring'
                       AND resource_version = ?3 AND consumer_version = ?4
                       AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins
                         WHERE boundary_id = ?1 AND revision = ?2)",
                vals![
                    boundary_id,
                    revision,
                    expected_version,
                    expected_consumer_version,
                    now
                ],
            ),
            _ => bail!("boundary revision is not active or retiring"),
        };
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let event_name = if resulting_state == "retired" {
            "topology.network_policy.retired"
        } else {
            "topology.network_policy.retirement_started"
        };
        let event_payload = serde_json::to_string(&serde_json::json!({
            "type": event_name,
            "resource_kind": "network_policy",
            "resource_stable_id": boundary_id,
            "resource_generation": revision,
            "resource_version": expected_version + 1,
            "state": resulting_state,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(sql, params).expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &event_id,
                    event_name,
                    owner_scope_key: &boundary.owner_scope_key,
                    resource_kind: "network_policy",
                    resource_stable_id: boundary_id,
                    resource_generation_key: revision,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.network_policy_revision(boundary_id, revision)
            .await?
            .context("retired boundary revision disappeared")
    }

    /// Lists live serving pins for one exact boundary revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn network_policy_serving_pins(
        &self,
        boundary_id: &str,
        revision: i64,
    ) -> Result<Vec<NetworkPolicyServingPinRecord>> {
        self.backend
            .query(
                "SELECT pin_id, boundary_id, revision, consumer_scope_key,
                 grant_generation, usage_kind, target_kind, target_stable_id,
                 target_generation_key, target_configuration_digest,
                 acquired_by, acquired_at FROM network_policy_serving_pins
                 WHERE boundary_id = ?1 AND revision = ?2 ORDER BY pin_id",
                &vals![boundary_id, revision],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(NetworkPolicyServingPinRecord {
                    pin_id: row.get(0)?,
                    boundary_id: row.get(1)?,
                    revision: row.get(2)?,
                    consumer_scope_key: row.get(3)?,
                    grant_generation: row.get(4)?,
                    usage_kind: row.get(5)?,
                    target_kind: row.get(6)?,
                    target_stable_id: row.get(7)?,
                    target_generation_key: row.get(8)?,
                    target_configuration_digest: row.get(9)?,
                    acquired_by: row.get(10)?,
                    acquired_at: row.get(11)?,
                })
            })
            .collect()
    }

    /// Lists exact live consumers on every other revision of a boundary.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn network_policy_coordination_impacts(
        &self,
        boundary_id: &str,
        target_revision: i64,
    ) -> Result<Vec<NetworkPolicyServingPinRecord>> {
        self.backend
            .query(
                "SELECT pin_id, boundary_id, revision, consumer_scope_key,
                 grant_generation, usage_kind, target_kind, target_stable_id,
                 target_generation_key, target_configuration_digest,
                 acquired_by, acquired_at FROM network_policy_serving_pins
                 WHERE boundary_id = ?1 AND revision <> ?2
                 ORDER BY target_kind, target_stable_id, target_generation_key, pin_id",
                &vals![boundary_id, target_revision],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(NetworkPolicyServingPinRecord {
                    pin_id: row.get(0)?,
                    boundary_id: row.get(1)?,
                    revision: row.get(2)?,
                    consumer_scope_key: row.get(3)?,
                    grant_generation: row.get(4)?,
                    usage_kind: row.get(5)?,
                    target_kind: row.get(6)?,
                    target_stable_id: row.get(7)?,
                    target_generation_key: row.get(8)?,
                    target_configuration_digest: row.get(9)?,
                    acquired_by: row.get(10)?,
                    acquired_at: row.get(11)?,
                })
            })
            .collect()
    }

    /// Deletes an unused non-public boundary under a resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for the public singleton, a stale/referenced boundary,
    /// or a database failure.
    pub async fn delete_network_policy(&self, id: &str, expected_version: i64) -> Result<()> {
        if id == "instance:public" {
            bail!("the public boundary singleton cannot be deleted");
        }
        let changed = self
            .backend
            .execute(
                "DELETE FROM network_policies WHERE id = ?1 AND resource_version = ?2
                   AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins
                     WHERE boundary_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM endpoints
                     WHERE network_policy_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.state IN ('pending', 'running') AND (
                       (o.primary_target_kind = 'network_policy'
                         AND o.primary_target_stable_id = ?1)
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                         WHERE t.operation_id = o.operation_id
                           AND t.target_kind = 'network_policy' AND t.stable_id = ?1)))",
                &vals![id, expected_version],
            )
            .await?;
        if changed != 1 {
            bail!("network policy is missing, stale, or still referenced");
        }
        Ok(())
    }

    /// Creates an endpoint identity and generation one atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/revision fields, a missing exact
    /// active boundary/grant, duplicate identity, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_endpoint(
        &self,
        id: &str,
        owner_scope_key: &str,
        org_id: Option<i64>,
        scheme: &str,
        host: &EndpointHostInput,
        effective_port: u16,
        network_policy_id: &str,
        revision: &EndpointRevisionSpec,
        cleartext_acknowledged_at: Option<i64>,
        actor: &str,
        request_id: &str,
    ) -> Result<EndpointRecord> {
        validate_stable_id(id, "endpoint id")?;
        self.validate_owner_scope_binding(owner_scope_key, org_id)
            .await?;
        validate_endpoint_revision_spec(revision)?;
        if scheme == "http" && cleartext_acknowledged_at.is_none() {
            bail!("cleartext endpoint requires a durable acknowledgement");
        }
        if !matches!(scheme, "http" | "https") || effective_port == 0 {
            bail!("invalid endpoint scheme or port");
        }
        if (scheme == "http" && revision.tls_configuration != "{}")
            || (scheme == "https" && revision.tls_configuration == "{}")
        {
            bail!("endpoint TLS configuration does not match its immutable scheme");
        }
        let (domain_id, ipv4, ipv6, rendered_host) = match host {
            EndpointHostInput::Domain(stable_id) => {
                let domain = self
                    .delivery_domain(stable_id)
                    .await?
                    .context("endpoint domain does not exist")?;
                if domain.owner_scope_key != owner_scope_key {
                    bail!("endpoint domain owner scope does not match endpoint owner");
                }
                (Some(domain.id), None, None, domain.hostname)
            }
            EndpointHostInput::Ipv4(address) => (
                None,
                Some(address.to_vec()),
                None,
                Ipv4Addr::from(*address).to_string(),
            ),
            EndpointHostInput::Ipv6(address) => {
                let address = Ipv6Addr::from(*address);
                if address.to_ipv4_mapped().is_some() {
                    bail!("endpoint rejects IPv4-mapped IPv6 aliases");
                }
                (
                    None,
                    None,
                    Some(address.octets().to_vec()),
                    format!("[{address}]"),
                )
            }
        };
        let origin =
            EndpointOrigin::parse(&format!("{scheme}://{rendered_host}:{effective_port}"))?;
        let boundary = self
            .network_policy(network_policy_id)
            .await?
            .context("endpoint boundary does not exist")?;
        let fingerprint: [u8; 32] = hex::decode(&boundary.identity_fingerprint)
            .context("decoding boundary identity fingerprint")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("boundary identity fingerprint must contain 32 bytes"))?;
        let identity_digest = hex::encode(origin.identity_digest(&fingerprint));
        let content_digest = sha256_hex(canonical_json(revision)?);
        let boundary_consumer_version = self
            .verified_active_boundary_consumer_version(
                network_policy_id,
                revision.boundary_revision,
            )
            .await?;
        let now = unix_now();
        let boundary_pin_id = format!("boundary-pin:{}", Uuid::new_v4().simple());
        let endpoint_pin_id = format!("endpoint-pin:{}", Uuid::new_v4().simple());
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.endpoint.created",
            "resource_kind": "endpoint",
            "resource_stable_id": id,
            "resource_generation": 1,
            "resource_version": 1,
        }))?;
        let grant_event_id = format!("grant-event:{}", Uuid::new_v4().simple());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO endpoints (id, org_id, owner_scope_key, scheme,
                     domain_id, ipv4_bytes, ipv6_bytes, effective_port, network_policy_id,
                     cleartext_acknowledged_at, endpoint_identity_digest, created_at, updated_at)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12
                     WHERE EXISTS (SELECT 1 FROM network_policy_consumer_scopes
                       WHERE boundary_id = ?9 AND consumer_scope_key = ?3 AND state = 'active')
                       AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                         WHERE boundary_id = ?9 AND revision = ?13 AND state = 'active'
                           AND consumer_version = ?14)
                       AND EXISTS (SELECT 1 FROM network_policy_observations o
                         JOIN network_policy_revisions r
                           ON r.boundary_id = o.boundary_id AND r.revision = o.revision
                         WHERE o.boundary_id = ?9 AND o.revision = ?13
                           AND o.state = 'verified'
                           AND o.protected_transport_observed = r.protected_transport_required
                           AND o.trusted_ingress_observed = r.trusted_ingress_kind)",
                    vals![
                        id,
                        org_id,
                        owner_scope_key,
                        scheme,
                        domain_id,
                        ipv4,
                        ipv6,
                        i64::from(effective_port),
                        network_policy_id,
                        cleartext_acknowledged_at,
                        identity_digest,
                        now,
                        revision.boundary_revision,
                        boundary_consumer_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO endpoint_revisions (endpoint_id, generation,
                     network_policy_id, boundary_revision, ingress_kind,
                     listener_configuration, tls_configuration, probe_configuration,
                     content_digest, created_by, created_at)
                     SELECT ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                     WHERE EXISTS (SELECT 1 FROM endpoints WHERE id = ?1)
                       AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                         WHERE boundary_id = ?2 AND revision = ?3 AND state = 'active'
                           AND consumer_version = ?11)",
                    vals![
                        id,
                        network_policy_id,
                        revision.boundary_revision,
                        revision.ingress_kind,
                        revision.listener_configuration,
                        revision.tls_configuration,
                        revision.probe_configuration,
                        content_digest,
                        actor,
                        now,
                        boundary_consumer_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO endpoint_route_scopes
                     (endpoint_id, endpoint_generation, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     SELECT ?1, 1, ?2, 1, 'owner', 'active', ?3, ?4, 1
                     WHERE EXISTS (SELECT 1 FROM endpoint_revisions
                       WHERE endpoint_id = ?1 AND generation = 1)",
                    vals![id, owner_scope_key, actor, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id,
                      resource_generation_key, consumer_scope_key, grant_generation,
                      transition, previous_state, resulting_state, actor_id,
                      occurred_at, request_id)
                     SELECT ?1, 'endpoint', ?2, 1, ?3, 1, 'granted',
                       NULL, 'active', ?4, ?5, ?6 WHERE EXISTS (
                         SELECT 1 FROM endpoint_route_scopes
                         WHERE endpoint_id = ?2 AND endpoint_generation = 1
                           AND consumer_scope_key = ?3 AND grant_generation = 1
                           AND state = 'active')",
                    vals![grant_event_id, id, owner_scope_key, actor, now, request_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO endpoint_observations (endpoint_id, boundary_id,
                     state, listener_observed, tls_observed, observed_at)
                     SELECT ?1, ?2, 'unknown', 0, 0, ?3 WHERE EXISTS (
                       SELECT 1 FROM endpoint_revisions WHERE endpoint_id = ?1 AND generation = 1)",
                    vals![id, network_policy_id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO network_policy_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key, grant_generation,
                      grant_state, usage_kind, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest, acquired_by,
                      acquired_at, resource_version)
                     SELECT ?1, ?2, ?3, ?4, grant_generation, 'active',
                       'endpoint_listener', 'endpoint', ?5, 1, ?6, ?7, ?8, 1
                     FROM network_policy_consumer_scopes
                     WHERE boundary_id = ?2 AND consumer_scope_key = ?4 AND state = 'active'
                       AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                         WHERE boundary_id = ?2 AND revision = ?3 AND state = 'active'
                           AND consumer_version = ?9)
                       AND EXISTS (SELECT 1 FROM endpoint_revisions
                         WHERE endpoint_id = ?5 AND generation = 1)",
                    vals![
                        boundary_pin_id,
                        network_policy_id,
                        revision.boundary_revision,
                        owner_scope_key,
                        id,
                        content_digest,
                        actor,
                        now,
                        boundary_consumer_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET consumer_version = consumer_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2 AND state = 'active'
                       AND consumer_version = ?3 AND EXISTS (
                         SELECT 1 FROM network_policy_serving_pins
                         WHERE pin_id = ?4 AND boundary_id = ?1 AND revision = ?2)",
                    vals![
                        network_policy_id,
                        revision.boundary_revision,
                        boundary_consumer_version,
                        boundary_pin_id
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoints SET desired_generation = 1
                     WHERE id = ?1 AND EXISTS (SELECT 1 FROM endpoint_revisions
                       WHERE endpoint_id = ?1 AND generation = 1)
                       AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                         WHERE boundary_id = ?2 AND revision = ?3
                           AND consumer_version = ?4)",
                    vals![
                        id,
                        network_policy_id,
                        revision.boundary_revision,
                        boundary_consumer_version + 1
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO endpoint_scope_grant_pins
                     (pin_id, endpoint_id, endpoint_generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest, resource_version)
                     SELECT ?1, ?2, 1, ?3, grant_generation, 'active',
                       'listener', ?2, 1, ?4, 1 FROM endpoint_route_scopes
                     WHERE endpoint_id = ?2 AND endpoint_generation = 1
                       AND consumer_scope_key = ?3 AND state = 'active'
                       AND EXISTS (SELECT 1 FROM endpoints
                         WHERE id = ?2 AND desired_generation = 1)",
                    vals![endpoint_pin_id, id, owner_scope_key, content_digest],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.endpoint.created",
                    owner_scope_key,
                    resource_kind: "endpoint",
                    resource_stable_id: id,
                    resource_generation_key: 1,
                    actor_kind: "key",
                    actor_id: None,
                    actor_label: actor,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        let endpoint = self
            .endpoint(id)
            .await?
            .context("endpoint creation lost its boundary/grant CAS")?;
        if endpoint.desired_generation != Some(1) {
            bail!("endpoint creation did not install generation one");
        }
        Ok(endpoint)
    }

    /// Returns an endpoint identity by stable id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn endpoint(&self, id: &str) -> Result<Option<EndpointRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {ENDPOINT_COLUMNS} FROM endpoints e
                     LEFT JOIN domains d ON d.id = e.domain_id WHERE e.id = ?1"
                ),
                &vals![id],
            )
            .await?
            .as_ref()
            .map(row_to_endpoint)
            .transpose()
    }

    /// Lists a stable page of endpoints in one owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid scope or database failure.
    pub async fn list_endpoints_page(
        &self,
        owner_scope_key: &str,
        page_size: u32,
        after_id: Option<&str>,
        include_granted: bool,
    ) -> Result<DeliveryIdentityPage<EndpointRecord>> {
        validate_scope(owner_scope_key)?;
        let limit = normalize_page_size(page_size);
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {ENDPOINT_COLUMNS} FROM endpoints e
                     LEFT JOIN domains d ON d.id = e.domain_id
                     WHERE (e.owner_scope_key = ?1 OR (?4 AND EXISTS (
                         SELECT 1 FROM endpoint_route_scopes grant_record
                         WHERE grant_record.endpoint_id = e.id
                           AND grant_record.endpoint_generation = e.desired_generation
                           AND grant_record.consumer_scope_key = ?1
                           AND grant_record.state = 'active'
                     ))) AND e.id > ?2 ORDER BY e.id LIMIT ?3"
                ),
                &vals![
                    owner_scope_key,
                    after_id.unwrap_or(""),
                    limit + 1,
                    include_granted
                ],
            )
            .await?;
        let mut records: Vec<_> = rows.iter().map(row_to_endpoint).collect::<Result<_>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Returns one immutable endpoint generation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn endpoint_revision(
        &self,
        endpoint_id: &str,
        generation: i64,
    ) -> Result<Option<EndpointRevisionRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {ENDPOINT_REVISION_COLUMNS} FROM endpoint_revisions r
                     WHERE r.endpoint_id = ?1 AND r.generation = ?2"
                ),
                &vals![endpoint_id, generation],
            )
            .await?
            .as_ref()
            .map(row_to_endpoint_revision)
            .transpose()
    }

    /// Lists every immutable generation of one endpoint in generation order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn endpoint_revisions(
        &self,
        endpoint_id: &str,
    ) -> Result<Vec<EndpointRevisionRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {ENDPOINT_REVISION_COLUMNS} FROM endpoint_revisions r
                     WHERE r.endpoint_id = ?1 ORDER BY r.generation"
                ),
                &vals![endpoint_id],
            )
            .await?
            .iter()
            .map(row_to_endpoint_revision)
            .collect()
    }

    /// Lists every route, gateway generation, and default pinned to one exact
    /// endpoint generation in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn endpoint_generation_impacts(
        &self,
        endpoint_id: &str,
        generation: i64,
    ) -> Result<Vec<EndpointImpactRecord>> {
        self.backend
            .query(
                "SELECT 'route', id, endpoint_generation, resource_version
                   FROM routes
                  WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                 UNION ALL
                 SELECT 'gateway', g.id, r.generation, g.resource_version
                   FROM gateway_revisions r
                   JOIN gateways g ON g.id = r.gateway_id
                  WHERE r.endpoint_id = ?1 AND r.endpoint_generation = ?2
                 UNION ALL
                 SELECT 'topology_default', scope_key, endpoint_generation,
                        resource_version
                   FROM topology_defaults
                  WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                 ORDER BY 1, 2, 3",
                &vals![endpoint_id, generation],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(EndpointImpactRecord {
                    resource_kind: row.get(0)?,
                    stable_id: row.get(1)?,
                    generation: row.get(2)?,
                    resource_version: row.get(3)?,
                })
            })
            .collect()
    }

    /// Appends an immutable endpoint generation without selecting it.
    ///
    /// Staging is valid against a verified staged, activating, or active
    /// boundary revision. It copies exact grants but creates no serving pins;
    /// selection is a separate lifecycle CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale endpoint/grant seals, an unverified boundary
    /// revision, invalid content, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_endpoint_generation(
        &self,
        endpoint_id: &str,
        spec: &EndpointRevisionSpec,
        owner_grant: &EndpointGrantCarryForward,
        carry_forward_grants: &[EndpointGrantCarryForward],
        actor: &str,
        request_id: &str,
        expected_version: i64,
    ) -> Result<EndpointRevisionRecord> {
        validate_endpoint_revision_spec(spec)?;
        let endpoint = self
            .endpoint(endpoint_id)
            .await?
            .context("endpoint does not exist")?;
        if endpoint.resource_version != expected_version
            || (endpoint.scheme == "http" && spec.tls_configuration != "{}")
            || (endpoint.scheme == "https" && spec.tls_configuration == "{}")
        {
            bail!("endpoint is stale or its TLS shape is invalid");
        }
        let previous = endpoint
            .desired_generation
            .context("endpoint has no selected generation")?;
        if owner_grant.consumer_scope_key != endpoint.owner_scope_key
            || owner_grant.grant_generation <= 0
            || owner_grant.resource_version <= 0
        {
            bail!("plan-sealed endpoint owner grant is invalid");
        }
        let mut carried = BTreeMap::new();
        for grant in carry_forward_grants {
            validate_scope(&grant.consumer_scope_key)?;
            if grant.consumer_scope_key == endpoint.owner_scope_key
                || grant.grant_generation <= 0
                || grant.resource_version <= 0
                || carried
                    .insert(
                        grant.consumer_scope_key.clone(),
                        (grant.grant_generation, grant.resource_version),
                    )
                    .is_some()
            {
                bail!("invalid or duplicate carried endpoint grant");
            }
        }
        let next: i64 = self
            .backend
            .query_opt(
                "SELECT COALESCE(MAX(generation), 0) + 1
                 FROM endpoint_revisions WHERE endpoint_id = ?1",
                &vals![endpoint_id],
            )
            .await?
            .context("endpoint generation query returned no row")?
            .get(0)?;
        let content_digest = sha256_hex(canonical_json(spec)?);
        let now = unix_now();
        let expected_grants = i64::try_from(carried.len() + 1)?;
        let mut statements = vec![
            Statement::new(
                "INSERT INTO endpoint_revisions
                 (endpoint_id, generation, network_policy_id, boundary_revision,
                  ingress_kind, listener_configuration, tls_configuration,
                  probe_configuration, content_digest, created_by, created_at)
                 SELECT endpoint.id, ?2, endpoint.network_policy_id, ?3, ?4, ?5,
                   ?6, ?7, ?8, ?9, ?10
                 FROM endpoints endpoint
                 WHERE endpoint.id = ?1 AND endpoint.resource_version = ?11
                   AND endpoint.desired_generation = ?12
                   AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle lifecycle
                     JOIN network_policy_observations observation
                       ON observation.boundary_id = lifecycle.boundary_id
                      AND observation.revision = lifecycle.revision
                     JOIN network_policy_revisions revision
                       ON revision.boundary_id = lifecycle.boundary_id
                      AND revision.revision = lifecycle.revision
                     WHERE lifecycle.boundary_id = endpoint.network_policy_id
                       AND lifecycle.revision = ?3
                       AND lifecycle.state IN('staged', 'activating', 'active')
                       AND observation.state = 'verified'
                       AND observation.protected_transport_observed
                           = revision.protected_transport_required
                       AND observation.trusted_ingress_observed
                           = revision.trusted_ingress_kind)",
                vals![
                    endpoint_id,
                    next,
                    spec.boundary_revision,
                    spec.ingress_kind,
                    spec.listener_configuration,
                    spec.tls_configuration,
                    spec.probe_configuration,
                    content_digest,
                    actor,
                    now,
                    expected_version,
                    previous
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO endpoint_route_scopes
                 (endpoint_id, endpoint_generation, consumer_scope_key,
                  grant_generation, grant_kind, state, granted_by, granted_at,
                  resource_version)
                 SELECT ?1, ?2, consumer_scope_key, 1, 'owner', 'active', ?4, ?5, 1
                 FROM endpoint_route_scopes
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?3
                   AND consumer_scope_key = ?6 AND grant_kind = 'owner'
                   AND state = 'active' AND grant_generation = ?7
                   AND resource_version = ?8",
                vals![
                    endpoint_id,
                    next,
                    previous,
                    actor,
                    now,
                    endpoint.owner_scope_key,
                    owner_grant.grant_generation,
                    owner_grant.resource_version
                ],
            )
            .expecting(1),
        ];
        for (scope, (generation, version)) in carried {
            statements.push(
                Statement::new(
                    "INSERT INTO endpoint_route_scopes
                     (endpoint_id, endpoint_generation, consumer_scope_key,
                      grant_generation, grant_kind, state, granted_by, granted_at,
                      resource_version)
                     SELECT ?1, ?2, consumer_scope_key, 1, grant_kind, 'active', ?4, ?5, 1
                     FROM endpoint_route_scopes
                     WHERE endpoint_id = ?1 AND endpoint_generation = ?3
                       AND consumer_scope_key = ?6 AND state = 'active'
                       AND grant_generation = ?7 AND resource_version = ?8",
                    vals![
                        endpoint_id,
                        next,
                        previous,
                        actor,
                        now,
                        scope,
                        generation,
                        version
                    ],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "UPDATE endpoints
                 SET resource_version = resource_version + 1, updated_at = ?3
                 WHERE id = ?1 AND resource_version = ?2
                   AND (SELECT COUNT(*) FROM endpoint_route_scopes
                     WHERE endpoint_id = ?1 AND endpoint_generation = ?4) = ?5",
                vals![endpoint_id, expected_version, now, next, expected_grants],
            )
            .expecting(1),
        );
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.endpoint.generation_staged",
            "resource_kind": "endpoint",
            "resource_stable_id": endpoint_id,
            "resource_generation": next,
            "resource_version": expected_version + 1,
            "request_id": request_id,
        }))?;
        statements.push(Database::topology_event_statement(
            &crate::db::NewTopologyEvent {
                event_id: &event_id,
                event_name: "topology.endpoint.generation_staged",
                owner_scope_key: &endpoint.owner_scope_key,
                resource_kind: "endpoint",
                resource_stable_id: endpoint_id,
                resource_generation_key: next,
                actor_kind: "key",
                actor_id: None,
                actor_label: actor,
                payload_json: &payload,
                occurred_at: now,
            },
        ));
        self.backend.checked_batch(&statements).await?;
        self.endpoint_revision(endpoint_id, next)
            .await?
            .context("staged endpoint generation disappeared")
    }

    /// Returns the latest endpoint-controller observation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn endpoint_observation(
        &self,
        endpoint_id: &str,
    ) -> Result<Option<EndpointObservationRecord>> {
        self.backend
            .query_opt(
                "SELECT endpoint_id, observed_generation, boundary_id, boundary_revision,
             state, listener_observed, tls_observed, observed_at, error
             FROM endpoint_observations WHERE endpoint_id = ?1",
                &vals![endpoint_id],
            )
            .await?
            .as_ref()
            .map(|row| {
                Ok(EndpointObservationRecord {
                    endpoint_id: row.get(0)?,
                    observed_generation: row.get(1)?,
                    boundary_id: row.get(2)?,
                    boundary_revision: row.get(3)?,
                    state: row.get(4)?,
                    listener_observed: row.get(5)?,
                    tls_observed: row.get(6)?,
                    observed_at: row.get(7)?,
                    error: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Returns the retained observation for one immutable endpoint generation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn endpoint_generation_observation(
        &self,
        endpoint_id: &str,
        generation: i64,
    ) -> Result<Option<EndpointObservationRecord>> {
        self.backend
            .query_opt(
                "SELECT endpoint_id, observed_generation, boundary_id, boundary_revision,
                 state, listener_observed, tls_observed, observed_at, error
                 FROM endpoint_generation_observations
                 WHERE endpoint_id = ?1 AND observed_generation = ?2",
                &vals![endpoint_id, generation],
            )
            .await?
            .as_ref()
            .map(|row| {
                Ok(EndpointObservationRecord {
                    endpoint_id: row.get(0)?,
                    observed_generation: Some(row.get(1)?),
                    boundary_id: row.get(2)?,
                    boundary_revision: Some(row.get(3)?),
                    state: row.get(4)?,
                    listener_observed: row.get(5)?,
                    tls_observed: row.get(6)?,
                    observed_at: row.get(7)?,
                    error: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Records one exact endpoint-generation observation under an endpoint CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid observation shape, a stale/mismatched
    /// generation, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_endpoint(
        &self,
        endpoint_id: &str,
        observed_generation: i64,
        boundary_revision: i64,
        state: &str,
        listener_observed: bool,
        tls_observed: bool,
        error: Option<&str>,
        expected_version: i64,
    ) -> Result<EndpointObservationRecord> {
        if !matches!(
            state,
            "declared" | "probing" | "healthy" | "degraded" | "failed"
        ) {
            bail!("invalid endpoint observation state");
        }
        if (state == "failed") != error.is_some() {
            bail!("failed observations require an error and non-failures reject one");
        }
        let current = self
            .endpoint(endpoint_id)
            .await?
            .context("endpoint does not exist")?;
        if current.resource_version != expected_version {
            bail!("endpoint is stale");
        }
        let now = unix_now();
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.endpoint.reconciled",
            "resource_kind": "endpoint",
            "resource_stable_id": endpoint_id,
            "resource_generation": observed_generation,
            "resource_version": expected_version + 1,
            "state": state,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO endpoint_generation_observations
                     (endpoint_id, observed_generation, boundary_id, boundary_revision,
                      state, listener_observed, tls_observed, observed_at, error)
                     SELECT e.id, ?2, e.network_policy_id, ?3, ?4, ?5, ?6, ?7, ?8
                     FROM endpoints e
                     JOIN endpoint_revisions r ON r.endpoint_id = e.id
                       AND r.generation = ?2 AND r.boundary_revision = ?3
                     WHERE e.id = ?1 AND e.resource_version = ?9
                     ON CONFLICT(endpoint_id, observed_generation) DO UPDATE SET
                       boundary_id = excluded.boundary_id,
                       boundary_revision = excluded.boundary_revision,
                       state = excluded.state,
                       listener_observed = excluded.listener_observed,
                       tls_observed = excluded.tls_observed,
                       observed_at = CASE
                         WHEN endpoint_generation_observations.observed_at
                           >= excluded.observed_at
                         THEN endpoint_generation_observations.observed_at + 1
                         ELSE excluded.observed_at END,
                       error = excluded.error",
                    vals![
                        endpoint_id,
                        observed_generation,
                        boundary_revision,
                        state,
                        listener_observed,
                        tls_observed,
                        now,
                        error,
                        expected_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoint_observations SET observed_generation = ?2,
                 boundary_revision = ?3, state = ?4, listener_observed = ?5,
                 tls_observed = ?6,
                 observed_at = CASE WHEN observed_at >= ?7 THEN observed_at + 1 ELSE ?7 END,
                 error = ?8 WHERE endpoint_id = ?1
                   AND EXISTS (SELECT 1 FROM endpoints e
                     JOIN endpoint_revisions r ON r.endpoint_id = e.id
                       AND r.generation = ?2 AND r.boundary_revision = ?3
                     WHERE e.id = ?1 AND e.resource_version = ?9)",
                    vals![
                        endpoint_id,
                        observed_generation,
                        boundary_revision,
                        state,
                        listener_observed,
                        tls_observed,
                        now,
                        error,
                        expected_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE endpoints SET resource_version = resource_version + 1,
                 updated_at = ?3 WHERE id = ?1 AND resource_version = ?2
                   AND EXISTS (SELECT 1 FROM endpoint_observations
                     WHERE endpoint_id = ?1 AND observed_generation IS NOT NULL)",
                    vals![endpoint_id, expected_version, now],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.endpoint.reconciled",
                    owner_scope_key: &current.owner_scope_key,
                    resource_kind: "endpoint",
                    resource_stable_id: endpoint_id,
                    resource_generation_key: observed_generation,
                    actor_kind: "system",
                    actor_id: None,
                    actor_label: "delivery-endpoint-controller",
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        let endpoint = self
            .endpoint(endpoint_id)
            .await?
            .context("endpoint does not exist")?;
        if endpoint.resource_version != expected_version + 1 {
            bail!("endpoint is stale or observation generation mismatched");
        }
        self.endpoint_observation(endpoint_id)
            .await?
            .context("endpoint observation disappeared")
    }

    /// Deletes an unused endpoint under a resource-version CAS.
    ///
    /// The endpoint's own listener pins are released in the same batch. Route,
    /// gateway, and default pins remain structural blockers.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/referenced endpoint or database failure.
    pub async fn delete_endpoint(
        &self,
        endpoint_id: &str,
        expected_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<()> {
        let endpoint = self
            .endpoint(endpoint_id)
            .await?
            .context("endpoint does not exist")?;
        if endpoint.resource_version != expected_version {
            bail!("endpoint is stale");
        }
        let generation = endpoint
            .desired_generation
            .context("endpoint has no desired generation")?;
        let revision = self
            .endpoint_revision(endpoint_id, generation)
            .await?
            .context("desired endpoint generation does not exist")?;
        let consumer_version = self
            .releasable_boundary_consumer_version(
                &endpoint.network_policy_id,
                revision.boundary_revision,
            )
            .await?;
        let now = unix_now();
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.endpoint.deleted",
            "resource_kind": "endpoint",
            "resource_stable_id": endpoint_id,
            "resource_generation": generation,
            "resource_version": expected_version,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM endpoint_scope_grant_pins
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?3
                   AND target_kind = 'listener' AND target_stable_id = ?1
                   AND target_generation_key = ?3
                   AND target_configuration_digest = ?4
                   AND EXISTS (SELECT 1 FROM endpoints
                     WHERE id = ?1 AND resource_version = ?2)
                   AND NOT EXISTS (SELECT 1 FROM endpoint_scope_grant_pins
                     WHERE endpoint_id = ?1 AND target_kind <> 'listener')",
                    vals![
                        endpoint_id,
                        expected_version,
                        generation,
                        revision.content_digest
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM network_policy_serving_pins
                 WHERE boundary_id = ?3 AND revision = ?4
                   AND usage_kind = 'endpoint_listener' AND target_kind = 'endpoint'
                   AND target_stable_id = ?1 AND target_generation_key = ?5
                   AND target_configuration_digest = ?6
                   AND EXISTS (SELECT 1 FROM endpoints
                     WHERE id = ?1 AND resource_version = ?2)
                   AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                     WHERE boundary_id = ?3 AND revision = ?4 AND consumer_version = ?7)
                   AND NOT EXISTS (SELECT 1 FROM endpoint_scope_grant_pins
                     WHERE endpoint_id = ?1)",
                    vals![
                        endpoint_id,
                        expected_version,
                        endpoint.network_policy_id,
                        revision.boundary_revision,
                        generation,
                        revision.content_digest,
                        consumer_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE network_policy_revision_lifecycle
                     SET consumer_version = consumer_version + 1
                     WHERE boundary_id = ?1 AND revision = ?2
                       AND state IN ('active', 'retiring') AND consumer_version = ?3
                       AND NOT EXISTS (SELECT 1 FROM network_policy_serving_pins
                         WHERE boundary_id = ?1 AND revision = ?2
                           AND usage_kind = 'endpoint_listener'
                           AND target_kind = 'endpoint' AND target_stable_id = ?4)
                       AND EXISTS (SELECT 1 FROM endpoints
                         WHERE id = ?4 AND resource_version = ?5)",
                    vals![
                        endpoint.network_policy_id,
                        revision.boundary_revision,
                        consumer_version,
                        endpoint_id,
                        expected_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM endpoints WHERE id = ?1 AND resource_version = ?2
                   AND NOT EXISTS (SELECT 1 FROM endpoint_scope_grant_pins
                     WHERE endpoint_id = ?1)
                   AND EXISTS (SELECT 1 FROM network_policy_revision_lifecycle
                     WHERE boundary_id = ?3 AND revision = ?4 AND consumer_version = ?5)
                   AND NOT EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.state IN ('pending', 'running')
                       AND o.operation_kind <> 'consumer_scope_grant_revocation' AND (
                       (o.primary_target_kind = 'endpoint'
                         AND o.primary_target_stable_id = ?1)
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                         WHERE t.operation_id = o.operation_id
                           AND t.target_kind = 'endpoint' AND t.stable_id = ?1)))",
                    vals![
                        endpoint_id,
                        expected_version,
                        endpoint.network_policy_id,
                        revision.boundary_revision,
                        consumer_version + 1
                    ],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.endpoint.deleted",
                    owner_scope_key: &endpoint.owner_scope_key,
                    resource_kind: "endpoint",
                    resource_stable_id: endpoint_id,
                    resource_generation_key: generation,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        if self.endpoint(endpoint_id).await?.is_some() {
            bail!("endpoint is stale or still referenced");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision_spec() -> NetworkPolicyRevisionSpec {
        NetworkPolicyRevisionSpec {
            protected_transport_required: true,
            trusted_ingress_kind: "none".to_owned(),
            trusted_ingress_configuration: "{}".to_owned(),
            source_allowlist_cidrs: None,
            probe_location_configuration: "probe:us-west".to_owned(),
        }
    }

    #[test]
    fn boundary_fingerprints_match_normative_vectors() {
        assert_eq!(
            hex::encode(
                NetworkPolicyIdentitySpec::Public
                    .fingerprint("instance")
                    .unwrap()
            ),
            "a45d7088ef1cb3f42b0f7c1284e56a781daabc736ecce73134b8e4f53078c08d"
        );
        let source = NetworkPolicyIdentitySpec::SourceAllowlist {
            logical_id: "prod".to_owned(),
        };
        assert_eq!(
            hex::encode(
                source
                    .fingerprint("org:00000000000000000000000000000001")
                    .unwrap()
            ),
            "a9b44e3f188c15c96b985c1746d7f6a990e6dce473c6879b66e5189cc324a4f3"
        );
        let vpc = NetworkPolicyIdentitySpec::Vpc {
            provider: "aws".to_owned(),
            account_or_tenant: "123456789012".to_owned(),
            resource_id: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789abcdef0".to_owned(),
        };
        assert_eq!(
            hex::encode(vpc.fingerprint("instance").unwrap()),
            "beec20e1ae5f82f5a55a53d425d4e9a08521808d787a209b8c2a589ac39b412e"
        );
        let uppercase_account = NetworkPolicyIdentitySpec::Vpc {
            provider: "aws".to_owned(),
            account_or_tenant: "Tenant-A".to_owned(),
            resource_id: "provider:network:one".to_owned(),
        };
        assert!(uppercase_account.fingerprint("instance").is_err());
    }

    #[test]
    fn cidrs_are_masked_sorted_and_deduplicated() {
        assert_eq!(
            canonicalize_cidrs(&[
                "2001:db8::5/64".to_owned(),
                "10.2.3.4/8".to_owned(),
                "10.0.0.1/8".to_owned(),
            ])
            .unwrap(),
            vec!["10.0.0.0/8", "2001:db8::/64"]
        );
        assert!(canonicalize_cidrs(&["::ffff:192.0.2.1/128".to_owned()]).is_err());
    }

    #[test]
    fn security_configurations_are_closed_and_require_exact_fields() {
        let mut boundary = revision_spec();
        boundary.trusted_ingress_kind = "mtls".to_owned();
        boundary.trusted_ingress_configuration = "{}".to_owned();
        assert!(validate_boundary_revision_spec(&boundary).is_err());
        boundary.trusted_ingress_configuration =
            "{\"ca_secret_ref\":\"secret:ca\",\"client_sans\":[],\"extra\":true}".to_owned();
        assert!(validate_boundary_revision_spec(&boundary).is_err());

        let endpoint = EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_owned(),
            listener_configuration: "listener:test".to_owned(),
            tls_configuration: "{\"garbage\":true}".to_owned(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_owned(),
        };
        assert!(validate_endpoint_revision_spec(&endpoint).is_err());
    }

    #[tokio::test]
    async fn domain_mutations_are_version_checked_and_paged() {
        let db = Database::open_in_memory().await.unwrap();
        assert!(db
            .create_delivery_domain("instance", None, "www.example.test:443", "plan-invalid")
            .await
            .is_err());
        let first = db
            .create_delivery_domain("instance", None, "WWW.Example.test", "plan-create")
            .await
            .unwrap();
        assert_eq!(first.hostname, "www.example.test");
        let recovered = db
            .delivery_domain_created_by_plan("plan-create", "instance", None, "WWW.EXAMPLE.TEST")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.stable_id, first.stable_id);
        assert!(db
            .delivery_domain_created_by_plan("another-plan", "instance", None, "www.example.test",)
            .await
            .unwrap()
            .is_none());
        let dns = DeliveryDnsConfigurationSpec::HubManaged {
            provider: "cloudflare".to_owned(),
            zone_id: "zone:test".to_owned(),
            record_mode: "managed".to_owned(),
            target: "edge.example.test".to_owned(),
            ttl_seconds: 300,
        };
        let configured = db
            .configure_delivery_domain_dns(&first.stable_id, &dns, 1, "plan-dns")
            .await
            .unwrap();
        assert_eq!(configured.resource_version, 2);
        assert!(db
            .delivery_domain_matches_configuration_plan(
                &first.stable_id,
                2,
                "plan-dns",
                Some(&dns),
                None,
            )
            .await
            .unwrap());
        assert!(!db
            .delivery_domain_matches_configuration_plan(
                &first.stable_id,
                2,
                "another-plan",
                Some(&dns),
                None,
            )
            .await
            .unwrap());
        assert_eq!(
            configured.dns_configuration_json.as_deref(),
            Some(
                "{\"kind\":\"hub_managed\",\"provider\":\"cloudflare\",\"zone_id\":\"zone:test\",\"record_mode\":\"managed\",\"target\":\"edge.example.test\",\"ttl_seconds\":300}"
            )
        );
        let certificate = DeliveryCertificateConfigurationSpec::External {
            certificate_secret_ref: "secret:certificate:1".to_owned(),
        };
        assert!(db
            .configure_delivery_domain_certificate(
                &first.stable_id,
                &certificate,
                1,
                "plan-certificate",
            )
            .await
            .is_err());
        let page = db
            .list_delivery_domains_page("instance", 1, None)
            .await
            .unwrap();
        assert_eq!(page.records.len(), 1);
    }

    #[tokio::test]
    async fn public_boundary_seed_matches_the_normative_posture() {
        let db = Database::open_in_memory().await.unwrap();
        let boundary = db.network_policy("instance:public").await.unwrap().unwrap();
        assert_eq!(
            boundary.identity_fingerprint,
            "a45d7088ef1cb3f42b0f7c1284e56a781daabc736ecce73134b8e4f53078c08d"
        );
        assert_eq!(boundary.default_revision, Some(1));
        let revision = db
            .network_policy_revision("instance:public", 1)
            .await
            .unwrap()
            .unwrap();
        assert!(!revision.spec.protected_transport_required);
        assert_eq!(revision.spec.probe_location_configuration, "");
        assert_eq!(
            revision.content_digest,
            "04f0d6f002c20c3711ec06812007e824b6c56782afd71288992894e5c5dce0cd"
        );
        assert_eq!(revision.observation_state, "verified");
        assert!(!revision.protected_transport_observed);
        assert_eq!(revision.lifecycle_state, "active");
        assert_eq!(revision.activation_mode, "system");
        let grant = db
            .backend
            .query_opt(
                "SELECT grant_kind, state, grant_generation
                 FROM network_policy_consumer_scopes
                 WHERE boundary_id = 'instance:public'
                   AND consumer_scope_key = 'instance'",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(grant.get::<String>(0).unwrap(), "instance_default");
        assert_eq!(grant.get::<String>(1).unwrap(), "active");
        assert_eq!(grant.get::<i64>(2).unwrap(), 1);
        let seed_event_count = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM consumer_scope_grant_events
                 WHERE resource_kind = 'network_policy'
                   AND resource_stable_id = 'instance:public'
                   AND consumer_scope_key = 'instance'
                   AND grant_generation = 1 AND transition = 'granted'
                   AND resulting_state = 'active'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(seed_event_count, 1);

        let org_id = db.create_org("seeded", "Seeded").await.unwrap();
        let org_scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
        let org_grant = db
            .backend
            .query_opt(
                "SELECT grant_kind, state FROM network_policy_consumer_scopes
                 WHERE boundary_id = 'instance:public'
                   AND consumer_scope_key = ?1",
                &vals![org_scope],
            )
            .await
            .unwrap();
        assert!(org_grant.is_none());
        let org_event_count = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM consumer_scope_grant_events
                 WHERE resource_kind = 'network_policy'
                   AND resource_stable_id = 'instance:public'
                   AND consumer_scope_key = ?1
                   AND grant_generation = 1 AND transition = 'granted'
                   AND resulting_state = 'active'",
                &vals![org_scope],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(org_event_count, 0);
    }

    #[tokio::test]
    async fn boundary_lifecycle_requires_verified_observation_and_cas() {
        let db = Database::open_in_memory().await.unwrap();
        let identity = NetworkPolicyIdentitySpec::Vpc {
            provider: "aws".to_owned(),
            account_or_tenant: "123456789012".to_owned(),
            resource_id: "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-test".to_owned(),
        };
        db.create_network_policy(
            "boundary:test",
            "instance",
            None,
            "test",
            &identity,
            &revision_spec(),
            "test",
            "request:test",
        )
        .await
        .unwrap();
        let default_cas = NetworkPolicyDefaultCas {
            boundary_resource_version: 1,
            previous_revision: None,
            previous_resource_version: None,
        };
        assert!(db
            .activate_network_policy_revision(
                "boundary:test",
                1,
                "overlap",
                Some(&default_cas),
                1,
                "system",
                None,
                "test",
                None,
                &[],
                &[],
                &[],
            )
            .await
            .is_err());
        assert!(db
            .reconcile_network_policy_revision(
                "boundary:test",
                1,
                "verified",
                false,
                "none",
                None,
                1,
            )
            .await
            .is_err());
        assert!(db
            .reconcile_network_policy_revision(
                "boundary:test",
                1,
                "verified",
                true,
                "mtls",
                None,
                1,
            )
            .await
            .is_err());
        let observed = db
            .reconcile_network_policy_revision(
                "boundary:test",
                1,
                "verified",
                true,
                "none",
                None,
                1,
            )
            .await
            .unwrap();
        assert_eq!(observed.resource_version, 2);
        let stale_default_cas = NetworkPolicyDefaultCas {
            boundary_resource_version: 99,
            previous_revision: None,
            previous_resource_version: None,
        };
        assert!(db
            .activate_network_policy_revision(
                "boundary:test",
                1,
                "overlap",
                Some(&stale_default_cas),
                2,
                "system",
                None,
                "test",
                None,
                &[],
                &[],
                &[],
            )
            .await
            .is_err());
        let active = db
            .activate_network_policy_revision(
                "boundary:test",
                1,
                "overlap",
                Some(&default_cas),
                2,
                "system",
                None,
                "test",
                None,
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(active.lifecycle_state, "active");
        assert_eq!(db.materialize_topology_events().await.unwrap(), 1);
        let activation_audit = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM audit_log
                 WHERE action = 'topology.network_policy.activated'
                   AND scope = 'instance' AND outbox_event_id IS NOT NULL",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(activation_audit, 1);
        db.revise_network_policy("boundary:test", &revision_spec(), "test", 2)
            .await
            .unwrap();
        db.reconcile_network_policy_revision("boundary:test", 2, "verified", true, "none", None, 1)
            .await
            .unwrap();
        let stale_existing_default = NetworkPolicyDefaultCas {
            boundary_resource_version: 3,
            previous_revision: Some(1),
            previous_resource_version: Some(99),
        };
        assert!(db
            .activate_network_policy_revision(
                "boundary:test",
                2,
                "overlap",
                Some(&stale_existing_default),
                2,
                "system",
                None,
                "test",
                None,
                &[],
                &[],
                &[],
            )
            .await
            .is_err());
        let existing_default = NetworkPolicyDefaultCas {
            boundary_resource_version: 3,
            previous_revision: Some(1),
            previous_resource_version: Some(1),
        };
        db.activate_network_policy_revision(
            "boundary:test",
            2,
            "coordinated",
            Some(&existing_default),
            2,
            "system",
            None,
            "test",
            Some("operation:boundary-test"),
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
        let coordination = db
            .topology_operation("operation:boundary-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            coordination.operation_kind,
            "network_policy_coordinated_activation"
        );
        assert_eq!(coordination.primary_target_generation_key, 2);
        assert_eq!(
            db.network_policy_revision("boundary:test", 2)
                .await
                .unwrap()
                .unwrap()
                .lifecycle_state,
            "activating"
        );
        let claimed = db
            .claim_network_policy_coordination_operation(
                "operation:boundary-test",
                coordination.resource_version,
                30,
            )
            .await
            .unwrap()
            .unwrap();
        db.finalize_network_policy_coordination(
            "operation:boundary-test",
            claimed.resource_version,
            "boundary:test",
            2,
            &db.network_policy_revision("boundary:test", 2)
                .await
                .unwrap()
                .unwrap()
                .content_digest,
            &[],
            Some(&existing_default),
            "system",
            None,
            "test",
        )
        .await
        .unwrap();
        assert_eq!(
            db.network_policy_revision("boundary:test", 2)
                .await
                .unwrap()
                .unwrap()
                .lifecycle_state,
            "active"
        );
        assert!(db
            .reconcile_network_policy_revision(
                "boundary:test",
                1,
                "verified",
                true,
                "none",
                None,
                2,
            )
            .await
            .is_err());

        let endpoint_spec = EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_owned(),
            listener_configuration: "listener:test".to_owned(),
            tls_configuration: "{\"provider\":\"external\",\"certificate_ref\":\"secret:test\",\"require_client_certificate\":false}".to_owned(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_owned(),
        };
        let endpoint = db
            .create_endpoint(
                "endpoint:test",
                "instance",
                None,
                "https",
                &EndpointHostInput::Ipv4([192, 0, 2, 1]),
                443,
                "boundary:test",
                &endpoint_spec,
                None,
                "test",
                "request:endpoint-create",
            )
            .await
            .unwrap();
        assert_eq!(endpoint.desired_generation, Some(1));
        assert_eq!(
            db.network_policy_serving_pins("boundary:test", 1)
                .await
                .unwrap()
                .len(),
            1
        );
        let observation = db
            .reconcile_endpoint("endpoint:test", 1, 1, "healthy", true, true, None, 1)
            .await
            .unwrap();
        assert_eq!(observation.state, "healthy");
        let initial_pin = db
            .network_policy_serving_pins("boundary:test", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        db.create_org("consumer", "Consumer").await.unwrap();
        let consumer_scope = db.org_by_slug("consumer").await.unwrap().unwrap().stable_id;
        db.grant_consumer_scope(
            crate::db::GrantResource::Endpoint {
                id: "endpoint:test",
                generation: 1,
            },
            &consumer_scope,
            "explicit",
            "test",
            "request:grant-consumer",
        )
        .await
        .unwrap();
        let owner_grant = EndpointGrantCarryForward {
            consumer_scope_key: "instance".to_owned(),
            grant_generation: 1,
            resource_version: 1,
        };
        assert!(db
            .stage_endpoint_generation(
                "endpoint:test",
                &endpoint_spec,
                &owner_grant,
                &[EndpointGrantCarryForward {
                    consumer_scope_key: consumer_scope.clone(),
                    grant_generation: 1,
                    resource_version: 2,
                }],
                "test",
                "request:endpoint-stage-stale-carry",
                2,
            )
            .await
            .is_err());
        let unchanged = db.endpoint("endpoint:test").await.unwrap().unwrap();
        assert_eq!(unchanged.desired_generation, Some(1));
        assert_eq!(unchanged.resource_version, 2);
        assert!(db
            .endpoint_revision("endpoint:test", 2)
            .await
            .unwrap()
            .is_none());
        let leaked_events: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM consumer_scope_grant_events
                 WHERE resource_kind = 'endpoint'
                   AND resource_stable_id = 'endpoint:test'
                   AND resource_generation_key = 2",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(leaked_events, 0);
        assert_eq!(
            db.network_policy_serving_pins("boundary:test", 1)
                .await
                .unwrap(),
            vec![initial_pin]
        );

        let staged = db
            .stage_endpoint_generation(
                "endpoint:test",
                &endpoint_spec,
                &owner_grant,
                &[EndpointGrantCarryForward {
                    consumer_scope_key: consumer_scope.clone(),
                    grant_generation: 1,
                    resource_version: 1,
                }],
                "test",
                "request:endpoint-stage-valid-carry",
                2,
            )
            .await
            .unwrap();
        assert_eq!(staged.generation, 2);
        let staged_endpoint = db.endpoint("endpoint:test").await.unwrap().unwrap();
        assert_eq!(staged_endpoint.desired_generation, Some(1));
        assert_eq!(staged_endpoint.resource_version, 3);
        let carried_grant = db
            .load_consumer_scope_grant(
                crate::db::GrantResource::Endpoint {
                    id: "endpoint:test",
                    generation: 2,
                },
                &consumer_scope,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(carried_grant.state, "active");
        assert_eq!(carried_grant.grant_generation, 1);

        let revisions = db.endpoint_revisions("endpoint:test").await.unwrap();
        assert_eq!(revisions.len(), 2);
        let updated = db
            .activate_staged_endpoint_generation(
                "endpoint:test",
                2,
                3,
                false,
                "system",
                None,
                "test",
            )
            .await
            .unwrap();
        assert_eq!(updated.desired_generation, Some(2));
        assert_eq!(updated.resource_version, 4);
        let retained_observation = db
            .endpoint_generation_observation("endpoint:test", 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained_observation.state, "healthy");
        assert!(db
            .endpoint_revision("endpoint:test", 2)
            .await
            .unwrap()
            .is_some());
        assert!(db
            .endpoint_revision("endpoint:test", 3)
            .await
            .unwrap()
            .is_none());
        let pins = db
            .network_policy_serving_pins("boundary:test", 1)
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].target_generation_key, 2);
        assert_ne!(pins[0].target_configuration_digest, "");
        db.delete_endpoint("endpoint:test", 4, "user", Some(1), "test")
            .await
            .unwrap();
    }
}
