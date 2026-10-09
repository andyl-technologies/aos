//! Tenancy records returned by typed Hub persistence operations.

use super::*;

/// An organization (tenant boundary) system-of-record row.
#[derive(Debug, Clone)]
pub struct OrgRecord {
    /// Database id.
    pub id: i64,
    /// Non-reusable organization incarnation id and canonical scope key.
    pub stable_id: String,
    /// URL-safe unique slug the org is addressed by.
    pub slug: String,
    /// Human-readable display name.
    pub name: String,
    /// Unix time the org was created.
    pub created_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Unix time of the latest profile mutation.
    pub updated_at: i64,
}

/// Per-org quota caps on hub-managed resources (system-of-record row).
///
/// Mirrors the `org_quotas` row. Every cap is optional: `None` means *that*
/// dimension is unlimited (an org with no `org_quotas` row at all is
/// unlimited on every dimension). Quotas are enforced at typed upload admission
/// (bytes/objects, via [`Database::would_exceed_quota`]) and in the
/// registry/token create paths (counts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgQuota {
    /// Maximum total stored bytes, or `None` for unlimited.
    pub max_bytes: Option<i64>,
    /// Maximum total stored objects, or `None` for unlimited.
    pub max_objects: Option<i64>,
    /// Maximum number of registries, or `None` for unlimited.
    pub max_registries: Option<i64>,
    /// Maximum number of active (non-revoked) tokens, or `None` for unlimited.
    pub max_tokens: Option<i64>,
}

/// Per-org running usage totals (system-of-record row).
///
/// Mirrors the `org_usage` row. The totals are maintained incrementally on
/// each upload ([`Database::add_org_usage`]) and are *approximate* — they
/// count bytes as written, so a deleted object's bytes linger until a
/// re-index/GC reconciliation (a later refinement) rebuilds them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgUsage {
    /// Total bytes written under the org's managed registries.
    pub used_bytes: i64,
    /// Total objects written under the org's managed registries.
    pub object_count: i64,
    /// Unix time the totals were last updated.
    pub updated_at: i64,
}

/// The instance-wide policy gating who may create organizations.
///
/// Stored in `instance_config` under the key `signup_policy`; see
/// [`Database::signup_policy`]. The default is [`SignupPolicy::InviteOnly`]
/// (the hosted-instance posture: free hub-managed storage behind open signup
/// is an abuse magnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum SignupPolicy {
    /// Any authenticated principal may create an org.
    Open,
    /// Org creation requires an invitation or an existing membership (or an
    /// instance admin). The safe default.
    #[default]
    InviteOnly,
}

/// A project (materialized-path node) system-of-record row.
#[derive(Debug, Clone)]
pub struct ProjectRecord {
    /// Database id.
    pub id: i64,
    /// Non-reusable project incarnation identity.
    pub stable_id: String,
    /// Exact stable authorization scope for the project.
    pub scope_key: String,
    /// Infrastructure-owner scope for resources owned by the project.
    pub owner_scope_key: String,
    /// Owning org id.
    pub org_id: i64,
    /// Materialized path within the org (`""` for an org-root project).
    pub path: String,
    /// Human-readable display name.
    pub name: String,
    /// Unix time the project was created.
    pub created_at: i64,
    /// Optimistic-concurrency version for project lifecycle changes.
    pub resource_version: i64,
    /// Last lifecycle update time in Unix seconds.
    pub updated_at: i64,
}

/// A captured (DNS-TXT-verifiable) email domain bound to an org.
#[derive(Debug, Clone)]
pub struct OrgDomainRecord {
    /// The fully-qualified domain (lowercased).
    pub domain: String,
    /// The org that claimed the domain.
    pub org_id: i64,
    /// The TXT record value the org must publish to prove control.
    pub txt_challenge: String,
    /// Unix time the domain was verified, or `None` while unverified.
    pub verified_at: Option<i64>,
    /// Optimistic-concurrency version for claim lifecycle mutations.
    pub resource_version: i64,
    /// Immutable incarnation that changes when a released domain is reclaimed.
    pub incarnation_id: Option<String>,
    /// Reviewed plan that produced the current state, when any.
    pub mutation_plan_id: Option<String>,
}

impl SignupPolicy {
    /// The wire string stored in `instance_config.value`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SignupPolicy::Open => "open",
            SignupPolicy::InviteOnly => "invite_only",
        }
    }

    /// Parse a stored policy string, defaulting to [`SignupPolicy::InviteOnly`]
    /// for any unknown value (fail closed).
    #[must_use]
    pub fn parse(s: &str) -> SignupPolicy {
        match s {
            "open" => SignupPolicy::Open,
            _ => SignupPolicy::InviteOnly,
        }
    }
}
