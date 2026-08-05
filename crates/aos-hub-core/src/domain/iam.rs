//! Pure tenancy authorization: roles, permissions, stable scopes, and the
//! `allow` decision function.
//!
//! This module is **IO-free and wasm-clean**: it owns no database handle,
//! reads no clock, and allocates only short strings. It is the kernel that
//! both runtimes (native and Workers) share for every authorization
//! decision, so it stays a pure function of its inputs.
//!
//! # Roles and permissions
//!
//! [`Role`] is the five-rung ladder from RFC-0004's role table — `owner`,
//! `admin`, `maintainer`, `developer`, `viewer`. Each role expands to a
//! fixed set of [`Permission`] verbs via [`role_grants`]; the expansion is
//! the authoritative encoding of that table.
//!
//! # Scope grammar
//!
//! A [`Scope`] is a non-reusable identity naming an authorization boundary.
//! Human-facing slugs and paths are deliberately absent from its grammar:
//!
//! ```text
//! scope         := "instance"
//!                | "org:" lower_hex_32
//!                | "project:" lower_hex_32
//!                | "registry:" lower_hex_32
//!                | "cache:" lower_hex_32
//! lower_hex_32  := 32 lowercase hexadecimal digits
//! ```
//!
//! Scope keys contain no hierarchy. [`AuthorizationContext`] carries the
//! validated ancestor closure loaded from `authorization_scope_ancestors`.
//! This keeps identity stable across slug changes and reparenting while making
//! every inheritance decision explicit and auditable.
//!
//! # Decision function
//!
//! [`allow`] answers "may a principal with these `(scope, role)` grants
//! perform `permission` on `target`?" — true iff some grant at scope `S`
//! with role `R` satisfies both `target.ancestors.contains(S)` and `role_grants(R)`
//! includes `permission`.

/// A role on the five-rung RFC-0004 ladder, grantable at any scope.
///
/// Higher [`Role::rank`] means more authority; [`Role::Owner`] is highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Everything, including delete, ownership transfer, and IAM admin.
    Owner,
    /// Members, tokens, registries, delivery topology, storage, signing keys.
    Admin,
    /// Publish, advance channels, manage rosters, repair validation.
    Maintainer,
    /// Read private surfaces and topology metadata; self-service own tokens.
    Developer,
    /// Read private surfaces and topology metadata without token self-service.
    Viewer,
}

impl Role {
    /// Returns the snake-case wire name of this role.
    ///
    /// The returned string is the exact token stored in the
    /// `memberships.role` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Maintainer => "maintainer",
            Role::Developer => "developer",
            Role::Viewer => "viewer",
        }
    }

    /// Parses a role from its snake-case wire name.
    ///
    /// Returns `None` for any string that is not one of the five role
    /// names.
    #[must_use]
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "owner" => Some(Role::Owner),
            "admin" => Some(Role::Admin),
            "maintainer" => Some(Role::Maintainer),
            "developer" => Some(Role::Developer),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }

    /// Returns the authority rank of this role: higher is more powerful.
    ///
    /// [`Role::Owner`] is `4` and [`Role::Viewer`] is `0`. Ranks order
    /// roles for "at least this role" comparisons; they are not a
    /// substitute for permission checks, which go through [`role_grants`].
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Role::Owner => 4,
            Role::Admin => 3,
            Role::Maintainer => 2,
            Role::Developer => 1,
            Role::Viewer => 0,
        }
    }
}

/// A permission verb — one capability a [`Role`] may grant.
///
/// The verbs mirror RFC-0004's permission list; [`role_grants`] maps each
/// role to the exact set it confers.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Permission {
    /// Read registry content (private registries, member lists, etc.).
    Read,
    /// Publish releases and tags.
    Publish,
    /// Advance or initialize channels.
    ChannelAdvance,
    /// Manage the registry's key roster.
    KeysManage,
    /// Manage one's own provisioning tokens.
    TokensSelf,
    /// Manage other principals' tokens.
    TokensManage,
    /// Manage memberships and role grants.
    MembersManage,
    /// Configure registries and their delivery topology.
    RegistryConfigure,
    /// Manage storage bindings, buckets, and cache stores.
    StorageManage,
    /// Read storage-binding identity and redacted health information.
    ///
    /// Provider coordinates and credential metadata require
    /// [`Permission::StorageBindingManage`].
    StorageBindingRead,
    /// Create, revise, and retire storage bindings.
    StorageBindingManage,
    /// Grant a storage binding to another authorization scope.
    StorageBindingGrant,
    /// Read placement configuration and observations.
    PlacementRead,
    /// Create, reconcile, promote, drain, or remove placements.
    PlacementManage,
    /// Read immutable placement-policy revisions.
    PlacementPolicyRead,
    /// Create and publish placement-policy revisions.
    PlacementPolicyManage,
    /// Read delivery-domain configuration and observations.
    DomainRead,
    /// Configure, verify, replace, or delete delivery domains.
    DomainManage,
    /// Read network-boundary identities and revisions.
    NetworkBoundaryRead,
    /// Create, probe, activate, retire, or delete network boundaries.
    NetworkBoundaryManage,
    /// Grant network-boundary revisions across authorization scopes.
    NetworkBoundaryGrant,
    /// Read delivery-endpoint identities and generations.
    DeliveryEndpointRead,
    /// Create, probe, reconcile, replace, or delete delivery endpoints.
    DeliveryEndpointManage,
    /// Grant delivery-endpoint generations across authorization scopes.
    DeliveryEndpointGrant,
    /// Read direct-delivery storage gateways and generations.
    StorageGatewayRead,
    /// Create, reconcile, enable, disable, replace, or delete gateways.
    StorageGatewayManage,
    /// Grant storage-gateway generations across authorization scopes.
    StorageGatewayGrant,
    /// Read and explain delivery routes.
    RouteRead,
    /// Create, probe, enable, disable, replace, or delete delivery routes.
    RouteManage,
    /// Reconcile controller-observed surface write authority.
    TopologyReconcile,
    /// Manage registry-derived retention policy and manual roots.
    CacheRetentionManage,
    /// Build and inspect destructive cache-GC plans.
    CacheGcPlan,
    /// Apply cache-GC plans and administer deletion work.
    CacheGcExecute,
    /// Manage only leases owned by the calling service account.
    CacheLeaseSelf,
    /// Run consistency-validation repair jobs.
    ValidationRepair,
    /// Read the audit log.
    AuditRead,
    /// Full IAM administration (the owner-only verb).
    IamAdmin,
}

impl Permission {
    /// Returns the snake-case wire name of this permission verb.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Publish => "publish",
            Permission::ChannelAdvance => "channel.advance",
            Permission::KeysManage => "keys.manage",
            Permission::TokensSelf => "tokens.self",
            Permission::TokensManage => "tokens.manage",
            Permission::MembersManage => "members.manage",
            Permission::RegistryConfigure => "registry.configure",
            Permission::StorageManage => "storage.manage",
            Permission::StorageBindingRead => "storage_binding.read",
            Permission::StorageBindingManage => "storage_binding.manage",
            Permission::StorageBindingGrant => "storage_binding.grant",
            Permission::PlacementRead => "placement.read",
            Permission::PlacementManage => "placement.manage",
            Permission::PlacementPolicyRead => "placement_policy.read",
            Permission::PlacementPolicyManage => "placement_policy.manage",
            Permission::DomainRead => "domain.read",
            Permission::DomainManage => "domain.manage",
            Permission::NetworkBoundaryRead => "network_boundary.read",
            Permission::NetworkBoundaryManage => "network_boundary.manage",
            Permission::NetworkBoundaryGrant => "network_boundary.grant",
            Permission::DeliveryEndpointRead => "delivery_endpoint.read",
            Permission::DeliveryEndpointManage => "delivery_endpoint.manage",
            Permission::DeliveryEndpointGrant => "delivery_endpoint.grant",
            Permission::StorageGatewayRead => "storage_gateway.read",
            Permission::StorageGatewayManage => "storage_gateway.manage",
            Permission::StorageGatewayGrant => "storage_gateway.grant",
            Permission::RouteRead => "route.read",
            Permission::RouteManage => "route.manage",
            Permission::TopologyReconcile => "topology.reconcile",
            Permission::CacheRetentionManage => "cache.retention.manage",
            Permission::CacheGcPlan => "cache.gc.plan",
            Permission::CacheGcExecute => "cache.gc.execute",
            Permission::CacheLeaseSelf => "cache.lease.self",
            Permission::ValidationRepair => "validation.repair",
            Permission::AuditRead => "audit.read",
            Permission::IamAdmin => "iam.admin",
        }
    }
}

/// Returns the exact set of permission verbs a [`Role`] confers.
///
/// This is the authoritative encoding of RFC-0004's role table:
///
/// - **Owner** — every verb, including [`Permission::IamAdmin`].
/// - **Admin** — members, tokens (manage), registries/delivery/storage
///   configuration, validation repair, audit read, plus the baseline
///   read and self-token verbs.
/// - **Maintainer** — publish, channel advance, roster (key) management,
///   validation repair, plus read and self-tokens.
/// - **Developer** — registry read, specialized topology reads, and
///   self-service tokens.
/// - **Viewer** — registry and specialized topology reads only.
///
/// The slices are `'static` and ordered for stable iteration; callers
/// must treat them as sets.
#[must_use]
pub fn role_grants(role: Role) -> &'static [Permission] {
    use Permission::*;
    match role {
        Role::Owner => &[
            Read,
            Publish,
            ChannelAdvance,
            KeysManage,
            TokensSelf,
            TokensManage,
            MembersManage,
            RegistryConfigure,
            StorageManage,
            StorageBindingRead,
            StorageBindingManage,
            StorageBindingGrant,
            PlacementRead,
            PlacementManage,
            PlacementPolicyRead,
            PlacementPolicyManage,
            DomainRead,
            DomainManage,
            NetworkBoundaryRead,
            NetworkBoundaryManage,
            NetworkBoundaryGrant,
            DeliveryEndpointRead,
            DeliveryEndpointManage,
            DeliveryEndpointGrant,
            StorageGatewayRead,
            StorageGatewayManage,
            StorageGatewayGrant,
            RouteRead,
            RouteManage,
            TopologyReconcile,
            CacheRetentionManage,
            CacheGcPlan,
            CacheGcExecute,
            CacheLeaseSelf,
            ValidationRepair,
            AuditRead,
            IamAdmin,
        ],
        Role::Admin => &[
            Read,
            TokensSelf,
            TokensManage,
            MembersManage,
            RegistryConfigure,
            StorageManage,
            StorageBindingRead,
            StorageBindingManage,
            StorageBindingGrant,
            PlacementRead,
            PlacementManage,
            PlacementPolicyRead,
            PlacementPolicyManage,
            DomainRead,
            DomainManage,
            NetworkBoundaryRead,
            NetworkBoundaryManage,
            NetworkBoundaryGrant,
            DeliveryEndpointRead,
            DeliveryEndpointManage,
            DeliveryEndpointGrant,
            StorageGatewayRead,
            StorageGatewayManage,
            StorageGatewayGrant,
            RouteRead,
            RouteManage,
            TopologyReconcile,
            CacheRetentionManage,
            CacheGcPlan,
            CacheGcExecute,
            ValidationRepair,
            AuditRead,
        ],
        Role::Maintainer => &[
            Read,
            TokensSelf,
            Publish,
            ChannelAdvance,
            KeysManage,
            ValidationRepair,
            StorageBindingRead,
            PlacementRead,
            PlacementPolicyRead,
            DomainRead,
            NetworkBoundaryRead,
            DeliveryEndpointRead,
            StorageGatewayRead,
            RouteRead,
        ],
        Role::Developer => &[
            Read,
            TokensSelf,
            StorageBindingRead,
            PlacementRead,
            PlacementPolicyRead,
            DomainRead,
            NetworkBoundaryRead,
            DeliveryEndpointRead,
            StorageGatewayRead,
            RouteRead,
        ],
        Role::Viewer => &[
            Read,
            StorageBindingRead,
            PlacementRead,
            PlacementPolicyRead,
            DomainRead,
            NetworkBoundaryRead,
            DeliveryEndpointRead,
            StorageGatewayRead,
            RouteRead,
        ],
    }
}

/// A globally stable authorization resource identity.
///
/// Human slugs, project paths, and parentage are never encoded into the key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(String);

impl serde::Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !Self::is_canonical(self.as_str()) {
            return Err(serde::ser::Error::custom(
                "unresolved authorization scope cannot be serialized",
            ));
        }
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!("non-canonical authorization scope '{value}'"))
        })
    }
}

impl Scope {
    /// Parses a canonical stable scope identity.
    ///
    /// Prefer [`Scope::try_parse`] at trust boundaries. This convenience is
    /// for schema-constrained database values and constants; malformed input
    /// becomes a deliberately unresolved scope that every authorization check
    /// denies and that cannot be serialized as a grant identity.
    #[must_use]
    pub fn parse(s: &str) -> Scope {
        Self::try_parse(s).unwrap_or_else(Self::denied)
    }

    /// Parses a canonical stable scope identity, rejecting slugs and malformed
    /// or alias spellings.
    #[must_use]
    pub fn try_parse(s: &str) -> Option<Scope> {
        Self::is_canonical(s).then(|| Scope(s.to_string()))
    }

    /// Returns a closed fail-denied target for a resource whose stable scope
    /// could not be resolved. It is never serializable as grant identity.
    pub(crate) fn denied() -> Scope {
        Scope("<unresolved>".to_string())
    }

    /// Returns the instance-root scope.
    #[must_use]
    pub fn root() -> Scope {
        Scope("instance".to_string())
    }

    /// Returns the exact stable scope key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this is the instance-root scope.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0 == "instance"
    }

    /// Returns `true` if `raw` is already in canonical scope form.
    ///
    /// Canonical scopes use the closed stable-identity grammar documented by
    /// this module. Uppercase hexadecimal, human slugs, arbitrary descendants,
    /// and path-normalization variants are rejected so one authority has only
    /// one serialized identity.
    #[must_use]
    pub fn is_canonical(raw: &str) -> bool {
        if raw == "instance" {
            return true;
        }
        let (prefix, id) = raw.split_once(':').unwrap_or_default();
        matches!(prefix, "org" | "project" | "registry" | "cache")
            && id.len() == 32
            && id.bytes().all(is_lower_hex)
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// A target scope together with its validated ancestor closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationContext {
    target: Scope,
    ancestors: Vec<Scope>,
}

impl AuthorizationContext {
    /// Constructs a context from database-validated canonical identities.
    ///
    /// # Errors
    ///
    /// Returns an error unless the target and every ancestor are canonical and
    /// the closure includes both the target itself and the instance root.
    pub fn try_new(target: Scope, ancestors: Vec<Scope>) -> Result<Self, &'static str> {
        if !Scope::is_canonical(target.as_str())
            || ancestors
                .iter()
                .any(|scope| !Scope::is_canonical(scope.as_str()))
        {
            return Err("authorization context contains a non-canonical scope");
        }
        if ancestors.first() != Some(&target) || !ancestors.last().is_some_and(Scope::is_root) {
            return Err("authorization context is not ordered from self to instance");
        }
        let unique = ancestors
            .iter()
            .map(Scope::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() != ancestors.len() {
            return Err("authorization context contains a duplicate ancestor");
        }
        Ok(Self { target, ancestors })
    }

    /// Returns an exact-scope context for the instance root.
    #[must_use]
    pub fn instance() -> Self {
        let root = Scope::root();
        Self {
            target: root.clone(),
            ancestors: vec![root],
        }
    }

    /// Returns the target resource identity.
    #[must_use]
    pub fn target(&self) -> &Scope {
        &self.target
    }

    /// Returns whether `scope` is the target or one of its ancestors.
    #[must_use]
    pub fn is_covered_by(&self, scope: &Scope) -> bool {
        self.ancestors.iter().any(|ancestor| ancestor == scope)
    }
}

/// Decides whether a principal's grants authorize `permission` on `target`.
///
/// Returns `true` iff some `(scope, role)` grant satisfies both:
///
/// 1. `scope` is present in the target's validated ancestor closure (roles
///    inherit downward), and
/// 2. `role_grants(role)` includes `permission`.
///
/// A grant on a sibling subtree never leaks. An empty `grants` slice denies
/// everything.
#[must_use]
pub fn allow(
    grants: &[(Scope, Role)],
    permission: Permission,
    target: &AuthorizationContext,
) -> bool {
    grants.iter().any(|(scope, role)| {
        target.is_covered_by(scope) && role_grants(*role).contains(&permission)
    })
}

/// Decides whether a JWT's own claims authorize `perm` on `target`.
///
/// Database-free once the caller has loaded the context: the token must be
/// bound to the target or one of its validated ancestors and must carry `perm`
/// explicitly. Unknown permission strings in the claims
/// are ignored. This is the token half of the two-sided authorization check —
/// the principal's *current* [`allow`] grants are the other half — so a revoked
/// role still denies even on an unexpired token. The bodies live here (shared by
/// the native hub and the Cloudflare Worker) rather than in either shell.
#[must_use]
pub fn token_allows(
    claims: &crate::auth::jwt::Claims,
    perm: Permission,
    target: &AuthorizationContext,
) -> bool {
    if !Scope::is_canonical(&claims.scope) {
        return false;
    }
    let scope = Scope::parse(&claims.scope);
    if !target.is_covered_by(&scope) {
        return false;
    }
    claims
        .perms
        .iter()
        .filter_map(|p| crate::auth::permission_from_str(p))
        .any(|p| p == perm)
}

/// The [`Principal`] a JWT's claims identify, if the `owner_kind` is known.
///
/// Returns `None` when `claims.owner_kind` is not a recognized
/// [`PrincipalKind`]; callers treat that as fail-closed (no principal, no
/// grants).
#[must_use]
pub fn claims_principal(claims: &crate::auth::jwt::Claims) -> Option<super::Principal> {
    super::PrincipalKind::parse(&claims.owner_kind).map(|kind| super::Principal {
        kind,
        id: claims.owner_id,
    })
}

/// Top-level slugs reserved for routes and the `/-/` namespace.
///
/// An org (or registry) may not take one of these names, since the slug
/// becomes a top-level URL path segment and would otherwise shadow a built-in
/// route or the management namespace.
const RESERVED_SLUGS: &[&str] = &[
    "_assets", "healthz", "metrics", "-", "login", "activate", "account", "new", "oauth2", "api",
];

/// Why a candidate org/registry slug was rejected by [`validate_org_slug`].
///
/// Carries no owned data; the offending slug is the caller's to format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlugError {
    /// The slug was the empty string.
    Empty,
    /// The slug collides with a reserved top-level route or the `/-/`
    /// namespace (see the `RESERVED_SLUGS` list).
    Reserved,
    /// The slug contained a character outside the allowed
    /// `[a-z0-9_-]` set — including any `/`, whitespace, control, or
    /// uppercase character.
    BadChar,
}

impl SlugError {
    /// Returns a human-readable explanation of this rejection.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            SlugError::Empty => "slug must not be empty",
            SlugError::Reserved => "slug is a reserved name",
            SlugError::BadChar => {
                "slug may contain only lowercase ASCII letters, digits, '-', and '_'"
            }
        }
    }
}

impl std::fmt::Display for SlugError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SlugError {}

/// Validates an organization (or registry) slug against the canonical
/// single-segment ruleset.
///
/// A slug is a top-level URL and display path segment, so it is constrained to
/// a conservative, single-segment, URL-safe charset. It is never an
/// authorization identity. This is the **one** authoritative ruleset shared by the
/// Connect RPC `CreateOrg`, the web console's new-org form, and the `aos`
/// CLI, so the three surfaces can never drift apart.
///
/// A valid slug is non-empty, is not a reserved name (`RESERVED_SLUGS`), and
/// consists only of lowercase ASCII letters, ASCII digits, `-`, and `_`.
/// Crucially it contains **no** `/`, so it remains one unambiguous routing
/// segment.
///
/// # Errors
///
/// Returns [`SlugError::Empty`] for the empty string,
/// [`SlugError::Reserved`] for a reserved name, and [`SlugError::BadChar`]
/// for any character outside `[a-z0-9_-]` (including `/`, whitespace,
/// control, and uppercase characters).
///
/// # Examples
///
/// ```
/// use aos_hub_core::domain::iam::{validate_org_slug, SlugError};
///
/// assert!(validate_org_slug("acme").is_ok());
/// assert!(validate_org_slug("cdn-edge_2").is_ok());
/// assert_eq!(validate_org_slug(""), Err(SlugError::Empty));
/// assert_eq!(validate_org_slug("/victimorg"), Err(SlugError::BadChar));
/// assert_eq!(validate_org_slug("Acme"), Err(SlugError::BadChar));
/// assert_eq!(validate_org_slug("api"), Err(SlugError::Reserved));
/// ```
pub fn validate_org_slug(slug: &str) -> Result<(), SlugError> {
    if slug.is_empty() {
        return Err(SlugError::Empty);
    }
    if RESERVED_SLUGS.contains(&slug) {
        return Err(SlugError::Reserved);
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(SlugError::BadChar);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_roundtrips_and_ranks() {
        for role in [
            Role::Owner,
            Role::Admin,
            Role::Maintainer,
            Role::Developer,
            Role::Viewer,
        ] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("nope"), None);
        assert!(Role::Owner.rank() > Role::Admin.rank());
        assert!(Role::Admin.rank() > Role::Maintainer.rank());
        assert!(Role::Maintainer.rank() > Role::Developer.rank());
        assert!(Role::Developer.rank() > Role::Viewer.rank());
    }

    fn grant_set(role: Role) -> std::collections::BTreeSet<Permission> {
        role_grants(role).iter().copied().collect()
    }

    #[test]
    fn owner_grants_everything() {
        use Permission::*;
        let all: std::collections::BTreeSet<Permission> = [
            Read,
            Publish,
            ChannelAdvance,
            KeysManage,
            TokensSelf,
            TokensManage,
            MembersManage,
            RegistryConfigure,
            StorageManage,
            StorageBindingRead,
            StorageBindingManage,
            StorageBindingGrant,
            PlacementRead,
            PlacementManage,
            PlacementPolicyRead,
            PlacementPolicyManage,
            DomainRead,
            DomainManage,
            NetworkBoundaryRead,
            NetworkBoundaryManage,
            NetworkBoundaryGrant,
            DeliveryEndpointRead,
            DeliveryEndpointManage,
            DeliveryEndpointGrant,
            StorageGatewayRead,
            StorageGatewayManage,
            StorageGatewayGrant,
            RouteRead,
            RouteManage,
            TopologyReconcile,
            CacheRetentionManage,
            CacheGcPlan,
            CacheGcExecute,
            CacheLeaseSelf,
            ValidationRepair,
            AuditRead,
            IamAdmin,
        ]
        .into_iter()
        .collect();
        assert_eq!(grant_set(Role::Owner), all);
        // The owner-only verb is exclusive to owner.
        assert!(grant_set(Role::Owner).contains(&IamAdmin));
        assert!(!grant_set(Role::Admin).contains(&IamAdmin));
    }

    #[test]
    fn admin_grants_management_but_not_publish() {
        use Permission::*;
        let g = grant_set(Role::Admin);
        for p in [
            Read,
            TokensSelf,
            TokensManage,
            MembersManage,
            RegistryConfigure,
            StorageManage,
            StorageBindingRead,
            StorageBindingManage,
            StorageBindingGrant,
            PlacementRead,
            PlacementManage,
            PlacementPolicyRead,
            PlacementPolicyManage,
            DomainRead,
            DomainManage,
            NetworkBoundaryRead,
            NetworkBoundaryManage,
            NetworkBoundaryGrant,
            DeliveryEndpointRead,
            DeliveryEndpointManage,
            DeliveryEndpointGrant,
            StorageGatewayRead,
            StorageGatewayManage,
            StorageGatewayGrant,
            RouteRead,
            RouteManage,
            TopologyReconcile,
            CacheRetentionManage,
            CacheGcPlan,
            CacheGcExecute,
            ValidationRepair,
            AuditRead,
        ] {
            assert!(g.contains(&p), "admin missing {p:?}");
        }
        assert!(!g.contains(&Publish));
        assert!(!g.contains(&ChannelAdvance));
        assert!(!g.contains(&KeysManage));
        assert!(!g.contains(&CacheLeaseSelf));
        assert!(!g.contains(&IamAdmin));
    }

    #[test]
    fn lease_self_requires_an_explicit_token_permission() {
        let scope = "org:00000000000000000000000000000001";
        assert!(!role_grants(Role::Admin).contains(&Permission::CacheLeaseSelf));
        let claims = crate::auth::jwt::Claims {
            sub: "service-token".to_string(),
            owner_kind: "service_account".to_string(),
            owner_id: 7,
            scope: scope.to_string(),
            perms: vec![Permission::CacheLeaseSelf.as_str().to_string()],
            authz_version: crate::auth::jwt::AUTHORIZATION_CLAIMS_VERSION.to_string(),
            iat: 0,
            exp: i64::MAX,
        };
        assert!(token_allows(
            &claims,
            Permission::CacheLeaseSelf,
            &AuthorizationContext::try_new(
                Scope::parse(scope),
                vec![Scope::parse(scope), Scope::root()],
            )
            .unwrap(),
        ));
    }

    #[test]
    fn maintainer_grants_publish_path() {
        use Permission::*;
        let g = grant_set(Role::Maintainer);
        for p in [
            Read,
            TokensSelf,
            Publish,
            ChannelAdvance,
            KeysManage,
            ValidationRepair,
        ] {
            assert!(g.contains(&p), "maintainer missing {p:?}");
        }
        assert!(!g.contains(&MembersManage));
        assert!(!g.contains(&TokensManage));
        assert!(!g.contains(&RegistryConfigure));
        assert!(!g.contains(&AuditRead));
    }

    #[test]
    fn developer_grants_exact_read_topology_and_self_token_set() {
        use Permission::*;
        assert_eq!(
            grant_set(Role::Developer),
            [
                Read,
                TokensSelf,
                StorageBindingRead,
                PlacementRead,
                PlacementPolicyRead,
                DomainRead,
                NetworkBoundaryRead,
                DeliveryEndpointRead,
                StorageGatewayRead,
                RouteRead,
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn viewer_grants_exact_read_topology_set() {
        use Permission::*;
        assert_eq!(
            grant_set(Role::Viewer),
            [
                Read,
                StorageBindingRead,
                PlacementRead,
                PlacementPolicyRead,
                DomainRead,
                NetworkBoundaryRead,
                DeliveryEndpointRead,
                StorageGatewayRead,
                RouteRead,
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn scope_parse_accepts_only_exact_stable_identity() {
        assert!(Scope::parse("instance").is_root());
        assert!(Scope::try_parse("/instance").is_none());
        assert!(Scope::try_parse("acme").is_none());
        assert!(Scope::try_parse("org:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none());
    }

    #[test]
    fn scope_is_canonical_blocks_normalization_surprises() {
        // Canonical scopes round-trip and are accepted.
        for good in [
            "instance",
            "org:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "project:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "registry:cccccccccccccccccccccccccccccccc",
            "cache:dddddddddddddddddddddddddddddddd",
        ] {
            assert!(Scope::is_canonical(good), "{good:?} should be canonical");
        }
        // Normalization-surprise inputs are rejected (CR-2).
        for bad in [
            "",
            "/",
            "acme",
            "org:acme",
            "org:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/p:old/path",
        ] {
            assert!(!Scope::is_canonical(bad), "{bad:?} should be non-canonical");
        }
    }

    #[test]
    fn validate_org_slug_enforces_single_segment_charset() {
        for good in ["acme", "a", "cdn-edge_2", "x9"] {
            assert!(validate_org_slug(good).is_ok(), "{good:?} should be valid");
        }
        assert_eq!(validate_org_slug(""), Err(SlugError::Empty));
        assert_eq!(validate_org_slug("api"), Err(SlugError::Reserved));
        assert_eq!(validate_org_slug("-"), Err(SlugError::Reserved));
        // Anything that would smuggle a path or out-of-charset char.
        for bad in [
            "/",
            "/victimorg",
            "foo/bar",
            "foo/",
            "Acme",
            "foo ",
            " foo",
            "föo",
        ] {
            assert_eq!(
                validate_org_slug(bad),
                Err(SlugError::BadChar),
                "{bad:?} should be a bad char"
            );
        }
    }

    #[test]
    fn authorization_context_carries_explicit_ancestry() {
        let org = Scope::parse("org:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let project = Scope::parse("project:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let context = AuthorizationContext::try_new(
            project.clone(),
            vec![project.clone(), org.clone(), Scope::root()],
        )
        .unwrap();
        assert_eq!(context.target(), &project);
        assert!(context.is_covered_by(&project));
        assert!(context.is_covered_by(&org));
        assert!(context.is_covered_by(&Scope::root()));
        assert!(!context.is_covered_by(&Scope::parse("org:cccccccccccccccccccccccccccccccc")));
    }

    #[test]
    fn allow_inheritance_matrix() {
        let project = Scope::parse("project:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let registry = Scope::parse("registry:dddddddddddddddddddddddddddddddd");
        let org = Scope::parse("org:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let sibling_org = Scope::parse("org:cccccccccccccccccccccccccccccccc");
        let registry_context = AuthorizationContext::try_new(
            registry.clone(),
            vec![
                registry.clone(),
                project.clone(),
                org.clone(),
                Scope::root(),
            ],
        )
        .unwrap();
        let project_context = AuthorizationContext::try_new(
            project.clone(),
            vec![project.clone(), org.clone(), Scope::root()],
        )
        .unwrap();

        // 1. Org-admin can configure a registry under the org (downward
        //    inheritance).
        assert!(allow(
            &[(org.clone(), Role::Admin)],
            Permission::RegistryConfigure,
            &registry_context,
        ));
        // 2. Org-owner has IamAdmin everywhere under it.
        assert!(allow(
            &[(org.clone(), Role::Owner)],
            Permission::IamAdmin,
            &registry_context,
        ));
        // 3. A viewer at the registry scope cannot publish.
        assert!(!allow(
            &[(registry.clone(), Role::Viewer)],
            Permission::Publish,
            &registry_context,
        ));
        // 4. A viewer can read at its own scope.
        assert!(allow(
            &[(registry.clone(), Role::Viewer)],
            Permission::Read,
            &registry_context,
        ));
        // 5. A grant on a sibling org does not leak.
        assert!(!allow(
            &[(sibling_org, Role::Owner)],
            Permission::Read,
            &registry_context,
        ));
        // 6. A registry-scoped grant does NOT apply upward to the project.
        assert!(!allow(
            &[(registry.clone(), Role::Owner)],
            Permission::Read,
            &project_context,
        ));
        // 7. A maintainer at the project can advance a channel on a
        //    registry beneath it.
        assert!(allow(
            &[(project.clone(), Role::Maintainer)],
            Permission::ChannelAdvance,
            &registry_context,
        ));
        // 8. But a project maintainer cannot manage members (admin verb).
        assert!(!allow(
            &[(project.clone(), Role::Maintainer)],
            Permission::MembersManage,
            &registry_context,
        ));
        // 9. Multiple grants: the most-privileged covering grant wins.
        assert!(allow(
            &[(registry.clone(), Role::Viewer), (org.clone(), Role::Admin),],
            Permission::RegistryConfigure,
            &registry_context,
        ));
        // 10. Empty grants deny.
        assert!(!allow(&[], Permission::Read, &registry_context));
        // 11. Instance-root owner covers any target.
        assert!(allow(
            &[(Scope::root(), Role::Owner)],
            Permission::IamAdmin,
            &registry_context,
        ));
    }

    #[test]
    fn recreated_slug_does_not_reuse_authority() {
        let old_registry = Scope::parse("registry:11111111111111111111111111111111");
        let replacement = Scope::parse("registry:22222222222222222222222222222222");
        let org = Scope::parse("org:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let replacement_context = AuthorizationContext::try_new(
            replacement,
            vec![
                org,
                Scope::root(),
                Scope::parse("registry:22222222222222222222222222222222"),
            ],
        )
        .unwrap();
        assert!(!allow(
            &[(old_registry, Role::Owner)],
            Permission::Read,
            &replacement_context,
        ));
    }
}
