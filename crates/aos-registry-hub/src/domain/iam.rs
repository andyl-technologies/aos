//! Pure tenancy authorization: roles, permissions, scope paths, and the
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
//! A [`Scope`] is a `/`-separated path naming a point in the
//! org → project → registry hierarchy. Its grammar:
//!
//! ```text
//! scope    := ""                                   # instance root
//!           | org                                  # one organization
//!           | org "/" project_path                 # a project (materialized path)
//!           | org "/" project_path "/" registry    # a registry under a project
//!
//! org           := segment
//! registry      := segment
//! project_path  := segment ("/" segment)*          # arbitrary depth
//! segment       := one or more chars, no "/"
//! ```
//!
//! Containment ([`Scope::contains`]) is prefix-on-segment-boundary, so
//! `acme` contains `acme/infra` but **not** `acme-corp`. Because role
//! grants inherit downward, a grant at scope `S` covers every target scope
//! `T` for which `S.contains(T)` — `S` is `T` or one of its ancestors.
//!
//! # Decision function
//!
//! [`allow`] answers "may a principal with these `(scope, role)` grants
//! perform `permission` on `target`?" — true iff some grant at scope `S`
//! with role `R` satisfies both `S.contains(target)` and `role_grants(R)`
//! includes `permission`.

/// A role on the five-rung RFC-0004 ladder, grantable at any scope.
///
/// Higher [`Role::rank`] means more authority; [`Role::Owner`] is highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Everything, including delete, ownership transfer, and IAM admin.
    Owner,
    /// Members, tokens, registries, frontends, storage, hosted keys.
    Admin,
    /// Publish, advance channels, manage rosters, repair validation.
    Maintainer,
    /// Read private registries and self-service own tokens.
    Developer,
    /// Read-only.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Configure registries and frontends.
    RegistryConfigure,
    /// Manage storage bindings, buckets, and cache stores.
    StorageManage,
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
/// - **Admin** — members, tokens (manage), registries/frontends/storage
///   configuration, validation repair, audit read, plus the baseline
///   read and self-token verbs.
/// - **Maintainer** — publish, channel advance, roster (key) management,
///   validation repair, plus read and self-tokens.
/// - **Developer** — read and self-service tokens only.
/// - **Viewer** — read only.
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
        ],
        Role::Developer => &[Read, TokensSelf],
        Role::Viewer => &[Read],
    }
}

/// A scope path naming a point in the org → project → registry hierarchy.
///
/// Stored as the raw path string (`""`, `"acme"`, `"acme/infra/prod"`,
/// `"acme/infra/prod/cdn"`); see the [module docs](self) for the grammar
/// and containment rules. Construct with [`Scope::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(String);

impl Scope {
    /// Parses a scope from its path string, normalizing it.
    ///
    /// Leading and trailing `/` are trimmed, so `"/acme/"` and `"acme"`
    /// parse equal; the empty string (or a string of only slashes) is the
    /// instance-root scope. Parsing never fails: any string is a valid
    /// scope path, since segments are opaque.
    #[must_use]
    pub fn parse(s: &str) -> Scope {
        Scope(s.trim_matches('/').to_string())
    }

    /// Returns the instance-root scope (`""`).
    #[must_use]
    pub fn root() -> Scope {
        Scope(String::new())
    }

    /// Returns the raw path string of this scope (`""` for the root).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this is the instance-root scope.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns this scope's segments, left to right.
    ///
    /// The root scope yields an empty iterator.
    fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// Returns the parent scope, or `None` for the instance root.
    ///
    /// The parent drops the last path segment: the parent of
    /// `acme/infra/prod` is `acme/infra`, and the parent of `acme` is the
    /// instance root.
    #[must_use]
    pub fn parent(&self) -> Option<Scope> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.rsplit_once('/') {
            Some((head, _)) => Some(Scope(head.to_string())),
            None => Some(Scope::root()),
        }
    }

    /// Returns `true` if this scope is `other` or an ancestor of `other`.
    ///
    /// Containment is on segment boundaries, so `acme` contains
    /// `acme/infra` but not `acme-corp`. The instance root contains every
    /// scope. A scope always contains itself.
    #[must_use]
    pub fn contains(&self, other: &Scope) -> bool {
        let mut mine = self.segments();
        let mut theirs = other.segments();
        loop {
            match mine.next() {
                // Exhausted our segments: every prefix matched, so `other`
                // is at or below us.
                None => return true,
                Some(seg) => match theirs.next() {
                    // `other` is shorter than us: we cannot be its ancestor.
                    None => return false,
                    // A boundary segment diverged: disjoint subtrees.
                    Some(other_seg) if other_seg != seg => return false,
                    Some(_) => {}
                },
            }
        }
    }
}

/// Decides whether a principal's grants authorize `permission` on `target`.
///
/// Returns `true` iff some `(scope, role)` grant satisfies both:
///
/// 1. `scope.contains(target)` — the grant is at `target` or an ancestor
///    (roles inherit downward), and
/// 2. `role_grants(role)` includes `permission`.
///
/// A grant on a sibling subtree never leaks: `acme/infra` does not cover a
/// target under `acme/data`. An empty `grants` slice denies everything.
#[must_use]
pub fn allow(grants: &[(Scope, Role)], permission: Permission, target: &Scope) -> bool {
    grants
        .iter()
        .any(|(scope, role)| scope.contains(target) && role_grants(*role).contains(&permission))
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
            ValidationRepair,
            AuditRead,
        ] {
            assert!(g.contains(&p), "admin missing {p:?}");
        }
        assert!(!g.contains(&Publish));
        assert!(!g.contains(&ChannelAdvance));
        assert!(!g.contains(&KeysManage));
        assert!(!g.contains(&IamAdmin));
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
    fn developer_grants_read_and_self_tokens() {
        use Permission::*;
        assert_eq!(
            grant_set(Role::Developer),
            [Read, TokensSelf].into_iter().collect()
        );
    }

    #[test]
    fn viewer_grants_read_only() {
        use Permission::*;
        assert_eq!(grant_set(Role::Viewer), [Read].into_iter().collect());
    }

    #[test]
    fn scope_parse_normalizes() {
        assert!(Scope::parse("").is_root());
        assert!(Scope::parse("/").is_root());
        assert_eq!(Scope::parse("/acme/").as_str(), "acme");
        assert_eq!(Scope::parse("acme/infra"), Scope::parse("/acme/infra/"));
    }

    #[test]
    fn scope_parent_walks_up() {
        let s = Scope::parse("acme/infra/prod");
        assert_eq!(s.parent(), Some(Scope::parse("acme/infra")));
        assert_eq!(
            Scope::parse("acme/infra").parent(),
            Some(Scope::parse("acme"))
        );
        assert_eq!(Scope::parse("acme").parent(), Some(Scope::root()));
        assert_eq!(Scope::root().parent(), None);
    }

    #[test]
    fn scope_contains_segment_boundary() {
        let acme = Scope::parse("acme");
        assert!(acme.contains(&acme), "self-containment");
        assert!(acme.contains(&Scope::parse("acme/infra")));
        assert!(acme.contains(&Scope::parse("acme/infra/prod")));
        // Prefix-on-boundary: a string prefix that is not a segment
        // prefix does not count.
        assert!(!acme.contains(&Scope::parse("acme-corp")));
        assert!(!acme.contains(&Scope::parse("acmexyz")));
        // A child does not contain its parent.
        assert!(!Scope::parse("acme/infra").contains(&acme));
        // The root contains everything.
        assert!(Scope::root().contains(&Scope::parse("acme/infra/prod/cdn")));
        assert!(Scope::root().contains(&Scope::root()));
    }

    #[test]
    fn allow_inheritance_matrix() {
        let registry = Scope::parse("acme/infra/prod/cdn");
        let project = Scope::parse("acme/infra/prod");
        let org = Scope::parse("acme");
        let sibling_org = Scope::parse("globex");

        // 1. Org-admin can configure a registry under the org (downward
        //    inheritance).
        assert!(allow(
            &[(org.clone(), Role::Admin)],
            Permission::RegistryConfigure,
            &registry,
        ));
        // 2. Org-owner has IamAdmin everywhere under it.
        assert!(allow(
            &[(org.clone(), Role::Owner)],
            Permission::IamAdmin,
            &registry,
        ));
        // 3. A viewer at the registry scope cannot publish.
        assert!(!allow(
            &[(registry.clone(), Role::Viewer)],
            Permission::Publish,
            &registry,
        ));
        // 4. A viewer can read at its own scope.
        assert!(allow(
            &[(registry.clone(), Role::Viewer)],
            Permission::Read,
            &registry,
        ));
        // 5. A grant on a sibling org does not leak.
        assert!(!allow(
            &[(sibling_org, Role::Owner)],
            Permission::Read,
            &registry,
        ));
        // 6. A registry-scoped grant does NOT apply upward to the project.
        assert!(!allow(
            &[(registry.clone(), Role::Owner)],
            Permission::Read,
            &project,
        ));
        // 7. A maintainer at the project can advance a channel on a
        //    registry beneath it.
        assert!(allow(
            &[(project.clone(), Role::Maintainer)],
            Permission::ChannelAdvance,
            &registry,
        ));
        // 8. But a project maintainer cannot manage members (admin verb).
        assert!(!allow(
            &[(project.clone(), Role::Maintainer)],
            Permission::MembersManage,
            &registry,
        ));
        // 9. Multiple grants: the most-privileged covering grant wins.
        assert!(allow(
            &[(registry.clone(), Role::Viewer), (org.clone(), Role::Admin),],
            Permission::RegistryConfigure,
            &registry,
        ));
        // 10. Empty grants deny.
        assert!(!allow(&[], Permission::Read, &registry));
        // 11. Instance-root owner covers any target.
        assert!(allow(
            &[(Scope::root(), Role::Owner)],
            Permission::IamAdmin,
            &registry,
        ));
    }
}
