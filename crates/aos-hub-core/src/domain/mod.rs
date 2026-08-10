//! Tenancy and IAM domain model: orgs, projects, principals, and the pure
//! authorization kernel.
//!
//! This module owns the *meaning* of the tenancy hierarchy described in
//! RFC-0004's "Tenancy and IAM" section — the org → project → registry
//! tree, the principal kinds that act on it, and the role/permission/scope
//! algebra that decides what each principal may do.
//!
//! Its core, [`iam`], is **IO-free and wasm-clean**: pure functions over
//! roles, permissions, and stable scope identities. The thin database bridge that
//! reads a principal's effective grants lives in the hub's `db` layer, which
//! returns the same [`Scope`]/[`Role`] pairs [`iam::allow`] consumes — so
//! the decision itself never touches a connection.
//!
//! # Principals
//!
//! A [`Principal`] is the actor in an authorization decision. RFC-0004 has
//! two grantable principal kinds — human **users** and token-only
//! **service accounts** — distinguished on the wire by the
//! `memberships.principal_kind` column (`"user"` / `"service_account"`).
//! Tokens and sessions are *owned by* a principal rather than being
//! principals themselves, so they do not appear here.

pub mod iam;

pub use iam::{allow, role_grants, validate_org_slug, Permission, Role, Scope, SlugError};

/// The kind of principal a membership or token belongs to.
///
/// Serialized as the snake-case token stored in the
/// `memberships.principal_kind` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PrincipalKind {
    /// A human user (sessions plus owned tokens).
    User,
    /// A token-only service account (no sessions, no email).
    ServiceAccount,
}

impl PrincipalKind {
    /// Returns the snake-case wire name of this principal kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::ServiceAccount => "service_account",
        }
    }

    /// Parses a principal kind from its snake-case wire name.
    ///
    /// Returns `None` for any string other than `"user"` or
    /// `"service_account"`.
    #[must_use]
    pub fn parse(s: &str) -> Option<PrincipalKind> {
        match s {
            "user" => Some(PrincipalKind::User),
            "service_account" => Some(PrincipalKind::ServiceAccount),
            _ => None,
        }
    }
}

/// A principal: a grantable actor identified by its kind and database id.
///
/// The pair `(kind, id)` is the foreign key into `memberships`; it is what
/// the hub's `Database::list_memberships_for` keys on when resolving the
/// effective grants fed to [`allow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Principal {
    /// Whether this principal is a user or a service account.
    pub kind: PrincipalKind,
    /// The principal's row id in `users` or `service_accounts`.
    pub id: i64,
}

impl Principal {
    /// Returns a principal for the human user with the given id.
    #[must_use]
    pub fn user(id: i64) -> Principal {
        Principal {
            kind: PrincipalKind::User,
            id,
        }
    }

    /// Returns a principal for the service account with the given id.
    #[must_use]
    pub fn service_account(id: i64) -> Principal {
        Principal {
            kind: PrincipalKind::ServiceAccount,
            id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_kind_roundtrips() {
        for kind in [PrincipalKind::User, PrincipalKind::ServiceAccount] {
            assert_eq!(PrincipalKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(PrincipalKind::parse("token"), None);
    }

    #[test]
    fn principal_constructors() {
        assert_eq!(Principal::user(7).kind, PrincipalKind::User);
        assert_eq!(Principal::service_account(3).id, 3);
    }
}
