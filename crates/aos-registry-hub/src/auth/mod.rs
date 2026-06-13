//! Authentication: the credentials principals present and the machinery
//! that verifies them.
//!
//! This module owns RFC-0004's "Authentication: sessions, tokens, SSO"
//! plane — *who you are*, as distinct from the pure *what you may do*
//! authorization kernel in [`crate::domain::iam`], which it reuses for
//! every access decision. Two principal planes that never cross:
//!
//! - **Machines** present `aos_`-prefixed [provisioning tokens](token),
//!   hashed at rest, exchanged at `POST /oauth2/token`
//!   ([`extract::oauth2_token_handler`]) for short-TTL [HS256 JWTs](jwt).
//!   The hub generalizes the `aos-server` token from a set of *views* to a
//!   `{scope-path, permissions[]}` grant, and *honors* the rotation grace
//!   window that `aos-server` recorded but ignored.
//! - **Humans** carry opaque [cookie sessions](session)
//!   (`__Host-aos_session`) with a sudo `auth_level`, obtained through the
//!   [device-authorization flow](device) (RFC 8628) for the CLI or
//!   [email magic links](magic) for the browser.
//!
//! # Module map
//!
//! - [`token`] — provisioning-token secret generation and hashing.
//! - [`jwt`] — HS256 JWT minting and verification ([`jwt::Claims`]).
//! - [`session`] — opaque human session secrets.
//! - [`device`] — RFC 8628 device-code and user-code minting.
//! - [`magic`] — single-use email magic-link secrets and the [`magic::Mailer`]
//!   delivery trait.
//! - [`extract`] — the axum extractors and middleware that gate requests:
//!   [`extract::BearerAuth`], [`extract::SessionAuth`],
//!   [`extract::MaybeSession`], plus the `/oauth2/token` handler.
//!
//! The on-disk system of record for every credential lives in
//! [`crate::db`] (migration v4): the `tokens`, `sessions`, `device_codes`,
//! and `magic_links` tables. Only secret *hashes* are stored, so a database
//! leak never yields a usable credential.

pub mod device;
pub mod extract;
pub mod jwt;
pub mod magic;
pub mod session;
pub mod token;

use crate::domain::Permission;

/// Parses a permission verb from its snake-case wire name.
///
/// This is the inverse of [`Permission::as_str`]; it is the single point
/// that maps the JSON/JWT permission strings back to the domain enum.
/// Returns `None` for any string that is not one of the known verbs.
#[must_use]
pub fn permission_from_str(s: &str) -> Option<Permission> {
    match s {
        "read" => Some(Permission::Read),
        "publish" => Some(Permission::Publish),
        "channel.advance" => Some(Permission::ChannelAdvance),
        "keys.manage" => Some(Permission::KeysManage),
        "tokens.self" => Some(Permission::TokensSelf),
        "tokens.manage" => Some(Permission::TokensManage),
        "members.manage" => Some(Permission::MembersManage),
        "registry.configure" => Some(Permission::RegistryConfigure),
        "storage.manage" => Some(Permission::StorageManage),
        "validation.repair" => Some(Permission::ValidationRepair),
        "audit.read" => Some(Permission::AuditRead),
        "iam.admin" => Some(Permission::IamAdmin),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_roundtrips_through_str() {
        use Permission::*;
        for perm in [
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
        ] {
            assert_eq!(permission_from_str(perm.as_str()), Some(perm));
        }
        assert_eq!(permission_from_str("nope"), None);
    }
}
