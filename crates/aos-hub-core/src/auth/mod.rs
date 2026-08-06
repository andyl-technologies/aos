//! Runtime-agnostic authentication primitives shared by the hub and Worker.
//!
//! These are the deployment-independent halves of the hub's auth stack — the
//! credential operations that depend on neither a specific HTTP server, a
//! database driver, nor an async runtime. They are gathered here (RFC-0004
//! Phase 5) so the native `aos-hub` binary and the Cloudflare Worker
//! run the *same* credential code rather than two divergent implementations.
//!
//! - [`token`] — provisioning-token secret generation and SHA-256 hashing.
//! - [`session`] — opaque human session secrets and the cookie header.
//! - [`magic`] — single-use email magic-link secrets and the [`magic::Mailer`]
//!   delivery trait.
//! - [`device`] — RFC 8628 device-code and user-code minting.
//! - [`oidc`] — per-org OIDC SSO: the authorization-code + PKCE flow and
//!   JWKS-backed RS256 id_token verification, over the
//!   [`HttpClient`](crate::web::console::ports::HttpClient) port.
//! - [`password`] — Argon2id password hashing and constant-time verification.
//! - [`seal`] — the [`SecretSealer`](seal::SecretSealer) seam (AES-256-GCM
//!   production sealer + the dev/test XOR placeholder) for at-rest secrets.
//! - [`webauthn`] — the in-house WebAuthn relying-party verifier
//!   (`attestation: none`): COSE key decode and ES256/Ed25519/RS256 assertion
//!   verification, over [`Database`](crate::db::Database) credential rows.
//! - [`permission_from_str`] — the inverse of `Permission::as_str`.
//!
//! The HTTP-bound and database-bound halves (axum extractors, JWT minting, the
//! sealed-secret envelope, the WebAuthn verifier, and the
//! session/token row queries) currently stay in the deployment crates; later
//! phases move the runtime-agnostic ones here too. The on-disk system of record
//! for every credential is the hub's `db` layer; only secret *hashes* are
//! stored, so a database leak never yields a usable credential.

// jwt: HS256 access-token mint/verify (hmac/sha2-based; no jsonwebtoken/ring).
pub mod device;
pub mod jwt;
pub mod magic;
pub mod oidc;
pub mod password;
pub mod seal;
pub mod session;
pub mod token;
pub mod webauthn;

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
        "storage_binding.read" => Some(Permission::StorageBindingRead),
        "storage_binding.manage" => Some(Permission::StorageBindingManage),
        "storage_binding.grant" => Some(Permission::StorageBindingGrant),
        "placement.read" => Some(Permission::PlacementRead),
        "placement.manage" => Some(Permission::PlacementManage),
        "placement_policy.read" => Some(Permission::PlacementPolicyRead),
        "placement_policy.manage" => Some(Permission::PlacementPolicyManage),
        "domain.read" => Some(Permission::DomainRead),
        "domain.manage" => Some(Permission::DomainManage),
        "network_boundary.read" => Some(Permission::NetworkBoundaryRead),
        "network_boundary.manage" => Some(Permission::NetworkBoundaryManage),
        "network_boundary.grant" => Some(Permission::NetworkBoundaryGrant),
        "delivery_endpoint.read" => Some(Permission::DeliveryEndpointRead),
        "delivery_endpoint.manage" => Some(Permission::DeliveryEndpointManage),
        "delivery_endpoint.grant" => Some(Permission::DeliveryEndpointGrant),
        "storage_gateway.read" => Some(Permission::StorageGatewayRead),
        "storage_gateway.manage" => Some(Permission::StorageGatewayManage),
        "storage_gateway.grant" => Some(Permission::StorageGatewayGrant),
        "route.read" => Some(Permission::RouteRead),
        "route.manage" => Some(Permission::RouteManage),
        "topology.reconcile" => Some(Permission::TopologyReconcile),
        "cache.retention.manage" => Some(Permission::CacheRetentionManage),
        "cache.gc.plan" => Some(Permission::CacheGcPlan),
        "cache.gc.execute" => Some(Permission::CacheGcExecute),
        "cache.lease.self" => Some(Permission::CacheLeaseSelf),
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
        ] {
            assert_eq!(permission_from_str(perm.as_str()), Some(perm));
        }
        assert_eq!(permission_from_str("nope"), None);
    }
}
