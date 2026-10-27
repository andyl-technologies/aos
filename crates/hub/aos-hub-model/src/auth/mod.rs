//! Portable credential values, secret generation, and cryptographic validation.

pub mod device;
pub mod jwt;
pub mod magic;
pub mod password;
pub mod seal;
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
        "binding.read" => Some(Permission::BindingRead),
        "binding.manage" => Some(Permission::BindingManage),
        "binding.grant" => Some(Permission::BindingGrant),
        "placement.read" => Some(Permission::PlacementRead),
        "placement.manage" => Some(Permission::PlacementManage),
        "placement_policy.read" => Some(Permission::PlacementPolicyRead),
        "placement_policy.manage" => Some(Permission::PlacementPolicyManage),
        "domain.read" => Some(Permission::DomainRead),
        "domain.manage" => Some(Permission::DomainManage),
        "network_policy.read" => Some(Permission::NetworkPolicyRead),
        "network_policy.manage" => Some(Permission::NetworkPolicyManage),
        "network_policy.grant" => Some(Permission::NetworkPolicyGrant),
        "endpoint.read" => Some(Permission::EndpointRead),
        "endpoint.manage" => Some(Permission::EndpointManage),
        "endpoint.grant" => Some(Permission::EndpointGrant),
        "gateway.read" => Some(Permission::GatewayRead),
        "gateway.manage" => Some(Permission::GatewayManage),
        "gateway.grant" => Some(Permission::GatewayGrant),
        "route.read" => Some(Permission::RouteRead),
        "route.manage" => Some(Permission::RouteManage),
        "topology.reconcile" => Some(Permission::TopologyReconcile),
        "cache.retention.manage" => Some(Permission::CacheRetentionManage),
        "cache.gc.plan" => Some(Permission::CacheGcPlan),
        "cache.gc.execute" => Some(Permission::CacheGcExecute),
        "cache.lease.self" => Some(Permission::CacheLeaseSelf),
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
            BindingRead,
            BindingManage,
            BindingGrant,
            PlacementRead,
            PlacementManage,
            PlacementPolicyRead,
            PlacementPolicyManage,
            DomainRead,
            DomainManage,
            NetworkPolicyRead,
            NetworkPolicyManage,
            NetworkPolicyGrant,
            EndpointRead,
            EndpointManage,
            EndpointGrant,
            GatewayRead,
            GatewayManage,
            GatewayGrant,
            RouteRead,
            RouteManage,
            TopologyReconcile,
            CacheRetentionManage,
            CacheGcPlan,
            CacheGcExecute,
            CacheLeaseSelf,
            AuditRead,
            IamAdmin,
        ] {
            assert_eq!(permission_from_str(perm.as_str()), Some(perm));
        }
        assert_eq!(permission_from_str("nope"), None);
    }
}
