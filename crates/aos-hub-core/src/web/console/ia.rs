//! Typed information architecture for management-console scopes.
//!
//! This module is the authoritative ordering, naming, path, and read-permission
//! contract for organization, registry, cache, and storage-binding settings.
//! Renderers consume these declarations for both navigation and overview cards;
//! routers and tests use the same typed page keys to reject unknown sections.

use std::collections::BTreeSet;

use crate::domain::iam::Permission;

/// Exact permissions available to the current actor in one settings scope.
///
/// Renderers use this set only for discovery. Handlers independently enforce
/// the same [`PageSpec::permission`] before reading a page.
pub type NavigationPermissions = BTreeSet<Permission>;

/// One management page declared by a scope's information architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSpec<K> {
    /// Typed identity used by handlers and renderers.
    pub key: K,
    /// Navigation group; an empty label denotes an ungrouped item.
    pub group: &'static str,
    /// User-facing navigation label.
    pub label: &'static str,
    /// Canonical suffix relative to the scope's base route.
    pub suffix: &'static str,
    /// Permission required to discover and read the page.
    pub permission: Permission,
}

impl<K: Copy> PageSpec<K> {
    /// Builds the canonical page URL below `base`.
    #[must_use]
    pub fn href(self, base: &str) -> String {
        format!("{base}{}", self.suffix)
    }
}

macro_rules! page_key {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[doc = concat!("Typed page key for the `", stringify!($name), "` management scope.")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Returns the stable renderer key used in tests and diagnostics.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }

            /// Parses an exact declared page key.
            #[must_use]
            pub fn parse(value: &str) -> Option<Self> {
                match value { $($wire => Some(Self::$variant)),+, _ => None }
            }
        }
    };
}

page_key!(OrgPage {
    Overview => "overview",
    Projects => "projects",
    Registries => "registries",
    Caches => "caches",
    StorageBindings => "storage-bindings",
    Domains => "domains",
    NetworkBoundaries => "network-boundaries",
    DeliveryEndpoints => "delivery-endpoints",
    StorageGateways => "storage-gateways",
    TopologyDefaults => "topology-defaults",
    Access => "identity-and-access",
    Members => "members",
    Sso => "sso",
    SigningKeys => "signing-keys",
    Webhooks => "webhooks",
    Operations => "operations",
    Audit => "audit-log",
    Danger => "danger",
});

/// Canonical organization settings order and visibility contract.
pub const ORG_PAGES: &[PageSpec<OrgPage>] = &[
    PageSpec {
        key: OrgPage::Overview,
        group: "",
        label: "Overview",
        suffix: "",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Projects,
        group: "Resources",
        label: "Projects",
        suffix: "/projects",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Registries,
        group: "Resources",
        label: "Registries",
        suffix: "/registries",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Caches,
        group: "Resources",
        label: "Binary caches",
        suffix: "/caches",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::StorageBindings,
        group: "Infrastructure",
        label: "Storage bindings",
        suffix: "/storage-bindings",
        permission: Permission::StorageBindingRead,
    },
    PageSpec {
        key: OrgPage::Domains,
        group: "Infrastructure",
        label: "Domains",
        suffix: "/domains",
        permission: Permission::DomainRead,
    },
    PageSpec {
        key: OrgPage::NetworkBoundaries,
        group: "Infrastructure",
        label: "Network boundaries",
        suffix: "/network-boundaries",
        permission: Permission::NetworkBoundaryRead,
    },
    PageSpec {
        key: OrgPage::DeliveryEndpoints,
        group: "Infrastructure",
        label: "Delivery endpoints",
        suffix: "/delivery-endpoints",
        permission: Permission::DeliveryEndpointRead,
    },
    PageSpec {
        key: OrgPage::StorageGateways,
        group: "Infrastructure",
        label: "Storage gateways",
        suffix: "/storage-gateways",
        permission: Permission::StorageGatewayRead,
    },
    PageSpec {
        key: OrgPage::TopologyDefaults,
        group: "Infrastructure",
        label: "Topology defaults",
        suffix: "/topology-defaults",
        permission: Permission::TopologyReconcile,
    },
    PageSpec {
        key: OrgPage::Access,
        group: "Access & trust",
        label: "Identity & access",
        suffix: "/identity-and-access",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Members,
        group: "Access & trust",
        label: "Members",
        suffix: "/members",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Sso,
        group: "Access & trust",
        label: "SSO",
        suffix: "/sso",
        permission: Permission::IamAdmin,
    },
    PageSpec {
        key: OrgPage::SigningKeys,
        group: "Access & trust",
        label: "Signing keys",
        suffix: "/signing-keys",
        permission: Permission::KeysManage,
    },
    PageSpec {
        key: OrgPage::Webhooks,
        group: "Automation",
        label: "Webhooks",
        suffix: "/webhooks",
        permission: Permission::RegistryConfigure,
    },
    PageSpec {
        key: OrgPage::Operations,
        group: "Activity",
        label: "Operations",
        suffix: "/operations",
        permission: Permission::Read,
    },
    PageSpec {
        key: OrgPage::Audit,
        group: "Activity",
        label: "Audit log",
        suffix: "/audit-log",
        permission: Permission::AuditRead,
    },
    PageSpec {
        key: OrgPage::Danger,
        group: "",
        label: "Danger zone",
        suffix: "/danger",
        permission: Permission::IamAdmin,
    },
];

page_key!(RegistryPage {
    Overview => "overview",
    Placements => "placements",
    PlacementPolicies => "placement-policies",
    PlacementEquivalences => "placement-equivalences",
    DeliveryRoutes => "delivery-routes",
    CacheStack => "cache-stack",
    RetentionConsumers => "retention-consumers",
    PopulationTargets => "population-targets",
    Configuration => "configuration",
    ChangeRequests => "change-requests",
    Channels => "channels",
    UpstreamMirror => "upstream-mirror",
    PublishHistory => "publish-history",
    Access => "access",
    SigningKeys => "signing-keys",
    Tokens => "tokens",
    Operations => "operations",
    Danger => "danger",
});

/// Canonical registry settings order and visibility contract.
pub const REGISTRY_PAGES: &[PageSpec<RegistryPage>] = &[
    PageSpec {
        key: RegistryPage::Overview,
        group: "",
        label: "Overview",
        suffix: "",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::Placements,
        group: "Topology",
        label: "Placements",
        suffix: "/placements",
        permission: Permission::PlacementRead,
    },
    PageSpec {
        key: RegistryPage::PlacementPolicies,
        group: "Topology",
        label: "Placement policies",
        suffix: "/placement-policies",
        permission: Permission::PlacementPolicyRead,
    },
    PageSpec {
        key: RegistryPage::PlacementEquivalences,
        group: "Topology",
        label: "Placement equivalences",
        suffix: "/placement-equivalences",
        permission: Permission::PlacementPolicyRead,
    },
    PageSpec {
        key: RegistryPage::DeliveryRoutes,
        group: "Topology",
        label: "Delivery routes",
        suffix: "/delivery-routes",
        permission: Permission::RouteRead,
    },
    PageSpec {
        key: RegistryPage::CacheStack,
        group: "Cache relationships",
        label: "Consumer cache stack",
        suffix: "/cache-stack",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::RetentionConsumers,
        group: "Cache relationships",
        label: "Retention consumers",
        suffix: "/retention-consumers",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::PopulationTargets,
        group: "Cache relationships",
        label: "Population targets",
        suffix: "/population-targets",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::Configuration,
        group: "Publishing",
        label: "Configuration",
        suffix: "/configuration",
        permission: Permission::RegistryConfigure,
    },
    PageSpec {
        key: RegistryPage::ChangeRequests,
        group: "Publishing",
        label: "Change requests",
        suffix: "/change-requests",
        permission: Permission::AuditRead,
    },
    PageSpec {
        key: RegistryPage::Channels,
        group: "Publishing",
        label: "Channels",
        suffix: "/channels",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::UpstreamMirror,
        group: "Publishing",
        label: "Upstream mirror",
        suffix: "/upstream-mirror",
        permission: Permission::RegistryConfigure,
    },
    PageSpec {
        key: RegistryPage::PublishHistory,
        group: "Publishing",
        label: "Publish history",
        suffix: "/publish-history",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::Access,
        group: "Access & trust",
        label: "Identity & access",
        suffix: "/access",
        permission: Permission::RegistryConfigure,
    },
    PageSpec {
        key: RegistryPage::SigningKeys,
        group: "Access & trust",
        label: "Signing keys",
        suffix: "/signing-keys",
        permission: Permission::KeysManage,
    },
    PageSpec {
        key: RegistryPage::Tokens,
        group: "Access & trust",
        label: "Tokens",
        suffix: "/tokens",
        permission: Permission::TokensSelf,
    },
    PageSpec {
        key: RegistryPage::Operations,
        group: "Activity",
        label: "Operations & health",
        suffix: "/operations",
        permission: Permission::Read,
    },
    PageSpec {
        key: RegistryPage::Danger,
        group: "",
        label: "Danger zone",
        suffix: "/danger",
        permission: Permission::IamAdmin,
    },
];

page_key!(CachePage {
    Overview => "overview",
    Placements => "placements",
    PlacementPolicies => "placement-policies",
    PlacementEquivalences => "placement-equivalences",
    DeliveryRoutes => "delivery-routes",
    RetentionSubscriptions => "retention-subscriptions",
    PopulationTargets => "population-targets",
    Objects => "objects",
    ManualRoots => "manual-roots",
    Access => "access",
    SigningKey => "signing-key",
    GarbageCollection => "garbage-collection",
    Operations => "operations",
    Danger => "danger",
});

/// Canonical cache settings order and visibility contract.
pub const CACHE_PAGES: &[PageSpec<CachePage>] = &[
    PageSpec {
        key: CachePage::Overview,
        group: "",
        label: "Overview",
        suffix: "",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::Placements,
        group: "Topology",
        label: "Placements",
        suffix: "/placements",
        permission: Permission::PlacementRead,
    },
    PageSpec {
        key: CachePage::PlacementPolicies,
        group: "Topology",
        label: "Placement policies",
        suffix: "/placement-policies",
        permission: Permission::PlacementPolicyRead,
    },
    PageSpec {
        key: CachePage::PlacementEquivalences,
        group: "Topology",
        label: "Placement equivalences",
        suffix: "/placement-equivalences",
        permission: Permission::PlacementPolicyRead,
    },
    PageSpec {
        key: CachePage::DeliveryRoutes,
        group: "Topology",
        label: "Delivery routes",
        suffix: "/delivery-routes",
        permission: Permission::RouteRead,
    },
    PageSpec {
        key: CachePage::RetentionSubscriptions,
        group: "Relationships",
        label: "Registry retention",
        suffix: "/retention-subscriptions",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::PopulationTargets,
        group: "Relationships",
        label: "Population targets",
        suffix: "/population-targets",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::Objects,
        group: "Content",
        label: "Objects & closures",
        suffix: "/objects",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::ManualRoots,
        group: "Content",
        label: "Manual roots & leases",
        suffix: "/manual-roots",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::Access,
        group: "Access & trust",
        label: "Identity & access",
        suffix: "/access",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::SigningKey,
        group: "Access & trust",
        label: "Signing key",
        suffix: "/signing-key",
        permission: Permission::KeysManage,
    },
    PageSpec {
        key: CachePage::GarbageCollection,
        group: "Lifecycle",
        label: "Garbage collection",
        suffix: "/garbage-collection",
        permission: Permission::CacheGcPlan,
    },
    PageSpec {
        key: CachePage::Operations,
        group: "Activity",
        label: "Operations & health",
        suffix: "/operations",
        permission: Permission::Read,
    },
    PageSpec {
        key: CachePage::Danger,
        group: "",
        label: "Danger zone",
        suffix: "/danger",
        permission: Permission::IamAdmin,
    },
];

page_key!(BindingPage {
    Overview => "overview",
    Credentials => "credentials",
    WriteRevisions => "write-revisions",
    ConsumerGrants => "consumer-grants",
    Placements => "placements",
    StorageGateways => "storage-gateways",
    Danger => "danger",
});

/// Canonical storage-binding settings order and visibility contract.
pub const BINDING_PAGES: &[PageSpec<BindingPage>] = &[
    PageSpec {
        key: BindingPage::Overview,
        group: "",
        label: "Overview",
        suffix: "",
        permission: Permission::StorageBindingRead,
    },
    PageSpec {
        key: BindingPage::Credentials,
        group: "Configuration",
        label: "Credentials",
        suffix: "/credentials",
        permission: Permission::StorageBindingManage,
    },
    PageSpec {
        key: BindingPage::WriteRevisions,
        group: "Configuration",
        label: "Write revisions",
        suffix: "/write-revisions",
        permission: Permission::StorageBindingManage,
    },
    PageSpec {
        key: BindingPage::ConsumerGrants,
        group: "Access",
        label: "Consumer grants",
        suffix: "/consumer-grants",
        permission: Permission::StorageBindingGrant,
    },
    PageSpec {
        key: BindingPage::Placements,
        group: "Backlinks",
        label: "Placements",
        suffix: "/placements",
        permission: Permission::PlacementRead,
    },
    PageSpec {
        key: BindingPage::StorageGateways,
        group: "Backlinks",
        label: "Storage gateways",
        suffix: "/storage-gateways",
        permission: Permission::StorageGatewayRead,
    },
    PageSpec {
        key: BindingPage::Danger,
        group: "",
        label: "Danger zone",
        suffix: "/danger",
        permission: Permission::StorageBindingManage,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scope_begins_with_a_direct_overview() {
        assert_eq!(
            ORG_PAGES.first().map(|page| page.key),
            Some(OrgPage::Overview)
        );
        assert_eq!(
            REGISTRY_PAGES.first().map(|page| page.key),
            Some(RegistryPage::Overview)
        );
        assert_eq!(
            CACHE_PAGES.first().map(|page| page.key),
            Some(CachePage::Overview)
        );
        assert_eq!(
            BINDING_PAGES.first().map(|page| page.key),
            Some(BindingPage::Overview)
        );
        assert!(ORG_PAGES.first().is_some_and(|page| page.suffix.is_empty()));
        assert!(REGISTRY_PAGES
            .first()
            .is_some_and(|page| page.suffix.is_empty()));
        assert!(CACHE_PAGES
            .first()
            .is_some_and(|page| page.suffix.is_empty()));
        assert!(BINDING_PAGES
            .first()
            .is_some_and(|page| page.suffix.is_empty()));
    }

    #[test]
    fn unknown_page_keys_are_rejected() {
        assert_eq!(OrgPage::parse("missing"), None);
        assert_eq!(RegistryPage::parse("consumer-stack"), None);
        assert_eq!(CachePage::parse("retention"), None);
        assert_eq!(BindingPage::parse("grants"), None);
    }

    #[test]
    fn direct_page_suffixes_end_with_their_exact_wire_key() {
        for (key, suffix) in ORG_PAGES
            .iter()
            .map(|page| (page.key.as_str(), page.suffix))
            .chain(
                REGISTRY_PAGES
                    .iter()
                    .map(|page| (page.key.as_str(), page.suffix)),
            )
            .chain(
                CACHE_PAGES
                    .iter()
                    .map(|page| (page.key.as_str(), page.suffix)),
            )
            .chain(
                BINDING_PAGES
                    .iter()
                    .map(|page| (page.key.as_str(), page.suffix)),
            )
        {
            if suffix.is_empty() {
                assert_eq!(key, "overview");
            } else {
                assert_eq!(suffix.rsplit('/').next(), Some(key), "{suffix}");
            }
        }
    }
}
