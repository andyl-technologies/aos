//! Closed deep-link registry for the Hub management application.
//!
//! The parser recognizes only the canonical settings roots recorded by
//! RFC-0012. It does not provide aliases or a prefix-wide fallback: an unknown
//! page remains a server-side 404 instead of receiving the application shell.

/// One page in a scope's deterministic settings navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSpec {
    /// Stable application page key.
    pub key: &'static str,
    /// Human-facing navigation label.
    pub label: &'static str,
    /// Ordered navigation group; empty for Overview.
    pub group: &'static str,
    /// Canonical suffix below the scope root.
    pub suffix: &'static str,
    /// Capability-manifest workflow rendered by the page.
    pub workflow: &'static str,
}

impl PageSpec {
    const fn new(
        key: &'static str,
        label: &'static str,
        group: &'static str,
        suffix: &'static str,
        workflow: &'static str,
    ) -> Self {
        Self {
            key,
            label,
            group,
            suffix,
            workflow,
        }
    }
}

/// Canonical scope resolved from one management deep link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleScope {
    /// Deployment-wide settings.
    Instance,
    /// Organization inventory and creation.
    Organizations,
    /// One organization.
    Organization {
        /// Canonical organization slug.
        slug: String,
    },
    /// One registry, including a nested registry path.
    Registry {
        /// Slash-separated canonical registry path.
        path: String,
    },
    /// One organization-owned binary cache.
    Cache {
        /// Owning organization slug.
        organization: String,
        /// Cache slug.
        cache: String,
    },
}

/// One exact management deep link and its navigation definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleRoute {
    /// Resolved settings scope.
    pub scope: ConsoleScope,
    /// Canonical scope root used to construct sibling links.
    pub base_path: String,
    /// Exact page selected inside the scope.
    pub page: &'static PageSpec,
}

impl ConsoleRoute {
    /// Resolves one URL path against the closed application route registry.
    ///
    /// Query strings, fragments, empty segments, dot segments, encoded path
    /// separators, and unknown page suffixes are rejected.
    #[must_use]
    pub fn resolve(path: &str) -> Option<Self> {
        let segments = canonical_segments(path)?;
        if segments.starts_with(&["-", "instance"]) {
            return resolve_page(
                ConsoleScope::Instance,
                "/-/instance".to_string(),
                &segments[2..],
                INSTANCE_PAGES,
            );
        }
        if segments.starts_with(&["-", "orgs"]) {
            return resolve_page(
                ConsoleScope::Organizations,
                "/-/orgs".to_string(),
                &segments[2..],
                ORGANIZATION_INVENTORY_PAGES,
            );
        }
        if segments.len() >= 3 && segments[..2] == ["-", "org"] {
            let organization = segments[2].to_string();
            if segments.len() >= 5 && segments[3] == "caches" {
                let cache = segments[4].to_string();
                return resolve_page(
                    ConsoleScope::Cache {
                        organization: organization.clone(),
                        cache: cache.clone(),
                    },
                    format!("/-/org/{organization}/caches/{cache}"),
                    &segments[5..],
                    CACHE_PAGES,
                );
            }
            return resolve_page(
                ConsoleScope::Organization {
                    slug: organization.clone(),
                },
                format!("/-/org/{organization}"),
                &segments[3..],
                ORGANIZATION_PAGES,
            );
        }
        resolve_registry(&segments)
    }

    /// Returns the deterministic navigation for the resolved scope.
    #[must_use]
    pub fn navigation(&self) -> &'static [PageSpec] {
        match self.scope {
            ConsoleScope::Instance => INSTANCE_PAGES,
            ConsoleScope::Organizations => ORGANIZATION_INVENTORY_PAGES,
            ConsoleScope::Organization { .. } => ORGANIZATION_PAGES,
            ConsoleScope::Registry { .. } => REGISTRY_PAGES,
            ConsoleScope::Cache { .. } => CACHE_PAGES,
        }
    }

    /// Constructs the canonical deep link for one sibling page.
    #[must_use]
    pub fn href(&self, page: &PageSpec) -> String {
        if page.suffix.is_empty() {
            self.base_path.clone()
        } else {
            format!("{}/{}", self.base_path, page.suffix)
        }
    }
}

fn resolve_registry(segments: &[&str]) -> Option<ConsoleRoute> {
    let settings = segments
        .windows(2)
        .position(|window| window == ["-", "settings"])?;
    if settings == 0 {
        return None;
    }
    let suffix_start = settings.checked_add(2)?;
    let registry_path = segments[..settings].join("/");
    let base_path = format!("/{registry_path}/-/settings");
    resolve_page(
        ConsoleScope::Registry {
            path: registry_path,
        },
        base_path,
        &segments[suffix_start..],
        REGISTRY_PAGES,
    )
}

fn resolve_page(
    scope: ConsoleScope,
    base_path: String,
    suffix: &[&str],
    pages: &'static [PageSpec],
) -> Option<ConsoleRoute> {
    let suffix = suffix.join("/");
    let page = pages.iter().find(|page| page.suffix == suffix)?;
    Some(ConsoleRoute {
        scope,
        base_path,
        page,
    })
}

fn canonical_segments(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/')
        || path.len() > 2_048
        || path.contains(['?', '#', '\\'])
        || path.contains('%')
    {
        return None;
    }
    let segments = path.strip_prefix('/')?.split('/').collect::<Vec<_>>();
    if segments.is_empty() || segments.iter().any(|segment| !canonical_segment(segment)) {
        return None;
    }
    Some(segments)
}

fn canonical_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && !matches!(segment, "." | "..")
        && segment.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

/// Instance settings pages in final navigation order.
pub const INSTANCE_PAGES: &[PageSpec] = &[
    PageSpec::new("overview", "Overview", "", "", "instance-settings"),
    PageSpec::new(
        "storage",
        "Storage bindings",
        "Infrastructure",
        "storage-bindings",
        "storage-bindings",
    ),
    PageSpec::new("domains", "Domains", "Infrastructure", "domains", "domains"),
    PageSpec::new(
        "boundaries",
        "Network boundaries",
        "Infrastructure",
        "network-boundaries",
        "network-boundaries",
    ),
    PageSpec::new(
        "endpoints",
        "Delivery endpoints",
        "Infrastructure",
        "delivery-endpoints",
        "delivery-endpoints",
    ),
    PageSpec::new(
        "gateways",
        "Storage gateways",
        "Infrastructure",
        "storage-gateways",
        "storage-gateways",
    ),
    PageSpec::new(
        "defaults",
        "Topology defaults",
        "Infrastructure",
        "topology-defaults",
        "topology-defaults",
    ),
    PageSpec::new(
        "identity",
        "Identity & signup",
        "Access & trust",
        "identity-and-signup",
        "instance-settings",
    ),
    PageSpec::new(
        "resource-defaults",
        "Resource defaults",
        "Policy",
        "resource-defaults",
        "instance-settings",
    ),
    PageSpec::new(
        "branding",
        "Branding",
        "Appearance",
        "branding",
        "instance-settings",
    ),
    PageSpec::new(
        "operations",
        "Operations",
        "Activity",
        "operations",
        "operations",
    ),
];

/// Organization inventory pages in final navigation order.
pub const ORGANIZATION_INVENTORY_PAGES: &[PageSpec] = &[
    PageSpec::new(
        "overview",
        "Organizations",
        "",
        "",
        "organization-inventory",
    ),
    PageSpec::new(
        "new",
        "Create organization",
        "",
        "new",
        "organization-inventory",
    ),
];

/// Organization settings pages in final navigation order.
pub const ORGANIZATION_PAGES: &[PageSpec] = &[
    PageSpec::new("overview", "Overview", "", "", "organization-overview"),
    PageSpec::new(
        "projects",
        "Projects",
        "Resources",
        "projects",
        "project-inventory",
    ),
    PageSpec::new(
        "registries",
        "Registries",
        "Resources",
        "registries",
        "registry-inventory",
    ),
    PageSpec::new(
        "caches",
        "Binary caches",
        "Resources",
        "caches",
        "cache-overview",
    ),
    PageSpec::new(
        "storage",
        "Storage bindings",
        "Infrastructure",
        "storage-bindings",
        "storage-bindings",
    ),
    PageSpec::new("domains", "Domains", "Infrastructure", "domains", "domains"),
    PageSpec::new(
        "boundaries",
        "Network boundaries",
        "Infrastructure",
        "network-boundaries",
        "network-boundaries",
    ),
    PageSpec::new(
        "endpoints",
        "Delivery endpoints",
        "Infrastructure",
        "delivery-endpoints",
        "delivery-endpoints",
    ),
    PageSpec::new(
        "gateways",
        "Storage gateways",
        "Infrastructure",
        "storage-gateways",
        "storage-gateways",
    ),
    PageSpec::new(
        "defaults",
        "Topology defaults",
        "Infrastructure",
        "topology-defaults",
        "topology-defaults",
    ),
    PageSpec::new(
        "identity",
        "Identity & access",
        "Access & trust",
        "identity-and-access",
        "organization-overview",
    ),
    PageSpec::new(
        "members",
        "Members",
        "Access & trust",
        "members",
        "memberships",
    ),
    PageSpec::new("sso", "SSO", "Access & trust", "sso", "organization-sso"),
    PageSpec::new(
        "signing",
        "Signing keys",
        "Access & trust",
        "signing-keys",
        "signing-keys",
    ),
    PageSpec::new("webhooks", "Webhooks", "Automation", "webhooks", "webhooks"),
    PageSpec::new(
        "operations",
        "Operations",
        "Activity",
        "operations",
        "operations",
    ),
    PageSpec::new("audit", "Audit log", "Activity", "audit-log", "audit-log"),
    PageSpec::new(
        "danger",
        "Danger zone",
        "Danger zone",
        "danger",
        "organization-danger",
    ),
];

/// Registry settings pages in final navigation order.
pub const REGISTRY_PAGES: &[PageSpec] = &[
    PageSpec::new("overview", "Overview", "", "", "registry-overview"),
    PageSpec::new(
        "placements",
        "Storage & replicas",
        "Topology",
        "placements",
        "placements",
    ),
    PageSpec::new(
        "delivery",
        "Delivery",
        "Topology",
        "delivery",
        "delivery-routes",
    ),
    PageSpec::new(
        "caches",
        "Binary caches",
        "Topology",
        "caches",
        "registry-cache-stack",
    ),
    PageSpec::new(
        "access",
        "Identity & access",
        "Access & trust",
        "access",
        "registry-overview",
    ),
    PageSpec::new(
        "signing",
        "Signing keys",
        "Access & trust",
        "signing-keys",
        "signing-keys",
    ),
    PageSpec::new(
        "tokens",
        "Tokens",
        "Access & trust",
        "tokens",
        "access-tokens",
    ),
    PageSpec::new(
        "mirror",
        "Upstream mirror",
        "Publishing",
        "mirror",
        "registry-mirror",
    ),
    PageSpec::new(
        "configuration",
        "Configuration",
        "Publishing",
        "configuration",
        "registry-configuration",
    ),
    PageSpec::new(
        "channels",
        "Channels",
        "Publishing",
        "channels",
        "registry-channels",
    ),
    PageSpec::new(
        "changes",
        "Change requests",
        "Publishing",
        "change-requests",
        "change-requests",
    ),
    PageSpec::new(
        "publishes",
        "Publish history",
        "Publishing",
        "publishes",
        "registry-publication",
    ),
    PageSpec::new(
        "operations",
        "Operations & health",
        "Activity",
        "operations",
        "operations",
    ),
    PageSpec::new(
        "danger",
        "Danger zone",
        "Danger zone",
        "danger",
        "registry-danger",
    ),
];

/// Binary-cache settings pages in final navigation order.
pub const CACHE_PAGES: &[PageSpec] = &[
    PageSpec::new("overview", "Overview", "", "", "cache-overview"),
    PageSpec::new(
        "placements",
        "Storage & replicas",
        "Topology",
        "placements",
        "placements",
    ),
    PageSpec::new(
        "delivery",
        "Delivery",
        "Topology",
        "delivery",
        "delivery-routes",
    ),
    PageSpec::new(
        "objects",
        "Objects & closures",
        "Content",
        "objects",
        "cache-objects",
    ),
    PageSpec::new(
        "integrations",
        "Integrations",
        "Content",
        "integrations",
        "cache-integrations",
    ),
    PageSpec::new(
        "access",
        "Identity & access",
        "Access & trust",
        "access",
        "cache-overview",
    ),
    PageSpec::new(
        "signing",
        "Signing key",
        "Access & trust",
        "signing-key",
        "signing-keys",
    ),
    PageSpec::new(
        "retention",
        "Retention",
        "Policy",
        "retention",
        "cache-retention",
    ),
    PageSpec::new(
        "gc",
        "Garbage collection",
        "Policy",
        "garbage-collection",
        "cache-gc",
    ),
    PageSpec::new(
        "operations",
        "Operations & health",
        "Activity",
        "operations",
        "operations",
    ),
    PageSpec::new(
        "danger",
        "Danger zone",
        "Danger zone",
        "danger",
        "cache-danger",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scope_root_selects_overview_first() {
        for path in [
            "/-/instance",
            "/-/org/acme",
            "/-/org/acme/caches/build",
            "/acme/main/-/settings",
        ] {
            let route = ConsoleRoute::resolve(path).expect("canonical scope root must resolve");
            assert_eq!(route.page.key, "overview");
            assert_eq!(route.navigation().first(), Some(route.page));
        }
    }

    #[test]
    fn nested_registry_and_cache_routes_remain_distinct() {
        let registry = ConsoleRoute::resolve("/acme/tools/main/-/settings/delivery")
            .expect("nested registry route must resolve");
        assert_eq!(
            registry.scope,
            ConsoleScope::Registry {
                path: "acme/tools/main".to_string()
            }
        );
        assert_eq!(registry.page.key, "delivery");

        let cache = ConsoleRoute::resolve("/-/org/acme/caches/main/retention")
            .expect("cache route must resolve");
        assert!(matches!(cache.scope, ConsoleScope::Cache { .. }));
        assert_eq!(cache.page.key, "retention");
    }

    #[test]
    fn unknown_and_ambiguous_paths_do_not_receive_the_application() {
        for path in [
            "/-/org/acme/general",
            "/-/org/acme/caches/main/gc-and-pins",
            "/main/-/settings/serving-and-mirror",
            "/-/org/acme//members",
            "/-/org/acme/../admin",
            "/-/org/acme/members?all=true",
            "/main/%2F-/settings",
            "/-/org/%2e%2e/members",
            "/-/org/Acme/members",
            "/-/org/acme!/members",
        ] {
            assert!(ConsoleRoute::resolve(path).is_none(), "accepted {path}");
        }
    }

    #[test]
    fn sibling_links_are_canonical() {
        let route = ConsoleRoute::resolve("/-/org/acme/members")
            .expect("organization members route must resolve");
        assert_eq!(route.href(&ORGANIZATION_PAGES[0]), "/-/org/acme");
        assert_eq!(route.href(&ORGANIZATION_PAGES[1]), "/-/org/acme/projects");
    }

    #[test]
    fn every_page_is_backed_by_a_declared_web_workflow() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/rfcs/0012-hub-surface-topology/hub-control-plane-capabilities-v1.json"
        ))
        .expect("capability manifest must be valid JSON");
        let services = manifest["services"]
            .as_array()
            .expect("services must be an array");
        let mut workflows = services
            .iter()
            .flat_map(|service| {
                service["web_workflows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
            })
            .collect::<std::collections::BTreeSet<_>>();
        for workflow in manifest["http_capabilities"]
            .as_array()
            .expect("HTTP capabilities must be an array")
            .iter()
            .flat_map(|capability| {
                capability["web_workflows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
            })
        {
            workflows.insert(workflow);
        }
        let missing = INSTANCE_PAGES
            .iter()
            .chain(ORGANIZATION_INVENTORY_PAGES)
            .chain(ORGANIZATION_PAGES)
            .chain(REGISTRY_PAGES)
            .chain(CACHE_PAGES)
            .filter(|page| !workflows.contains(page.workflow))
            .map(|page| format!("{}:{}", page.key, page.workflow))
            .collect::<Vec<_>>();
        assert!(missing.is_empty(), "undeclared page workflows: {missing:?}");
    }
}
