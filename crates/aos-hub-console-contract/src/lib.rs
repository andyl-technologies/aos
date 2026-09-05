//! Closed deep-link registry for the Hub management application.
//!
//! The parser recognizes only the canonical settings roots recorded by
//! RFC-0012. It does not provide aliases or a prefix-wide fallback: an unknown
//! page remains a server-side 404 instead of receiving the application shell.

/// One destination in the signed-in masthead navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimaryNavigationItem {
    /// Canonical application path.
    pub href: &'static str,
    /// Human-facing link label.
    pub label: &'static str,
}

/// Signed-in masthead navigation shared by the SSR and browser shells.
pub const AUTHENTICATED_PRIMARY_NAVIGATION: &[PrimaryNavigationItem] = &[
    PrimaryNavigationItem {
        href: "/",
        label: "registries",
    },
    PrimaryNavigationItem {
        href: "/-/caches",
        label: "caches",
    },
    PrimaryNavigationItem {
        href: "/-/orgs",
        label: "organizations",
    },
    PrimaryNavigationItem {
        href: "/-/instance",
        label: "settings",
    },
    PrimaryNavigationItem {
        href: "/-/account",
        label: "account",
    },
];

/// Maximum number of leading characters shown for a compact hash.
pub const COMPACT_HASH_CHARACTERS: usize = 12;

/// Presentation data for a hash rendered in a compact, copyable control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashPresentation<'a> {
    /// Complete hash retained for tooltips and clipboard actions.
    pub full: &'a str,
    /// Bounded visible form, with an ellipsis when characters were omitted.
    pub compact: String,
}

impl<'a> HashPresentation<'a> {
    /// Builds the shared compact representation for `full`.
    #[must_use]
    pub fn new(full: &'a str) -> Self {
        let mut characters = full.chars();
        let prefix = characters
            .by_ref()
            .take(COMPACT_HASH_CHARACTERS)
            .collect::<String>();
        let compact = if characters.next().is_some() {
            format!("{prefix}…")
        } else {
            prefix
        };

        Self { full, compact }
    }
}

/// One ready-to-copy client command for an OCI distribution reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerPullCommand {
    /// Human-facing client name.
    pub client: &'static str,
    /// Complete command passed to the user's shell.
    pub command: String,
}

/// Builds pull commands from the exact distribution reference supplied by the Hub.
///
/// An absent reference produces no commands. The reference is otherwise used
/// verbatim: browser or control-plane origins are not suitable substitutes for
/// the Distribution endpoint selected by the server.
#[must_use]
pub fn container_pull_commands(distribution_reference: &str) -> Vec<ContainerPullCommand> {
    if distribution_reference.is_empty() {
        return Vec::new();
    }

    [
        ("Docker", "docker pull"),
        ("nerdctl", "nerdctl pull"),
        ("AOS", "aos container pull"),
    ]
    .into_iter()
    .map(|(client, invocation)| ContainerPullCommand {
        client,
        command: format!("{invocation} {distribution_reference}"),
    })
    .collect()
}

/// Selects the effective enabled route for one delivery audience.
///
/// The current advertisement wins when it still names an enabled route. An
/// absent or stale advertisement falls back to the first enabled route so a
/// browser form and its submitted value begin in the same state.
#[must_use]
pub fn route_selection_for_audience(
    audience: &str,
    advertisements: &[(String, String)],
    enabled_route_ids: &[String],
) -> String {
    advertisements
        .iter()
        .find(|(candidate, route_id)| candidate == audience && enabled_route_ids.contains(route_id))
        .map(|(_, route_id)| route_id.clone())
        .or_else(|| enabled_route_ids.first().cloned())
        .unwrap_or_default()
}

/// Primary action available for one durable delivery workflow state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryWorkflowAction {
    /// Rechecks prerequisites and continues unfinished provisioning.
    Resume,
    /// Opens the reviewed activation step after verification succeeds.
    ReviewActivation,
}

/// Returns the primary action supported by a delivery workflow state.
#[must_use]
pub fn delivery_workflow_action(state: &str) -> Option<DeliveryWorkflowAction> {
    match state {
        "preparing" | "awaiting_verification" | "blocked" => Some(DeliveryWorkflowAction::Resume),
        "ready" => Some(DeliveryWorkflowAction::ReviewActivation),
        "active" => None,
        _ => Some(DeliveryWorkflowAction::Resume),
    }
}

/// Returns prerequisite messages for a delivery-destination draft.
#[must_use]
pub fn delivery_draft_prerequisites(
    placement_selected: bool,
    endpoint_selected: bool,
    new_endpoint: bool,
    hostname_source_present: bool,
    network_policy_selected: bool,
    provider_attachment_present: bool,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !placement_selected {
        missing.push("A storage placement is required.");
    }
    if !new_endpoint && !endpoint_selected {
        missing.push("Choose an existing endpoint or configure a new one.");
    }
    if new_endpoint && !hostname_source_present {
        missing.push("A hostname or managed domain is required for the new endpoint.");
    }
    if new_endpoint && !network_policy_selected {
        missing.push("A network policy is required for the new endpoint.");
    }
    if new_endpoint && !provider_attachment_present {
        missing.push("Provider listener, TLS, and probe references are required for verification.");
    }
    missing
}

/// Returns whether owner-only controls belong on a scoped resource card.
#[must_use]
pub fn owner_controls_visible(
    owner_scope_key: &str,
    consumer_scope_key: &str,
    permission_granted: bool,
) -> bool {
    permission_granted && owner_scope_key == consumer_scope_key
}

/// Returns whether settings navigation starts expanded at a viewport width.
///
/// An unavailable width preserves the desktop behavior. Narrow clients start
/// with the scope and workflow visible and can expand navigation on demand.
#[must_use]
pub fn settings_navigation_starts_open(viewport_width: Option<f64>) -> bool {
    viewport_width.is_none_or(|width| width > 768.0)
}

/// Permissions that determine which delivery-destination setup paths are usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliverySetupAccess {
    /// Whether an existing-endpoint workflow can be resumed.
    pub can_resume_existing: bool,
    /// Whether a new-endpoint workflow can be resumed.
    pub can_resume_new: bool,
    /// Whether an existing endpoint can be connected to the surface.
    pub can_use_existing_endpoint: bool,
    /// Whether a hostname, domain, and endpoint can be created inline.
    pub can_create_hostname_endpoint: bool,
    /// Whether a new endpoint can use an existing managed domain.
    pub can_create_managed_domain_endpoint: bool,
}

impl DeliverySetupAccess {
    /// Returns whether at least one guided delivery setup path is usable.
    #[must_use]
    pub fn can_start(self) -> bool {
        self.can_use_existing_endpoint
            || self.can_create_hostname_endpoint
            || self.can_create_managed_domain_endpoint
    }
}

/// Derives delivery setup access from the live route-scoped session permissions.
#[must_use]
pub fn delivery_setup_access(permissions: &[String]) -> DeliverySetupAccess {
    let allows = |required: &str| permissions.iter().any(|value| value == required);
    let common = allows("read")
        && allows("binding.read")
        && allows("route.manage")
        && allows("gateway.manage");
    let can_create_endpoint = common && allows("endpoint.manage") && allows("network_policy.read");

    DeliverySetupAccess {
        can_resume_existing: common,
        can_resume_new: common && allows("endpoint.manage") && allows("domain.manage"),
        can_use_existing_endpoint: common && allows("endpoint.read"),
        can_create_hostname_endpoint: can_create_endpoint && allows("domain.manage"),
        can_create_managed_domain_endpoint: can_create_endpoint
            && allows("domain.read")
            && allows("domain.manage"),
    }
}

/// Joins a gateway URL prefix and binding-relative placement prefix for display.
#[must_use]
pub fn delivery_public_path(client_base_path: &str, placement_prefix: &str) -> String {
    let base = client_base_path.trim_end_matches('/');
    let placement = placement_prefix.trim_matches('/');
    match (base.is_empty(), placement.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{placement}"),
        (false, true) => base.to_string(),
        (false, false) => format!("{base}/{placement}"),
    }
}

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

    /// Returns whether the page belongs in persistent scope navigation.
    ///
    /// Dedicated creation workflows remain deep-linkable but are reached from
    /// the corresponding inventory's primary action.
    #[must_use]
    pub fn is_navigation_item(&self) -> bool {
        self.key != "new" && !self.key.ends_with("-new")
    }

    /// Returns the permission required to open this page or discover it in navigation.
    ///
    /// Pages default to the baseline `read` permission. Sensitive audit,
    /// identity-provider, and destructive areas require their narrower live
    /// capability even though the API remains the final authorization gate.
    #[must_use]
    pub fn navigation_permission(&self) -> &'static str {
        if self.workflow == "instance-settings" {
            return "iam.admin";
        }
        match self.key {
            "defaults" => "binding.manage",
            "audit" | "operations" => "audit.read",
            "signing" => "keys.manage",
            "mirror" => "registry.configure",
            "publish-history" => "publish",
            "webhooks" => "members.manage",
            "storage" => "binding.read",
            "domains" => "domain.read",
            "boundaries" => "network_policy.read",
            "endpoints" => "endpoint.read",
            "gateways" => "gateway.read",
            "placements" => "placement.read",
            "delivery" => "route.read",
            "danger" | "sso" => "iam.admin",
            "tokens" => "tokens.self",
            // Every authenticated user may open the organization bootstrap
            // surface. The API evaluates invite and domain policy when the
            // user submits a plan.
            "new" => "read",
            "projects-new" | "registries-new" => "registry.configure",
            "caches-new" => "registry.configure",
            "storage-new" => "binding.manage",
            "domains-new" => "domain.manage",
            "boundaries-new" => "network_policy.manage",
            "endpoints-new" => "endpoint.manage",
            "gateways-new" => "gateway.manage",
            _ => "read",
        }
    }
}

/// Canonical scope resolved from one management deep link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleScope {
    /// Deployment-wide settings.
    Instance,
    /// Global inventory of every binary cache visible to the caller.
    Caches,
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
    /// One binary cache, identified by its canonical slash-separated slug.
    Cache {
        /// An organization-owned `organization/cache` slug or a standalone
        /// instance cache's single-segment slug.
        path: String,
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
        if segments.starts_with(&["-", "caches"]) {
            if segments.len() >= 3 {
                let cache = segments[2].to_string();
                return resolve_page(
                    ConsoleScope::Cache {
                        path: cache.clone(),
                    },
                    format!("/-/caches/{cache}"),
                    &segments[3..],
                    CACHE_PAGES,
                );
            }
            return resolve_page(
                ConsoleScope::Caches,
                "/-/caches".to_string(),
                &segments[2..],
                CACHE_INVENTORY_PAGES,
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
            if segments.get(3..) == Some(&["caches", "new"][..]) {
                return resolve_page(
                    ConsoleScope::Organization {
                        slug: organization.clone(),
                    },
                    format!("/-/org/{organization}"),
                    &segments[3..],
                    ORGANIZATION_PAGES,
                );
            }
            if segments.len() >= 5 && segments[3] == "caches" {
                let cache = segments[4].to_string();
                return resolve_page(
                    ConsoleScope::Cache {
                        path: format!("{organization}/{cache}"),
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
            ConsoleScope::Caches => CACHE_INVENTORY_PAGES,
            ConsoleScope::Organizations => ORGANIZATION_INVENTORY_PAGES,
            ConsoleScope::Organization { .. } => ORGANIZATION_PAGES,
            ConsoleScope::Registry { .. } => REGISTRY_PAGES,
            ConsoleScope::Cache { .. } => CACHE_PAGES,
        }
    }

    /// Returns persistent navigation pages allowed by live route permissions.
    ///
    /// Creation workflows remain available through permission-gated inventory
    /// actions, but never become permanent navigation items.
    #[must_use]
    pub fn visible_navigation(&self, permissions: &[String]) -> Vec<&'static PageSpec> {
        self.navigation()
            .iter()
            .filter(|page| {
                page.is_navigation_item()
                    && permissions
                        .iter()
                        .any(|permission| permission == page.navigation_permission())
            })
            .collect()
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

/// Returns the public catalog destination for a former read-only settings page.
///
/// Catalogs belong to registry browsing. Exact old bookmarks remain usable,
/// including nested registry paths, without retaining duplicate settings UIs.
#[must_use]
pub fn registry_catalog_redirect(path: &str) -> Option<String> {
    let segments = canonical_segments(path)?;
    let settings = segments
        .windows(2)
        .position(|window| window == ["-", "settings"])?;
    if settings == 0 || segments.len() != settings + 3 {
        return None;
    }
    let catalog = match segments[settings + 2] {
        "packages" => "packages",
        "documentation" => "docs",
        "images" => "images",
        "channels" => "channels",
        _ => return None,
    };
    Some(format!("/{}/-/{catalog}", segments[..settings].join("/")))
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
        "Bindings",
        "Infrastructure",
        "bindings",
        "bindings",
    ),
    PageSpec::new(
        "storage-new",
        "Create binding",
        "",
        "bindings/new",
        "bindings",
    ),
    PageSpec::new("domains", "Domains", "Infrastructure", "domains", "domains"),
    PageSpec::new("domains-new", "Add domain", "", "domains/new", "domains"),
    PageSpec::new(
        "boundaries",
        "Network policies",
        "Infrastructure",
        "network-policies",
        "network-policies",
    ),
    PageSpec::new(
        "boundaries-new",
        "Create network policy",
        "",
        "network-policies/new",
        "network-policies",
    ),
    PageSpec::new(
        "endpoints",
        "Endpoints",
        "Infrastructure",
        "endpoints",
        "endpoints",
    ),
    PageSpec::new(
        "endpoints-new",
        "Create endpoint",
        "",
        "endpoints/new",
        "endpoints",
    ),
    PageSpec::new(
        "gateways",
        "Gateways",
        "Infrastructure",
        "gateways",
        "gateways",
    ),
    PageSpec::new(
        "gateways-new",
        "Create gateway",
        "",
        "gateways/new",
        "gateways",
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
        "tokens",
        "Access tokens",
        "Access & trust",
        "tokens",
        "access-tokens",
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

/// Global binary-cache inventory pages.
pub const CACHE_INVENTORY_PAGES: &[PageSpec] = &[PageSpec::new(
    "overview",
    "Caches",
    "",
    "",
    "cache-overview",
)];

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
        "projects-new",
        "Create project",
        "",
        "projects/new",
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
        "registries-new",
        "Create registry",
        "",
        "registries/new",
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
        "caches-new",
        "Create binary cache",
        "",
        "caches/new",
        "cache-overview",
    ),
    PageSpec::new(
        "storage",
        "Bindings",
        "Infrastructure",
        "bindings",
        "bindings",
    ),
    PageSpec::new(
        "storage-new",
        "Create binding",
        "",
        "bindings/new",
        "bindings",
    ),
    PageSpec::new("domains", "Domains", "Infrastructure", "domains", "domains"),
    PageSpec::new("domains-new", "Add domain", "", "domains/new", "domains"),
    PageSpec::new(
        "boundaries",
        "Network policies",
        "Infrastructure",
        "network-policies",
        "network-policies",
    ),
    PageSpec::new(
        "boundaries-new",
        "Create network policy",
        "",
        "network-policies/new",
        "network-policies",
    ),
    PageSpec::new(
        "endpoints",
        "Endpoints",
        "Infrastructure",
        "endpoints",
        "endpoints",
    ),
    PageSpec::new(
        "endpoints-new",
        "Create endpoint",
        "",
        "endpoints/new",
        "endpoints",
    ),
    PageSpec::new(
        "gateways",
        "Gateways",
        "Infrastructure",
        "gateways",
        "gateways",
    ),
    PageSpec::new(
        "gateways-new",
        "Create gateway",
        "",
        "gateways/new",
        "gateways",
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
    PageSpec::new(
        "tokens",
        "Access tokens",
        "Access & trust",
        "tokens",
        "access-tokens",
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
    PageSpec::new("delivery", "Delivery", "Topology", "delivery", "routes"),
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
        "Access tokens",
        "Access & trust",
        "tokens",
        "access-tokens",
    ),
    PageSpec::new(
        "containers",
        "Containers",
        "Publishing",
        "containers",
        "registry-containers",
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
        "Configuration history",
        "Activity",
        "configuration",
        "registry-configuration",
    ),
    PageSpec::new(
        "changes",
        "Change requests",
        "Activity",
        "change-requests",
        "change-requests",
    ),
    PageSpec::new(
        "publish-history",
        "Publications",
        "Activity",
        "publish-history",
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
    PageSpec::new("delivery", "Delivery", "Topology", "delivery", "routes"),
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
        "Signing keys",
        "Access & trust",
        "signing-keys",
        "signing-keys",
    ),
    PageSpec::new(
        "tokens",
        "Access tokens",
        "Access & trust",
        "tokens",
        "access-tokens",
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
    fn catalog_bookmarks_leave_settings_without_accepting_unknown_paths() {
        for (old, new) in [
            ("packages", "packages"),
            ("documentation", "docs"),
            ("images", "images"),
            ("channels", "channels"),
        ] {
            let path = format!("/acme/project/main/-/settings/{old}");
            assert_eq!(
                registry_catalog_redirect(&path),
                Some(format!("/acme/project/main/-/{new}"))
            );
            assert!(ConsoleRoute::resolve(&path).is_none());
        }
        for path in [
            "/-/settings/packages",
            "/acme/main/-/settings/packages/extra",
            "/acme/main/-/settings/unknown",
            "/acme/../main/-/settings/packages",
        ] {
            assert!(registry_catalog_redirect(path).is_none(), "{path}");
        }
    }

    #[test]
    fn container_pull_commands_require_and_preserve_the_server_reference() {
        assert!(container_pull_commands("").is_empty());

        let commands = container_pull_commands("oci.example.test:5443/acme/base@sha256:0123");
        assert_eq!(
            commands,
            vec![
                ContainerPullCommand {
                    client: "Docker",
                    command: "docker pull oci.example.test:5443/acme/base@sha256:0123".to_string(),
                },
                ContainerPullCommand {
                    client: "nerdctl",
                    command: "nerdctl pull oci.example.test:5443/acme/base@sha256:0123".to_string(),
                },
                ContainerPullCommand {
                    client: "AOS",
                    command: "aos container pull oci.example.test:5443/acme/base@sha256:0123"
                        .to_string(),
                },
            ]
        );
    }

    #[test]
    fn compact_hash_presentation_preserves_the_full_value() {
        let full = "sha256:0123456789abcdef";
        let presentation = HashPresentation::new(full);
        assert_eq!(presentation.full, full);
        assert_eq!(presentation.compact, "sha256:01234…");
        assert_eq!(HashPresentation::new("short").compact, "short");
    }

    #[test]
    fn authenticated_navigation_includes_plain_settings_label() {
        let settings = AUTHENTICATED_PRIMARY_NAVIGATION
            .iter()
            .find(|item| item.href == "/-/instance")
            .expect("settings navigation item");
        assert_eq!(settings.label, "settings");
    }

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
    fn closed_page_registry_matches_the_implemented_adapters() {
        for (pages, expected) in [
            (
                INSTANCE_PAGES,
                &[
                    "overview",
                    "storage",
                    "storage-new",
                    "domains",
                    "domains-new",
                    "boundaries",
                    "boundaries-new",
                    "endpoints",
                    "endpoints-new",
                    "gateways",
                    "gateways-new",
                    "defaults",
                    "identity",
                    "tokens",
                    "resource-defaults",
                    "branding",
                    "operations",
                ][..],
            ),
            (
                ORGANIZATION_PAGES,
                &[
                    "overview",
                    "projects",
                    "projects-new",
                    "registries",
                    "registries-new",
                    "caches",
                    "caches-new",
                    "storage",
                    "storage-new",
                    "domains",
                    "domains-new",
                    "boundaries",
                    "boundaries-new",
                    "endpoints",
                    "endpoints-new",
                    "gateways",
                    "gateways-new",
                    "defaults",
                    "identity",
                    "members",
                    "sso",
                    "signing",
                    "tokens",
                    "webhooks",
                    "operations",
                    "audit",
                    "danger",
                ][..],
            ),
            (
                REGISTRY_PAGES,
                &[
                    "overview",
                    "placements",
                    "delivery",
                    "caches",
                    "access",
                    "signing",
                    "tokens",
                    "containers",
                    "mirror",
                    "configuration",
                    "changes",
                    "publish-history",
                    "operations",
                    "danger",
                ][..],
            ),
            (
                CACHE_PAGES,
                &[
                    "overview",
                    "placements",
                    "delivery",
                    "objects",
                    "integrations",
                    "access",
                    "signing",
                    "tokens",
                    "retention",
                    "gc",
                    "operations",
                    "danger",
                ][..],
            ),
        ] {
            assert_eq!(
                pages.iter().map(|page| page.key).collect::<Vec<_>>(),
                expected,
                "a page was added or reordered without a workflow-adapter audit"
            );
        }
    }

    #[test]
    fn navigation_groups_are_contiguous() {
        for pages in [
            INSTANCE_PAGES,
            ORGANIZATION_PAGES,
            REGISTRY_PAGES,
            CACHE_PAGES,
        ] {
            let mut completed = std::collections::BTreeSet::new();
            let mut previous = None;
            for page in pages.iter().filter(|page| page.is_navigation_item()) {
                if previous != Some(page.group) {
                    assert!(
                        completed.insert(page.group),
                        "navigation group is split into multiple sections: {}",
                        page.group
                    );
                    previous = Some(page.group);
                }
            }
        }
    }

    #[test]
    fn role_aware_navigation_snapshots_use_live_permissions() {
        let route = ConsoleRoute::resolve("/-/org/acme").expect("organization route");
        for (permissions, expected) in [
            (
                &["read"][..],
                &[
                    "overview",
                    "projects",
                    "registries",
                    "caches",
                    "identity",
                    "members",
                ][..],
            ),
            (
                &["read", "tokens.self"][..],
                &[
                    "overview",
                    "projects",
                    "registries",
                    "caches",
                    "identity",
                    "members",
                    "tokens",
                ][..],
            ),
            (
                &["read", "iam.admin", "audit.read"][..],
                &[
                    "overview",
                    "projects",
                    "registries",
                    "caches",
                    "identity",
                    "members",
                    "sso",
                    "operations",
                    "audit",
                    "danger",
                ][..],
            ),
        ] {
            let permissions = permissions
                .iter()
                .map(|permission| (*permission).to_string())
                .collect::<Vec<_>>();
            let actual = route
                .visible_navigation(&permissions)
                .into_iter()
                .map(|page| page.key)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{permissions:?}");
        }
    }

    #[test]
    fn administrative_settings_match_their_read_api_permissions() {
        for (path, permission) in [
            ("/acme/main/-/settings/mirror", "registry.configure"),
            ("/acme/main/-/settings/publish-history", "publish"),
            ("/acme/main/-/settings/signing-keys", "keys.manage"),
            ("/acme/main/-/settings/operations", "audit.read"),
            ("/-/org/acme/signing-keys", "keys.manage"),
            ("/-/instance/operations", "audit.read"),
        ] {
            let route = ConsoleRoute::resolve(path).expect("settings route");
            assert_eq!(route.page.navigation_permission(), permission, "{path}");
            assert!(!route
                .visible_navigation(&["read".into()])
                .contains(&route.page));
            assert!(route
                .visible_navigation(&["read".into(), permission.into()])
                .contains(&route.page));
        }
        let tokens = ConsoleRoute::resolve("/acme/main/-/settings/tokens").expect("tokens");
        assert!(tokens
            .visible_navigation(&["read".into(), "tokens.self".into()])
            .contains(&tokens.page));
    }

    #[test]
    fn settings_workspace_keeps_wide_medium_and_narrow_layout_contracts() {
        let css = include_str!("../../aos-hub-core/src/web/static_assets/style.css");
        for rule in [
            ".settings {",
            "grid-template-columns: 12rem 1fr;",
            ".settings-nav-disclosure > summary { display: none; }",
            "@media (max-width: 48rem)",
            ".settings { grid-template-columns: 1fr; gap: 0.6rem; }",
            ".settings-nav-disclosure > summary {",
        ] {
            assert!(css.contains(rule), "missing responsive layout rule: {rule}");
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
        assert_eq!(
            cache.scope,
            ConsoleScope::Cache {
                path: "acme/main".to_string()
            }
        );
        assert_eq!(cache.page.key, "retention");

        let standalone = ConsoleRoute::resolve("/-/caches/nix/retention")
            .expect("standalone cache route must resolve");
        assert_eq!(
            standalone.scope,
            ConsoleScope::Cache {
                path: "nix".to_string()
            }
        );
        assert_eq!(standalone.base_path, "/-/caches/nix");
        assert_eq!(standalone.page.key, "retention");
    }

    #[test]
    fn access_and_token_routes_use_one_uniform_vocabulary() {
        for path in [
            "/-/instance/tokens",
            "/-/org/acme/tokens",
            "/acme/main/-/settings/tokens",
            "/-/org/acme/caches/main/tokens",
            "/acme/main/-/settings/access",
            "/-/org/acme/caches/main/access",
            "/-/org/acme/caches/main/signing-keys",
        ] {
            assert!(
                ConsoleRoute::resolve(path).is_some(),
                "route did not resolve: {path}"
            );
        }
        assert!(ConsoleRoute::resolve("/-/org/acme/caches/main/signing-key").is_none());
    }

    #[test]
    fn creation_routes_require_their_navigation_capability() {
        for (path, permission) in [
            ("/-/orgs/new", "read"),
            ("/-/org/acme/projects/new", "registry.configure"),
            ("/-/org/acme/registries/new", "registry.configure"),
            ("/-/org/acme/caches/new", "registry.configure"),
            ("/-/org/acme/bindings/new", "binding.manage"),
            ("/-/instance/domains/new", "domain.manage"),
            ("/-/instance/network-policies/new", "network_policy.manage"),
            ("/-/instance/endpoints/new", "endpoint.manage"),
            ("/-/instance/gateways/new", "gateway.manage"),
        ] {
            let route = ConsoleRoute::resolve(path).expect("creation route must resolve");
            assert_eq!(route.page.navigation_permission(), permission, "{path}");
            assert!(!route.page.is_navigation_item(), "{path}");
        }
    }

    #[test]
    fn registry_publish_history_uses_only_the_canonical_path() {
        let route = ConsoleRoute::resolve("/acme/main/-/settings/publish-history")
            .expect("publish history route must resolve");
        assert_eq!(route.page.key, "publish-history");
        assert!(ConsoleRoute::resolve("/acme/main/-/settings/publishes").is_none());
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
    fn sibling_pages_share_one_session_scope() {
        let caches = ConsoleRoute::resolve("/acme/main/-/settings/caches")
            .expect("registry cache settings route must resolve");
        let delivery = ConsoleRoute::resolve("/acme/main/-/settings/delivery")
            .expect("registry delivery settings route must resolve");
        let other_registry = ConsoleRoute::resolve("/acme/other/-/settings/delivery")
            .expect("second registry route must resolve");

        assert_eq!(caches.base_path, delivery.base_path);
        assert_ne!(caches.base_path, other_registry.base_path);
    }

    #[test]
    fn registry_container_route_is_canonical_and_declared() {
        let route = ConsoleRoute::resolve("/acme/main/-/settings/containers")
            .expect("registry container route must resolve");
        assert_eq!(route.page.key, "containers");
        assert_eq!(route.page.workflow, "registry-containers");
        assert_eq!(route.base_path, "/acme/main/-/settings");
    }

    #[test]
    fn container_workflow_has_no_ssr_data_or_mutation_path() {
        let source = [
            include_str!("../../aos-hub-console/src/workflows/registry_containers/mod.rs"),
            include_str!("../../aos-hub-console/src/workflows/registry_containers/tags.rs"),
            include_str!("../../aos-hub-console/src/workflows/registry_containers/inspection.rs"),
            include_str!("../../aos-hub-console/src/workflows/registry_containers/publications.rs"),
            include_str!("../../aos-hub-console/src/workflows/registry_containers/retention.rs"),
        ]
        .join("\n");

        assert!(source.contains("ApiClient"));
        assert!(source.contains("CONTAINER_SERVICE_LIST_CONTAINER_REPOSITORIES_PATH"));
        for forbidden in ["#[server", "ServerFn", "server_fn::", "<form action="] {
            assert!(
                !source.contains(forbidden),
                "container workflow introduced an SSR path: {forbidden}"
            );
        }
    }

    #[test]
    fn repository_pull_commands_use_the_explicit_server_distribution_reference() {
        let repository_source =
            include_str!("../../aos-hub-console/src/workflows/registry_containers/mod.rs");
        let component_source = include_str!("../../aos-hub-console/src/components.rs");

        assert!(repository_source.contains(
            "RepositoryPullCommands distribution_reference=repository.distribution_reference"
        ));
        assert!(repository_source.contains("container_pull_commands(&distribution_reference)"));
        assert!(component_source.contains("data-copy-value=command"));
        for forbidden in ["window.location", "document.location", "location.origin"] {
            assert!(
                !repository_source.contains(forbidden),
                "pull command inferred a browser origin: {forbidden}"
            );
        }
    }

    #[test]
    fn route_selection_starts_from_the_current_audience_advertisement() {
        let advertisements = vec![
            ("git".to_string(), "route-git".to_string()),
            ("web".to_string(), "route-web".to_string()),
        ];
        let enabled = vec!["route-other".to_string(), "route-git".to_string()];

        assert_eq!(
            route_selection_for_audience("git", &advertisements, &enabled),
            "route-git"
        );
    }

    #[test]
    fn route_selection_falls_back_when_the_advertisement_is_not_enabled() {
        let advertisements = vec![("git".to_string(), "route-disabled".to_string())];
        let enabled = vec!["route-ready".to_string()];

        assert_eq!(
            route_selection_for_audience("git", &advertisements, &enabled),
            "route-ready"
        );
        assert!(route_selection_for_audience("web", &[], &[]).is_empty());
    }

    #[test]
    fn delivery_workflow_actions_follow_verification_and_activation() {
        assert_eq!(
            delivery_workflow_action("awaiting_verification"),
            Some(DeliveryWorkflowAction::Resume)
        );
        assert_eq!(
            delivery_workflow_action("ready"),
            Some(DeliveryWorkflowAction::ReviewActivation)
        );
        assert_eq!(delivery_workflow_action("active"), None);
    }

    #[test]
    fn new_delivery_endpoint_requires_verifiable_provider_attachment() {
        assert_eq!(
            delivery_draft_prerequisites(true, false, true, true, true, false),
            vec!["Provider listener, TLS, and probe references are required for verification."]
        );
        assert!(delivery_draft_prerequisites(true, true, false, false, false, false).is_empty());
    }

    #[test]
    fn granted_infrastructure_never_exposes_owner_mutations() {
        assert!(owner_controls_visible(
            "scope:org:acme",
            "scope:org:acme",
            true
        ));
        assert!(!owner_controls_visible(
            "scope:instance",
            "scope:org:acme",
            true
        ));
        assert!(!owner_controls_visible(
            "scope:org:acme",
            "scope:org:acme",
            false
        ));
    }

    #[test]
    fn narrow_settings_navigation_starts_collapsed() {
        assert!(!settings_navigation_starts_open(Some(390.0)));
        assert!(settings_navigation_starts_open(Some(1440.0)));
        assert!(settings_navigation_starts_open(None));
    }

    #[test]
    fn delivery_setup_requires_each_resource_permission() {
        let existing = delivery_setup_access(&[
            "read".to_string(),
            "binding.read".to_string(),
            "endpoint.read".to_string(),
            "route.manage".to_string(),
            "gateway.manage".to_string(),
        ]);
        assert!(existing.can_use_existing_endpoint);
        assert!(existing.can_resume_existing);
        assert!(!existing.can_resume_new);
        assert!(!existing.can_create_hostname_endpoint);

        let hostname = delivery_setup_access(&[
            "read".to_string(),
            "binding.read".to_string(),
            "route.manage".to_string(),
            "gateway.manage".to_string(),
            "endpoint.manage".to_string(),
            "network_policy.read".to_string(),
            "domain.manage".to_string(),
        ]);
        assert!(hostname.can_create_hostname_endpoint);
        assert!(!hostname.can_create_managed_domain_endpoint);
        assert!(hostname.can_resume_new);

        let managed_domain = delivery_setup_access(&[
            "read".to_string(),
            "binding.read".to_string(),
            "route.manage".to_string(),
            "gateway.manage".to_string(),
            "endpoint.manage".to_string(),
            "network_policy.read".to_string(),
            "domain.read".to_string(),
            "domain.manage".to_string(),
        ]);
        assert!(managed_domain.can_create_managed_domain_endpoint);

        let endpoint_only = delivery_setup_access(&[
            "read".to_string(),
            "binding.read".to_string(),
            "route.manage".to_string(),
            "gateway.manage".to_string(),
            "endpoint.manage".to_string(),
        ]);
        assert!(!endpoint_only.can_resume_new);
    }

    #[test]
    fn delivery_path_appends_the_placement_prefix() {
        assert_eq!(delivery_public_path("/cdn", "org/cache"), "/cdn/org/cache");
        assert_eq!(delivery_public_path("/", "org/cache"), "/org/cache");
    }

    #[test]
    fn delivery_inventory_does_not_wait_on_duplicate_route_or_binding_reads() {
        let source = include_str!("../../aos-hub-console/src/workflows/routes.rs");
        assert!(!source.contains("ROUTE_SERVICE_LIST_ROUTES_PATH"));
        assert!(!source.contains("OrganizationBindingRef"));
        assert!(source.contains("owner_scope_key: gateway_scope.clone()"));
        assert!(source.contains("include_granted: true"));
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
            .chain(CACHE_INVENTORY_PAGES)
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
