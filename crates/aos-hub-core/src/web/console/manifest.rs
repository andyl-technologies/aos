//! Declared producer-console method and path contract.
//!
//! The native hub and Cloudflare Worker both mount [`super::console_router`],
//! while nested registry paths additionally pass through
//! [`super::dispatch_nested`]. This module is the single route declaration
//! shared by those three entry points. Router tests compare the declarations
//! here with the routes mounted in `router.rs`; the nested dispatcher derives
//! its recognized tails and methods directly from [`REGISTRY_ROUTES`].

/// The GET and POST methods declared for one console path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteMethods {
    /// The path accepts GET only.
    Get,
    /// The path accepts POST only.
    Post,
    /// The path accepts both GET and POST.
    GetAndPost,
}

impl RouteMethods {
    /// Returns whether this declaration permits a GET request.
    #[must_use]
    pub const fn allows_get(self) -> bool {
        matches!(self, Self::Get | Self::GetAndPost)
    }

    /// Returns whether this declaration permits a POST request.
    #[must_use]
    pub const fn allows_post(self) -> bool {
        matches!(self, Self::Post | Self::GetAndPost)
    }

    /// Returns the exact `Allow` header for rejected methods.
    #[must_use]
    pub const fn allow_header(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::GetAndPost => "GET, POST",
        }
    }
}

/// One canonical console path template and its declared methods.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteSpec {
    /// The axum-style canonical path template.
    pub path: &'static str,
    /// The GET and POST methods accepted by the path.
    pub methods: RouteMethods,
}

impl RouteSpec {
    /// Materializes this template with deterministic, syntactically valid
    /// resource identifiers for request-level contract tests.
    #[must_use]
    pub fn sample_path(&self, registry: &str) -> String {
        self.path
            .split('/')
            .map(|segment| match segment {
                "{registry}" => registry,
                "{org}" => "acme",
                "{cache}" | "{slug}" => "build",
                "{placement}" => "primary",
                "{name}" => "stable",
                "{token}" => "token-1",
                "{principal}" | "{project}" | "{webhook}" | "{id}" => "1",
                "{binding}" => "binding-1",
                literal => literal,
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Returns whether this route is scoped to one registry path.
    #[must_use]
    pub fn is_registry(self) -> bool {
        self.path.starts_with("/{registry}/")
    }

    /// Normalizes capture names so independently named router parameters have
    /// one structural identity.
    #[must_use]
    pub fn structural_path(self) -> String {
        self.path
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') && segment.ends_with('}') {
                    "{}"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

const fn route(path: &'static str, methods: RouteMethods) -> RouteSpec {
    RouteSpec { path, methods }
}

/// Internal response sentinel stamped after a request matches a declared route.
///
/// Contract tests use this sentinel to distinguish a handler-produced `400` or
/// `404` from the host router's fallback response. It is deliberately not a
/// wire-level compatibility signal and carries no resource or authorization
/// information.
#[derive(Clone, Copy, Debug)]
pub struct ConsoleRouteMatched;

/// Canonical console routes not scoped to one registry.
pub const CONSOLE_ROUTES: &[RouteSpec] = &[
    route("/login", RouteMethods::GetAndPost),
    route("/login/password", RouteMethods::Post),
    route("/auth/magic", RouteMethods::Get),
    route("/auth/sso", RouteMethods::Post),
    route("/auth/oidc/start", RouteMethods::Get),
    route("/auth/oidc/callback", RouteMethods::Get),
    route("/logout", RouteMethods::GetAndPost),
    route("/-/account", RouteMethods::Get),
    route("/-/account/password", RouteMethods::Post),
    route("/-/reauth", RouteMethods::Post),
    route("/-/account/sessions/revoke-all", RouteMethods::Post),
    route("/-/account/passkeys", RouteMethods::Get),
    route("/-/account/passkeys/remove", RouteMethods::Post),
    route("/-/account/passkeys/begin", RouteMethods::Post),
    route("/-/account/passkeys/finish", RouteMethods::Post),
    route("/auth/passkey/begin", RouteMethods::Post),
    route("/auth/passkey/finish", RouteMethods::Post),
    route("/activate", RouteMethods::GetAndPost),
    route("/-/instance/identity-and-signup", RouteMethods::GetAndPost),
    route("/-/orgs/new", RouteMethods::GetAndPost),
    route("/-/orgs", RouteMethods::Get),
    route("/-/caches", RouteMethods::Get),
    route("/-/org/{org}", RouteMethods::Get),
    route("/-/org/{org}/audit-log", RouteMethods::Get),
    route("/-/org/{org}/members", RouteMethods::Get),
    route("/-/org/{org}/members/invitations/new", RouteMethods::Get),
    route("/-/org/{org}/members/invitations", RouteMethods::Post),
    route(
        "/-/org/{org}/members/{principal}/remove",
        RouteMethods::Post,
    ),
    route("/-/org/{org}/members/{principal}/role", RouteMethods::Post),
    route("/-/org/{org}/projects", RouteMethods::Get),
    route("/-/org/{org}/storage-bindings", RouteMethods::Get),
    route("/-/org/{org}/storage-bindings/new", RouteMethods::Get),
    route(
        "/-/org/{org}/storage-bindings/plan-create",
        RouteMethods::Post,
    ),
    route("/-/org/{org}/domains", RouteMethods::Get),
    route("/-/org/{org}/network-boundaries", RouteMethods::Get),
    route("/-/org/{org}/delivery-endpoints", RouteMethods::Get),
    route("/-/org/{org}/storage-gateways", RouteMethods::Get),
    route("/-/org/{org}/topology-defaults", RouteMethods::Get),
    route("/-/org/{org}/identity-and-access", RouteMethods::Get),
    route("/-/org/{org}/operations", RouteMethods::Get),
    route("/-/org/{org}/danger", RouteMethods::Get),
    route(
        "/-/org/{org}/storage-bindings/{binding}/plan-delete",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/delete",
        RouteMethods::Post,
    ),
    route("/-/org/{org}/storage-bindings/create", RouteMethods::Post),
    route("/-/org/{org}/storage-bindings/{binding}", RouteMethods::Get),
    route(
        "/-/org/{org}/storage-bindings/{binding}/credentials",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/write-revisions",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/consumer-grants",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/placements",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/storage-gateways",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/danger",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/credentials/plan-set",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/credentials/set",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/credentials/plan-rotate",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/credentials/rotate",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-grant",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/consumer-grants/grant",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-revoke",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/storage-bindings/{binding}/consumer-grants/revoke",
        RouteMethods::Post,
    ),
    route("/-/org/{org}/caches", RouteMethods::Get),
    route("/-/org/{org}/caches/{slug}", RouteMethods::Get),
    route("/-/org/{org}/caches/{slug}/access", RouteMethods::Get),
    route(
        "/-/org/{org}/caches/{slug}/access/plan-update",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/access/update",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/retention-subscriptions",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/population-targets",
        RouteMethods::Get,
    ),
    route("/-/org/{org}/caches/{slug}/manual-roots", RouteMethods::Get),
    route("/-/org/{org}/caches/{slug}/objects", RouteMethods::Get),
    route(
        "/-/org/{org}/caches/{slug}/signing-key",
        RouteMethods::GetAndPost,
    ),
    route("/-/org/{org}/caches/{slug}/operations", RouteMethods::Get),
    route(
        "/-/org/{org}/caches/{slug}/garbage-collection",
        RouteMethods::Get,
    ),
    route("/-/org/{org}/caches/{slug}/danger", RouteMethods::Get),
    route("/-/org/{org}/caches/{slug}/placements", RouteMethods::Get),
    route(
        "/-/org/{org}/caches/{slug}/placement-policies",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placement-equivalences",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/new",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/plan-create",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/create",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/plan-promote",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/promote",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/plan-update",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/update",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/plan-drain",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/drain",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/plan-delete",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/{placement}/delete",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/plan-remove-write-authority",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/remove-write-authority",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/plan-cancel-promotion",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/placements/cancel-promotion",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/delivery-routes",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/delivery-routes/canonical-audiences",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/garbage-collection/plans",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/garbage-collection/runs",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/garbage-collection/jobs",
        RouteMethods::Get,
    ),
    route(
        "/-/org/{org}/caches/{slug}/danger/plan-delete",
        RouteMethods::Post,
    ),
    route(
        "/-/org/{org}/caches/{slug}/danger/delete",
        RouteMethods::Post,
    ),
    route("/-/org/{org}/registries", RouteMethods::Get),
    route("/-/org/{org}/danger/delete", RouteMethods::Post),
    route("/-/org/{org}/signing-keys", RouteMethods::GetAndPost),
    route("/-/org/{org}/signing-keys/new", RouteMethods::Get),
    route("/-/org/{org}/webhooks", RouteMethods::Get),
    route("/-/org/{org}/webhooks/new", RouteMethods::Get),
    route("/-/org/{org}/sso", RouteMethods::GetAndPost),
    route("/-/instance", RouteMethods::Get),
    route("/-/instance/storage-bindings", RouteMethods::Get),
    route("/-/instance/branding", RouteMethods::GetAndPost),
    route("/-/instance/resource-defaults", RouteMethods::GetAndPost),
];

/// Canonical registry-scoped console routes.
///
/// `{registry}` is a structural capture name, independent of the local name a
/// transport router gives its parameter. The nested dispatcher replaces that
/// segment with the complete registry path.
pub const REGISTRY_ROUTES: &[RouteSpec] = &[
    route("/{registry}/-/settings", RouteMethods::Get),
    route("/{registry}/-/settings/access", RouteMethods::Get),
    route("/{registry}/-/settings/placements", RouteMethods::Get),
    route(
        "/{registry}/-/settings/placement-policies",
        RouteMethods::Get,
    ),
    route(
        "/{registry}/-/settings/placement-equivalences",
        RouteMethods::Get,
    ),
    route("/{registry}/-/settings/placements/new", RouteMethods::Get),
    route(
        "/{registry}/-/settings/placements/plan-create",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/create",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/plan-promote",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/promote",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/plan-update",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/update",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/plan-drain",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/drain",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/plan-delete",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/{placement}/delete",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/plan-remove-write-authority",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/remove-write-authority",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/plan-cancel-promotion",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/placements/cancel-promotion",
        RouteMethods::Post,
    ),
    route("/{registry}/-/settings/cache-stack", RouteMethods::Get),
    route(
        "/{registry}/-/settings/retention-consumers",
        RouteMethods::Get,
    ),
    route(
        "/{registry}/-/settings/population-targets",
        RouteMethods::Get,
    ),
    route("/{registry}/-/settings/operations", RouteMethods::Get),
    route("/{registry}/-/settings/danger", RouteMethods::Get),
    route("/{registry}/-/settings/delivery-routes", RouteMethods::Get),
    route(
        "/{registry}/-/settings/delivery-routes/canonical-audiences",
        RouteMethods::Get,
    ),
    route("/{registry}/-/settings/upstream-mirror", RouteMethods::Get),
    route("/{registry}/-/settings/tokens", RouteMethods::GetAndPost),
    route(
        "/{registry}/-/settings/tokens/{token}/revoke",
        RouteMethods::Post,
    ),
    route("/{registry}/-/settings/channels", RouteMethods::Get),
    route("/{registry}/-/settings/channels/{name}", RouteMethods::Get),
    route(
        "/{registry}/-/settings/signing-keys",
        RouteMethods::GetAndPost,
    ),
    route(
        "/{registry}/-/settings/signing-keys/rotate",
        RouteMethods::Get,
    ),
    route("/{registry}/-/settings/publish-history", RouteMethods::Get),
    route(
        "/{registry}/-/settings/configuration",
        RouteMethods::GetAndPost,
    ),
    route("/{registry}/-/settings/change-requests", RouteMethods::Get),
    route(
        "/{registry}/-/settings/change-requests/{id}",
        RouteMethods::Get,
    ),
    route(
        "/{registry}/-/settings/change-requests/{id}/comment",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/change-requests/{id}/review",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/change-requests/{id}/close",
        RouteMethods::Post,
    ),
    route(
        "/{registry}/-/settings/change-requests/{id}/reopen",
        RouteMethods::Post,
    ),
];

/// Iterates over the complete native and Worker console route contract.
pub fn route_manifest() -> impl Iterator<Item = &'static RouteSpec> {
    CONSOLE_ROUTES.iter().chain(REGISTRY_ROUTES)
}

/// Returns the declaration for one mounted router template.
///
/// Capture names are intentionally ignored, so the router's `{slug}` and the
/// manifest's `{registry}` describe the same structural route.
#[must_use]
pub fn declared_route(template: &str) -> Option<&'static RouteSpec> {
    let structural = structural_path(template);
    route_manifest().find(|route| route.structural_path() == structural)
}

/// Returns the declared methods for one concrete flat console request path.
#[must_use]
pub fn route_methods_for_path(path: &str) -> Option<RouteMethods> {
    let path = path.trim_start_matches('/');
    route_manifest()
        .find(|route| path_matches(route.path.trim_start_matches('/'), path))
        .map(|route| route.methods)
}

/// Returns the declared methods for a nested registry settings tail.
#[must_use]
pub fn nested_route_methods(tail: &str) -> Option<RouteMethods> {
    REGISTRY_ROUTES.iter().find_map(|route| {
        let template = route.path.strip_prefix("/{registry}/-/")?;
        path_matches(template, tail).then_some(route.methods)
    })
}

/// Matches literal path segments and requires each `{parameter}` to be one
/// non-empty segment.
fn path_matches(template: &str, path: &str) -> bool {
    let mut template = template.split('/');
    let mut path = path.split('/');
    loop {
        match (template.next(), path.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual)) => {
                let parameter = expected.starts_with('{') && expected.ends_with('}');
                if actual.is_empty() || (!parameter && expected != actual) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn structural_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "{}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn nested_dispatch_is_generated_from_registry_manifest() {
        for route in REGISTRY_ROUTES {
            let tail = route
                .path
                .strip_prefix("/{registry}/-/")
                .expect("registry route prefix")
                .replace("{token}", "token-1")
                .replace("{name}", "stable")
                .replace("{id}", "change-1");
            assert_eq!(nested_route_methods(&tail), Some(route.methods), "{tail}");
        }
    }

    #[test]
    fn nested_templates_do_not_capture_extra_or_empty_segments() {
        for tail in [
            "settings/tokens//revoke",
            "settings/tokens/token-1/revoke/extra",
            "settings/channels/stable/extra",
            "settings/change-requests/change-1/unknown",
        ] {
            assert_eq!(nested_route_methods(tail), None, "{tail}");
        }
    }

    #[test]
    fn declared_method_path_pairs_are_structurally_unique() {
        let pairs = route_manifest()
            .flat_map(expand_structural_methods)
            .collect::<Vec<_>>();
        let unique = pairs.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(pairs.len(), unique.len(), "duplicate route declaration");
    }

    #[test]
    fn concrete_paths_resolve_to_their_exact_method_contract() {
        for route in route_manifest() {
            let path = route.sample_path("demo");
            assert_eq!(route_methods_for_path(&path), Some(route.methods), "{path}");
            assert_eq!(declared_route(route.path), Some(route));
        }
    }

    fn expand_structural_methods(
        route: &RouteSpec,
    ) -> impl Iterator<Item = (String, &'static str)> {
        [
            route
                .methods
                .allows_get()
                .then(|| (route.structural_path(), "GET")),
            route
                .methods
                .allows_post()
                .then(|| (route.structural_path(), "POST")),
        ]
        .into_iter()
        .flatten()
    }
}
