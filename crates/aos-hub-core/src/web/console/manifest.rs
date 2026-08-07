//! Closed HTTP route contract for authentication and the browser console.
//!
//! Authentication ceremonies retain their purpose-built methods. Management
//! deep links are GET-only application-shell routes validated against
//! [`aos_hub_console_contract::ConsoleRoute`]; all management mutations use the
//! canonical Connect API.

/// Methods declared for one HTTP route.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteMethods {
    /// The route accepts GET only.
    Get,
    /// The route accepts POST only.
    Post,
    /// The route accepts GET and POST.
    GetAndPost,
}

impl RouteMethods {
    /// Returns whether the declaration permits GET.
    #[must_use]
    pub const fn allows_get(self) -> bool {
        matches!(self, Self::Get | Self::GetAndPost)
    }

    /// Returns whether the declaration permits POST.
    #[must_use]
    pub const fn allows_post(self) -> bool {
        matches!(self, Self::Post | Self::GetAndPost)
    }

    /// Returns the exact `Allow` header value.
    #[must_use]
    pub const fn allow_header(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::GetAndPost => "GET, POST",
        }
    }
}

/// One canonical route template and its declared methods.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteSpec {
    /// Axum-style path template.
    pub path: &'static str,
    /// Accepted methods.
    pub methods: RouteMethods,
}

impl RouteSpec {
    /// Materializes the template for request-level contract tests.
    #[must_use]
    pub fn sample_path(&self, registry: &str) -> String {
        self.path
            .split('/')
            .map(|segment| match segment {
                "{registry}" => registry,
                "{org}" => "acme",
                "{cache}" => "build",
                "{page}" => sample_page(self.path),
                literal => literal,
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Returns whether this template belongs to a registry scope.
    #[must_use]
    pub fn is_registry(self) -> bool {
        self.path.starts_with("/{registry}/")
    }

    /// Normalizes parameter names for structural comparisons.
    #[must_use]
    pub fn structural_path(self) -> String {
        structural_path(self.path)
    }
}

fn sample_page(template: &str) -> &'static str {
    if template.contains("/caches/{cache}/") {
        "objects"
    } else if template.starts_with("/{registry}/") {
        "images"
    } else if template.starts_with("/-/instance/") {
        "domains"
    } else {
        "projects"
    }
}

const fn route(path: &'static str, methods: RouteMethods) -> RouteSpec {
    RouteSpec { path, methods }
}

/// Internal sentinel proving that the shared router claimed a request.
#[derive(Clone, Copy, Debug)]
pub struct ConsoleRouteMatched;

/// Authentication, account, and non-registry management routes.
pub const CONSOLE_ROUTES: &[RouteSpec] = &[
    route("/oauth2/device_authorization", RouteMethods::Post),
    route("/oauth2/token", RouteMethods::Post),
    route("/oauth2/revoke", RouteMethods::Post),
    route("/login", RouteMethods::GetAndPost),
    route("/login/password", RouteMethods::Post),
    route("/auth/magic", RouteMethods::Get),
    route("/auth/sso", RouteMethods::Post),
    route("/auth/oidc/start", RouteMethods::Get),
    route("/auth/oidc/callback", RouteMethods::Get),
    route("/logout", RouteMethods::GetAndPost),
    route("/-/auth/session-token", RouteMethods::Post),
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
    route("/-/instance", RouteMethods::Get),
    route("/-/instance/{page}", RouteMethods::Get),
    route("/-/instance/domains/new", RouteMethods::Get),
    route("/-/instance/network-boundaries/new", RouteMethods::Get),
    route("/-/instance/delivery-endpoints/new", RouteMethods::Get),
    route("/-/instance/storage-gateways/new", RouteMethods::Get),
    route("/-/orgs", RouteMethods::Get),
    route("/-/orgs/new", RouteMethods::Get),
    route("/-/org/{org}", RouteMethods::Get),
    route("/-/org/{org}/{page}", RouteMethods::Get),
    route("/-/org/{org}/projects/new", RouteMethods::Get),
    route("/-/org/{org}/registries/new", RouteMethods::Get),
    route("/-/org/{org}/caches/new", RouteMethods::Get),
    route("/-/org/{org}/storage-bindings/new", RouteMethods::Get),
    route("/-/org/{org}/domains/new", RouteMethods::Get),
    route("/-/org/{org}/network-boundaries/new", RouteMethods::Get),
    route("/-/org/{org}/delivery-endpoints/new", RouteMethods::Get),
    route("/-/org/{org}/storage-gateways/new", RouteMethods::Get),
    route("/-/org/{org}/caches/{cache}", RouteMethods::Get),
    route("/-/org/{org}/caches/{cache}/{page}", RouteMethods::Get),
    route("/-/org/{org}/invitations/accept", RouteMethods::GetAndPost),
];

/// Registry management shell routes. Nested registry paths use the same tail.
pub const REGISTRY_ROUTES: &[RouteSpec] = &[
    route("/{registry}/-/settings", RouteMethods::Get),
    route("/{registry}/-/settings/{page}", RouteMethods::Get),
];

/// Iterates over the complete shared HTTP route contract.
pub fn route_manifest() -> impl Iterator<Item = &'static RouteSpec> {
    CONSOLE_ROUTES.iter().chain(REGISTRY_ROUTES)
}

/// Finds the declaration for one mounted router template.
#[must_use]
pub fn declared_route(template: &str) -> Option<&'static RouteSpec> {
    let structural = structural_path(template);
    route_manifest().find(|route| route.structural_path() == structural)
}

/// Resolves the declared methods for one concrete request path.
#[must_use]
pub fn route_methods_for_path(path: &str) -> Option<RouteMethods> {
    if aos_hub_console_contract::ConsoleRoute::resolve(path).is_some() {
        return Some(RouteMethods::Get);
    }
    let path = path.trim_start_matches('/');
    CONSOLE_ROUTES
        .iter()
        .filter(|route| !is_management_shell_template(route.path))
        .find(|route| path_matches(route.path.trim_start_matches('/'), path))
        .map(|route| route.methods)
}

fn is_management_shell_template(path: &str) -> bool {
    matches!(
        path,
        "/-/instance"
            | "/-/instance/{page}"
            | "/-/instance/domains/new"
            | "/-/instance/network-boundaries/new"
            | "/-/instance/delivery-endpoints/new"
            | "/-/instance/storage-gateways/new"
            | "/-/orgs"
            | "/-/orgs/new"
            | "/-/org/{org}"
            | "/-/org/{org}/{page}"
            | "/-/org/{org}/projects/new"
            | "/-/org/{org}/registries/new"
            | "/-/org/{org}/caches/new"
            | "/-/org/{org}/storage-bindings/new"
            | "/-/org/{org}/domains/new"
            | "/-/org/{org}/network-boundaries/new"
            | "/-/org/{org}/delivery-endpoints/new"
            | "/-/org/{org}/storage-gateways/new"
            | "/-/org/{org}/caches/{cache}"
            | "/-/org/{org}/caches/{cache}/{page}"
    )
}

/// Resolves a nested registry settings tail when it is canonical.
#[must_use]
pub fn nested_route_methods(tail: &str) -> Option<RouteMethods> {
    let path = format!("/acme/main/-/{tail}");
    aos_hub_console_contract::ConsoleRoute::resolve(&path).map(|_| RouteMethods::Get)
}

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
    fn only_canonical_registry_pages_are_nested_console_routes() {
        assert_eq!(
            nested_route_methods("settings/images"),
            Some(RouteMethods::Get)
        );
        assert_eq!(nested_route_methods("settings/signing-key"), None);
        assert_eq!(nested_route_methods("settings/tokens/1/revoke"), None);
    }

    #[test]
    fn declared_method_path_pairs_are_structurally_unique() {
        let pairs = route_manifest()
            .flat_map(|route| {
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
            })
            .collect::<Vec<_>>();
        let unique = pairs.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(pairs.len(), unique.len(), "duplicate route declaration");
    }

    #[test]
    fn concrete_samples_resolve_to_their_method_contract() {
        for route in route_manifest() {
            let path = route.sample_path("demo");
            assert_eq!(route_methods_for_path(&path), Some(route.methods), "{path}");
            assert_eq!(declared_route(route.path), Some(route));
        }
    }
}
