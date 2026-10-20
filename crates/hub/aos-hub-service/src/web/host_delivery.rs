//! Per-host delivery status for the registries the browse pages list.
//!
//! The exact control authority renders every visible registry's browse pages,
//! whether or not that host also delivers the registry's machine surface (Git,
//! Nix cache, Web bytes, or OCI). A registry is *routed* on a host only when an
//! enabled delivery route bound to that exact endpoint targets it. The route
//! dispatcher ([`crate::connect::rewrite_for_route`]) already loads those
//! enabled routes to match the request, so it attaches the same rows to each
//! request it admits to the control-plane router as a [`HostRoutes`]
//! extension. Browse pages read that extension instead of re-deriving route
//! matching, and say plainly when a listed registry cannot be fetched from the
//! host the visitor is on.
//!
//! A request that carries no [`HostRoutes`] (a router used without route
//! dispatch, or a page reached through a matched delivery route) renders no
//! delivery status, so the pages degrade to their previous output.

use std::collections::BTreeMap;

use aos_hub_db::db::{Database, InboundRouteRecord, RegistryRecord, SurfaceTarget};

/// The registries one exact request host serves through enabled routes.
///
/// Built from the enabled-route rows the dispatcher matched the request
/// against ([`Database::inbound_routes`]), keyed by registry slug so both the
/// relational home listing and the anonymous directory projection (whose rows
/// carry no registry id) can look entries up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRoutes {
    /// Registry slug to whether at least one of its enabled routes is ready.
    registries: BTreeMap<String, bool>,
}

impl HostRoutes {
    /// Summarizes the enabled routes bound to one request host.
    ///
    /// Binary-cache routes are ignored: cache slugs share the URL namespace
    /// but are never listed as registries.
    #[must_use]
    pub fn from_inbound(routes: &[InboundRouteRecord]) -> Self {
        let mut registries = BTreeMap::new();
        for route in routes {
            if !matches!(route.surface, SurfaceTarget::Registry(_)) {
                continue;
            }

            let ready = registries.entry(route.target_slug.clone()).or_insert(false);
            *ready |= route.ready;
        }

        Self { registries }
    }

    /// Classifies `slug` from this host's enabled routes alone.
    ///
    /// Never returns [`HostDelivery::Disabled`]; distinguishing a disabled
    /// route from no route at all needs the registry's full route list (see
    /// [`registry_delivery`]).
    #[must_use]
    pub fn delivery(&self, slug: &str) -> HostDelivery {
        match self.registries.get(slug) {
            Some(true) => HostDelivery::Routed,
            Some(false) => HostDelivery::Pending,
            None => HostDelivery::Unrouted,
        }
    }
}

/// How the request host delivers one registry's machine surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDelivery {
    /// An enabled, ready route on this host serves the registry.
    Routed,
    /// An enabled route on this host exists but is not ready yet: its
    /// endpoint, route, or access observations are missing or stale.
    Pending,
    /// The registry has delivery routes and every one of them is disabled.
    Disabled,
    /// No enabled route on this host serves the registry.
    Unrouted,
}

impl HostDelivery {
    /// Whether this host has no enabled route for the registry at all.
    ///
    /// Machine clients must not be told a surface exists on a host that does
    /// not serve it, so content negotiation treats these registries as absent.
    #[must_use]
    pub fn lacks_enabled_route(self) -> bool {
        matches!(self, Self::Disabled | Self::Unrouted)
    }

    /// Returns the short status badge for the instance home listing, or
    /// `None` when the registry is routed and needs no badge.
    ///
    /// The glyph and the words carry the state on their own; the `warn`
    /// color only reinforces them.
    #[must_use]
    pub fn badge_html(self) -> Option<&'static str> {
        match self {
            Self::Routed => None,
            Self::Pending => Some("<span class=\"badge warn\">◐ route not ready</span>"),
            Self::Disabled => Some("<span class=\"badge warn\">○ route disabled</span>"),
            Self::Unrouted => Some("<span class=\"badge warn\">○ no route on this host</span>"),
        }
    }

    /// Returns the explanatory notice for the registry home, or `None` when
    /// the registry is routed.
    #[must_use]
    pub fn notice_html(self) -> Option<&'static str> {
        match self {
            Self::Routed => None,
            Self::Pending => Some(
                "<p class=\"warn registry-delivery\">This registry's route on this host \
                 is enabled but not ready yet. Clients can fetch from this host once \
                 the route's health checks pass.</p>",
            ),
            Self::Disabled => Some(
                "<p class=\"warn registry-delivery\">This registry's delivery route is \
                 disabled. You can browse what it has published here, but clients \
                 cannot fetch from it until an operator enables a route.</p>",
            ),
            Self::Unrouted => Some(
                "<p class=\"warn registry-delivery\">This registry has no public route \
                 on this host yet. You can browse what it has published here, but \
                 clients cannot fetch from this host until an operator adds and \
                 enables a route.</p>",
            ),
        }
    }
}

/// Resolves the full delivery status of `registry` on the request host.
///
/// Starts from the dispatcher's [`HostRoutes`]. A registry with no enabled
/// route on this host is reported as [`HostDelivery::Disabled`] when it has
/// routes and none of them is enabled anywhere; a registry that is delivered
/// from some other host stays [`HostDelivery::Unrouted`] here.
///
/// Returns `None` when the route list cannot be read, so a database failure
/// never renders a status claim the page cannot back up.
pub async fn registry_delivery(
    db: &Database,
    host_routes: &HostRoutes,
    registry: &RegistryRecord,
) -> Option<HostDelivery> {
    let on_host = host_routes.delivery(&registry.slug);
    if on_host != HostDelivery::Unrouted {
        return Some(on_host);
    }

    let routes = db
        .list_routes(SurfaceTarget::Registry(registry.id))
        .await
        .ok()?;
    let all_disabled = !routes.is_empty() && routes.iter().all(|route| !route.enabled);

    Some(if all_disabled {
        HostDelivery::Disabled
    } else {
        HostDelivery::Unrouted
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(slug: &str, surface: SurfaceTarget, ready: bool) -> InboundRouteRecord {
        InboundRouteRecord {
            id: format!("route:{slug}"),
            configuration_generation: 1,
            configuration_digest: String::new(),
            base_path: String::new(),
            surface,
            target_slug: slug.to_string(),
            mode: "hub_proxy".to_string(),
            access_policy_kind: "public".to_string(),
            access_boundary_id: None,
            access_boundary_revision: None,
            external_provider_kind: None,
            external_provider_resource_id: None,
            external_provider_revision: None,
            placement_id: None,
            placement_policy_revision_id: None,
            serves_git: true,
            serves_cache: true,
            serves_web: true,
            serves_oci: false,
            ready,
        }
    }

    #[test]
    fn host_routes_classify_registries_by_their_enabled_routes_on_this_host() {
        let routes = HostRoutes::from_inbound(&[
            inbound("acme/ready", SurfaceTarget::Registry(1), true),
            inbound("acme/pending", SurfaceTarget::Registry(2), false),
            inbound("acme/mixed", SurfaceTarget::Registry(3), false),
            inbound("acme/mixed", SurfaceTarget::Registry(3), true),
            inbound("acme/cache", SurfaceTarget::BinaryCache(4), true),
        ]);

        assert_eq!(routes.delivery("acme/ready"), HostDelivery::Routed);
        assert_eq!(routes.delivery("acme/pending"), HostDelivery::Pending);
        assert_eq!(routes.delivery("acme/mixed"), HostDelivery::Routed);
        assert_eq!(routes.delivery("acme/cache"), HostDelivery::Unrouted);
        assert_eq!(routes.delivery("acme/absent"), HostDelivery::Unrouted);
    }

    #[test]
    fn only_routed_registries_render_without_a_status() {
        assert!(HostDelivery::Routed.badge_html().is_none());
        assert!(HostDelivery::Routed.notice_html().is_none());

        for status in [
            HostDelivery::Pending,
            HostDelivery::Disabled,
            HostDelivery::Unrouted,
        ] {
            assert!(status
                .badge_html()
                .is_some_and(|badge| badge.contains("badge")));
            assert!(status
                .notice_html()
                .is_some_and(|notice| notice.contains("route")));
        }
        assert!(HostDelivery::Unrouted
            .notice_html()
            .is_some_and(|notice| notice.contains("no public route on this host yet")));
        assert!(HostDelivery::Disabled
            .notice_html()
            .is_some_and(|notice| notice.contains("route is disabled")));
    }

    #[test]
    fn content_negotiation_hides_registries_without_an_enabled_host_route() {
        assert!(HostDelivery::Unrouted.lacks_enabled_route());
        assert!(HostDelivery::Disabled.lacks_enabled_route());
        assert!(!HostDelivery::Pending.lacks_enabled_route());
        assert!(!HostDelivery::Routed.lacks_enabled_route());
    }
}
