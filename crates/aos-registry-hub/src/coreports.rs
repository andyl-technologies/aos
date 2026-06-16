//! Native adapters from the hub's concrete types to the core service ports.
//!
//! The shared, transport-free service
//! ([`RpcService`](aos_registry_core::service::RpcService)) depends on a small
//! set of platform ports — a [`RateLimiter`](aos_registry_core::ratelimit::RateLimiter)
//! and a [`SurfaceProvider`](aos_registry_core::fetch::SurfaceProvider) — so the
//! same method bodies run unchanged on the native hub and the Cloudflare Worker.
//! The native hub already owns concrete equivalents (the in-process
//! [`RateLimiter`](crate::ratelimit::RateLimiter) and the filesystem/HTTP
//! [`SurfaceFetch`](crate::fetch::SurfaceFetch) transports), so this module is the
//! thin glue that makes those concrete types *satisfy the core ports*:
//!
//! - [`crate::ratelimit::RateLimiter`] gains an
//!   [`aos_registry_core::ratelimit::RateLimiter`] impl. The core trait method is
//!   `async`; the hub's check is a synchronous counter read-modify-write, so the
//!   impl simply runs it inline. The two enums ([`RateClass`] and
//!   [`RateDecision`]) are mirror-for-mirror and are mapped by name.
//! - [`crate::fetch::LocalFsFetch`] and [`crate::fetch::HttpFetch`] each gain an
//!   [`aos_registry_core::fetch::SurfaceFetch`] impl with the identical
//!   `fetch`/`describe` signatures, delegating to their inherent methods.
//! - [`HubSurfaceProvider`] is the
//!   [`SurfaceProvider`](aos_registry_core::fetch::SurfaceProvider): it resolves a
//!   per-registry fetcher through the existing
//!   [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry) and
//!   re-boxes it as a core [`SurfaceFetch`] via [`CoreFetchAdapter`].

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use aos_registry_core::db::{Database, RegistryRecord};
use aos_registry_core::fetch as core_fetch;
use aos_registry_core::ratelimit as core_rl;

/// Map a core [`RateClass`](core_rl::RateClass) to the hub's own
/// [`RateClass`](crate::ratelimit::RateClass).
///
/// The two enums are variant-for-variant mirrors (the core enum was defined to
/// match the native limiter), so this is a 1:1 rename — the shared service
/// currently meters only [`RateClass::CreateOrg`](core_rl::RateClass::CreateOrg),
/// but every variant is mapped so the port is total.
fn map_class(class: core_rl::RateClass) -> crate::ratelimit::RateClass {
    use crate::ratelimit::RateClass as Hub;
    use core_rl::RateClass as Core;
    match class {
        Core::DeviceAuthorization => Hub::DeviceAuthorization,
        Core::MagicLinkEmail => Hub::MagicLinkEmail,
        Core::MagicLinkIp => Hub::MagicLinkIp,
        Core::PasswordEmail => Hub::PasswordEmail,
        Core::PasswordIp => Hub::PasswordIp,
        Core::TokenExchange => Hub::TokenExchange,
        Core::BrowseSearch => Hub::BrowseSearch,
        Core::CreateOrg => Hub::CreateOrg,
        Core::DeviceActivate => Hub::DeviceActivate,
    }
}

/// Map the hub's [`RateDecision`](crate::ratelimit::RateDecision) to the core's.
fn map_decision(decision: crate::ratelimit::RateDecision) -> core_rl::RateDecision {
    match decision {
        crate::ratelimit::RateDecision::Allowed => core_rl::RateDecision::Allowed,
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            core_rl::RateDecision::Limited { retry_after }
        }
    }
}

/// The hub's in-process limiter, exposed as the core [`RateLimiter`] port.
///
/// The hub's [`check`](crate::ratelimit::RateLimiter::check) is synchronous (a
/// `Mutex`-guarded counter), so the `async` port method runs it inline and
/// completes immediately.
#[async_trait]
impl core_rl::RateLimiter for crate::ratelimit::RateLimiter {
    async fn check(&self, class: core_rl::RateClass, key: &str, now: i64) -> core_rl::RateDecision {
        map_decision(crate::ratelimit::RateLimiter::check(
            self,
            map_class(class),
            key,
            now,
        ))
    }
}

/// The hub's filesystem fetcher, exposed as the core [`SurfaceFetch`] port.
#[async_trait]
impl core_fetch::SurfaceFetch for crate::fetch::LocalFsFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        crate::fetch::SurfaceFetch::fetch(self, path).await
    }

    fn describe(&self) -> String {
        crate::fetch::SurfaceFetch::describe(self)
    }
}

/// The hub's HTTP(S) fetcher, exposed as the core [`SurfaceFetch`] port.
#[async_trait]
impl core_fetch::SurfaceFetch for crate::fetch::HttpFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        crate::fetch::SurfaceFetch::fetch(self, path).await
    }

    fn describe(&self) -> String {
        crate::fetch::SurfaceFetch::describe(self)
    }
}

/// Adapts a boxed hub [`SurfaceFetch`](crate::fetch::SurfaceFetch) to the core
/// [`SurfaceFetch`](core_fetch::SurfaceFetch) port by delegation.
///
/// [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry)
/// returns a `Box<dyn crate::fetch::SurfaceFetch>` (the hub trait object) chosen
/// per registry. The core service needs a `Box<dyn core_fetch::SurfaceFetch>`,
/// and a trait object cannot be re-coerced to a *different* trait, so this
/// concrete wrapper holds the hub box and forwards both methods.
struct CoreFetchAdapter(Box<dyn crate::fetch::SurfaceFetch>);

#[async_trait]
impl core_fetch::SurfaceFetch for CoreFetchAdapter {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        self.0.fetch(path).await
    }

    fn describe(&self) -> String {
        self.0.describe()
    }
}

/// The native [`SurfaceProvider`](core_fetch::SurfaceProvider): resolves a
/// per-registry surface fetcher over the hub's storage bindings.
///
/// Delegates to
/// [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry) —
/// the same resolver the rest of the hub uses — and re-boxes the chosen fetcher
/// through [`CoreFetchAdapter`] so it satisfies the core port.
pub struct HubSurfaceProvider {
    /// The hub database, used to resolve a registry's storage-binding root.
    db: Arc<Database>,
}

impl HubSurfaceProvider {
    /// Build a provider over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubSurfaceProvider {
        HubSurfaceProvider { db }
    }
}

#[async_trait]
impl core_fetch::SurfaceProvider for HubSurfaceProvider {
    async fn fetcher(&self, registry: &RegistryRecord) -> Result<Box<dyn core_fetch::SurfaceFetch>> {
        let hub_fetch = crate::gitwrite::fetcher_for_registry(&self.db, registry).await?;
        Ok(Box::new(CoreFetchAdapter(hub_fetch)))
    }
}
