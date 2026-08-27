//! Page composition, re-exported from [`aos_hub_core::web::browse_pages`].
//!
//! RFC-0004 Phase 5 (console-dedup stage G) moved the rich, session-aware browse
//! renderer — the instance home, registry home, the searchable/sortable package
//! index and data-rich package detail, the channel partition grid and bucket
//! calculator, the releases list, and the per-registry health page — into the
//! shared, wasm-clean core crate so the Cloudflare Worker serves the *identical*
//! branded/searchable/session-aware browse the native hub does.
//!
//! The plain data types, enums, and constants ([`SortColumn`], [`SortDir`],
//! [`PackageBrowse`], [`ResolvedDependency`], [`PackageClosure`],
//! [`PACKAGES_PER_PAGE`], [`LIST_PER_PAGE`], [`channel_grid_pre`]) are re-exported
//! unchanged. The page-building functions take an explicit
//! [`SessionIndicator`](aos_hub_core::web::console_render::SessionIndicator)
//! in core (so the renderer stays task-local-free and wasm-clean); the thin
//! wrappers below preserve the hub's historical signatures by supplying the
//! current request's indicator from the native session middleware's task-local
//! ([`current_session_indicator`](crate::ui::render::current_session_indicator)),
//! so every `crate::ui::pages::…` call site in the hub compiles unchanged.

use std::time::Instant;

pub use aos_hub_core::web::browse_pages::{
    channel_grid_pre, ImageBrowse, PackageBrowse, PackageClosure, ResolvedDependency,
    RouteHealthRow, SortColumn, SortDir, LIST_PER_PAGE, PACKAGES_PER_PAGE,
};

use aos_hub_core::db::{
    CacheProbeRow, ChannelSummary, IndexStatus, IndexedSystemImage, PackageDetail, PackageRow,
    RegistryRecord, ReleaseRow, RepairJobRow, ValidationRunRow,
};
use aos_hub_core::stack::StackNode;

use crate::ui::render::current_session_indicator;

/// The instance home: every registered registry and its index state.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::instance_home`], supplying the
/// request's masthead identity from the session middleware's task-local.
#[must_use]
pub fn instance_home(
    rows: &[(RegistryRecord, Option<IndexStatus>)],
    query: Option<&str>,
    page_number: usize,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::instance_home(
        rows,
        query,
        page_number,
        started,
        &current_session_indicator(),
    )
}

/// The registry home: trust anchors, channels, caches, package count, setup.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::registry_home`].
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn registry_home(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    packages: &[PackageRow],
    caches: &[(String, u32)],
    roster: &[(String, String, String)],
    validations: &[ValidationRunRow],
    external_url: &str,
    manage_link: bool,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::registry_home(
        registry,
        status,
        channels,
        packages.len(),
        caches,
        roster,
        validations,
        Some(external_url),
        manage_link,
        started,
        &current_session_indicator(),
    )
}

/// The package index page: one pre-filtered, pre-sorted, pre-sliced page.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::package_index`].
#[must_use]
pub fn package_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    rows: &[PackageRow],
    browse: &PackageBrowse<'_>,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::package_index(
        registry,
        status,
        rows,
        browse,
        started,
        &current_session_indicator(),
    )
}

/// One package's detail page — the data-rich closure browser.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::package_page`].
#[must_use]
pub fn package_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    detail: &PackageDetail,
    closure: &PackageClosure,
    external_url: &str,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::package_page(
        registry,
        status,
        detail,
        closure,
        external_url,
        started,
        &current_session_indicator(),
    )
}

/// The channel page with the 16×16 partition grid and bucket calculator.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::channel_page`].
#[must_use]
pub fn channel_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channel: &ChannelSummary,
    floor: Option<&str>,
    bucket_query: Option<&str>,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::channel_page(
        registry,
        status,
        channel,
        floor,
        bucket_query,
        started,
        &current_session_indicator(),
    )
}

/// The channels index page.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::channels_index`].
#[must_use]
pub fn channels_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    page_number: usize,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::channels_index(
        registry,
        status,
        channels,
        page_number,
        started,
        &current_session_indicator(),
    )
}

/// The signed system-image catalog with direct disk-download actions.
#[must_use]
pub fn images_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    images: &[IndexedSystemImage],
    channels: &[ChannelSummary],
    download_base: Option<&str>,
    browse: &ImageBrowse<'_>,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::images_page(
        registry,
        status,
        images,
        channels,
        download_base,
        browse,
        started,
        &current_session_indicator(),
    )
}

/// The releases page: every verified signed tag, newest first by semver.
///
/// Native-hub shim over
/// [`aos_hub_core::web::browse_pages::releases_page`].
#[must_use]
pub fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    releases: &[ReleaseRow],
    page_number: usize,
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::releases_page(
        registry,
        status,
        releases,
        page_number,
        started,
        &current_session_indicator(),
    )
}

/// The health page: the cache × coverage validation matrix and drill-downs.
///
/// Native-hub shim over [`aos_hub_core::web::browse_pages::health_page`].
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn health_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    runs: &[(ValidationRunRow, Vec<String>, Vec<String>)],
    stack: Option<&StackNode>,
    cache_probes: &[CacheProbeRow],
    repair_jobs: &[RepairJobRow],
    routes: &[RouteHealthRow],
    started: Instant,
) -> String {
    aos_hub_core::web::browse_pages::health_page(
        registry,
        status,
        runs,
        stack,
        cache_probes,
        repair_jobs,
        routes,
        started,
        &current_session_indicator(),
    )
}
