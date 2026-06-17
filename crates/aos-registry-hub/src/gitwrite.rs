//! Resolving a registry's read surface, and re-exporting the shared git-backed
//! change-request flow.
//!
//! RFC-0004 Phase 5 (stage H3) relocated the git-backed configuration
//! change-request *write* flow into the shared core crate
//! ([`aos_registry_core::gitwrite`]) over the [`SurfaceWrite`] port, and the
//! read side ([`commit_log`], [`diff_config_files`], [`load_committed_file`],
//! [`unified_diff`], [`merge_command`], the `AOS-Change-Id` trailer parser) into
//! [`aos_registry_core::git`]. This module re-exports both so existing
//! `crate::gitwrite::…` call sites compile unchanged.
//!
//! The one piece that stays native is [`fetcher_for_registry`]: resolving a
//! registry's *read* surface picks between the filesystem
//! ([`LocalFsFetch`](crate::fetch::LocalFsFetch)) and HTTP transports, neither
//! of which is wasm-clean, so it cannot move to core. The merge/read paths and
//! the native [`HubSurfaceProvider`](crate::coreports::HubSurfaceProvider) call
//! it.
//!
//! [`SurfaceWrite`]: aos_registry_core::surface_write::SurfaceWrite

use anyhow::Result;

use aos_registry_core::db::{Database, RegistryRecord};

// The git-backed change-request write flow (relocated to core over the ports).
pub use aos_registry_core::gitwrite::{propose_config_change, ProposedChange};

// The read side of the git-backed config/change-request flow (relocated to
// core's `git` module); re-exported so `crate::gitwrite::…` call sites in the
// console, indexer, and validation paths resolve unchanged.
pub use aos_registry_core::git::{
    commit_log, diff_config_files, extract_change_id_trailer, load_committed_file, merge_command,
    unified_diff, LoggedCommit, CHANGE_ID_TRAILER, DIFFED_FILES,
};

/// Build a surface fetcher for a registry's committed git surface.
///
/// A managed registry (one with a storage-binding root) is read from that root
/// over the filesystem; a registration-only registry is read through its
/// `source_url` (`file://`, a bare path, or `http(s)://`).
///
/// This resolves the registry's *read* surface and stays native because it
/// dispatches over the filesystem/HTTP transports
/// ([`crate::fetch::LocalFsFetch`], [`crate::fetch::fetch_for_url`]), which do
/// not compile to wasm.
///
/// # Errors
///
/// Returns an error on database failure resolving the surface root, or for an
/// unsupported `source_url` scheme.
pub async fn fetcher_for_registry(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Box<dyn crate::fetch::SurfaceFetch>> {
    if let Some(root) = db.registry_surface_root(registry.id).await? {
        return Ok(Box::new(crate::fetch::LocalFsFetch::new(root)));
    }
    crate::fetch::fetch_for_url(&registry.source_url).await
}
