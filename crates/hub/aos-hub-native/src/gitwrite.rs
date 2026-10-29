//! Re-exports for the shared git-backed change-request flow.
//!
//! RFC-0004 Phase 5 (stage H3) relocated the git-backed configuration
//! change-request *write* flow into the shared core crate
//! ([`aos_hub_service::gitwrite`]) over the [`SurfaceWrite`] port, and the
//! read side ([`commit_log`], [`diff_config_files`], [`load_committed_file`],
//! [`unified_diff`], [`merge_command`], the `AOS-Change-Id` trailer parser) into
//! [`aos_hub_service::git`]. This module re-exports both so existing
//! `crate::gitwrite::…` call sites compile unchanged.
//!
//! [`SurfaceWrite`]: aos_hub_service::surface_write::SurfaceWrite

// The git-backed change-request write flow (relocated to core over the ports).
pub use aos_hub_service::gitwrite::propose_config_change;
pub use aos_hub_service::gitwrite::ProposeMeta;
pub use aos_hub_service::gitwrite::ProposedChange;

// The read side of the git-backed config/change-request flow (relocated to
// core's `git` module); re-exported so `crate::gitwrite::…` call sites in the
// console, indexer, and validation paths resolve unchanged.
pub use aos_hub_service::git::commit_log;
pub use aos_hub_service::git::diff_config_files;
pub use aos_hub_service::git::extract_change_id_trailer;
pub use aos_hub_service::git::load_committed_file;
pub use aos_hub_service::git::merge_command;
pub use aos_hub_service::git::unified_diff;
pub use aos_hub_service::git::LoggedCommit;
pub use aos_hub_service::git::CHANGE_ID_TRAILER;
pub use aos_hub_service::git::DIFFED_FILES;
