//! Re-exports for the shared git-backed change-request flow.
//!
//! RFC-0004 Phase 5 (stage H3) relocated the git-backed configuration
//! change-request *write* flow into the shared core crate
//! ([`aos_hub_core::gitwrite`]) over the [`SurfaceWrite`] port, and the
//! read side ([`commit_log`], [`diff_config_files`], [`load_committed_file`],
//! [`unified_diff`], [`merge_command`], the `AOS-Change-Id` trailer parser) into
//! [`aos_hub_core::git`]. This module re-exports both so existing
//! `crate::gitwrite::…` call sites compile unchanged.
//!
//! [`SurfaceWrite`]: aos_hub_core::surface_write::SurfaceWrite

// The git-backed change-request write flow (relocated to core over the ports).
pub use aos_hub_core::gitwrite::{propose_config_change, ProposeMeta, ProposedChange};

// The read side of the git-backed config/change-request flow (relocated to
// core's `git` module); re-exported so `crate::gitwrite::…` call sites in the
// console, indexer, and validation paths resolve unchanged.
pub use aos_hub_core::git::{
    commit_log, diff_config_files, extract_change_id_trailer, load_committed_file, merge_command,
    unified_diff, LoggedCommit, CHANGE_ID_TRAILER, DIFFED_FILES,
};
