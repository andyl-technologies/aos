//! MEMO-2 applied-package boundary memo options for `TreeWalkOptions`.
//!
//! Governs the (default-off, advisory) applied-package boundary memo: whether
//! the evaluator builds the source-Merkle
//! [`BoundaryIdentityMap`](crate::cache::boundary_identity::BoundaryIdentityMap)
//! for a package set and recognizes package-boundary applications at the apply
//! seam. This increment wires recognition and a validation counter only — no
//! record store, no replay.
//!
//! Configured from the environment (read once at [`TreeWalkOptions`]
//! construction), so a builder measurement run needs only:
//!
//! ```text
//! AOS_NIX_BOUNDARY_MEMO=1               # master switch (default off)
//! AOS_NIX_BOUNDARY_PKGS_ROOT=/repo/pkgs # the package-set root to key
//! # optional; derived from the pkgs root when unset:
//! AOS_NIX_BOUNDARY_FRAMEWORK_ROOTS=/repo/lib:/repo/stdenv:/repo/pkgs/build-support
//! ```

use std::path::PathBuf;

use super::*;

/// Applied-package boundary memo configuration.
///
/// Disabled unless `AOS_NIX_BOUNDARY_MEMO` is set to a non-`0` value and a
/// package-set root is configured. Immutable after construction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundaryMemoOptions {
    /// Master switch (`AOS_NIX_BOUNDARY_MEMO`).
    pub(crate) enabled: bool,
    /// The package-set root to key (`AOS_NIX_BOUNDARY_PKGS_ROOT`), i.e. the
    /// `pkgs/` directory `discoverPackages` scans.
    pub(crate) pkgs_root: Option<PathBuf>,
    /// Framework-source roots folded into `frameworkIdentity`
    /// (`AOS_NIX_BOUNDARY_FRAMEWORK_ROOTS`, `:`-separated). Derived from the
    /// package-set root when unset.
    pub(crate) framework_roots: Vec<PathBuf>,
}

impl BoundaryMemoOptions {
    /// Reads the boundary-memo configuration from the environment.
    ///
    /// Returns a disabled configuration unless `AOS_NIX_BOUNDARY_MEMO` is set to
    /// a value other than `0`. Framework roots default to `lib/`, `stdenv/`, and
    /// `pkgs/build-support/` resolved relative to the package-set root's parent.
    pub(crate) fn from_env() -> Self {
        let enabled = std::env::var_os("AOS_NIX_BOUNDARY_MEMO")
            .is_some_and(|value| value != "0" && !value.is_empty());
        if !enabled {
            return Self::default();
        }
        let pkgs_root = std::env::var_os("AOS_NIX_BOUNDARY_PKGS_ROOT").map(PathBuf::from);
        let framework_roots = match std::env::var_os("AOS_NIX_BOUNDARY_FRAMEWORK_ROOTS") {
            Some(raw) => std::env::split_paths(&raw).collect(),
            None => pkgs_root
                .as_ref()
                .map(|root| default_framework_roots(root))
                .unwrap_or_default(),
        };
        Self {
            enabled,
            pkgs_root,
            framework_roots,
        }
    }
}

/// Derives the default framework-source roots from a package-set root: the
/// sibling `lib/` and `stdenv/` trees plus `build-support/` under the root.
fn default_framework_roots(pkgs_root: &std::path::Path) -> Vec<PathBuf> {
    let repo_root = pkgs_root.parent().map(std::path::Path::to_path_buf);
    let mut roots = Vec::new();
    if let Some(repo) = &repo_root {
        roots.push(repo.join("lib"));
        roots.push(repo.join("stdenv"));
    }
    roots.push(pkgs_root.join("build-support"));
    roots
}

impl TreeWalkOptions {
    /// Returns the applied-package boundary memo configuration.
    pub(crate) fn boundary_memo(&self) -> &BoundaryMemoOptions {
        &self.boundary_memo
    }

    /// Returns whether the applied-package boundary memo is enabled and has a
    /// package-set root to key.
    pub(crate) fn boundary_memo_active(&self) -> bool {
        self.boundary_memo.enabled && self.boundary_memo.pkgs_root.is_some()
    }

    /// Overrides the boundary-memo configuration (tests and explicit callers).
    #[cfg(test)]
    pub(crate) fn set_boundary_memo(&mut self, boundary_memo: BoundaryMemoOptions) {
        self.boundary_memo = boundary_memo;
    }
}
