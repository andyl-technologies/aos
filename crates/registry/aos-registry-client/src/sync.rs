//! Neutral outcomes and errors for verified registry metadata acquisition.
//!
//! The registry transport returns [`SyncResult`] after verification. Consumer
//! applications decide which configured registries to refresh and how to render
//! those results; this module contains no command orchestration or terminal UI.

use thiserror::Error;

/// Reports an invalid registry selection or a failed metadata refresh.
#[derive(Debug, Error)]
#[error("registry error: {message}")]
pub struct RegistrySyncError {
    /// Human-readable reason the refresh could not complete.
    pub message: String,
}

/// Summary of a sync operation against a single registry.
#[derive(Debug)]
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Total number of packages in the registry after sync.
    pub packages_count: usize,
    /// Number of packages added.
    pub packages_added: usize,
    /// Number of packages updated.
    pub packages_updated: usize,
    /// Number of packages removed.
    pub packages_removed: usize,
}

/// Explains a fail-closed registry trust or continuity refusal.
///
/// Applications can match these reasons to offer recovery guidance appropriate
/// to their interface without the acquisition library prescribing commands.
#[derive(Debug, Error)]
pub enum RegistryVerificationError {
    /// Signed metadata has no independently trusted verification key.
    #[error("registry '{registry}' requires signed metadata but no trusted key is available")]
    MissingTrustedKey {
        /// Registry whose metadata could not be authenticated.
        registry: String,
    },
    /// A verified registry head omits its required key roster.
    #[error(
        "registry '{registry}' requires signed metadata but commit {commit} has no keys.toml trust roster"
    )]
    MissingTrustRoster {
        /// Registry whose committed roster is missing.
        registry: String,
        /// Verified head at which the roster was required.
        commit: String,
    },
    /// A verified registry roster contains no active signing keys.
    #[error(
        "registry '{registry}' requires signed metadata but its keys.toml roster has no active keys at {commit}"
    )]
    EmptyTrustRoster {
        /// Registry whose committed roster is empty.
        registry: String,
        /// Verified head at which active keys were required.
        commit: String,
    },
    /// Channel metadata cannot be selected without a trusted signing key.
    #[error("channel tracking for '{registry}' requires a trusted key")]
    MissingChannelTrustedKey {
        /// Registry whose channel could not be authenticated.
        registry: String,
    },
    /// The selected commit does not descend from the verified continuity anchor.
    #[error(
        "registry downgrade detected: commit {selected_commit} is not a descendant of previously verified commit {previous_commit}; this could indicate a downgrade attack or a force-pushed registry"
    )]
    NonFastForward {
        /// Last independently verified continuity anchor.
        previous_commit: String,
        /// Commit refused because its ancestry breaks continuity.
        selected_commit: String,
    },
}
