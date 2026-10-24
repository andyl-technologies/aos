//! Checks authenticated path policy before a trusted read driver can persist content.
//!
//! Storage restrictions can refuse a read; they never grant Read, select history,
//! change effective properties or replace the repository's closing authorization.

use super::{AuthorizedSnapshot, Guard};
use crate::store::{Clock, Store, StoreFailure};
use std::sync::Arc;
use terrane_format::properties::{EffectiveProperties, RootLayer};

/// Restricts content routing according to the selected path's effective policy.
///
/// Trusted composition installs this alongside a driver with physical storage
/// constraints. The guard resolves signed root and graft properties using the
/// exact selected interpretation, including domain-dependent registry defaults.
pub trait ReadStoragePolicy: Send + Sync {
    /// Checks whether the actual storage route can honor the effective policy.
    ///
    /// # Errors
    /// Refuses unsupported storage or erasure requirements before content I/O.
    fn validate(&self, properties: &EffectiveProperties<'_>) -> Result<(), StoreFailure>;
}

impl<S, C> Guard<S, C> {
    /// Binds trusted storage restrictions without changing repository authority.
    ///
    /// Read-cache and driver adapters preserve this binding. No restriction can
    /// authorize a denied path or substitute host settings for signed policy.
    pub fn with_read_storage_policy(mut self, policy: Arc<dyn ReadStoragePolicy>) -> Self {
        self.read_storage_policy = Some(policy);
        self
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Resolves storage restrictions from the same immutable authenticated path.
    pub(crate) fn check_read_storage(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
    ) -> Result<(), StoreFailure> {
        let Some(policy) = &self.read_storage_policy else {
            return Ok(());
        };
        let path = snapshot
            .evidence
            .policy_path(path, self.config().min_chunk_size)?;
        let layers = path
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = snapshot
            .interpretation
            .resolve(&layers, self.defaults_for(&snapshot.evidence))?;
        policy.validate(&effective)
    }
}
