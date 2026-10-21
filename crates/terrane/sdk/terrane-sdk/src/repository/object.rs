//! Composes trusted object presentation after complete repository authorization.
//!
//! A provider supplies actual prepared plaintext, not history or authorization.
//! The repository first performs its original guarded read, compares every
//! prepared byte with that verified result, and rechecks current path authority
//! before returning any provider bytes. The frozen store interface is unchanged.

use super::{Error, Repository};
use crate::store::{Clock, CorruptSubject, LocalFs, Store, StoreErrorKind, StoreFailure};
use std::sync::Arc;
use terrane_format::{
    identity::{Identity, IdentityKind, TERRANE_V1},
    tree_format::ContentRef,
};

/// Supplies actual host object plaintext after the repository's guarded content read.
///
/// Trusted host composition binds this provider to the same disclosure domain
/// and immutable profile as the original repository. It grants no authorization,
/// reference, provenance or readiness authority. Implementations retain real
/// backing and funding through reads and finish their physical cleanup before
/// returning; cancellation must leave accepted work with its original owner.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait ObjectPresentation: Send + Sync {
    /// Reads an actual prepared object with the exact expected plaintext size.
    ///
    /// # Errors
    /// Refuses unavailable or invalid backing, policy violations, size mismatch,
    /// exhausted bounds, and failed preparation or durable cleanup.
    async fn read(&self, identity: &Identity, size: usize) -> Result<Vec<u8>, StoreFailure>;
}

impl<S: Store, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Binds trusted same-domain object presentation without granting read authority.
    ///
    /// Every read still performs the original complete guarded content checks.
    /// Provider failures are terminal; successful bytes must exactly match that
    /// verified plaintext before a final current-authority check. Configuration
    /// cannot supply a provider, readiness or an authorization bypass.
    pub fn with_object_presentation(mut self, provider: Arc<dyn ObjectPresentation>) -> Self {
        self.object_presentation = Some(provider);
        self
    }

    pub(super) async fn present_object(
        &self,
        content: ContentRef,
        verified: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let Some(provider) = &self.object_presentation else {
            return Ok(verified);
        };
        let (kind, digest) = match content {
            ContentRef::Inline(digest) => (IdentityKind::Chunk, digest),
            ContentRef::Manifest(digest) => (IdentityKind::Manifest, digest),
        };
        let identity = TERRANE_V1.from_digest(kind, &digest)?;
        let actual = provider.read(&identity, verified.len()).await?;
        if actual != verified {
            return Err(
                StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::Identity(identity)))
                    .into(),
            );
        }
        Ok(actual)
    }
}
