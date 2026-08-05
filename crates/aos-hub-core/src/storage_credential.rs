//! Purpose- and generation-bound storage credential resolution.

use std::sync::Arc;

use anyhow::{Context as _, Result};

use crate::backend::BackendBounds;
use crate::db::Database;
use crate::secret_version::{verify_secret_fingerprint, SecretVersionResolver};

/// Plaintext credential material confined to a runtime adapter.
pub struct ResolvedStorageCredential {
    generation: i64,
    secret: crate::secret_version::ResolvedSecretVersion,
}

impl ResolvedStorageCredential {
    /// Returns the immutable credential generation that was resolved.
    #[must_use]
    pub const fn generation(&self) -> i64 {
        self.generation
    }

    /// Borrows the plaintext for immediate provider use.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider value is not UTF-8.
    pub fn secret(&self) -> Result<&str> {
        self.secret.expose_utf8()
    }
}

/// Resolves immutable secret-version references without exposing them publicly.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait StorageCredentialResolver: BackendBounds {
    /// Resolves one exact validated purpose and generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is absent or invalid, secret
    /// resolution fails, or the database cannot be read.
    async fn resolve_exact(
        &self,
        storage_binding_id: i64,
        purpose: &str,
        generation: i64,
    ) -> Result<ResolvedStorageCredential>;

    /// Resolves the current validated generation for one purpose.
    ///
    /// # Errors
    ///
    /// Returns an error when the purpose has no current valid generation,
    /// secret resolution fails, or the database cannot be read.
    async fn resolve_current(
        &self,
        storage_binding_id: i64,
        purpose: &str,
    ) -> Result<ResolvedStorageCredential>;
}

/// Database-backed resolver shared by native and Worker storage adapters.
pub struct DatabaseStorageCredentialResolver {
    db: Arc<Database>,
    secrets: Arc<dyn SecretVersionResolver>,
}

impl DatabaseStorageCredentialResolver {
    /// Creates a resolver over the authoritative credential heads and revisions.
    #[must_use]
    pub fn new(db: Arc<Database>, secrets: Arc<dyn SecretVersionResolver>) -> Self {
        Self { db, secrets }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl StorageCredentialResolver for DatabaseStorageCredentialResolver {
    async fn resolve_exact(
        &self,
        storage_binding_id: i64,
        purpose: &str,
        generation: i64,
    ) -> Result<ResolvedStorageCredential> {
        let revision = self
            .db
            .storage_binding_credential_revision(storage_binding_id, purpose, generation)
            .await?
            .context("storage credential revision does not exist")?;
        anyhow::ensure!(
            revision.validation_state == "valid",
            "storage credential revision is not valid"
        );
        let secret = self
            .secrets
            .resolve(&revision.secret_version_ref)
            .await
            .context("resolving immutable storage credential version")?;
        verify_secret_fingerprint(&secret, &revision.credential_fingerprint)?;
        Ok(ResolvedStorageCredential { generation, secret })
    }

    async fn resolve_current(
        &self,
        storage_binding_id: i64,
        purpose: &str,
    ) -> Result<ResolvedStorageCredential> {
        let revision = self
            .db
            .current_storage_binding_credential(storage_binding_id, purpose)
            .await?
            .context("storage credential purpose has no current generation")?;
        self.resolve_exact(storage_binding_id, purpose, revision.generation)
            .await
    }
}
