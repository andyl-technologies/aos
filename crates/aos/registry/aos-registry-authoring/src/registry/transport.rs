//! Immutable publication storage and bounded registry object uploads.

use anyhow::Result;
use aos_nix_cache::backend::CacheBackend;
use aos_registry_client::registry::transport::validate_relative_path;
use std::path::Path;

/// Adapts existing cache storage to immutable registry publication.
pub struct RegistryStorage<'a> {
    backend: &'a dyn CacheBackend,
}

impl<'a> RegistryStorage<'a> {
    /// Borrows a configured cache backend, preserving its authentication.
    pub fn new(backend: &'a dyn CacheBackend) -> Self {
        Self { backend }
    }

    /// Checks exact remote byte identity before skipping an immutable upload.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or failed remote identity checks.
    pub async fn object_matches(
        &self,
        relative: &str,
        sha256: &str,
        byte_size: u64,
    ) -> Result<bool> {
        validate_relative_path(relative)?;
        Ok(self
            .backend
            .static_file_identity(relative)
            .await?
            .is_some_and(|identity| identity.sha256 == sha256 && identity.byte_size == byte_size))
    }

    /// Publishes one immutable registry object through its cache backend.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, conflicting immutable bytes,
    /// unavailable conditional writes, or failed backend uploads.
    pub async fn put_object(&self, relative: &str, source: &Path, sha256: &str) -> Result<()> {
        validate_relative_path(relative)?;
        self.backend
            .put_immutable_file(relative, source, sha256)
            .await
    }
}

mod immutable;

/// Re-exports bounded immutable transfer and pointer-ordering contracts.
pub use immutable::{
    ImmutableUpload, ImmutableUploadPhase, pointer_upload_rank, upload_immutable_inventory,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn storage_reuses_exact_objects_and_refuses_immutable_conflicts() {
        use sha2::{Digest as _, Sha256};

        let root = tempfile::TempDir::new().unwrap();
        let source = root.path().join("source");
        std::fs::write(&source, b"first object").unwrap();
        let backend_root = root.path().join("origin");
        let origin = url::Url::from_directory_path(&backend_root).unwrap();
        let backend =
            aos_nix_cache::from_url(origin.as_str(), &aos_nix_cache::AuthOptions::default())
                .await
                .unwrap();
        let storage = RegistryStorage::new(backend.as_ref());
        let digest = hex::encode(Sha256::digest(b"first object"));

        storage
            .put_object("objects/item", &source, &digest)
            .await
            .unwrap();
        storage
            .put_object("objects/item", &source, &digest)
            .await
            .unwrap();
        assert!(
            storage
                .object_matches("objects/item", &digest, 12)
                .await
                .unwrap()
        );

        std::fs::write(&source, b"second object").unwrap();
        let conflicting_digest = hex::encode(Sha256::digest(b"second object"));
        assert!(
            storage
                .put_object("objects/item", &source, &conflicting_digest)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(backend_root.join("objects/item")).unwrap(),
            b"first object"
        );
    }
}
