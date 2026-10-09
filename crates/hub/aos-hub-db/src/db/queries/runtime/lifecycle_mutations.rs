//! Lifecycle mutations in the runtime capability.

use super::*;

impl Database {
    /// Attaches a provider upload identity to its durable creating record.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, a lifecycle conflict, or
    /// database failure.
    pub async fn attach_registry_publication_multipart_backend(
        &self,
        upload_id: &str,
        placement_id: i64,
        backend_upload_id: &str,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(backend_upload_id, "backend multipart upload id", 1024)?;
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE registry_publication_multipart_backends
             SET backend_upload_id = ?3, state = 'ready'
             WHERE upload_id = ?1 AND placement_id = ?2 AND state = 'creating'
               AND EXISTS (SELECT 1 FROM registry_publication_multipart_uploads
                 WHERE upload_id = ?1 AND state = 'active')",
                vals![upload_id, placement_id, backend_upload_id],
            )
            .expecting(1)])
            .await
    }

    /// Borrows the raw backend for migration and fault-injection fixtures.
    ///
    /// Production code uses typed database operations instead of raw SQL.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn fixture_backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    /// Open (creating and migrating if needed) the hub sqlite database.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or a migration fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open(path: &Path) -> Result<Self> {
        let path_str = path
            .to_str()
            .with_context(|| format!("hub database path is not valid UTF-8: {}", path.display()))?;
        let backend = SqlxBackend::connect_sqlite(path_str)
            .await
            .with_context(|| format!("opening hub database {}", path.display()))?;
        Self::with_backend(Box::new(backend)).await
    }

    /// Open an in-memory sqlite database (tests only).
    ///
    /// `serve --dev` does *not* use this: dev mode persists a regular
    /// `hub.db` under its `--root` directory (defaulting to `./.aos-hub`).
    ///
    /// # Errors
    ///
    /// Returns an error if a migration fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open_in_memory() -> Result<Self> {
        let backend = SqlxBackend::connect_sqlite(":memory:").await?;
        Self::with_backend(Box::new(backend)).await
    }

    /// Connect to a hub database by URL, dispatching on the scheme.
    ///
    /// The native self-hosting entry point (RFC-0004 "Database abstraction"):
    ///
    /// - `sqlite://<path>`, `file://<path>`, or a bare filesystem path → the
    ///   always-available sqlite [`SqlxBackend`].
    /// - `postgres://…` / `postgresql://…` → the postgres [`SqlxBackend`], when
    ///   the crate is built with the `postgres` feature (else an error).
    /// - `mysql://…` → the mysql [`SqlxBackend`], when built with the `mysql`
    ///   feature (else an error).
    ///
    /// In every case the schema is created and migrated to the current
    /// version before returning.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported scheme, a backend whose feature is
    /// not enabled, a connection failure, or a migration failure.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(url: &str) -> Result<Self> {
        if let Some(rest) = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
        {
            let _ = rest;
            #[cfg(feature = "postgres")]
            {
                let backend = SqlxBackend::connect_postgres(url).await?;
                return Self::with_backend(Box::new(backend)).await;
            }
            #[cfg(not(feature = "postgres"))]
            {
                bail!("postgres support not compiled in (build with --features postgres)");
            }
        }
        if let Some(rest) = url.strip_prefix("mysql://") {
            let _ = rest;
            #[cfg(feature = "mysql")]
            {
                let backend = SqlxBackend::connect_mysql(url).await?;
                return Self::with_backend(Box::new(backend)).await;
            }
            #[cfg(not(feature = "mysql"))]
            {
                bail!("mysql support not compiled in (build with --features mysql)");
            }
        }
        // sqlite:// or file:// or a bare path.
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file://"))
            .unwrap_or(url);
        if path.is_empty() || path == ":memory:" {
            return Self::open_in_memory().await;
        }
        Self::open(Path::new(path)).await
    }

    pub async fn with_backend(backend: Box<dyn Backend>) -> Result<Self> {
        let db = Self { backend };
        db.migrate().await?;
        Ok(db)
    }

    /// Wraps an already-migrated `backend` **without** running migrations.
    ///
    /// For read paths that open a fresh handle per request against a database
    /// some other path already migrated — notably the Cloudflare Worker, whose
    /// HubDb schema is owned by the Durable Object and which must not pay a
    /// migration round-trip on every read.
    /// Use
    /// [`with_backend`](Self::with_backend) when the caller owns the schema and
    /// should migrate it.
    #[must_use]
    pub fn attach(backend: Box<dyn Backend>) -> Self {
        Self { backend }
    }
}
