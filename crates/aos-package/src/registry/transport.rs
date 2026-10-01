//! Shared registry byte transport and publication storage adapters.
//!
//! [`RegistryRead`] exposes the static origin's relative object namespace.
//! [`RegistryTransport`] supplies that interface with the existing `aos-net`
//! transfer engine, including local paths and `file://` origins. Git object
//! verification and channel trust remain in their respective registry modules.
//! [`RegistryStorage`] reuses cache backends for publication and exact identity
//! checks; an existence response alone never establishes immutable identity.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use aos_cache::backend::CacheBackend;
use aos_core::output::TransferProgress;
use aos_net::{TransferEngine, TransferEngineConfig, TransferRequest};
use aos_net::{TransferEvent, TransferObserver};
use async_trait::async_trait;

/// Selects the static object reader for HTTP and exported local Git surfaces.
///
/// An exported surface advertises Git references but omits Git's repository
/// configuration. Passing that surface to the native local transport would
/// interpret its SHA-256 object IDs using Git's SHA-1 default.
pub(crate) fn uses_static_git_reader(origin: &str) -> bool {
    let origin = origin.strip_prefix("git+").unwrap_or(origin);
    if origin.starts_with("http://") || origin.starts_with("https://") {
        return true;
    }
    let path = if origin.starts_with("file://") {
        let Ok(url) = url::Url::parse(origin) else {
            return false;
        };
        let Ok(path) = url.to_file_path() else {
            return false;
        };
        path
    } else if origin.contains("://") {
        return false;
    } else {
        std::path::PathBuf::from(origin)
    };

    !path.join("config").exists() && path.join("info/refs").is_file()
}

/// Reads objects in a registry origin's normalized relative namespace.
#[async_trait]
pub trait RegistryRead: Send + Sync {
    /// Reads an optional object, refusing bodies above `max_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed transfers, or oversized data.
    async fn read_optional(&self, relative: &str, max_bytes: u64) -> Result<Option<Vec<u8>>>;

    /// Streams an optional object into an atomically replaced destination.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed transfers, or local I/O errors.
    async fn download_optional(
        &self,
        relative: &str,
        destination: &Path,
        progress: Option<&TransferProgress>,
    ) -> Result<bool>;
}

/// Shares the existing transfer engine across registry object reads.
#[derive(Clone)]
pub struct RegistryTransport {
    origin: url::Url,
    head_url: Option<url::Url>,
    engine: Arc<TransferEngine>,
}

impl RegistryTransport {
    /// Creates a reader for an HTTP, file, S3, or SFTP origin or local path.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed origins or unsupported URL schemes.
    pub fn new(origin: &str) -> Result<Self> {
        let origin = origin.strip_prefix("git+").unwrap_or(origin);
        let mut parsed = if origin.contains("://") {
            url::Url::parse(origin).context("parsing registry origin")?
        } else {
            let path = std::path::absolute(origin).context("resolving registry origin path")?;
            url::Url::from_directory_path(path)
                .map_err(|_| anyhow::anyhow!("registry origin path is not a file URL"))?
        };
        if !matches!(
            parsed.scheme(),
            "http" | "https" | "file" | "s3" | "sftp" | "ssh"
        ) {
            bail!("unsupported static registry transport: {}", parsed.scheme());
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            bail!("registry origin must not contain a query or fragment");
        }
        let mut head_url = None;
        if parsed.scheme() == "file" {
            let path = parsed
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid local registry URL"))?;
            if let Ok(repository) = git2::Repository::open(&path) {
                // Linked worktrees have their own HEAD but share the registry's
                // object and partition namespace in the common Git directory.
                head_url = Some(
                    url::Url::from_file_path(repository.path().join("HEAD"))
                        .map_err(|_| anyhow::anyhow!("invalid registry Git HEAD path"))?,
                );
                parsed = url::Url::from_directory_path(repository.commondir())
                    .map_err(|_| anyhow::anyhow!("invalid registry Git directory"))?;
            }
        }
        let path = format!("{}/", parsed.path().trim_end_matches('/'));
        parsed.set_path(&path);

        Ok(Self {
            origin: parsed,
            head_url,
            engine: Arc::new(TransferEngine::new(TransferEngineConfig::default())),
        })
    }

    /// Uses a caller-owned engine with its existing credentials and policy.
    pub fn with_engine(mut self, engine: Arc<TransferEngine>) -> Self {
        self.engine = engine;
        self
    }

    /// Discovers the default channel from the origin's symbolic `HEAD`.
    ///
    /// Detached or malformed HEAD files cannot select draft commits.
    ///
    /// # Errors
    ///
    /// Returns an error when HEAD is absent, malformed, detached, or names an
    /// invalid channel, or when the origin cannot be read.
    pub async fn default_channel(&self) -> Result<String> {
        let bytes = self
            .read_optional("HEAD", 4096)
            .await?
            .context("registry origin does not advertise HEAD")?;
        let content = std::str::from_utf8(&bytes).context("registry HEAD is not UTF-8")?;
        let channel = aos_registry_surface::refs::parse_head(content)
            .context("registry HEAD must be a symbolic reference to a release channel")?;
        crate::types::validate_channel_name(&channel)
            .context("registry HEAD names an invalid default channel")?;
        Ok(channel)
    }

    fn object_url(&self, relative: &str) -> Result<String> {
        validate_relative_path(relative)?;
        if relative == "HEAD" {
            if let Some(head_url) = &self.head_url {
                return Ok(head_url.to_string());
            }
        }
        // Append individual segments so '?' and '#' remain literal filename
        // bytes rather than changing the origin's query or fragment.
        let mut url = self.origin.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("registry origin cannot contain relative objects"))?
            .pop_if_empty()
            .extend(relative.split('/'));
        Ok(url.to_string())
    }
}

#[async_trait]
impl RegistryRead for RegistryTransport {
    async fn read_optional(&self, relative: &str, max_bytes: u64) -> Result<Option<Vec<u8>>> {
        let url = self.object_url(relative)?;
        let mut request = TransferRequest::get(&url);
        request.maximum_bytes = Some(max_bytes);
        let response = match self.engine.execute(request).await {
            Ok(response) => response,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("reading registry object {relative}"));
            }
        };
        let bytes = response.body.context("registry read returned no body")?;
        Ok(Some(bytes))
    }

    async fn download_optional(
        &self,
        relative: &str,
        destination: &Path,
        progress: Option<&TransferProgress>,
    ) -> Result<bool> {
        let url = self.object_url(relative)?;
        let parent = destination
            .parent()
            .context("registry download destination has no parent")?;
        tokio::fs::create_dir_all(parent).await?;
        let temporary = tempfile::Builder::new()
            .prefix(".registry-download-")
            .tempfile_in(parent)?
            .into_temp_path();
        let request = TransferRequest::get_to_file(&url, temporary.to_path_buf());
        let observer = RegistryDownloadProgress {
            progress,
            previous: std::sync::atomic::AtomicU64::new(0),
        };
        match self.engine.execute_observed(request, &observer).await {
            Ok(_) => {}
            Err(error) if is_not_found(&error) => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("downloading registry object {relative}"));
            }
        };
        temporary
            .persist(destination)
            .map_err(|error| anyhow::anyhow!("installing registry download: {error}"))?;
        Ok(true)
    }
}

/// Adapts existing cache storage to immutable registry publication.
pub struct RegistryStorage<'a> {
    backend: &'a dyn CacheBackend,
}

impl<'a> RegistryStorage<'a> {
    /// Borrows a configured cache backend, preserving its authentication.
    pub fn new(backend: &'a dyn CacheBackend) -> Self {
        Self { backend }
    }

    /// Returns the underlying backend for conditional mutable writes.
    pub fn backend(&self) -> &'a dyn CacheBackend {
        self.backend
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

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<aos_net::protocol::http::HttpStatusError>()
        .is_some_and(|response| response.status == 404)
        || error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
}

struct RegistryDownloadProgress<'a> {
    progress: Option<&'a TransferProgress>,
    previous: std::sync::atomic::AtomicU64,
}

impl TransferObserver for RegistryDownloadProgress<'_> {
    fn observe(&self, event: TransferEvent<'_>) {
        if let TransferEvent::Progress {
            transferred_bytes, ..
        } = event
        {
            let previous = self
                .previous
                .swap(transferred_bytes, std::sync::atomic::Ordering::Relaxed);
            if let Some(progress) = self.progress {
                progress.inc(transferred_bytes.saturating_sub(previous));
            }
        }
    }
}

fn validate_relative_path(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains('\0')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("registry object path must be a normalized relative path: {relative:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_paths_and_file_urls_read_the_same_namespace() {
        let root = tempfile::TempDir::new().unwrap();
        std::fs::write(root.path().join("HEAD"), b"ref: refs/heads/stable\n").unwrap();
        std::fs::write(root.path().join("object"), b"registry bytes").unwrap();
        let file_url = url::Url::from_directory_path(root.path()).unwrap();

        for origin in [root.path().to_str().unwrap(), file_url.as_str()] {
            let reader = RegistryTransport::new(origin).unwrap();
            assert_eq!(reader.default_channel().await.unwrap(), "stable");
            assert_eq!(
                reader.read_optional("object", 64).await.unwrap().unwrap(),
                b"registry bytes"
            );
            assert!(reader.read_optional("missing", 64).await.unwrap().is_none());
            assert!(reader.read_optional("object", 3).await.is_err());
            assert!(reader.read_optional("../HEAD", 64).await.is_err());

            let destination = root.path().join("downloaded");
            assert!(
                reader
                    .download_optional("object", &destination, None)
                    .await
                    .unwrap()
            );
            assert_eq!(std::fs::read(destination).unwrap(), b"registry bytes");
        }
    }

    #[tokio::test]
    async fn default_channel_rejects_detached_and_malformed_head() {
        let root = tempfile::TempDir::new().unwrap();
        let reader = RegistryTransport::new(root.path().to_str().unwrap()).unwrap();
        for head in [
            "a".repeat(64),
            "ref: refs/heads/../draft".into(),
            "ref: refs/heads/stable\nref: refs/heads/draft".into(),
        ] {
            std::fs::write(root.path().join("HEAD"), head).unwrap();
            assert!(reader.default_channel().await.is_err());
        }
    }

    #[tokio::test]
    async fn unsuccessful_http_reads_keep_diagnostics_within_the_byte_limit() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        for maximum in [32, 1024 * 1024] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                stream.read(&mut request).await.unwrap();
                let body = vec![b'x'; 64 * 1024];
                let headers = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                // The bounded reader may close before this complete response
                // is written; that is the behavior this fixture exercises.
                let _ = stream.write_all(&body).await;
            });
            let reader = RegistryTransport::new(&format!("http://{address}")).unwrap();

            let error = reader.read_optional("object", maximum).await.unwrap_err();
            let response = error
                .downcast_ref::<aos_net::protocol::http::HttpStatusError>()
                .unwrap();

            assert_eq!(response.status, 403);
            assert_eq!(response.body.len(), maximum.min(8192) as usize);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn linked_worktree_reads_its_head_and_shared_registry_namespace() {
        let root = tempfile::TempDir::new().unwrap();
        let source = root.path().join("source");
        let mut options = git2::RepositoryInitOptions::new();
        options
            .object_format(git2::ObjectFormat::Sha256)
            .initial_head("stable");
        let repository = git2::Repository::init_opts(&source, &options).unwrap();
        let tree = repository.treebuilder(None).unwrap().write().unwrap();
        let signature = git2::Signature::now("Fixture", "fixture@example.com").unwrap();
        repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "initial",
                &repository.find_tree(tree).unwrap(),
                &[],
            )
            .unwrap();
        let linked = root.path().join("linked");
        repository.worktree("linked", &linked, None).unwrap();
        let partition = repository.path().join("channels/linked/00");
        std::fs::create_dir_all(partition.parent().unwrap()).unwrap();
        std::fs::write(partition, b"shared partition bytes").unwrap();

        let reader = RegistryTransport::new(linked.to_str().unwrap()).unwrap();

        assert_eq!(reader.default_channel().await.unwrap(), "linked");
        assert_eq!(
            reader
                .read_optional("channels/linked/00", 64)
                .await
                .unwrap()
                .unwrap(),
            b"shared partition bytes"
        );
    }

    #[tokio::test]
    async fn storage_reuses_exact_objects_and_refuses_immutable_conflicts() {
        use sha2::{Digest as _, Sha256};

        let root = tempfile::TempDir::new().unwrap();
        let source = root.path().join("source");
        std::fs::write(&source, b"first object").unwrap();
        let backend_root = root.path().join("origin");
        let origin = url::Url::from_directory_path(&backend_root).unwrap();
        let backend = aos_cache::from_url(origin.as_str(), &aos_cache::AuthOptions::default())
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

mod immutable;

/// Re-exports bounded immutable transfer and pointer-ordering contracts.
pub use immutable::{
    ImmutableUpload, ImmutableUploadPhase, pointer_upload_rank, upload_immutable_inventory,
};
