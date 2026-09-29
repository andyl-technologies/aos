//! Binds portable HTTP, timers, and filesystem contracts to the native runtime.

use super::{ByteRange, Clock, HttpClient, HttpError, HttpRequest, HttpResponse, LocalFs};
use std::time::{Duration, SystemTime};

/// Binds portable HTTP transport to the native runtime (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Debug)]
pub struct TokioHttpClient {
    client: reqwest::Client,
}

#[cfg(feature = "tokio")]
impl TokioHttpClient {
    /// Wraps an already configured native HTTP client.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl HttpClient for TokioHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
        let mut outgoing = self.client.request(method, request.url);

        for (name, value) in request.headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
            let value = reqwest::header::HeaderValue::from_bytes(&value)
                .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
            outgoing = outgoing.header(name, value);
        }

        let response = outgoing
            .body(request.body)
            .send()
            .await
            .map_err(|source| HttpError::Unavailable(Box::new(source)))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|source| HttpError::Unavailable(Box::new(source)))?;

        Ok(HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

/// Binds portable wall-clock reads to the native host (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioClock;

#[cfg(feature = "tokio")]
#[allow(
    clippy::disallowed_methods,
    reason = "The native clock binding is the injection boundary for host time."
)]
#[async_trait::async_trait]
impl Clock for TokioClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Duration {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

        ORIGIN.get_or_init(std::time::Instant::now).elapsed()
    }

    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        if std::time::Instant::now().checked_add(duration).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "timer duration overflow",
            ));
        }
        tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
        tokio::time::sleep(duration).await;
        Ok(())
    }
}

/// Retains native file exclusion until dropped or the process terminates.
///
/// The descriptor stays private so callers cannot explicitly unlock it while
/// a CAS write still holds the guard. Closing the descriptor releases the lock.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct TokioFileLock {
    _file: std::fs::File,
}

/// Binds portable file operations to the native runtime (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioLocalFs;

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl LocalFs for TokioLocalFs {
    type Lock = TokioFileLock;

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        // Entropy-device I/O belongs to this native binding, and must not
        // block an executor thread or escape into portable pack code.
        tokio::task::spawn_blocking(move || {
            use std::io::Read;

            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(std::io::Error::other)?;
            bytes.resize(length, 0);
            std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            Ok(bytes)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    async fn lock_exclusive(&self, path: &std::path::Path) -> std::io::Result<Self::Lock> {
        let path = path.to_owned();

        // Waiting for the kernel lock must not block an async executor thread.
        tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            file.lock()?;

            Ok(TokioFileLock { _file: file })
        })
        .await
        .map_err(std::io::Error::other)?
    }

    async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(path).await
    }

    async fn read_range(
        &self,
        path: &std::path::Path,
        range: ByteRange,
    ) -> std::io::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let length = usize::try_from(range.length)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        bytes.resize(length, 0);

        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(range.start)).await?;
        file.read_exact(&mut bytes).await?;
        Ok(bytes)
    }

    async fn write_new(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await
    }

    async fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::create_dir_all(path).await
    }

    async fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            paths.push(entry.path());
        }
        Ok(paths)
    }

    async fn metadata(&self, path: &std::path::Path) -> std::io::Result<std::fs::Metadata> {
        tokio::fs::metadata(path).await
    }

    async fn symlink_metadata(&self, path: &std::path::Path) -> std::io::Result<std::fs::Metadata> {
        tokio::fs::symlink_metadata(path).await
    }

    async fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::remove_file(path).await
    }

    async fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::rename(from, to).await
    }

    async fn rename_no_replace(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
    ) -> std::io::Result<()> {
        tokio::fs::hard_link(from, to).await?;
        tokio::fs::remove_file(from).await
    }

    async fn sync_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::File::open(path).await?.sync_all().await
    }

    async fn sync_directory(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::File::open(path).await?.sync_all().await
    }

    async fn read_nofollow(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        #[cfg(not(unix))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nofollow open unavailable",
        ));

        let mut file = options.open(path).await?;
        if !file.metadata().await?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
        let mut bytes = Vec::new();

        file.read_to_end(&mut bytes).await?;
        Ok(bytes)
    }

    async fn read_link(&self, path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        tokio::fs::read_link(path).await
    }

    async fn symlink(
        &self,
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> std::io::Result<()> {
        let target = target.to_owned();
        let link = link.to_owned();
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, link)
            }
            #[cfg(not(unix))]
            {
                let _ = (target, link);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "symlink unavailable",
                ))
            }
        })
        .await
        .map_err(std::io::Error::other)?
    }

    async fn hard_link(
        &self,
        existing: &std::path::Path,
        new: &std::path::Path,
    ) -> std::io::Result<()> {
        tokio::fs::hard_link(existing, new).await
    }

    async fn set_permissions(
        &self,
        path: &std::path::Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        tokio::fs::set_permissions(path, permissions).await
    }

    async fn list_xattrs(
        &self,
        path: &std::path::Path,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || xattr::list(path).map(Iterator::collect))
            .await
            .map_err(std::io::Error::other)?
    }

    async fn get_xattr(
        &self,
        path: &std::path::Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let path = path.to_owned();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || xattr::get(path, name))
            .await
            .map_err(std::io::Error::other)?
    }

    async fn set_xattr(
        &self,
        path: &std::path::Path,
        name: &std::ffi::OsStr,
        value: &[u8],
    ) -> std::io::Result<()> {
        let path = path.to_owned();
        let name = name.to_owned();
        let value = value.to_vec();
        tokio::task::spawn_blocking(move || xattr::set(path, name, &value))
            .await
            .map_err(std::io::Error::other)?
    }

    async fn create_dir_new(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::create_dir(path).await
    }

    async fn remove_dir(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::remove_dir(path).await
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Test setup and assertions intentionally panic on failure."
)]
mod tests {
    use super::*;

    #[test]
    fn native_timer_waits_and_rejects_duration_overflow() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let clock = TokioClock;
            let start = clock.monotonic();
            let duration = Duration::from_millis(2);
            clock.sleep(duration).await.unwrap();
            assert!(clock.monotonic() - start >= duration);
            assert_eq!(
                clock.sleep(Duration::MAX).await.unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn native_metadata_preserves_links_permissions_and_nofollow_attributes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let fs = TokioLocalFs;
            let random = fs.random_bytes(16).await.unwrap();
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let root = std::path::PathBuf::from(format!("/tmp/terrane-native-metadata-{suffix}"));
            fs.create_dir_new(&root).await.unwrap();
            assert_eq!(
                fs.create_dir_new(&root).await.unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists
            );
            let source = root.join("source");
            let alias = root.join("alias");
            let link = root.join("link");

            fs.write_new(&source, b"verified file").await.unwrap();
            fs.set_permissions(&source, std::fs::Permissions::from_mode(0o640))
                .await
                .unwrap();
            fs.hard_link(&source, &alias).await.unwrap();
            fs.symlink(std::path::Path::new("source"), &link)
                .await
                .unwrap();
            assert_eq!(
                fs.read_link(&link).await.unwrap(),
                std::path::Path::new("source")
            );
            assert_eq!(fs.read_nofollow(&source).await.unwrap(), b"verified file");
            assert!(fs.read_nofollow(&link).await.is_err());
            assert_eq!(
                fs.metadata(&source).await.unwrap().ino(),
                fs.metadata(&alias).await.unwrap().ino()
            );
            assert_eq!(
                fs.metadata(&source).await.unwrap().permissions().mode() & 0o777,
                0o640
            );

            let name = std::ffi::OsStr::new("user.terrane-test");
            match fs.set_xattr(&source, name, b"metadata").await {
                Ok(()) => {
                    assert_eq!(
                        fs.get_xattr(&alias, name).await.unwrap(),
                        Some(b"metadata".to_vec())
                    );
                    assert!(
                        fs.list_xattrs(&source)
                            .await
                            .unwrap()
                            .iter()
                            .any(|attribute| attribute == name)
                    );
                    assert_eq!(fs.get_xattr(&link, name).await.unwrap(), None);
                }
                // Some sandbox filesystems lack extended attributes. The
                // binding must preserve that failure for callers to reject
                // a checkout that requires them, rather than discard metadata.
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::Unsupported),
            }
            assert!(fs.remove_dir(&root).await.is_err());

            fs.remove_file(&link).await.unwrap();
            fs.remove_file(&alias).await.unwrap();
            fs.remove_file(&source).await.unwrap();
            fs.remove_dir(&root).await.unwrap();
        });
    }
}
