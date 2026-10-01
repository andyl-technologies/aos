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
    fn retain_native_clock(&self) -> std::io::Result<super::NativeEffectClock> {
        // TokioClock is stateless; all instances use the same native monotonic
        // origin. Copying this exact injected binding retains the same clock.
        Ok(super::NativeEffectClock::from_native_clock(*self))
    }

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

/// Distinguishes new namespace setup from read-only existing-state inspection.
#[cfg(feature = "tokio")]
enum LockOpenMode {
    Create,
    Existing,
}

/// Opens coordination with the requested creation policy and verifies its lock.
#[cfg(feature = "tokio")]
async fn native_file_lock(
    path: &std::path::Path,
    mode: LockOpenMode,
) -> std::io::Result<TokioFileLock> {
    let path = path.to_owned();

    // Kernel lock waits run outside the executor. An abandoned result owns
    // its descriptor until it is dropped, and existing-only opens never create.
    tokio::task::spawn_blocking(move || {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(matches!(mode, LockOpenMode::Create))
                .truncate(false)
                // Creation must keep namespace exclusion private regardless
                // of the process umask; existing inode modes remain unchanged.
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?;
            lock_opened(&path, file)
        }

        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "nofollow coordination locking unavailable",
            ))
        }
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Locks the opened regular inode and verifies that its pathname still names it.
#[cfg(all(feature = "tokio", unix))]
fn lock_opened(path: &std::path::Path, file: std::fs::File) -> std::io::Result<TokioFileLock> {
    use std::os::unix::fs::MetadataExt;

    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "coordination inode is not a single-link regular file",
        ));
    }

    file.lock()?;

    // A waiter may resume after the name has been replaced. Holding the old
    // inode's kernel lock cannot establish exclusion at that new pathname.
    let opened = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !opened.is_file()
        || !named.is_file()
        || named.file_type().is_symlink()
        || opened.nlink() != 1
        || named.nlink() != 1
        || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "coordination pathname changed while acquiring its lock",
        ));
    }

    Ok(TokioFileLock { _file: file })
}

/// Binds portable file operations to the native runtime (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioLocalFs;

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl LocalFs for TokioLocalFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: super::NativePublicationInitialization,
    ) -> Result<super::NativePublicationInitializationOutcome, super::StoreFailure> {
        #[cfg(unix)]
        {
            request.execute_tokio().await
        }
        #[cfg(not(unix))]
        {
            let _ = request;
            Err(super::StoreFailure::new(super::StoreErrorKind::Unsupported))
        }
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<super::NativeExclusion> {
        Ok(super::NativeExclusion::from_held_descriptor(
            held._file.try_clone()?,
        ))
    }

    async fn execute_retained_effect(
        &self,
        effect: super::NativeFsEffect,
    ) -> Result<(), super::NativeEffectFailure> {
        effect.execute_tokio().await
    }

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
        native_file_lock(path, LockOpenMode::Create).await
    }

    async fn lock_existing_exclusive(&self, path: &std::path::Path) -> std::io::Result<Self::Lock> {
        native_file_lock(path, LockOpenMode::Existing).await
    }

    async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(path).await
    }

    async fn read_range(
        &self,
        path: &std::path::Path,
        range: ByteRange,
    ) -> std::io::Result<Vec<u8>> {
        let length = usize::try_from(range.length)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        bytes.resize(length, 0);

        #[cfg(unix)]
        {
            use std::io::{Read, Seek};
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

            tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
            let path = path.to_owned();

            // Seek and read share one nofollow descriptor and one worker.
            // General file reads permit hardlinks; protected publication probes
            // separately enforce their captured single-link physical preimage.
            tokio::task::spawn_blocking(move || {
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)?;
                let opened = file.metadata()?;
                let stamp = |metadata: &std::fs::Metadata| {
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.uid(),
                        metadata.mode(),
                        metadata.nlink(),
                    )
                };
                let check = |metadata: &std::fs::Metadata| -> std::io::Result<()> {
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || stamp(metadata) != stamp(&opened)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "range read file incarnation changed",
                        ));
                    }
                    Ok(())
                };
                check(&opened)?;
                check(&std::fs::symlink_metadata(&path)?)?;

                file.seek(std::io::SeekFrom::Start(range.start))?;
                file.read_exact(&mut bytes)?;

                check(&file.metadata()?)?;
                check(&std::fs::symlink_metadata(&path)?)?;
                Ok(bytes)
            })
            .await
            .map_err(std::io::Error::other)?
        }
        #[cfg(not(unix))]
        {
            let _ = (path, range, bytes);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "nofollow range reads unavailable",
            ))
        }
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

    async fn symlink_metadata_batch(
        &self,
        paths: &[std::path::PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
        let paths = paths.to_vec();

        let observations = tokio::task::spawn_blocking(move || {
            paths
                .iter()
                .map(std::fs::symlink_metadata)
                .collect::<Vec<_>>()
        })
        .await
        .map_err(std::io::Error::other)?;
        Ok(observations)
    }

    async fn read_protected_record(
        &self,
        read: super::NativeProtectedRead,
    ) -> Result<Option<super::NativeProtectedRecord>, super::StoreFailure> {
        #[cfg(unix)]
        {
            tokio::runtime::Handle::try_current()
                .map_err(|error| super::protected_read::io_failure(std::io::Error::other(error)))?;

            tokio::task::spawn_blocking(move || read.execute())
                .await
                .map_err(|error| super::protected_read::io_failure(std::io::Error::other(error)))?
                .map(Some)
        }
        #[cfg(not(unix))]
        {
            let _ = read;
            Ok(None)
        }
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

    async fn sync_file_nofollow(
        &self,
        path: &std::path::Path,
        expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
            let mut options = tokio::fs::OpenOptions::new();
            options.read(true);
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = options.open(path).await?;
            let before = file.metadata().await?;
            if !expected.is_file()
                || !before.is_file()
                || (before.dev(), before.ino()) != (expected.dev(), expected.ino())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "regular file identity changed before synchronization",
                ));
            }

            // Sync and inspect the opened object, rather than resolving the
            // pathname again after its identity has been checked.
            file.sync_all().await?;
            let after = file.metadata().await?;
            if !after.is_file() || (after.dev(), after.ino()) != (before.dev(), before.ino()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "regular file identity changed during synchronization",
                ));
            }
            Ok(after)
        }

        #[cfg(not(unix))]
        {
            let _ = (path, expected);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "nofollow file synchronization unavailable",
            ))
        }
    }

    async fn sync_directory(&self, path: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::File::open(path).await?.sync_all().await
    }

    async fn read_nofollow(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "nofollow open unavailable",
            ))
        }

        #[cfg(unix)]
        {
            use std::io::Read;
            use std::os::unix::fs::OpenOptionsExt;

            tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
            let path = path.to_owned();

            // One worker owns the same nofollow descriptor through inspection
            // and the complete read; these blocking steps stay off the executor.
            tokio::task::spawn_blocking(move || {
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)?;
                if !file.metadata()?.is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "path is not a regular file",
                    ));
                }

                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Ok(bytes)
            })
            .await
            .map_err(std::io::Error::other)?
        }
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

    async fn set_permissions_and_sync(
        &self,
        path: &std::path::Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        // Keep the descriptor open across the mode change: reopening a
        // restrictive final mode may fail for the unprivileged owner.
        let file = tokio::fs::File::open(path).await?;

        file.set_permissions(permissions).await?;
        file.sync_all().await
    }

    async fn create_dir_new(&self, path: &std::path::Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).await
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "private directory creation unavailable",
            ))
        }
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
    fn native_lock_rejects_symlinks_hardlinks_and_replaced_open_inodes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let fs = TokioLocalFs;
            let entropy = fs.random_bytes(16).await.unwrap();
            let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
            let root = std::env::temp_dir().join(format!("terrane-lock-inode-{suffix}"));
            fs.create_dir_new(&root).await.unwrap();
            let path = root.join("coordination");
            let link = root.join("symlink");
            let alias = root.join("alias");
            let retained = root.join("retained-inode");
            fs.write_new(&path, b"original").await.unwrap();

            let guard = fs.lock_exclusive(&path).await.unwrap();
            drop(guard);
            fs.symlink(&path, &link).await.unwrap();
            assert!(fs.lock_exclusive(&link).await.is_err());
            assert!(fs.lock_exclusive(&root).await.is_err());
            fs.hard_link(&path, &alias).await.unwrap();
            assert!(fs.lock_exclusive(&path).await.is_err());
            fs.remove_file(&alias).await.unwrap();

            // Model replacement after the primitive opens its descriptor but
            // before its waiting lock can establish current-name exclusion.
            let opened = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            fs.rename(&path, &retained).await.unwrap();
            fs.write_new(&path, b"replacement").await.unwrap();

            assert_eq!(
                lock_opened(&path, opened).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
            assert_eq!(fs.read(&retained).await.unwrap(), b"original");
            assert_eq!(fs.read(&path).await.unwrap(), b"replacement");
            let guard = fs.lock_exclusive(&path).await.unwrap();
            drop(guard);

            for path in [link, retained, path] {
                fs.remove_file(&path).await.unwrap();
            }
            fs.remove_dir(&root).await.unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn native_existing_lock_never_creates_missing_coordination() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let fs = TokioLocalFs;
            let entropy = fs.random_bytes(16).await.unwrap();
            let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
            let root = std::env::temp_dir().join(format!("terrane-existing-lock-{suffix}"));
            fs.create_dir_new(&root).await.unwrap();
            let path = root.join("coordination");
            let alias = root.join("alias");
            let link = root.join("symlink");

            assert_eq!(
                fs.lock_existing_exclusive(&path).await.unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
            assert!(!path.exists());

            let guard = fs.lock_exclusive(&path).await.unwrap();
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(
                    fs.metadata(&path).await.unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            drop(guard);
            fs.remove_file(&path).await.unwrap();

            fs.write_new(&path, b"registered coordination")
                .await
                .unwrap();
            let original_permissions = fs.metadata(&path).await.unwrap().permissions();
            let guard = fs.lock_existing_exclusive(&path).await.unwrap();
            assert_eq!(fs.read(&path).await.unwrap(), b"registered coordination");
            assert_eq!(
                fs.metadata(&path).await.unwrap().permissions(),
                original_permissions
            );
            drop(guard);
            fs.symlink(&path, &link).await.unwrap();
            assert!(fs.lock_existing_exclusive(&link).await.is_err());
            assert!(fs.lock_existing_exclusive(&root).await.is_err());
            fs.hard_link(&path, &alias).await.unwrap();
            assert!(fs.lock_existing_exclusive(&path).await.is_err());
            fs.remove_file(&alias).await.unwrap();
            fs.remove_file(&path).await.unwrap();

            // Existing-state inspection after removal must not recreate the
            // coordination inode, even when a symlink still names its old path.
            assert_eq!(
                fs.lock_existing_exclusive(&path).await.unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
            assert!(!path.exists());
            fs.remove_file(&link).await.unwrap();
            fs.remove_dir(&root).await.unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn native_nofollow_sync_rejects_replacement_symlink_and_nonregular_files() {
        use std::os::unix::fs::MetadataExt;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let fs = TokioLocalFs;
            let suffix: String = fs
                .random_bytes(16)
                .await
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let root = std::env::temp_dir().join(format!("terrane-nofollow-sync-{suffix}"));
            fs.create_dir_new(&root).await.unwrap();
            let original = root.join("original");
            let replacement = root.join("replacement");
            let link = root.join("link");
            fs.write_new(&original, b"durable incarnation")
                .await
                .unwrap();
            fs.write_new(&replacement, b"durable incarnation")
                .await
                .unwrap();
            fs.symlink(std::path::Path::new("original"), &link)
                .await
                .unwrap();
            let expected = fs.symlink_metadata(&original).await.unwrap();

            let actual = fs.sync_file_nofollow(&original, &expected).await.unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (expected.dev(), expected.ino())
            );
            assert!(
                fs.sync_file_nofollow(&replacement, &expected)
                    .await
                    .is_err()
            );
            assert!(fs.sync_file_nofollow(&link, &expected).await.is_err());
            assert!(fs.sync_file_nofollow(&root, &expected).await.is_err());
            let directory = fs.symlink_metadata(&root).await.unwrap();
            assert!(fs.sync_file_nofollow(&original, &directory).await.is_err());

            // Preserve the old inode at another name so equal bytes cannot
            // accidentally make replacement appear to be the observed object.
            fs.rename(&original, &root.join("old")).await.unwrap();
            fs.rename(&replacement, &original).await.unwrap();
            assert!(fs.sync_file_nofollow(&original, &expected).await.is_err());
            fs.remove_file(&link).await.unwrap();
            fs.remove_file(&original).await.unwrap();
            fs.remove_file(&root.join("old")).await.unwrap();
            fs.remove_dir(&root).await.unwrap();
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
                fs.metadata(&root).await.unwrap().permissions().mode() & 0o777,
                0o700
            );
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
                fs.read_range(
                    &source,
                    ByteRange {
                        start: 0,
                        length: 8
                    }
                )
                .await
                .unwrap(),
                b"verified"
            );
            assert_eq!(
                fs.read_range(
                    &alias,
                    ByteRange {
                        start: 9,
                        length: 4
                    }
                )
                .await
                .unwrap(),
                b"file"
            );
            assert!(
                fs.read_range(
                    &link,
                    ByteRange {
                        start: 0,
                        length: 1
                    }
                )
                .await
                .is_err()
            );
            assert_eq!(
                fs.read_range(
                    &source,
                    ByteRange {
                        start: 0,
                        length: 100
                    }
                )
                .await
                .unwrap_err()
                .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
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

            fs.set_permissions_and_sync(&source, std::fs::Permissions::from_mode(0o0))
                .await
                .unwrap();
            assert_eq!(
                fs.metadata(&alias).await.unwrap().permissions().mode() & 0o777,
                0
            );
            fs.set_permissions(&source, std::fs::Permissions::from_mode(0o640))
                .await
                .unwrap();

            fs.set_permissions_and_sync(&root, std::fs::Permissions::from_mode(0o0))
                .await
                .unwrap();
            fs.set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();

            fs.remove_file(&link).await.unwrap();
            fs.remove_file(&alias).await.unwrap();
            fs.remove_file(&source).await.unwrap();
            fs.remove_dir(&root).await.unwrap();
        });
    }
}
