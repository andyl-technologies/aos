//! Supplies bounded existing ordinary data to the unchanged copy validators.
//!
//! Distinct file/count budgets bound retained I/O inputs. Every real body read
//! uses the existing ordinary native range capture, never `read` or an unbounded
//! whole-file nofollow call. Cached bytes preserve one coherent validation input;
//! final native closing checks reread them through the original descriptors.

use super::super::PortableReadLimits;
use crate::{
    bucket::{BucketBinding, files},
    store::{
        ByteRange, LocalFs, StoreErrorKind, StoreFailure,
        native_publication_effects::{PayloadRangeCapture, RetainedPayloadRanges},
    },
};
use std::{
    collections::BTreeMap,
    fs::Metadata,
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

struct Input {
    bytes: Vec<u8>,
    retained: RetainedPayloadRanges,
}

#[derive(Default)]
struct Inputs {
    files: BTreeMap<PathBuf, Arc<Input>>,
    bytes: usize,
    capacity_exceeded: bool,
    native_failure: Option<StoreErrorKind>,
}

/// Supplies bounded cached validation inputs and retains their native captures.
///
/// Every effect is refused. Retention proves ordinary read continuity only,
/// without establishing host custody or Original publication authority.
pub(super) struct ValidationFs<'a, F> {
    source: &'a F,
    root: PathBuf,
    limits: PortableReadLimits,
    inputs: Mutex<Inputs>,
}

impl<'a, F: LocalFs + BucketBinding> ValidationFs<'a, F> {
    /// Configures an empty validation scope without performing filesystem I/O.
    pub(super) fn new(source: &'a F, root: &Path, limits: PortableReadLimits) -> Self {
        Self {
            source,
            root: root.to_owned(),
            limits,
            inputs: Mutex::default(),
        }
    }

    fn canonical(&self, path: &Path) -> io::Result<()> {
        if path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && (path.starts_with(&self.root) || self.root.starts_with(path))
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "portable read escaped configured root",
            ))
        }
    }

    async fn load(&self, path: &Path) -> io::Result<Arc<Input>> {
        self.canonical(path)?;
        let relative = path.strip_prefix(&self.root).map_err(io::Error::other)?;
        let key = relative
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 bucket key"))?;
        terrane_format::bucket::BucketKey::parse(key).map_err(io::Error::other)?;

        // This private binding serializes input capture, including reservation,
        // so repeated reads cannot double-spend the unique-input budgets.
        let mut inputs = self.inputs.lock().await;
        if let Some(input) = inputs.files.get(path) {
            return Ok(Arc::clone(input));
        }
        if inputs.files.len() >= self.limits.max_files {
            inputs.capacity_exceeded = true;
            return Err(capacity());
        }
        let mut capture = match PayloadRangeCapture::capture_ordinary(self.source, path).await {
            Ok(capture) => capture,
            Err(error) => {
                inputs.native_failure = Some(error.kind().clone());
                return Err(io::Error::other(error));
            }
        };
        let length = match usize::try_from(capture.len()) {
            Ok(length) => length,
            Err(_) => {
                inputs.capacity_exceeded = true;
                return Err(capacity());
            }
        };
        let total = inputs.bytes.checked_add(length);
        if length > self.limits.max_file_bytes
            || total.is_none_or(|total| total > self.limits.max_input_bytes)
        {
            inputs.capacity_exceeded = true;
            return Err(capacity());
        }
        let bytes = match capture
            .read_range(
                self.source,
                ByteRange {
                    start: 0,
                    length: capture.len(),
                },
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(error) => {
                inputs.native_failure = Some(error.kind().clone());
                return Err(io::Error::other(error));
            }
        };
        let input = Arc::new(Input {
            bytes,
            retained: capture.finish(),
        });
        inputs.bytes = total.ok_or_else(capacity)?;
        inputs.files.insert(path.to_owned(), Arc::clone(&input));
        Ok(input)
    }

    /// Copies bytes already consumed from one registered key in this scope.
    ///
    /// # Errors
    /// Returns layout corruption when the key has no captured input.
    pub(super) async fn input(&self, key: &str) -> Result<Vec<u8>, StoreFailure> {
        let path = self.root.join(key);
        let inputs = self.inputs.lock().await;
        inputs
            .files
            .get(&path)
            .map(|input| input.bytes.clone())
            .ok_or_else(files::layout_corrupt)
    }

    /// Restores the captured native or budget category around a validator failure.
    ///
    /// Unclassified failures retain their original category and source.
    pub(super) async fn classify(&self, error: StoreFailure) -> StoreFailure {
        let inputs = self.inputs.lock().await;
        if inputs.capacity_exceeded {
            StoreFailure::with_source(StoreErrorKind::Capacity, error)
        } else if let Some(kind) = &inputs.native_failure {
            // LocalFs preserves its io::Error contract. Preserve the actual
            // native category instead of disguising an unavailable capture
            // as a retryable generic I/O failure.
            StoreFailure::with_source(kind.clone(), error)
        } else {
            error
        }
    }

    /// Freshly revalidates every consumed range through its original capture.
    ///
    /// # Errors
    /// Refuses changed ancestors, leaf bindings or bytes, unavailable native
    /// checks, and actual descriptor or read failures.
    pub(super) async fn close(&self) -> Result<(), StoreFailure> {
        let inputs = self.inputs.lock().await;
        for input in inputs.files.values() {
            input.retained.revalidate(self.source).await?;
        }
        Ok(())
    }
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "portable validation resource budget exceeded",
    )
}

fn read_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::ReadOnlyFilesystem,
        "portable validation performs no effects",
    )
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding> LocalFs for ValidationFs<'_, F> {
    type Lock = ();

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.read_nofollow(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        Ok(self.load(path).await?.bytes.clone())
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        let input = self.load(path).await?;
        let start = usize::try_from(range.start).map_err(io::Error::other)?;
        let length = usize::try_from(range.length).map_err(io::Error::other)?;
        let end = start.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "portable range overflow")
        })?;
        input
            .bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "portable range beyond input")
            })
    }

    async fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.symlink_metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.canonical(path)?;
        self.source.symlink_metadata(path).await
    }

    async fn random_bytes(&self, _length: usize) -> io::Result<Vec<u8>> {
        Err(read_only())
    }

    async fn lock_exclusive(&self, _path: &Path) -> io::Result<Self::Lock> {
        Err(read_only())
    }

    async fn write_new(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(read_only())
    }

    async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Err(read_only())
    }

    async fn read_dir(&self, _path: &Path) -> io::Result<Vec<PathBuf>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "portable validation never discovers content by listing",
        ))
    }

    async fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(read_only())
    }

    async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(read_only())
    }

    async fn rename_no_replace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(read_only())
    }

    async fn sync_file(&self, _path: &Path) -> io::Result<()> {
        Err(read_only())
    }

    async fn sync_directory(&self, _path: &Path) -> io::Result<()> {
        Err(read_only())
    }
}
