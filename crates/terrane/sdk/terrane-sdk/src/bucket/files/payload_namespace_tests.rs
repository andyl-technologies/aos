//! Compares batched payload ancestry with the original sequential metadata recipe.
//!
//! Each witness uses real filesystem nodes. The local binding records dispatch
//! boundaries and injects named I/O failures without reading payload bodies.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

use super::{io_failure, layout_corrupt, malformed};
use crate::bucket::{FileBucket, Inner, tests};
use crate::store::{ByteRange, LocalFs, StoreFailure, TokioClock, TokioLocalFs};
use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use terrane_format::bucket::BucketKey;

/// Records individual metadata requests and complete native batch inputs.
#[derive(Debug, Eq, PartialEq)]
enum Request {
    Scalar(PathBuf),
    Batch(Vec<PathBuf>),
}

/// Retains metadata-only dispatch observations for one independent operation.
struct MetadataFs {
    requests: Mutex<Vec<Request>>,
    fault: Option<(PathBuf, ErrorKind)>,
    short_batch: bool,
}

impl MetadataFs {
    fn new(fault: Option<(PathBuf, ErrorKind)>, short_batch: bool) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            fault,
            short_batch,
        }
    }

    // Actual named metadata is observed even when its result is replaced by a
    // test-only I/O failure. No synthetic metadata can admit an unsafe node.
    async fn named(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        let actual = TokioLocalFs.symlink_metadata(path).await;
        if let Some((fault_path, kind)) = &self.fault
            && path == fault_path
        {
            return Err(io::Error::new(*kind, "payload metadata witness"));
        }
        actual
    }

    fn requests(&self) -> Vec<Request> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for MetadataFs {
    type Lock = crate::store::TokioFileLock;

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
        panic!("payload namespace validation must not read a body")
    }

    async fn read_range(&self, _path: &Path, _range: ByteRange) -> io::Result<Vec<u8>> {
        panic!("payload namespace validation must not read a body range")
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        self.requests
            .lock()
            .unwrap()
            .push(Request::Scalar(path.to_owned()));
        self.named(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> io::Result<Vec<io::Result<std::fs::Metadata>>> {
        self.requests
            .lock()
            .unwrap()
            .push(Request::Batch(paths.to_vec()));
        let mut observations = TokioLocalFs.symlink_metadata_batch(paths).await?;
        for (path, observation) in paths.iter().zip(&mut observations) {
            if let Some((fault_path, kind)) = &self.fault
                && path == fault_path
            {
                *observation = Err(io::Error::new(*kind, "payload metadata witness"));
            }
        }
        if self.short_batch {
            observations.pop();
        }
        Ok(observations)
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }
}

type Bucket = FileBucket<MetadataFs, TokioClock, tests::Validator>;

/// Borrows the real initialized namespace without performing initialization again.
fn bucket(source: &tests::Bucket, fault: Option<(PathBuf, ErrorKind)>, short: bool) -> Bucket {
    FileBucket {
        inner: Arc::new(Inner {
            config: source.inner.config.clone(),
            fs: MetadataFs::new(fault, short),
            clock: TokioClock,
            validator: tests::Validator,
            capabilities: source.inner.capabilities.clone(),
            access: source.inner.access,
            content_observation: Arc::default(),
        }),
    }
}

/// Executes the original sequential checks independently of the batched helper.
async fn scalar_namespace(bucket: &Bucket, key: &BucketKey) -> Result<(), StoreFailure> {
    let mut path = bucket.root().to_owned();
    let metadata = bucket
        .inner
        .fs
        .symlink_metadata(&path)
        .await
        .map_err(io_failure)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(layout_corrupt());
    }

    let relative = Path::new(key.as_str()).parent().ok_or_else(malformed)?;
    for part in relative.components() {
        path.push(part);
        match bucket.inner.fs.symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(layout_corrupt()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_failure(error)),
        }
    }

    match bucket.inner.fs.symlink_metadata(&bucket.path(key)).await {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(layout_corrupt()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_failure(error)),
    }
}

fn assert_parity(actual: &Result<(), StoreFailure>, scalar: &Result<(), StoreFailure>) {
    match (actual, scalar) {
        (Ok(()), Ok(())) => {}
        (Err(actual), Err(scalar)) => {
            assert_eq!(actual.kind(), scalar.kind());
            let source = |error: &StoreFailure| {
                error.source().map(|source| {
                    let io = source.downcast_ref::<io::Error>().unwrap();
                    (io.kind(), io.to_string())
                })
            };
            assert_eq!(source(actual), source(scalar));
        }
        _ => panic!("batched and original scalar namespace outcomes differ"),
    }
}

fn assert_no_leaf(requests: &[Request], leaf: &Path) {
    assert!(
        !requests
            .iter()
            .any(|request| { matches!(request, Request::Scalar(path) if path == leaf) })
    );
}

#[tokio::test]
async fn payload_namespace_batches_present_parents_and_keeps_root_keys_scalar() {
    let source = tests::fixture().await;
    for text in ["objects/index/1/MANIFEST", "CAPABILITIES"] {
        let key = BucketKey::parse(text).unwrap();
        let actual = bucket(&source, None, false);
        let scalar = bucket(&source, None, false);
        let outcome = actual.check_payload_namespace(&key).await;
        assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
        assert!(outcome.is_ok());
        let root = source.root().to_owned();
        let leaf = source.path(&key);
        let mut expected = vec![Request::Scalar(root.clone())];
        if text.starts_with("objects/") {
            expected.push(Request::Batch(vec![
                root.join("objects"),
                root.join("objects/index"),
                root.join("objects/index/1"),
            ]));
        }
        expected.push(Request::Scalar(leaf));
        assert_eq!(actual.inner.fs.requests(), expected);
        assert!(
            scalar
                .inner
                .fs
                .requests()
                .iter()
                .all(|request| matches!(request, Request::Scalar(_)))
        );
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn payload_namespace_rejects_unsafe_root_or_ordered_parent_before_leaf() {
    let source = tests::fixture().await;
    let key = BucketKey::parse("objects/index/2/MANIFEST").unwrap();
    let root = source.root().to_owned();
    let saved = root.with_extension("namespace-saved");
    std::fs::rename(&root, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &root).unwrap();
    let actual = bucket(&source, None, false);
    let scalar = bucket(&source, None, false);
    let outcome = actual.check_payload_namespace(&key).await;
    assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
    assert_eq!(outcome.unwrap_err().kind(), layout_corrupt().kind());
    assert_eq!(
        actual.inner.fs.requests(),
        vec![Request::Scalar(root.clone())]
    );
    assert_eq!(
        scalar.inner.fs.requests(),
        vec![Request::Scalar(root.clone())]
    );
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&saved, &root).unwrap();

    let index = root.join("objects/index");
    std::fs::remove_dir_all(&index).unwrap();
    std::fs::write(&index, b"unsafe earlier ancestor").unwrap();
    for fault in [None, Some((index.join("2"), ErrorKind::PermissionDenied))] {
        let actual = bucket(&source, fault.clone(), false);
        let scalar = bucket(&source, fault, false);
        let outcome = actual.check_payload_namespace(&key).await;
        assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
        assert_eq!(outcome.unwrap_err().kind(), layout_corrupt().kind());
        assert_no_leaf(&actual.inner.fs.requests(), &source.path(&key));
        assert_eq!(
            scalar.inner.fs.requests(),
            vec![
                Request::Scalar(root.clone()),
                Request::Scalar(root.join("objects")),
                Request::Scalar(index.clone())
            ]
        );
    }
    std::fs::remove_file(&index).unwrap();
    std::os::unix::fs::symlink(root.join("objects"), &index).unwrap();
    for fault in [None, Some((index.join("2"), ErrorKind::PermissionDenied))] {
        let actual = bucket(&source, fault.clone(), false);
        let scalar = bucket(&source, fault, false);
        let outcome = actual.check_payload_namespace(&key).await;
        assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
        assert_eq!(outcome.unwrap_err().kind(), layout_corrupt().kind());
        assert_no_leaf(&actual.inner.fs.requests(), &source.path(&key));
    }
    std::fs::remove_file(&index).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn payload_namespace_preserves_absence_errors_and_rejects_incomplete_batches() {
    let source = tests::fixture().await;
    let key = BucketKey::parse("objects/index/2/MANIFEST").unwrap();
    let parent = source.root().join("objects/index/2");
    let leaf = source.path(&key);
    let actual = bucket(&source, None, false);
    let scalar = bucket(&source, None, false);
    let outcome = actual.check_payload_namespace(&key).await;
    assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
    assert!(outcome.is_ok());
    assert_no_leaf(&actual.inner.fs.requests(), &leaf);
    std::fs::create_dir(&parent).unwrap();

    // A physically absent leaf is compatible, while present nonregular leaves
    // retain the same CAPABILITIES corruption subject in both recipes.
    let actual = bucket(&source, None, false);
    let scalar = bucket(&source, None, false);
    let outcome = actual.check_payload_namespace(&key).await;
    assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
    assert!(outcome.is_ok());
    assert_eq!(
        actual.inner.fs.requests().last(),
        Some(&Request::Scalar(leaf.clone()))
    );
    std::fs::create_dir(&leaf).unwrap();
    let actual = bucket(&source, None, false);
    let scalar = bucket(&source, None, false);
    let outcome = actual.check_payload_namespace(&key).await;
    assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
    assert_eq!(outcome.unwrap_err().kind(), layout_corrupt().kind());
    std::fs::remove_dir(&leaf).unwrap();
    std::fs::write(&leaf, b"metadata-only witness").unwrap();

    for path in [source.root().to_owned(), parent.clone(), leaf.clone()] {
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::StorageFull,
            ErrorKind::Unsupported,
            ErrorKind::Other,
        ] {
            let fault = Some((path.clone(), kind));
            let actual = bucket(&source, fault.clone(), false);
            let scalar = bucket(&source, fault, false);
            let outcome = actual.check_payload_namespace(&key).await;
            assert_parity(&outcome, &scalar_namespace(&scalar, &key).await);
            if kind == ErrorKind::NotFound && path != source.root() {
                assert!(outcome.is_ok());
            } else {
                let error = outcome.unwrap_err();
                assert_eq!(
                    error.kind(),
                    io_failure(io::Error::new(kind, "payload metadata witness")).kind()
                );
                assert_eq!(
                    error.source().unwrap().to_string(),
                    "payload metadata witness"
                );
            }
            if path != leaf {
                assert_no_leaf(&actual.inner.fs.requests(), &leaf);
            }
        }
    }

    let actual = bucket(&source, None, true);
    assert_eq!(
        actual
            .check_payload_namespace(&key)
            .await
            .unwrap_err()
            .kind(),
        layout_corrupt().kind()
    );
    let requests = actual.inner.fs.requests();
    assert_no_leaf(&requests, &leaf);
    assert_eq!(requests.len(), 2);
    assert!(matches!(&requests[1], Request::Batch(paths) if paths.len() == 3));
    std::fs::remove_dir_all(source.root()).unwrap();
}
