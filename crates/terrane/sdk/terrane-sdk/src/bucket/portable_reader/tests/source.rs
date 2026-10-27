//! Records actual native reads while refusing every mutation and fallback.

use crate::store::{
    ByteRange, LocalFs, NativePayloadRangeRead, NativePayloadRangeRecord, TokioLocalFs,
};
use std::{
    fs::Metadata,
    io,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) struct ReadSource {
    root: PathBuf,
    pub(super) ranges: Mutex<Vec<(PathBuf, ByteRange)>>,
    pub(super) mutations: AtomicBool,
    pub(super) decline_capture: bool,
    pub(super) change_on_close: AtomicBool,
}

impl ReadSource {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            ranges: Mutex::default(),
            mutations: AtomicBool::new(false),
            decline_capture: false,
            change_on_close: AtomicBool::new(false),
        }
    }

    fn refuse(&self) -> io::Error {
        self.mutations.store(true, Ordering::SeqCst);
        io::Error::new(
            io::ErrorKind::ReadOnlyFilesystem,
            "unexpected validation effect",
        )
    }
}

#[async_trait::async_trait]
impl LocalFs for ReadSource {
    type Lock = ();

    async fn read_payload_ranges(
        &self,
        read: NativePayloadRangeRead,
    ) -> io::Result<Option<NativePayloadRangeRecord>> {
        if self.decline_capture {
            return Ok(None);
        }
        if let Some(path) = read.capture_path_for_test() {
            assert!(
                path.starts_with(&self.root),
                "outside portable root: {}",
                path.display()
            );
        }
        if let Some((path, range)) = read.read_data_range() {
            self.ranges.lock().unwrap().push((path.to_owned(), range));
        }
        let closing = read.closing_data_ranges_for_test().is_some();
        if closing && self.change_on_close.swap(false, Ordering::SeqCst) {
            let path = self.root.join("publication/PORTABLE");
            let mut bytes = tokio::fs::read(&path).await.unwrap();
            bytes[0] ^= 1;
            tokio::fs::write(path, bytes).await.unwrap();
        }
        TokioLocalFs.read_payload_ranges(read).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        assert!(path.starts_with(&self.root) || self.root.starts_with(path));
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.symlink_metadata(path).await
    }

    async fn random_bytes(&self, _length: usize) -> io::Result<Vec<u8>> {
        Err(self.refuse())
    }

    async fn lock_exclusive(&self, _path: &Path) -> io::Result<Self::Lock> {
        Err(self.refuse())
    }

    async fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
        panic!("unbounded ordinary read")
    }

    async fn read_nofollow(&self, _path: &Path) -> io::Result<Vec<u8>> {
        panic!("unbounded nofollow read")
    }

    async fn read_range(&self, _path: &Path, _range: ByteRange) -> io::Result<Vec<u8>> {
        panic!("uncaptured range fallback")
    }

    async fn write_new(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn read_dir(&self, _path: &Path) -> io::Result<Vec<PathBuf>> {
        panic!("raw discovery cannot select a portable catalog")
    }

    async fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn rename_no_replace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn sync_file(&self, _path: &Path) -> io::Result<()> {
        Err(self.refuse())
    }

    async fn sync_directory(&self, _path: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
}
