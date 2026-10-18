//! Retains actual immutable binding-record custody through quarantine repair.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rustix::fs::{self, AtFlags, Mode, OFlags};

fn open_regular(directory: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    // A corrupt private name must not trigger device read-open effects or a
    // FIFO wait before custody validation. Retain and classify the actual inode
    // first; procfs then reopens only that retained regular file for reading.
    let retained = File::from(fs::openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let expected = retained.metadata()?;
    if !expected.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binding record is not regular",
        ));
    }
    let file = File::from(fs::open(
        format!("/proc/self/fd/{}", retained.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let actual = file.metadata()?;
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
        return Err(io::Error::other(
            "binding inode changed during retained reopen",
        ));
    }
    Ok(file)
}

struct Snapshot {
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
}

pub(super) struct RetainedBinding {
    directory: File,
    snapshot: Mutex<Option<Snapshot>>,
}

impl RetainedBinding {
    pub(super) fn new(directory: File) -> Self {
        Self {
            directory,
            snapshot: Mutex::new(None),
        }
    }

    pub(super) fn capture(&self, path: &Path) -> io::Result<()> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("missing binding name"))?;
        let snapshot = match open_regular(&self.directory, name) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                (&mut file).take(65537).read_to_end(&mut bytes)?;
                if bytes.len() > 65536 {
                    return Err(io::Error::other("oversized retained binding"));
                }
                Some(Snapshot {
                    path: path.to_owned(),
                    file,
                    bytes,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        *self
            .snapshot
            .lock()
            .map_err(|_| io::Error::other("binding custody lock poisoned"))? = snapshot;
        Ok(())
    }

    pub(super) fn remove(&mut self, path: &Path) -> io::Result<()> {
        let snapshot = self
            .snapshot
            .get_mut()
            .map_err(|_| io::Error::other("binding custody lock poisoned"))?
            .as_mut()
            .ok_or_else(|| io::Error::other("no retained stale binding"))?;
        if snapshot.path != path {
            return Err(io::Error::other("stale binding context changed"));
        }
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("missing binding name"))?;
        let current = open_regular(&self.directory, name)?;
        let expected = snapshot.file.metadata()?;
        let actual = current.metadata()?;
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() || !actual.is_file() {
            return Err(io::Error::other("stale binding inode changed"));
        }
        snapshot.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut snapshot.file).take(65537).read_to_end(&mut bytes)?;
        if bytes != snapshot.bytes {
            return Err(io::Error::other("stale binding contents changed"));
        }
        // The native actor owns the private directory and its exclusion through
        // both operations. A sync failure retains the snapshot for reconciliation;
        // it never grants a backing handle or replaces a binding record.
        fs::unlinkat(&self.directory, name, AtFlags::empty())?;
        self.directory.sync_all()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terrane-binding-repair-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn binding_capture_refuses_special_inodes_before_read_open() {
        let mut retained = RetainedBinding::new(File::open("/dev").unwrap());
        assert!(retained.capture(Path::new("/dev/null")).is_err());
        assert!(retained.snapshot.get_mut().unwrap().is_none());

        let fixture = Fixture::new();
        let path = fixture.0.join("binding.toml");
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        let mut retained = RetainedBinding::new(File::open(&fixture.0).unwrap());
        assert!(retained.capture(&path).is_err());
        assert!(retained.snapshot.get_mut().unwrap().is_none());
    }

    #[test]
    fn repair_refuses_replacement_and_same_inode_mutation() {
        let fixture = Fixture::new();
        let path = fixture.0.join("binding.toml");
        std::fs::write(&path, b"original").unwrap();
        let mut retained = RetainedBinding::new(File::open(&fixture.0).unwrap());
        retained.capture(&path).unwrap();

        std::fs::rename(&path, fixture.0.join("old")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(retained.remove(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");

        retained.capture(&path).unwrap();
        std::fs::write(&path, b"changed in place").unwrap();
        assert!(retained.remove(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"changed in place");
    }

    #[test]
    fn actual_parent_sync_failure_withholds_repair_success() {
        let fixture = Fixture::new();
        let path = fixture.0.join("binding.toml");
        std::fs::write(&path, b"stale").unwrap();
        // O_PATH supports descriptor-relative lookup/unlink, but fsync genuinely
        // fails with EBADF after unlink. This is a real durability failure.
        let directory = File::from(
            fs::openat(
                fs::CWD,
                &fixture.0,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        let mut retained = RetainedBinding::new(directory);
        retained.capture(&path).unwrap();

        assert_eq!(
            retained.remove(&path).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(!path.exists());
        assert!(retained.snapshot.get_mut().unwrap().is_some());

        // Recovery uses real readable directory custody and a newly captured
        // record; failed durability never licenses deleting a replacement.
        std::fs::write(&path, b"replacement").unwrap();
        assert!(retained.remove(&path).is_err());
        let mut recovered = RetainedBinding::new(File::open(&fixture.0).unwrap());
        recovered.capture(&path).unwrap();
        recovered.remove(&path).unwrap();
        assert!(!path.exists());
    }
}
