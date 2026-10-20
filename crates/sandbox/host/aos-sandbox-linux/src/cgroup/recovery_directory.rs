//! Owns the fixed Storage remnant census and its actual native read prefix.
//!
//! Both dispositions share one basename policy. Ordinary capture preserves
//! its existing read_dir/drop order. Selected capture uses the shared rustix
//! getdents decoder with an owned descriptor and fixed raw destination.

use super::RetainedCgroupAnchor;
use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

const MAXIMUM_NAMES: usize = 128;
const PREFIXES: [&str; 5] = [
    "aos-sandbox-workspace-pin-worker@",
    "aos-sandbox-workspace-pin-observer@",
    "aos-sandbox-workspace-root-initializer@",
    "aos-sandbox-zfs-worker@",
    "aos-sandbox-guest-root-publisher@",
];
const SUFFIX: &str = ".service";

/// Preserves directory-native and closed-name refusal classifications.
#[derive(Debug, thiserror::Error)]
pub enum StorageWorkerRecoveryDirectoryErrorV1 {
    /// Owns an ordinary directory open or iteration error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Owns a selected raw directory syscall error.
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    /// Owns the original non-UTF-8 filename.
    #[error("Storage worker cgroup name is not UTF-8")]
    Name(OsString),
    /// Rejects a malformed fixed worker instance.
    #[error("Storage worker cgroup name is not a fixed instance")]
    Instance(String),
    /// Reports the unchanged maximum128 census boundary.
    #[error("recovered workspace pin worker cgroup count exceeded its ceiling")]
    Count,
    /// Rejects repeated or incomplete capture without further IO.
    #[error("Storage worker directory observation is closed")]
    Closed,
}

/// Reports refusal while all reached native originals remain resident.
#[derive(Debug, thiserror::Error)]
#[error("retained Storage worker directory census refused")]
pub struct StorageWorkerRecoveryDirectoryRefusalV1;

#[derive(Clone, Copy)]
enum First {
    Open,
    Read,
    Name,
    Closed,
}

/// Owns one actual directory, fixed raw bytes and partial basename census.
///
/// This passive holder grants no payer or cancellation authority. A genuine
/// entered stage must prepay capture and retain it through independent posts.
pub struct StorageWorkerRecoveryDirectoryV1 {
    parent_id: Option<u64>,
    open: Option<Result<OwnedFd, rustix::io::Errno>>,
    raw: [MaybeUninit<u8>; 4096],
    read_error: Option<rustix::io::Errno>,
    current: Option<OsString>,
    names: Vec<String>,
    semantic: Option<StorageWorkerRecoveryDirectoryErrorV1>,
    first: Option<First>,
    entered: bool,
    completed: bool,
}

impl Default for StorageWorkerRecoveryDirectoryV1 {
    fn default() -> Self { Self::new() }
}

impl StorageWorkerRecoveryDirectoryV1 {
    /// Creates fixed destinations without allocation or IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parent_id: None,
            open: None,
            raw: [MaybeUninit::uninit(); 4096],
            read_error: None,
            current: None,
            names: Vec::new(),
            semantic: None,
            first: None,
            entered: false,
            completed: false,
        }
    }

    /// Bounds inline/frame storage,129 native names and original errors.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<rustix::fs::RawDir<'_, std::os::fd::BorrowedFd<'_>>>())?
            .checked_add(3 * (MAXIMUM_NAMES + 1) * (255 + std::mem::size_of::<String>()))?
            .checked_add(2 * 256)
    }

    /// Counts the actual directory; descendants are separately paid.
    pub const OPEN_FILES_V1: usize = 1;

    /// Counts the retained worker basenames, including the overflow refusal row.
    ///
    /// The fixed raw iterator, native fields and String backing occupy memory;
    /// they create no additional namespace. Parent paths are priced separately.
    pub const METADATA_ENTRIES_V1: usize = MAXIMUM_NAMES + 1;

    /// Captures the fixed basenames under the same actual parent once.
    ///
    /// # Errors
    /// Retains native open/read, name and count refusals with partial bytes and
    /// names. Repeated entry never replaces the earlier native observation.
    pub fn capture_once(&mut self, parent: &RetainedCgroupAnchor)
        -> Result<(), StorageWorkerRecoveryDirectoryRefusalV1>
    {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(StorageWorkerRecoveryDirectoryRefusalV1);
        }
        self.entered = true;
        self.parent_id = Some(parent.kernel_id());
        self.open = Some(rustix::fs::openat(parent.as_fd(), Path::new("."),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty()));
        if !matches!(self.open, Some(Ok(_))) {
            self.first = Some(First::Open);
            return Err(StorageWorkerRecoveryDirectoryRefusalV1);
        }
        self.read_opened()
    }

    fn read_opened(&mut self) -> Result<(), StorageWorkerRecoveryDirectoryRefusalV1> {
        let Some(Ok(directory)) = self.open.as_ref() else { std::process::abort() };
        let mut entries = rustix::fs::RawDir::new(directory.as_fd(), &mut self.raw);
        while let Some(entry) = entries.next() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.read_error = Some(error);
                    self.first = Some(First::Read);
                    return Err(StorageWorkerRecoveryDirectoryRefusalV1);
                }
            };
            self.current = Some(OsString::from_vec(entry.file_name().to_bytes().to_vec()));
            let Some(name) = self.current.take() else { std::process::abort() };
            if let Err(error) = accept_name(name, &mut self.names) {
                self.semantic = Some(error);
                self.first = Some(First::Name);
                return Err(StorageWorkerRecoveryDirectoryRefusalV1);
            }
        }
        self.names.sort_unstable();
        self.completed = true;
        Ok(())
    }

    /// Borrows only the actual positive completed census.
    #[must_use]
    pub fn names(&self) -> Option<&[String]> {
        (self.completed && self.first.is_none()).then_some(self.names.as_slice())
    }

    /// Compares the census with the continuously held original parent.
    ///
    /// # Errors
    /// Refuses incomplete capture or a different native parent.
    pub fn require_same_parent_v1(&self, parent: &RetainedCgroupAnchor)
        -> Result<(), StorageWorkerRecoveryDirectoryErrorV1>
    {
        if self.names().is_none() || self.parent_id != Some(parent.kernel_id()) {
            return Err(StorageWorkerRecoveryDirectoryErrorV1::Closed);
        }
        Ok(())
    }

    /// Borrows the first original cause without IO or disposal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Open => self.open.as_ref()?.as_ref().err().map(|error| error as _),
            First::Read => self.read_error.as_ref().map(|error| error as _),
            First::Name => self.semantic.as_ref().map(|error| error as _),
            First::Closed => Some(&StorageWorkerRecoveryDirectoryErrorV1::Closed),
        }
    }
}

fn accept_name(name: OsString, names: &mut Vec<String>)
    -> Result<(), StorageWorkerRecoveryDirectoryErrorV1>
{
    let name = name.into_string().map_err(StorageWorkerRecoveryDirectoryErrorV1::Name)?;
    if PREFIXES.iter().any(|prefix| name.starts_with(prefix)) && name.ends_with(SUFFIX) {
        let valid = PREFIXES.iter().find_map(|prefix| name.strip_prefix(prefix))
            .and_then(|instance| instance.strip_suffix(SUFFIX))
            .is_some_and(|instance| !instance.is_empty() && instance.len() <= 255
                && !instance.contains('/') && instance != "." && instance != "..");
        if !valid { return Err(StorageWorkerRecoveryDirectoryErrorV1::Instance(name)); }
        names.push(name);
        if names.len() > MAXIMUM_NAMES { return Err(StorageWorkerRecoveryDirectoryErrorV1::Count); }
    }
    Ok(())
}

/// Preserves ordinary directory iteration and disposal using the same policy.
///
/// # Errors
/// Returns the actual native or fixed-name classification in the old order.
pub fn read_storage_worker_recovery_names_v1(parent: &RetainedCgroupAnchor)
    -> Result<Vec<String>, StorageWorkerRecoveryDirectoryErrorV1>
{
    use std::os::fd::AsRawFd as _;
    let path = format!("/proc/self/fd/{}", parent.as_fd().as_raw_fd());
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        accept_name(entry?.file_name(), &mut names)?;
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_native(directory: &std::path::Path) -> StorageWorkerRecoveryDirectoryV1 {
        let mut native = StorageWorkerRecoveryDirectoryV1::new();
        native.entered = true;
        native.open = Some(rustix::fs::open(directory, rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()));
        let _ = native.read_opened();
        native
    }

    #[test]
    fn native_count_refusal_retains_actual_directory_and_all129_names() {
        let directory = tempfile::tempdir().unwrap();
        for number in 0..129 {
            std::fs::create_dir(directory.path().join(format!("{}{}.service", PREFIXES[0], number))).unwrap();
        }
        let native = capture_native(directory.path());

        assert!(matches!(native.semantic, Some(StorageWorkerRecoveryDirectoryErrorV1::Count)));
        assert_eq!(native.names.len(), 129);
        assert!(native.names().is_none());
        let descriptor = native.open.as_ref().unwrap().as_ref().unwrap();
        assert!(rustix::fs::fstat(descriptor.as_fd()).is_ok());
        assert!(native.failure().is_some());
    }

    #[test]
    fn selected_native_and_ordinary_sources_share_fixed_roster_and_sort() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["unrelated", "aos-sandbox-zfs-worker@z.service",
            "aos-sandbox-workspace-pin-observer@a.service", "aos-sandbox-workspace-root-initializer@b.service"]
        {
            std::fs::create_dir(directory.path().join(name)).unwrap();
        }
        let mut ordinary = Vec::new();
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            accept_name(entry.unwrap().file_name(), &mut ordinary).unwrap();
        }
        ordinary.sort_unstable();
        let native = capture_native(directory.path());

        assert_eq!(native.names(), Some(ordinary.as_slice()));
        assert_eq!(ordinary.len(), 3);
        assert!(native.failure().is_none());
    }

    #[test]
    fn malformed_returned_name_remains_owned_in_selected_error() {
        let directory = tempfile::tempdir().unwrap();
        // Empty fixed instances are native-representable ASCII filenames even
        // when the backing filesystem requires all names to be valid UTF-8.
        let name = format!("{}{}", PREFIXES[0], SUFFIX);
        std::fs::create_dir(directory.path().join(&name)).unwrap();
        let native = capture_native(directory.path());

        match native.semantic.as_ref().unwrap() {
            StorageWorkerRecoveryDirectoryErrorV1::Instance(actual) => assert_eq!(actual, &name),
            other => panic!("wrong native error: {other}"),
        }
        let descriptor = native.open.as_ref().unwrap().as_ref().unwrap();
        assert!(rustix::fs::fstat(descriptor.as_fd()).is_ok());
        assert!(native.names().is_none());
        assert!(native.failure().is_some());
    }
}
