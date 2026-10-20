//! Retains an exact current-task-only sample of a held worker cgroup.
//!
//! The actual caller owns the trusted cgroup selection and its funding. This
//! native observation supplies no service or execution authority. Its complete
//! current-task-only sample is a local no-remnant observation, not a lock
//! against future migration or process creation.

use super::*;
use std::os::unix::fs::FileExt as _;

#[derive(Clone, Copy, Debug)]
enum First {
    Before,
    Open,
    Read,
    Tail,
    Membership,
    After,
    Closed,
}

/// Retains native active/open/read/parse/active samples and their partial bytes.
#[derive(Debug)]
pub struct CgroupSingleTaskObservationV1 {
    before_probe: PendingRegularFileV1,
    before: Option<Result<()>>,
    opening: PendingRegularFileV1,
    open: Option<Result<()>>,
    file: Option<File>,
    bytes: [u8; 4097],
    read: Option<std::io::Result<usize>>,
    tail: [u8; 1],
    tail_read: Option<std::io::Result<usize>>,
    membership: Option<Result<()>>,
    after_probe: PendingRegularFileV1,
    after: Option<Result<()>>,
    process: Option<u32>,
    first: Option<First>,
    entered: bool,
    completed: bool,
    disposed: bool,
}

impl Default for CgroupSingleTaskObservationV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupSingleTaskObservationV1 {
    /// Creates empty native destinations without IO or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            before_probe: PendingRegularFileV1::default(),
            before: None,
            opening: PendingRegularFileV1::default(),
            open: None,
            file: None,
            bytes: [0; 4097],
            read: None,
            tail: [0; 1],
            tail_read: None,
            membership: None,
            after_probe: PendingRegularFileV1::default(),
            after: None,
            process: None,
            first: None,
            entered: false,
            completed: false,
            disposed: false,
        }
    }

    /// Prices actual retained and construction frames plus native error lanes.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?.checked_add(6 * 256)
    }

    /// Bounds the held read and both independent active-file probes.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = 3;

    /// Counts the two actual fixed cgroup control-file namespace entries.
    ///
    /// Both active probes address `cgroup.procs`; the held membership reader
    /// addresses `cgroup.threads`. Results, PID scalars, parser iterators and
    /// repeated observations of those same paths are memory, not new entries.
    pub const METADATA_ENTRIES_V1: usize = 2;

    /// Samples this held cgroup once and requires only this process leader's PID/TID.
    ///
    /// # Errors
    ///
    /// Retains the original active/open/read/malformed/membership refusal and
    /// executes the independent trailing active observation after entered work.
    /// Reentry performs no further native IO.
    pub fn capture_current_only_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.capture_once(anchor, false)
    }

    /// Requires no direct tasks after moving only the actual owning process.
    ///
    /// This shares the original native reader and both active bookends. It
    /// observes only the held cgroup, never a global process table or a PID
    /// supplied by a caller. Descendant population is a separate observation.
    ///
    /// # Errors
    /// Retains incomplete/native failures and every nonempty direct task set.
    pub fn capture_empty_once_v2(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.capture_once(anchor, true)
    }

    fn capture_once(&mut self, anchor: &RetainedCgroupAnchor, expected_empty: bool) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(refused());
        }
        self.entered = true;
        self.process = (!expected_empty).then(std::process::id);
        self.before = Some(anchor.validate_active_retaining(&mut self.before_probe));
        if !matches!(self.before, Some(Ok(()))) {
            self.first = Some(First::Before);
        } else {
            self.open = Some(anchor.root.open_regular_retaining(Path::new("cgroup.threads"), &mut self.opening));
            if !matches!(self.open, Some(Ok(()))) {
                self.first = Some(First::Open);
            } else {
                self.file = self.opening.take_readable_file();
                let Some(file) = self.file.as_ref() else {
                    std::process::abort();
                };
                self.read = Some(file.read_at(&mut self.bytes, 0));
                match self.read.as_ref() {
                    Some(Ok(length)) => {
                        self.tail_read = Some(file.read_at(&mut self.tail, *length as u64));
                        self.membership = Some(match self.tail_read.as_ref() {
                            Some(Ok(0)) if expected_empty && *length == 0 => Ok(()),
                            Some(Ok(0)) if !expected_empty => require_only_current_task(&self.bytes, *length),
                            _ => Err(Error::invalid("worker cgroup members", "native record is incomplete")),
                        });
                        if self.tail_read.as_ref().is_some_and(|result| result.is_err()) {
                            self.first = Some(First::Tail);
                        } else if !matches!(self.membership, Some(Ok(()))) {
                            self.first = Some(First::Membership);
                        }
                    }
                    _ => { self.first = Some(First::Read); }
                }
            }
        }
        // This exact anchor observation remains owed after any primary error.
        self.after = Some(anchor.validate_active_retaining(&mut self.after_probe));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        self.completed = self.first.is_none();
        if self.completed {
            Ok(())
        } else {
            Err(refused())
        }
    }

    /// Disposes only the completed local native sample after caller posts.
    ///
    /// # Errors
    ///
    /// Refuses failed/incomplete observations without releasing originals.
    pub fn dispose_positive_after_posts_v1(&mut self) -> Result<()> {
        if !self.completed || self.first.is_some() || self.disposed {
            return Err(refused());
        }
        self.before_probe = PendingRegularFileV1::default();
        self.opening = PendingRegularFileV1::default();
        drop(self.file.take());
        self.after_probe = PendingRegularFileV1::default();
        self.disposed = true;
        Ok(())
    }

    /// Borrows the original chronological native or semantic cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(value: &Option<std::result::Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            value.as_ref()?.as_ref().err().map(|error| error as _)
        }
        match self.first? {
            First::Before => cause(&self.before),
            First::Open => cause(&self.open),
            First::Read => cause(&self.read),
            First::Tail => cause(&self.tail_read),
            First::Membership => cause(&self.membership),
            First::After => cause(&self.after),
            First::Closed => Some(&REFUSED),
        }
    }
}

fn require_only_current_task(bytes: &[u8; 4097], length: usize) -> Result<()> {
    if length == 0 || length == bytes.len() {
        return Err(Error::invalid("worker cgroup members", "empty or oversized native record"));
    }
    let text = std::str::from_utf8(&bytes[..length])
        .map_err(|_| Error::invalid("worker cgroup members", "native record is not UTF-8"))?;
    let mut rows = text.lines();
    let actual = rows.next().filter(|row| !row.is_empty()
        && row.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|row| row.parse::<u32>().ok());
    if actual != Some(std::process::id()) || rows.next().is_some() {
        return Err(Error::invalid("worker cgroup members", "requires exactly the current process"));
    }
    Ok(())
}

static REFUSED: ObservationRefused = ObservationRefused;

#[derive(Debug, thiserror::Error)]
#[error("held worker cgroup current-task observation refused")]
struct ObservationRefused;

fn refused() -> Error {
    Error::invalid("worker cgroup members", "actual native original retained")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately invalid native input. Ordinary control-file names cannot
    // substitute for the cgroup2 filesystem checked by both real bookends.
    fn ordinary_directory_anchor(path: &Path) -> RetainedCgroupAnchor {
        let root = crate::path::BeneathRoot::from_owned(std::fs::File::open(path).unwrap().into()).unwrap();
        RetainedCgroupAnchor { kernel_id: root.identity().inode, root }
    }

    #[test]
    fn empty_ordinary_directory_retains_both_real_native_refusals() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cgroup.procs"), b"").unwrap();
        std::fs::write(directory.path().join("cgroup.threads"), b"").unwrap();
        let anchor = ordinary_directory_anchor(directory.path());
        let mut empty = CgroupSingleTaskObservationV1::new();

        assert!(empty.capture_empty_once_v2(&anchor).is_err());

        assert!(matches!(empty.before, Some(Err(Error::WrongDescriptorType { .. }))));
        assert!(matches!(empty.after, Some(Err(Error::WrongDescriptorType { .. }))));
        assert!(empty.file.is_none());
        assert!(empty.membership.is_none());
        assert!(empty.dispose_positive_after_posts_v1().is_err());
        let first = empty.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(empty.capture_empty_once_v2(&anchor).is_err());

        assert_eq!(empty.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        assert!(matches!(empty.after, Some(Err(Error::WrongDescriptorType { .. }))));
    }

    #[test]
    fn matching_task_file_cannot_upgrade_an_ordinary_directory_to_a_cgroup() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cgroup.procs"), b"").unwrap();
        std::fs::write(directory.path().join("cgroup.threads"), format!("{}\n", std::process::id())).unwrap();
        let anchor = ordinary_directory_anchor(directory.path());
        let mut occupied = CgroupSingleTaskObservationV1::new();

        assert!(occupied.capture_current_only_once(&anchor).is_err());

        assert!(matches!(occupied.before, Some(Err(Error::WrongDescriptorType { .. }))));
        assert!(matches!(occupied.after, Some(Err(Error::WrongDescriptorType { .. }))));
        assert!(occupied.read.is_none());
        assert!(occupied.membership.is_none());
        assert!(occupied.failure().is_some());
        assert!(occupied.dispose_positive_after_posts_v1().is_err());
        assert!(occupied.file.is_none());
    }

    fn record(text: &str) -> ([u8; 4097], usize) {
        let mut bytes = [0; 4097];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        (bytes, text.len())
    }

    #[test]
    fn sole_current_process_is_distinct_from_empty_foreign_and_remaining_members() {
        let actual = std::process::id();
        let (bytes, length) = record(&format!("{actual}\n"));
        require_only_current_task(&bytes, length).unwrap();

        for text in [String::new(), format!("{}\n", actual.saturating_add(1)),
            format!("{actual}\n{actual}\n"), format!("+{actual}\n")]
        {
            let (bytes, length) = record(&text);
            assert!(require_only_current_task(&bytes, length).is_err());
        }
    }
}
