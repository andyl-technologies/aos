//! Retains complete empty-cgroup observations for the three Host runtime trees.
//!
//! Fixed locators select payloads, Guardians and Host-owned FUSE workers. Every
//! native directory, population read and independent root post stays owned.
//! A populated tree or even an empty child directory prevents absence. Missing
//! trees count only through the actual strict-resolution ENOENT plus root post.
//! This mechanical observation grants no service, cleanup or resource authority.

use super::*;
use std::mem::MaybeUninit;

mod owned_cleanup;
use owned_cleanup::{OwnedCensusV8, OwnedTreeV8};

const TREES: [&str; 3] = [
    "aos.slice/aos-sandboxes.slice",
    "aos.slice/aos-assignment.slice/aos-assignment-guardians.slice",
    "aos.slice/aos-view.slice/aos-view-workers.slice",
];

/// Reports refusal while the actual native census remains owned.
#[derive(Debug, thiserror::Error)]
#[error("Host runtime cgroup census is incomplete or contains a residual")]
pub struct HostRuntimeCgroupAbsenceRefusalV5;

struct Tree {
    opening: WorkerCgroupOpeningV1,
    descendant: Option<std::result::Result<(), WorkerCgroupOpeningRefusalV1>>,
    root_post: Option<std::result::Result<(), WorkerCgroupOpeningRefusalV1>>,
    population_open: Option<std::result::Result<(), WorkerCgroupOpeningRefusalV1>>,
    population: CgroupPopulationObservationV1,
    population_empty: Option<Result<()>>,
    population_read: Option<std::result::Result<(), CgroupPopulationObservationRefusalV1>>,
    direct_tasks: Option<Box<CgroupSingleTaskObservationV1>>,
    selected_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    selected_identity: Option<Result<()>>,
    directory: Option<rustix::io::Result<OwnedFd>>,
    raw: [MaybeUninit<u8>; 4096],
    directory_result: Option<Result<()>>,
    first_child: [u8; 256],
    first_child_bytes: usize,
    missing: bool,
    complete: bool,
}

impl Tree {
    fn new() -> Self {
        Self {
            opening: WorkerCgroupOpeningV1::new(),
            descendant: None,
            root_post: None,
            population_open: None,
            population: CgroupPopulationObservationV1::new(),
            population_read: None,
            population_empty: None,
            direct_tasks: None,
            selected_stat: None,
            selected_identity: None,
            directory: None,
            raw: [MaybeUninit::uninit(); 4096],
            directory_result: None,
            first_child: [0; 256],
            first_child_bytes: 0,
            missing: false,
            complete: false,
        }
    }

    fn capture(&mut self, root: &CgroupV2Root, path: &str, selected: Option<OwnedTreeV8>) {
        self.capture_primary(root, path, selected);

        // This same-root post is owed after the entire entered tree read,
        // including missing paths, populated trees and directory failures.
        self.root_post = Some(self.opening.observe_root_parent_after_attempt_once(root));
        if !matches!(self.root_post, Some(Ok(()))) {
            self.complete = false;
        }
    }

    fn capture_primary(&mut self, root: &CgroupV2Root, path: &str, selected: Option<OwnedTreeV8>) {
        self.descendant = Some(
            self.opening
                .capture_root_descendant_once(root, Path::new(path)),
        );
        if !matches!(self.descendant, Some(Ok(()))) {
            self.missing = self
                .opening
                .failure()
                .and_then(|cause| cause.downcast_ref::<Error>())
                .is_some_and(|cause| {
                    matches!(cause, Error::Syscall { source, .. }
                    if source.raw_os_error() == Some(libc::ENOENT))
                });
        }

        if self.missing {
            self.complete = selected.is_none();
            if selected.is_some() {
                self.selected_identity = Some(Err(owned_cleanup::refused()));
            }
            return;
        }
        if !matches!(self.descendant, Some(Ok(()))) {
            return;
        }

        self.population_open = Some(self.opening.capture_population_once());
        if !matches!(self.population_open, Some(Ok(()))) {
            return;
        }
        let Some(monitor) = self.opening.population() else {
            return;
        };
        self.population_read = Some(monitor.observe_state_retaining_v1(&mut self.population));
        if !matches!(self.population_read, Some(Ok(()))) {
            return;
        }
        self.population_empty = Some(
            if (selected.is_none() && self.population.state() == Some(CgroupPopulationState::Empty))
                || (selected.is_some() && self.population.state() == Some(CgroupPopulationState::Populated)) {
                Ok(())
            } else {
                Err(Error::invalid(
                    "Host runtime tree population",
                    "is populated or retired",
                ))
            },
        );
        if !matches!(self.population_empty, Some(Ok(()))) {
            return;
        }

        let Some(anchor) = self.opening.anchor() else {
            return;
        };
        if selected.is_some() {
            // The owned supplier prepaid all four actual readers before the
            // global census. Empty mode constructs no dormant task buffers.
            self.direct_tasks = Some(Box::new(CgroupSingleTaskObservationV1::new()));
            if self.direct_tasks.as_mut().is_none_or(|tasks| tasks.capture_empty_once_v2(anchor).is_err()) {
                return;
            }
        }
        self.directory = Some(rustix::fs::openat(
            anchor.as_fd(),
            Path::new("."),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ));
        let Some(Ok(directory)) = self.directory.as_ref() else {
            return;
        };
        self.directory_result = Some(match selected {
            Some(selected) => owned_cleanup::require_selected_child_v8(
                directory.as_fd(), &mut self.raw, &mut self.first_child,
                &mut self.first_child_bytes, selected, &mut self.selected_stat,
                &mut self.selected_identity,
            ),
            None => require_no_child_directories_v6(
                directory.as_fd(), &mut self.raw, &mut self.first_child,
                &mut self.first_child_bytes, &mut |_, _| Ok(false),
            ),
        });
        self.complete = matches!(self.directory_result, Some(Ok(())));
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.missing && let Some(Err(cause)) = self.selected_identity.as_ref() {
            return Some(cause);
        }
        if !self.missing && !matches!(self.descendant, Some(Ok(()))) {
            return self.opening.failure();
        }
        if !self.missing {
            if !matches!(self.population_open, Some(Ok(()))) {
                return self.opening.failure();
            }
            if let Some(cause) = self.population.failure() {
                return Some(cause);
            }
            if let Some(Err(cause)) = self.population_empty.as_ref() {
                return Some(cause);
            }
            if let Some(cause) = self.direct_tasks.as_ref().and_then(|tasks| tasks.failure()) {
                return Some(cause);
            }
            if let Some(Err(cause)) = self.directory.as_ref() {
                return Some(cause);
            }
            if let Some(Err(cause)) = self.selected_identity.as_ref() {
                return Some(cause);
            }
            if let Some(Err(cause)) = self.directory_result.as_ref() {
                return Some(cause);
            }
        }
        self.opening
            .owed_parent_failure_v5()
            .map(|cause| cause as _)
    }
}


// Both roles use one native getdents/parser/error body. The Host caller's
// inert callback permits no residual; Network permits only its same held main.
pub(super) fn require_no_child_directories_v6(
    directory: BorrowedFd<'_>,
    raw: &mut [MaybeUninit<u8>; 4096],
    first_child: &mut [u8; 256],
    first_child_bytes: &mut usize,
    allow: &mut impl FnMut(&std::ffi::CStr, rustix::fs::FileType) -> Result<bool>,
) -> Result<()> {
    let mut entries = rustix::fs::RawDir::new(directory, raw);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|source| Error::Syscall {
            operation: "getdents64(Host runtime tree)",
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if allow(entry.file_name(), entry.file_type())? {
            continue;
        }
        match entry.file_type() {
            rustix::fs::FileType::RegularFile => {}
            _ => {
                // Preserve the first residual name without allocating a
                // topology-sized list. Any child blocks total absence.
                let length = name.len().min(first_child.len());
                first_child[..length].copy_from_slice(&name[..length]);
                *first_child_bytes = length;
                return Err(Error::invalid(
                    "Host runtime tree",
                    "contains a child or unknown entry",
                ));
            }
        }
    }
    Ok(())
}

/// Owns both complete fixed-tree rounds and their original root identity.
#[must_use = "retain all native census originals through the enclosing posts"]
pub struct HostRuntimeCgroupAbsenceOriginalV5 {
    duplicate: [Option<rustix::io::Result<OwnedFd>>; 2],
    root_original: [RuntimeScopeCgroupOriginalV1; 2],
    root_result: [Option<Result<()>>; 2],
    root: [Option<CgroupV2Root>; 2],
    anchor: [Option<RetainedCgroupAnchor>; 2],
    trees: [[Tree; 3]; 2],
    owned: [Option<OwnedCensusV8>; 2],
    changed_mode: Option<usize>,
    next: usize,
    failed_round: Option<usize>,
    closed: bool,
}

impl HostRuntimeCgroupAbsenceOriginalV5 {
    /// Creates inert fixed destinations without allocation or native work.
    #[must_use]
    pub fn new() -> Self {
        Self {
            duplicate: std::array::from_fn(|_| None),
            root_original: std::array::from_fn(|_| RuntimeScopeCgroupOriginalV1::new()),
            root_result: std::array::from_fn(|_| None),
            root: std::array::from_fn(|_| None),
            anchor: std::array::from_fn(|_| None),
            trees: std::array::from_fn(|_| std::array::from_fn(|_| Tree::new())),
            owned: [None; 2],
            changed_mode: None,
            next: 0,
            failed_round: None,
            closed: false,
        }
    }

    /// Bounds all native files, fixed names, construction and failure storage.
    #[must_use]
    pub fn receiving_obligations_v5() -> Option<(usize, usize, usize)> {
        let (root_bytes, root_files, root_names) =
            RuntimeScopeCgroupOriginalV1::receiving_demand_v1()?;
        let each = WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(2 * std::mem::size_of::<rustix::fs::RawDir<'_, BorrowedFd<'_>>>())?
            .checked_add(3 * 256)?;
        let path_bytes = TREES
            .iter()
            .try_fold(0usize, |sum, path| sum.checked_add(path.len()))?;
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(root_bytes.checked_mul(2)?)?
                .checked_add(each.checked_mul(6)?)?
                .checked_add(path_bytes.checked_mul(4)?)?,
            root_files
                .checked_mul(2)?
                .checked_add((WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1 + 1) * 6)?,
            // Three strict path component chains (2+3+3), each reached twice;
            // each child has actual active/population names and a dot open.
            root_names.checked_mul(2)?.checked_add(2 * (8 + 3 * 7))?,
        ))
    }

    /// Captures the next fixed round under the actual installed worker root.
    ///
    /// Round two remains independently owed after a failed first round. No
    /// healthy gate, reset, effect, replacement root or scalar scope is used.
    ///
    /// # Errors
    /// Retains every reached original and refuses nonempty, changed or failed
    /// trees. Reentry never performs another native census.
    pub fn capture_next_once_v5(
        &mut self,
        actual_root: &BeneathRoot,
    ) -> std::result::Result<(), HostRuntimeCgroupAbsenceRefusalV5> {
        self.capture_next_internal_v8(actual_root, None)
    }

    fn capture_next_internal_v8(
        &mut self, actual_root: &BeneathRoot, selected: Option<OwnedCensusV8>,
    ) -> std::result::Result<(), HostRuntimeCgroupAbsenceRefusalV5> {
        if self.closed || self.next == 2 {
            self.closed = true;
            return Err(HostRuntimeCgroupAbsenceRefusalV5);
        }
        let round = self.next;
        self.next += 1;
        self.owned[round] = selected;
        if selected.is_some_and(|scope| !scope.valid_v8())
            || (round == 1 && self.owned[0] != self.owned[1]) {
            self.changed_mode.get_or_insert(round);
            self.failed_round.get_or_insert(round);
        }
        self.duplicate[round] = Some(rustix::io::fcntl_dupfd_cloexec(actual_root.as_fd(), 0));
        if matches!(self.duplicate[round], Some(Ok(_))) {
            let Some(Ok(descriptor)) = self.duplicate[round].take() else {
                std::process::abort();
            };
            self.root_result[round] = Some(self.root_original[round].capture_once(descriptor));
            if matches!(self.root_result[round], Some(Ok(()))) {
                if let Some((root, anchor)) = self.root_original[round].take_completed_once() {
                    self.root[round] = Some(root);
                    self.anchor[round] = Some(anchor);
                }
            }
        }
        let Some(root) = self.root[round].as_ref() else {
            self.failed_round.get_or_insert(round);
            return Err(HostRuntimeCgroupAbsenceRefusalV5);
        };
        for (index, (tree, path)) in self.trees[round].iter_mut().zip(TREES).enumerate() {
            tree.capture(root, path, selected.and_then(|scope| scope.tree_v8(index)));
        }
        if self.trees[round].iter().any(|tree| !tree.complete)
            || (round == 1
                && self.anchor[0].as_ref().map(RetainedCgroupAnchor::kernel_id)
                    != self.anchor[1].as_ref().map(RetainedCgroupAnchor::kernel_id))
        {
            self.failed_round.get_or_insert(round);
        }
        if self.failed_round.is_some() {
            Err(HostRuntimeCgroupAbsenceRefusalV5)
        } else {
            Ok(())
        }
    }

    /// Reports both actual completed empty rounds, without new IO.
    #[must_use]
    pub fn completed_v5(&self) -> bool {
        self.owned.iter().all(Option::is_none) && self.completed_internal_v8()
    }

    fn completed_internal_v8(&self) -> bool {
        !self.closed
            && self.next == 2
            && self.failed_round.is_none()
            && self.trees.iter().flatten().all(|tree| tree.complete)
    }

    /// Borrows the earliest original native cause without replacing it.
    #[must_use]
    pub fn failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let round = self.failed_round?;
        if self.changed_mode == Some(round) {
            return Some(&HostRuntimeCgroupAbsenceRefusalV5);
        }
        if let Some(Err(cause)) = self.duplicate[round].as_ref() {
            return Some(cause);
        }
        if let Some(cause) = self.root_original[round].failure() {
            return Some(cause);
        }
        self.trees[round]
            .iter()
            .find_map(Tree::failure)
            .or(Some(&HostRuntimeCgroupAbsenceRefusalV5))
    }
}

impl Default for HostRuntimeCgroupAbsenceOriginalV5 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_first_root_does_not_skip_the_independent_native_round_or_replace_its_cause() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();
        let mut original = HostRuntimeCgroupAbsenceOriginalV5::new();

        assert!(original.capture_next_once_v5(&root).is_err());
        let first = original.failure_v5().unwrap() as *const dyn std::error::Error as *const ();
        assert!(
            original.root_result[0]
                .as_ref()
                .is_some_and(|result| result.is_err())
        );
        assert!(original.root_result[1].is_none());
        assert!(original.capture_next_once_v5(&root).is_err());
        assert!(
            original.root_result[1]
                .as_ref()
                .is_some_and(|result| result.is_err())
        );
        assert_eq!(
            original.failure_v5().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(!original.completed_v5());

        assert!(original.capture_next_once_v5(&root).is_err());
        assert_eq!(
            original.failure_v5().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(rustix::fs::fstat(root.as_fd()).is_ok());
    }
}

#[cfg(test)]
mod network_forest_directory_tests {
    use super::*;

    fn open(path: &std::path::Path, flags: rustix::fs::OFlags) -> OwnedFd {
        rustix::fs::open(
            path,
            flags | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn real_empty_child_still_blocks_the_complete_directory_census() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(temporary.path().join("cgroup.procs"), b"123").unwrap();
        std::fs::create_dir(temporary.path().join("untracked-worker.service")).unwrap();
        let directory = open(temporary.path(), rustix::fs::OFlags::RDONLY);
        let mut raw = [MaybeUninit::uninit(); 4096];
        let mut name = [0; 256];
        let mut length = 0;

        let result = require_no_child_directories_v6(
            directory.as_fd(),
            &mut raw,
            &mut name,
            &mut length,
            &mut |_, _| Ok(false),
        );

        assert!(result.is_err());
        assert_eq!(&name[..length], b"untracked-worker.service");
        assert!(rustix::fs::fstat(&directory).is_ok());
    }

    #[test]
    fn named_main_allowance_does_not_hide_any_other_directory_or_symlink() {
        for residual in [
            "second.service",
            "aos-sandbox-network-worker@orphan.service",
        ] {
            let temporary = tempfile::tempdir().unwrap();
            std::fs::create_dir(temporary.path().join("aos-netd.service")).unwrap();
            std::fs::create_dir(temporary.path().join(residual)).unwrap();
            let directory = open(temporary.path(), rustix::fs::OFlags::RDONLY);
            let mut raw = [MaybeUninit::uninit(); 4096];
            let mut name = [0; 256];
            let mut length = 0;
            let result = require_no_child_directories_v6(
                directory.as_fd(),
                &mut raw,
                &mut name,
                &mut length,
                &mut |name, kind| {
                    Ok(name.to_bytes() == b"aos-netd.service"
                        && kind == rustix::fs::FileType::Directory)
                },
            );
            assert!(result.is_err());
            assert_eq!(&name[..length], residual.as_bytes());
        }
        let temporary = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("elsewhere", temporary.path().join("foreign")).unwrap();
        let directory = open(temporary.path(), rustix::fs::OFlags::RDONLY);
        let mut raw = [MaybeUninit::uninit(); 4096];
        let mut name = [0; 256];
        let mut length = 0;
        assert!(
            require_no_child_directories_v6(
                directory.as_fd(),
                &mut raw,
                &mut name,
                &mut length,
                &mut |_, _| Ok(false)
            )
            .is_err()
        );
        assert_eq!(&name[..length], b"foreign");
    }

    #[test]
    fn actual_getdents_error_keeps_the_original_directory_and_raw_errno() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = open(temporary.path(), rustix::fs::OFlags::PATH);
        let mut raw = [MaybeUninit::uninit(); 4096];
        let mut name = [0; 256];
        let mut length = 0;

        let result = require_no_child_directories_v6(
            directory.as_fd(),
            &mut raw,
            &mut name,
            &mut length,
            &mut |_, _| Ok(false),
        );

        let Error::Syscall { source, .. } = result.as_ref().unwrap_err() else {
            panic!("native errno lost")
        };
        assert_eq!(source.raw_os_error(), Some(libc::EBADF));
        assert_eq!(length, 0);
        assert!(rustix::fs::fstat(&directory).is_ok());
    }
}
