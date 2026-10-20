//! Owns two complete fixed Network worker-forest observations.
//!
//! The enrolled daemon is the only allowed child. Its named inode must match
//! the continuously held main anchor. Any other directory, including an empty
//! stale unit or unknown name, blocks absence. No task is moved or killed and
//! neither this observation nor its native anchors grants service authority.

use super::*;
use std::mem::MaybeUninit;

/// Reports an incomplete or nonempty worker forest while originals stay held.
#[derive(Debug, thiserror::Error)]
#[error("Network worker forest is incomplete, changed or contains a residual")]
pub struct NetworkWorkerCgroupAbsenceRefusalV4;

fn closed() -> Error {
    Error::InvalidInput {
        field: "Network worker forest",
        message: "the fixed enrolled daemon is missing, changed or not the only directory"
            .to_owned(),
    }
}

#[derive(Clone, Copy)]
enum First {
    AggregateBefore,
    MainBefore,
    Directory,
    AggregateAfter,
    MainAfter,
    Closed,
}

struct Round {
    active: [CgroupActiveOriginalV2; 4],
    active_result: [Option<Result<()>>; 4],
    directory: Option<rustix::io::Result<OwnedFd>>,
    raw: [MaybeUninit<u8>; 4096],
    first_child: [u8; 256],
    first_child_bytes: usize,
    main_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    main_identity: Option<Result<()>>,
    directory_result: Option<Result<()>>,
    aggregate_id: Option<(u64, u64)>,
    main_id: Option<(u64, u64)>,
    first: Option<First>,
    main_seen: bool,
    complete: bool,
}

impl Round {
    fn new() -> Self {
        Self {
            active: std::array::from_fn(|_| CgroupActiveOriginalV2::new()),
            active_result: std::array::from_fn(|_| None),
            directory: None,
            raw: [MaybeUninit::uninit(); 4096],
            first_child: [0; 256],
            first_child_bytes: 0,
            main_stat: None,
            main_identity: None,
            directory_result: None,
            aggregate_id: None,
            main_id: None,
            first: None,
            main_seen: false,
            complete: false,
        }
    }

    fn capture(&mut self, aggregate: &RetainedCgroupAnchor, main: &RetainedCgroupAnchor) {
        self.aggregate_id = Some((aggregate.root.identity().device, aggregate.kernel_id()));
        self.main_id = Some((main.root.identity().device, main.kernel_id()));
        self.active_result[0] = Some(self.active[0].capture_once_v2(aggregate));
        if !matches!(self.active_result[0], Some(Ok(()))) {
            self.first = Some(First::AggregateBefore);
        }
        self.active_result[1] = Some(self.active[1].capture_once_v2(main));
        if !matches!(self.active_result[1], Some(Ok(()))) {
            self.first.get_or_insert(First::MainBefore);
        }
        if self.first.is_none() {
            self.capture_directory(aggregate, main);
            if !matches!(self.directory_result, Some(Ok(()))) {
                self.first.get_or_insert(First::Directory);
            }
        }

        // Both independently prearmed posts are owed after any before/open/
        // directory/identity failure. A failed first post skips neither second.
        self.active_result[2] = Some(self.active[2].capture_once_v2(aggregate));
        if !matches!(self.active_result[2], Some(Ok(()))) {
            self.first.get_or_insert(First::AggregateAfter);
        }
        self.active_result[3] = Some(self.active[3].capture_once_v2(main));
        if !matches!(self.active_result[3], Some(Ok(()))) {
            self.first.get_or_insert(First::MainAfter);
        }
        self.complete = self.first.is_none() && self.main_seen;
    }

    fn capture_directory(&mut self, aggregate: &RetainedCgroupAnchor, main: &RetainedCgroupAnchor) {
        self.directory = Some(rustix::fs::openat(
            aggregate.as_fd(),
            c".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ));
        let Some(Ok(directory)) = self.directory.as_ref() else {
            return;
        };
        let expected = (main.root.identity().device, main.kernel_id());
        let main_seen = &mut self.main_seen;
        let main_stat = &mut self.main_stat;
        let main_identity = &mut self.main_identity;
        self.directory_result = Some(super::host_inventory::require_no_child_directories_v6(
            directory.as_fd(),
            &mut self.raw,
            &mut self.first_child,
            &mut self.first_child_bytes,
            &mut |name, kind| {
                if name.to_bytes() != b"aos-netd.service" {
                    return Ok(false);
                }
                if *main_seen {
                    return Err(closed());
                }
                *main_seen = true;
                if kind != rustix::fs::FileType::Directory {
                    return Err(closed());
                }
                *main_stat = Some(rustix::fs::statat(
                    directory.as_fd(),
                    name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                ));
                *main_identity = Some(match main_stat.as_ref() {
                    Some(Ok(stat))
                        if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                            == rustix::fs::FileType::Directory
                            && (stat.st_dev, stat.st_ino) == expected =>
                    {
                        Ok(())
                    }
                    Some(Ok(_)) => Err(closed()),
                    Some(Err(source)) => Err(Error::Syscall {
                        operation: "fstatat(Network enrolled main)",
                        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                    }),
                    None => Err(closed()),
                });
                match main_identity.as_ref() {
                    Some(Ok(())) => Ok(true),
                    _ => Err(closed()),
                }
            },
        ));
        if matches!(self.directory_result, Some(Ok(()))) && !self.main_seen {
            self.directory_result = Some(Err(closed()));
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::AggregateBefore => self.active[0].failure().map(|cause| cause as _),
            First::MainBefore => self.active[1].failure().map(|cause| cause as _),
            First::AggregateAfter => self.active[2].failure().map(|cause| cause as _),
            First::MainAfter => self.active[3].failure().map(|cause| cause as _),
            First::Directory => self
                .directory
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    self.main_stat
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.main_identity
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.directory_result
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|cause| cause as _)
                }),
            First::Closed => Some(&NetworkWorkerCgroupAbsenceRefusalV4),
        }
    }
}

/// Retains two whole forest rounds and all independently owed native posts.
///
/// The genuine fixed Network F prepays this supplier and supplies its private
/// actual aggregate/main anchors. This mechanical owner adopts no paths or
/// descriptors and provides no account, child or resource-completion authority.
#[must_use = "retain both whole native rounds through the enclosing F posts"]
pub struct NetworkWorkerCgroupAbsenceOriginalV4 {
    rounds: [Round; 2],
    next: usize,
    failed_round: Option<usize>,
    closed: bool,
}

impl NetworkWorkerCgroupAbsenceOriginalV4 {
    /// Creates inert destinations without allocation or native work.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rounds: std::array::from_fn(|_| Round::new()),
            next: 0,
            failed_round: None,
            closed: false,
        }
    }

    /// Bounds actual native owners, directory scratch and fixed lookup names.
    #[must_use]
    pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(active.0.checked_mul(8)?)?
                .checked_add(4 * std::mem::size_of::<rustix::fs::RawDir<'_, BorrowedFd<'_>>>())?
                .checked_add(12 * 256)?,
            active.1.checked_mul(8)?.checked_add(2)?,
            // Per round: four cgroup.procs opens, one dot directory open and
            // the one literal named main fstatat. Rust fields add no names.
            active.2.checked_mul(8)?.checked_add(4)?,
        ))
    }

    /// Captures the next fixed round on the continuously held native inputs.
    ///
    /// Round two remains independently callable after round-one failure; no
    /// healthy financial gate or replacement input can be inferred here.
    ///
    /// # Errors
    /// Keeps the original native/identity failure, residual name and all posts.
    pub fn capture_next_once_v4(
        &mut self,
        aggregate: &RetainedCgroupAnchor,
        main: &RetainedCgroupAnchor,
    ) -> std::result::Result<(), NetworkWorkerCgroupAbsenceRefusalV4> {
        if self.closed || self.next == 2 {
            self.closed = true;
            return Err(NetworkWorkerCgroupAbsenceRefusalV4);
        }
        let round = self.next;
        self.next += 1;
        self.rounds[round].capture(aggregate, main);
        if !self.rounds[round].complete
            || (round == 1
                && (self.rounds[0].aggregate_id != self.rounds[1].aggregate_id
                    || self.rounds[0].main_id != self.rounds[1].main_id))
        {
            self.rounds[round].first.get_or_insert(First::Closed);
            self.failed_round.get_or_insert(round);
        }
        if self.failed_round.is_some() {
            Err(NetworkWorkerCgroupAbsenceRefusalV4)
        } else {
            Ok(())
        }
    }

    /// Reports both fully completed same-input rounds without performing IO.
    #[must_use]
    pub fn completed_v4(&self) -> bool {
        !self.closed
            && self.next == 2
            && self.failed_round.is_none()
            && self.rounds.iter().all(|round| round.complete)
    }

    /// Borrows the first real cause without selecting a later owed failure.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failed_round
            .and_then(|round| self.rounds[round].failure())
            .or_else(|| {
                self.closed
                    .then_some(&NetworkWorkerCgroupAbsenceRefusalV4 as _)
            })
    }
}

impl Default for NetworkWorkerCgroupAbsenceOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}
