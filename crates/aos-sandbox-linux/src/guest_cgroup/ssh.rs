//! Owns one newly created SSH subtree from fixed limits through actual child reap.
//!
//! The Guest's authenticated execution and original financial owner remain the
//! authority. This native owner accepts only finite denial DATA, creates its
//! own fresh child scope and never adopts a caller PID or persisted cgroup.
//! The same live Process must retain this owner before invoking its spawn port.

use std::os::fd::{AsFd as _, BorrowedFd};

use crate::cgroup::{
    CgroupActiveOriginalV2, CgroupKillAttemptV1, CgroupPopulationMonitor,
    CgroupPopulationMonitorOriginalV3, CgroupPopulationObservationV1, CgroupPopulationState,
    CgroupSingleTaskObservationV1, MemoryLimitReadbackV1, PidsLimitReadbackV1,
    RetainedCgroupAnchor,
};
use crate::process::{FixedProcessCaptureCutV3, GuestSshProcessOriginalV1};
use crate::{Error, Result};

use super::{control::ControlWriteOriginalV1, directory::DirectoryOriginalV1};

enum LimitReader {
    Pids(PidsLimitReadbackV1),
    Memory(MemoryLimitReadbackV1),
}

pub(super) mod source;
mod standing;

pub use standing::GuestSshStandingOriginalV1;

impl LimitReader {
    fn capture(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        match self {
            Self::Pids(reader) => reader.capture_once(anchor).map_err(|_| closed()),
            Self::Memory(reader) => reader.capture_once(anchor).map_err(|_| closed()),
        }
    }

    fn finish(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        match self {
            Self::Pids(reader) => reader.recheck_once(anchor).map_err(|_| closed()),
            Self::Memory(reader) => reader.recheck_once(anchor).map_err(|_| closed()),
        }
    }

    fn matches(&self, expected: &[u8]) -> bool {
        match self {
            Self::Pids(reader) => {
                reader.initial_bytes() == Some(expected) && reader.final_bytes() == Some(expected)
            }
            Self::Memory(reader) => {
                reader.initial_bytes() == Some(expected) && reader.final_bytes() == Some(expected)
            }
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pids(reader) => reader.failure().map(|cause| cause as _),
            Self::Memory(reader) => reader.failure().map(|cause| cause as _),
        }
    }
}

/// Keeps actual SSH scope, native child and every reached negative prefix.
///
/// Construction performs no IO. Its methods neither reserve resources nor
/// authenticate a request; the selected Guest caller prepays the full source
/// and binds it to the same live execution before native entry.
pub struct GuestSshScopeOriginalV1 {
    execution: [u8; 16],
    memory: u64,
    nofile: u32,
    deadline: u64,
    execution_deadline: u64,
    wall: i64,
    cut: Option<FixedProcessCaptureCutV3>,
    clock: crate::process::capture_cut::CaptureProcessCutOriginalV3,
    directory: Option<Box<DirectoryOriginalV1>>,
    anchor: Option<std::sync::Arc<RetainedCgroupAnchor>>,
    writer: Option<Box<ControlWriteOriginalV1>>,
    reader: Option<Box<LimitReader>>,
    reader_primary: Option<Result<()>>,
    reader_after: Option<Result<()>>,
    empty: Option<Box<CgroupSingleTaskObservationV1>>,
    population_open: Option<Box<CgroupPopulationMonitorOriginalV3>>,
    population: Option<CgroupPopulationMonitor>,
    prepare: Option<Result<()>>,
    prepare_after: Option<Box<CgroupActiveOriginalV2>>,
    spawn: Option<Box<GuestSshProcessOriginalV1>>,
    standing_taken: bool,
    retirement_wait: Option<Result<Option<i32>>>,
    closed: Option<Error>,
    finished: bool,
    source: Option<source::GuestSshBirthSourceDataV1>,
}

impl Default for GuestSshScopeOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestSshScopeOriginalV1 {
    /// Creates inert once-only native destinations without allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            execution: [0; 16],
            memory: 0,
            nofile: 0,
            deadline: 0,
            wall: 0,
            execution_deadline: 0,
            cut: None,
            clock: Default::default(),
            directory: None,
            anchor: None,
            writer: None,
            reader: None,
            reader_primary: None,
            reader_after: None,
            empty: None,
            population_open: None,
            population: None,
            prepare: None,
            prepare_after: None,
            spawn: None,
            standing_taken: false,
            retirement_wait: None,
            closed: None,
            finished: false,
            source: None,
        }
    }

    /// Creates only the exact execution's fresh `ssh-<execution>` descendant.
    ///
    /// Memory and the fixed four-task ceiling are written and independently
    /// read back before any child exists. The original absolute BOOTTIME and
    /// signed WALL endpoints only deny later work; no duration is started here.
    ///
    /// # Errors
    /// Retains invalid/repeated entry, occupied names, failed native writes,
    /// readbacks or owed posts. A negative never opens the spawn port.
    pub fn prepare_once_v1(
        &mut self,
        source: &source::GuestSshBirthSourceOriginalV1,
        root: &RetainedCgroupAnchor,
        execution: [u8; 16],
        memory: u64,
        nofile: u32,
        deadline: u64,
        execution_deadline: u64,
        wall: i64,
    ) -> Result<()> {
        if self.prepare.is_some() || self.directory.is_some() {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.execution = execution;
        self.memory = memory;
        self.nofile = nofile;
        self.deadline = deadline;
        self.execution_deadline = execution_deadline;
        self.wall = wall;
        self.prepare = Some(
            source
                .require_scope_parent_v1(root)
                .and_then(|source| {
                    self.source = Some(source);
                    self.prepare_inner(root)
                }),
        );
        if let Some(anchor) = self.anchor.as_ref() {
            self.prepare_after = Some(Box::new(CgroupActiveOriginalV2::new()));
            let _ = self
                .prepare_after
                .as_mut()
                .ok_or_else(closed)?
                .capture_once_v2(anchor);
        }
        if !matches!(self.prepare, Some(Ok(()))) || self.failure().is_some() {
            return Err(closed());
        }
        // Only complete positive setup and its independent caller post release
        // these temporary readers. Scope/population custody remains resident.
        drop(self.prepare_after.take());
        drop(self.population_open.take());
        drop(self.empty.take());
        drop(self.directory.take());
        Ok(())
    }

    fn prepare_inner(&mut self, root: &RetainedCgroupAnchor) -> Result<()> {
        if self.execution == [0; 16]
            || self.memory == 0
            || self.nofile < 3
            || self.deadline == 0
            || self.deadline > self.execution_deadline
        {
            return Err(closed());
        }
        let cut = FixedProcessCaptureCutV3::new(self.deadline, self.wall)?;
        self.cut = Some(cut);
        self.clock.observe(cut)?;
        self.directory = Some(Box::new(DirectoryOriginalV1::new()));
        let directory = self.directory.as_mut().ok_or_else(closed)?;
        directory.capture_ssh_leaf(root, &self.execution, cut, &mut self.clock)?;
        self.anchor = directory.take_completed_once().map(std::sync::Arc::new);
        let anchor = self.anchor.as_ref().ok_or_else(closed)?;
        for memory in [None, Some(self.memory)] {
            self.writer = Some(Box::new(ControlWriteOriginalV1::new()));
            self.writer.as_mut().ok_or_else(closed)?.limit_once(
                anchor,
                memory,
                cut,
                &mut self.clock,
            )?;
            self.reader = Some(Box::new(match memory {
                None => LimitReader::Pids(PidsLimitReadbackV1::new()),
                Some(_) => LimitReader::Memory(MemoryLimitReadbackV1::new()),
            }));
            let reader = self.reader.as_mut().ok_or_else(closed)?;
            self.reader_primary = Some(reader.capture(anchor));
            self.reader_after = Some(reader.finish(anchor));
            let bytes = format!("{}\n", memory.unwrap_or(4));
            if !matches!(self.reader_primary, Some(Ok(())))
                || !matches!(self.reader_after, Some(Ok(())))
                || !reader.matches(bytes.as_bytes())
            {
                return Err(closed());
            }
            // Both complete native readback bookends precede this transition.
            // The next limit cannot replace a failed writer or partial reader.
            drop(self.writer.take());
            drop(self.reader.take());
        }
        self.empty = Some(Box::new(CgroupSingleTaskObservationV1::new()));
        self.empty
            .as_mut()
            .ok_or_else(closed)?
            .capture_empty_once_v2(anchor)?;
        self.population_open = Some(Box::new(CgroupPopulationMonitorOriginalV3::new()));
        let population = self.population_open.as_mut().ok_or_else(closed)?;
        population.capture_once_v3(anchor)?;
        self.population = population.take_completed_once_v3();
        if self.population.is_none() {
            return Err(closed());
        }
        Ok(())
    }

    /// Spawns the same fixed helper atomically into its already limited scope.
    ///
    /// The supplied descriptor is the parent's actual private bootstrap socket.
    /// It becomes only child stdin; stdout/stderr are the same fixed null file.
    /// The caller keeps this original on its live Process before entering.
    ///
    /// # Errors
    /// Retains partial native setup, actual child/pidfd and failed after-clock.
    /// A second spawn or an incomplete preparation refuses before native work.
    pub fn spawn_helper_once_v1(&mut self, bootstrap: BorrowedFd<'_>) -> Result<()> {
        if self.spawn.is_some()
            || !self.standing_taken
            || !matches!(self.prepare, Some(Ok(())))
            || self.failure().is_some()
        {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        let anchor = self.anchor.as_ref().ok_or_else(closed)?;
        self.spawn = Some(Box::new(GuestSshProcessOriginalV1::new()));
        self.spawn.as_mut().ok_or_else(closed)?.spawn_once(
            anchor.as_fd(),
            bootstrap,
            self.nofile,
            self.deadline,
            self.wall,
            self.source.ok_or_else(closed)?,
        )
    }

    /// Borrows only the pidfd returned for this original's actual native child.
    ///
    /// # Errors
    /// Refuses an absent/incomplete spawn or a native pidfd admission failure.
    pub fn child_pidfd_v1(&self) -> Result<&crate::pidfd::PidFd> {
        self.spawn.as_ref().ok_or_else(closed)?.pidfd()
    }

    /// Returns the actual retained child's PID as nonauthorizing comparison DATA.
    #[must_use]
    pub fn child_id_data_v1(&self) -> Option<u32> {
        self.spawn.as_ref()?.id()
    }

    pub(crate) fn require_bootstrap_plan_v1(&self, plan: &[u8; 144]) -> Result<()> {
        if !matches!(self.prepare, Some(Ok(())))
            || self.failure().is_some()
            || &plan[..8] != b"AOSSSH01"
            || plan[72..88] != self.execution
            || plan[120..128] != self.memory.to_be_bytes()
            || plan[128..132] != 4_u32.to_be_bytes()
            || plan[132..136] != self.nofile.to_be_bytes()
            || !self.source.is_some_and(|source|
                plan[136..140] == source.copied_files.to_be_bytes()
                    && plan[140..144] == source.highest_fd.to_be_bytes())
        {
            return Err(closed());
        }
        Ok(())
    }

    pub(crate) fn bootstrap_anchor_v1(&self) -> Result<&std::sync::Arc<RetainedCgroupAnchor>> {
        self.anchor.as_ref().ok_or_else(closed)
    }

    pub(crate) fn bootstrap_horizon_v1(&self) -> (u64, i64) {
        (self.deadline, self.wall)
    }

    pub(crate) fn execution_data_v1(&self) -> [u8; 16] {
        self.execution
    }

    pub(crate) fn execution_horizon_v1(&self) -> Result<FixedProcessCaptureCutV3> {
        FixedProcessCaptureCutV3::new(self.execution_deadline, self.wall)
    }

    /// Shares the same actual child's pidfd without duplicating a descriptor.
    ///
    /// The scope keeps its own reference through exact-child reap. This
    /// constructor-closed borrow permits no caller-selected PID or process.
    ///
    /// # Errors
    /// Refuses a partial native spawn or failed independently owed post.
    pub fn share_child_pidfd_v1(&self) -> Result<std::sync::Arc<crate::pidfd::PidFd>> {
        self.spawn.as_ref().ok_or_else(closed)?.shared_pidfd()
    }

    /// Moves standing scope containment to the existing timeout worker's slot.
    ///
    /// The caller parks this owner before invoking the fixed spawn. Its anchor
    /// and population monitor remain accessible while libc or the bootstrap
    /// receipt is pending; neither requires the main birth owner's mutex.
    ///
    /// # Errors
    /// Refuses repeated transfer or incomplete original scope preparation.
    pub fn take_standing_once_v1(&mut self) -> Result<GuestSshStandingOriginalV1> {
        if self.standing_taken || !matches!(self.prepare, Some(Ok(()))) || self.failure().is_some()
        {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        let anchor = self.anchor.as_ref().ok_or_else(closed)?;
        let population = self.population.take().ok_or_else(closed)?;
        self.standing_taken = true;
        Ok(GuestSshStandingOriginalV1::new(
            std::sync::Arc::clone(anchor),
            population,
            self.execution,
            self.deadline,
            self.execution_deadline,
            self.wall,
        ))
    }

    /// Joins standing containment with the same original child's actual reap.
    ///
    /// The worker's completed empty observation alone cannot retire a birth
    /// prefix. This owner still owes its exact unreaped ChildGuard and pidfd;
    /// direct kill and nonblocking wait run even after containment refusal.
    ///
    /// # Errors
    /// Retains a foreign standing owner, failed direct kill or failed wait.
    /// Returns `true` only after this scope is sealed, recursively empty and
    /// its same actual child is reaped. A pending birth cannot complete here.
    pub fn poll_retirement_once_v1(
        &mut self,
        standing: &GuestSshStandingOriginalV1,
    ) -> Result<bool> {
        if self.finished {
            return Ok(true);
        }
        let anchor = self.anchor.as_ref().ok_or_else(closed)?;
        if !standing.belongs_to(anchor, self.execution) {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        let Some(child) = self.spawn.as_mut() else {
            // Main owns this scope outside the worker's mutex. An unentered
            // spawn has no in-flight clone or ChildGuard to reap; the same
            // completed seal/kill/empty still precedes native retirement.
            self.finished = standing.completed_v1() && standing.failure().is_none();
            return Ok(self.finished);
        };
        let killed = child.kill_once();
        self.retirement_wait = Some(child.poll_wait());
        if killed.is_err() || self.retirement_wait.as_ref().is_some_and(Result::is_err) {
            return Err(closed());
        }
        if standing.failure().is_some() {
            return Err(closed());
        }
        self.finished =
            standing.completed_v1() && matches!(self.retirement_wait, Some(Ok(Some(_))));
        Ok(self.finished)
    }

    /// Borrows the earliest retained setup, child or containment native cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.directory
            .as_ref()
            .and_then(|owner| owner.failure())
            .map(|cause| original_clock_cause(cause, &self.clock))
            .or_else(|| {
                self.writer
                    .as_ref()
                    .and_then(|owner| owner.failure())
                    .map(|cause| original_clock_cause(cause, &self.clock))
            })
            .or_else(|| self.reader.as_ref().and_then(|owner| owner.failure()))
            .or_else(|| self.clock.failure().map(|cause| cause as _))
            .or_else(|| {
                self.empty
                    .as_ref()
                    .and_then(|owner| owner.failure())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.population_open
                    .as_ref()
                    .and_then(|owner| owner.failure())
            })
            .or_else(|| {
                self.prepare
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.prepare_after
                    .as_ref()
                    .and_then(|owner| owner.failure())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.spawn
                    .as_ref()
                    .and_then(|owner| owner.startup_failure())
            })
            .or_else(|| self.spawn.as_ref().and_then(|owner| owner.kill_failure()))
            .or_else(|| self.spawn.as_ref().and_then(|owner| owner.wait_failure()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Prices the actual scope's finite constructor, native and retained planes.
    ///
    /// This excludes the separately financed descendant M/four-task/FD envelope,
    /// clone FD-table copy, external bootstrap socket/record and listener owners.
    /// Completed directory/control/readback phases physically retire before the
    /// following phase; every failure stops while retaining that whole prefix.
    #[must_use]
    pub fn receiving_obligations_v1(source_copied_files: u32) -> Option<(usize, usize, usize)> {
        let directory = DirectoryOriginalV1::receiving_obligations_for_name_v1(36)?;
        let writer = ControlWriteOriginalV1::receiving_obligations_v1()?;
        let reader = PidsLimitReadbackV1::dominant_requested_bytes_v1()?
            .max(MemoryLimitReadbackV1::dominant_requested_bytes_v1()?);
        let population = CgroupPopulationMonitorOriginalV3::receiving_obligations_v3()?;
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let child = GuestSshProcessOriginalV1::receiving_obligations_v1(source_copied_files)?;
        let standing = GuestSshStandingOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(standing.0)?
            .checked_add(
                2 * (std::mem::size_of::<RetainedCgroupAnchor>()
                    + 2 * std::mem::size_of::<usize>()),
            )?
            .checked_add(directory.0)?
            .checked_add(writer.0)?
            .checked_add(reader)?
            .checked_add(CgroupSingleTaskObservationV1::requested_bytes_v1()?)?
            .checked_add(population.0)?
            .checked_add(active.0.checked_mul(3)?)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(child.0)?
            .checked_add(8 * 256 + 2 * 37 + 2 * 21)?;
        let prepare = directory
            .1
            .max(
                1_usize
                    .checked_add(writer.1.max(PidsLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1))?
                    .checked_add(active.1)?,
            )
            .max(
                1_usize
                    .checked_add(CgroupSingleTaskObservationV1::MAXIMUM_RETAINED_FILES_V1)?
                    .checked_add(population.1)?
                    .checked_add(active.1)?,
            );
        let spawn = 2_usize.checked_add(child.1)?;
        // The standing source can be entered during libc/receipt work. Its
        // failed whole prefix therefore sums with the retained birth prefix;
        // the scope's shared Arc contributes no second native descriptor.
        let shutdown = standing.1.checked_add(child.1)?;
        // One actual scope name, its six named controls and the three fixed
        // Owner-policy names used by the shared native directory/writer engine.
        Some((bytes, prepare.max(spawn).max(shutdown), 10_usize.checked_add(child.2)?))
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest SSH original scope",
        "native prefix is incomplete or refused",
    )
}

fn original_clock_cause<'held>(
    cause: &'held (dyn std::error::Error + 'static),
    clock: &'held crate::process::capture_cut::CaptureProcessCutOriginalV3,
) -> &'held (dyn std::error::Error + 'static) {
    if cause
        .downcast_ref::<Error>()
        .is_some_and(crate::process::capture_cut::is_marker)
    {
        clock.failure().map_or(cause, |original| original as _)
    } else {
        cause
    }
}
