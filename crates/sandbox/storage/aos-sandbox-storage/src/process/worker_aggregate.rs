//! Selected fixed-launch aggregate observation shared by the existing workers.
//!
//! The inherited directory is DATA. A recipient compares it with the actual
//! compiled aggregate before selecting the main cgroup; the financial parent
//! separately binds the worker to its held paid aggregate before an effect.

use super::*;
use aos_sandbox_linux::cgroup::{
    CgroupSingleTaskObservationV1, StorageWorkerAggregateReadbackV1,
    WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1,
};
use aos_sandbox_linux::process::{
    FixedProcessOutcome, FixedProcessOutput, FixedProcessRequest, StorageWorkerForkObservationV1,
    FixedProcessRunOriginalV3, FixedProcessRunRefusalV3,
    run_fixed_process_observing_storage_fork_retaining_v3,
};
use aos_sandbox_linux::inherited_fd::StorageWorkerAggregateInitialTableV1;

const NAME: &str = "aos-storage-worker-aggregate-v1";

// Existing transaction plans emit at most five precondition commands, six
// postcondition commands, two mutation commands or three atomic commands.
const MAXIMUM_INVOCATIONS: usize = 6;

// Capture is one closed resident operation: two preflight commands, one create,
// then three observations each after create, before mount, mounted, and after
// both stream EOFs. It does not widen the existing generic six-command branch.
const CAPTURE_INVOCATIONS_V3: usize = 2 + 1 + 4 * 3;

#[derive(Clone, Copy)]
enum WorkerCommandFamilyV3 { Catalog, Capture }

impl WorkerCommandFamilyV3 {
    const fn maximum_invocations(self) -> usize {
        match self {
            Self::Catalog => MAXIMUM_INVOCATIONS,
            Self::Capture => CAPTURE_INVOCATIONS_V3,
        }
    }
}

struct WorkerForkOriginalV1 {
    before: CgroupSingleTaskObservationV1,
    before_result: Option<Result<(), aos_linux_descriptors::Error>>,
    census: StorageWorkerForkObservationV1,
    process: FixedProcessRunOriginalV3,
    process_result: Option<Result<(), FixedProcessRunRefusalV3>>,
    process_disposal: Option<Result<(), FixedProcessRunRefusalV3>>,
    completed_output: Option<FixedProcessOutput>,
    after: CgroupSingleTaskObservationV1,
    after_result: Option<Result<(), aos_linux_descriptors::Error>>,
    disposal: Option<Result<(), aos_linux_descriptors::Error>>,
}

impl WorkerForkOriginalV1 {
    fn new() -> Self {
        Self {
            before: CgroupSingleTaskObservationV1::new(),
            before_result: None,
            census: StorageWorkerForkObservationV1::new(),
            process: FixedProcessRunOriginalV3::new(),
            process_result: None,
            process_disposal: None,
            completed_output: None,
            after: CgroupSingleTaskObservationV1::new(),
            after_result: None,
            disposal: None,
        }
    }
}

struct WorkerExecutionOriginalV1 {
    initial_limits: Option<Result<rustix::process::Rlimit, aos_linux_descriptors::Error>>,
    initial_limits_result: Option<Result<(), aos_linux_descriptors::Error>>,
    own_opening: WorkerCgroupOpeningV1,
    own_result: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    own_post: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    own_anchor: Option<RetainedCgroupAnchor>,
    own_sample: CgroupSingleTaskObservationV1,
    own_sample_result: Option<Result<(), aos_linux_descriptors::Error>>,
    forks: Vec<WorkerForkOriginalV1>,
}

impl WorkerExecutionOriginalV1 {
    fn new() -> Self {
        Self {
            initial_limits: None,
            initial_limits_result: None,
            own_opening: WorkerCgroupOpeningV1::new(),
            own_result: None,
            own_post: None,
            own_anchor: None,
            own_sample: CgroupSingleTaskObservationV1::new(),
            own_sample_result: None,
            forks: Vec::new(),
        }
    }
}

pub(crate) struct WorkerAggregateV1 {
    table: StorageWorkerAggregateInitialTableV1,
    inherited_limit: aos_sandbox_linux::process::StorageWorkerInheritedLimitOriginalV1,
    inherited_limit_result: Option<Result<(), aos_sandbox_linux::process::StorageWorkerInheritedLimitRefusalV1>>,
    native: StorageWorkerAggregateReadbackV1,
    result: Option<Result<(), aos_linux_descriptors::Error>>,
    root: Option<CgroupV2Root>,
    main: Option<RetainedCgroupAnchor>,
    completed: bool,
}

impl WorkerAggregateV1 {
    fn capture() -> Result<Option<Self>, ZfsWorkerError> {
        let pid = std::env::var_os("LISTEN_PID");
        let count = std::env::var_os("LISTEN_FDS");
        let names = std::env::var_os("LISTEN_FDNAMES");
        // Unselected launches preserve their old handling of unrelated
        // activation hints. Only the one closed OpenFile name selects this
        // passive recipient; it cannot select a financial parent.
        if names.as_deref() != Some(std::ffi::OsStr::new(NAME)) {
            return Ok(None);
        }
        if pid.as_deref() != Some(std::ffi::OsStr::new(&std::process::id().to_string()))
            || count.as_deref() != Some(std::ffi::OsStr::new("1"))
            || names.as_deref() != Some(std::ffi::OsStr::new(NAME))
        {
            return Err(ZfsWorkerError::Protocol("fixed worker aggregate table differs"));
        }

        let mut original = Self {
            table: StorageWorkerAggregateInitialTableV1::new(),
            inherited_limit: aos_sandbox_linux::process::StorageWorkerInheritedLimitOriginalV1::new(),
            inherited_limit_result: None,
            native: StorageWorkerAggregateReadbackV1::new(),
            result: None, root: None, main: None, completed: false,
        };
        original.table.observe_once(1)
            .map_err(|_| ZfsWorkerError::Protocol("worker aggregate table retained"))?;
        let Some([Some(directory)]) = original.table.take_completed_entries() else {
            std::process::abort();
        };
        original.result = Some(original.native.capture_once(directory));
        if !matches!(original.result, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("worker aggregate directory retained"));
        }
        let Some((root, main)) = original.native.take_validated_pair() else {
            std::process::abort();
        };
        original.root = Some(root);
        original.main = Some(main);
        // Both genuine returned objects are parked before disposing the
        // completed local comparison scratch. Later failures keep these same
        // objects and terminate through this owner's existing Drop fence.
        original.native.settle_transferred_once_v1()
            .map_err(|_| ZfsWorkerError::Protocol("worker aggregate settlement refused"))?;
        // This actual fixed worker, not its caller's profile DATA, proves the
        // inherited per-table premise before any selected READY or effect.
        // Ordinary unselected capture returned above without these syscalls.
        original.inherited_limit_result = Some(original.inherited_limit.capture_once());
        if !matches!(original.inherited_limit_result, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("worker inherited hard-limit recipe retained"));
        }
        Ok(Some(original))
    }

    pub(crate) fn borrow_execution_scope_v1(&mut self, current: &str) -> Result<WorkerExecutionScopeV1<'_>, ZfsWorkerError> {
        self.borrow_execution_family_v3(current, WorkerCommandFamilyV3::Catalog)
    }

    /// Borrows the fixed publisher's actual inherited aggregate without a fork.
    ///
    /// Its1GiB service envelope and same-F parent are checked by the retained
    /// descriptor-worker loan before any request is sent. This entry additionally
    /// proves the exact selected basename on the worker's own native original.
    pub(crate) fn borrow_guest_root_execution_scope_v2(&mut self, current: &str)
        -> Result<WorkerExecutionScopeV1<'_>, ZfsWorkerError>
    {
        let instance = selected_worker_instance(current,
            "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@")
            .and_then(|value| value.strip_suffix(".service"))
            .filter(|value| !value.is_empty() && value.len() <= 255 && !value.contains('/'))
            .ok_or(ZfsWorkerError::PeerMismatch)?;
        if instance == "." || instance == ".." { return Err(ZfsWorkerError::PeerMismatch); }
        self.borrow_execution_family_v3(current, WorkerCommandFamilyV3::Catalog)
    }

    // Only the authenticated Capture child context selects this fixed family.
    // No caller-supplied count, resource vector or ordinary request selects it.
    pub(super) fn borrow_capture_execution_scope_v3(&mut self, current: &str)
        -> Result<WorkerExecutionScopeV1<'_>, ZfsWorkerError>
    {
        self.borrow_execution_family_v3(current, WorkerCommandFamilyV3::Capture)
    }

    fn borrow_execution_family_v3(&mut self, current: &str, family: WorkerCommandFamilyV3)
        -> Result<WorkerExecutionScopeV1<'_>, ZfsWorkerError>
    {
        let parent = aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate
            .worker_parent_relative_v1();
        let relative = current.strip_prefix(parent).and_then(|path| path.strip_prefix('/'))
            .ok_or(ZfsWorkerError::PeerMismatch)?;
        // The caller has already applied its exact fixed service basename
        // grammar. The root is the actual validated inherited aggregate.
        // Moving this actual root is consume-only: another scope cannot be
        // entered after a successful branch, nor replace a failed original.
        let root = self.root.take()
            .ok_or(ZfsWorkerError::Protocol("worker aggregate execution already entered"))?;
        let mut scope = WorkerExecutionScopeV1 {
            _aggregate: self,
            family,
            root,
            original: Box::new(WorkerExecutionOriginalV1::new()),
            completed: false, capture_cut: None,
        };
        let root = &scope.root;
        let execution = &mut scope.original;
        execution.initial_limits = Some(aos_sandbox_linux::process::observe_nofile_limit_v1());
        execution.initial_limits_result = Some(match execution.initial_limits.as_ref() {
            Some(Ok(rustix::process::Rlimit { current: Some(128), maximum: Some(128) })) => Ok(()),
            _ => Err(aos_linux_descriptors::Error::InvalidInput {
                field: "selected worker descriptor limit", message: "requires exact inherited soft/hard128".to_owned(),
            }),
        });
        if !matches!(execution.initial_limits_result, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("worker inherited descriptor limit retained"));
        }
        execution.own_result = Some(execution.own_opening.capture_root_descendant_once(root, Path::new(relative)));
        execution.own_post = Some(execution.own_opening.observe_root_parent_after_attempt_once(root));
        if !matches!(execution.own_result, Some(Ok(()))) || !matches!(execution.own_post, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("worker execution scope native prefix retained"));
        }
        execution.own_anchor = execution.own_opening.take_anchor_once();
        let Some(anchor) = execution.own_anchor.as_ref() else { std::process::abort() };
        execution.own_sample_result = Some(execution.own_sample.capture_current_only_once(anchor));
        if !matches!(execution.own_sample_result, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("worker execution scope retains another process"));
        }
        execution.own_sample.dispose_positive_after_posts_v1()?;
        execution.own_opening = WorkerCgroupOpeningV1::new();
        Ok(scope)
    }

    /// Prices all reached worker-side frames, vectors and native holders.
    pub(crate) fn fork_requested_bytes_v1() -> Option<usize> {
        Self::fork_family_requested_bytes_v3(WorkerCommandFamilyV3::Catalog)
    }

    pub(super) fn capture_planner_requested_bytes_v3() -> Option<usize> {
        // The retained domain command/argv models coexist with each actual
        // prepared native invocation. The same fixed argc/argument/path/output
        // envelope dominates that second representation plane for all15
        // compiled commands, without a caller-selected multiplier or parser.
        CAPTURE_INVOCATIONS_V3.checked_mul(FixedProcessRunOriginalV3::bounded_representation_bytes_v3(
            MAXIMUM_MACHINE_OUTPUT_BYTES, MAXIMUM_STDERR_BYTES,
        )?)
    }

    pub(super) fn capture_tool_output_bytes_v3() -> Option<usize> {
        // The actual preflight/create engines use4096 on BOTH streams.
        // Four later fixed three-command readbacks keep4096 stdout/64KiB stderr.
        // Each invocation's native rejected chunk is included by Linux's sole
        // output reader supplier; an error prevents all later commands.
        let entry = FixedProcessRunOriginalV3::bounded_output_bytes_v3(
            MAXIMUM_MACHINE_OUTPUT_BYTES, MAXIMUM_MACHINE_OUTPUT_BYTES,
        )?;
        let readback = FixedProcessRunOriginalV3::bounded_output_bytes_v3(
            MAXIMUM_MACHINE_OUTPUT_BYTES, MAXIMUM_STDERR_BYTES,
        )?;
        entry.checked_mul(2 + 1)?.checked_add(readback.checked_mul(4 * 3)?)
    }

    pub(super) fn capture_fork_requested_bytes_v3() -> Option<usize> {
        Self::fork_family_requested_bytes_v3(WorkerCommandFamilyV3::Capture)
    }

    fn fork_family_requested_bytes_v3(family: WorkerCommandFamilyV3) -> Option<usize> {
        let invocations = family.maximum_invocations();
        std::mem::size_of::<WorkerExecutionScopeV1<'_>>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<WorkerExecutionOriginalV1>())?
            // Vec growth can overlap old and new buffers. This separately
            // pays their real carrier capacity and one construction frame.
            .checked_add((3 * invocations + 1)
                .checked_mul(std::mem::size_of::<WorkerForkOriginalV1>())?)?
            .checked_add(super::worker_entry::WorkerEntryOriginalV3::requested_bytes_v3()?)?
            .checked_add(2 * 256)?
            .checked_add(WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?)?
            .checked_add(CgroupSingleTaskObservationV1::requested_bytes_v1()?)?
            .checked_add(invocations.checked_mul(
                StorageWorkerForkObservationV1::requested_bytes_v1()?
                    .checked_add(2 * CgroupSingleTaskObservationV1::requested_bytes_v1()?)?
                    .checked_add(FixedProcessRunOriginalV3::bounded_representation_bytes_v3(
                        MAXIMUM_STDOUT_BYTES, MAXIMUM_STDERR_BYTES,
                    )?)?)?)
    }

    /// Counts actual worker paths and each retained native descriptor-name index.
    pub(crate) const fn fork_metadata_entries_v1() -> usize {
        Self::fork_family_metadata_entries_v3(WorkerCommandFamilyV3::Catalog)
    }

    pub(super) const fn capture_fork_metadata_entries_v3() -> usize {
        Self::fork_family_metadata_entries_v3(WorkerCommandFamilyV3::Capture)
    }

    const fn fork_family_metadata_entries_v3(family: WorkerCommandFamilyV3) -> usize {
        // The fixed basename grammar permits one worker directory beneath the
        // existing aggregate. Its opening touches the aggregate cgroup.procs;
        // current-task samples touch worker cgroup.procs and cgroup.threads.
        // All six turns reuse those same paths and the same /proc/self/fd
        // directory; only their separately retained numeric indexes add rows.
        let worker_and_parent_paths = 2;
        let descriptor_directory = 1;
        // The unchanged reaping check opens /proc/self/task and can retain
        // two actual task-directory entries on refusal. Positive task checks
        // dispose these before spawn, so all turns share this namespace peak.
        let task_directory_and_entries = 3;
        // Startup additionally names the cgroup root and its active file,
        // fixed executable, /proc/self/cgroup and main's cgroup.procs. These
        // paths stay the same through request/ACK samples.
        let entry_paths = 5;
        entry_paths + worker_and_parent_paths + CgroupSingleTaskObservationV1::METADATA_ENTRIES_V1
            + descriptor_directory + task_directory_and_entries
            + family.maximum_invocations() * StorageWorkerForkObservationV1::MAXIMUM_DESCRIPTOR_INDEX_ENTRIES_V1
    }

    /// Moves the actual validated main once, without a fallback or fresh lookup.
    pub(crate) fn take_main(&mut self) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
        self.main.take().ok_or(ZfsWorkerError::Protocol("worker aggregate main already moved"))
    }
}

/// Owns only a paid generic worker branch while borrowing its same aggregate.
///
/// Other fixed worker families never construct this body or alter their old
/// aggregate header. The borrow remains exclusive through command IO and the
/// final authenticated ACK; a failed scope terminates before releasing fields.
pub(crate) struct WorkerExecutionScopeV1<'aggregate> {
    _aggregate: &'aggregate mut WorkerAggregateV1,
    family: WorkerCommandFamilyV3,
    root: CgroupV2Root,
    original: Box<WorkerExecutionOriginalV1>,
    completed: bool,
    capture_cut: Option<Result<aos_sandbox_linux::process::FixedProcessCaptureCutV3, aos_linux_descriptors::Error>>,
}

impl WorkerExecutionScopeV1<'_> {
    pub(super) fn require_capture_context_v3(&self) -> Result<(), ZfsWorkerError> {
        if !matches!(self.family, WorkerCommandFamilyV3::Capture) || self.completed
            || !self.original.forks.is_empty() || self.original.own_anchor.is_none()
            || !matches!(self.original.own_sample_result, Some(Ok(())))
        { return Err(ZfsWorkerError::Authority); }
        Ok(())
    }

    pub(super) fn bind_capture_process_cut_v3(&mut self,
        context: &capture_worker::AuthenticatedCaptureWorkerContextV3<'_>) -> Result<(), ZfsWorkerError> {
        self.require_capture_context_v3()?;
        if self.capture_cut.is_some() { return Err(ZfsWorkerError::Authority); }
        self.capture_cut = Some(context.process_cut_data_v3());
        if matches!(self.capture_cut, Some(Ok(_))) { Ok(()) } else { Err(worker_entry::retained()) }
    }

    pub(crate) fn run_fixed_process_v1(&mut self, request: FixedProcessRequest<'_>)
        -> Result<FixedProcessOutcome, aos_linux_descriptors::Error>
    {
        let capture = match self.family {
            WorkerCommandFamilyV3::Capture => Some(self.capture_cut.as_ref()
                .and_then(|result| result.as_ref().ok()).copied().ok_or_else(retained_process_refusal_v3)?),
            WorkerCommandFamilyV3::Catalog => None,
        };
        let execution = &mut self.original;
        if execution.forks.len() >= self.family.maximum_invocations() || execution.own_sample_result.as_ref()
            .is_none_or(|result| result.is_err())
        {
            return Err(aos_linux_descriptors::Error::InvalidInput {
                field: "selected worker invocation", message: "fixed family or actual native scope refused".to_owned(),
            });
        }
        let Some(anchor) = execution.own_anchor.as_ref() else { std::process::abort() };
        execution.forks.push(WorkerForkOriginalV1::new());
        let Some(original) = execution.forks.last_mut() else { std::process::abort() };
        original.before_result = Some(original.before.capture_current_only_once(anchor));
        if matches!(original.before_result, Some(Ok(()))) {
            original.disposal = Some(original.before.dispose_positive_after_posts_v1());
            if matches!(original.disposal, Some(Ok(()))) {
                original.process_result = Some(match capture {
                    Some(cut) => aos_sandbox_linux::process::run_fixed_capture_process_retaining_v3(
                        request, &mut original.census, &mut original.process, cut),
                    None => run_fixed_process_observing_storage_fork_retaining_v3(
                        request, &mut original.census, &mut original.process),
                });
            }
        }
        // An entered native scope owes this observation after primary refusal
        // too. It retains the exact raw tasks/open/read/active results, and
        // never turns an earlier process error into a later post error.
        original.after_result = Some(original.after.capture_current_only_once(anchor));
        if !matches!(original.before_result, Some(Ok(())))
            || !matches!(original.disposal, Some(Ok(())))
            || !matches!(original.process_result, Some(Ok(())))
            || !matches!(original.after_result, Some(Ok(())))
        {
            return Err(aos_linux_descriptors::Error::InvalidInput {
                field: "selected worker invocation", message: "actual process/native originals retained".to_owned(),
            });
        }
        original.disposal = Some(original.after.dispose_positive_after_posts_v1());
        if !matches!(original.disposal, Some(Ok(()))) {
            return Err(aos_linux_descriptors::Error::InvalidInput {
                field: "selected worker invocation", message: "actual positive native disposition refused".to_owned(),
            });
        }
        match original.process.outcome() {
            Some(FixedProcessOutcome::TimedOut) => return Ok(FixedProcessOutcome::TimedOut),
            Some(FixedProcessOutcome::OutputLimitExceeded) => {
                return Ok(FixedProcessOutcome::OutputLimitExceeded);
            }
            Some(FixedProcessOutcome::Completed(_)) => {}
            None => return Err(retained_process_refusal_v3()),
        }

        // Both child EOFs/reap and the independently owed cgroup post have
        // completed. Keep the output in this owner until positive native
        // disposition succeeds; a disposition refusal cannot lose its bytes.
        original.completed_output = Some(original.process.take_completed_output_v3()
            .map_err(|_| retained_process_refusal_v3())?);
        original.process_disposal = Some(original.process.dispose_after_completed_posts_v3());
        if !matches!(original.process_disposal, Some(Ok(()))) {
            return Err(retained_process_refusal_v3());
        }
        let Some(output) = original.completed_output.take() else { std::process::abort() };
        Ok(FixedProcessOutcome::Completed(output))
    }

    /// Borrows the first actual reached fork/process cause before termination.
    pub(crate) fn failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.capture_cut.as_ref() { return Some(cause); }
        for original in &self.original.forks {
            if let Some(error) = original.before.failure() { return Some(error); }
            if let Some(Err(error)) = original.disposal.as_ref() { return Some(error); }
            if let Some(error) = original.census.failure() { return Some(error); }
            if let Some(error) = original.process.failure() { return Some(error); }
            if let Some(error) = original.after.failure() { return Some(error); }
            if let Some(Err(error)) = original.process_disposal.as_ref() { return Some(error); }
        }
        None
    }

    /// Marks only the fully checked final ACK boundary; no native work follows.
    pub(crate) fn complete_after_ack_v1(&mut self) {
        self.completed = true;
    }
}

fn retained_process_refusal_v3() -> aos_linux_descriptors::Error {
    aos_linux_descriptors::Error::InvalidInput {
        field: "selected worker process",
        message: "actual native process prefix is retained".to_owned(),
    }
}

impl Drop for WorkerExecutionScopeV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            std::process::abort();
        }
    }
}

impl Drop for WorkerAggregateV1 {
    fn drop(&mut self) {
        // Returning to an ordinary worker path after a selected partial failure
        // would discard its actual launch/native prefix. The fixed one-shot
        // process terminates before those resident fields can be released.
        if !self.completed {
            std::process::abort();
        }
    }
}

pub(crate) fn with_worker_aggregate_v1<T>(
    operation: impl FnOnce(Option<&mut WorkerAggregateV1>) -> Result<T, ZfsWorkerError>,
) -> Result<T, ZfsWorkerError> {
    let mut aggregate = WorkerAggregateV1::capture()?;
    let result = operation(aggregate.as_mut());
    if result.is_ok() {
        if let Some(original) = aggregate.as_mut() {
            original.completed = true;
        }
    }
    result
}

/// Recognizes only the same fixed service basename beneath the selected slice.
pub(crate) fn selected_worker_instance<'a>(path: &'a str, ordinary_prefix: &str) -> Option<&'a str> {
    use aos_sandbox_linux::cgroup::StorageCgroupLayoutV1;
    let basename = ordinary_prefix.strip_prefix(StorageCgroupLayoutV1::Ordinary.worker_parent_relative_v1())?
        .strip_prefix('/')?;
    path.strip_prefix(StorageCgroupLayoutV1::ReceivingAggregate.worker_parent_relative_v1())?
        .strip_prefix('/')?.strip_prefix(basename)
}
