//! Progress-bounded waits for whole campaign attempts.
//!
//! An attempt's semantic horizon is its campaign policy: a bounded stop ends
//! in a policy timeout once virtual time reaches the policy deadline, so the
//! harness needs no wall-clock ceiling of its own, and a run may take minutes
//! or hours depending on the host. A wait instead fails when the attempt
//! makes no observable progress for a bounded stall window, or when an outer
//! safety cap derived from the policy horizon expires.
//!
//! Progress is a change in the public state the wait already reads, such as
//! the campaign snapshot or the attempt's runtime phase; a change in the
//! guest progress the service reports, such as its frontier and node clocks;
//! or host work sampled from `/proc`:
//!
//! ```text
//! service CPU time of the service process itself       publication work
//! qemu    a replaced QEMU set restarting its totals     new guests
//! ```
//!
//! QEMU CPU time alone is not progress. A node livelocked at one coordinate
//! spins a full core while no clock moves, and a wedged guest waiting on a
//! lost acknowledgement spins none; both are stalls, and only reported guest
//! progress tells them apart from execution. Service time counts only when it
//! is close to a full core, which polling does not reach. Sampled CPU time is
//! advisory: it only extends a wait and never satisfies one.

use super::*;

// Linux reports `/proc/<pid>/stat` CPU times in USER_HZ ticks, fixed at 100
// per second by the kernel ABI.
const PROC_TICKS_PER_SECOND: u64 = 100;
// Host progress is judged over windows this long.
const PROGRESS_SAMPLE: Duration = Duration::from_secs(30);
// Service time above this share of one core within a sample is host work.
const SERVICE_PROGRESS_PERCENT: u64 = 75;
// A wait fails after this long without public or host progress.
const STALL_WINDOW: Duration = Duration::from_secs(600);
// Progress rows are printed this often while a wait lasts.
const PROGRESS_REPORT: Duration = Duration::from_secs(60);
// The slowest sustained guest rate the safety cap allows for: one virtual
// millisecond per host second, well below every rate observed on the
// supported hosts.
const MINIMUM_VIRTUAL_PS_PER_HOST_SECOND: u64 = 1_000_000_000;

/// Stall and safety limits for one progress-bounded attempt wait.
#[derive(Clone, Copy, Debug)]
pub(super) struct AttemptWaitLimits {
    stall: Duration,
    safety_cap: Duration,
}

impl AttemptWaitLimits {
    /// Derives the limits for an attempt bounded by an absolute policy horizon.
    ///
    /// The horizon counts from scenario genesis and includes replay, so an
    /// attempt never executes more virtual time than it. The safety cap is
    /// the host time that horizon takes at the minimum supported guest rate.
    pub(super) fn for_policy_horizon(horizon_ps: u64) -> Self {
        let safety_seconds = horizon_ps.div_ceil(MINIMUM_VIRTUAL_PS_PER_HOST_SECOND);
        Self {
            stall: STALL_WINDOW,
            safety_cap: Duration::from_secs(safety_seconds).max(STALL_WINDOW),
        }
    }

    /// Returns the outer host-time cap for one wait.
    pub(super) const fn safety_cap(self) -> Duration {
        self.safety_cap
    }
}

/// CPU ticks consumed by a service and its QEMU descendants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HostCpuSample {
    service_ticks: u64,
    qemu_ticks: u64,
    qemu_processes: usize,
}

impl HostCpuSample {
    /// Reads the current totals; unreadable processes contribute nothing.
    fn read(service_pid: u32) -> Self {
        let service_ticks = process_cpu_ticks(service_pid).unwrap_or_default();
        let mut sample = Self {
            service_ticks,
            ..Self::default()
        };
        // A process that exits between the scan and the read is skipped.
        for (pid, arguments) in descendant_process_commands(service_pid).unwrap_or_default() {
            let is_qemu = arguments
                .first()
                .is_some_and(|binary| binary.contains("qemu-system"));
            if !is_qemu {
                continue;
            }
            if let Some(ticks) = process_cpu_ticks(pid) {
                sample.qemu_ticks = sample.qemu_ticks.saturating_add(ticks);
                sample.qemu_processes += 1;
            }
        }
        sample
    }
}

/// One QEMU thread's identity, scheduler state and CPU ticks.
#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuThreadSample {
    pid: u32,
    tid: u32,
    name: String,
    state: char,
    ticks: u64,
}

/// Reads every thread of the service's QEMU descendants.
fn qemu_thread_samples(service_pid: u32) -> Vec<QemuThreadSample> {
    let mut samples = Vec::new();
    for (pid, arguments) in descendant_process_commands(service_pid).unwrap_or_default() {
        let is_qemu = arguments
            .first()
            .is_some_and(|binary| binary.contains("qemu-system"));
        if !is_qemu {
            continue;
        }
        let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for task in tasks.filter_map(Result::ok) {
            let Some(tid) = task.file_name().to_str().and_then(|name| name.parse().ok()) else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(task.path().join("stat")) else {
                continue;
            };
            if let Some(sample) = parse_thread_sample(pid, tid, &stat) {
                samples.push(sample);
            }
        }
    }
    samples
}

/// Parses a thread's name, state and CPU ticks from its stat line.
fn parse_thread_sample(pid: u32, tid: u32, stat: &str) -> Option<QemuThreadSample> {
    let (head, tail) = stat.rsplit_once(") ")?;
    let name = head.split_once(" (")?.1.replace(' ', "_");
    let state = tail.chars().next()?;
    Some(QemuThreadSample {
        pid,
        tid,
        name,
        state,
        ticks: parse_cpu_ticks(stat)?,
    })
}

/// Names the QEMU threads that used CPU across a one-second window.
///
/// A livelocked node spins one thread at a fixed coordinate; its name tells
/// a vCPU loop from the main loop, and its syscall field tells a busy loop
/// (`running`) from a wait. Rows are `pid/tid:name:state:ticks:syscall`.
fn qemu_thread_report(service_pid: u32) -> String {
    let before = qemu_thread_samples(service_pid);
    std::thread::sleep(Duration::from_secs(1));
    let after = qemu_thread_samples(service_pid);

    let mut busy = after
        .iter()
        .map(|thread| {
            let earlier = before
                .iter()
                .find(|old| old.pid == thread.pid && old.tid == thread.tid)
                .map_or(0, |old| old.ticks);
            (thread.ticks.saturating_sub(earlier), thread)
        })
        .filter(|(delta, _thread)| *delta > 0)
        .collect::<Vec<_>>();
    busy.sort_by(|left, right| right.0.cmp(&left.0));

    let rows = busy
        .iter()
        .take(8)
        .map(|(delta, thread)| {
            let syscall = fs::read_to_string(format!(
                "/proc/{}/task/{}/syscall",
                thread.pid, thread.tid
            ))
            .ok()
            .and_then(|text| text.split_whitespace().next().map(str::to_owned))
            .unwrap_or_else(|| "unavailable".to_owned());
            format!(
                "{}/{}:{}:{}:{delta}:{syscall}",
                thread.pid, thread.tid, thread.name, thread.state
            )
        })
        .collect::<Vec<_>>();
    format!("CRUCIBLE-QEMU-THREADS-V1 busy={}", rows.join(","))
}

/// Returns a process's user plus system CPU ticks from `/proc/<pid>/stat`.
fn process_cpu_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_cpu_ticks(&stat)
}

/// Parses user and system ticks, fields 14 and 15 of a stat line.
///
/// The command name may contain spaces, so fields are counted after its
/// closing parenthesis, where field 3 is the first.
fn parse_cpu_ticks(stat: &str) -> Option<u64> {
    let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
    let user = fields.nth(11)?.parse::<u64>().ok()?;
    let system = fields.next()?.parse::<u64>().ok()?;
    user.checked_add(system)
}

/// Returns whether a sample window shows host work.
///
/// QEMU CPU time is deliberately absent: a livelocked node burns it without
/// moving any clock, so guest progress comes from the service's reports.
fn host_progressed(before: HostCpuSample, after: HostCpuSample, window: Duration) -> bool {
    let window_ticks = u64::try_from(window.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_mul(PROC_TICKS_PER_SECOND)
        / 1_000;
    let service = after.service_ticks.saturating_sub(before.service_ticks);
    // A replaced QEMU set restarts its totals; its new guests count as work.
    let qemu_replaced = after.qemu_ticks < before.qemu_ticks && after.qemu_ticks != 0;

    qemu_replaced
        || service.saturating_mul(100) >= window_ticks.saturating_mul(SERVICE_PROGRESS_PERCENT)
}

/// Prefix of the service's per-window RUN progress row.
pub(super) const ATTEMPT_PROGRESS_ROW: &str = "CRUCIBLE-ATTEMPT-PROGRESS-V1 ";

/// Renders the guest progress in one service RUN progress row.
///
/// The rendering keeps only the frontier and each node's clock, the last
/// field of its `nodes=` entry. Window counts such as `quanta` change with
/// every row even when no clock moves, so they are left out:
///
/// ```text
/// frontier_ps=4100000000 clocks=router-a:4149999950,router-b:4100000000
/// ```
///
/// Returns `None` when the row is not a progress row or omits a field.
pub(super) fn reported_guest_progress(row: &str) -> Option<String> {
    let fields = row.strip_prefix(ATTEMPT_PROGRESS_ROW)?;
    let field = |key: &str| {
        fields
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix(key))
    };
    let frontier = field("frontier_ps=")?;
    let mut clocks = Vec::new();
    for node in field("nodes=")?.split(',') {
        let (name, counters) = node.split_once(':')?;
        clocks.push(format!("{name}:{}", counters.rsplit('/').next()?));
    }
    Some(format!("frontier_ps={frontier} clocks={}", clocks.join(",")))
}

/// Tracks one attempt wait and fails it once progress stops.
pub(super) struct AttemptProgressWatch {
    label: String,
    service_pid: u32,
    limits: AttemptWaitLimits,
    started: Instant,
    last_progress: Instant,
    public_state: Option<String>,
    guest_progress: Option<String>,
    guest_sampled: Option<Instant>,
    sample_started: Instant,
    sample: HostCpuSample,
    next_report: Instant,
}

impl AttemptProgressWatch {
    /// Starts watching a wait for `label` on the service with `service_pid`.
    pub(super) fn new(
        label: impl Into<String>,
        service_pid: u32,
        limits: AttemptWaitLimits,
    ) -> Self {
        let now = Instant::now();
        Self {
            label: label.into(),
            service_pid,
            limits,
            started: now,
            last_progress: now,
            public_state: None,
            guest_progress: None,
            guest_sampled: None,
            sample_started: now,
            sample: HostCpuSample::read(service_pid),
            next_report: now + PROGRESS_REPORT,
        }
    }

    /// Returns the instant at which the outer safety cap expires.
    pub(super) fn deadline(&self) -> Instant {
        self.started + self.limits.safety_cap()
    }

    /// Samples the guest progress the service last reported, at most once
    /// per progress sample.
    ///
    /// `read` returns a stable rendering of reported guest or scheduler
    /// progress, such as [`reported_guest_progress`]; a change counts as
    /// progress. Reading may scan the whole service stream, so it runs only
    /// when a sample is due. Callers sample before [`Self::observe`], which
    /// judges the stall.
    pub(super) fn sample_guest_progress(&mut self, read: impl FnOnce() -> Option<String>) {
        let now = Instant::now();
        if self
            .guest_sampled
            .is_some_and(|sampled| now.duration_since(sampled) < PROGRESS_SAMPLE)
        {
            return;
        }
        self.guest_sampled = Some(now);

        let guest_progress = read();
        if guest_progress.is_some() && self.guest_progress != guest_progress {
            self.guest_progress = guest_progress;
            self.last_progress = now;
        }
    }

    /// Records one observation of the attempt's public state.
    ///
    /// `public_state` is any stable rendering of what the wait observed; a
    /// change counts as progress.
    ///
    /// # Errors
    ///
    /// Returns an error naming the last observed state when neither the
    /// public state, reported guest progress, nor sampled host work advanced
    /// for the stall window.
    pub(super) fn observe(&mut self, public_state: &str) -> Result<(), Box<dyn Error>> {
        let now = Instant::now();
        if self.public_state.as_deref() != Some(public_state) {
            self.public_state = Some(public_state.to_owned());
            self.last_progress = now;
        }
        if now.duration_since(self.sample_started) >= PROGRESS_SAMPLE {
            let sample = HostCpuSample::read(self.service_pid);
            if host_progressed(self.sample, sample, now.duration_since(self.sample_started)) {
                self.last_progress = now;
            }
            self.sample = sample;
            self.sample_started = now;
        }

        if now >= self.next_report {
            eprintln!("{}", self.progress_row(now));
            self.next_report = now + PROGRESS_REPORT;
        }
        let idle = now.duration_since(self.last_progress);
        if idle >= self.limits.stall {
            return Err(format!(
                "{} made no progress for {}s; {}; {}",
                self.label,
                idle.as_secs(),
                self.progress_row(now),
                qemu_thread_report(self.service_pid)
            )
            .into());
        }
        Ok(())
    }

    /// Describes the wait after the outer safety cap expired.
    pub(super) fn safety_cap_expired(&self) -> String {
        format!(
            "{} exceeded its {}s safety cap while still progressing; {}",
            self.label,
            self.limits.safety_cap().as_secs(),
            self.progress_row(Instant::now())
        )
    }

    fn progress_row(&self, now: Instant) -> String {
        format!(
            "CRUCIBLE-ATTEMPT-WAIT-V1 label={:?} elapsed_s={} idle_s={} stall_s={} cap_s={} qemu_processes={} qemu_cpu_s={} service_cpu_s={} state={:?} guest={:?}",
            self.label,
            now.duration_since(self.started).as_secs(),
            now.duration_since(self.last_progress).as_secs(),
            self.limits.stall.as_secs(),
            self.limits.safety_cap().as_secs(),
            self.sample.qemu_processes,
            self.sample.qemu_ticks / PROC_TICKS_PER_SECOND,
            self.sample.service_ticks / PROC_TICKS_PER_SECOND,
            self.public_state
                .as_deref()
                .unwrap_or("unobserved")
                .chars()
                .take(240)
                .collect::<String>(),
            self.guest_progress
                .as_deref()
                .unwrap_or("unreported")
                .chars()
                .take(240)
                .collect::<String>(),
        )
    }
}

#[test]
fn stat_cpu_ticks_count_fields_after_a_spaced_command_name() {
    let stat = "4242 (qemu system x86) S 1 2 3 4 5 6 7 8 9 10 1200 34 0 0 20 0 9 0 100";

    assert_eq!(parse_cpu_ticks(stat), Some(1234));
    assert_eq!(parse_cpu_ticks("4242 (truncated"), None);
}

#[test]
fn host_progress_requires_near_full_service_work_or_replaced_guests() {
    let window = Duration::from_secs(30);
    let before = HostCpuSample {
        service_ticks: 1_000,
        qemu_ticks: 50_000,
        qemu_processes: 5,
    };
    let sample = |service: u64, qemu: u64| HostCpuSample {
        service_ticks: before.service_ticks + service,
        qemu_ticks: before.qemu_ticks + qemu,
        qemu_processes: 5,
    };

    // A livelocked guest spinning a full core is not progress by itself.
    assert!(!host_progressed(before, sample(0, 3_000), window));
    // A polling service with wedged guests is a stall.
    assert!(!host_progressed(before, sample(1_500, 10), window));
    assert!(host_progressed(before, sample(2_250, 0), window));
    // Replaced guests restart their totals and count as progress.
    let replaced = HostCpuSample {
        qemu_ticks: 10,
        ..before
    };
    assert!(host_progressed(before, replaced, window));
}

#[test]
fn thread_samples_keep_spaced_names_and_scheduler_state() {
    let stat = "4243 (CPU 0/TCG) R 1 2 3 4 5 6 7 8 9 10 1200 34 0 0 20 0 9 0 100";

    assert_eq!(
        parse_thread_sample(4242, 4243, stat),
        Some(QemuThreadSample {
            pid: 4242,
            tid: 4243,
            name: "CPU_0/TCG".to_owned(),
            state: 'R',
            ticks: 1234,
        })
    );
}

#[test]
fn reported_guest_progress_keeps_clocks_and_drops_window_counts() {
    let row = |quanta: u32, clock: u64| {
        format!(
            "CRUCIBLE-ATTEMPT-PROGRESS-V1 window_ms=30004 quanta={quanta} frontier_ps=4100000000 nodes=router-a:{quanta}/27900/900/4150000000/{clock},router-b:7/1/2/4150000000/4100000000"
        )
    };

    let first = reported_guest_progress(&row(812, 4_149_999_950));
    assert_eq!(
        first.as_deref(),
        Some("frontier_ps=4100000000 clocks=router-a:4149999950,router-b:4100000000")
    );
    // More dispatched quanta with no clock movement report the same progress.
    assert_eq!(reported_guest_progress(&row(900, 4_149_999_950)), first);
    assert_ne!(reported_guest_progress(&row(900, 4_150_000_000)), first);
    assert_eq!(reported_guest_progress("CRUCIBLE-ATTEMPT-DISPATCH-V1 runs="), None);
}

#[test]
fn policy_horizon_sets_a_generous_safety_cap_above_the_stall_window() {
    let envoy = AttemptWaitLimits::for_policy_horizon(30_000_000_000_000);
    let tiny = AttemptWaitLimits::for_policy_horizon(1);

    assert_eq!(envoy.safety_cap(), Duration::from_secs(30_000));
    assert_eq!(tiny.safety_cap(), STALL_WINDOW);
}
