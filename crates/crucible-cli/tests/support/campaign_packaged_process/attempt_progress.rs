//! Progress-bounded waits for whole campaign attempts.
//!
//! An attempt's semantic horizon is its campaign policy: a bounded stop ends
//! in a policy timeout once virtual time reaches the policy deadline, so the
//! harness needs no wall-clock ceiling of its own, and a run may take minutes
//! or hours depending on the host. A wait instead fails when the attempt
//! makes no observable progress for a bounded stall window, or when an outer
//! safety cap derived from the policy horizon expires.
//!
//! Progress is either a change in the public state the wait already reads,
//! such as the campaign snapshot or the attempt's runtime phase, or host
//! execution sampled from `/proc`:
//!
//! ```text
//! qemu    CPU time of the service's QEMU descendants   guest execution
//! service CPU time of the service process itself       publication work
//! ```
//!
//! A wedged guest, for example one waiting on a lost control acknowledgement,
//! consumes almost no CPU while the service keeps polling it. QEMU time
//! therefore counts above a small fraction of one core, and service time
//! only when it is close to a full core, which polling does not reach.
//! Sampled CPU time is advisory: it only extends a wait and never satisfies
//! one.

use super::*;

// Linux reports `/proc/<pid>/stat` CPU times in USER_HZ ticks, fixed at 100
// per second by the kernel ABI.
const PROC_TICKS_PER_SECOND: u64 = 100;
// Host progress is judged over windows this long.
const PROGRESS_SAMPLE: Duration = Duration::from_secs(30);
// QEMU time above this share of one core within a sample is guest progress.
const QEMU_PROGRESS_PERCENT: u64 = 5;
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

/// Returns whether a sample window shows guest or host work.
fn host_progressed(before: HostCpuSample, after: HostCpuSample, window: Duration) -> bool {
    let window_ticks = u64::try_from(window.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_mul(PROC_TICKS_PER_SECOND)
        / 1_000;
    let qemu = after.qemu_ticks.saturating_sub(before.qemu_ticks);
    let service = after.service_ticks.saturating_sub(before.service_ticks);
    // A replaced QEMU set restarts its totals; its new guests count as work.
    let qemu_replaced = after.qemu_ticks < before.qemu_ticks && after.qemu_ticks != 0;

    qemu_replaced
        || qemu.saturating_mul(100) >= window_ticks.saturating_mul(QEMU_PROGRESS_PERCENT)
        || service.saturating_mul(100) >= window_ticks.saturating_mul(SERVICE_PROGRESS_PERCENT)
}

/// Tracks one attempt wait and fails it once progress stops.
pub(super) struct AttemptProgressWatch {
    label: String,
    service_pid: u32,
    limits: AttemptWaitLimits,
    started: Instant,
    last_progress: Instant,
    public_state: Option<String>,
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
            sample_started: now,
            sample: HostCpuSample::read(service_pid),
            next_report: now + PROGRESS_REPORT,
        }
    }

    /// Returns the instant at which the outer safety cap expires.
    pub(super) fn deadline(&self) -> Instant {
        self.started + self.limits.safety_cap()
    }

    /// Records one observation of the attempt's public state.
    ///
    /// `public_state` is any stable rendering of what the wait observed; a
    /// change counts as progress.
    ///
    /// # Errors
    ///
    /// Returns an error naming the last observed state when neither the
    /// public state nor sampled host execution advanced for the stall window.
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
                "{} made no progress for {}s; {}",
                self.label,
                idle.as_secs(),
                self.progress_row(now)
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
            "CRUCIBLE-ATTEMPT-WAIT-V1 label={:?} elapsed_s={} idle_s={} stall_s={} cap_s={} qemu_processes={} qemu_cpu_s={} service_cpu_s={} state={:?}",
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
fn host_progress_requires_guest_work_or_near_full_service_work() {
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

    // Five percent of one core over thirty seconds is 150 ticks.
    assert!(host_progressed(before, sample(0, 150), window));
    assert!(!host_progressed(before, sample(0, 149), window));
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
fn policy_horizon_sets_a_generous_safety_cap_above_the_stall_window() {
    let envoy = AttemptWaitLimits::for_policy_horizon(30_000_000_000_000);
    let tiny = AttemptWaitLimits::for_policy_horizon(1);

    assert_eq!(envoy.safety_cap(), Duration::from_secs(30_000));
    assert_eq!(tiny.safety_cap(), STALL_WINDOW);
}
