//! Live QEMU process, guest workload, and private resource evidence for VM flights.

use super::*;
use std::io::Write;

#[derive(Default)]
pub(super) struct ProcessAudit {
    observed: BTreeSet<u32>,
    guest_arguments: BTreeMap<u32, BTreeSet<String>>,
    private_fork: bool,
    cpu_reports_remaining: u16,
    cpu_observations: BTreeMap<u32, CpuObservation>,
    service_pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuObservation {
    start_time_ticks: u64,
    cpu_ticks: u64,
}

impl CpuObservation {
    fn parse(stat: &str) -> Option<Self> {
        if stat.len() > 4096 {
            return None;
        }
        let (_, fields) = stat.rsplit_once(") ")?;
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        let user: u64 = fields.get(11)?.parse().ok()?;
        let system: u64 = fields.get(12)?.parse().ok()?;
        Some(Self {
            start_time_ticks: fields.get(19)?.parse().ok()?,
            cpu_ticks: user.checked_add(system)?,
        })
    }

    fn delta_from(self, prior: Self) -> Option<u64> {
        (self.start_time_ticks == prior.start_time_ticks)
            .then(|| self.cpu_ticks.checked_sub(prior.cpu_ticks))
            .flatten()
    }
}

struct QemuResources {
    pid: u32,
    parent: u32,
    rings: BTreeSet<(String, u64)>,
    overlays: BTreeSet<(u64, u64)>,
}

impl ProcessAudit {
    /// Enables bounded CPU snapshots only for the explicit diagnostic flight.
    pub(super) fn with_cpu_diagnostics(maximum: u16) -> Self {
        Self {
            cpu_reports_remaining: maximum.min(256),
            ..Self::default()
        }
    }

    pub(super) fn report_observed_processes(&mut self, stage: &str) {
        const MAX_REPORTED_PROCESSES: usize = 32;
        println!(
            "packaged_process_audit stage={stage} observed_qemu_count={} omitted_processes={} private_fork_observed={}",
            self.observed.len(),
            self.observed.len().saturating_sub(MAX_REPORTED_PROCESSES),
            self.private_fork,
        );
        for pid in self.observed.iter().take(MAX_REPORTED_PROCESSES) {
            let workloads = self.guest_arguments.get(pid).map(|arguments| {
                arguments
                    .iter()
                    .filter_map(|argument| argument.strip_prefix("crucible.workload="))
                    .take(8)
                    .collect::<Vec<_>>()
            });
            println!(
                "packaged_process_audit stage={stage} observed_qemu_pid={pid} observed_workloads={workloads:?}"
            );
        }
        self.report_cpu_with(stage, |pid| {
            fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| CpuObservation::parse(&stat))
        });
    }

    /// Reads only retained service/guest PIDs, never scans for new processes.
    fn report_cpu_with(
        &mut self,
        stage: &str,
        mut read: impl FnMut(u32) -> Option<CpuObservation>,
    ) {
        if self.cpu_reports_remaining == 0 {
            return;
        }
        self.cpu_reports_remaining -= 1;
        let mut stdout = std::io::stdout().lock();
        let pids = self
            .service_pid
            .into_iter()
            .chain(self.observed.iter().take(32).copied());
        for pid in pids {
            let Some(current) = read(pid) else {
                let _ = writeln!(
                    stdout,
                    "packaged_process_cpu stage={stage:?} pid={pid} snapshot=unavailable"
                );
                continue;
            };
            let previous = self.cpu_observations.get(&pid).copied();
            let delta = previous.and_then(|prior| current.delta_from(prior));
            let identity_matches =
                previous.is_none_or(|prior| prior.start_time_ticks == current.start_time_ticks);
            // Retain the first identity: a recycled PID never acquires a delta
            // from a different process's CPU counters.
            if previous.is_none() || (identity_matches && delta.is_some()) {
                self.cpu_observations.insert(pid, current);
            }
            let role = if self.service_pid == Some(pid) {
                "service"
            } else {
                "qemu"
            };
            let _ = writeln!(
                stdout,
                "packaged_process_cpu stage={stage:?} role={role} pid={pid} start_time_ticks={} cpu_ticks={} delta_cpu_ticks={delta:?} identity_matches={identity_matches} units=kernel-clock-ticks",
                current.start_time_ticks, current.cpu_ticks,
            );
        }
    }

    pub(super) fn observe(&mut self, service_pid: u32, fork: bool) -> Result<(), Box<dyn Error>> {
        if self.cpu_reports_remaining != 0 {
            self.service_pid = Some(service_pid);
        }
        let expected = required_path("CRUCIBLE_FLIGHT_QEMU")?
            .to_string_lossy()
            .into_owned();
        let mut resources = BTreeMap::new();
        for (pid, arguments) in descendant_process_commands(service_pid)? {
            if arguments.first() != Some(&expected) {
                continue;
            }
            self.observed.insert(pid);
            if let Some(command_line) = arguments
                .windows(2)
                .find(|pair| pair[0] == "-append")
                .map(|pair| &pair[1])
            {
                self.guest_arguments.insert(
                    pid,
                    command_line.split_whitespace().map(str::to_owned).collect(),
                );
            }
            if fork && let Some(resource) = qemu_resources(pid)? {
                resources.insert(pid, resource);
            }
        }
        if !fork || self.private_fork || resources.len() != 2 {
            return Ok(());
        }
        for child in resources.values() {
            let Some(source) = resources.get(&child.parent) else {
                continue;
            };
            if source.rings.is_empty()
                || child.rings.is_empty()
                || source.overlays.is_empty()
                || child.overlays.is_empty()
            {
                continue;
            }
            // Inherited descriptors may still be present during child adoption.
            // Count the pair only after both private resource sets are distinct.
            if !source.rings.is_disjoint(&child.rings)
                || !source.overlays.is_disjoint(&child.overlays)
            {
                continue;
            }
            self.private_fork = true;
            eprintln!(
                "single_guest_live_fork source_pid={} child_pid={} source_overlays={:?} child_overlays={:?}",
                source.pid, child.pid, source.overlays, child.overlays
            );
            break;
        }
        Ok(())
    }

    pub(super) fn require_private_fork(&self) -> Result<(), Box<dyn Error>> {
        if !self.private_fork {
            return Err("one-guest HotFork did not expose an actual source/child pair with distinct live ring and writable root-overlay backing files".into());
        }
        Ok(())
    }

    pub(super) fn require_guest_workloads(&self, workloads: &[&str]) -> Result<(), Box<dyn Error>> {
        let mut guests = BTreeSet::new();
        for workload in workloads {
            let argument = format!("crucible.workload={workload}");
            let guest = self
                .guest_arguments
                .iter()
                .find_map(|(pid, arguments)| arguments.contains(&argument).then_some(*pid));
            let Some(pid) = guest else {
                return Err(format!(
                    "packaged flight observed no owned QEMU guest for workload {workload}; guest arguments={:?}",
                    self.guest_arguments
                )
                .into());
            };
            if !guests.insert(pid) {
                return Err(format!(
                    "packaged flight cannot prove distinct guests: QEMU process {pid} carries multiple required workloads"
                )
                .into());
            }
        }
        eprintln!("packaged_guest_workloads_observed workloads={workloads:?} qemu_pids={guests:?}");
        Ok(())
    }

    pub(super) fn verify_cleanup(&mut self) -> Result<(), Box<dyn Error>> {
        if self.observed.is_empty() {
            return Err("packaged flight observed no physical QEMU process".into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut remaining = Vec::new();
        let cleaned = wait_for_process_observation(deadline, || {
            remaining = self
                .observed
                .iter()
                .copied()
                .filter(|pid| PathBuf::from(format!("/proc/{pid}")).exists())
                .collect::<Vec<_>>();
            if remaining.is_empty() {
                return Ok(Some(()));
            }
            Ok(None)
        })?;
        cleaned.ok_or_else(|| format!("packaged service left QEMU processes {remaining:?}"))?;
        self.observed.clear();
        self.guest_arguments.clear();
        Ok(())
    }
}

#[test]
fn cpu_snapshot_parser_preserves_units_and_rejects_pid_reuse() {
    let stat = "24 (qemu (worker)) R 1 0 0 0 0 0 0 0 0 0 17 9 0 0 0 0 1 0 12345";
    let observed = CpuObservation::parse(stat);
    assert_eq!(
        observed,
        Some(CpuObservation {
            start_time_ticks: 12345,
            cpu_ticks: 26
        })
    );
    let prior = CpuObservation {
        start_time_ticks: 12345,
        cpu_ticks: 20,
    };
    assert_eq!(
        observed.and_then(|current| current.delta_from(prior)),
        Some(6)
    );
    assert_eq!(
        CpuObservation {
            start_time_ticks: 12346,
            cpu_ticks: 30
        }
        .delta_from(prior),
        None
    );
    assert_eq!(
        CpuObservation {
            start_time_ticks: 12345,
            cpu_ticks: 19
        }
        .delta_from(prior),
        None
    );
    assert!(CpuObservation::parse("malformed stat").is_none());
}

#[test]
fn disabled_and_exhausted_cpu_diagnostics_never_read_process_files() {
    assert_eq!(
        ProcessAudit::with_cpu_diagnostics(u16::MAX).cpu_reports_remaining,
        256
    );

    let mut disabled = ProcessAudit::default();
    disabled.observed.insert(24);
    disabled.report_cpu_with("disabled", |_| panic!("disabled CPU snapshot read proc"));

    let mut enabled = ProcessAudit::with_cpu_diagnostics(1);
    enabled.observed.insert(24);
    enabled.report_cpu_with("sample", |_| {
        Some(CpuObservation {
            start_time_ticks: 1,
            cpu_ticks: 2,
        })
    });
    enabled.report_cpu_with("exhausted", |_| panic!("exhausted CPU snapshot read proc"));
    assert_eq!(enabled.cpu_reports_remaining, 0);
}

fn qemu_resources(pid: u32) -> Result<Option<QemuResources>, Box<dyn Error>> {
    let process = PathBuf::from(format!("/proc/{pid}"));
    let Ok(stat) = fs::read_to_string(process.join("stat")) else {
        return Ok(None);
    };
    let parent = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(1))
        .ok_or("QEMU process stat omits its parent")?
        .parse()?;
    let Ok(maps) = fs::read_to_string(process.join("maps")) else {
        return Ok(None);
    };
    let rings = maps
        .lines()
        .filter(|line| line.contains("memfd:crucible-qemu-shmem"))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            Some((fields.get(3)?.to_string(), fields.get(4)?.parse().ok()?))
        })
        .collect();
    let Ok(descriptors) = fs::read_dir(process.join("fd")) else {
        return Ok(None);
    };
    let mut overlays = BTreeSet::new();
    for entry in descriptors {
        let Ok(entry) = entry else {
            return Ok(None);
        };
        let Ok(target) = fs::read_link(entry.path()) else {
            return Ok(None);
        };
        if !target
            .to_string_lossy()
            .contains("crucible-root-overlay.qcow2")
        {
            continue;
        }
        let Ok(info) = fs::read_to_string(process.join("fdinfo").join(entry.file_name())) else {
            return Ok(None);
        };
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
            .ok_or("root-overlay descriptor omits its access flags")?;
        if flags & 0o3 == 0 {
            continue;
        }
        let Ok(metadata) = fs::metadata(entry.path()) else {
            return Ok(None);
        };
        overlays.insert((metadata.dev(), metadata.ino()));
    }
    Ok(Some(QemuResources {
        pid,
        parent,
        rings,
        overlays,
    }))
}

#[test]
fn workload_evidence_requires_both_http_guests() {
    let mut processes = ProcessAudit::default();
    assert!(
        processes
            .require_guest_workloads(&["httpget", "httpd"])
            .is_err()
    );

    processes
        .guest_arguments
        .insert(101, BTreeSet::from(["crucible.workload=httpget".into()]));
    assert!(
        processes
            .require_guest_workloads(&["httpget", "httpd"])
            .is_err()
    );

    processes
        .guest_arguments
        .insert(102, BTreeSet::from(["crucible.workload=httpd".into()]));
    processes
        .require_guest_workloads(&["httpget", "httpd"])
        .unwrap();

    processes.guest_arguments.remove(&102);
    processes
        .guest_arguments
        .get_mut(&101)
        .unwrap()
        .insert("crucible.workload=httpd".into());
    assert!(
        processes
            .require_guest_workloads(&["httpget", "httpd"])
            .is_err()
    );
}
