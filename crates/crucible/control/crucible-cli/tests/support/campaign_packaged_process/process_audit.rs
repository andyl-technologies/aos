//! Live QEMU process, guest workload, and private resource evidence for VM flights.

use super::*;
use std::io::Write;

#[path = "process_audit/fork_diagnostics.rs"]
mod fork_diagnostics;

#[derive(Default)]
pub(super) struct ProcessAudit {
    observed: BTreeSet<u32>,
    guest_arguments: BTreeMap<u32, BTreeSet<String>>,
    private_fork: bool,
    cpu_reports_remaining: u16,
    cpu_observations: BTreeMap<u32, CpuObservation>,
    service_pid: Option<u32>,
    fork_diagnostics: fork_diagnostics::ForkDiagnostics,
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
    start_time_ticks: Option<u64>,
    rings: BTreeSet<(String, u64)>,
    overlays: BTreeSet<(u64, u64)>,
    read_only_overlays: BTreeSet<(u64, u64)>,
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
        if fork {
            self.fork_diagnostics.begin_sample();
        }
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
            if fork {
                let mut incomplete = None;
                let mut partial = None;
                let observation = qemu_resources_at(
                    pid,
                    &PathBuf::from(format!("/proc/{pid}")),
                    &mut incomplete,
                    &mut partial,
                );
                if observation.is_err() && incomplete.is_none() {
                    incomplete = Some("process-parent-malformed".into());
                }
                self.fork_diagnostics.record(
                    pid,
                    observation
                        .as_ref()
                        .ok()
                        .and_then(Option::as_ref)
                        .or(partial.as_ref()),
                    incomplete.as_deref(),
                );
                if observation.is_err() {
                    self.fork_diagnostics
                        .refusal("resource-read-error", resources.len());
                    self.fork_diagnostics
                        .report("owned-process-sampling", &mut std::io::stderr().lock());
                }
                if let Some(resource) = observation? {
                    resources.insert(pid, resource);
                }
            }
        }
        if !fork || self.private_fork || resources.len() != 2 {
            if fork && !self.private_fork {
                self.fork_diagnostics
                    .refusal("resource-count-not-two", resources.len());
            }
            return Ok(());
        }
        self.fork_diagnostics
            .refusal("no-source-child-parent-pair", resources.len());
        for child in resources.values() {
            let Some(source) = resources.get(&child.parent) else {
                continue;
            };
            // Inherited descriptors may still be present during child adoption.
            // PREPARE seals the source read-only; only the child root must be writable.
            // Both live rings and every writable file alias remain distinct.
            if let Some(reason) = fork_diagnostics::pair_refusal(source, child) {
                self.fork_diagnostics.refusal(reason, resources.len());
                continue;
            }
            self.private_fork = true;
            eprintln!(
                "single_guest_live_fork source_pid={} child_pid={} source_read_only_overlay_count={} source_overlays={:?} child_overlays={:?}",
                source.pid,
                child.pid,
                source.read_only_overlays.len(),
                source.overlays,
                child.overlays
            );
            break;
        }
        Ok(())
    }

    pub(super) fn require_private_fork(&mut self, stage: &str) -> Result<(), Box<dyn Error>> {
        if !self.private_fork {
            self.fork_diagnostics
                .report(stage, &mut std::io::stderr().lock());
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

fn qemu_resources_at(
    pid: u32,
    process: &Path,
    incomplete: &mut Option<String>,
    partial: &mut Option<QemuResources>,
) -> Result<Option<QemuResources>, Box<dyn Error>> {
    *incomplete = None;
    *partial = None;
    let Ok(stat) = fs::read_to_string(process.join("stat")) else {
        *incomplete = Some("stat-unreadable".into());
        return Ok(None);
    };
    let parent: u32 = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(1))
        .ok_or_else(|| {
            *incomplete = Some("process-parent-field-unavailable".into());
            "QEMU process stat omits its parent"
        })?
        .parse()
        .inspect_err(|_error| *incomplete = Some("process-parent-malformed".into()))?;
    let start_time_ticks = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok());
    *partial = Some(QemuResources {
        pid,
        parent,
        start_time_ticks,
        rings: BTreeSet::new(),
        overlays: BTreeSet::new(),
        read_only_overlays: BTreeSet::new(),
    });
    if !process_identity_matches(&stat, pid, parent, start_time_ticks) {
        *incomplete = Some("process-identity-unavailable-or-stale".into());
        return Ok(None);
    }
    let Ok(maps) = fs::read_to_string(process.join("maps")) else {
        *incomplete = Some("maps-unreadable".into());
        return Ok(None);
    };
    let rings: BTreeSet<(String, u64)> = maps
        .lines()
        .filter(|line| line.contains("memfd:crucible-qemu-shmem"))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            Some((fields.get(3)?.to_string(), fields.get(4)?.parse().ok()?))
        })
        .collect();
    if let Some(progress) = partial.as_mut() {
        progress.rings.clone_from(&rings);
    }
    let Ok(descriptors) = fs::read_dir(process.join("fd")) else {
        *incomplete = Some("fd-directory-unreadable".into());
        return Ok(None);
    };
    let mut overlays = BTreeSet::new();
    let mut read_only_overlays = BTreeSet::new();
    for entry in descriptors {
        let Ok(entry) = entry else {
            *incomplete = Some("fd-entry-unreadable".into());
            return Ok(None);
        };
        let Ok(target) = fs::read_link(entry.path()) else {
            *incomplete = Some(format!("fd-link-unreadable fd={:?}", entry.file_name()));
            return Ok(None);
        };
        if !target
            .to_string_lossy()
            .contains("crucible-root-overlay.qcow2")
        {
            continue;
        }
        let Ok(info) = fs::read_to_string(process.join("fdinfo").join(entry.file_name())) else {
            *incomplete = Some(format!(
                "overlay-fdinfo-unreadable fd={:?}",
                entry.file_name()
            ));
            return Ok(None);
        };
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
            .ok_or_else(|| {
                *incomplete = Some(format!(
                    "overlay-access-flags-malformed fd={:?}",
                    entry.file_name()
                ));
                "root-overlay descriptor omits its access flags"
            })?;
        if flags & 0o3 == 0o3 || flags & u64::from(rustix::fs::OFlags::PATH.bits()) != 0 {
            *incomplete = Some(format!(
                "overlay-access-mode-invalid fd={:?}",
                entry.file_name()
            ));
            return Err(
                "root-overlay descriptor is not an ordinary readable or writable file".into(),
            );
        }
        let Ok(metadata) = fs::metadata(entry.path()) else {
            *incomplete = Some(format!(
                "overlay-metadata-unreadable fd={:?}",
                entry.file_name()
            ));
            return Ok(None);
        };
        if !metadata.is_file() || metadata.ino() == 0 {
            *incomplete = Some(format!(
                "overlay-file-identity-invalid fd={:?}",
                entry.file_name()
            ));
            return Ok(None);
        }
        let identity = (metadata.dev(), metadata.ino());
        if flags & 0o3 == 0 {
            read_only_overlays.insert(identity);
            if let Some(progress) = partial.as_mut() {
                progress.read_only_overlays.insert(identity);
            }
        } else {
            overlays.insert(identity);
            if let Some(progress) = partial.as_mut() {
                progress.overlays.insert(identity);
            }
        }
    }
    let resources = QemuResources {
        pid,
        parent,
        start_time_ticks,
        rings,
        overlays,
        read_only_overlays,
    };
    // Reject exit or PID reuse during the maps/descriptor read, before accepting
    // the resources as one live process observation.
    if !revalidate_process_identity(process, &resources) {
        *incomplete = Some("process-identity-changed-during-resource-read".into());
        return Ok(None);
    }
    Ok(Some(resources))
}

fn process_identity_matches(stat: &str, pid: u32, parent: u32, start: Option<u64>) -> bool {
    let observed_pid = stat
        .split_once(' ')
        .and_then(|(value, _)| value.parse::<u32>().ok());
    let Some((_, fields)) = stat.rsplit_once(") ") else {
        return false;
    };
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    let observed_parent = fields.get(1).and_then(|value| value.parse::<u32>().ok());
    let observed_start = fields.get(19).and_then(|value| value.parse::<u64>().ok());
    pid != 0
        && observed_pid == Some(pid)
        && observed_parent == Some(parent)
        && start.is_some()
        && observed_start == start
        && fields
            .first()
            .is_some_and(|state| !matches!(*state, "Z" | "X" | "x"))
}

fn revalidate_process_identity(process: &Path, resources: &QemuResources) -> bool {
    fs::read_to_string(process.join("stat")).is_ok_and(|stat| {
        process_identity_matches(
            &stat,
            resources.pid,
            resources.parent,
            resources.start_time_ticks,
        )
    })
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
