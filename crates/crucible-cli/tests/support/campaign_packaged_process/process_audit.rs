//! Live QEMU process, guest workload, and private resource evidence for VM flights.

use super::*;

#[derive(Default)]
pub(super) struct ProcessAudit {
    observed: BTreeSet<u32>,
    guest_arguments: BTreeMap<u32, BTreeSet<String>>,
    private_fork: bool,
}

struct QemuResources {
    pid: u32,
    parent: u32,
    rings: BTreeSet<(String, u64)>,
    overlays: BTreeSet<(u64, u64)>,
}

impl ProcessAudit {
    pub(super) fn observe(&mut self, service_pid: u32, fork: bool) -> Result<(), Box<dyn Error>> {
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
        loop {
            let remaining = self
                .observed
                .iter()
                .copied()
                .filter(|pid| PathBuf::from(format!("/proc/{pid}")).exists())
                .collect::<Vec<_>>();
            if remaining.is_empty() {
                self.observed.clear();
                self.guest_arguments.clear();
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("packaged service left QEMU processes {remaining:?}").into());
            }
            std::thread::sleep(PROCESS_OBSERVATION_INTERVAL);
        }
    }
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
