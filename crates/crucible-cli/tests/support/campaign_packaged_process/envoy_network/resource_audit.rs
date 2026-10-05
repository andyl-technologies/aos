//! Live `/proc` resource and isolation audit for the five-guest Envoy HotFork.

use super::*;

#[derive(Debug)]
struct ProductQemuResources {
    pid: u32,
    parent_pid: u32,
    mappings: usize,
    descriptors: usize,
    threads: u64,
    private_dirty_kib: u64,
    writable_shared_guest_mappings: usize,
    ring_backings: BTreeSet<(String, u64)>,
    overlay_backings: BTreeSet<(u64, u64)>,
}

#[derive(Debug)]
pub(super) struct ProductHotForkResourceAudit {
    sources: Vec<ProductQemuResources>,
    children: Vec<ProductQemuResources>,
}

impl ProductHotForkResourceAudit {
    pub(super) fn verify_source_dirty_growth(&self) -> Result<(), Box<dyn Error>> {
        let mut growth_kib = 0_u64;
        for source in &self.sources {
            let path = PathBuf::from(format!("/proc/{}", source.pid));
            if !path.exists() {
                return Err(format!(
                    "frozen Envoy HotFork source {} vanished before service stop",
                    source.pid
                )
                .into());
            }
            let now = proc_field_kib(&path.join("smaps_rollup"), "Private_Dirty:")?;
            growth_kib = growth_kib.saturating_add(now.saturating_sub(source.private_dirty_kib));
        }
        if growth_kib > 512 * 1024 {
            return Err(format!(
                "frozen five-node Envoy source dirtied {growth_kib} KiB after its child ran"
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn verify_process_cleanup(&self) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = self
                .sources
                .iter()
                .chain(&self.children)
                .map(|process| process.pid)
                .filter(|pid| PathBuf::from(format!("/proc/{pid}")).exists())
                .collect::<Vec<_>>();
            if remaining.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "packaged Envoy service left hot-fork QEMU processes {remaining:?}"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

pub(super) fn wait_for_envoy_hot_fork_resources(
    service_pid: u32,
    canceled: &std::sync::atomic::AtomicBool,
) -> Result<ProductHotForkResourceAudit, String> {
    let deadline = Instant::now() + Duration::from_secs(900);
    while Instant::now() < deadline && !canceled.load(std::sync::atomic::Ordering::Acquire) {
        if let Some(audit) = sample_envoy_hot_fork_resources(service_pid)? {
            return Ok(audit);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("five-node Envoy HotFork never exposed five live source/child QEMU pairs with private ring and overlay resources".into())
}

fn sample_envoy_hot_fork_resources(
    service_pid: u32,
) -> Result<Option<ProductHotForkResourceAudit>, String> {
    let expected_qemu = required_path("CRUCIBLE_FLIGHT_QEMU")
        .map_err(|error| error.to_string())?
        .to_string_lossy()
        .into_owned();
    let descendants =
        descendant_process_commands(service_pid).map_err(|error| error.to_string())?;
    let qemu_pids = descendants
        .into_iter()
        .filter(|(_, arguments)| arguments.first() == Some(&expected_qemu))
        .map(|(pid, _)| pid)
        .collect::<Vec<_>>();
    if qemu_pids.len() != 10 {
        return Ok(None);
    }

    let mut processes = BTreeMap::new();
    for pid in qemu_pids {
        let Some(resources) = product_qemu_resources(pid)? else {
            return Ok(None);
        };
        processes.insert(pid, resources);
    }
    let child_pids = processes
        .values()
        .filter(|process| processes.contains_key(&process.parent_pid))
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    if child_pids.len() != 5 {
        return Ok(None);
    }

    let mut sources = Vec::new();
    let mut children = Vec::new();
    let mut ring_backings = BTreeSet::new();
    let mut overlay_backings = BTreeSet::new();
    for child_pid in child_pids {
        let Some(child) = processes.remove(&child_pid) else {
            return Ok(None);
        };
        let Some(source) = processes.remove(&child.parent_pid) else {
            return Ok(None);
        };
        if source.ring_backings.is_empty()
            || child.ring_backings.is_empty()
            || source.overlay_backings.is_empty()
            || child.overlay_backings.is_empty()
        {
            return Ok(None);
        }
        if !source.ring_backings.is_disjoint(&child.ring_backings) {
            // A just-forked child has not yet replaced the inherited mapping.
            return Ok(None);
        }
        for process in [&source, &child] {
            if process
                .overlay_backings
                .iter()
                .any(|backing| !overlay_backings.insert(*backing))
                || process
                    .ring_backings
                    .iter()
                    .any(|backing| !ring_backings.insert(backing.clone()))
            {
                return Ok(None);
            }
        }
        sources.push(source);
        children.push(child);
    }

    let total_descriptors = sources
        .iter()
        .chain(&children)
        .map(|process| process.descriptors)
        .sum::<usize>();
    let total_threads = sources
        .iter()
        .chain(&children)
        .map(|process| process.threads)
        .sum::<u64>();
    let child_private_dirty_kib = children
        .iter()
        .map(|process| process.private_dirty_kib)
        .sum::<u64>();
    // Each guest has 512 MiB RAM. A full private copy of every child's RAM
    // would exceed this half-RAM-per-child dirty ceiling at child readiness.
    const MAX_CHILD_PRIVATE_DIRTY_KIB: u64 = 5 * 256 * 1024;
    if total_descriptors > 16_384
        || total_threads > 256
        || child_private_dirty_kib > MAX_CHILD_PRIVATE_DIRTY_KIB
        || sources
            .iter()
            .chain(&children)
            .any(|process| process.mappings == 0 || process.writable_shared_guest_mappings > 0)
    {
        return Err(format!(
            "Envoy HotFork exceeded product resource limits: descriptors={total_descriptors}, threads={total_threads}, child_private_dirty_kib={child_private_dirty_kib}"
        ));
    }
    Ok(Some(ProductHotForkResourceAudit { sources, children }))
}

fn product_qemu_resources(pid: u32) -> Result<Option<ProductQemuResources>, String> {
    let process = PathBuf::from(format!("/proc/{pid}"));
    let Ok(stat) = fs::read_to_string(process.join("stat")) else {
        return Ok(None);
    };
    let Some(parent_pid) = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(None);
    };
    let Ok(maps) = fs::read_to_string(process.join("maps")) else {
        return Ok(None);
    };
    let ring_backings = maps
        .lines()
        .filter(|line| line.contains("memfd:crucible-qemu-shmem"))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _address = fields.next()?;
            let _access = fields.next()?;
            let _offset = fields.next()?;
            let device = fields.next()?.to_owned();
            let inode = fields.next()?.parse::<u64>().ok()?;
            Some((device, inode))
        })
        .collect::<BTreeSet<_>>();
    let writable_shared_guest_mappings = maps
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else {
                return false;
            };
            if !fields
                .next()
                .is_some_and(|access| access.starts_with("rw-s"))
            {
                return false;
            }
            let Some((start, end)) = range.split_once('-') else {
                return false;
            };
            match (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16)) {
                (Ok(start), Ok(end)) => end.saturating_sub(start) >= 256 * 1024 * 1024,
                _ => false,
            }
        })
        .count();

    let Ok(descriptors) = fs::read_dir(process.join("fd")) else {
        return Ok(None);
    };
    let mut descriptor_count = 0;
    let mut overlay_backings = BTreeSet::new();
    for descriptor in descriptors {
        let Ok(descriptor) = descriptor else {
            return Ok(None);
        };
        descriptor_count += 1;
        let Ok(target) = fs::read_link(descriptor.path()) else {
            return Ok(None);
        };
        if !target
            .to_string_lossy()
            .contains("crucible-root-overlay.qcow2")
        {
            continue;
        }
        let Ok(fdinfo) = fs::read_to_string(process.join("fdinfo").join(descriptor.file_name()))
        else {
            return Ok(None);
        };
        let Some(flags) = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| u64::from_str_radix(value, 8).ok())
        else {
            return Ok(None);
        };
        if flags & 0o3 == 0 {
            continue;
        }
        let Ok(metadata) = fs::metadata(descriptor.path()) else {
            return Ok(None);
        };
        overlay_backings.insert((metadata.dev(), metadata.ino()));
    }
    let Ok(status) = fs::read_to_string(process.join("status")) else {
        return Ok(None);
    };
    let Some(threads) = proc_field(&status, "Threads:") else {
        return Ok(None);
    };
    let Ok(private_dirty_kib) = proc_field_kib(&process.join("smaps_rollup"), "Private_Dirty:")
    else {
        return Ok(None);
    };

    Ok(Some(ProductQemuResources {
        pid,
        parent_pid,
        mappings: maps.lines().count(),
        descriptors: descriptor_count,
        threads,
        private_dirty_kib,
        writable_shared_guest_mappings,
        ring_backings,
        overlay_backings,
    }))
}

fn proc_field_kib(path: &Path, field: &str) -> Result<u64, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    proc_field(&content, field).ok_or_else(|| format!("{} omitted {field}", path.display()).into())
}

fn proc_field(content: &str, field: &str) -> Option<u64> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}
