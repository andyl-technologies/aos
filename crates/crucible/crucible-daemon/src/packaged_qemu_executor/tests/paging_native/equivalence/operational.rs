//! Operational process, storage, and elapsed-time acceptance measurements.

use super::*;
use std::os::unix::fs::MetadataExt;

// Operational measurements never enter modeled state or continuation decisions.
pub(super) fn operational_monotonic_nanoseconds() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .expect("positive monotonic seconds")
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            seconds.checked_add(u64::try_from(now.tv_nsec).expect("positive nanoseconds"))
        })
        .expect("bounded operational clock")
}

pub(super) fn count_process_entries(processes: &[u32], kind: &str) -> usize {
    processes
        .iter()
        .map(|pid| {
            std::fs::read_dir(format!("/proc/{pid}/{kind}"))
                .expect("actual retained process inventory")
                .count()
        })
        .sum()
}

pub(super) fn cgroup_processes(root: &Path) -> Vec<u32> {
    let mut processes = std::fs::read_to_string(root.join("cgroup.procs"))
        .expect("actual child cgroup process inventory")
        .lines()
        .map(|pid| pid.parse().expect("canonical Linux PID"))
        .collect::<Vec<_>>();
    for entry in std::fs::read_dir(root).expect("actual child cgroup hierarchy") {
        let entry = entry.expect("cgroup directory entry");
        if entry.file_type().expect("cgroup entry type").is_dir() {
            processes.extend(cgroup_processes(&entry.path()));
        }
    }
    processes.sort_unstable();
    processes.dedup();
    processes
}

pub(super) fn allocated_tree_bytes(root: &Path) -> u64 {
    let metadata = std::fs::symlink_metadata(root).expect("actual retained storage metadata");
    let mut allocated = metadata
        .blocks()
        .checked_mul(512)
        .expect("bounded allocated size");
    if metadata.is_dir() {
        for entry in std::fs::read_dir(root).expect("actual retained storage tree") {
            allocated = allocated
                .checked_add(allocated_tree_bytes(&entry.expect("storage entry").path()))
                .expect("bounded storage usage");
        }
    }
    allocated
}

/// Counts anonymous disk extents once across actual process and host aliases.
///
/// Only unlinked regular descriptors beneath the admitted run roots qualify.
/// Memfds and immutable CAS descriptors are outside these disk namespaces.
pub(super) fn unlinked_disk_files(processes: &[u32], roots: &[&Path]) -> BTreeMap<(u64, u64), u64> {
    let mut files = BTreeMap::new();
    for pid in processes {
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
            .expect("actual preservation descriptor inventory")
        {
            let descriptor = entry.expect("actual descriptor entry").path();
            // The host can close an ephemeral lookup descriptor while the
            // paused QEMU still owns every preservation file. Closed aliases
            // have no extents to count; all other observation failures refuse.
            let target = match std::fs::read_link(&descriptor) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("actual descriptor target: {error}"),
            };
            if !roots.iter().any(|root| target.starts_with(root)) {
                continue;
            }
            let metadata = match std::fs::metadata(&descriptor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("actual preservation inode: {error}"),
            };
            if !metadata.is_file() || metadata.nlink() != 0 {
                continue;
            }
            assert_eq!(
                std::fs::read_link(&descriptor).expect("stable owned descriptor target"),
                target,
                "descriptor authority changed during paused storage observation"
            );
            let allocated = metadata
                .blocks()
                .checked_mul(512)
                .expect("bounded disk blocks");
            if let Some(previous) = files.insert((metadata.dev(), metadata.ino()), allocated) {
                assert_eq!(
                    previous, allocated,
                    "paused inode extents changed between aliases"
                );
            }
        }
    }
    files
}

pub(super) fn inode_allocated_bytes(files: &BTreeMap<(u64, u64), u64>) -> u64 {
    files
        .values()
        .try_fold(0_u64, |total, bytes| total.checked_add(*bytes))
        .expect("bounded independently owned preservation extents")
}

#[test]
fn anonymous_disk_observation_deduplicates_aliases_and_excludes_linked_artifacts() {
    use std::io::Write;

    let root = tempfile::TempDir::new().expect("actual disk namespace");
    let preserved_path = root.path().join("preserved");
    let mut preserved = std::fs::File::create(&preserved_path).expect("private disk inode");
    preserved
        .write_all(&[0x5a; 4096])
        .expect("actual preservation blocks");
    let alias = preserved
        .try_clone()
        .expect("second owned descriptor alias");
    let identity = preserved.metadata().expect("actual inode identity");
    std::fs::remove_file(&preserved_path).expect("retained unlinked inode");
    let linked_path = root.path().join("linked-artifact");
    let mut linked = std::fs::File::create(&linked_path).expect("ordinary linked artifact");
    linked.write_all(&[0xa5; 4096]).expect("linked disk blocks");

    let files = unlinked_disk_files(&[std::process::id()], &[root.path()]);

    assert_eq!(files.len(), 1);
    assert_eq!(
        files.get(&(identity.dev(), identity.ino())),
        Some(&(identity.blocks() * 512))
    );
    assert_eq!(inode_allocated_bytes(&files), identity.blocks() * 512);
    assert!(alias.metadata().expect("alias remains owned").nlink() == 0);
    assert!(
        linked
            .metadata()
            .expect("linked artifact remains owned")
            .nlink()
            == 1
    );
}

#[derive(Clone, Copy, Default)]
pub(super) struct MemoryEvidence {
    pub(super) private_dirty_kib: u64,
    pub(super) private_rss_kib: u64,
    pub(super) vm_pte_kib: u64,
    pub(super) vm_data_kib: u64,
    pub(super) anon_huge_pages_kib: u64,
    pub(super) numa_resident_pages: u64,
    pub(super) numa_nodes: usize,
}

pub(super) fn process_memory_evidence(processes: &[u32]) -> MemoryEvidence {
    let mut evidence = MemoryEvidence::default();
    let mut numa_nodes = std::collections::BTreeSet::new();
    for pid in processes {
        let field = |file: &str, label: &str| {
            let text = std::fs::read_to_string(format!("/proc/{pid}/{file}"))
                .expect("actual process memory evidence");
            text.lines()
                .find_map(|line| line.strip_prefix(label))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .expect("canonical process memory field")
        };
        let dirty = field("smaps_rollup", "Private_Dirty:");
        evidence.private_dirty_kib += dirty;
        evidence.private_rss_kib += dirty + field("smaps_rollup", "Private_Clean:");
        evidence.vm_pte_kib += field("status", "VmPTE:");
        evidence.vm_data_kib += field("status", "VmData:");
        evidence.anon_huge_pages_kib += field("smaps_rollup", "AnonHugePages:");
        let numa = std::fs::read_to_string(format!("/proc/{pid}/numa_maps"))
            .expect("actual NUMA memory evidence");
        for token in numa.split_whitespace() {
            if let Some((node, pages)) = token.split_once('=')
                && let Some(node) = node.strip_prefix('N')
                && node.chars().all(|character| character.is_ascii_digit())
            {
                numa_nodes.insert(node.to_owned());
                evidence.numa_resident_pages +=
                    pages.parse::<u64>().expect("canonical NUMA page count");
            }
        }
    }
    evidence.numa_nodes = numa_nodes.len();
    evidence
}

pub(super) fn print_memory(index: usize, before: MemoryEvidence, after: MemoryEvidence) {
    println!("corpus_{index}_vm_pte_kib={}", before.vm_pte_kib);
    println!("corpus_{index}_vm_data_kib={}", before.vm_data_kib);
    println!(
        "corpus_{index}_anon_huge_pages_kib={}",
        before.anon_huge_pages_kib
    );
    println!(
        "corpus_{index}_numa_resident_pages={}",
        before.numa_resident_pages
    );
    println!("corpus_{index}_numa_nodes={}", before.numa_nodes);
    println!("corpus_{index}_post_dirty_vm_pte_kib={}", after.vm_pte_kib);
    println!(
        "corpus_{index}_post_dirty_vm_data_kib={}",
        after.vm_data_kib
    );
    println!(
        "corpus_{index}_post_dirty_anon_huge_pages_kib={}",
        after.anon_huge_pages_kib
    );
    println!(
        "corpus_{index}_post_dirty_numa_resident_pages={}",
        after.numa_resident_pages
    );
    println!("corpus_{index}_post_dirty_numa_nodes={}", after.numa_nodes);
}
