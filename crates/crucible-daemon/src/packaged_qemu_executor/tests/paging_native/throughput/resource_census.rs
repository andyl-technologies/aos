//! Bounded controller-thread kernel observations at stopped benchmark cuts.
//!
//! Reservations remain separate from these measurements. Shared RSS sums
//! mappings and can count an inode more than once; PSS is the kernel's
//! proportional attribution. Storage deduplicates actual `(device, inode)`
//! identities, including unlinked attempt files, and excludes the catalog.
//! Attempt storage includes the admitted host-run and lifecycle run-state
//! roots, deduplicated together.
//! Cgroup file bytes include shared memory; these counters are overlapping
//! subsets, not additive categories. Proc KiB and inode 512-byte blocks retain
//! their kernel precision when converted to byte units.
//! These are best-effort kernel observations, not an atomic snapshot or cleanup
//! authority. Process birth/inode tags and membership are rechecked; observed
//! identity changes make process-attributed measurements unavailable.

use super::workers::WorkerService;
use crucible_linux_resource::host_supervision::{HostOperationClass, HostOperationGuard};
use rustix::fs::{CWD, Mode, OFlags, RawDir};
use serde::Serialize;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_TEXT: usize = 64 * 1024;
const MAX_PATH: usize = 1024;
const MAX_PENDING: usize = 128;
const MAX_PROCESSES: usize = 1024;
const MAX_INODES: usize = 16_384;
const MAX_VISITS: usize = 131_072;
pub(super) const SCRATCH_BYTES: u64 = 1 << 20;
pub(super) const DESCRIPTORS: u64 = 2;

// Retained path capacity can grow to twice the accepted path length. The
// sorted inode table uses no auxiliary sort allocation. Two proc text bodies,
// the PID table, explicit getdents buffer and fixed transient paths fit beside
// these arrays. RawDir borrows the fixed buffer; no libc DIR allocation occurs.
const SCRATCH_PAYLOAD_BOUND: usize = MAX_INODES * std::mem::size_of::<(u64, u64, u64, bool)>()
    + MAX_PENDING * (std::mem::size_of::<PathBuf>() + 2 * MAX_PATH)
    + 2 * (MAX_TEXT + 1)
    + 2 * MAX_PROCESSES * std::mem::size_of::<u32>()
    + MAX_PROCESSES * std::mem::size_of::<ProcessIdentity>()
    + 4096
    + 2 * (MAX_PATH + 1)
    + 32 * 1024;
const _: () = assert!(SCRATCH_PAYLOAD_BOUND <= SCRATCH_BYTES as usize);

#[derive(Debug, Default, Serialize)]
pub(super) struct Census {
    pub(super) sampling_elapsed_ns: Option<u64>,
    pub(super) process_count: Option<usize>,
    pub(super) process_memory: Option<ProcessMemory>,
    pub(super) cgroup_memory: Option<CgroupMemory>,
    pub(super) attempt_storage: Option<Storage>,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct ProcessMemory {
    private_rss_bytes: u64,
    shared_mapping_rss_bytes: u64,
    proportional_set_bytes: u64,
    page_table_bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct CgroupMemory {
    current_bytes: Option<u64>,
    anonymous_bytes: Option<u64>,
    file_bytes: Option<u64>,
    shared_memory_bytes: Option<u64>,
    page_table_bytes: Option<u64>,
    kernel_stack_bytes: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct Storage {
    allocated_bytes: u64,
    unique_inodes: usize,
    unlinked_inodes: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    birth_tick: u64,
    device: u64,
    inode: u64,
}

pub(super) fn sample(controller: &WorkerService, cgroup: &Path, storage: &[&Path]) -> Census {
    let started = super::report::now();
    // The lease precedes every allocation/open. All walkers, files and buffers
    // drop before it. The receipt contains only scalar observations, financed
    // by the report's retained loan. No extra monitor task is created.
    let Ok(_loan) = controller.reserve_census() else {
        return Census::default();
    };
    let supervisor = controller.supervisor();
    let Ok(guard) = supervisor.begin(HostOperationClass::Preparation) else {
        return Census::default();
    };
    let processes = processes(cgroup, &guard);
    let before = processes
        .as_ref()
        .ok()
        .and_then(|pids| process_identities(pids, &guard).ok());
    let mut census = Census {
        sampling_elapsed_ns: None,
        process_count: processes.as_ref().ok().map(Vec::len),
        process_memory: processes
            .as_ref()
            .ok()
            .and_then(|pids| memory(pids, &guard).ok()),
        cgroup_memory: cgroup_memory(cgroup, &guard).ok(),
        attempt_storage: processes
            .as_ref()
            .ok()
            .and_then(|pids| storage_usage(storage, pids, &guard).ok()),
    };
    let stable = match (&processes, before) {
        (Ok(pids), Some(before)) => {
            stable_processes(cgroup, pids, &before, &guard).unwrap_or(false)
        }
        _ => false,
    };
    if !stable {
        census.process_count = None;
        census.process_memory = None;
        census.attempt_storage = None;
    }
    if guard.complete().is_err() {
        return Census::default();
    }
    census.sampling_elapsed_ns = super::report::now().checked_sub(started);
    census
}

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

fn check(guard: &HostOperationGuard) -> io::Result<()> {
    guard
        .wait_slice()
        .map(|_| ())
        .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))
}

fn text(path: &Path, guard: &HostOperationGuard) -> io::Result<String> {
    check(guard)?;
    let mut file = std::fs::File::open(path)?;
    let mut bytes = vec![0; MAX_TEXT + 1];
    let mut count = 0;
    while count < bytes.len() {
        check(guard)?;
        let read = file.read(&mut bytes[count..])?;
        if read == 0 {
            break;
        }
        count += read;
    }
    if count > MAX_TEXT {
        return Err(invalid());
    }
    bytes.truncate(count);
    String::from_utf8(bytes).map_err(|_| invalid())
}

fn field(text: &str, key: &str, kib: bool) -> io::Result<Option<u64>> {
    let mut result = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some(key) {
            continue;
        }
        if result.is_some() {
            return Err(invalid());
        }
        let value = words
            .next()
            .ok_or_else(invalid)?
            .parse::<u64>()
            .map_err(|_| invalid())?;
        if kib && words.next() != Some("kB") {
            return Err(invalid());
        }
        if words.next().is_some() {
            return Err(invalid());
        }
        result = Some(if kib {
            value.checked_mul(1024).ok_or_else(invalid)?
        } else {
            value
        });
    }
    Ok(result)
}

fn walk(
    root: &Path,
    guard: &HostOperationGuard,
    mut visit: impl FnMut(&Path, &std::fs::Metadata) -> io::Result<()>,
) -> io::Result<()> {
    if root.as_os_str().len() > MAX_PATH {
        return Err(invalid());
    }
    let mut pending = Vec::with_capacity(MAX_PENDING);
    pending.push(root.to_owned());
    let mut visited = 0;
    while let Some(path) = pending.pop() {
        check(guard)?;
        visited += 1;
        if visited > MAX_VISITS {
            return Err(invalid());
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        visit(&path, &metadata)?;
        if !metadata.is_dir() {
            continue;
        }
        directory_entries(&path, guard, |child| {
            let metadata = std::fs::symlink_metadata(child)?;
            if metadata.is_dir() {
                if pending.len() == MAX_PENDING {
                    return Err(invalid());
                }
                pending.push(child.to_owned());
            } else {
                visited += 1;
                if visited > MAX_VISITS {
                    return Err(invalid());
                }
                visit(child, &metadata)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn directory_entries(
    root: &Path,
    guard: &HostOperationGuard,
    mut visit: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    check(guard)?;
    let descriptor = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let mut entries = RawDir::new(descriptor, &mut buffer);
    let mut count = 0;
    while let Some(entry) = entries.next() {
        check(guard)?;
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        count += 1;
        if count > MAX_VISITS || name.len() > 255 {
            return Err(invalid());
        }
        let child = root.join(std::ffi::OsStr::from_bytes(name));
        if child.as_os_str().len() > MAX_PATH {
            return Err(invalid());
        }
        visit(&child)?;
    }
    Ok(())
}

fn processes(root: &Path, guard: &HostOperationGuard) -> io::Result<Vec<u32>> {
    let mut pids = Vec::with_capacity(MAX_PROCESSES);
    walk(root, guard, |path, metadata| {
        if metadata.is_dir() {
            for line in text(&path.join("cgroup.procs"), guard)?.lines() {
                let pid = line.parse::<u32>().map_err(|_| invalid())?;
                if pid == 0 || pids.len() == MAX_PROCESSES {
                    return Err(invalid());
                }
                pids.push(pid);
            }
        }
        Ok(())
    })?;
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn birth_tick(stat: &str, pid: u32) -> io::Result<u64> {
    // The command name may itself contain spaces and ')'. Numeric fields
    // follow the final closing parenthesis; starttime is field 22 (index 19
    // after the command). No command-name copy or parser heap is necessary.
    let (command, fields) = stat.rsplit_once(')').ok_or_else(invalid)?;
    let (number, _) = command.split_once('(').ok_or_else(invalid)?;
    if number.trim().parse::<u32>().map_err(|_| invalid())? != pid {
        return Err(invalid());
    }
    fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())
}

fn process_identity(pid: u32, guard: &HostOperationGuard) -> io::Result<ProcessIdentity> {
    let directory = PathBuf::from(format!("/proc/{pid}"));
    check(guard)?;
    let metadata = std::fs::metadata(&directory)?;
    let stat = text(&directory.join("stat"), guard)?;
    Ok(ProcessIdentity {
        pid,
        birth_tick: birth_tick(&stat, pid)?,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn process_identities(
    pids: &[u32],
    guard: &HostOperationGuard,
) -> io::Result<Vec<ProcessIdentity>> {
    if pids.len() > MAX_PROCESSES {
        return Err(invalid());
    }
    let mut identities = Vec::with_capacity(MAX_PROCESSES);
    for pid in pids {
        identities.push(process_identity(*pid, guard)?);
    }
    Ok(identities)
}

fn stable_processes(
    cgroup: &Path,
    pids: &[u32],
    before: &[ProcessIdentity],
    guard: &HostOperationGuard,
) -> io::Result<bool> {
    if processes(cgroup, guard)? != pids {
        return Ok(false);
    }
    for identity in before {
        if process_identity(identity.pid, guard)? != *identity {
            return Ok(false);
        }
    }
    Ok(true)
}

fn memory(pids: &[u32], guard: &HostOperationGuard) -> io::Result<ProcessMemory> {
    let mut result = ProcessMemory::default();
    for pid in pids {
        let rollup = text(Path::new(&format!("/proc/{pid}/smaps_rollup")), guard)?;
        let status = text(Path::new(&format!("/proc/{pid}/status")), guard)?;
        for (destination, keys, source) in [
            (
                &mut result.private_rss_bytes,
                &["Private_Clean:", "Private_Dirty:"][..],
                &rollup,
            ),
            (
                &mut result.shared_mapping_rss_bytes,
                &["Shared_Clean:", "Shared_Dirty:"][..],
                &rollup,
            ),
            (&mut result.proportional_set_bytes, &["Pss:"][..], &rollup),
            (&mut result.page_table_bytes, &["VmPTE:"][..], &status),
        ] {
            for key in keys {
                *destination = destination
                    .checked_add(field(source, key, true)?.ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
            }
        }
    }
    Ok(result)
}

fn cgroup_memory(root: &Path, guard: &HostOperationGuard) -> io::Result<CgroupMemory> {
    let stat = text(&root.join("memory.stat"), guard)?;
    let current = text(&root.join("memory.current"), guard)?;
    Ok(CgroupMemory {
        current_bytes: Some(current.trim().parse().map_err(|_| invalid())?),
        anonymous_bytes: field(&stat, "anon", false)?,
        file_bytes: field(&stat, "file", false)?,
        shared_memory_bytes: field(&stat, "shmem", false)?,
        page_table_bytes: field(&stat, "pagetables", false)?,
        kernel_stack_bytes: field(&stat, "kernel_stack", false)?,
    })
}

fn insert_inode(
    inodes: &mut Vec<(u64, u64, u64, bool)>,
    metadata: &std::fs::Metadata,
    unlinked: bool,
) -> io::Result<()> {
    if inodes.len() == MAX_INODES {
        return Err(invalid());
    }
    let bytes = metadata.blocks().checked_mul(512).ok_or_else(invalid)?;
    inodes.push((metadata.dev(), metadata.ino(), bytes, unlinked));
    Ok(())
}

fn summarize_inodes(inodes: &mut [(u64, u64, u64, bool)]) -> io::Result<Storage> {
    inodes.sort_unstable_by_key(|(device, inode, _, _)| (*device, *inode));
    let mut result = Storage::default();
    let mut previous = None;
    for &(device, inode, bytes, unlinked) in inodes.iter() {
        if let Some((old_device, old_inode, old_bytes, old_unlinked)) = previous
            && (device, inode) == (old_device, old_inode)
        {
            if (bytes, unlinked) != (old_bytes, old_unlinked) {
                return Err(invalid());
            }
            continue;
        }
        result.allocated_bytes = result
            .allocated_bytes
            .checked_add(bytes)
            .ok_or_else(invalid)?;
        result.unique_inodes += 1;
        result.unlinked_inodes += usize::from(unlinked);
        previous = Some((device, inode, bytes, unlinked));
    }
    Ok(result)
}

fn storage_usage(roots: &[&Path], pids: &[u32], guard: &HostOperationGuard) -> io::Result<Storage> {
    let mut inodes = Vec::with_capacity(MAX_INODES);
    if roots.len() > 2 {
        return Err(invalid());
    }
    for root in roots {
        walk(root, guard, |_, metadata| {
            insert_inode(&mut inodes, metadata, false)
        })?;
    }
    for pid in pids
        .iter()
        .copied()
        .chain(std::iter::once(std::process::id()))
    {
        directory_entries(Path::new(&format!("/proc/{pid}/fd")), guard, |descriptor| {
            let mut first = [0; MAX_PATH + 1];
            let target = match link_target(descriptor, &mut first, guard) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                result => result?,
            };
            if !roots.iter().any(|root| target.starts_with(root)) {
                return Ok(());
            }
            let metadata = match std::fs::metadata(descriptor) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                result => result?,
            };
            if metadata.is_file() && metadata.nlink() == 0 {
                let mut second = [0; MAX_PATH + 1];
                let after = std::fs::metadata(descriptor)?;
                if link_target(descriptor, &mut second, guard)? != target
                    || (after.dev(), after.ino(), after.blocks(), after.nlink())
                        != (
                            metadata.dev(),
                            metadata.ino(),
                            metadata.blocks(),
                            metadata.nlink(),
                        )
                {
                    return Err(invalid());
                }
                insert_inode(&mut inodes, &metadata, true)?;
            }
            Ok(())
        })?;
    }
    summarize_inodes(&mut inodes)
}

fn link_target<'a>(
    descriptor: &Path,
    buffer: &'a mut [u8; MAX_PATH + 1],
    guard: &HostOperationGuard,
) -> io::Result<&'a Path> {
    check(guard)?;
    // readlinkat_raw performs one syscall into caller storage. A full buffer
    // is rejected as possibly truncated; no PATH_MAX-driven growth occurs.
    let count = rustix::fs::readlinkat_raw(CWD, descriptor, &mut buffer[..])?;
    if count > MAX_PATH {
        return Err(invalid());
    }
    Ok(Path::new(std::ffi::OsStr::from_bytes(&buffer[..count])))
}

#[cfg(test)]
mod tests;
