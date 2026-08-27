//! Bounded Linux process inventory for QEMU hot-fork audits.
//!
//! Hot-fork readiness remains a QEMU-owned protocol decision. This module
//! supplies the complementary host audit of one exact process generation: it
//! records every visible thread, descriptor, and mapping twice under fixed
//! entry and byte limits and accepts only an identical fixed point. The report
//! is operational evidence for the Phase 6 lab; it is not a child-resource
//! disposition table and cannot authorize a fork.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::{
    QemuNodeChannelError, QemuNodeError, QemuProcessIdentity, QmpHotForkRcuInventory,
    QmpHotForkReadiness, QmpHotForkThreadInventory,
};

/// Maximum threads, descriptors, or mappings retained by one audit.
pub const MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES: usize = 65_536;
/// Maximum aggregate bytes retained from one `/proc/<pid>` inventory pass.
pub const MAX_QEMU_HOT_FORK_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes retained for one thread name.
pub const MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES: usize = 256;
/// Maximum bytes retained for one descriptor target.
pub const MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES: usize = 4 * 1024;
/// Maximum bytes retained for one canonical `/proc/<pid>/maps` record.
pub const MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES: usize = 8 * 1024;

/// One Linux thread visible in the audited QEMU generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkThreadInventory {
    thread_id: u32,
    name: Vec<u8>,
}

impl QemuHotForkThreadInventory {
    /// Returns the Linux thread identifier.
    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Returns the exact bounded bytes from `/proc/<pid>/task/<tid>/comm`.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// One open Linux descriptor visible in the audited QEMU generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkDescriptorInventory {
    descriptor: u32,
    target: Vec<u8>,
}

impl QemuHotForkDescriptorInventory {
    /// Returns the process-local descriptor number.
    #[must_use]
    pub const fn descriptor(&self) -> u32 {
        self.descriptor
    }

    /// Returns the exact bounded `/proc/<pid>/fd/<n>` link target bytes.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.target
    }
}

/// One canonical Linux virtual-memory mapping record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkMappingInventory {
    record: Vec<u8>,
    writable: bool,
    shared: bool,
}

impl QemuHotForkMappingInventory {
    /// Returns the exact bounded record from `/proc/<pid>/maps`, without newline.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// Returns whether the kernel marks this mapping writable.
    #[must_use]
    pub const fn writable(&self) -> bool {
        self.writable
    }

    /// Returns whether the kernel marks this mapping shared.
    #[must_use]
    pub const fn shared(&self) -> bool {
        self.shared
    }
}

/// Stable two-pass inventory of one exact Linux QEMU process generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkProcessInventory {
    process: QemuProcessIdentity,
    threads: Vec<QemuHotForkThreadInventory>,
    descriptors: Vec<QemuHotForkDescriptorInventory>,
    mappings: Vec<QemuHotForkMappingInventory>,
    retained_bytes: usize,
}

impl QemuHotForkProcessInventory {
    /// Returns the exact process generation bracketed around the inventory.
    #[must_use]
    pub const fn process(&self) -> &QemuProcessIdentity {
        &self.process
    }

    /// Returns every visible thread in numeric identifier order.
    #[must_use]
    pub fn threads(&self) -> &[QemuHotForkThreadInventory] {
        &self.threads
    }

    /// Returns every visible descriptor in numeric order.
    #[must_use]
    pub fn descriptors(&self) -> &[QemuHotForkDescriptorInventory] {
        &self.descriptors
    }

    /// Returns every mapping in the kernel-provided address order.
    #[must_use]
    pub fn mappings(&self) -> &[QemuHotForkMappingInventory] {
        &self.mappings
    }

    /// Returns aggregate retained thread-name, descriptor-target, and map bytes.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Returns the number of writable shared mappings requiring disposition.
    #[must_use]
    pub fn writable_shared_mappings(&self) -> usize {
        self.mappings
            .iter()
            .filter(|mapping| mapping.writable() && mapping.shared())
            .count()
    }
}

/// Exact QEMU readiness and stable Linux process evidence from one audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkAudit {
    readiness: QmpHotForkReadiness,
    qemu_threads: QmpHotForkThreadInventory,
    qemu_rcu: QmpHotForkRcuInventory,
    process: QemuHotForkProcessInventory,
    externally_created_thread_ids: Vec<u32>,
}

impl QemuHotForkAudit {
    pub(crate) fn new(
        readiness: QmpHotForkReadiness,
        qemu_threads: QmpHotForkThreadInventory,
        qemu_rcu: QmpHotForkRcuInventory,
        process: QemuHotForkProcessInventory,
    ) -> Result<Self, QemuHotForkAuditError> {
        let mut qemu_index = 0_usize;
        let mut externally_created_thread_ids = Vec::new();
        for process_thread in process.threads() {
            let process_thread_id = process_thread.thread_id();
            if qemu_threads
                .threads()
                .get(qemu_index)
                .is_some_and(|thread| thread.thread_id() == process_thread_id)
            {
                qemu_index += 1;
            } else {
                externally_created_thread_ids.push(process_thread_id);
            }
        }
        if let Some(thread) = qemu_threads.threads().get(qemu_index) {
            return Err(QemuHotForkAuditError::RegisteredThreadMissing {
                thread_id: thread.thread_id(),
            });
        }
        let mut qemu_thread_index = 0_usize;
        for reader in qemu_rcu.readers() {
            while qemu_threads
                .threads()
                .get(qemu_thread_index)
                .is_some_and(|thread| thread.thread_id() < reader.thread_id())
            {
                qemu_thread_index += 1;
            }
            if qemu_threads
                .threads()
                .get(qemu_thread_index)
                .is_none_or(|thread| thread.thread_id() != reader.thread_id())
            {
                return Err(QemuHotForkAuditError::RcuReaderMissing {
                    thread_id: reader.thread_id(),
                });
            }
        }
        Ok(Self {
            readiness,
            qemu_threads,
            qemu_rcu,
            process,
            externally_created_thread_ids,
        })
    }

    /// Returns QEMU's exact versioned readiness proof report.
    #[must_use]
    pub const fn readiness(&self) -> QmpHotForkReadiness {
        self.readiness
    }

    /// Returns QEMU's matching bounded internal active-thread registry.
    #[must_use]
    pub const fn qemu_threads(&self) -> &QmpHotForkThreadInventory {
        &self.qemu_threads
    }

    /// Returns QEMU's matching bounded observational RCU inventory.
    #[must_use]
    pub const fn qemu_rcu(&self) -> &QmpHotForkRcuInventory {
        &self.qemu_rcu
    }

    /// Returns the matching stable process inventory.
    #[must_use]
    pub const fn process(&self) -> &QemuHotForkProcessInventory {
        &self.process
    }

    /// Returns procfs thread IDs absent from QEMU's internal registry.
    ///
    /// These threads may come from linked libraries or other raw pthread users;
    /// each remains a blocker until QEMU owns an explicit disposition for it.
    #[must_use]
    pub fn externally_created_thread_ids(&self) -> &[u32] {
        &self.externally_created_thread_ids
    }
}

/// Failure while capturing one exact hot-fork process audit.
#[derive(Debug, Error)]
pub enum QemuHotForkAuditError {
    /// The QEMU child identity could not be authenticated.
    #[error("QEMU process identity could not be authenticated for hot-fork audit")]
    ProcessIdentity(#[source] QemuNodeError),
    /// The QMP readiness query failed.
    #[error("QEMU hot-fork readiness query failed")]
    Readiness(#[source] QemuNodeChannelError),
    /// The QEMU-owned active-thread inventory query failed.
    #[error("QEMU hot-fork active-thread inventory query failed")]
    ThreadInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned RCU inventory query failed.
    #[error("QEMU hot-fork RCU inventory query failed")]
    RcuInventory(#[source] QemuNodeChannelError),
    /// QEMU was not at the exact paused/device-flush boundary.
    #[error("QEMU is not at the exact paused boundary required for hot-fork audit")]
    NotExactPausedBoundary,
    /// QEMU's proof bitmap changed around the process inventory.
    #[error("QEMU hot-fork readiness changed during process inventory")]
    ReadinessChanged,
    /// QEMU's internal active-thread registry changed around procfs capture.
    #[error("QEMU hot-fork active-thread inventory changed during process inventory")]
    ThreadInventoryChanged,
    /// QEMU's observational RCU inventory changed around procfs capture.
    #[error("QEMU hot-fork RCU inventory changed during process inventory")]
    RcuInventoryChanged,
    /// A QEMU-registered thread was absent from the exact procfs inventory.
    #[error("QEMU-registered thread {thread_id} is absent from the process inventory")]
    RegisteredThreadMissing {
        /// Missing registered operating-system thread identifier.
        thread_id: u32,
    },
    /// An RCU reader was absent from QEMU's exact active-thread registry.
    #[error("QEMU RCU reader {thread_id} is absent from the active-thread registry")]
    RcuReaderMissing {
        /// Missing RCU reader operating-system thread identifier.
        thread_id: u32,
    },
    /// Linux process inventory failed.
    #[error(transparent)]
    Inventory(#[from] QemuHotForkInventoryError),
}

/// Failure while reading a bounded Linux QEMU process inventory.
#[derive(Debug, Error)]
pub enum QemuHotForkInventoryError {
    /// The expected PID no longer exists.
    #[error("QEMU process {process_id} is not present")]
    ProcessMissing {
        /// Missing process identifier.
        process_id: u32,
    },
    /// The PID names another process generation or executable.
    #[error("QEMU process identity changed during hot-fork inventory")]
    ProcessIdentityChanged,
    /// Reading the current process generation failed.
    #[error("QEMU process {process_id} identity could not be read")]
    ProcessIdentityRead {
        /// Process identifier whose generation was requested.
        process_id: u32,
        /// Typed process-identity failure.
        source: QemuNodeError,
    },
    /// A `/proc` operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Affected procfs path.
        path: PathBuf,
        /// Underlying host error.
        source: io::Error,
    },
    /// A kernel record was malformed.
    #[error("QEMU hot-fork {category} inventory contains a malformed record")]
    Malformed {
        /// Stable inventory category.
        category: &'static str,
    },
    /// A dimension exceeded its fixed audit bound.
    #[error("QEMU hot-fork {category} inventory exceeds limit {limit}")]
    LimitExceeded {
        /// Stable inventory category.
        category: &'static str,
        /// Enforced maximum.
        limit: usize,
    },
    /// Two consecutive bounded passes did not identify one fixed point.
    #[error("QEMU process resources changed during hot-fork inventory")]
    InventoryChanged,
}

/// Captures one stable bounded inventory for an exact Linux QEMU generation.
///
/// The function authenticates `expected` before and after two complete passes
/// and requires the passes to match byte-for-byte. This proves only an observed
/// fixed point. It does not classify mutexes, make mappings fork-safe, or grant
/// child-reinitialization authority.
///
/// # Errors
///
/// Returns [`QemuHotForkInventoryError`] when the process is absent or changed,
/// procfs is unavailable or malformed, a bound is exceeded, or the two passes
/// differ.
pub(crate) fn capture_linux_qemu_hot_fork_process_inventory(
    expected: &QemuProcessIdentity,
) -> Result<QemuHotForkProcessInventory, QemuHotForkInventoryError> {
    require_process_identity(expected)?;
    let proc_directory = PathBuf::from("/proc").join(expected.process_id.to_string());

    // Warm the bounded allocations before the compared passes. This matters
    // when a diagnostic targets its own process in a conformance test: the
    // audit's allocator growth must not look like guest mapping drift.
    let warm = capture_once(&proc_directory, expected)?;
    drop(warm);
    let first = capture_once(&proc_directory, expected)?;
    let second = capture_once(&proc_directory, expected)?;
    require_process_identity(expected)?;
    if first != second {
        return Err(QemuHotForkInventoryError::InventoryChanged);
    }
    Ok(first)
}

fn require_process_identity(
    expected: &QemuProcessIdentity,
) -> Result<(), QemuHotForkInventoryError> {
    match crate::linux_process_identity(expected.process_id) {
        Ok(Some(observed)) if observed == *expected => Ok(()),
        Ok(Some(_)) => Err(QemuHotForkInventoryError::ProcessIdentityChanged),
        Ok(None) => Err(QemuHotForkInventoryError::ProcessMissing {
            process_id: expected.process_id,
        }),
        Err(source) => Err(QemuHotForkInventoryError::ProcessIdentityRead {
            process_id: expected.process_id,
            source,
        }),
    }
}

fn capture_once(
    proc_directory: &Path,
    process: &QemuProcessIdentity,
) -> Result<QemuHotForkProcessInventory, QemuHotForkInventoryError> {
    let mut retained_bytes = 0_usize;
    let threads = capture_threads(proc_directory, &mut retained_bytes)?;
    let descriptors = capture_descriptors(proc_directory, &mut retained_bytes)?;
    let mappings = capture_mappings(proc_directory, &mut retained_bytes)?;
    Ok(QemuHotForkProcessInventory {
        process: process.clone(),
        threads,
        descriptors,
        mappings,
        retained_bytes,
    })
}

fn capture_threads(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkThreadInventory>, QemuHotForkInventoryError> {
    let task_directory = proc_directory.join("task");
    let thread_ids = numeric_directory_entries(&task_directory, "thread-count")?;
    let mut threads = Vec::with_capacity(thread_ids.len());
    for thread_id in thread_ids {
        let path = task_directory.join(thread_id.to_string()).join("comm");
        let record_limit = MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES.checked_add(1).ok_or(
            QemuHotForkInventoryError::LimitExceeded {
                category: "thread-name-bytes",
                limit: MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES,
            },
        )?;
        let mut name = read_bounded_file(&path, record_limit, "thread-name-record-bytes")?;
        if name.last() == Some(&b'\n') {
            name.pop();
        }
        if name.len() > MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "thread-name-bytes",
                limit: MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES,
            });
        }
        charge_bytes(retained_bytes, name.len())?;
        threads.push(QemuHotForkThreadInventory { thread_id, name });
    }
    Ok(threads)
}

fn capture_descriptors(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkDescriptorInventory>, QemuHotForkInventoryError> {
    let descriptor_directory = proc_directory.join("fd");
    let descriptors = numeric_directory_entries(&descriptor_directory, "descriptor-count")?;
    let mut inventory = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let path = descriptor_directory.join(descriptor.to_string());
        let target = fs::read_link(&path)
            .map_err(|source| proc_io("read descriptor target", &path, source))?;
        let target = target.as_os_str().as_bytes();
        if target.len() > MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "descriptor-target-bytes",
                limit: MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES,
            });
        }
        charge_bytes(retained_bytes, target.len())?;
        inventory.push(QemuHotForkDescriptorInventory {
            descriptor,
            target: target.to_vec(),
        });
    }
    Ok(inventory)
}

fn capture_mappings(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkMappingInventory>, QemuHotForkInventoryError> {
    let path = proc_directory.join("maps");
    let file =
        File::open(&path).map_err(|source| proc_io("open mapping inventory", &path, source))?;
    let mut reader = BufReader::new(file);
    let mut mappings = Vec::new();
    loop {
        let Some(record) = read_bounded_line(
            &mut reader,
            MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES,
            "mapping-record-bytes",
            &path,
        )?
        else {
            break;
        };
        if mappings.len() == MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "mapping-count",
                limit: MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES,
            });
        }
        let (writable, shared) = validate_mapping_record(&record)?;
        charge_bytes(retained_bytes, record.len())?;
        mappings.push(QemuHotForkMappingInventory {
            record,
            writable,
            shared,
        });
    }
    Ok(mappings)
}

fn numeric_directory_entries(
    directory: &Path,
    category: &'static str,
) -> Result<Vec<u32>, QemuHotForkInventoryError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| proc_io("open process inventory directory", directory, source))?;
    let mut values = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|source| proc_io("read process inventory directory", directory, source))?;
        let Some(value) = parse_decimal_u32(entry.file_name().as_os_str().as_bytes()) else {
            return Err(QemuHotForkInventoryError::Malformed { category });
        };
        if values.len() == MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category,
                limit: MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES,
            });
        }
        values.push(value);
    }
    values.sort_unstable();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(QemuHotForkInventoryError::Malformed { category });
    }
    Ok(values)
}

fn parse_decimal_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then_some(())
            .and_then(|()| value.checked_mul(10))
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
    })
}

fn read_bounded_file(
    path: &Path,
    limit: usize,
    category: &'static str,
) -> Result<Vec<u8>, QemuHotForkInventoryError> {
    let file =
        File::open(path).map_err(|source| proc_io("open process inventory file", path, source))?;
    let maximum = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(QemuHotForkInventoryError::LimitExceeded { category, limit })?;
    let mut bytes = Vec::new();
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|source| proc_io("read process inventory file", path, source))?;
    if bytes.len() > limit {
        return Err(QemuHotForkInventoryError::LimitExceeded { category, limit });
    }
    Ok(bytes)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    category: &'static str,
    path: &Path,
) -> Result<Option<Vec<u8>>, QemuHotForkInventoryError> {
    let mut record = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|source| QemuHotForkInventoryError::Io {
                operation: "read process mapping inventory",
                path: path.to_path_buf(),
                source,
            })?;
        if available.is_empty() {
            return if record.is_empty() {
                Ok(None)
            } else {
                Ok(Some(record))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content_end = newline.unwrap_or(available.len());
        let new_length = record
            .len()
            .checked_add(content_end)
            .ok_or(QemuHotForkInventoryError::LimitExceeded { category, limit })?;
        if new_length > limit {
            return Err(QemuHotForkInventoryError::LimitExceeded { category, limit });
        }
        record.extend_from_slice(&available[..content_end]);
        if newline.is_some() {
            reader.consume(content_end + 1);
            return Ok(Some(record));
        }
        reader.consume(content_end);
    }
}

fn validate_mapping_record(record: &[u8]) -> Result<(bool, bool), QemuHotForkInventoryError> {
    let mut fields = record
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let range = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let permissions = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let offset = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let device = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let inode = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;

    let Some((start, end)) = split_once_byte(range, b'-') else {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    };
    if !valid_hex(start) || !valid_hex(end) || permissions.len() != 4 || !valid_hex(offset) {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    }
    let Some((major, minor)) = split_once_byte(device, b':') else {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    };
    if !valid_hex(major)
        || !valid_hex(minor)
        || inode.is_empty()
        || !inode.iter().all(|byte| byte.is_ascii_digit())
        || !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    }
    Ok((permissions[1] == b'w', permissions[3] == b's'))
}

fn valid_hex(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| byte.is_ascii_hexdigit())
}

fn split_once_byte(bytes: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == delimiter)?;
    let (before, after) = bytes.split_at(index);
    Some((before, &after[1..]))
}

fn charge_bytes(retained: &mut usize, amount: usize) -> Result<(), QemuHotForkInventoryError> {
    let next = retained
        .checked_add(amount)
        .ok_or(QemuHotForkInventoryError::LimitExceeded {
            category: "aggregate-bytes",
            limit: MAX_QEMU_HOT_FORK_INVENTORY_BYTES,
        })?;
    if next > MAX_QEMU_HOT_FORK_INVENTORY_BYTES {
        return Err(QemuHotForkInventoryError::LimitExceeded {
            category: "aggregate-bytes",
            limit: MAX_QEMU_HOT_FORK_INVENTORY_BYTES,
        });
    }
    *retained = next;
    Ok(())
}

fn proc_io(operation: &'static str, path: &Path, source: io::Error) -> QemuHotForkInventoryError {
    QemuHotForkInventoryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn fixture_inventory_is_sorted_complete_and_classifies_shared_writes() {
        let directory = TempDir::new().expect("inventory fixture");
        let process = directory.path().join("42");
        fs::create_dir_all(process.join("task/42")).expect("primary task");
        fs::create_dir_all(process.join("task/77")).expect("secondary task");
        fs::write(process.join("task/42/comm"), b"qemu-main\n").expect("primary comm");
        fs::write(process.join("task/77/comm"), b"worker\n").expect("secondary comm");
        fs::create_dir_all(process.join("fd")).expect("descriptor directory");
        symlink("socket:[11]", process.join("fd/9")).expect("socket link");
        symlink("/run/qmp.sock", process.join("fd/3")).expect("QMP link");
        fs::write(
            process.join("maps"),
            b"1000-2000 r--p 00000000 00:00 0 /qemu\n2000-3000 rw-s 00000000 00:01 7 /ring\n",
        )
        .expect("mapping fixture");
        let identity = QemuProcessIdentity {
            process_id: 42,
            start_time_ticks: 9,
            executable: PathBuf::from("/qemu"),
        };

        let inventory = capture_once(&process, &identity).expect("fixture inventory");
        assert_eq!(
            inventory
                .threads()
                .iter()
                .map(QemuHotForkThreadInventory::thread_id)
                .collect::<Vec<_>>(),
            vec![42, 77]
        );
        assert_eq!(
            inventory
                .descriptors()
                .iter()
                .map(QemuHotForkDescriptorInventory::descriptor)
                .collect::<Vec<_>>(),
            vec![3, 9]
        );
        assert_eq!(inventory.mappings().len(), 2);
        assert_eq!(inventory.writable_shared_mappings(), 1);
        assert_eq!(inventory.process(), &identity);
    }

    #[test]
    fn mapping_parser_rejects_alternate_or_oversized_records() {
        assert_eq!(
            validate_mapping_record(b"1000-2000 rw-s 0 00:01 7 /ring").expect("canonical mapping"),
            (true, true)
        );
        assert!(matches!(
            validate_mapping_record(b"1000-2000 rw-z 0 00:01 7 /ring"),
            Err(QemuHotForkInventoryError::Malformed {
                category: "mapping"
            })
        ));

        let input = vec![b'x'; MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES + 1];
        assert!(matches!(
            read_bounded_line(
                &mut BufReader::new(input.as_slice()),
                MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES,
                "mapping-record-bytes",
                Path::new("fixture-maps")
            ),
            Err(QemuHotForkInventoryError::LimitExceeded {
                category: "mapping-record-bytes",
                ..
            })
        ));
    }

    #[test]
    fn aggregate_byte_charge_is_checked_before_retention() {
        let mut retained = MAX_QEMU_HOT_FORK_INVENTORY_BYTES;
        assert!(matches!(
            charge_bytes(&mut retained, 1),
            Err(QemuHotForkInventoryError::LimitExceeded {
                category: "aggregate-bytes",
                ..
            })
        ));
        assert_eq!(retained, MAX_QEMU_HOT_FORK_INVENTORY_BYTES);
    }

    #[test]
    fn qemu_registry_is_exactly_reconciled_with_procfs_threads() {
        let process = QemuHotForkProcessInventory {
            process: QemuProcessIdentity {
                process_id: 10,
                start_time_ticks: 1,
                executable: PathBuf::from("/qemu"),
            },
            threads: vec![
                QemuHotForkThreadInventory {
                    thread_id: 10,
                    name: b"qmp-main-loop".to_vec(),
                },
                QemuHotForkThreadInventory {
                    thread_id: 20,
                    name: b"external".to_vec(),
                },
            ],
            descriptors: Vec::new(),
            mappings: Vec::new(),
            retained_bytes: 26,
        };
        let readiness =
            QmpHotForkReadiness::from_acknowledged_proofs(7).expect("scripted readiness bitmap");
        let audit = QemuHotForkAudit::new(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            process.clone(),
        )
        .expect("registered coordinator should match procfs");
        assert_eq!(audit.externally_created_thread_ids(), &[20]);

        assert!(matches!(
            QemuHotForkAudit::new(
                readiness,
                QmpHotForkThreadInventory::one_coordinator(10),
                QmpHotForkRcuInventory::from_reader_ids(&[20]),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::RcuReaderMissing { thread_id: 20 })
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                readiness,
                QmpHotForkThreadInventory::one_coordinator(30),
                QmpHotForkRcuInventory::from_reader_ids(&[30]),
                process,
            ),
            Err(QemuHotForkAuditError::RegisteredThreadMissing { thread_id: 30 })
        ));
    }

    #[test]
    fn process_generation_mismatch_fails_before_inventory() {
        let mut identity = crate::linux_process_identity(std::process::id())
            .expect("read current process identity")
            .expect("current process exists");
        identity.start_time_ticks = identity.start_time_ticks.wrapping_add(1);

        assert!(matches!(
            capture_linux_qemu_hot_fork_process_inventory(&identity),
            Err(QemuHotForkInventoryError::ProcessIdentityChanged)
        ));
    }
}
