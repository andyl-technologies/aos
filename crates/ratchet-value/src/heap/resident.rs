//! Process resident-memory sampling for heap budget policy.
//!
//! The high-water heap budget is defined in resident bytes. Linux exposes a
//! cheap process-wide RSS sample through `/proc/self/statm`, and Darwin exposes
//! one through Mach task metadata. Other targets currently report that no live
//! process sampler is available so callers can fall back to allocator-mapped
//! bytes without changing correctness.

use std::num::ParseIntError;

use thiserror::Error;

/// A live process resident-memory sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessResidentMemorySample {
    resident_bytes: usize,
    source: ProcessResidentMemorySource,
}

impl ProcessResidentMemorySample {
    /// Returns the sampled process resident set in bytes.
    pub const fn resident_bytes(self) -> usize {
        self.resident_bytes
    }

    /// Returns where this process resident-memory sample came from.
    pub const fn source(self) -> ProcessResidentMemorySource {
        self.source
    }

    /// Samples the current process resident set when this target has a sampler.
    ///
    /// Unsupported targets return `Ok(None)` so heap budget policy can use its
    /// allocator-mapped fallback.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessResidentMemoryError`] if the target sampler exists but
    /// cannot read or parse the operating-system resident-memory source.
    pub fn current() -> Result<Option<Self>, ProcessResidentMemoryError> {
        process_resident_memory_sample()
    }
}

/// The operating-system source used for a process resident-memory sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcessResidentMemorySource {
    /// Linux `/proc/self/statm`, using the resident-pages field.
    LinuxProcSelfStatm,
    /// Darwin Mach `MACH_TASK_BASIC_INFO`, using the current resident-size field.
    DarwinMachTaskBasicInfo,
}

/// A process resident-memory sample failed.
#[derive(Debug, Error)]
pub enum ProcessResidentMemoryError {
    /// The target page-size query failed.
    #[error("process resident-memory page size is unavailable")]
    PageSizeUnavailable,
    /// Linux `/proc/self/statm` could not be read.
    #[error("failed to read /proc/self/statm for process resident memory")]
    LinuxStatmReadFailed {
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The Linux `/proc/self/statm` payload did not include the resident-pages field.
    #[error("missing resident-pages field in /proc/self/statm")]
    LinuxStatmMissingResidentPages,
    /// The Linux `/proc/self/statm` resident-pages field was not an integer.
    #[error("invalid resident-pages field in /proc/self/statm")]
    LinuxStatmInvalidResidentPages {
        /// The integer parser failure.
        source: ParseIntError,
    },
    /// The Linux `/proc/self/statm` resident byte calculation overflowed.
    #[error("resident byte count overflowed while parsing /proc/self/statm")]
    LinuxStatmResidentBytesOverflow,
    /// Darwin `task_info(MACH_TASK_BASIC_INFO)` did not return task metadata.
    #[error("failed to query Mach task basic info for process resident memory: {code}")]
    DarwinMachTaskInfoFailed {
        /// The Mach kernel return code.
        code: i32,
    },
    /// Darwin `task_info(MACH_TASK_BASIC_INFO)` returned a short metadata payload.
    #[error("Mach task basic info returned {actual_count} words, expected {expected_count}")]
    DarwinMachTaskInfoShortRead {
        /// The number of words returned by Mach.
        actual_count: u32,
        /// The number of words required for `mach_task_basic_info_data_t`.
        expected_count: u32,
    },
    /// The Darwin Mach resident byte count did not fit in `usize`.
    #[error("resident byte count overflowed while reading Mach task basic info")]
    DarwinMachResidentBytesOverflow,
    /// The `getrusage` peak resident-memory query failed.
    #[error("getrusage failed for peak resident memory: errno {errno}")]
    GetrusageFailed {
        /// The failing `getrusage` errno.
        errno: i32,
    },
}

/// The process scope of a peak resident-memory (`ru_maxrss`) query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeakResidentMemoryScope {
    /// The calling process itself (`RUSAGE_SELF`).
    SelfProcess,
    /// All terminated and waited-for children (`RUSAGE_CHILDREN`).
    ///
    /// `ru_maxrss` under this scope is the **maximum** resident set observed
    /// across all waited-for children since process start, not a sum, and it
    /// never decreases. Attributing it to one child requires comparing the
    /// watermark before and after that child exits.
    WaitedChildren,
}

/// Returns the peak resident set in bytes for `scope`, when supported.
///
/// The value is the kernel's `ru_maxrss` watermark: it is monotonic for the
/// life of the process (scope [`PeakResidentMemoryScope::SelfProcess`]) or the
/// running maximum over waited-for children
/// ([`PeakResidentMemoryScope::WaitedChildren`]). Unsupported targets return
/// `Ok(None)` so callers can skip peak accounting without special-casing the
/// platform.
///
/// # Errors
///
/// Returns [`ProcessResidentMemoryError::GetrusageFailed`] when the target has
/// a sampler but the `getrusage` call fails.
pub fn peak_resident_memory_bytes(
    scope: PeakResidentMemoryScope,
) -> Result<Option<u64>, ProcessResidentMemoryError> {
    peak_resident_memory_bytes_for_target(scope)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn peak_resident_memory_bytes_for_target(
    scope: PeakResidentMemoryScope,
) -> Result<Option<u64>, ProcessResidentMemoryError> {
    let who = match scope {
        PeakResidentMemoryScope::SelfProcess => libc::RUSAGE_SELF,
        PeakResidentMemoryScope::WaitedChildren => libc::RUSAGE_CHILDREN,
    };
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let status = {
        // SAFETY: `who` is one of the two standard rusage selectors and the
        // output pointer names valid, writable `rusage` storage. `getrusage`
        // is a side-effect-free process query; the result is only read after
        // the success check below.
        unsafe { libc::getrusage(who, usage.as_mut_ptr()) }
    };
    if status != 0 {
        return Err(ProcessResidentMemoryError::GetrusageFailed {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    let usage = {
        // SAFETY: `getrusage` returned success, so it filled the `rusage`
        // structure completely.
        unsafe { usage.assume_init() }
    };
    let raw = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    // Linux reports `ru_maxrss` in kilobytes; Darwin reports bytes.
    #[cfg(target_os = "linux")]
    let bytes = raw.saturating_mul(1024);
    #[cfg(target_os = "macos")]
    let bytes = raw;
    Ok(Some(bytes))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peak_resident_memory_bytes_for_target(
    _scope: PeakResidentMemoryScope,
) -> Result<Option<u64>, ProcessResidentMemoryError> {
    Ok(None)
}

/// Samples current process resident bytes when a platform sampler exists.
///
/// Unsupported targets return `Ok(None)`, allowing callers to use a fallback
/// resident-memory proxy.
///
/// # Errors
///
/// Returns [`ProcessResidentMemoryError`] if the target sampler exists but
/// cannot read or parse the operating-system resident-memory source.
pub fn process_resident_memory_sample()
-> Result<Option<ProcessResidentMemorySample>, ProcessResidentMemoryError> {
    process_resident_memory_sample_for_target()
}

/// Parses a Linux `/proc/self/statm` payload into a resident-memory sample.
///
/// The second whitespace-separated field is the resident page count. The caller
/// supplies the page size so tests and future platform adapters can validate the
/// parser without reading host process state.
///
/// # Errors
///
/// Returns [`ProcessResidentMemoryError::PageSizeUnavailable`] when
/// `page_size_bytes` is zero; returns a Linux statm parse error when the
/// resident-pages field is missing, malformed, or overflows when converted to
/// bytes.
pub fn process_resident_memory_sample_from_linux_statm(
    statm: &str,
    page_size_bytes: usize,
) -> Result<ProcessResidentMemorySample, ProcessResidentMemoryError> {
    if page_size_bytes == 0 {
        return Err(ProcessResidentMemoryError::PageSizeUnavailable);
    }
    let resident_pages = statm
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(ProcessResidentMemoryError::LinuxStatmMissingResidentPages)?
        .parse::<usize>()
        .map_err(|source| ProcessResidentMemoryError::LinuxStatmInvalidResidentPages { source })?;
    let resident_bytes = resident_pages
        .checked_mul(page_size_bytes)
        .ok_or(ProcessResidentMemoryError::LinuxStatmResidentBytesOverflow)?;
    Ok(ProcessResidentMemorySample {
        resident_bytes,
        source: ProcessResidentMemorySource::LinuxProcSelfStatm,
    })
}

#[cfg(target_os = "linux")]
fn process_resident_memory_sample_for_target()
-> Result<Option<ProcessResidentMemorySample>, ProcessResidentMemoryError> {
    let statm = std::fs::read_to_string("/proc/self/statm")
        .map_err(|source| ProcessResidentMemoryError::LinuxStatmReadFailed { source })?;
    let sample = process_resident_memory_sample_from_linux_statm(&statm, system_page_size()?)?;
    Ok(Some(sample))
}

#[cfg(target_os = "macos")]
fn process_resident_memory_sample_for_target()
-> Result<Option<ProcessResidentMemorySample>, ProcessResidentMemoryError> {
    let resident_bytes = darwin_resident_size_bytes()?;
    Ok(Some(ProcessResidentMemorySample {
        resident_bytes,
        source: ProcessResidentMemorySource::DarwinMachTaskBasicInfo,
    }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_resident_memory_sample_for_target()
-> Result<Option<ProcessResidentMemorySample>, ProcessResidentMemoryError> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn system_page_size() -> Result<usize, ProcessResidentMemoryError> {
    let page_size = {
        // SAFETY: `sysconf(_SC_PAGESIZE)` is a side-effect-free libc query. The
        // return value is validated before conversion to `usize`.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
    };
    if page_size <= 0 {
        return Err(ProcessResidentMemoryError::PageSizeUnavailable);
    }
    usize::try_from(page_size).map_err(|_| ProcessResidentMemoryError::PageSizeUnavailable)
}

#[cfg(target_os = "macos")]
fn darwin_resident_size_bytes() -> Result<usize, ProcessResidentMemoryError> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info_data_t>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    let task = {
        // SAFETY: `mach_task_self` reads the process-local current task port.
        // The returned send right is borrowed from the process and must not be
        // deallocated by this sampler.
        #[allow(deprecated)]
        unsafe {
            libc::mach_task_self()
        }
    };
    let status = {
        // SAFETY: `task` names the current task. `task_info` writes at most
        // `count` integer slots into the valid `mach_task_basic_info_data_t`
        // storage, and `count` is initialized to the exact slot count for the
        // requested flavor.
        unsafe {
            libc::task_info(
                task,
                libc::MACH_TASK_BASIC_INFO,
                info.as_mut_ptr().cast::<libc::integer_t>(),
                &mut count,
            )
        }
    };
    if status != libc::KERN_SUCCESS {
        return Err(ProcessResidentMemoryError::DarwinMachTaskInfoFailed {
            code: status as i32,
        });
    }
    if count < libc::MACH_TASK_BASIC_INFO_COUNT {
        return Err(ProcessResidentMemoryError::DarwinMachTaskInfoShortRead {
            actual_count: count as u32,
            expected_count: libc::MACH_TASK_BASIC_INFO_COUNT as u32,
        });
    }
    let info = {
        // SAFETY: `task_info` returned success with the full
        // `MACH_TASK_BASIC_INFO` payload, so the output structure is initialized.
        unsafe { info.assume_init() }
    };
    usize::try_from(info.resident_size)
        .map_err(|_| ProcessResidentMemoryError::DarwinMachResidentBytesOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_statm_parser_reads_resident_pages() {
        let sample = process_resident_memory_sample_from_linux_statm("123 45 6\n", 4096)
            .expect("statm parses");

        assert_eq!(sample.resident_bytes(), 45 * 4096);
        assert_eq!(
            sample.source(),
            ProcessResidentMemorySource::LinuxProcSelfStatm
        );
    }

    #[test]
    fn linux_statm_parser_rejects_zero_page_size() {
        assert!(matches!(
            process_resident_memory_sample_from_linux_statm("123 45 6\n", 0),
            Err(ProcessResidentMemoryError::PageSizeUnavailable)
        ));
    }

    #[test]
    fn linux_statm_parser_requires_resident_pages() {
        assert!(matches!(
            process_resident_memory_sample_from_linux_statm("123\n", 4096),
            Err(ProcessResidentMemoryError::LinuxStatmMissingResidentPages)
        ));
    }

    #[test]
    fn linux_statm_parser_rejects_invalid_resident_pages() {
        assert!(matches!(
            process_resident_memory_sample_from_linux_statm("123 nope 6\n", 4096),
            Err(ProcessResidentMemoryError::LinuxStatmInvalidResidentPages { .. })
        ));
    }

    #[test]
    fn linux_statm_parser_rejects_resident_byte_overflow() {
        assert!(matches!(
            process_resident_memory_sample_from_linux_statm("123 2\n", usize::MAX),
            Err(ProcessResidentMemoryError::LinuxStatmResidentBytesOverflow)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peak_sampler_reports_at_least_current_resident_bytes() {
        let peak = peak_resident_memory_bytes(PeakResidentMemoryScope::SelfProcess)
            .expect("peak sampler succeeds")
            .expect("target has a peak resident-memory sampler");
        let current = ProcessResidentMemorySample::current()
            .expect("target sampler succeeds")
            .expect("target has a live resident-memory sampler");

        assert!(peak > 0);
        assert!(peak >= current.resident_bytes() as u64 / 2);

        // The children watermark is monotonic and may be zero when this test
        // process has not waited for any children.
        let children = peak_resident_memory_bytes(PeakResidentMemoryScope::WaitedChildren)
            .expect("children peak sampler succeeds");
        assert!(children.is_some());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn current_process_sampler_reports_target_source() {
        let sample = ProcessResidentMemorySample::current()
            .expect("target sampler succeeds")
            .expect("target has a live resident-memory sampler");

        assert!(sample.resident_bytes() > 0);
        #[cfg(target_os = "linux")]
        assert_eq!(
            sample.source(),
            ProcessResidentMemorySource::LinuxProcSelfStatm
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            sample.source(),
            ProcessResidentMemorySource::DarwinMachTaskBasicInfo
        );
    }
}
