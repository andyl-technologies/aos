//! Process resident-memory sampling for heap budget policy.
//!
//! The high-water heap budget is defined in resident bytes. Linux exposes a
//! cheap process-wide RSS sample through `/proc/self/statm`; other targets
//! currently report that no live process sampler is available so callers can
//! fall back to allocator-mapped bytes without changing correctness.

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

#[cfg(not(target_os = "linux"))]
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
}
