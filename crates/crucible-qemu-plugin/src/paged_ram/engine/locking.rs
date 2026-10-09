//! Retains exact guest mapping locks and verifies their kernel VMA coverage.
//!
//! Lock preparation admits its metadata and opens verification before physical
//! exclusion. The fault actor can populate pages during prefaulting because no
//! owner mutex is held. A partial lock failure keeps its receipt until teardown;
//! dropping a Rust handle never silently unlocks guest RAM.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LockSpan {
    start: u64,
    end: u64,
}

/// Retains a deduplicated mapping inventory before the first locking syscall.
pub(super) struct LockedMemory {
    spans: Vec<LockSpan>,
    bytes: u64,
    locked_spans: AtomicU64,
    verified: AtomicBool,
    _reservation: MetadataReservation,
}

impl LockedMemory {
    pub(super) fn prepare(service: &FaultService) -> Result<Arc<Self>, RamError> {
        let budget = crate::ram_fingerprint::fork_metadata_budget()?;
        let bytes = (service.arenas.len() as u64)
            .checked_mul(size_of::<LockSpan>() as u64)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or("guest lock inventory overflow")?;
        let reservation = budget.reserve_bytes(bytes)?;
        let mut spans = Vec::new();
        spans.try_reserve_exact(service.arenas.len())?;
        for arena in &service.arenas {
            spans.push(rounded_span(
                arena.native.host_address,
                arena.native.logical_length,
            )?);
        }
        spans.sort_unstable_by_key(|span| span.start);
        let mut retained = 0;
        for index in 0..spans.len() {
            let next = spans[index];
            if retained > 0 && spans[retained - 1].end >= next.start {
                spans[retained - 1].end = spans[retained - 1].end.max(next.end);
            } else {
                spans[retained] = next;
                retained += 1;
            }
        }
        spans.truncate(retained);
        let bytes = spans.iter().try_fold(0_u64, |bytes, span| {
            bytes
                .checked_add(span.end - span.start)
                .ok_or("guest lock extent overflow")
        })?;
        if bytes == 0 {
            return Err(RamError::Invariant("guest lock inventory is empty"));
        }
        let admitted = maximum_locked_bytes()?;
        if bytes > admitted {
            return Err(RamError::LockedMemoryAdmission {
                required: bytes,
                admitted,
            });
        }
        Ok(Arc::new(Self {
            spans,
            bytes,
            locked_spans: AtomicU64::new(0),
            verified: AtomicBool::new(false),
            _reservation: reservation,
        }))
    }

    /// Prefaults, locks and verifies every span under existing accessor exclusion.
    pub(super) fn lock(
        &self,
        mappings: &mut File,
        operation: &dyn SourceOperation,
        mut progress: impl FnMut() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        let admitted = maximum_locked_bytes()?;
        if self.bytes > admitted {
            return Err(RamError::LockedMemoryAdmission {
                required: self.bytes,
                admitted,
            });
        }
        verify_spans(mappings, &self.spans, false, operation, &mut progress)?;
        for (index, span) in self.spans.iter().enumerate() {
            let mut address = span.start;
            while address < span.end {
                operation.wait_slice()?;
                // SAFETY: the retained physical certificate covers each whole
                // mapped host page intersecting an admitted guest RAM arena.
                // Reading identical bytes does not author a logical RAM write.
                unsafe { std::ptr::read_volatile(address as *const u8) };
                progress()?;
                address += PAGE_BYTES as u64;
            }
            operation.wait_slice()?;
            // SAFETY: spans are checked, mapped, page-rounded and retained by
            // native exclusion. No other owner locks these guest VMA ranges.
            if unsafe {
                libc::mlock(
                    span.start as *const c_void,
                    usize::try_from(span.end - span.start)
                        .map_err(|_| "guest lock extent exceeds address space")?,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            self.locked_spans.store(index as u64 + 1, Ordering::Release);
            progress()?;
        }
        operation.wait_slice()?;
        verify_spans(mappings, &self.spans, true, operation, &mut progress)?;
        self.verified.store(true, Ordering::Release);
        Ok(())
    }

    /// Releases only spans whose successful lock syscall is retained here.
    pub(super) fn unlock(
        &self,
        mappings: &mut File,
        operation: &dyn SourceOperation,
        mut progress: impl FnMut() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        self.verified.store(false, Ordering::Release);
        let count = usize::try_from(self.locked_spans.load(Ordering::Acquire))
            .map_err(|_| "guest lock receipt exceeds address space")?;
        for span in self.spans[..count].iter().rev() {
            operation.wait_slice()?;
            // SAFETY: this receipt retains the same deduplicated stable guest
            // mappings; unlocking never changes their addresses or bytes.
            if unsafe {
                libc::munlock(
                    span.start as *const c_void,
                    usize::try_from(span.end - span.start)
                        .map_err(|_| "guest unlock extent exceeds address space")?,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            progress()?;
        }
        verify_spans(mappings, &self.spans, false, operation, &mut progress)?;
        self.locked_spans.store(0, Ordering::Release);
        Ok(())
    }

    pub(super) fn verified_bytes(&self) -> Option<u64> {
        self.verified.load(Ordering::Acquire).then_some(self.bytes)
    }

    pub(super) fn verify(
        &self,
        mappings: &mut File,
        operation: &dyn SourceOperation,
        mut progress: impl FnMut() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        verify_spans(mappings, &self.spans, true, operation, &mut progress)
    }
}

pub(super) fn maximum_locked_bytes() -> Result<u64, RamError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one initialized host-private scalar structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if limit.rlim_cur != limit.rlim_max || limit.rlim_max == libc::RLIM_INFINITY {
        return Err(RamError::Invariant(
            "guest memlock requires an exact finite process entitlement",
        ));
    }
    Ok(limit.rlim_cur)
}

fn rounded_span(address: u64, length: u64) -> Result<LockSpan, RamError> {
    let end = address
        .checked_add(length)
        .and_then(|end| end.checked_add(PAGE_BYTES as u64 - 1))
        .map(|end| end & !(PAGE_BYTES as u64 - 1))
        .ok_or("guest lock span overflow")?;
    let start = address & !(PAGE_BYTES as u64 - 1);
    if address == 0 || length == 0 || end <= start || usize::try_from(end).is_err() {
        return Err(RamError::Invariant("guest lock span is invalid"));
    }
    Ok(LockSpan { start, end })
}

/// Reads kernel-owned VMA evidence without allocating unbounded path strings.
fn verify_spans(
    mappings: &mut File,
    spans: &[LockSpan],
    locked: bool,
    operation: &dyn SourceOperation,
    progress: &mut impl FnMut() -> Result<(), RamError>,
) -> Result<(), RamError> {
    operation.wait_slice()?;
    mappings.seek(SeekFrom::Start(0))?;
    verify_reader(mappings, spans, locked, operation, progress)
}

fn verify_reader(
    input: &mut impl Read,
    spans: &[LockSpan],
    locked: bool,
    operation: &dyn SourceOperation,
    progress: &mut impl FnMut() -> Result<(), RamError>,
) -> Result<(), RamError> {
    let mut buffer = [0_u8; 8192];
    let mut begin = 0;
    let mut end = 0;
    let mut line = [0_u8; 8192];
    let mut length = 0;
    let mut mapping = None;
    let mut flags = None;
    let mut index = 0;
    let mut covered = spans.first().map_or(0, |span| span.start);
    loop {
        if begin == end {
            operation.wait_slice()?;
            end = input.read(&mut buffer)?;
            operation.wait_slice()?;
            begin = 0;
            if end == 0 {
                if length != 0 {
                    return Err(RamError::Invariant("truncated kernel VMA evidence"));
                }
                let previous = (index, covered);
                verify_mapping(mapping, flags, spans, locked, &mut index, &mut covered)?;
                if previous != (index, covered) {
                    progress()?;
                }
                break;
            }
        }
        let byte = buffer[begin];
        begin += 1;
        if byte != b'\n' {
            let destination = line
                .get_mut(length)
                .ok_or("kernel VMA evidence line exceeds bound")?;
            *destination = byte;
            length += 1;
            continue;
        }
        let value = &line[..length];
        if let Some(next) = mapping_header(value) {
            operation.wait_slice()?;
            let previous = (index, covered);
            verify_mapping(mapping, flags, spans, locked, &mut index, &mut covered)?;
            if previous != (index, covered) {
                progress()?;
            }
            mapping = Some(next);
            flags = None;
        } else if let Some(value) = value.strip_prefix(b"VmFlags:") {
            if flags.is_some() {
                return Err(RamError::Invariant("duplicate kernel VMA flags"));
            }
            flags = Some(
                value
                    .split(|byte| byte.is_ascii_whitespace())
                    .any(|word| word == b"lo"),
            );
        }
        length = 0;
    }
    if index != spans.len() {
        return Err(RamError::Invariant(
            "guest mapping lock coverage is incomplete",
        ));
    }
    Ok(())
}

fn verify_mapping(
    mapping: Option<LockSpan>,
    flags: Option<bool>,
    spans: &[LockSpan],
    locked: bool,
    index: &mut usize,
    covered: &mut u64,
) -> Result<(), RamError> {
    let Some(mapping) = mapping else {
        return Ok(());
    };
    while let Some(span) = spans.get(*index) {
        if mapping.end <= *covered || mapping.start >= span.end {
            return Ok(());
        }
        if mapping.start > *covered || flags != Some(locked) {
            return Err(RamError::Invariant("guest mapping lock coverage changed"));
        }
        *covered = mapping.end.min(span.end);
        if *covered != span.end {
            return Ok(());
        }
        *index += 1;
        if let Some(next) = spans.get(*index) {
            *covered = next.start;
        }
    }
    Ok(())
}

fn mapping_header(line: &[u8]) -> Option<LockSpan> {
    let dash = line.iter().position(|byte| *byte == b'-')?;
    let space = line[dash + 1..].iter().position(|byte| *byte == b' ')? + dash + 1;
    let start = hexadecimal(&line[..dash])?;
    let end = hexadecimal(&line[dash + 1..space])?;
    (start < end).then_some(LockSpan { start, end })
}

fn hexadecimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 16 {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOperation {
        polls: AtomicU64,
        limit: u64,
    }

    impl SourceOperation for TestOperation {
        fn wait_slice_for_observation(
            &self,
        ) -> Result<std::time::Duration, crate::paged_ram::source::ObservationOperationError>
        {
            Err(
                crate::paged_ram::source::ObservationOperationError::Static {
                    kind: std::io::ErrorKind::Unsupported,
                    message: "fixture has no observation authority",
                },
            )
        }

        fn complete_observation(
            &self,
        ) -> Result<(), crate::paged_ram::source::ObservationOperationError> {
            Err(
                crate::paged_ram::source::ObservationOperationError::Static {
                    kind: std::io::ErrorKind::Unsupported,
                    message: "fixture has no observation authority",
                },
            )
        }

        fn wait_slice(&self) -> io::Result<std::time::Duration> {
            if self.polls.fetch_add(1, Ordering::Relaxed) >= self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original test operation expired",
                ));
            }
            Ok(std::time::Duration::from_millis(10))
        }

        fn complete(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn verify_fixture(
        input: &mut impl Read,
        spans: &[LockSpan],
        locked: bool,
    ) -> Result<(), RamError> {
        verify_reader(
            input,
            spans,
            locked,
            &TestOperation {
                polls: AtomicU64::new(0),
                limit: u64::MAX,
            },
            &mut || Ok(()),
        )
    }

    #[test]
    fn partial_guest_regions_round_only_their_intersecting_host_pages() {
        assert_eq!(
            rounded_span(0x2003, 4096).unwrap(),
            LockSpan {
                start: 0x2000,
                end: 0x4000
            }
        );
        assert!(rounded_span(u64::MAX - 3, 8).is_err());
        assert!(rounded_span(0, 4096).is_err());
    }

    #[test]
    fn exact_vma_flags_are_required_across_every_split_mapping() {
        let span = [LockSpan {
            start: 0x2000,
            end: 0x6000,
        }];
        let valid = b"2000-4000 rw-p 0 0:0 0\nVmFlags: rd wr lo\n4000-6000 rw-p 0 0:0 0\nVmFlags: rd wr lo\n";
        verify_fixture(&mut &valid[..], &span, true).unwrap();
        for mut invalid in [
            &b"2000-4000 rw-p 0 0:0 0\nVmFlags: rd wr lo\n4000-6000 rw-p 0 0:0 0\nVmFlags: rd wr\n"
                [..],
            &b"2000-3000 rw-p 0 0:0 0\nVmFlags: lo\n4000-6000 rw-p 0 0:0 0\nVmFlags: lo\n"[..],
            &b"2000-6000 rw-p 0 0:0 0\nLocked: 16 kB\n"[..],
        ] {
            assert!(verify_fixture(&mut invalid, &span, true).is_err());
        }
    }

    #[test]
    fn unlock_verification_rejects_surviving_lock_flags() {
        let span = [LockSpan {
            start: 0x2000,
            end: 0x4000,
        }];
        let unlocked = b"1000-5000 rw-p 0 0:0 0\nVmFlags: rd wr\n";
        verify_fixture(&mut &unlocked[..], &span, false).unwrap();
        let locked = b"1000-5000 rw-p 0 0:0 0\nVmFlags: rd wr lo\n";
        assert!(verify_fixture(&mut &locked[..], &span, false).is_err());
    }

    #[test]
    fn verification_preserves_original_expiry_without_reporting_poll_progress() {
        let mut input = &b"1000-5000 rw-p 0 0:0 0\nVmFlags: lo\n"[..];
        let operation = TestOperation {
            polls: AtomicU64::new(0),
            limit: 1,
        };
        let mut completed = 0;
        assert!(
            verify_reader(
                &mut input,
                &[LockSpan {
                    start: 0x2000,
                    end: 0x4000
                }],
                true,
                &operation,
                &mut || {
                    completed += 1;
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(completed, 0);
    }

    #[test]
    fn actual_guest_span_lock_and_unlock_have_verified_kernel_evidence() {
        // SAFETY: mmap returns a separately owned unit-test host page; it is
        // neither guest RAM nor registered in another paging authority.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let span = rounded_span(mapping as u64, PAGE_BYTES as u64).unwrap();
        let budget = crucible_ram::MetadataBudget::new(4096);
        let ownership = LockedMemory {
            spans: vec![span],
            bytes: PAGE_BYTES as u64,
            locked_spans: AtomicU64::new(0),
            verified: AtomicBool::new(false),
            _reservation: budget.reserve_bytes(256).unwrap(),
        };
        let mut mappings = File::open("/proc/self/smaps").unwrap();
        let operation = TestOperation {
            polls: AtomicU64::new(0),
            limit: u64::MAX,
        };
        let result = ownership.lock(&mut mappings, &operation, || Ok(()));
        match maximum_locked_bytes() {
            Ok(entitlement) if entitlement >= PAGE_BYTES as u64 => {
                result.unwrap();
                assert_eq!(ownership.verified_bytes(), Some(PAGE_BYTES as u64));
                ownership
                    .unlock(&mut mappings, &operation, || Ok(()))
                    .unwrap();
                assert!(ownership.verified_bytes().is_none());
            }
            _ => {
                assert!(matches!(result, Err(RamError::Invariant(_))));
                assert!(ownership.verified_bytes().is_none());
                assert_eq!(ownership.locked_spans.load(Ordering::Acquire), 0);
            }
        }
        // SAFETY: the test no longer holds any lock or borrowed pointer into its
        // exclusively owned original mapping.
        assert_eq!(unsafe { libc::munmap(mapping, PAGE_BYTES) }, 0);
    }
}
