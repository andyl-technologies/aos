//! Low-overhead inherited-PMU snapshots for FinalForce leaf attribution.
//!
//! The Linux benchmark wrapper owns and enables the perf events. In the
//! explicitly default-off attribution mode it transfers duplicate descriptors
//! to the evaluator. This module maps their read-only metadata pages and uses
//! the kernel-advertised userspace RDPMC path, avoiding a syscall at every
//! nested force transition.

#![allow(unsafe_code)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use std::arch::asm;
    use std::fs::File;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::ptr::NonNull;
    use std::sync::atomic::{Ordering, compiler_fence};

    const CAP_USER_RDPMC: u64 = 1 << 2;
    const MAP_FAILED: *mut core::ffi::c_void = usize::MAX as *mut core::ffi::c_void;
    const MAP_SHARED: i32 = 0x01;
    const PROT_READ: i32 = 0x01;
    const PAGE_BYTES: usize = 4096;
    const MAX_SEQLOCK_ATTEMPTS: usize = 16;
    const SYS_PERF_EVENT_OPEN: isize = 298;
    const SYS_GETTID: isize = 186;
    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
    const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
    const PERF_EVENT_IOC_RESET: usize = 0x2403;
    const PERF_EVENT_IOC_ENABLE: usize = 0x2400;
    const PERF_IOC_FLAG_GROUP: usize = 1;
    const ATTR_DISABLED_EXCLUDE_KERNEL_HV: u64 = (1 << 0) | (1 << 5) | (1 << 6);
    const ATTR_EXCLUDE_KERNEL_HV: u64 = (1 << 5) | (1 << 6);

    /// Reason the worker-local PMU reader could not be connected.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum FinalForceCounterConnectError {
        CyclesOpen,
        InstructionsOpen,
        MetadataMap,
        RdpmcUnavailable,
        GroupReset,
        GroupEnable,
    }

    unsafe extern "C" {
        fn mmap(
            address: *mut core::ffi::c_void,
            length: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut core::ffi::c_void;
        fn munmap(address: *mut core::ffi::c_void, length: usize) -> i32;
        fn ioctl(fd: i32, request: usize, ...) -> i32;
        fn syscall(number: isize, ...) -> isize;
    }

    /// Stable prefix of `perf_event_attr` accepted by `perf_event_open`.
    #[repr(C)]
    struct PerfEventAttr {
        event_type: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        remainder: [u8; 80],
    }

    /// Prefix of Linux's `perf_event_mmap_page` through `pmc_width`.
    #[repr(C)]
    struct PerfEventMmapPage {
        version: u32,
        compat_version: u32,
        lock: u32,
        index: u32,
        offset: i64,
        time_enabled: u64,
        time_running: u64,
        capabilities: u64,
        pmc_width: u16,
        time_shift: u16,
        time_mult: u32,
        time_offset: u64,
    }

    struct PerfCounter {
        _descriptor: File,
        page: NonNull<PerfEventMmapPage>,
    }

    impl PerfCounter {
        fn map(descriptor: File) -> Result<Self, FinalForceCounterConnectError> {
            // SAFETY: A perf-event descriptor supports a read-only, shared
            // metadata-page mapping at offset zero. The returned mapping is
            // checked before constructing the typed non-null pointer.
            let mapping = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    PAGE_BYTES,
                    PROT_READ,
                    MAP_SHARED,
                    descriptor.as_raw_fd(),
                    0,
                )
            };
            if mapping == MAP_FAILED {
                return Err(FinalForceCounterConnectError::MetadataMap);
            }
            let Some(page) = NonNull::new(mapping.cast::<PerfEventMmapPage>()) else {
                // SAFETY: `mapping` is the exact non-failed mapping returned above.
                unsafe {
                    munmap(mapping, PAGE_BYTES);
                }
                return Err(FinalForceCounterConnectError::MetadataMap);
            };
            // SAFETY: `page` addresses the mapped perf metadata prefix.
            let capabilities = unsafe { std::ptr::read_volatile(&page.as_ref().capabilities) };
            if capabilities & CAP_USER_RDPMC == 0 {
                // SAFETY: `mapping` is the exact mapping returned above.
                unsafe {
                    munmap(mapping, PAGE_BYTES);
                }
                return Err(FinalForceCounterConnectError::RdpmcUnavailable);
            }
            Ok(Self {
                _descriptor: descriptor,
                page,
            })
        }

        fn read(&self) -> Option<u64> {
            for _ in 0..MAX_SEQLOCK_ATTEMPTS {
                // SAFETY: The mapping remains live for `self`; volatile reads
                // follow the perf metadata seqlock contract.
                let sequence = unsafe { std::ptr::read_volatile(&self.page.as_ref().lock) };
                if sequence & 1 != 0 {
                    continue;
                }
                compiler_fence(Ordering::Acquire);
                // SAFETY: These fields are within the mapped metadata prefix.
                let (index, offset, width) = unsafe {
                    (
                        std::ptr::read_volatile(&self.page.as_ref().index),
                        std::ptr::read_volatile(&self.page.as_ref().offset),
                        std::ptr::read_volatile(&self.page.as_ref().pmc_width),
                    )
                };
                if index == 0 || width == 0 || width > 64 {
                    return None;
                }
                let mut low: u32;
                let mut high: u32;
                // SAFETY: `cap_user_rdpmc` is set and `index - 1` is the
                // kernel-provided hardware-counter selector for this event.
                unsafe {
                    asm!(
                        "rdpmc",
                        in("ecx") index - 1,
                        out("eax") low,
                        out("edx") high,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                let raw = (u64::from(high) << 32) | u64::from(low);
                let shift = 64 - u32::from(width);
                let signed = ((raw << shift) as i64) >> shift;
                let count = offset.checked_add(signed)?;
                compiler_fence(Ordering::Acquire);
                // SAFETY: The mapping remains live for `self`.
                let after = unsafe { std::ptr::read_volatile(&self.page.as_ref().lock) };
                if sequence == after {
                    return u64::try_from(count).ok();
                }
            }
            None
        }
    }

    fn open_counter(config: u64, group: i32, disabled: bool) -> Option<File> {
        let attributes = PerfEventAttr {
            event_type: PERF_TYPE_HARDWARE,
            size: u32::try_from(std::mem::size_of::<PerfEventAttr>()).ok()?,
            config,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: if disabled {
                ATTR_DISABLED_EXCLUDE_KERNEL_HV
            } else {
                ATTR_EXCLUDE_KERNEL_HV
            },
            remainder: [0; 80],
        };
        // SAFETY: The attribute has the kernel UAPI layout and remains live for
        // the syscall. pid=0 binds the event to this exact evaluator worker TID.
        let descriptor = unsafe {
            syscall(
                SYS_PERF_EVENT_OPEN,
                &attributes,
                0isize,
                -1isize,
                group,
                0usize,
            )
        };
        let descriptor = i32::try_from(descriptor).ok().filter(|fd| *fd >= 0)?;
        // SAFETY: A successful perf_event_open return is a fresh owned fd.
        Some(unsafe { File::from_raw_fd(descriptor) })
    }

    fn current_tid() -> Option<i32> {
        // SAFETY: gettid has no pointer arguments or side effects beyond
        // returning the caller's kernel thread identifier.
        i32::try_from(unsafe { syscall(SYS_GETTID) })
            .ok()
            .filter(|tid| *tid > 0)
    }

    impl Drop for PerfCounter {
        fn drop(&mut self) {
            // SAFETY: `page` is the live mapping created by `connect`, and this
            // is its single unmap at object destruction.
            unsafe {
                munmap(self.page.as_ptr().cast(), PAGE_BYTES);
            }
        }
    }

    /// Pair of directly readable counters owned by one evaluator worker.
    pub(crate) struct FinalForceCounterReader {
        instructions: PerfCounter,
        cycles: PerfCounter,
        tid: i32,
    }

    impl std::fmt::Debug for FinalForceCounterReader {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("FinalForceCounterReader")
        }
    }

    impl FinalForceCounterReader {
        /// Opens, maps, resets, and enables a PMU group on the current worker.
        pub(crate) fn connect(
            _instructions_name: &str,
            _cycles_name: &str,
        ) -> Result<Self, FinalForceCounterConnectError> {
            let tid = current_tid().ok_or(FinalForceCounterConnectError::CyclesOpen)?;
            let cycles = open_counter(PERF_COUNT_HW_CPU_CYCLES, -1, true)
                .ok_or(FinalForceCounterConnectError::CyclesOpen)?;
            let instructions = open_counter(PERF_COUNT_HW_INSTRUCTIONS, cycles.as_raw_fd(), false)
                .ok_or(FinalForceCounterConnectError::InstructionsOpen)?;
            let instructions = PerfCounter::map(instructions)?;
            let cycles = PerfCounter::map(cycles)?;
            // SAFETY: `cycles` owns the live perf group leader fd; these ioctls
            // reset and enable that group exactly once before hot snapshots.
            if unsafe {
                ioctl(
                    cycles._descriptor.as_raw_fd(),
                    PERF_EVENT_IOC_RESET,
                    PERF_IOC_FLAG_GROUP,
                )
            } < 0
            {
                return Err(FinalForceCounterConnectError::GroupReset);
            }
            // SAFETY: Same live group leader and documented perf group flag.
            if unsafe {
                ioctl(
                    cycles._descriptor.as_raw_fd(),
                    PERF_EVENT_IOC_ENABLE,
                    PERF_IOC_FLAG_GROUP,
                )
            } < 0
            {
                return Err(FinalForceCounterConnectError::GroupEnable);
            }
            Ok(Self {
                instructions,
                cycles,
                tid,
            })
        }

        /// Reads retired instructions and cycles without a syscall.
        pub(crate) fn snapshot(&self) -> Option<(u64, u64)> {
            Some((self.instructions.read()?, self.cycles.read()?))
        }

        /// Checks that an outer boundary still runs on the owning worker TID.
        pub(crate) fn thread_matches(&self) -> bool {
            current_tid() == Some(self.tid)
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    /// Reason the worker-local PMU reader could not be connected.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum FinalForceCounterConnectError {
        CyclesOpen,
        InstructionsOpen,
        MetadataMap,
        RdpmcUnavailable,
        GroupReset,
        GroupEnable,
        UnsupportedPlatform,
    }

    /// Unavailable PMU reader on unsupported targets.
    #[derive(Debug)]
    pub(crate) struct FinalForceCounterReader;

    impl FinalForceCounterReader {
        pub(crate) fn connect(
            _instructions_name: &str,
            _cycles_name: &str,
        ) -> Result<Self, FinalForceCounterConnectError> {
            Err(FinalForceCounterConnectError::UnsupportedPlatform)
        }

        pub(crate) fn snapshot(&self) -> Option<(u64, u64)> {
            None
        }

        pub(crate) fn thread_matches(&self) -> bool {
            false
        }
    }
}

pub(super) use imp::{FinalForceCounterConnectError, FinalForceCounterReader};
