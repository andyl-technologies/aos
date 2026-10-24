//! Conserves the authentic Main table and every live node's native tables.
//!
//! Main's original hard limit never changes. A selected World reserves its
//! actual native table ceilings and Main landing peaks together before effects.
//! Its live native-table sum determines Main's current soft limit. Existing
//! native children retain their own issued limits; another World cannot change
//! those already-born tables or their immutable Source/Target family relation.
// SPDX-License-Identifier: Apache-2.0

use super::{HostOperationGuard, HostServiceLease, ServiceBirthError};

pub(super) const CENSUS_BYTES: usize = 4096;

pub(super) struct HostDescriptorPartition {
    original: u64,
    host: u64,
    pool_ceiling: u64,
    shared_peak: u64,
    native_tables: u64,
    pool_window_peak: u64,
    ready: bool,
    // Both are existing paid parent owners. Cloning a window only retains
    // these same counters; the joint ledger prevents spending either twice.
    native: HostServiceLease,
    _external: Option<HostServiceLease>,
    target_window: Option<(u64, u64)>,
    next_window: u64,
    dispatcher_claimed: bool,
}

impl HostDescriptorPartition {
    pub(super) fn new(
        original: u64,
        pool_ceiling: u64,
        shared_peak: u64,
        native: HostServiceLease,
        external: Option<HostServiceLease>,
    ) -> Result<Self, ServiceBirthError> {
        if shared_peak == 0
            || shared_peak >= pool_ceiling
            || pool_ceiling > original
            || native.file_descriptors() < pool_ceiling
        {
            return Err(ServiceBirthError::policy(
                "Main/native descriptor geometry has no paid parent",
            ));
        }
        Ok(Self {
            original,
            host: original,
            pool_ceiling,
            shared_peak,
            native_tables: 0,
            pool_window_peak: 0,
            ready: false,
            native,
            _external: external,
            target_window: None,
            next_window: 0,
            dispatcher_claimed: false,
        })
    }

    pub(super) fn reserve_target_window(
        &mut self,
        peak: u64,
        original: &HostOperationGuard,
    ) -> Result<(u64, HostServiceLease), ServiceBirthError> {
        self.check()?;
        if self.dispatcher_claimed
            || self.target_window.is_some()
            || peak == 0
            || peak > self.shared_peak
        {
            return Err(ServiceBirthError::policy(
                "Target dispatcher landing is occupied or exceeds its prepaid Main bound",
            ));
        }
        let epoch = self
            .next_window
            .checked_add(1)
            .ok_or_else(|| ServiceBirthError::policy("Target descriptor epoch exhausted"))?;
        // Occupy before census/post: an uncertain shared-worker birth cannot
        // retry the same descriptor role as a second fresh dispatcher.
        self.next_window = epoch;
        self.target_window = Some((epoch, peak));
        self.dispatcher_claimed = true;
        self.corroborate_census(original)?;
        Ok((epoch, self.native.clone()))
    }

    /// Reserves actual node tables and Main landings in one physical split.
    pub(super) fn reserve_pool_windows(
        &mut self,
        peak: u64,
        tables: u64,
        original: &HostOperationGuard,
    ) -> Result<HostServiceLease, ServiceBirthError> {
        self.check()?;
        let windows = self
            .pool_window_peak
            .checked_add(peak)
            .filter(|_| peak != 0 && tables != 0)
            .ok_or_else(|| ServiceBirthError::policy("node descriptor assignment overflows"))?;
        let tables = self
            .native_tables
            .checked_add(tables)
            .ok_or_else(|| ServiceBirthError::policy("native descriptor tables overflow"))?;
        tables
            .checked_add(windows)
            .and_then(|sum| sum.checked_add(self.shared_peak))
            .filter(|sum| *sum <= self.pool_ceiling)
            .ok_or_else(|| {
                ServiceBirthError::policy("native tables and Main landings exceed their SAME pool")
            })?;
        let host = self
            .original
            .checked_sub(tables)
            .ok_or_else(|| ServiceBirthError::policy("native tables exceed original Main"))?;
        // Publish the attempted split before setrlimit/census. Refusal retains
        // it and seals admission; no rollback can silently restore broader work.
        self.ready = false;
        self.native_tables = tables;
        self.pool_window_peak = windows;
        self.host = host;
        self.write_soft_limit()?;
        self.corroborate_census(original)?;
        self.ready = true;
        self.check()?;
        Ok(self.native.clone())
    }

    pub(super) fn retain_pool_remainder(&self) -> Result<HostServiceLease, ServiceBirthError> {
        self.check()?;
        Ok(self.native.clone())
    }

    pub(super) fn close_pool_windows(&mut self, peak: u64) -> Result<(), ServiceBirthError> {
        self.check()?;
        self.pool_window_peak = self.pool_window_peak.checked_sub(peak).ok_or_else(|| {
            ServiceBirthError::policy("landing return exceeds its actual reservation")
        })?;
        Ok(())
    }

    /// Returns one assignment's windows and child tables as the same physical cut.
    pub(super) fn close_pool_assignment(
        &mut self,
        peak: u64,
        tables: u64,
    ) -> (Result<(), ServiceBirthError>, bool) {
        self.close_pool_assignment_after_write(peak, tables, || {})
    }

    // The observer changes no production check. It lets the isolated kernel
    // control perturb the real table after the real write and before readback.
    fn close_pool_assignment_after_write(
        &mut self,
        peak: u64,
        tables: u64,
        after_write: impl FnOnce(),
    ) -> (Result<(), ServiceBirthError>, bool) {
        let mut consumed = false;
        let result = (|| {
            self.check()?;
            let windows = self.pool_window_peak.checked_sub(peak).ok_or_else(|| {
                ServiceBirthError::policy("landing return exceeds its actual reservation")
            })?;
            let tables = self.native_tables.checked_sub(tables).ok_or_else(|| {
                ServiceBirthError::policy("native table return exceeds physical assignment")
            })?;
            let host = self
                .original
                .checked_sub(tables)
                .ok_or_else(|| ServiceBirthError::policy("native table return overflows"))?;
            self.ready = false;
            self.pool_window_peak = windows;
            self.native_tables = tables;
            self.host = host;
            self.apply_soft_limit()?;
            // Record the syscall's irreversible success before any readback.
            // Failure below cannot keep this exact assignment outstanding or
            // authorize spending the uncertain resulting partition again.
            consumed = true;
            after_write();
            self.check_limits()?;
            self.ready = true;
            if let Err(error) = self.check() {
                self.ready = false;
                return Err(error);
            }
            Ok(())
        })();
        (result, consumed)
    }

    pub(super) fn check_target_window(&self, epoch: u64) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !self
            .target_window
            .is_some_and(|(current, _)| current == epoch)
        {
            return Err(ServiceBirthError::policy(
                "Target dispatcher landing is stale",
            ));
        }
        Ok(())
    }

    pub(super) fn close_target_window(&mut self, epoch: u64) -> Result<(), ServiceBirthError> {
        self.check_target_window(epoch)?;
        self.target_window = None;
        Ok(())
    }

    pub(super) fn install(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), ServiceBirthError> {
        original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        self.check_limits()?;
        self.corroborate_census(original)?;
        self.ready = true;
        original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        self.check()
    }

    pub(super) fn check(&self) -> Result<(), ServiceBirthError> {
        if !self.ready {
            return Err(ServiceBirthError::policy(
                "Main descriptor split is incomplete",
            ));
        }
        self.check_limits()
    }

    fn corroborate_census(&self, original: &HostOperationGuard) -> Result<(), ServiceBirthError> {
        self.check_limits()?;
        let accounted_main = self
            .original
            .checked_sub(self.pool_ceiling)
            .and_then(|bytes| bytes.checked_add(self.shared_peak))
            .and_then(|bytes| bytes.checked_add(self.pool_window_peak))
            .filter(|main| *main <= self.host)
            .ok_or_else(|| {
                ServiceBirthError::policy("Main descriptor accounting exceeds its split")
            })?;
        let observed = census_count(self.host, self.original, original)?;
        // Live windows may already be materialized in this count. Compare to
        // their total assigned bound; never add old windows on top of observed.
        if observed > accounted_main {
            return Err(ServiceBirthError::policy(
                "actual Main descriptors exceed retained Main owners",
            ));
        }
        Ok(())
    }

    fn write_soft_limit(&self) -> Result<(), ServiceBirthError> {
        self.apply_soft_limit()?;
        self.check_limits()
    }

    fn apply_soft_limit(&self) -> Result<(), ServiceBirthError> {
        let limits = libc::rlimit {
            rlim_cur: self.host,
            rlim_max: self.original,
        };
        // SAFETY: setrlimit copies this initialized value. The original hard
        // limit is unchanged; only the jointly reserved live split is applied.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
            return Err(kernel_error("apply conserved Main/native descriptor split"));
        }
        Ok(())
    }

    fn check_limits(&self) -> Result<(), ServiceBirthError> {
        let actual = limits()?;
        if actual.rlim_cur != self.host || actual.rlim_max != self.original {
            return Err(ServiceBirthError::policy(
                "Main original descriptor partition changed",
            ));
        }
        Ok(())
    }
}

fn kernel_error(operation: &'static str) -> ServiceBirthError {
    ServiceBirthError::Kernel {
        operation,
        source: std::io::Error::last_os_error(),
    }
}

fn limits() -> Result<libc::rlimit, ServiceBirthError> {
    let mut value = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes this one value on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, value.as_mut_ptr()) } != 0 {
        return Err(kernel_error("refine or inspect Main descriptor partition"));
    }
    // SAFETY: the successful syscall initialized the complete value.
    Ok(unsafe { value.assume_init() })
}

fn census_count(
    host: u64,
    maximum: u64,
    original: &HostOperationGuard,
) -> Result<u64, ServiceBirthError> {
    // The containing Main holds the previously unused descriptor remainder;
    // this transient directory and fixed scratch are prepaid before birth.
    // SAFETY: the static path is NUL terminated and open copies no Rust data.
    let descriptor = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(kernel_error("refine or inspect Main descriptor partition"));
    }
    let observed = scan(descriptor, host, maximum, original);
    // SAFETY: this function owns the descriptor returned by open.
    let closed = unsafe { libc::close(descriptor) };
    match (observed, closed) {
        (Err(first), _) => Err(first),
        (Ok(count), 0) => Ok(count),
        (Ok(_), _) => Err(kernel_error("refine or inspect Main descriptor partition")),
    }
}

fn scan(
    descriptor: libc::c_int,
    host: u64,
    maximum: u64,
    original: &HostOperationGuard,
) -> Result<u64, ServiceBirthError> {
    let mut buffer = [0_u8; CENSUS_BYTES];
    let mut entries = 0_u64;
    loop {
        original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        // SAFETY: Linux getdents64 writes at most buffer.len() initialized bytes
        // into this fixed buffer using the live directory descriptor.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                descriptor,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            return Err(kernel_error("refine or inspect Main descriptor partition"));
        }
        if count == 0 {
            return Ok(entries.saturating_sub(2));
        }
        let count = usize::try_from(count).map_err(super::super::message)?;
        let mut offset = 0;
        while offset < count {
            let record = buffer
                .get(offset..count)
                .filter(|record| record.len() >= 20)
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor census is malformed"))?;
            let length = usize::from(u16::from_ne_bytes([record[16], record[17]]));
            let record = record
                .get(..length)
                .filter(|record| record.len() >= 20)
                .ok_or_else(|| {
                    ServiceBirthError::policy("Main descriptor census record is malformed")
                })?;
            let name = record[19..]
                .split(|byte| *byte == 0)
                .next()
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor census has no name"))?;
            entries = entries
                .checked_add(1)
                .filter(|entries| *entries <= maximum.saturating_add(2))
                .ok_or_else(|| {
                    ServiceBirthError::policy("Main descriptor census exceeds the original table")
                })?;
            if name != b"." && name != b".." {
                let index = name
                    .iter()
                    .try_fold(0_u64, |value, byte| {
                        byte.is_ascii_digit().then_some(())?;
                        value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
                    })
                    .filter(|_| !name.is_empty());
                if index.is_none_or(|index| index >= host) {
                    return Err(ServiceBirthError::policy(
                        "an existing Main descriptor lies outside its assigned host table",
                    ));
                }
            }
            offset += length;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    // Each helper runs in a fresh process: the production setrlimit operation
    // must not alter this test executable's other cases or its parent process.
    const HELPER: &str = "host_services::process_birth::executor_purpose::host_descriptors::tests::host_partition_kernel_helper";

    fn paid_descriptors(count: u64) -> HostServiceLease {
        // A local accounting mechanism, not an authenticated Main/Source issuer.
        crate::host_services::HostServiceAllocator::new(1, count, 1)
            .unwrap()
            .reserve_resources(0, count, 0)
            .unwrap()
    }

    #[test]
    fn host_partition_kernel_helper() {
        let Ok(case) = std::env::var("CRUCIBLE_FD_PARTITION_HELPER") else {
            return;
        };
        if case == "child-hard" {
            let inherited = limits().unwrap();
            assert_eq!((inherited.rlim_cur, inherited.rlim_max), (16, 64));
            let child = libc::rlimit {
                rlim_cur: 24,
                rlim_max: 24,
            };
            // SAFETY: the isolated child installs a value within retained hard
            // authority; this control issues no production descriptor loan.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &child) }, 0);
            assert_eq!(
                (limits().unwrap().rlim_cur, limits().unwrap().rlim_max),
                (24, 24)
            );
            return;
        }
        let initial = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        // SAFETY: this isolated helper lowers its own limits using one fully
        // initialized value; no production issuer is created by this fixture.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &initial) }, 0);
        let supervisor = crate::host_supervision::HostOperationSupervisor::new(
            crate::host_supervision::HostOperationBudgets::default(),
            Some(std::time::Duration::from_secs(30)),
        )
        .unwrap();
        let original = supervisor
            .begin(crate::host_supervision::HostOperationClass::Preparation)
            .unwrap();
        let mut partition =
            HostDescriptorPartition::new(64, 64, 8, paid_descriptors(64), None).unwrap();
        if case == "cancelled" {
            supervisor.cancel().unwrap();
            assert!(partition.install(&original).is_err());
            assert_eq!(limits().unwrap().rlim_cur, 64);
            assert!(!partition.ready);
            return;
        }
        partition.install(&original).unwrap();
        assert_eq!(limits().unwrap().rlim_cur, 64);

        let descriptor = std::fs::File::open("/dev/null").unwrap();
        let high = if case == "high-index" {
            // SAFETY: fcntl duplicates this retained file descriptor, which is
            // valid for the whole syscall; the returned descriptor is owned.
            let high = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 50) };
            assert!(high >= 50);
            Some(high)
        } else {
            None
        };
        let result = partition.reserve_pool_windows(8, 48, &original);
        assert_eq!(limits().unwrap().rlim_cur, 16);
        assert_eq!(limits().unwrap().rlim_max, 64);
        if let Some(high) = high {
            assert!(result.is_err());
            assert!(!partition.ready);
            assert!(partition.check().is_err());
            // SAFETY: this helper exclusively owns the successful duplicate.
            assert_eq!(unsafe { libc::close(high) }, 0);
            // Removing the offending descriptor cannot mint the failed owner.
            assert!(partition.check().is_err());
        } else {
            let _pool_controls = result.unwrap();
            partition.check().unwrap();
            if matches!(
                case.as_str(),
                "world-return-post" | "world-return-readback-post" | "world-return-refused"
            ) {
                let readback_failure = case == "world-return-readback-post";
                let refused = case == "world-return-refused";
                super::super::native_pool::check_real_kernel_world_return(
                    std::sync::Arc::new(original),
                    _pool_controls,
                    |cleanup| {
                        if refused {
                            let changed = libc::rlimit {
                                rlim_cur: 16,
                                rlim_max: 63,
                            };
                            assert_eq!(
                                // SAFETY: only this isolated child lowers its hard
                                // limit. The real pre-write check must refuse it.
                                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &changed) },
                                0
                            );
                            let result = partition.close_pool_assignment(8, 48);
                            cleanup.complete().unwrap();
                            return result;
                        }
                        partition.close_pool_assignment_after_write(8, 48, || {
                            assert_eq!(limits().unwrap().rlim_cur, 64);
                            // Complete the actual same guard after the real
                            // write, so its independent post must refuse.
                            cleanup.complete().unwrap();
                            if readback_failure {
                                let changed = libc::rlimit {
                                    rlim_cur: 63,
                                    rlim_max: 64,
                                };
                                assert_eq!(
                                    // SAFETY: only this isolated helper's actual
                                    // soft limit changes within its original hard.
                                    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &changed) },
                                    0
                                );
                            }
                        })
                    },
                    readback_failure || refused,
                    !refused,
                );
                if refused {
                    assert_eq!(
                        (partition.pool_window_peak, partition.native_tables),
                        (8, 48)
                    );
                    assert_eq!(
                        (limits().unwrap().rlim_cur, limits().unwrap().rlim_max),
                        (16, 63)
                    );
                    return;
                }
                assert_eq!(
                    (partition.pool_window_peak, partition.native_tables),
                    (0, 0)
                );
                assert_eq!(
                    limits().unwrap().rlim_cur,
                    if readback_failure { 63 } else { 64 }
                );
                let (repeated, consumed) = partition.close_pool_assignment(8, 48);
                assert!(repeated.is_err());
                assert!(!consumed);
                return;
            }
            if case == "return-readback" {
                let (returned, consumed) =
                    partition.close_pool_assignment_after_write(8, 48, || {
                        // This observes real success, then changes only this
                        // isolated process's soft limit. No syscall or check is
                        // replaced with a synthetic success/failure result.
                        let written = limits().unwrap();
                        assert_eq!((written.rlim_cur, written.rlim_max), (64, 64));
                        let changed = libc::rlimit {
                            rlim_cur: 63,
                            rlim_max: 64,
                        };
                        // SAFETY: the isolated helper owns this initialized limit;
                        // lowering soft within unchanged hard affects no peer.
                        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &changed) }, 0);
                    });
                assert!(matches!(returned, Err(ServiceBirthError::Policy(message))
                    if message == "Main original descriptor partition changed"));
                assert!(consumed);
                assert_eq!(
                    (partition.pool_window_peak, partition.native_tables),
                    (0, 0)
                );
                assert_eq!(limits().unwrap().rlim_cur, 63);
                assert!(!partition.ready);
                assert!(partition.check().is_err());
                let (repeated, consumed) = partition.close_pool_assignment(8, 48);
                assert!(repeated.is_err());
                assert!(!consumed);
                assert!(partition.reserve_pool_windows(8, 48, &original).is_err());
                assert_eq!(
                    (partition.pool_window_peak, partition.native_tables),
                    (0, 0)
                );
                // Rejected retry/admission did not apply the assignment again.
                let unchanged = limits().unwrap();
                assert_eq!((unchanged.rlim_cur, unchanged.rlim_max), (63, 64));
                return;
            }
            if case == "paired-return" {
                let (underflow, consumed) = partition.close_pool_assignment(9, 48);
                assert!(underflow.is_err());
                assert!(!consumed);
                let (underflow, consumed) = partition.close_pool_assignment(8, 49);
                assert!(underflow.is_err());
                assert!(!consumed);
                assert_eq!(
                    (partition.pool_window_peak, partition.native_tables),
                    (8, 48)
                );
                assert_eq!(limits().unwrap().rlim_cur, 16);
                partition.check().unwrap();

                let (returned, consumed) = partition.close_pool_assignment(8, 48);
                assert!(consumed);
                returned.unwrap();
                assert_eq!(
                    (partition.pool_window_peak, partition.native_tables),
                    (0, 0)
                );
                assert_eq!(limits().unwrap().rlim_cur, 64);
                let (repeated, consumed) = partition.close_pool_assignment(8, 48);
                assert!(repeated.is_err());
                assert!(!consumed);
                partition.check().unwrap();
                return;
            }
            if case == "dispatcher-terminal" {
                // Exercise the real refined table, without fabricating a Main
                // descriptor payer. Permanent occupancy must win first.
                partition.dispatcher_claimed = true;
                assert!(partition.target_window.is_none());
                let refusal = partition.reserve_target_window(1, &original).unwrap_err();
                assert!(refusal.to_string().contains("occupied"));
                assert!(partition.dispatcher_claimed);
                return;
            }
            // Retaining the original hard limit is required: an unprivileged
            // child may install its own already-issued limit above host soft.
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", HELPER, "--test-threads=1"])
                .env("CRUCIBLE_FD_PARTITION_HELPER", "child-hard")
                .status()
                .unwrap();
            assert!(child.success());
        }
    }

    #[test]
    fn kernel_partition_contains_existing_indices_and_retains_hard_authority() {
        for case in [
            "positive",
            "high-index",
            "cancelled",
            "dispatcher-terminal",
            "paired-return",
            "return-readback",
            "world-return-post",
            "world-return-readback-post",
            "world-return-refused",
        ] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", HELPER, "--test-threads=1"])
                .env("CRUCIBLE_FD_PARTITION_HELPER", case)
                .status()
                .unwrap();
            assert!(status.success(), "descriptor helper {case} failed");
        }
    }

    #[test]
    fn original_descriptor_partition_requires_one_paid_dynamic_pool() {
        assert!(HostDescriptorPartition::new(64, 64, 0, paid_descriptors(64), None).is_err());
        assert!(HostDescriptorPartition::new(64, 64, 64, paid_descriptors(64), None).is_err());
        assert!(HostDescriptorPartition::new(64, 65, 8, paid_descriptors(65), None).is_err());
        assert!(HostDescriptorPartition::new(64, 64, 8, paid_descriptors(63), None).is_err());

        let accepted = HostDescriptorPartition::new(64, 64, 8, paid_descriptors(64), None).unwrap();
        assert_eq!(accepted.host, accepted.original);
        assert_eq!(accepted.native_tables, 0);
        assert_eq!(accepted.pool_window_peak, 0);
        assert!(!accepted.ready);
    }
}
