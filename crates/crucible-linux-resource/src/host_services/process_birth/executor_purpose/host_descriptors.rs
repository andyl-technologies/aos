//! Conserves the authenticated Main table and two issued native tables.
//!
//! The Main soft limit is lowered inside its unchanged hard authority before
//! native effects. A fixed-buffer census rejects every surviving descriptor
//! outside that soft limit. Actual children set their own finite soft and hard
//! limits; they never receive a fresh aggregate descriptor allowance.
// SPDX-License-Identifier: Apache-2.0

use super::{HostOperationGuard, HostServiceLease, ServiceBirthError};

pub(super) const CENSUS_BYTES: usize = 4096;

pub(super) struct HostDescriptorPartition {
    original: u64,
    host: u64,
    ready: bool,
    _remainder: Option<HostServiceLease>,
    target_window: Option<(u64, u64)>,
    source_window: Option<(u64, u64)>,
    next_window: u64,
    dispatcher_claimed: bool,
}

impl HostDescriptorPartition {
    pub(super) fn new(
        original: u64,
        local: u64,
        remainder: Option<HostServiceLease>,
    ) -> Result<Self, ServiceBirthError> {
        let host = local
            .checked_mul(2)
            .and_then(|children| original.checked_sub(children))
            .filter(|host| *host > 0 && local > 0 && local <= original)
            .ok_or_else(|| {
                ServiceBirthError::policy(
                    "host and two child descriptor tables do not fit the original",
                )
            })?;
        Ok(Self {
            original,
            host,
            ready: false,
            _remainder: remainder,
            target_window: None,
            source_window: None,
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
        if self.dispatcher_claimed || self.target_window.is_some() || peak == 0 || peak >= self.host
        {
            return Err(ServiceBirthError::policy(
                "Target host descriptor window is occupied or invalid",
            ));
        }
        let paid = self
            ._remainder
            .as_ref()
            .filter(|paid| paid.file_descriptors() >= peak)
            .ok_or_else(|| {
                ServiceBirthError::policy("Target host window has no authentic descriptor payer")
            })?;
        let observed = census_count(self.host, self.original, original)?;
        let held_source = self.source_window.map_or(0, |(_, peak)| peak);
        if observed
            .checked_add(held_source)
            .and_then(|count| count.checked_add(peak))
            .is_none_or(|needed| needed > self.host)
        {
            return Err(ServiceBirthError::policy(
                "Target host descriptor landing exceeds Main table",
            ));
        }
        let epoch = self.next_window.checked_add(1).ok_or_else(|| {
            ServiceBirthError::policy("Target descriptor window epoch is exhausted")
        })?;
        let loan = paid.clone();
        self.next_window = epoch;
        self.target_window = Some((epoch, peak));
        self.dispatcher_claimed = true;
        Ok((epoch, loan))
    }

    /// Reserves Source landing from the same paid Main table remainder.
    pub(super) fn reserve_source_window(
        &mut self,
        peak: u64,
        original: &HostOperationGuard,
    ) -> Result<(u64, HostServiceLease), ServiceBirthError> {
        self.check()?;
        if self.source_window.is_some() || peak == 0 || peak >= self.host {
            return Err(ServiceBirthError::policy(
                "Source host window is occupied or invalid",
            ));
        }
        let paid = self
            ._remainder
            .as_ref()
            .filter(|paid| paid.file_descriptors() >= peak)
            .ok_or_else(|| ServiceBirthError::policy("Source host window has no actual payer"))?;
        let observed = census_count(self.host, self.original, original)?;
        let held_target = self.target_window.map_or(0, |(_, peak)| peak);
        if observed
            .checked_add(held_target)
            .and_then(|count| count.checked_add(peak))
            .is_none_or(|needed| needed > self.host)
        {
            return Err(ServiceBirthError::policy(
                "Source and Target landing exceed Main table",
            ));
        }
        let epoch = self
            .next_window
            .checked_add(1)
            .ok_or_else(|| ServiceBirthError::policy("Source host window epoch is exhausted"))?;
        self.next_window = epoch;
        self.source_window = Some((epoch, peak));
        Ok((epoch, paid.clone()))
    }

    pub(super) fn check_source_window(&self, epoch: u64) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !self
            .source_window
            .is_some_and(|(current, _)| current == epoch)
        {
            return Err(ServiceBirthError::policy("Source host window is stale"));
        }
        Ok(())
    }

    pub(super) fn close_source_window(&mut self, epoch: u64) -> Result<(), ServiceBirthError> {
        self.check_source_window(epoch)?;
        self.source_window = None;
        Ok(())
    }

    pub(super) fn check_target_window(&self, epoch: u64) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !self
            .target_window
            .is_some_and(|(current, _)| current == epoch)
        {
            return Err(ServiceBirthError::policy(
                "Target descriptor window is stale",
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
        let actual = limits()?;
        if actual.rlim_cur != self.original || actual.rlim_max != self.original {
            return Err(ServiceBirthError::policy(
                "Main descriptor limits differ from its authenticated original",
            ));
        }
        let refined = libc::rlimit {
            rlim_cur: self.host,
            rlim_max: self.original,
        };
        // SAFETY: setrlimit reads one initialized fixed-size value. Only the
        // soft limit decreases; original child hard authority is retained.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &refined) } != 0 {
            return Err(kernel_error("refine or inspect Main descriptor partition"));
        }
        self.check_limits()?;
        census(self.host, self.original, original)?;
        self.ready = true;
        original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        self.check()
    }

    pub(super) fn check(&self) -> Result<(), ServiceBirthError> {
        if !self.ready {
            return Err(ServiceBirthError::policy(
                "Main descriptor refinement is incomplete",
            ));
        }
        self.check_limits()
    }

    fn check_limits(&self) -> Result<(), ServiceBirthError> {
        let actual = limits()?;
        if actual.rlim_cur != self.host || actual.rlim_max != self.original {
            return Err(ServiceBirthError::policy(
                "Main descriptor partition changed",
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

fn census(host: u64, maximum: u64, original: &HostOperationGuard) -> Result<(), ServiceBirthError> {
    census_count(host, maximum, original).map(|_| ())
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
        let mut partition = HostDescriptorPartition::new(64, 24, None).unwrap();
        if case == "cancelled" {
            supervisor.cancel().unwrap();
            assert!(partition.install(&original).is_err());
            assert_eq!(limits().unwrap().rlim_cur, 64);
            assert!(!partition.ready);
            return;
        }
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
        let result = partition.install(&original);
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
            result.unwrap();
            partition.check().unwrap();
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
        for case in ["positive", "high-index", "cancelled", "dispatcher-terminal"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", HELPER, "--test-threads=1"])
                .env("CRUCIBLE_FD_PARTITION_HELPER", case)
                .status()
                .unwrap();
            assert!(status.success(), "descriptor helper {case} failed");
        }
    }

    #[test]
    fn original_descriptor_partition_rejects_overflow_or_no_host_table() {
        assert!(HostDescriptorPartition::new(64, 32, None).is_err());
        assert!(HostDescriptorPartition::new(64, 0, None).is_err());
        assert!(HostDescriptorPartition::new(u64::MAX, u64::MAX, None).is_err());
        let accepted = HostDescriptorPartition::new(64, 16, None).unwrap();
        assert_eq!(accepted.host + 2 * 16, accepted.original);
        assert!(!accepted.ready);
    }
}
