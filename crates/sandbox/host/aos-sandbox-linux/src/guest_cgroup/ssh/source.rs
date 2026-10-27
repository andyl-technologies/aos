//! Proves this Agent's actual source cgroup before the existing SSH birth.
//!
//! The source is the original payload ancestor, not the sibling execution
//! root's default limit. Only the completed topology can enter this native
//! recipe; a caller cannot adopt a path, PID, resource scalar or notes proof.

use std::num::NonZeroU32;

use super::*;
use crate::cgroup::ExactCgroupMembershipReadbackV1;
use crate::kernel_clone::ConfiguredKernelCloneOriginalV1;
use aos_linux_descriptors::pidfd::PidFd;
use crate::pidfd::PidFdOpenAttemptV1;

#[derive(Clone, Copy)]
pub(crate) struct GuestSshBirthSourceDataV1 {
    pub(crate) copied_files: u32,
    pub(crate) highest_fd: u32,
    pub(crate) future_files: u64,
}

/// Keeps the same Agent's configured kernel proof and parent hard backstop.
///
/// This original grants no resources. The real accepted execution prepays its
/// compiled/native source, copied references, table permit and libc stack before
/// entry. A child-subtree limit or a successful notes hash cannot pay that debt.
pub struct GuestSshBirthSourceOriginalV1 {
    kernel: ConfiguredKernelCloneOriginalV1,
    pidfd: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    membership: [Option<Box<ExactCgroupMembershipReadbackV1>>; 2],
    memory: Option<Box<MemoryLimitReadbackV1>>,
    memory_initial_failed: bool,
    source: Option<GuestSshBirthSourceDataV1>,
    parent: u64,
    execution_root: u64,
    limit: Option<u64>,
    body: Option<Result<()>>,
    memory_after: Option<Result<()>>,
    membership_after: Option<Result<()>>,
    closed: Option<Error>,
    complete: bool,
}

impl Default for GuestSshBirthSourceOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestSshBirthSourceOriginalV1 {
    /// Creates only inert receiving destinations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kernel: ConfiguredKernelCloneOriginalV1::new(),
            pidfd: PidFdOpenAttemptV1::new(),
            process: None,
            membership: [None, None],
            memory: None,
            memory_initial_failed: false,
            source: None,
            parent: 0,
            execution_root: 0,
            limit: None,
            body: None,
            memory_after: None,
            membership_after: None,
            closed: None,
            complete: false,
        }
    }

    pub(in crate::guest_cgroup) fn capture_once_v1(
        &mut self,
        binding: Result<&RetainedCgroupAnchor>,
        payload: &super::super::GuestPayloadCgroupCustodyV1,
        execution_root: &RetainedCgroupAnchor,
        copied_files: u32,
        highest_fd: u32,
        future_files: u64,
    ) -> Result<()> {
        if self.body.is_some() || self.closed.is_some() {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        let leaf = match binding {
            Ok(leaf) => leaf,
            Err(cause) => {
                self.body = Some(Err(cause));
                return Err(closed());
            }
        };
        self.parent = payload.payload.kernel_id();
        self.execution_root = execution_root.kernel_id();
        if copied_files == 0 || highest_fd < 2
            || crate::kernel_clone::dominant_birth_bytes_data_v1(u64::from(highest_fd), 5).is_none()
        {
            self.body = Some(Err(closed()));
            return Err(closed());
        }
        self.source = Some(GuestSshBirthSourceDataV1 { copied_files, highest_fd, future_files });
        self.body = Some(self.capture_inner(&payload.payload, leaf));
        // Both actual readback afters remain owed after a primary refusal.
        // They use the same held payload and actual self pidfd, without a
        // healthy financial gate or a new process/membership constructor.
        if let Some(memory) = self.memory.as_mut() {
            self.memory_after = Some(memory.recheck_once(&payload.payload).map_err(|_| closed()));
        }
        if let Some(process) = self.process.as_ref() {
            self.membership[1] = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
            self.membership_after = Some(
                self.membership[1]
                    .as_mut()
                    .ok_or_else(closed)?
                    .capture_once(leaf, process)
                    .map_err(|_| closed()),
            );
        }
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(closed());
        }
        let memory = self.memory.as_ref().ok_or_else(closed)?;
        if memory.initial_bytes() != memory.final_bytes() {
            self.closed = Some(closed());
            return Err(closed());
        }
        self.complete = true;
        // The parent itself remains pinned by Effects. Only these completed
        // temporary native observations physically retire before the FD scan.
        drop(self.memory.take());
        self.membership = [None, None];
        drop(self.process.take());
        Ok(())
    }

    fn capture_inner(
        &mut self,
        payload: &RetainedCgroupAnchor,
        leaf: &RetainedCgroupAnchor,
    ) -> Result<()> {
        self.kernel.capture_once_v1()?;
        let pid = NonZeroU32::new(std::process::id()).ok_or_else(closed)?;
        self.pidfd.capture_once(pid).map_err(|_| closed())?;
        self.process = self.pidfd.take_validated();
        let process = self.process.as_ref().ok_or_else(closed)?;
        self.membership[0] = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
        self.membership[0]
            .as_mut()
            .ok_or_else(closed)?
            .capture_once(leaf, process)
            .map_err(|_| closed())?;
        self.memory = Some(Box::new(MemoryLimitReadbackV1::new()));
        let memory = self.memory.as_mut().ok_or_else(closed)?;
        let captured = memory.capture_once(payload);
        self.memory_initial_failed = memory.failure().is_some();
        captured.map_err(|_| closed())?;
        self.limit = Some(finite_limit(memory.initial_bytes().ok_or_else(closed)?)?);
        Ok(())
    }

    pub(super) fn require_scope_parent_v1(&self, root: &RetainedCgroupAnchor)
        -> Result<GuestSshBirthSourceDataV1> {
        if !self.complete
            || self.failure().is_some()
            || !self.kernel.completed_v1()
            || self.parent == 0
            || self.execution_root != root.kernel_id()
            || self.limit.is_none()
        {
            return Err(closed());
        }
        self.source.ok_or_else(closed)
    }

    /// Prices this same temporary native proof before the first notes open.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let kernel = ConfiguredKernelCloneOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(kernel.0)?
            .checked_add(MemoryLimitReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(
                ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?.checked_mul(2)?,
            )?
            .checked_add(2 * std::mem::size_of::<PidFd>())?
            .checked_add(4 * 256)?;
        // Notes retires before self membership and memory; a failed later
        // prefix retains actual self pin +both membership probes +limit probes.
        let files = kernel.1.max(
            1_usize
                .checked_add(2 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
                .checked_add(PidsLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1)?,
        );
        // The two actual active names belong to different held anchors:
        // payload/cgroup.events and AgentLeaf/cgroup.events. Repeated probes
        // share those names; memory.max and the notes name are separate.
        Some((bytes, files, kernel.2.checked_add(3)?))
    }

    /// Borrows the first actual kernel/native refusal without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.body.as_ref() {
            return self
                .kernel
                .failure()
                .or_else(|| self.pidfd.failure().map(|cause| cause as _))
                .or_else(|| {
                    self.membership[0]
                        .as_ref()?
                        .failure()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.memory_initial_failed
                        .then(|| self.memory.as_ref()?.failure())
                        .flatten()
                        .map(|cause| cause as _)
                })
                .or(Some(cause));
        }
        self.memory
            .as_ref()
            .and_then(|original| original.failure())
            .map(|cause| cause as _)
            .or_else(|| {
                self.memory_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.membership[1]
                    .as_ref()?
                    .failure()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.membership_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn finite_limit(bytes: &[u8]) -> Result<u64> {
    let digits = bytes.strip_suffix(b"\n").ok_or_else(closed)?;
    if digits.is_empty()
        || digits.len() > 20
        || digits[0] == b'0'
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return Err(closed());
    }
    digits.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or_else(closed)
    })
}

fn closed() -> Error {
    Error::invalid(
        "Guest SSH birth source",
        "same original parent backstop is incomplete",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_backstop_requires_an_actual_finite_positive_kernel_record() {
        assert_eq!(finite_limit(b"1048576\n").unwrap(), 1048576);
        for bytes in [
            b"max\n".as_slice(),
            b"0\n",
            b"01\n",
            b"1",
            b"-1\n",
            b"18446744073709551616\n",
        ] {
            assert!(finite_limit(bytes).is_err());
        }
    }
}
