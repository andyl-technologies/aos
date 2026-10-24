//! Keeps one exact cgroup freezer-control request's native refusal prefixes.
//!
//! This owner runs the existing active/open/type/write recipe. It grants no
//! cgroup role or financial capacity. The caller pays it before entry and
//! retains it beside the original operation through independently owed posts.

use super::*;

/// Retains the original active probe and freezer control through every refusal.
#[derive(Debug, Default)]
pub struct FreezerRequestOriginalV2 {
    pub(super) probe: PendingRegularFileV1,
    pub(super) active: Option<Result<()>>,
    pub(super) opened: Option<Result<OwnedFd>>,
    pub(super) filesystem: Option<Result<libc::c_long>>,
    pub(super) metadata: Option<Result<libc::stat>>,
    pub(super) write: Option<rustix::io::Result<usize>>,
    checked: bool,
    pub(super) write_attempts: usize,
    pub(super) write_gate: Option<Result<()>>,
    returned: Option<Result<()>>,
    entered: bool,
    refusal: Option<Error>,
}

impl FreezerRequestOriginalV2 {
    /// Creates inert native destinations without opening or writing a control.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs the ordinary request recipe once on the same retained anchor.
    ///
    /// Successful writes request a transition; they do not prove quiescence.
    /// The upper caller must independently observe the resulting freezer state.
    ///
    /// # Errors
    /// Retains the actual probe/control, validation and terminal write failure.
    /// Reentry refuses before IO without replacing the first native cause.
    pub fn request_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        state: CgroupFreezerState,
    ) -> Result<()> {
        self.capture(anchor, state, None)
    }

    /// Runs the same request with a caller-owned native authority bookend.
    ///
    /// The hook is mechanical: it grants no cgroup or clock authority. The
    /// enclosing role must bind it to its actual original clock and signed
    /// cutoff, and retain its native clock inputs and cause independently.
    /// The hook runs immediately before every native write, including retries.
    /// This selected lane permits at most two attempts for the two-byte record;
    /// interruption or partial progress may therefore exhaust it and fail closed.
    /// The ordinary and unchecked retained lanes keep their original retries.
    ///
    /// # Errors
    /// Retains every reached probe/control, failed hook, write and exhaustion.
    pub fn request_checked_once_v2(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        state: CgroupFreezerState,
        before_write: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.capture(anchor, state, Some(before_write))
    }

    fn capture(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        state: CgroupFreezerState,
        mut before_write: Option<&mut dyn FnMut() -> Result<()>>,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.checked = before_write.is_some();
        self.returned = Some((|| freezer_request_recipe!(anchor, state, Retained, self, before_write))());
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(super) fn require_write_once_v2(
        attempts: &mut usize,
        result: &mut Option<Result<()>>,
        gate: &mut Option<&mut dyn FnMut() -> Result<()>>,
    ) -> Result<()> {
        let Some(gate) = gate.as_mut() else { return Ok(()); };
        if *attempts == 2 {
            return Err(Error::ObservationLimitExceeded {
                object: "checked freezer-control native writes", limit: 2,
            });
        }
        *attempts += 1;
        *result = Some(gate());
        if matches!(result, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    /// Borrows the first actual native or complete-control-write failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.active)
            .or_else(|| error(&self.opened))
            .or_else(|| error(&self.filesystem))
            .or_else(|| error(&self.metadata))
            .or_else(|| self.write.as_ref()?.as_ref().err()
                .filter(|cause| !self.checked || **cause != rustix::io::Errno::INTR)
                .map(|cause| cause as _))
            .or_else(|| error(&self.write_gate))
            .or_else(|| error(&self.returned))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    /// Bounds both actual Files and their two fixed cgroup control names.
    ///
    /// Native result/control carriers incur bytes, not namespace entries.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((
            std::mem::size_of::<Self>().checked_mul(2)?.checked_add(2 * (13 + 14))?,
            2,
            2,
        ))
    }
}

pub(super) fn closed() -> Error {
    Error::invalid("retained freezer request", "original request remains closed")
}

fn error<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_retry_gates_before_native_write_and_keeps_control() {
        use std::os::fd::AsFd as _;
        let directory = tempfile::tempdir().unwrap();
        let control = std::fs::File::create(directory.path().join("control")).unwrap();
        let descriptor = control.as_fd().try_clone_to_owned().unwrap();
        let identity = rustix::fs::fstat(&descriptor).unwrap();
        let mut original = FreezerRequestOriginalV2::new();
        original.checked = true;
        original.opened = Some(Ok(descriptor));
        original.write = Some(Err(rustix::io::Errno::INTR));
        let mut observed = 0;
        let mut authority = || {
            observed += 1;
            Err(Error::invalid("actual original cutoff", "expired before retry"))
        };
        let mut gate: Option<&mut dyn FnMut() -> Result<()>> = Some(&mut authority);

        original.returned = Some((|| {
            freezer_request_step!(Retained, write, original, gate, {
                panic!("refused actual cutoff reached native write")
            });
            Ok(())
        })());

        assert_eq!(observed, 1);
        let cause = original.failure().unwrap().downcast_ref::<Error>().unwrap();
        assert!(std::ptr::eq(cause, original.write_gate.as_ref().unwrap().as_ref().unwrap_err()));
        let held = rustix::fs::fstat(original.opened.as_ref().unwrap().as_ref().unwrap()).unwrap();
        assert_eq!((held.st_dev, held.st_ino), (identity.st_dev, identity.st_ino));
        assert_eq!(original.write_attempts, 1);
        assert_eq!(control.metadata().unwrap().len(), 0);
    }

    #[test]
    fn root_freezer_refusal_keeps_same_native_cause_through_reentry() {
        let fd = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let root = CgroupV2Root::from_owned(fd).unwrap();
        let anchor = root.resolve(Path::new(".")).unwrap();
        let mut original = FreezerRequestOriginalV2::new();

        // The cgroup-v2 root has no cgroup.freeze control. Requesting Thawed
        // also avoids introducing a test that could suspend the test process.
        assert!(original.request_once(&anchor, CgroupFreezerState::Thawed).is_err());
        let native = original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const _;
        assert!(matches!(original.opened, Some(Err(_))));
        assert!(original.probe.file().is_ok());

        assert!(original.request_once(&anchor, CgroupFreezerState::Thawed).is_err());
        let retained = original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const _;
        assert_eq!(native, retained);
        assert!(original.probe.file().is_ok());
    }
}
