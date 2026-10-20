//! Same-anchor kernel backstops for an independently paid service receiver.
//!
//! These observations are DATA. Only the original role-specific PID1 recipient
//! supplies payment and decides which immutable hard limits must match. The
//! reader never opens a caller path or grants a reservation. It retains actual
//! native observations across both frontiers; allocator metadata remains under
//! the independently installed service limits rather than an exact heap model.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    CgroupLimitControlV1 as Control, CgroupLimitReadbackV1, FirstGlobalCpuReadbackV1,
    CgroupLimitCurrentnessSampleV1, CpuLimitCurrentnessSampleV1,
    RetainedCgroupAnchor,
};

/// Retains one service-limit capture and its final independent bookend.
///
/// The genuine receiver pays the inline slots and at most 24 retained control
/// descriptors before capture. No successful observation supplies that payment.
#[derive(Default)]
pub struct ReceivingContainmentReadbackV1 {
    controls: CgroupLimitReadbackV1,
    cpu: FirstGlobalCpuReadbackV1,
    captured_controls: Option<Result<(), aos_sandbox_linux::Error>>,
    captured_cpu: Option<Result<(), aos_sandbox_linux::Error>>,
    initial_nofile: Option<rustix::process::Rlimit>,
    initial_binding: Option<Result<(), ContainmentBindingErrorV1>>,
    checked_controls: Option<Result<(), aos_sandbox_linux::Error>>,
    checked_cpu: Option<Result<(), aos_sandbox_linux::Error>>,
    final_nofile: Option<rustix::process::Rlimit>,
    final_binding: Option<Result<(), ContainmentBindingErrorV1>>,
    expected: Option<ResourceVector>,
    settled_control_names: Option<Result<(), aos_sandbox_linux::Error>>,
    settled_cpu_names: Option<Result<(), aos_sandbox_linux::Error>>,
    reentry: Option<ContainmentBindingErrorV1>,
}

/// Retains one bounded recurring sample over an independently held reader.
#[derive(Default)]
pub struct ReceivingContainmentCurrentnessV1 {
    controls: CgroupLimitCurrentnessSampleV1,
    cpu: CpuLimitCurrentnessSampleV1,
    controls_result: Option<Result<(), aos_sandbox_linux::Error>>,
    cpu_result: Option<Result<(), aos_sandbox_linux::Error>>,
    nofile: Option<rustix::process::Rlimit>,
    binding: Option<Result<(), ContainmentBindingErrorV1>>,
    reentry: Option<ContainmentBindingErrorV1>,
}

impl ReceivingContainmentCurrentnessV1 {
    /// Measures actual inline readers and bounded fresh control observations.
    pub fn fixed_demand() -> ResourceVector {
        ResourceVector::ZERO
            .with(D::MemoryBytes, std::mem::size_of::<Self>() as u64 + 8 * 2 * 256)
            .with(D::OpenFiles, 8)
            .with(D::MetadataEntries, 8)
    }

    /// Borrows the earliest retained native or binding cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.controls.failure().map(|error| error as &dyn std::error::Error)
            .or_else(|| native_failure(&self.controls_result)
                .map(|error| error as &dyn std::error::Error))
            .or_else(|| self.cpu.failure().map(|error| error as &dyn std::error::Error))
            .or_else(|| native_failure(&self.cpu_result)
                .map(|error| error as &dyn std::error::Error))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error))
            .or_else(|| self.reentry.as_ref().map(|error| error as &dyn std::error::Error))
    }

    /// Checks the recorded native/control conjunction without resampling.
    ///
    /// # Errors
    /// Borrows the original cause or refuses an incomplete observation.
    pub fn require_current(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(error) = self.failure() { return Err(error); }
        if !matches!(self.binding, Some(Ok(()))) {
            return Err(&ContainmentBindingErrorV1::Incomplete);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum ContainmentBindingErrorV1 {
    #[error("receiving service limit observation is absent or incomplete")]
    Incomplete,
    #[error("receiving service memory.max differs from its immutable limit")]
    Memory,
    #[error("receiving service pids.max differs from its immutable limit")]
    Pids,
    #[error("receiving service finite CPU quota or period differs")]
    Cpu,
    #[error("receiving process soft or hard descriptor limit differs")]
    Nofile,
    #[error("receiving service limit observation was entered twice")]
    Reentry,
}

impl ReceivingContainmentReadbackV1 {
    /// Prices the fixed reader slots, bounded native path/error scratch and FDs.
    ///
    /// Each of eight controls keeps at most three same-name acquisitions. The
    /// original cgroup anchor and process owner remain separately charged.
    /// The 256-byte allowance exceeds every fixed control path and covers two
    /// simultaneous owned path/error representations per acquisition; allocator
    /// metadata and kernel objects remain under the same service backstop.
    pub fn fixed_demand() -> ResourceVector {
        const CONTROL_FILES: u64 = 8 * 3;
        let memory = std::mem::size_of::<Self>() as u64 + CONTROL_FILES * 2 * 256;
        ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, CONTROL_FILES)
            .with(D::MetadataEntries, CONTROL_FILES)
    }

    /// Samples current bytes/names over these same original readable OFDs.
    ///
    /// The caller prepays and retains this fresh bounded sample. No original
    /// control owner is recaptured, cleared, reset or replaced.
    pub fn observe_current_into(
        &self, anchor: &RetainedCgroupAnchor, sample: &mut ReceivingContainmentCurrentnessV1,
    ) {
        if sample.controls_result.is_some() || sample.reentry.is_some() {
            sample.reentry = Some(ContainmentBindingErrorV1::Reentry);
            return;
        }
        sample.controls_result = Some(self.controls.observe_current(anchor, &mut sample.controls));
        sample.cpu_result = Some(self.cpu.observe_current(anchor, &mut sample.cpu));
        sample.nofile = Some(rustix::process::getrlimit(rustix::process::Resource::Nofile));
        sample.binding = Some(self.require_current().map_err(|_| ContainmentBindingErrorV1::Incomplete)
            .and_then(|()| self.require_binding(sample.nofile)));
    }

    /// Captures every independent backstop under the actual retained anchor.
    ///
    /// `expected` is comparison DATA derived by the fixed role consumer from
    /// its immutable unit/image. It cannot manufacture a receiving original.
    pub fn capture(&mut self, anchor: &RetainedCgroupAnchor, expected: ResourceVector) {
        if self.expected.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert(ContainmentBindingErrorV1::Reentry);
            return;
        }
        self.expected = Some(expected);
        self.captured_controls = Some(self.controls.capture(anchor));
        self.captured_cpu = Some(self.cpu.capture(anchor));
        self.initial_nofile = Some(rustix::process::getrlimit(rustix::process::Resource::Nofile));
        self.initial_binding = Some(self.require_binding(self.initial_nofile));
    }

    /// Retains same-OFD, fresh-name and process-limit observations once.
    ///
    /// Both independent native readers run even if an earlier binding failed.
    /// Reentry never repeats a native effect or replaces the first real cause.
    pub fn recheck(&mut self, anchor: &RetainedCgroupAnchor) {
        if self.checked_controls.is_some() || self.expected.is_none() || self.reentry.is_some() {
            self.reentry.get_or_insert(ContainmentBindingErrorV1::Reentry);
            return;
        }
        self.checked_controls = Some(self.controls.recheck(anchor));
        self.checked_cpu = Some(self.cpu.recheck(anchor));
        self.final_nofile = Some(rustix::process::getrlimit(rustix::process::Resource::Nofile));
        self.final_binding = Some(self.require_binding(self.final_nofile).and_then(|()| {
            if self.initial_nofile == self.final_nofile {
                Ok(())
            } else {
                Err(ContainmentBindingErrorV1::Nofile)
            }
        }));
    }

    /// Settles only positive named verification handles after all joins.
    ///
    /// The existing 16-name peak may then serve sequential recurring checks.
    /// This does not release its permanent logical payment or any original OFD.
    /// Both returned native Results remain beside the original observations.
    pub fn settle_positive_named_verifications_once_v1(&mut self) {
        if self.settled_control_names.is_some() || self.settled_cpu_names.is_some()
            || self.require_current().is_err()
        {
            return;
        }
        self.settled_control_names = Some(self.controls.settle_positive_named_verifications_v1());
        self.settled_cpu_names = Some(self.cpu.settle_positive_named_verifications_v1());
    }

    /// Reports actual positive native-name disposal DATA without refunding use.
    pub fn named_verifications_settled_v1(&self) -> bool {
        matches!(self.settled_control_names, Some(Ok(())))
            && matches!(self.settled_cpu_names, Some(Ok(())))
    }

    /// Borrows the earliest original cause, leaving later independent debt held.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = native_failure(&self.captured_controls) {
            return Some(self.controls.failure().unwrap_or(error));
        }
        if let Some(error) = native_failure(&self.captured_cpu) {
            return Some(self.cpu.failure().unwrap_or(error));
        }
        if let Some(Err(error)) = &self.initial_binding {
            return Some(error);
        }
        if let Some(error) = native_failure(&self.checked_controls) {
            return Some(self.controls.failure().unwrap_or(error));
        }
        if let Some(error) = native_failure(&self.checked_cpu) {
            return Some(self.cpu.failure().unwrap_or(error));
        }
        if let Some(error) = native_failure(&self.settled_control_names) {
            return Some(error);
        }
        if let Some(error) = native_failure(&self.settled_cpu_names) {
            return Some(error);
        }
        self.final_binding.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
            .map(|error| error as &(dyn std::error::Error + 'static))
    }

    /// Requires initial native capture before any variable receiving decode.
    ///
    /// This only confirms backstop comparison DATA under the caller's retained
    /// anchor. Its original receiving payment must already cover the reader.
    ///
    /// # Errors
    /// Borrows an actual capture/binding failure or refuses an incomplete stage.
    pub fn require_initial(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if !matches!(self.initial_binding, Some(Ok(()))) {
            return Err(&ContainmentBindingErrorV1::Incomplete);
        }
        Ok(())
    }

    /// Requires the complete final bookend without converting it into authority.
    ///
    /// # Errors
    /// Borrows the original native/binding failure or refuses an incomplete cut.
    pub fn require_current(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if !matches!(self.final_binding, Some(Ok(()))) {
            return Err(&ContainmentBindingErrorV1::Incomplete);
        }
        Ok(())
    }

    fn require_binding(
        &self,
        nofile: Option<rustix::process::Rlimit>,
    ) -> Result<(), ContainmentBindingErrorV1> {
        let expected = self.expected.ok_or(ContainmentBindingErrorV1::Incomplete)?;
        require_limit_bytes(self.controls.bytes(Control::MemoryMax), expected.get(D::MemoryBytes))
            .map_err(|_| ContainmentBindingErrorV1::Memory)?;
        require_limit_bytes(self.controls.bytes(Control::PidsMax), expected.get(D::Pids))
            .map_err(|_| ContainmentBindingErrorV1::Pids)?;
        // The image names microseconds per 100ms. PID1's internal per-second
        // property multiplies by ten; the actual cpu.max quota does not.
        let quota = expected.get(D::CpuMicrosPerPeriod);
        if quota == 0 {
            return Err(ContainmentBindingErrorV1::Cpu);
        }
        if self.cpu.quota_and_period() != Some((quota, 100_000)) {
            return Err(ContainmentBindingErrorV1::Cpu);
        }
        require_nofile(nofile, expected.get(D::OpenFiles))
    }
}

fn native_failure(
    result: &Option<Result<(), aos_sandbox_linux::Error>>,
) -> Option<&aos_sandbox_linux::Error> {
    result.as_ref().and_then(|result| result.as_ref().err())
}

/// Compares a borrowed native finite limit through the existing decoder.
///
/// This is mechanical DATA comparison only. It opens no control, chooses no
/// service or policy and creates no capacity, receiving owner or grant.
///
/// # Errors
/// Refuses absent, noncanonical, nonfinite or unequal decimal records, or a
/// zero expected limit. The caller retains its actual native observations.
#[doc(hidden)]
pub fn require_finite_limit_bytes_v1(bytes: Option<&[u8]>, expected: u64) -> Result<(), ()> {
    require_limit_bytes(bytes, expected)
}

fn require_limit_bytes(bytes: Option<&[u8]>, expected: u64) -> Result<(), ()> {
    let bytes = bytes.and_then(|bytes| bytes.strip_suffix(b"\n")).ok_or(())?;
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') || expected == 0 {
        return Err(());
    }
    let value = bytes.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
    }).ok_or(())?;
    (value == expected).then_some(()).ok_or(())
}

fn require_nofile(
    observed: Option<rustix::process::Rlimit>,
    expected: u64,
) -> Result<(), ContainmentBindingErrorV1> {
    let exact = rustix::process::Rlimit { current: Some(expected), maximum: Some(expected) };
    if expected == 0 || observed != Some(exact) {
        return Err(ContainmentBindingErrorV1::Nofile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_limits_require_canonical_finite_exact_values() {
        assert!(require_limit_bytes(Some(b"536870912\n"), 512 * 1024 * 1024).is_ok());
        assert!(require_limit_bytes(Some(b"32\n"), 32).is_ok());
        for bytes in [b"max\n".as_slice(), b"032\n", b"32", b"32\n\n", b" 32\n", b"31\n",
            b"18446744073709551616\n"] {
            assert!(require_limit_bytes(Some(bytes), 32).is_err());
        }
        assert!(require_limit_bytes(None, 32).is_err());
        assert!(require_limit_bytes(Some(b"0\n"), 0).is_err());
    }

    #[test]
    fn descriptor_backstop_requires_both_limits_without_unlimited_fallback() {
        let finite = |current, maximum| Some(rustix::process::Rlimit { current, maximum });
        assert!(require_nofile(finite(Some(256), Some(256)), 256).is_ok());
        for actual in [None, finite(None, None), finite(Some(256), None),
            finite(Some(255), Some(256)), finite(Some(256), Some(257))] {
            assert!(require_nofile(actual, 256).is_err());
        }
    }

    #[test]
    fn a_fresh_data_capture_cannot_establish_receiving_currentness() {
        let original = ReceivingContainmentReadbackV1::default();
        assert!(original.failure().is_none());
        assert!(original.require_initial().is_err());
        assert!(original.require_current().is_err());
    }
}
