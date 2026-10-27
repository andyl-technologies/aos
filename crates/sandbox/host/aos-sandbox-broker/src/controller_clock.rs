//! Fixed native clock source retained by Controller authorization owners.
//!
//! The original constructor reads the fixed kernel boot identity and installs
//! the existing CLI clock provenance. Sampling retains the original BOOTTIME
//! then realtime observation order; it accepts no caller-supplied sample source.

use std::marker::PhantomData;

use aos_sandbox_model::RawPairedClockSample;

/// Supplies only the existing caller's clock-boundary diagnostics.
///
/// This adapter cannot observe a clock, choose a native source, admit work, or
/// supply an original. The fixed native engines remain in this module.
pub trait ContinuationClockErrorV1: std::error::Error + 'static {
    /// Returns the caller's existing protected-boundary refusal.
    fn protected_boundary() -> Self;

    /// Returns the caller's existing construction-size refusal.
    fn journal_too_large() -> Self;
}

/// Retains one observation from the same fixed Controller authorization clock.
///
/// Each independently owed destination owns its own boot reader and result.
/// The provenance is established by the actual clock constructor; no raw
/// sample is relabeled to fit a different sampler's origin.
#[cfg(target_os = "linux")]
pub struct RetainedControllerProtectedClockAttemptV1<E> {
    boot: aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1,
    clock: Option<ControllerProtectedClockV1>,
    result: Option<Result<RawPairedClockSample, crate::paired_clock::ProtectedOwnershipClockError>>,
    error: PhantomData<fn() -> E>,
}

#[cfg(target_os = "linux")]
impl<E> Default for RetainedControllerProtectedClockAttemptV1<E> {
    fn default() -> Self {
        Self {
            boot: Default::default(),
            clock: None,
            result: None,
            error: PhantomData,
        }
    }
}

#[cfg(target_os = "linux")]
impl<E: ContinuationClockErrorV1> RetainedControllerProtectedClockAttemptV1<E> {
    /// Returns the unchanged fixed reader, parser, and retained-control demand.
    ///
    /// # Errors
    /// Refuses overflow using the caller's established size diagnostic.
    pub fn receiving_demand_v1() -> Result<aos_sandbox_model::ResourceVector, E> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(E::journal_too_large())?;
        let entries = u64::try_from(
            aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1(
            ),
        )
        .map_err(|_| E::journal_too_large())?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, entries)
            .with(D::OpenFiles, aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))
    }

    /// Samples the fixed Controller clock once and retains every failed prefix.
    ///
    /// # Errors
    /// Refuses reentry or native acquisition/conversion failure. The actual
    /// boot reader and typed native result remain available through `failure`.
    pub fn observe_once_v1(&mut self) -> Result<RawPairedClockSample, E> {
        if self.result.is_some() {
            return Err(E::protected_boundary());
        }
        self.result = Some((|| {
            self.clock = Some(ControllerProtectedClockV1::open_retaining_v1(
                &mut self.boot,
            )?);
            self.clock
                .as_mut()
                .ok_or(crate::paired_clock::ProtectedOwnershipClockError)?
                .sample()
        })());
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(E::protected_boundary())
    }

    /// Borrows the actual first native boot or sampling cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.boot
            .failure()
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[cfg(target_os = "linux")]
/// Owns the fixed Controller authorization clock's provenance and boot identity.
///
/// A sample alone confers no role, financial admission, or native effect grant.
pub struct ControllerProtectedClockV1 {
    provenance: aos_sandbox_model::RawClockProvenance,
    host_boot_id: [u8; 16],
}

#[cfg(target_os = "linux")]
impl ControllerProtectedClockV1 {
    /// Opens the existing ordinary fixed boot-identity recipe.
    ///
    /// # Errors
    /// Refuses native read failure or noncanonical boot identity.
    pub fn open_fixed() -> Result<Self, crate::paired_clock::ProtectedOwnershipClockError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)?;
        let compact = boot_id.trim().replace('-', "");
        if compact.len() != 32 {
            return Err(crate::paired_clock::ProtectedOwnershipClockError);
        }
        let mut host_boot_id = [0_u8; 16];
        for (target, pair) in host_boot_id
            .iter_mut()
            .zip(compact.as_bytes().chunks_exact(2))
        {
            let high = fixed_hex_nibble(pair[0])
                .ok_or(crate::paired_clock::ProtectedOwnershipClockError)?;
            let low = fixed_hex_nibble(pair[1])
                .ok_or(crate::paired_clock::ProtectedOwnershipClockError)?;
            *target = (high << 4) | low;
        }
        let provenance = aos_sandbox_model::RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1")
            .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)?;

        Ok(Self {
            provenance,
            host_boot_id,
        })
    }

    /// Captures the fixed boot identity in the caller's genuine retained reader.
    ///
    /// # Errors
    /// Refuses reader failure or failed positive retirement, retaining that
    /// reader's actual native cause in the caller-owned destination.
    pub fn open_retaining_v1(
        boot: &mut aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1,
    ) -> Result<Self, crate::paired_clock::ProtectedOwnershipClockError> {
        let host_boot_id = boot
            .observe_once()
            .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)?
            .into_bytes();
        let provenance = aos_sandbox_model::RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1")
            .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)?;
        // Complete canonical EOF/procfs validation is this native reader's own
        // disposal frontier. Failed/partial files remain in the passed owner.
        boot.retire_positive_file_once()
            .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)?;
        Ok(Self {
            provenance,
            host_boot_id,
        })
    }

    /// Samples BOOTTIME before realtime with the unchanged Controller provenance.
    ///
    /// # Errors
    /// Refuses invalid or overflowing native time values.
    pub fn sample(
        &mut self,
    ) -> Result<RawPairedClockSample, crate::paired_clock::ProtectedOwnershipClockError> {
        let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let boottime_nanoseconds = u64::try_from(boottime.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| {
                u64::try_from(boottime.tv_nsec)
                    .ok()
                    .and_then(|nanoseconds| value.checked_add(nanoseconds))
            })
            .ok_or(crate::paired_clock::ProtectedOwnershipClockError)?;

        RawPairedClockSample::new_untrusted(
            self.provenance,
            self.host_boot_id,
            realtime.tv_sec,
            boottime_nanoseconds,
        )
        .map_err(|_| crate::paired_clock::ProtectedOwnershipClockError)
    }
}

#[cfg(target_os = "linux")]
const fn fixed_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
