//! Fixed native clock source retained by Controller authorization owners.
//!
//! The original constructor reads the fixed kernel boot identity and installs
//! the existing CLI clock provenance. Sampling retains the original BOOTTIME
//! then realtime observation order; it accepts no caller-supplied sample source.

use aos_sandbox_core::RawPairedClockSample;

#[cfg(target_os = "linux")]
pub(crate) struct ControllerProtectedClockV1 {
    provenance: aos_sandbox_core::RawClockProvenance,
    host_boot_id: [u8; 16],
}

#[cfg(target_os = "linux")]
impl ControllerProtectedClockV1 {
    pub(crate) fn open_fixed() -> Result<Self, crate::ProtectedOwnershipClockError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| crate::ProtectedOwnershipClockError)?;
        let compact = boot_id.trim().replace('-', "");
        if compact.len() != 32 {
            return Err(crate::ProtectedOwnershipClockError);
        }
        let mut host_boot_id = [0_u8; 16];
        for (target, pair) in host_boot_id
            .iter_mut()
            .zip(compact.as_bytes().chunks_exact(2))
        {
            let high = fixed_hex_nibble(pair[0]).ok_or(crate::ProtectedOwnershipClockError)?;
            let low = fixed_hex_nibble(pair[1]).ok_or(crate::ProtectedOwnershipClockError)?;
            *target = (high << 4) | low;
        }
        let provenance = aos_sandbox_core::RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1")
            .map_err(|_| crate::ProtectedOwnershipClockError)?;

        Ok(Self {
            provenance,
            host_boot_id,
        })
    }

    pub(crate) fn sample(
        &mut self,
    ) -> Result<RawPairedClockSample, crate::ProtectedOwnershipClockError> {
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
            .ok_or(crate::ProtectedOwnershipClockError)?;

        RawPairedClockSample::new_untrusted(
            self.provenance,
            self.host_boot_id,
            realtime.tv_sec,
            boottime_nanoseconds,
        )
        .map_err(|_| crate::ProtectedOwnershipClockError)
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
