//! Canonical parsing of the C owner's root-only PREPARED map report.
//!
//! ```text
//! AOSKPR01[152] = header[16] | canonical PREPARED map row[128] |
//!                 observed CLOCK_BOOTTIME nanoseconds:u64be
//! ```
//!
//! The privileged C CLI checks map/link metadata, two exact row/FD readbacks,
//! and grant-row absence before emitting this report. Its output is unsigned;
//! bytes delivered by another process have no owner provenance. This parser
//! can compare a point observation with the signed Stage claim, but cannot
//! authenticate a deployed C owner or provide a held currentness barrier.

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::bounded::boottime;
use sha2::{Digest as _, Sha256};

use crate::OwnerPeerError;
use crate::handoff::DenyStageHandoff;

/// Exact root-only C-owner report length.
pub const REPORT_BYTES: usize = 152;
const PREPARED_DOMAIN: &[u8] = b"aos.sandbox.kernel-export-owner.prepared-map.v1\0";
const MAX_REPORT_AGE_NS: u64 = 1_000_000_000;

/// Holds a checked PREPARED tuple without authenticating its byte carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedMapReport {
    epoch: u64,
    digest: [u8; 32],
    observed_boottime_nanoseconds: u64,
}

impl PreparedMapReport {
    /// Parses an exact recent report against the expected handoff and kernel boot.
    ///
    /// Report bytes must be obtained through a separately protected owner
    /// transport. Passing caller-controlled bytes supplies no map authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed format, wrong map ABI or phase, changed clone or
    /// consumer identity, nonzero lease digest, stale boot, or old/future time.
    pub fn parse_current(input: &[u8], handoff: &DenyStageHandoff) -> Result<Self, OwnerPeerError> {
        let boot = KernelBootId::current()
            .map_err(|_| OwnerPeerError::Physical)?
            .into_bytes();
        let now = boottime().map_err(|_| OwnerPeerError::Physical)?;
        Self::parse_at(input, handoff, boot, now)
    }

    /// Returns the independently reported owner epoch, not a grant epoch proof.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the canonical PREPARED row digest used by the signed Stage claim.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the report's point-in-time kernel BOOTTIME observation.
    #[must_use]
    pub const fn observed_boottime_nanoseconds(&self) -> u64 {
        self.observed_boottime_nanoseconds
    }

    fn parse_at(
        input: &[u8],
        handoff: &DenyStageHandoff,
        boot: [u8; 16],
        now: u64,
    ) -> Result<Self, OwnerPeerError> {
        let report: &[u8; REPORT_BYTES] =
            input.try_into().map_err(|_| OwnerPeerError::Noncanonical)?;
        let mount_id = u64::from_be_bytes(
            report[32..40]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );
        let epoch = u64::from_be_bytes(
            report[40..48]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );
        let device = u64::from_be_bytes(
            report[48..56]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );
        let inode = u64::from_be_bytes(
            report[56..64]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );
        let cgroup_id = u64::from_be_bytes(
            report[64..72]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );
        let observed = u64::from_be_bytes(
            report[144..152]
                .try_into()
                .map_err(|_| OwnerPeerError::Noncanonical)?,
        );

        if &report[..8] != b"AOSKPR01"
            || report[8..10] != 1_u16.to_be_bytes()
            || report[10..16] != [0; 6]
            || report[16..32] != boot
            || boot != handoff.boot_id()
            || mount_id != handoff.clone_mount_id()
            || (device, inode) != handoff.clone_root()
            || cgroup_id != handoff.cgroup_id()
            || report[72..104] != handoff.handoff_id()
            || report[104..136] != [0; 32]
            || report[136..140] != 3_u32.to_be_bytes()
            || report[140..144] != 1_u32.to_be_bytes()
            || epoch == 0
        {
            return Err(OwnerPeerError::Noncanonical);
        }
        if observed == 0 || observed > now || now - observed > MAX_REPORT_AGE_NS {
            return Err(OwnerPeerError::NotCurrent);
        }

        let digest = Sha256::new()
            .chain_update(PREPARED_DOMAIN)
            .chain_update(&report[16..144])
            .finalize()
            .into();
        Ok(Self {
            epoch,
            digest,
            observed_boottime_nanoseconds: observed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::tests::fixture;

    fn report() -> (DenyStageHandoff, [u8; REPORT_BYTES], u64) {
        let source = fixture();
        let handoff = DenyStageHandoff::parse(&source.handoff).unwrap();
        let now = boottime().unwrap();
        let mut report = [0_u8; REPORT_BYTES];
        report[..8].copy_from_slice(b"AOSKPR01");
        report[8..10].copy_from_slice(&1_u16.to_be_bytes());
        report[16..32].copy_from_slice(&handoff.boot_id());
        report[32..40].copy_from_slice(&handoff.clone_mount_id().to_be_bytes());
        report[40..48].copy_from_slice(&1_u64.to_be_bytes());
        let (device, inode) = handoff.clone_root();
        report[48..56].copy_from_slice(&device.to_be_bytes());
        report[56..64].copy_from_slice(&inode.to_be_bytes());
        report[64..72].copy_from_slice(&handoff.cgroup_id().to_be_bytes());
        report[72..104].copy_from_slice(&handoff.handoff_id());
        report[136..140].copy_from_slice(&3_u32.to_be_bytes());
        report[140..144].copy_from_slice(&1_u32.to_be_bytes());
        report[144..152].copy_from_slice(&now.to_be_bytes());
        (handoff, report, now)
    }

    #[test]
    fn exact_prepared_tuple_has_stage_digest_and_recent_kernel_time() {
        let (handoff, report, now) = report();
        let parsed =
            PreparedMapReport::parse_at(&report, &handoff, handoff.boot_id(), now).unwrap();
        let expected: [u8; 32] = Sha256::new()
            .chain_update(PREPARED_DOMAIN)
            .chain_update(&report[16..144])
            .finalize()
            .into();
        assert_eq!(parsed.digest(), &expected);
        assert_eq!(parsed.epoch(), 1);
        assert_eq!(parsed.observed_boottime_nanoseconds(), now);
    }

    #[test]
    fn changed_kernel_identity_phase_and_clock_fail_closed() {
        let (handoff, report, now) = report();
        for offset in [0, 8, 10, 16, 32, 48, 56, 64, 72, 104, 136, 140] {
            let mut changed = report;
            changed[offset] ^= 1;
            assert!(
                PreparedMapReport::parse_at(&changed, &handoff, handoff.boot_id(), now).is_err()
            );
        }
        let mut zero_epoch = report;
        zero_epoch[40..48].fill(0);
        assert!(
            PreparedMapReport::parse_at(&zero_epoch, &handoff, handoff.boot_id(), now).is_err()
        );
        assert!(
            PreparedMapReport::parse_at(&report[..151], &handoff, handoff.boot_id(), now).is_err()
        );
        assert!(PreparedMapReport::parse_at(&report, &handoff, [9; 16], now).is_err());
        assert!(matches!(
            PreparedMapReport::parse_at(
                &report,
                &handoff,
                handoff.boot_id(),
                now + MAX_REPORT_AGE_NS + 1
            ),
            Err(OwnerPeerError::NotCurrent)
        ));
        assert!(matches!(
            PreparedMapReport::parse_at(&report, &handoff, handoff.boot_id(), now - 1),
            Err(OwnerPeerError::NotCurrent)
        ));
    }
}
