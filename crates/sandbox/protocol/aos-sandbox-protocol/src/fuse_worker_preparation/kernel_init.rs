//! Zero-rights kernel-only preparation phases on the original worker channel.
//!
//! ```text
//! AOSFWK03 | phase:u8 | zero[7] | exact fresh challenge[112]
//! phase = START_INIT(1), INIT_COMPLETE(2), IDMAP_COMPLETE(3), SESSION_RETAINED(4)
//! ```
//!
//! These records schedule and compare preparation only. An INIT reply cannot
//! certify kernel negotiation, and an idmap reply cannot confer read authority.
//! The genuine Mount owner must perform the syscall on its original objects.

use super::{WorkerPreparationWireError, WorkerRendezvousChallengeV2};

/// Exact bounded record length for the version-three zero-rights profile.
pub const WORKER_KERNEL_PREPARATION_BYTES_V3: usize = 128;

/// Names a nonauthorizing phase in one original held preparation flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerKernelPreparationPhaseV3 {
    /// Mount schedules kernel-only INIT after the fresh subject join.
    StartInit = 1,
    /// Worker retains the same C session after actual kernel INIT.
    InitComplete = 2,
    /// Mount completed its original namespace's real idmap effect.
    IdmapComplete = 3,
    /// Worker still owns the same prepared session; no dispatch is enabled.
    SessionRetained = 4,
}

impl WorkerKernelPreparationPhaseV3 {
    /// Encodes this phase bound to the exact original fresh rendezvous.
    #[must_use]
    pub fn encode(
        self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> [u8; WORKER_KERNEL_PREPARATION_BYTES_V3] {
        let mut bytes = [0; WORKER_KERNEL_PREPARATION_BYTES_V3];
        bytes[..8].copy_from_slice(b"AOSFWK03");
        bytes[8] = self as u8;
        bytes[16..].copy_from_slice(&challenge.encode());
        bytes
    }

    /// Compares the entire record without adopting its sender or claimed effect.
    ///
    /// # Errors
    ///
    /// Rejects another version, direction/phase, nonce/scope, reserved byte,
    /// record length or expired original preparation deadline.
    pub fn compare(
        self,
        bytes: &[u8],
        challenge: &WorkerRendezvousChallengeV2,
        now: u64,
    ) -> Result<(), WorkerPreparationWireError> {
        challenge.check_deadline(now)?;
        if bytes != self.encode(challenge) {
            return Err(WorkerPreparationWireError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kernel_phase_requires_exact_fresh_version_scope_and_direction() {
        let plan = super::super::tests::plan();
        let challenge = WorkerRendezvousChallengeV2::new(&plan, [12; 32]).unwrap();
        let other = WorkerRendezvousChallengeV2::new(&plan, [13; 32]).unwrap();
        let phases = [
            WorkerKernelPreparationPhaseV3::StartInit,
            WorkerKernelPreparationPhaseV3::InitComplete,
            WorkerKernelPreparationPhaseV3::IdmapComplete,
            WorkerKernelPreparationPhaseV3::SessionRetained,
        ];

        for phase in phases {
            let bytes = phase.encode(&challenge);
            phase.compare(&bytes, &challenge, 99).unwrap();
            assert!(phase.compare(&bytes, &challenge, 100).is_err());
            assert!(phase.compare(&bytes, &other, 1).is_err());
            assert!(phase.compare(&challenge.reply(), &challenge, 1).is_err());
            for other_phase in phases {
                if phase != other_phase {
                    assert!(
                        phase
                            .compare(&other_phase.encode(&challenge), &challenge, 1)
                            .is_err()
                    );
                }
            }
            for offset in [0, 8, 9, 16, 24, 40, 56, 88, 120] {
                let mut changed = bytes;
                changed[offset] ^= 1;
                assert!(
                    phase.compare(&changed, &challenge, 1).is_err(),
                    "offset {offset}"
                );
            }
            assert!(phase.compare(&bytes[..127], &challenge, 1).is_err());
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(phase.compare(&trailing, &challenge, 1).is_err());
        }
    }
}
