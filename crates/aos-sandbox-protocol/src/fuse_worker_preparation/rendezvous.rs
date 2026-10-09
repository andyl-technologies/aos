//! Distinct, zero-rights fresh rendezvous comparison records.
//!
//! ```text
//! AOSFWQ02 | original worker[16] | boot[16] | fresh nonce[32] |
//! sealed-plan digest[32] | preparation deadline:u64le
//! AOSFWE02 | the identical original coordinates
//! ```
//!
//! Construction and decoding are structural only. The real Host must generate
//! the nonce after its launch-copy barrier, and Mount must retain its actual
//! original owners and consume the reply's kernel record subject. Neither
//! these bytes nor a successful comparison acknowledges readiness or reading.

use super::{WorkerPreparationPlanV1, WorkerPreparationWireError, array};

/// Exact size of each challenge and reply in the closed version-two profile.
pub const WORKER_RENDEZVOUS_BYTES_V2: usize = 112;

/// Carries nonauthorizing coordinates for one fresh original-channel exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRendezvousChallengeV2 {
    worker: [u8; 16],
    boot: [u8; 16],
    nonce: [u8; 32],
    plan: [u8; 32],
    deadline: u64,
}

impl WorkerRendezvousChallengeV2 {
    /// Binds comparison coordinates to a plan and a separately generated nonce.
    ///
    /// This function cannot establish when the nonce was generated or whether
    /// descriptor copies closed. Only the actual closed producer can do that.
    ///
    /// # Errors
    ///
    /// Rejects an invalid plan, zero nonce, or reuse of its prelaunch challenge.
    pub fn new(
        plan: &WorkerPreparationPlanV1,
        nonce: [u8; 32],
    ) -> Result<Self, WorkerPreparationWireError> {
        if nonce == [0; 32] || nonce == plan.challenge {
            return Err(WorkerPreparationWireError);
        }
        Ok(Self {
            worker: plan.worker_instance,
            boot: plan.kernel_boot,
            nonce,
            plan: plan.digest()?,
            deadline: plan.preparation_deadline_boottime_ns,
        })
    }

    /// Encodes only this profile's fixed zero-rights challenge.
    #[must_use]
    pub fn encode(&self) -> [u8; WORKER_RENDEZVOUS_BYTES_V2] {
        self.record(b"AOSFWQ02")
    }

    /// Decodes a challenge and compares its entire retained original scope.
    ///
    /// # Errors
    ///
    /// Rejects another grammar, stale deadline, reused nonce, or changed plan,
    /// worker, boot or preparation boundary. It does not authenticate a sender.
    pub fn decode(
        bytes: &[u8],
        original: &WorkerPreparationPlanV1,
        now: u64,
    ) -> Result<Self, WorkerPreparationWireError> {
        if bytes.len() != WORKER_RENDEZVOUS_BYTES_V2 || bytes[..8] != *b"AOSFWQ02" {
            return Err(WorkerPreparationWireError);
        }
        let expected = Self::new(original, array(bytes, 40)?)?;
        if expected.encode() != bytes {
            return Err(WorkerPreparationWireError);
        }
        expected.check_deadline(now)?;
        Ok(expected)
    }

    /// Encodes the distinct reply to this exact fresh challenge.
    #[must_use]
    pub fn reply(&self) -> [u8; WORKER_RENDEZVOUS_BYTES_V2] {
        self.record(b"AOSFWE02")
    }

    /// Compares the reply bytes without adopting its sender as a worker.
    ///
    /// # Errors
    ///
    /// Rejects an old HELLO, wrong nonce/scope/grammar, or elapsed deadline.
    pub fn compare_reply(&self, bytes: &[u8], now: u64) -> Result<(), WorkerPreparationWireError> {
        self.check_deadline(now)?;
        if bytes != self.reply() {
            return Err(WorkerPreparationWireError);
        }
        Ok(())
    }

    /// Checks the original absolute preparation deadline.
    ///
    /// # Errors
    ///
    /// Rejects equality or a time after the original preparation boundary.
    pub fn check_deadline(&self, now: u64) -> Result<(), WorkerPreparationWireError> {
        if now >= self.deadline {
            return Err(WorkerPreparationWireError);
        }
        Ok(())
    }

    fn record(&self, magic: &[u8; 8]) -> [u8; WORKER_RENDEZVOUS_BYTES_V2] {
        let mut bytes = [0; WORKER_RENDEZVOUS_BYTES_V2];
        bytes[..8].copy_from_slice(magic);
        bytes[8..24].copy_from_slice(&self.worker);
        bytes[24..40].copy_from_slice(&self.boot);
        bytes[40..72].copy_from_slice(&self.nonce);
        bytes[72..104].copy_from_slice(&self.plan);
        bytes[104..112].copy_from_slice(&self.deadline.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> WorkerPreparationPlanV1 {
        super::super::tests::plan()
    }

    #[test]
    fn fresh_profile_never_reinterprets_prelaunch_hello() {
        let original = plan();
        let challenge = WorkerRendezvousChallengeV2::new(&original, [12; 32]).unwrap();

        assert_eq!(
            WorkerRendezvousChallengeV2::decode(&challenge.encode(), &original, 99).unwrap(),
            challenge
        );
        challenge.compare_reply(&challenge.reply(), 99).unwrap();
        assert!(
            challenge
                .compare_reply(&original.hello().unwrap(), 99)
                .is_err()
        );
        assert!(WorkerRendezvousChallengeV2::new(&original, original.challenge).is_err());
        assert!(WorkerRendezvousChallengeV2::new(&original, [0; 32]).is_err());
        assert!(challenge.compare_reply(&challenge.reply(), 100).is_err());
        assert!(WorkerRendezvousChallengeV2::decode(&challenge.encode(), &original, 100).is_err());
    }

    #[test]
    fn every_coordinate_and_record_direction_is_exact() {
        let original = plan();
        let challenge = WorkerRendezvousChallengeV2::new(&original, [12; 32]).unwrap();
        for offset in [0, 8, 24, 40, 72, 104] {
            let mut reply = challenge.reply();
            reply[offset] ^= 1;
            assert!(
                challenge.compare_reply(&reply, 1).is_err(),
                "offset {offset}"
            );
        }
        let other = WorkerRendezvousChallengeV2::new(&original, [13; 32]).unwrap();
        assert!(other.compare_reply(&challenge.reply(), 1).is_err());
        assert!(challenge.compare_reply(&challenge.encode(), 1).is_err());
        assert!(WorkerRendezvousChallengeV2::decode(&challenge.reply(), &original, 1).is_err());
        assert!(
            challenge
                .compare_reply(&challenge.reply()[..111], 1)
                .is_err()
        );
        let mut trailing = challenge.reply().to_vec();
        trailing.push(0);
        assert!(challenge.compare_reply(&trailing, 1).is_err());
    }
}
