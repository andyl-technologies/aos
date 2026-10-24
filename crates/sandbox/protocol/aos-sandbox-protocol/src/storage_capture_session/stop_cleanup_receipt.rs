//! Canonical residual DATA after fresh Stop containment of an incomplete Capture.
//!
//! The receipt never represents drained output or Capture Complete. Actual
//! native sender/receiver and Controller durable settlement remain mandatory.
//!
//! ```text
//! AOSCSR04 | version:u16 | zero[2] | QuiescentIncomplete:u8 | zero[3]
//! | nonce32 | begin32 | source32 | attempt16 | durableAttempt32
//! | StopRequest16 | runtime32 | StopFrame32 | StopPlan32 | StopLease32
//! | physicalBinding32 | negativeNativeCommitment32
//! | finalWall:i64 | finalBoot:u64 | freshStopCutoff:u64 | domainDigest32
//! ```

use super::stop_cleanup::{CaptureStopCleanupProtocolErrorV4, CaptureStopCleanupRequestDataV4};
use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Exact fixed canonical residual receipt width; it is not an AOSCRS02 record.
pub const CAPTURE_STOP_RECEIPT_BYTES_V4: usize = 424;
const MAGIC: &[u8; 8] = b"AOSCSR04";
const DOMAIN: &[u8] = b"aos.sandbox.capture.stop-quiescent-incomplete.v4\0";

/// Supplies comparison fields; none of these values creates native authority.
pub struct CaptureQuiescentIncompleteFieldsDataV4 {
    /// Exact same held-channel challenge.
    pub nonce: [u8; 32],
    /// Exact original physical Begin digest.
    pub begin: [u8; 32],
    /// Whole original signed Source944 digest.
    pub source: ObjectDigest,
    /// Original durable physical attempt identifier.
    pub attempt: [u8; 16],
    /// Exact original canonical424 durable-attempt digest.
    pub durable_attempt: ObjectDigest,
    /// Fresh authenticated Host Stop request identifier.
    pub stop_request: [u8; 16],
    /// Runtime target derived by the sole Host semantics helper.
    pub runtime: ObjectDigest,
    /// Exact complete fresh Stop forwarding-frame digest.
    pub stop_frame: ObjectDigest,
    /// Actual independently verified fresh Root Stop plan digest.
    pub stop_plan: ObjectDigest,
    /// Actual independently verified fresh ownership lease digest.
    pub stop_lease: ObjectDigest,
    /// Same retained incomplete physical Output binding row digest.
    pub physical_binding: ObjectDigest,
    /// Commitment formed only by the actual negative native cleanup owner.
    pub native_cleanup: ObjectDigest,
    /// Final actual paired wall-clock sample after all cleanup bookends.
    pub observed_wall_seconds: i64,
    /// Final actual paired BOOTTIME sample after all cleanup bookends.
    pub observed_boottime_nanoseconds: u64,
    /// Fresh Stop cutoff, without renewing the previous execution horizon.
    pub stop_cutoff_boottime_nanoseconds: u64,
}

/// Retains canonical QuiescentIncomplete comparison DATA without a native proof.
///
/// Only an opaque actual native receive owner may lend this receipt onward as
/// verified residual cleanup. Decoding it does not settle old errors or debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureQuiescentIncompleteReceiptDataV4 {
    bytes: [u8; CAPTURE_STOP_RECEIPT_BYTES_V4],
}

impl CaptureQuiescentIncompleteReceiptDataV4 {
    /// Encodes explicit DATA fields without adopting a native result or grant.
    ///
    /// # Errors
    /// Refuses zero identity/digest fields or an observation outside fresh Stop.
    pub fn from_fields_v4(
        fields: CaptureQuiescentIncompleteFieldsDataV4,
    ) -> Result<Self, CaptureStopCleanupProtocolErrorV4> {
        let mut bytes = [0; CAPTURE_STOP_RECEIPT_BYTES_V4];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&4u16.to_be_bytes());
        bytes[12] = 1;
        bytes[16..48].copy_from_slice(&fields.nonce);
        bytes[48..80].copy_from_slice(&fields.begin);
        bytes[80..112].copy_from_slice(fields.source.as_bytes());
        bytes[112..128].copy_from_slice(&fields.attempt);
        bytes[128..160].copy_from_slice(fields.durable_attempt.as_bytes());
        bytes[160..176].copy_from_slice(&fields.stop_request);
        bytes[176..208].copy_from_slice(fields.runtime.as_bytes());
        bytes[208..240].copy_from_slice(fields.stop_frame.as_bytes());
        bytes[240..272].copy_from_slice(fields.stop_plan.as_bytes());
        bytes[272..304].copy_from_slice(fields.stop_lease.as_bytes());
        bytes[304..336].copy_from_slice(fields.physical_binding.as_bytes());
        bytes[336..368].copy_from_slice(fields.native_cleanup.as_bytes());
        bytes[368..376].copy_from_slice(&fields.observed_wall_seconds.to_be_bytes());
        bytes[376..384].copy_from_slice(&fields.observed_boottime_nanoseconds.to_be_bytes());
        bytes[384..392].copy_from_slice(&fields.stop_cutoff_boottime_nanoseconds.to_be_bytes());
        let commitment = digest(&bytes[..392]);
        bytes[392..].copy_from_slice(&commitment);
        Self::decode_v4(&bytes)
    }

    /// Decodes the one exact version/status and full domain commitment as DATA.
    ///
    /// # Errors
    /// Refuses foreign formats/status, reserved bytes, zero coordinates, stale
    /// observation, changed digest, truncation or trailing bytes.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, CaptureStopCleanupProtocolErrorV4> {
        if bytes.len() != CAPTURE_STOP_RECEIPT_BYTES_V4
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..16) != Some([0, 4, 0, 0, 1, 0, 0, 0].as_slice())
        {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        for (start, end) in [
            (16, 48),
            (48, 80),
            (80, 112),
            (112, 128),
            (128, 160),
            (160, 176),
            (176, 208),
            (208, 240),
            (240, 272),
            (272, 304),
            (304, 336),
            (336, 368),
        ] {
            if bytes[start..end].iter().all(|byte| *byte == 0) {
                return Err(CaptureStopCleanupProtocolErrorV4);
            }
        }
        if bytes[392..] != digest(&bytes[..392]) {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        let value = Self {
            bytes: bytes
                .try_into()
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
        };
        if value.observed_boottime_nanoseconds_v4() == 0
            || value.observed_boottime_nanoseconds_v4()
                >= value.stop_cutoff_boottime_nanoseconds_v4()
        {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        Ok(value)
    }

    /// Compares the exact request and genuine caller's original expected DATA.
    ///
    /// # Errors
    /// Refuses another challenge, source, attempt, Stop, runtime, original row,
    /// fresh plan/lease or cutoff. Successful comparison supplies no native proof.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_request_v4(
        &self,
        request: &CaptureStopCleanupRequestDataV4<'_>,
        stop_request: [u8; 16],
        runtime: ObjectDigest,
        durable_attempt: ObjectDigest,
        physical_binding: ObjectDigest,
        plan: ObjectDigest,
        lease: ObjectDigest,
    ) -> Result<(), CaptureStopCleanupProtocolErrorV4> {
        if self.bytes[16..48] != *request.nonce_v4()
            || self.bytes[48..80] != *request.begin_digest_v4()
            || self.source_digest_v4().as_bytes() != request.source_digest_v4()
            || self.attempt_v4() != *request.attempt_v4()
            || self.stop_request_id_v4() != stop_request
            || self.runtime_v4() != runtime
            || self.durable_attempt_digest_v4() != durable_attempt
            || self.physical_binding_digest_v4() != physical_binding
            || self.bytes[208..240] != request.digest_v4()
            || self.stop_plan_digest_v4() != plan
            || self.stop_lease_digest_v4() != lease
            || self.stop_cutoff_boottime_nanoseconds_v4() != request.cutoff_v4()
        {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        Ok(())
    }

    /// Borrows the full canonical receipt for exact durable Controller storage.
    #[must_use]
    pub const fn canonical_bytes_v4(&self) -> &[u8; CAPTURE_STOP_RECEIPT_BYTES_V4] {
        &self.bytes
    }
    /// Returns the complete canonical receipt without another encoding.
    #[must_use]
    pub const fn encode_v4(&self) -> [u8; CAPTURE_STOP_RECEIPT_BYTES_V4] {
        self.bytes
    }
    /// Returns the full domain commitment, never a native completion proof.
    #[must_use]
    pub fn digest_v4(&self) -> ObjectDigest {
        self.digest_at(392)
    }
    /// Returns the exact fresh Stop request identifier.
    #[must_use]
    pub fn stop_request_id_v4(&self) -> [u8; 16] {
        self.fixed_at(160)
    }
    /// Returns the exact canonical runtime target.
    #[must_use]
    pub fn runtime_v4(&self) -> ObjectDigest {
        self.digest_at(176)
    }
    /// Returns the complete original Source944 digest.
    #[must_use]
    pub fn source_digest_v4(&self) -> ObjectDigest {
        self.digest_at(80)
    }
    /// Returns the exact original physical attempt identifier.
    #[must_use]
    pub fn attempt_v4(&self) -> [u8; 16] {
        self.fixed_at(112)
    }
    /// Returns the original durable attempt digest without settling it.
    #[must_use]
    pub fn durable_attempt_digest_v4(&self) -> ObjectDigest {
        self.digest_at(128)
    }
    /// Returns the exact verified fresh Stop plan digest.
    #[must_use]
    pub fn stop_plan_digest_v4(&self) -> ObjectDigest {
        self.digest_at(240)
    }
    /// Returns the exact verified fresh Stop ownership lease digest.
    #[must_use]
    pub fn stop_lease_digest_v4(&self) -> ObjectDigest {
        self.digest_at(272)
    }
    /// Returns the original incomplete physical Output binding digest.
    #[must_use]
    pub fn physical_binding_digest_v4(&self) -> ObjectDigest {
        self.digest_at(304)
    }
    /// Returns the negative native cleanup commitment, never full output status.
    #[must_use]
    pub fn native_cleanup_digest_v4(&self) -> ObjectDigest {
        self.digest_at(336)
    }
    /// Returns the final actual paired wall observation as comparison DATA.
    #[must_use]
    pub fn observed_wall_seconds_v4(&self) -> i64 {
        i64::from_be_bytes(self.fixed_at(368))
    }
    /// Returns the final actual paired BOOTTIME observation as comparison DATA.
    #[must_use]
    pub fn observed_boottime_nanoseconds_v4(&self) -> u64 {
        u64::from_be_bytes(self.fixed_at(376))
    }
    /// Returns the separate fresh Stop cutoff without execution renewal.
    #[must_use]
    pub fn stop_cutoff_boottime_nanoseconds_v4(&self) -> u64 {
        u64::from_be_bytes(self.fixed_at(384))
    }

    fn fixed_at<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut value = [0; N];
        value.copy_from_slice(&self.bytes[offset..offset + N]);
        value
    }

    fn digest_at(&self, offset: usize) -> ObjectDigest {
        ObjectDigest::from_bytes(self.fixed_at(offset))
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_receipt_preserves_all_residual_bindings_and_refuses_complete_format() {
        let request = CaptureStopCleanupRequestDataV4::new(
            900,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 16],
            b"stop",
            crate::session::AuthorizationArtifactBytes {
                broker_plan: b"plan",
                broker_plan_signature: b"signature",
                ownership_lease: b"lease",
                ownership_lease_signature: b"lease-signature",
            },
        )
        .unwrap();
        let digest = |byte| ObjectDigest::from_bytes([byte; 32]);
        let value = CaptureQuiescentIncompleteReceiptDataV4::from_fields_v4(
            CaptureQuiescentIncompleteFieldsDataV4 {
                nonce: [1; 32],
                begin: [2; 32],
                source: digest(3),
                attempt: [4; 16],
                durable_attempt: digest(5),
                stop_request: [6; 16],
                runtime: digest(7),
                stop_frame: ObjectDigest::from_bytes(request.digest_v4()),
                stop_plan: digest(8),
                stop_lease: digest(9),
                physical_binding: digest(10),
                native_cleanup: digest(11),
                observed_wall_seconds: 12,
                observed_boottime_nanoseconds: 800,
                stop_cutoff_boottime_nanoseconds: 900,
            },
        )
        .unwrap();
        value
            .verify_request_v4(
                &request,
                [6; 16],
                digest(7),
                digest(5),
                digest(10),
                digest(8),
                digest(9),
            )
            .unwrap();
        assert!(
            value
                .verify_request_v4(
                    &request,
                    [6; 16],
                    digest(7),
                    digest(5),
                    digest(10),
                    digest(18),
                    digest(9)
                )
                .is_err()
        );
        let mut bytes = value.encode_v4();
        assert_eq!(
            CaptureQuiescentIncompleteReceiptDataV4::decode_v4(&bytes).unwrap(),
            value
        );
        assert_eq!(value.source_digest_v4(), digest(3));
        assert_eq!(value.stop_request_id_v4(), [6; 16]);
        bytes[..8].copy_from_slice(b"AOSCRS02");
        assert!(CaptureQuiescentIncompleteReceiptDataV4::decode_v4(&bytes).is_err());
    }
}
