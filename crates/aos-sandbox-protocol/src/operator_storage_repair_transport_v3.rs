//! Two-phase operator Repair carrier with a cold-recoverable signed probe.
//!
//! A prepare request may only observe and reserve. Execute must identify the
//! exact signed attestation returned by a prior prepare; neither legacy V2
//! effects nor an empty expected digest can cross this boundary.
//!
//! ```text
//! request = AOSORTR3 | request-id[16] | deadline:u64be | mode:u8 | zero[7]
//!           | signed-intent[364] | attestation-sha256[32]
//!           | envelope-len:u32be | exact-envelope
//! response = AOSORRS3 | request-id[16] | effect-id[32] | status:u8 | zero[7]
//!            | payload-len:u16be | zero[2] | payload
//! status 1 = prepared AOSOPA01; 2 = pending; 3 = evidence[308]+receipt[328]
//! ```

use aos_sandbox_core::operator_recovery_effect::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES;
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};

use crate::MAXIMUM_REQUEST_BYTES;

const REQUEST_MAGIC: &[u8; 8] = b"AOSORTR3";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSORRS3";
const REQUEST_HEADER_BYTES: usize = 440;
const RESPONSE_HEADER_BYTES: usize = 68;
const COMPLETION_BYTES: usize =
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2 + OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2;
const MINIMUM_ATTESTATION_BYTES: usize = 72 + 438 + 64;
const MAXIMUM_ATTESTATION_BYTES: usize = 72 + 1024 + 64;

/// Fixed socket whose old one-call V2 effect packet is rejected.
pub const OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3: &str =
    "/run/aos/sandbox-storage/operator-repair.sock";

/// Maximum bounded request packet.
pub const MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V3: usize =
    REQUEST_HEADER_BYTES + MAXIMUM_REQUEST_BYTES;

/// Maximum bounded response packet, including the signed probe preimage.
pub const MAXIMUM_OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V3: usize = 2048;

/// Rejects malformed or noncanonical two-phase packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid version-three operator Storage repair packet")]
pub struct OperatorStorageRepairTransportErrorV3;

/// Selects a no-effect probe, exact effect, or read-only cold recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairModeV3 {
    /// Reserves a fresh exact physical probe without effect dispatch.
    Prepare,
    /// Consumes only an already returned and retained probe.
    Execute,
    /// Returns the identical cold-retained probe packet without dispatch.
    RecoverProbe,
    /// Returns a terminal receipt if Storage has durably completed.
    RecoverReceipt,
}

/// Carries an exact signed intent and mode-bound authorization envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairRequestV3 {
    request_id: [u8; 16],
    deadline: u64,
    mode: OperatorStorageRepairModeV3,
    signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
    expected_attestation_digest: [u8; 32],
    envelope: Vec<u8>,
}

impl OperatorStorageRepairRequestV3 {
    /// Constructs only an exact mode profile with bounded authorization bytes.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, missing effect authority, or a wrong digest.
    pub fn new(
        request_id: [u8; 16],
        deadline: u64,
        mode: OperatorStorageRepairModeV3,
        signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
        expected_attestation_digest: [u8; 32],
        envelope: Vec<u8>,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV3> {
        let effectful = matches!(
            mode,
            OperatorStorageRepairModeV3::Prepare | OperatorStorageRepairModeV3::Execute
        );
        if request_id == [0; 16]
            || deadline == 0
            || signed_intent == [0; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            || envelope.len() > MAXIMUM_REQUEST_BYTES
            || effectful == envelope.is_empty()
            || (mode == OperatorStorageRepairModeV3::Execute)
                != (expected_attestation_digest != [0; 32])
        {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        Ok(Self {
            request_id,
            deadline,
            mode,
            signed_intent,
            expected_attestation_digest,
            envelope,
        })
    }

    /// Decodes only exact version-three request bytes.
    ///
    /// # Errors
    ///
    /// Rejects legacy, reserved, truncated, or noncanonical profiles.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV3> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V3
            || bytes.get(..8) != Some(REQUEST_MAGIC.as_slice())
            || bytes.get(33..40) != Some([0; 7].as_slice())
        {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        let mode = match bytes[32] {
            1 => OperatorStorageRepairModeV3::Prepare,
            2 => OperatorStorageRepairModeV3::Execute,
            3 => OperatorStorageRepairModeV3::RecoverProbe,
            4 => OperatorStorageRepairModeV3::RecoverReceipt,
            _ => return Err(OperatorStorageRepairTransportErrorV3),
        };
        let length = u32::from_be_bytes(take(bytes, 436)?) as usize;
        if bytes.len() != REQUEST_HEADER_BYTES + length {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        Self::new(
            take(bytes, 8)?,
            u64::from_be_bytes(take(bytes, 24)?),
            mode,
            take(bytes, 40)?,
            take(bytes, 404)?,
            bytes[REQUEST_HEADER_BYTES..].to_vec(),
        )
    }

    /// Encodes a canonical request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REQUEST_HEADER_BYTES + self.envelope.len());
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.deadline.to_be_bytes());
        bytes.push(match self.mode {
            OperatorStorageRepairModeV3::Prepare => 1,
            OperatorStorageRepairModeV3::Execute => 2,
            OperatorStorageRepairModeV3::RecoverProbe => 3,
            OperatorStorageRepairModeV3::RecoverReceipt => 4,
        });
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&self.signed_intent);
        bytes.extend_from_slice(&self.expected_attestation_digest);
        bytes.extend_from_slice(&(self.envelope.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.envelope);
        bytes
    }

    /// Returns the request nonce.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the BOOTTIME deadline.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Returns the closed mode.
    #[must_use]
    pub const fn mode(&self) -> OperatorStorageRepairModeV3 {
        self.mode
    }

    /// Returns the exact controller-signed intent.
    #[must_use]
    pub fn signed_intent(&self) -> &[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES] {
        &self.signed_intent
    }

    /// Returns the digest of the controller-accepted attestation.
    #[must_use]
    pub const fn expected_attestation_digest(&self) -> [u8; 32] {
        self.expected_attestation_digest
    }

    /// Returns the exact authorized Storage envelope.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

/// Carries a prepared probe, pending status, or separately signed completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairResultV3 {
    /// Complete owner-signed probe preimage, before any repair effect.
    Prepared(Vec<u8>),
    /// Exact repair is not yet durably complete.
    Pending,
    /// Signed physical evidence and generation-bound receipt.
    Complete(
        [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    ),
}

/// Binds a result to its transport nonce and intent effect identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairResponseV3 {
    request_id: [u8; 16],
    effect_id: [u8; 32],
    result: OperatorStorageRepairResultV3,
}

impl OperatorStorageRepairResponseV3 {
    /// Constructs a bounded result with no sentinel identity.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized evidence and identities.
    pub fn new(
        request_id: [u8; 16],
        effect_id: [u8; 32],
        result: OperatorStorageRepairResultV3,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV3> {
        let payload_length = match &result {
            OperatorStorageRepairResultV3::Prepared(packet) => packet.len(),
            OperatorStorageRepairResultV3::Pending => 0,
            OperatorStorageRepairResultV3::Complete(evidence, receipt) => {
                if evidence == &[0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                    || receipt == &[0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2]
                {
                    return Err(OperatorStorageRepairTransportErrorV3);
                }
                COMPLETION_BYTES
            }
        };
        if request_id == [0; 16]
            || effect_id == [0; 32]
            || matches!(&result, OperatorStorageRepairResultV3::Prepared(packet) if !valid_attestation_shape(packet))
            || payload_length
                > MAXIMUM_OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V3 - RESPONSE_HEADER_BYTES
        {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        Ok(Self {
            request_id,
            effect_id,
            result,
        })
    }

    /// Decodes only exact version-three status and payload shapes.
    ///
    /// # Errors
    ///
    /// Rejects legacy, malformed, or trailing response bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV3> {
        if bytes.len() < RESPONSE_HEADER_BYTES
            || bytes.len() > MAXIMUM_OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V3
            || bytes.get(..8) != Some(RESPONSE_MAGIC.as_slice())
            || bytes.get(57..64) != Some([0; 7].as_slice())
            || bytes.get(66..68) != Some([0; 2].as_slice())
        {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        let length = u16::from_be_bytes(take(bytes, 64)?) as usize;
        if bytes.len() != RESPONSE_HEADER_BYTES + length {
            return Err(OperatorStorageRepairTransportErrorV3);
        }
        let payload = &bytes[RESPONSE_HEADER_BYTES..];
        let result = match bytes[56] {
            1 => OperatorStorageRepairResultV3::Prepared(payload.to_vec()),
            2 if payload.is_empty() => OperatorStorageRepairResultV3::Pending,
            3 if payload.len() == COMPLETION_BYTES => OperatorStorageRepairResultV3::Complete(
                payload[..OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                    .try_into()
                    .map_err(|_| OperatorStorageRepairTransportErrorV3)?,
                payload[OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..]
                    .try_into()
                    .map_err(|_| OperatorStorageRepairTransportErrorV3)?,
            ),
            _ => return Err(OperatorStorageRepairTransportErrorV3),
        };
        Self::new(take(bytes, 8)?, take(bytes, 24)?, result)
    }

    /// Encodes an exact response packet.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (status, payload) = match &self.result {
            OperatorStorageRepairResultV3::Prepared(packet) => (1, packet.clone()),
            OperatorStorageRepairResultV3::Pending => (2, Vec::new()),
            OperatorStorageRepairResultV3::Complete(evidence, receipt) => {
                (3, [evidence.as_slice(), receipt.as_slice()].concat())
            }
        };
        let mut bytes = Vec::with_capacity(RESPONSE_HEADER_BYTES + payload.len());
        bytes.extend_from_slice(RESPONSE_MAGIC);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.effect_id);
        bytes.push(status);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&payload);
        bytes
    }

    /// Returns the caller nonce.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the signed intent effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Returns the exact mode-bound result.
    #[must_use]
    pub const fn result(&self) -> &OperatorStorageRepairResultV3 {
        &self.result
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], OperatorStorageRepairTransportErrorV3> {
    bytes
        .get(start..start + N)
        .ok_or(OperatorStorageRepairTransportErrorV3)?
        .try_into()
        .map_err(|_| OperatorStorageRepairTransportErrorV3)
}

fn valid_attestation_shape(packet: &[u8]) -> bool {
    if !(MINIMUM_ATTESTATION_BYTES..=MAXIMUM_ATTESTATION_BYTES).contains(&packet.len())
        || packet.get(..8) != Some(b"AOSOPA01".as_slice())
        || packet.get(70..72) != Some([0; 2].as_slice())
    {
        return false;
    }
    let Some(length) = packet.get(68..70) else {
        return false;
    };
    let Ok(length): Result<[u8; 2], _> = length.try_into() else {
        return false;
    };
    packet.len() == 72 + u16::from_be_bytes(length) as usize + 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_profiles_and_legacy_are_closed() {
        for mode in [
            OperatorStorageRepairModeV3::Prepare,
            OperatorStorageRepairModeV3::Execute,
            OperatorStorageRepairModeV3::RecoverProbe,
            OperatorStorageRepairModeV3::RecoverReceipt,
        ] {
            let effectful = matches!(
                mode,
                OperatorStorageRepairModeV3::Prepare | OperatorStorageRepairModeV3::Execute
            );
            let request = OperatorStorageRepairRequestV3::new(
                [1; 16],
                12,
                mode,
                [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
                if mode == OperatorStorageRepairModeV3::Execute {
                    [3; 32]
                } else {
                    [0; 32]
                },
                if effectful { vec![4; 9] } else { Vec::new() },
            )
            .unwrap();
            assert_eq!(
                OperatorStorageRepairRequestV3::decode(&request.encode()),
                Ok(request.clone())
            );
            let mut legacy = request.encode();
            legacy[..8].copy_from_slice(b"AOSORTR2");
            assert!(OperatorStorageRepairRequestV3::decode(&legacy).is_err());
            let mut trailing = request.encode();
            trailing.push(1);
            assert!(OperatorStorageRepairRequestV3::decode(&trailing).is_err());
        }
        assert!(
            OperatorStorageRepairRequestV3::new(
                [1; 16],
                12,
                OperatorStorageRepairModeV3::Execute,
                [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
                [0; 32],
                vec![4],
            )
            .is_err()
        );
        assert!(
            OperatorStorageRepairRequestV3::new(
                [1; 16],
                12,
                OperatorStorageRepairModeV3::Prepare,
                [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
                [3; 32],
                vec![4],
            )
            .is_err()
        );
    }

    #[test]
    fn response_profiles_are_exact() {
        for result in [
            OperatorStorageRepairResultV3::Prepared({
                let mut packet = vec![0; MINIMUM_ATTESTATION_BYTES];
                packet[..8].copy_from_slice(b"AOSOPA01");
                packet[68..70].copy_from_slice(&438_u16.to_be_bytes());
                packet
            }),
            OperatorStorageRepairResultV3::Pending,
            OperatorStorageRepairResultV3::Complete(
                [3; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
                [4; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
            ),
        ] {
            let response = OperatorStorageRepairResponseV3::new([1; 16], [2; 32], result).unwrap();
            assert_eq!(
                OperatorStorageRepairResponseV3::decode(&response.encode()),
                Ok(response.clone())
            );
            let mut legacy = response.encode();
            legacy[..8].copy_from_slice(b"AOSORRS2");
            assert!(OperatorStorageRepairResponseV3::decode(&legacy).is_err());
            let mut trailing = response.encode();
            trailing.push(1);
            assert!(OperatorStorageRepairResponseV3::decode(&trailing).is_err());
        }
    }
}
