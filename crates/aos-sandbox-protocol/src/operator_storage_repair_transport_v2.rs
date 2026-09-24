//! Version-two operator Repair carrier with separate signed owner evidence.
//!
//! The old `AOSORTR1`/`AOSORRS1` packets are not accepted on this path.
//! A completed response contains both a generation-bound receipt and a
//! separately signed before-probe, attempt-commit, and post-inventory record.
//!
//! ```text
//! request = AOSORTR2 | request-id[16] | deadline:u64be | mode:u8
//!           | reserved[7]=0 | signed-intent[364] | envelope-len:u32be
//!           | exact-authorized-envelope[envelope-len]
//! response = AOSORRS2 | request-id[16] | effect-id[32] | status:u8
//!            | reserved[7]=0 | signed-evidence[308] | signed-receipt[328]
//! mode 1 = effect, nonempty envelope; mode 2 = receipt recovery, empty envelope
//! status 1 = pending, zero evidence and receipt; status 2 = complete, both signed
//! ```

use aos_sandbox_core::operator_recovery_effect::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES;
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};

use crate::MAXIMUM_REQUEST_BYTES;

const REQUEST_MAGIC: &[u8; 8] = b"AOSORTR2";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSORRS2";
const REQUEST_HEADER_BYTES: usize = 408;
const RESPONSE_HEADER_BYTES: usize = 64;
const RESPONSE_BYTES: usize = RESPONSE_HEADER_BYTES
    + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2
    + OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2;

/// Fixed node-local filesystem socket for the version-two operator sidecar.
pub const OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V2: &str =
    "/run/aos/sandbox-storage/operator-repair.sock";

/// Maximum one-packet version-two request size.
pub const MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V2: usize =
    REQUEST_HEADER_BYTES + MAXIMUM_REQUEST_BYTES;
/// Exact version-two response size.
pub const OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V2: usize = RESPONSE_BYTES;

/// Rejects malformed or ambiguous version-two packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperatorStorageRepairTransportErrorV2 {
    /// An identity, field, version, status, or length is invalid.
    #[error("invalid version-two operator Storage repair packet")]
    Invalid,
}

/// Selects effect dispatch or read-only recovery of a retained completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairModeV2 {
    /// Requests the exact authorized Storage Repair effect.
    Effect,
    /// Reads only the retained signed physical result.
    RecoverReceipt,
}

/// Carries one signed intent and optional exact Storage authorization envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairRequestV2 {
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    mode: OperatorStorageRepairModeV2,
    signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
    authorized_envelope: Vec<u8>,
}

impl OperatorStorageRepairRequestV2 {
    /// Constructs a bounded request with an exact effect or read-only profile.
    ///
    /// # Errors
    ///
    /// Rejects sentinel fields, an oversized envelope, or wrong mode profile.
    pub fn new(
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        mode: OperatorStorageRepairModeV2,
        signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
        authorized_envelope: Vec<u8>,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV2> {
        if request_id == [0; 16]
            || deadline_boottime_nanoseconds == 0
            || signed_intent == [0; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            || authorized_envelope.len() > MAXIMUM_REQUEST_BYTES
            || (mode == OperatorStorageRepairModeV2::Effect) != !authorized_envelope.is_empty()
        {
            return Err(OperatorStorageRepairTransportErrorV2::Invalid);
        }
        Ok(Self {
            request_id,
            deadline_boottime_nanoseconds,
            mode,
            signed_intent,
            authorized_envelope,
        })
    }

    /// Decodes only the exact version-two packet with no trailing bytes.
    ///
    /// # Errors
    ///
    /// Rejects legacy version, reserved bits, wrong length, or invalid mode.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV2> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V2
            || bytes.get(..8) != Some(REQUEST_MAGIC.as_slice())
            || bytes[33..40] != [0; 7]
        {
            return Err(OperatorStorageRepairTransportErrorV2::Invalid);
        }
        let request_id = take(bytes, 8)?;
        let deadline = u64::from_be_bytes(take(bytes, 24)?);
        let mode = match bytes[32] {
            1 => OperatorStorageRepairModeV2::Effect,
            2 => OperatorStorageRepairModeV2::RecoverReceipt,
            _ => return Err(OperatorStorageRepairTransportErrorV2::Invalid),
        };
        let signed_intent = take(bytes, 40)?;
        let length = u32::from_be_bytes(take(bytes, 404)?) as usize;
        if bytes.len() != REQUEST_HEADER_BYTES + length {
            return Err(OperatorStorageRepairTransportErrorV2::Invalid);
        }
        Self::new(
            request_id,
            deadline,
            mode,
            signed_intent,
            bytes[REQUEST_HEADER_BYTES..].to_vec(),
        )
    }

    /// Encodes one canonical version-two request record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REQUEST_HEADER_BYTES + self.authorized_envelope.len());
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.push(match self.mode {
            OperatorStorageRepairModeV2::Effect => 1,
            OperatorStorageRepairModeV2::RecoverReceipt => 2,
        });
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&self.signed_intent);
        bytes.extend_from_slice(&(self.authorized_envelope.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.authorized_envelope);
        bytes
    }

    /// Returns the caller-selected nonce.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the absolute BOOTTIME deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the closed effect or receipt-recovery mode.
    #[must_use]
    pub const fn mode(&self) -> OperatorStorageRepairModeV2 {
        self.mode
    }

    /// Returns the exact controller-signed intent packet.
    #[must_use]
    pub fn signed_intent(&self) -> &[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES] {
        &self.signed_intent
    }

    /// Returns the exact authorized Storage envelope, if effectful.
    #[must_use]
    pub fn authorized_envelope(&self) -> &[u8] {
        &self.authorized_envelope
    }
}

/// Returns either pending or the separately signed physical evidence pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairResponseV2 {
    request_id: [u8; 16],
    effect_id: [u8; 32],
    completion: Option<(
        [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    )>,
}

impl OperatorStorageRepairResponseV2 {
    /// Constructs a pending or fully signed result for one request.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities or an all-zero claimed completion.
    pub fn new(
        request_id: [u8; 16],
        effect_id: [u8; 32],
        completion: Option<(
            [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
        )>,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV2> {
        if request_id == [0; 16]
            || effect_id == [0; 32]
            || completion.is_some_and(|(evidence, receipt)| {
                evidence == [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                    || receipt == [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2]
            })
        {
            return Err(OperatorStorageRepairTransportErrorV2::Invalid);
        }
        Ok(Self {
            request_id,
            effect_id,
            completion,
        })
    }

    /// Decodes only the exact version-two response profile.
    ///
    /// # Errors
    ///
    /// Rejects legacy packets, malformed status, reserved bits, or missing pair.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV2> {
        if bytes.len() != RESPONSE_BYTES
            || bytes.get(..8) != Some(RESPONSE_MAGIC.as_slice())
            || bytes[57..64] != [0; 7]
        {
            return Err(OperatorStorageRepairTransportErrorV2::Invalid);
        }
        let request_id = take(bytes, 8)?;
        let effect_id = take(bytes, 24)?;
        let evidence = take(bytes, 64)?;
        let receipt = take(bytes, 64 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2)?;
        let completion = match bytes[56] {
            1 if evidence == [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                && receipt == [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2] =>
            {
                None
            }
            2 if evidence != [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                && receipt != [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2] =>
            {
                Some((evidence, receipt))
            }
            _ => return Err(OperatorStorageRepairTransportErrorV2::Invalid),
        };
        Self::new(request_id, effect_id, completion)
    }

    /// Encodes a fixed-width version-two response record.
    #[must_use]
    pub fn encode(&self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..24].copy_from_slice(&self.request_id);
        bytes[24..56].copy_from_slice(&self.effect_id);
        if let Some((evidence, receipt)) = self.completion {
            bytes[56] = 2;
            bytes[64..64 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2].copy_from_slice(&evidence);
            bytes[64 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..].copy_from_slice(&receipt);
        } else {
            bytes[56] = 1;
        }
        bytes
    }

    /// Returns the exact request nonce.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the signed intent's effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Returns both signed owner packets, or no completion.
    #[must_use]
    pub const fn completion(
        &self,
    ) -> Option<&(
        [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    )> {
        self.completion.as_ref()
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorStorageRepairTransportErrorV2> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(OperatorStorageRepairTransportErrorV2::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_request_rejects_legacy_and_effectful_recovery() {
        let request = OperatorStorageRepairRequestV2::new(
            [1; 16],
            42,
            OperatorStorageRepairModeV2::RecoverReceipt,
            [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
            Vec::new(),
        )
        .unwrap();
        let bytes = request.encode();
        assert_eq!(OperatorStorageRepairRequestV2::decode(&bytes), Ok(request));
        let mut legacy = bytes.clone();
        legacy[..8].copy_from_slice(b"AOSORTR1");
        assert!(OperatorStorageRepairRequestV2::decode(&legacy).is_err());
        assert!(
            OperatorStorageRepairRequestV2::new(
                [1; 16],
                42,
                OperatorStorageRepairModeV2::RecoverReceipt,
                [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
                vec![3],
            )
            .is_err()
        );
    }

    #[test]
    fn v2_response_requires_both_owner_packets() {
        let complete = OperatorStorageRepairResponseV2::new(
            [1; 16],
            [2; 32],
            Some((
                [3; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
                [4; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
            )),
        )
        .unwrap();
        assert_eq!(
            OperatorStorageRepairResponseV2::decode(&complete.encode()),
            Ok(complete)
        );
        let mut missing = complete.encode();
        missing[64..64 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2].fill(0);
        assert!(OperatorStorageRepairResponseV2::decode(&missing).is_err());
        let mut legacy = complete.encode();
        legacy[..8].copy_from_slice(b"AOSORRS1");
        assert!(OperatorStorageRepairResponseV2::decode(&legacy).is_err());
    }
}
