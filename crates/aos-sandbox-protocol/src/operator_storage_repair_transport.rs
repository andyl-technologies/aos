//! Bounded node-local operator Storage repair and receipt-recovery packets.
//!
//! The controller-signed intent binds the exact inner Storage repair body;
//! the existing authorized broker envelope independently carries plan and
//! lease artifacts. A recovery query contains no effect envelope and can only
//! read a receipt already retained by Storage's protected sidecar.
//!
//! ```text
//! request = AOSORTR1 | request-id[16] | deadline:u64be | mode:u8
//!           | reserved[7]=0 | signed-intent[364] | envelope-len:u32be
//!           | exact-authorized-envelope[envelope-len]
//! response = AOSORRS1 | request-id[16] | effect-id[32] | status:u8
//!            | reserved[7]=0 | signed-receipt[288]
//! mode 1 = effect, nonempty envelope; mode 2 = receipt recovery, empty envelope
//! status 1 = pending, zero receipt; status 2 = complete, signed receipt
//! ```

use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_INTENT_BYTES, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES,
};

use crate::MAXIMUM_REQUEST_BYTES;

const REQUEST_MAGIC: &[u8; 8] = b"AOSORTR1";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSORRS1";
const REQUEST_HEADER_BYTES: usize = 408;
const RESPONSE_BYTES: usize = 64 + OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES;

/// Fixed node-local filesystem socket for the operator Repair sidecar.
pub const OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V1: &str =
    "/run/aos/sandbox-storage/operator-repair.sock";

/// Maximum one-packet operator repair request size.
pub const MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V1: usize =
    REQUEST_HEADER_BYTES + MAXIMUM_REQUEST_BYTES;
/// Exact one-packet operator repair response size.
pub const OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V1: usize = RESPONSE_BYTES;

/// Rejects malformed or ambiguous operator repair transport packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperatorStorageRepairTransportErrorV1 {
    /// A field, length, version, or mode is outside the closed contract.
    #[error("invalid operator Storage repair transport packet")]
    Invalid,
}

/// Selects effect dispatch or read-only receipt recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairModeV1 {
    /// Dispatches the exact signed repair at most once.
    Effect,
    /// Queries only the already durable effect and owner receipt.
    RecoverReceipt,
}

impl OperatorStorageRepairModeV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Effect => 1,
            Self::RecoverReceipt => 2,
        }
    }
}

/// Carries a signed controller intent and optional exact Storage envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairRequestV1 {
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    mode: OperatorStorageRepairModeV1,
    signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
    authorized_envelope: Vec<u8>,
}

impl OperatorStorageRepairRequestV1 {
    /// Constructs one bounded, nonzero request with its exact mode profile.
    ///
    /// # Errors
    ///
    /// Rejects a sentinel identity or deadline, wrong envelope presence, or
    /// an envelope exceeding the existing Storage broker request ceiling.
    pub fn new(
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        mode: OperatorStorageRepairModeV1,
        signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
        authorized_envelope: Vec<u8>,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV1> {
        if request_id == [0; 16]
            || deadline_boottime_nanoseconds == 0
            || signed_intent == [0; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            || authorized_envelope.len() > MAXIMUM_REQUEST_BYTES
            || (mode == OperatorStorageRepairModeV1::Effect) != !authorized_envelope.is_empty()
        {
            return Err(OperatorStorageRepairTransportErrorV1::Invalid);
        }
        Ok(Self {
            request_id,
            deadline_boottime_nanoseconds,
            mode,
            signed_intent,
            authorized_envelope,
        })
    }

    /// Decodes an exact canonical packet without admitting any effect.
    ///
    /// # Errors
    ///
    /// Rejects unknown mode, reserved bytes, sentinel values, or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV1> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V1
            || bytes.get(..8) != Some(REQUEST_MAGIC.as_slice())
            || bytes[33..40] != [0; 7]
        {
            return Err(OperatorStorageRepairTransportErrorV1::Invalid);
        }
        let request_id = bytes[8..24]
            .try_into()
            .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?;
        let deadline = u64::from_be_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?,
        );
        let mode = match bytes[32] {
            1 => OperatorStorageRepairModeV1::Effect,
            2 => OperatorStorageRepairModeV1::RecoverReceipt,
            _ => return Err(OperatorStorageRepairTransportErrorV1::Invalid),
        };
        let signed_intent = bytes[40..40 + OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            .try_into()
            .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?;
        let length = u32::from_be_bytes(
            bytes[404..408]
                .try_into()
                .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?,
        ) as usize;
        if bytes.len() != REQUEST_HEADER_BYTES + length {
            return Err(OperatorStorageRepairTransportErrorV1::Invalid);
        }
        Self::new(
            request_id,
            deadline,
            mode,
            signed_intent,
            bytes[REQUEST_HEADER_BYTES..].to_vec(),
        )
    }

    /// Encodes the request as one canonical record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REQUEST_HEADER_BYTES + self.authorized_envelope.len());
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.push(self.mode.code());
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&self.signed_intent);
        bytes.extend_from_slice(&(self.authorized_envelope.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.authorized_envelope);
        bytes
    }

    /// Returns the exact caller-selected nonce.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the absolute BOOTTIME deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the closed effect or read-only profile.
    #[must_use]
    pub const fn mode(&self) -> OperatorStorageRepairModeV1 {
        self.mode
    }

    /// Returns the exact controller-signed intent packet.
    #[must_use]
    pub fn signed_intent(&self) -> &[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES] {
        &self.signed_intent
    }

    /// Returns the exact existing authorized Storage envelope, if effectful.
    #[must_use]
    pub fn authorized_envelope(&self) -> &[u8] {
        &self.authorized_envelope
    }
}

/// Carries either no terminal evidence or the exact owner-signed receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorStorageRepairResponseV1 {
    request_id: [u8; 16],
    effect_id: [u8; 32],
    signed_receipt: Option<[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES]>,
}

impl OperatorStorageRepairResponseV1 {
    /// Constructs a pending or completed response for one exact request.
    ///
    /// # Errors
    ///
    /// Rejects absent identities or an all-zero claimed receipt.
    pub fn new(
        request_id: [u8; 16],
        effect_id: [u8; 32],
        signed_receipt: Option<[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES]>,
    ) -> Result<Self, OperatorStorageRepairTransportErrorV1> {
        if request_id == [0; 16]
            || effect_id == [0; 32]
            || signed_receipt == Some([0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES])
        {
            return Err(OperatorStorageRepairTransportErrorV1::Invalid);
        }
        Ok(Self {
            request_id,
            effect_id,
            signed_receipt,
        })
    }

    /// Decodes one exact response packet with no trailing bytes.
    ///
    /// # Errors
    ///
    /// Rejects reserved data, inconsistent status, or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorStorageRepairTransportErrorV1> {
        if bytes.len() != RESPONSE_BYTES
            || bytes.get(..8) != Some(RESPONSE_MAGIC.as_slice())
            || bytes[57..64] != [0; 7]
        {
            return Err(OperatorStorageRepairTransportErrorV1::Invalid);
        }
        let request_id = bytes[8..24]
            .try_into()
            .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?;
        let effect_id = bytes[24..56]
            .try_into()
            .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?;
        let packet: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] = bytes[64..]
            .try_into()
            .map_err(|_| OperatorStorageRepairTransportErrorV1::Invalid)?;
        let signed_receipt = match bytes[56] {
            1 if packet == [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] => None,
            2 if packet != [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] => Some(packet),
            _ => return Err(OperatorStorageRepairTransportErrorV1::Invalid),
        };
        Self::new(request_id, effect_id, signed_receipt)
    }

    /// Encodes one fixed-width response packet.
    #[must_use]
    pub fn encode(&self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..24].copy_from_slice(&self.request_id);
        bytes[24..56].copy_from_slice(&self.effect_id);
        if let Some(packet) = self.signed_receipt {
            bytes[56] = 2;
            bytes[64..].copy_from_slice(&packet);
        } else {
            bytes[56] = 1;
        }
        bytes
    }

    /// Returns the nonce bound to the request.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the Storage body-derived effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Returns the owner-signed receipt only after durable completion.
    #[must_use]
    pub const fn signed_receipt(&self) -> Option<&[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES]> {
        self.signed_receipt.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_and_recovery_packets_have_distinct_exact_shapes() {
        for (mode, envelope) in [
            (OperatorStorageRepairModeV1::Effect, vec![3; 17]),
            (OperatorStorageRepairModeV1::RecoverReceipt, Vec::new()),
        ] {
            let request = OperatorStorageRepairRequestV1::new(
                [1; 16],
                123,
                mode,
                [2; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
                envelope,
            )
            .unwrap();
            let encoded = request.encode();
            assert_eq!(
                OperatorStorageRepairRequestV1::decode(&encoded),
                Ok(request)
            );
            let mut extra = encoded.clone();
            extra.push(0);
            assert!(OperatorStorageRepairRequestV1::decode(&extra).is_err());
            let mut reserved = encoded;
            reserved[33] = 1;
            assert!(OperatorStorageRepairRequestV1::decode(&reserved).is_err());
        }
    }

    #[test]
    fn pending_and_complete_responses_never_alias() {
        let pending = OperatorStorageRepairResponseV1::new([1; 16], [2; 32], None).unwrap();
        let complete = OperatorStorageRepairResponseV1::new(
            [1; 16],
            [2; 32],
            Some([3; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES]),
        )
        .unwrap();
        assert_eq!(
            OperatorStorageRepairResponseV1::decode(&pending.encode()),
            Ok(pending)
        );
        assert_eq!(
            OperatorStorageRepairResponseV1::decode(&complete.encode()),
            Ok(complete)
        );
        let mut invalid = pending.encode();
        invalid[56] = 2;
        assert!(OperatorStorageRepairResponseV1::decode(&invalid).is_err());
    }
}
