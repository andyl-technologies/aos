//! Structural codec for the complete Mount `AOSMAJ`/`AOSMAE` record.
//!
//! Decoding proves closed framing and canonical field boundaries only. The
//! trailing MAC is retained but is not authenticated in this pure crate.

use super::MountSourceConsumptionStateError;

/// Exact Mount authenticated-wrapper magic.
pub const MOUNT_EFFECT_WRAPPER_MAGIC_V1: &[u8; 8] = b"AOSMAJ\0\0";
/// Exact Mount effect-payload magic.
pub const MOUNT_EFFECT_PAYLOAD_MAGIC_V1: &[u8; 8] = b"AOSMAE\0\0";
/// Maximum retained effect receipt.
pub const MAXIMUM_MOUNT_EFFECT_RECEIPT_BYTES_V1: usize = 1024 * 1024;
/// Maximum complete authenticated Mount effect value.
pub const MAXIMUM_MOUNT_EFFECT_VALUE_BYTES_V1: usize =
    32 + 554 + MAXIMUM_MOUNT_EFFECT_RECEIPT_BYTES_V1 + 32;
/// Exact encoded local-lease record size.
pub const LOCAL_LEASE_RECORD_BYTES_V1: usize = 234;

/// Retains every byte-bearing field of one structurally decoded Mount effect.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyDecodedMountEffectV1 {
    pub key_id: [u8; 16],
    pub status: u8,
    pub verb: u8,
    pub target_tag: u8,
    pub target_identity: [u8; 64],
    pub request_id: [u8; 16],
    pub transport_request_digest: [u8; 32],
    pub semantic_digest: [u8; 32],
    pub plan_digest: [u8; 32],
    pub lease_digest: [u8; 32],
    pub maximum_request_bytes: u32,
    pub maximum_descriptors: u16,
    pub plan_expires_seconds: i64,
    pub authority_expires_seconds: i64,
    pub host_boot_id: [u8; 16],
    pub fail_stop_boottime_nanoseconds: u64,
    pub clock_provenance: [u8; 16],
    pub admitted_wall_seconds: i64,
    pub admitted_boottime_nanoseconds: u64,
    pub request_deadline_boottime_nanoseconds: u64,
    pub effect_deadline_boottime_nanoseconds: u64,
    pub local_lease_record: [u8; LOCAL_LEASE_RECORD_BYTES_V1],
    pub receipt: Vec<u8>,
    pub mac: [u8; 32],
}

/// Structurally decodes one complete Mount effect wrapper and payload.
///
/// This function does not authenticate `mac`; callers requiring authority
/// must first obtain a broker-key-owned verification proof for the exact
/// namespace, key, and bytes.
///
/// # Errors
///
/// Returns an error for an over-limit value, malformed wrapper or payload,
/// unknown wrapper kind, nonzero reserved byte, or inconsistent length.
pub fn structurally_decode_mount_effect_v1(
    value: &[u8],
) -> Result<StructurallyDecodedMountEffectV1, MountSourceConsumptionStateError> {
    if value.len() < 64 || value.len() > MAXIMUM_MOUNT_EFFECT_VALUE_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    if value.get(..8) != Some(MOUNT_EFFECT_WRAPPER_MAGIC_V1.as_slice())
        || value.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || value.get(10).copied() != Some(2)
        || value.get(11).copied() != Some(0)
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let key_id = exact::<16>(value, 12)?;
    if key_id == [0; 16] {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let payload_length = u32::from_be_bytes(exact::<4>(value, 28)?) as usize;
    let payload_end = 32usize
        .checked_add(payload_length)
        .ok_or(MountSourceConsumptionStateError::InvalidSize)?;
    if payload_length > MAXIMUM_MOUNT_EFFECT_VALUE_BYTES_V1 - 64
        || payload_end.checked_add(32) != Some(value.len())
    {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    let payload = &value[32..payload_end];
    let mac = exact::<32>(value, payload_end)?;
    decode_payload(payload, key_id, mac)
}

/// Reencodes one structurally decoded Mount effect without authenticating it.
///
/// # Errors
///
/// Returns an error when the receipt or resulting value exceeds the closed
/// bounds. Broker code must authenticate the returned framing separately.
pub fn structurally_encode_mount_effect_v1(
    effect: &StructurallyDecodedMountEffectV1,
) -> Result<Vec<u8>, MountSourceConsumptionStateError> {
    if effect.key_id == [0; 16] || effect.receipt.len() > MAXIMUM_MOUNT_EFFECT_RECEIPT_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let payload = structurally_encode_mount_effect_payload_v1(effect)?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| MountSourceConsumptionStateError::InvalidSize)?;
    let mut value = Vec::with_capacity(64 + payload.len());
    value.extend_from_slice(MOUNT_EFFECT_WRAPPER_MAGIC_V1);
    value.extend_from_slice(&1_u16.to_be_bytes());
    value.push(2);
    value.push(0);
    value.extend_from_slice(&effect.key_id);
    value.extend_from_slice(&payload_length.to_be_bytes());
    value.extend_from_slice(&payload);
    value.extend_from_slice(&effect.mac);
    if value.len() > MAXIMUM_MOUNT_EFFECT_VALUE_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    Ok(value)
}

/// Encodes the complete structural `AOSMAE` payload without a wrapper or MAC.
///
/// # Errors
///
/// Returns an error for invalid sentinel or over-limit fields.
pub fn structurally_encode_mount_effect_payload_v1(
    effect: &StructurallyDecodedMountEffectV1,
) -> Result<Vec<u8>, MountSourceConsumptionStateError> {
    if effect.key_id == [0; 16] || effect.receipt.len() > MAXIMUM_MOUNT_EFFECT_RECEIPT_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let mut payload = Vec::with_capacity(554 + effect.receipt.len());
    payload.extend_from_slice(MOUNT_EFFECT_PAYLOAD_MAGIC_V1);
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.push(effect.status);
    payload.push(effect.verb);
    payload.push(effect.target_tag);
    payload.extend_from_slice(&effect.target_identity);
    payload.extend_from_slice(&effect.request_id);
    payload.extend_from_slice(&effect.transport_request_digest);
    payload.extend_from_slice(&effect.semantic_digest);
    payload.extend_from_slice(&effect.plan_digest);
    payload.extend_from_slice(&effect.lease_digest);
    payload.extend_from_slice(&effect.maximum_request_bytes.to_be_bytes());
    payload.extend_from_slice(&effect.maximum_descriptors.to_be_bytes());
    payload.extend_from_slice(&effect.plan_expires_seconds.to_be_bytes());
    payload.extend_from_slice(&effect.authority_expires_seconds.to_be_bytes());
    payload.extend_from_slice(&effect.host_boot_id);
    payload.extend_from_slice(&effect.fail_stop_boottime_nanoseconds.to_be_bytes());
    payload.extend_from_slice(&effect.clock_provenance);
    payload.extend_from_slice(&effect.admitted_wall_seconds.to_be_bytes());
    payload.extend_from_slice(&effect.admitted_boottime_nanoseconds.to_be_bytes());
    payload.extend_from_slice(&effect.request_deadline_boottime_nanoseconds.to_be_bytes());
    payload.extend_from_slice(&effect.effect_deadline_boottime_nanoseconds.to_be_bytes());
    payload.extend_from_slice(&effect.local_lease_record);
    let receipt_length = u32::try_from(effect.receipt.len())
        .map_err(|_| MountSourceConsumptionStateError::InvalidSize)?;
    payload.extend_from_slice(&receipt_length.to_be_bytes());
    payload.extend_from_slice(&effect.receipt);

    Ok(payload)
}

/// Structurally decodes a complete `AOSMAE` payload after broker MAC opening.
///
/// `key_id` and `mac` preserve the authenticated wrapper identity in the
/// returned projection; this pure function does not authenticate them.
///
/// # Errors
///
/// Returns an error for malformed, unknown, or over-limit payload fields.
pub fn structurally_decode_mount_effect_payload_v1(
    payload: &[u8],
    key_id: [u8; 16],
    mac: [u8; 32],
) -> Result<StructurallyDecodedMountEffectV1, MountSourceConsumptionStateError> {
    if key_id == [0; 16] || payload.len() > MAXIMUM_MOUNT_EFFECT_VALUE_BYTES_V1 - 64 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    decode_payload(payload, key_id, mac)
}

fn decode_payload(
    payload: &[u8],
    key_id: [u8; 16],
    mac: [u8; 32],
) -> Result<StructurallyDecodedMountEffectV1, MountSourceConsumptionStateError> {
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != *MOUNT_EFFECT_PAYLOAD_MAGIC_V1 || decoder.u16()? != 1 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let status = decoder.u8()?;
    let verb = decoder.u8()?;
    let target_tag = decoder.u8()?;
    let target_identity = decoder.array::<64>()?;
    let target_shape_valid = match target_tag {
        0 => target_identity == [0; 64],
        1 => {
            target_identity[..32].iter().any(|byte| *byte != 0) && target_identity[32..] == [0; 32]
        }
        2 => {
            target_identity[..32].iter().any(|byte| *byte != 0)
                && target_identity[32..].iter().any(|byte| *byte != 0)
        }
        _ => false,
    };
    if status > 1 || !(1..=8).contains(&verb) || !target_shape_valid {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let request_id = decoder.array::<16>()?;
    let transport_request_digest = decoder.array::<32>()?;
    let semantic_digest = decoder.array::<32>()?;
    let plan_digest = decoder.array::<32>()?;
    let lease_digest = decoder.array::<32>()?;
    let maximum_request_bytes = decoder.u32()?;
    let maximum_descriptors = decoder.u16()?;
    let plan_expires_seconds = decoder.i64()?;
    let authority_expires_seconds = decoder.i64()?;
    let host_boot_id = decoder.array::<16>()?;
    let fail_stop_boottime_nanoseconds = decoder.u64()?;
    let clock_provenance = decoder.array::<16>()?;
    let admitted_wall_seconds = decoder.i64()?;
    let admitted_boottime_nanoseconds = decoder.u64()?;
    let request_deadline_boottime_nanoseconds = decoder.u64()?;
    let effect_deadline_boottime_nanoseconds = decoder.u64()?;
    let local_lease_record = decoder.array::<LOCAL_LEASE_RECORD_BYTES_V1>()?;
    aos_sandbox_core::decode_local_lease_record(&local_lease_record)
        .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    let receipt_length = decoder.u32()? as usize;
    if receipt_length > MAXIMUM_MOUNT_EFFECT_RECEIPT_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    let receipt = decoder.bytes(receipt_length)?.to_vec();
    decoder.finish()?;

    Ok(StructurallyDecodedMountEffectV1 {
        key_id,
        status,
        verb,
        target_tag,
        target_identity,
        request_id,
        transport_request_digest,
        semantic_digest,
        plan_digest,
        lease_digest,
        maximum_request_bytes,
        maximum_descriptors,
        plan_expires_seconds,
        authority_expires_seconds,
        host_boot_id,
        fail_stop_boottime_nanoseconds,
        clock_provenance,
        admitted_wall_seconds,
        admitted_boottime_nanoseconds,
        request_deadline_boottime_nanoseconds,
        effect_deadline_boottime_nanoseconds,
        local_lease_record,
        receipt,
        mac,
    })
}

fn exact<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], MountSourceConsumptionStateError> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(MountSourceConsumptionStateError::InvalidValue)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], MountSourceConsumptionStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MountSourceConsumptionStateError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| MountSourceConsumptionStateError::InvalidValue)
    }

    fn u8(&mut self) -> Result<u8, MountSourceConsumptionStateError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, MountSourceConsumptionStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, MountSourceConsumptionStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, MountSourceConsumptionStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, MountSourceConsumptionStateError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), MountSourceConsumptionStateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(MountSourceConsumptionStateError::InvalidValue)
        }
    }
}
