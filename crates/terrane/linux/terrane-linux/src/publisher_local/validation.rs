//! Rejects unknown protobuf fields and invalid command combinations before I/O effects.
//!
//! ```text
//! packet: tags 1..15; claim: tags 1..6; body key: tags 1..4
//! Unknown fields, wrong wire types and duplicate singular fields fail closed.
//! ```

use prost::Message;
use terrane_format::{
    identity::{Descriptor, IdentityKind, IdentityProfile},
    properties::Domain,
};

use super::{
    Error,
    wire::{BodyKey, BodyKind, Operation, Packet, ResultCode},
};

/// The registered maximum protobuf payload length.
pub const MAX_PACKET: usize = 65_536;

/// Configured identities used to validate keys and publication claims.
pub struct ValidationPolicy<'a> {
    /// The configured disclosure domain; never a path supplied by a peer.
    pub domain: &'a str,
    /// The configured immutable-content identity profile.
    pub identity: &'a IdentityProfile,
    /// The configured registered chunk profile.
    pub chunk_profile: &'a str,
}

/// Decodes a closed version-one message and validates its descriptor count.
///
/// # Errors
///
/// Rejects malformed, unknown, repeated singular or inappropriate fields,
/// unregistered identities, wrong directions and invalid descriptor counts.
pub fn decode_packet(
    bytes: &[u8],
    descriptors: usize,
    response: bool,
    policy: &ValidationPolicy<'_>,
) -> Result<Packet, Error> {
    let packet = decode_envelope(bytes)?;
    validate_packet(&packet, descriptors, response, policy)?;
    Ok(packet)
}

/// Decodes the closed envelope before selecting an exact configured domain.
///
/// # Errors
/// Rejects oversized, malformed, unknown or inappropriate protobuf fields.
pub(super) fn decode_envelope(bytes: &[u8]) -> Result<Packet, Error> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET {
        return Err(Error::Invalid("packet length"));
    }
    let fields = preflight(bytes, Shape::Packet)?;
    let packet = Packet::decode(bytes).map_err(Error::Protobuf)?;
    if fields & !allowed_fields(&packet)? != 0 {
        return Err(Error::Invalid("unexpected operation field"));
    }
    Ok(packet)
}

/// Validates semantic fields and the exact operation-specific descriptor count.
///
/// # Errors
///
/// Rejects unsupported versions, identities, keys, claims, directions and
/// combinations that cannot occur in the registered operation matrix.
pub fn validate_packet(
    packet: &Packet,
    descriptors: usize,
    response: bool,
    policy: &ValidationPolicy<'_>,
) -> Result<(), Error> {
    let operation =
        Operation::try_from(packet.operation).map_err(|_| Error::Invalid("operation"))?;
    let result = ResultCode::try_from(packet.result).map_err(|_| Error::Invalid("result"))?;
    if packet.version != 1
        || packet.request_id == 0
        || operation == Operation::Unspecified
        || Domain::parse(&packet.domain).is_err()
        || packet.domain != policy.domain
        || packet.cache_incarnation.len() != 16
        || packet.response != response
        || packet.inventory_cursor.len() > 64
    {
        return Err(Error::Invalid("packet header"));
    }

    if response {
        if packet.wait_budget_ms != 0 || packet.claim.is_some() || packet.body.is_some() {
            return Err(Error::Invalid("response request fields"));
        }
        if result != ResultCode::Ok {
            if descriptors != 0
                || !packet.body_incarnation.is_empty()
                || packet.verity_algorithm != 0
                || !packet.verity_digest.is_empty()
                || !packet.inventory.is_empty()
                || !packet.inventory_cursor.is_empty()
            {
                return Err(Error::Invalid("error response fields"));
            }
            return Ok(());
        }
        let returned_fd = matches!(
            operation,
            Operation::Probe
                | Operation::Publish
                | Operation::Adopt
                | Operation::InspectBody
                | Operation::InspectQuarantine
        );
        if descriptors != usize::from(returned_fd) {
            return Err(Error::Invalid("response descriptor count"));
        }
        let token = matches!(
            operation,
            Operation::Publish
                | Operation::Adopt
                | Operation::InspectBody
                | Operation::InspectPending
        );
        if packet.body_incarnation.len() != if token { 32 } else { 0 } {
            return Err(Error::Invalid("response incarnation"));
        }
        let binding = match (packet.verity_algorithm, packet.verity_digest.len()) {
            (0, 0) => false,
            (1, 32) | (2, 64) => true,
            _ => return Err(Error::Invalid("verity binding")),
        };
        if matches!(
            operation,
            Operation::Probe | Operation::Publish | Operation::Adopt
        ) && !binding
            || !returned_fd && binding
            || operation == Operation::InspectQuarantine && binding
        {
            return Err(Error::Invalid("response binding"));
        }
        if operation == Operation::Inventory {
            if packet.inventory.len() > 64 {
                return Err(Error::Invalid("inventory size"));
            }
            for key in &packet.inventory {
                validate_body(key, policy)?;
            }
        } else if !packet.inventory.is_empty() || !packet.inventory_cursor.is_empty() {
            return Err(Error::Invalid("unexpected inventory"));
        }
        return Ok(());
    }

    if !(1..=300_000).contains(&packet.wait_budget_ms)
        || result != ResultCode::Ok
        || packet.verity_algorithm != 0
        || !packet.verity_digest.is_empty()
        || !packet.inventory.is_empty()
        || operation != Operation::Inventory && !packet.inventory_cursor.is_empty()
    {
        return Err(Error::Invalid("request response fields"));
    }
    if let Some(body) = &packet.body {
        validate_body(body, policy)?;
    }
    let sealed = packet
        .body
        .as_ref()
        .is_some_and(|body| body.kind == BodyKind::Sealed as i32);
    let needs_claim = matches!(operation, Operation::Publish | Operation::Adopt)
        || operation == Operation::InspectBody && sealed;
    let needs_body = needs_claim
        || matches!(
            operation,
            Operation::InspectBody
                | Operation::InspectPending
                | Operation::InspectQuarantine
                | Operation::Quarantine
                | Operation::Retire
                | Operation::Restore
                | Operation::FinishRetirement
        );
    let needs_token = matches!(
        operation,
        Operation::Retire
            | Operation::Restore
            | Operation::FinishRetirement
            | Operation::Quarantine
    );
    let valid_token = if operation == Operation::InspectQuarantine {
        matches!(packet.body_incarnation.len(), 0 | 32)
    } else {
        packet.body_incarnation.len() == if needs_token { 32 } else { 0 }
    };
    if packet.claim.is_some() != needs_claim
        || packet.body.is_some() != needs_body
        || !valid_token
        || needs_claim && !sealed
        || matches!(
            operation,
            Operation::InspectQuarantine | Operation::Quarantine
        ) && !sealed
    {
        return Err(Error::Invalid("request command fields"));
    }

    let mut expected_fds = usize::from(operation == Operation::Publish);
    if let Some(claim) = &packet.claim {
        let descriptor = Descriptor::decode(policy.identity, &claim.descriptor)
            .map_err(|_| Error::Invalid("claim descriptor"))?;
        let kind = policy
            .identity
            .kind(descriptor.domain())
            .map_err(|_| Error::Invalid("claim kind"))?;
        let manifest = kind == IdentityKind::Manifest;
        if !matches!(kind, IdentityKind::Chunk | IdentityKind::Manifest)
            || packet
                .body
                .as_ref()
                .is_none_or(|body| body.descriptor != claim.descriptor)
            || claim.chunk_profile != policy.chunk_profile
            || manifest && (claim.manifest_length == 0 || claim.retention_id.len() != 16)
            || !manifest
                && (claim.manifest_offset != 0
                    || claim.manifest_length != 0
                    || !claim.retention_id.is_empty()
                    || claim.plaintext_size != descriptor.size())
            || claim
                .manifest_offset
                .checked_add(claim.manifest_length)
                .is_none()
        {
            return Err(Error::Invalid("claim fields"));
        }
        expected_fds += usize::from(manifest);
    }
    if descriptors != expected_fds {
        return Err(Error::Invalid("request descriptor count"));
    }
    Ok(())
}

fn validate_body(body: &BodyKey, policy: &ValidationPolicy<'_>) -> Result<(), Error> {
    let kind = BodyKind::try_from(body.kind).map_err(|_| Error::Invalid("body kind"))?;
    if kind == BodyKind::Pack {
        return if body.pack_id.len() == 16 && body.descriptor.is_empty() && body.codec == 0 {
            Ok(())
        } else {
            Err(Error::Invalid("pack key"))
        };
    }
    let descriptor = Descriptor::decode(policy.identity, &body.descriptor)
        .map_err(|_| Error::Invalid("body descriptor"))?;
    let content_kind = policy
        .identity
        .kind(descriptor.domain())
        .map_err(|_| Error::Invalid("body domain"))?;
    if !body.pack_id.is_empty()
        || match kind {
            BodyKind::Sealed => {
                body.codec != 0
                    || !matches!(content_kind, IdentityKind::Chunk | IdentityKind::Manifest)
            }
            BodyKind::Chunk => body.codec > 2 || content_kind != IdentityKind::Chunk,
            _ => true,
        }
    {
        return Err(Error::Invalid("body key"));
    }
    Ok(())
}

fn allowed_fields(packet: &Packet) -> Result<u32, Error> {
    let operation =
        Operation::try_from(packet.operation).map_err(|_| Error::Invalid("operation"))?;
    let mut fields = bits(&[1, 2, 3, 4, 5]);
    if packet.response {
        fields |= bits(&[10, 11]);
        if packet.result == 0 {
            match operation {
                Operation::Probe => fields |= bits(&[12, 13]),
                Operation::Publish | Operation::Adopt | Operation::InspectBody => {
                    fields |= bits(&[9, 12, 13])
                }
                Operation::Inventory => fields |= bits(&[14, 15]),
                Operation::InspectPending => fields |= bits(&[9]),
                _ => {}
            }
        }
    } else {
        fields |= bits(&[6]);
        match operation {
            Operation::Publish | Operation::Adopt | Operation::InspectBody => {
                fields |= bits(&[7, 8])
            }
            Operation::Retire
            | Operation::Restore
            | Operation::FinishRetirement
            | Operation::Quarantine => fields |= bits(&[8, 9]),
            Operation::Inventory => fields |= bits(&[14]),
            Operation::InspectPending => fields |= bits(&[8]),
            Operation::InspectQuarantine => fields |= bits(&[8, 9]),
            _ => {}
        }
    }
    Ok(fields)
}

fn bits(tags: &[u32]) -> u32 {
    tags.iter().fold(0, |mask, tag| mask | 1 << tag)
}

#[derive(Clone, Copy)]
enum Shape {
    Packet,
    Claim,
    Body,
}

fn preflight(mut input: &[u8], shape: Shape) -> Result<u32, Error> {
    let original = input;
    let mut seen = 0u32;
    while !input.is_empty() {
        let tag = varint(&mut input)?;
        let field = tag >> 3;
        let wire = tag & 7;
        let expected = match shape {
            Shape::Packet => match field {
                1..=3 | 6 | 10..=12 => 0,
                4..=5 | 7..=9 | 13..=15 => 2,
                _ => return Err(Error::Invalid("unknown packet field")),
            },
            Shape::Claim => match field {
                1..=2 | 6 => 2,
                3..=5 => 0,
                _ => return Err(Error::Invalid("unknown claim field")),
            },
            Shape::Body => match field {
                1 | 3 => 0,
                2 | 4 => 2,
                _ => return Err(Error::Invalid("unknown body field")),
            },
        };
        let bit = 1u32 << field;
        let repeated = matches!(shape, Shape::Packet) && field == 15;
        if wire != expected || seen & bit != 0 && !repeated {
            return Err(Error::Invalid("protobuf field shape"));
        }
        seen |= bit;
        if wire == 0 {
            let value = varint(&mut input)?;
            if (matches!(shape, Shape::Packet) && matches!(field, 1 | 3 | 11 | 12)
                || matches!(shape, Shape::Body) && matches!(field, 1 | 3))
                && value > u64::from(u32::MAX)
            {
                return Err(Error::Invalid("overflowing uint32"));
            }
            if matches!(shape, Shape::Packet) && field == 10 && value > 1 {
                return Err(Error::Invalid("boolean encoding"));
            }
        } else {
            let length = usize::try_from(varint(&mut input)?)
                .map_err(|_| Error::Invalid("protobuf length"))?;
            let value = input
                .get(..length)
                .ok_or(Error::Invalid("truncated protobuf field"))?;
            input = &input[length..];
            match (shape, field) {
                (Shape::Packet, 7) => {
                    preflight(value, Shape::Claim)?;
                }
                (Shape::Packet, 8 | 15) => {
                    preflight(value, Shape::Body)?;
                }
                _ => {}
            }
        }
    }
    if matches!(shape, Shape::Body) {
        let key = BodyKey::decode(original).map_err(Error::Protobuf)?;
        let allowed = match BodyKind::try_from(key.kind).map_err(|_| Error::Invalid("body kind"))? {
            BodyKind::Sealed => bits(&[1, 2]),
            BodyKind::Chunk => bits(&[1, 2, 3]),
            BodyKind::Pack => bits(&[1, 4]),
            BodyKind::Unspecified => return Err(Error::Invalid("body kind")),
        };
        if seen & !allowed != 0 {
            return Err(Error::Invalid("unexpected body key field"));
        }
    }
    Ok(seen)
}

fn varint(input: &mut &[u8]) -> Result<u64, Error> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or(Error::Invalid("truncated varint"))?;
        *input = rest;
        if shift == 63 && byte > 1 {
            return Err(Error::Invalid("overflowing varint"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(Error::Invalid("overflowing varint"))
}
