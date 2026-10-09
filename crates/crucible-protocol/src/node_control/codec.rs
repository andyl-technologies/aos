//! Bounded fixed-endian encoding independent of legacy ControlV3 framing.

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};

use super::{
    BoundaryPolicy, ExecutionCommand, ExecutionKind, NODE_CONTROL_HEADER_BYTES,
    NODE_CONTROL_MAX_BODY_BYTES, NODE_CONTROL_VERSION, NativeCommandError, OwnerScope,
};

pub(super) const MAGIC: &[u8; 8] = b"CNQEMU01";

/// Encodes a locally valid original native command with explicit version framing.
///
/// # Errors
/// Rejects invalid local schemas or a body beyond the finite wire allowance.
pub fn encode_command(command: &ExecutionCommand) -> Result<Vec<u8>, NativeCommandError> {
    command.validate()?;
    let mut body = Vec::new();
    integer(&mut body, command.sequence.get());
    scope(&mut body, &command.scope)?;
    for value in [
        &command.operation,
        &command.grant,
        &command.input_epoch,
        &command.input_batch,
    ] {
        identifier(&mut body, value);
    }
    hash(&mut body, &command.input_batch_hash)?;
    position(&mut body, command.closed_input_prefix);
    body.extend_from_slice(&command.authorization_digest);
    position(&mut body, command.kind.start());
    position(&mut body, command.kind.limit());
    body.push(match command.kind {
        ExecutionKind::ExactRun {
            boundary_policy: BoundaryPolicy::HorizonPark,
            ..
        }
        | ExecutionKind::BoundarySettle { .. } => 0,
        ExecutionKind::ExactRun {
            boundary_policy: BoundaryPolicy::InputBlockedPark,
            ..
        } => 1,
    });
    if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }

    let mut frame = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&NODE_CONTROL_VERSION.to_be_bytes());
    let kind: u16 = match command.kind {
        ExecutionKind::ExactRun { .. } => 1,
        ExecutionKind::BoundarySettle { .. } => 2,
    };
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes exactly one bounded closed native command without granting authority.
///
/// The decoder rejects unknown versions, kinds, policy values, phases, trailing
/// bytes and oversized declared bodies before copying variable-size identifiers.
///
/// # Errors
/// Rejects malformed framing, unsupported versions and invalid local schemas.
pub fn decode_command(frame: &[u8]) -> Result<ExecutionCommand, NativeCommandError> {
    let mut cursor = Cursor(frame);
    if cursor.take(8)? != MAGIC {
        return Err(NativeCommandError::Invalid("wrong native command magic"));
    }
    let version = cursor.u16()?;
    if version != NODE_CONTROL_VERSION {
        return Err(NativeCommandError::UnsupportedVersion(version));
    }
    let kind = cursor.u16()?;
    if !matches!(kind, 1 | 2) {
        return Err(NativeCommandError::Invalid("unknown native command kind"));
    }
    let body_length = cursor.u32()? as usize;
    if body_length > NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    if cursor.0.len() != body_length {
        return Err(NativeCommandError::Invalid(
            "native command length mismatch",
        ));
    }
    let sequence = U64::new(cursor.u64()?);
    let scope = cursor.scope()?;
    let operation = cursor.id()?;
    let grant = cursor.id()?;
    let input_epoch = cursor.id()?;
    let input_batch = cursor.id()?;
    let input_batch_hash = cursor.hash("cnp.input-batch.v1")?;
    let closed_input_prefix = cursor.position()?;
    let authorization_digest = cursor.array()?;
    let start = cursor.position()?;
    let limit = cursor.position()?;
    let policy = cursor.u8()?;
    let kind = match (kind, policy) {
        (1, 0) => ExecutionKind::ExactRun {
            start,
            limit,
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
        (1, 1) => ExecutionKind::ExactRun {
            start,
            limit,
            boundary_policy: BoundaryPolicy::InputBlockedPark,
        },
        (2, 0) => ExecutionKind::BoundarySettle { start, limit },
        _ => {
            return Err(NativeCommandError::Invalid(
                "unknown native boundary policy",
            ));
        }
    };
    if !cursor.0.is_empty() {
        return Err(NativeCommandError::Invalid("trailing native command data"));
    }
    let command = ExecutionCommand {
        sequence,
        scope,
        operation,
        grant,
        input_epoch,
        input_batch,
        input_batch_hash,
        closed_input_prefix,
        authorization_digest,
        kind,
    };
    command.validate()?;
    Ok(command)
}

pub(super) fn scope(body: &mut Vec<u8>, scope: &OwnerScope) -> Result<(), NativeCommandError> {
    for value in [
        &scope.session,
        &scope.incarnation,
        &scope.activation,
        &scope.node,
        &scope.owner,
    ] {
        identifier(body, value);
    }
    integer(body, scope.world_generation.get());
    integer(body, scope.owner_generation.get());
    hash(body, &scope.world_binding)?;
    hash(body, &scope.owner_binding)?;
    Ok(())
}

fn identifier(body: &mut Vec<u8>, value: &Id) {
    body.extend_from_slice(&(value.as_str().len() as u16).to_be_bytes());
    body.extend_from_slice(value.as_str().as_bytes());
}

pub(super) fn integer(body: &mut Vec<u8>, value: u64) {
    body.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn position(body: &mut Vec<u8>, value: Position) {
    integer(body, value.time_ps.get());
    integer(body, value.microstep.get());
    body.extend_from_slice(&(value.phase as u16).to_be_bytes());
}

fn hash(body: &mut Vec<u8>, value: &HashRef) -> Result<(), NativeCommandError> {
    let bytes = value.digest.as_bytes();
    if bytes.len() != 64 {
        return Err(NativeCommandError::Invalid("invalid native digest length"));
    }
    for pair in bytes.as_chunks::<2>().0 {
        body.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(())
}

fn nibble(value: u8) -> Result<u8, NativeCommandError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(NativeCommandError::Invalid(
            "native digest is not canonical lowercase hex",
        )),
    }
}

pub(super) struct Cursor<'a>(pub(super) &'a [u8]);

impl<'a> Cursor<'a> {
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], NativeCommandError> {
        if self.0.len() < length {
            return Err(NativeCommandError::Invalid("truncated native command"));
        }
        let (result, remaining) = self.0.split_at(length);
        self.0 = remaining;
        Ok(result)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeCommandError> {
        self.take(N)?
            .try_into()
            .map_err(|_| NativeCommandError::Invalid("truncated fixed field"))
    }

    pub(super) fn u8(&mut self) -> Result<u8, NativeCommandError> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, NativeCommandError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, NativeCommandError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, NativeCommandError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn scope(&mut self) -> Result<OwnerScope, NativeCommandError> {
        let scope = OwnerScope {
            session: self.id()?,
            incarnation: self.id()?,
            activation: self.id()?,
            node: self.id()?,
            owner: self.id()?,
            world_generation: U64::new(self.u64()?),
            owner_generation: U64::new(self.u64()?),
            world_binding: self.hash("cnp.world-binding.v1")?,
            owner_binding: self.hash("cnp.owner-binding.v1")?,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn id(&mut self) -> Result<Id, NativeCommandError> {
        let length = self.u16()? as usize;
        if length > 128 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| NativeCommandError::Invalid("native identity is not ASCII"))?;
        Id::new(text).map_err(|_| NativeCommandError::Invalid("invalid native identity"))
    }

    pub(super) fn position(&mut self) -> Result<Position, NativeCommandError> {
        let time_ps = U64::new(self.u64()?);
        let microstep = U64::new(self.u64()?);
        let phase = match self.u16()? {
            0 => Phase::BoundaryControl,
            1 => Phase::Publication,
            2 => Phase::Delivery,
            3 => Phase::Reaction,
            _ => return Err(NativeCommandError::Invalid("unknown native phase")),
        };
        Ok(Position {
            time_ps,
            microstep,
            phase,
        })
    }

    fn hash(&mut self, domain: &str) -> Result<HashRef, NativeCommandError> {
        use std::fmt::Write;
        let bytes: [u8; 32] = self.array()?;
        let mut digest = String::with_capacity(64);
        for byte in bytes {
            write!(&mut digest, "{byte:02x}")
                .map_err(|_| NativeCommandError::Invalid("digest formatting failed"))?;
        }
        Ok(HashRef {
            algorithm: "blake3-256".into(),
            domain: domain.into(),
            digest,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
