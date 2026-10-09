//! Closed native command, stop-fact and acknowledgement frame codecs.

use crucible_node_contract::U64;

use super::codec::{Cursor, MAGIC, integer, position};
use super::{
    NODE_CONTROL_HEADER_BYTES, NODE_CONTROL_MAX_BODY_BYTES, NODE_CONTROL_VERSION,
    NativeCommandError, NativeCpuParkFacts, NativeFrame, NativePreparation, NativeStopFacts,
    NativeStopKind, ReceiptAcknowledgement,
};

/// Encodes one bounded independently versioned native channel frame.
///
/// # Errors
/// Rejects invalid local records, zero sequences or exhausted byte allowances.
pub fn encode_frame(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    let (kind, body) = match frame {
        NativeFrame::QueryWriters(_)
        | NativeFrame::WriterChunk(_)
        | NativeFrame::SourceFault(_) => {
            return Err(NativeCommandError::UnsupportedVersion(2));
        }
        NativeFrame::QueryTimers(query) => {
            if query.prepared_scope_hash == [0; 32]
                || query.offset.get() >= super::NATIVE_TIMER_OBJECT_MAX_BYTES as u64
            {
                return Err(NativeCommandError::ResourceLimit);
            }
            let mut body = query.prepared_scope_hash.to_vec();
            integer(&mut body, query.sequence.get());
            integer(&mut body, query.offset.get());
            (9, body)
        }
        NativeFrame::TimerChunk(chunk) => {
            chunk.validate()?;
            let mut body = chunk.prepared_scope_hash.to_vec();
            integer(&mut body, chunk.sequence.get());
            body.extend_from_slice(&chunk.object_digest);
            integer(&mut body, chunk.total_bytes.get());
            integer(&mut body, chunk.offset.get());
            body.extend_from_slice(&chunk.bytes);
            (10, body)
        }
        NativeFrame::CpuPark(facts) => {
            facts.validate()?;
            let mut body = Vec::new();
            body.extend_from_slice(&facts.coverage.to_be_bytes());
            body.extend_from_slice(&facts.cpu_count.to_be_bytes());
            integer(&mut body, facts.current_ps.get());
            integer(&mut body, facts.retired_count.get());
            integer(
                &mut body,
                facts.next_service_deadline_ps.map_or(u64::MAX, U64::get),
            );
            integer(&mut body, facts.pending_service_credit_ps.get());
            body.extend_from_slice(&facts.prepared_scope_hash);
            body.extend_from_slice(&facts.roster_sha256);
            (7, body)
        }
        NativeFrame::QueryCpuPark(scope) => {
            if *scope == [0; 32] {
                return Err(NativeCommandError::Invalid(
                    "native CPU park scope must be pinned",
                ));
            }
            (8, scope.to_vec())
        }
        NativeFrame::Prepare(plan) => {
            plan.validate()?;
            let mut body = Vec::new();
            super::codec::scope(&mut body, &plan.scope)?;
            position(&mut body, plan.boundary);
            integer(&mut body, plan.maximum_commands.get());
            (5u16, body)
        }
        NativeFrame::Command(command) => return super::encode_command(command),
        NativeFrame::Stopped(facts) => {
            facts.validate()?;
            let mut body = Vec::new();
            integer(&mut body, facts.sequence.get());
            body.extend_from_slice(&facts.command_digest);
            body.extend_from_slice(&(facts.kind as u16).to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&facts.pending_classes.to_be_bytes());
            position(&mut body, facts.reached);
            integer(&mut body, facts.retired_count.get());
            integer(
                &mut body,
                facts.next_native_deadline_ps.map_or(u64::MAX, U64::get),
            );
            integer(
                &mut body,
                facts.next_service_deadline_ps.map_or(u64::MAX, U64::get),
            );
            integer(&mut body, facts.pending_service_credit_ps.get());
            (3u16, body)
        }
        NativeFrame::Acknowledge(ack) | NativeFrame::Acknowledged(ack) => {
            if ack.sequence.get() == 0 {
                return Err(NativeCommandError::Invalid(
                    "native acknowledgement sequence must be positive",
                ));
            }
            let mut body = Vec::new();
            integer(&mut body, ack.sequence.get());
            body.extend_from_slice(&ack.command_digest);
            body.extend_from_slice(&ack.authorization_digest);
            (
                if matches!(frame, NativeFrame::Acknowledged(_)) {
                    6
                } else {
                    4
                },
                body,
            )
        }
    };
    if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    let mut encoded = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&NODE_CONTROL_VERSION.to_be_bytes());
    encoded.extend_from_slice(&kind.to_be_bytes());
    encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

/// Decodes exactly one closed native frame without authenticating live authority.
///
/// # Errors
/// Rejects malformed or oversized frames, unsupported versions and unknown kinds,
/// phases, stop dispositions, reserved values or trailing bytes.
pub fn decode_frame(encoded: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(encoded);
    if cursor.take(8)? != MAGIC {
        return Err(NativeCommandError::Invalid("wrong native command magic"));
    }
    let version = cursor.u16()?;
    if version != NODE_CONTROL_VERSION {
        return Err(NativeCommandError::UnsupportedVersion(version));
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    if cursor.0.len() != length {
        return Err(NativeCommandError::Invalid("native frame length mismatch"));
    }
    let frame = match kind {
        9 => {
            let query = super::NativeTimerQuery {
                prepared_scope_hash: cursor.array()?,
                sequence: U64::new(cursor.u64()?),
                offset: U64::new(cursor.u64()?),
            };
            if query.prepared_scope_hash == [0; 32]
                || query.offset.get() >= super::NATIVE_TIMER_OBJECT_MAX_BYTES as u64
            {
                return Err(NativeCommandError::ResourceLimit);
            }
            NativeFrame::QueryTimers(query)
        }
        10 => {
            let prepared_scope_hash = cursor.array()?;
            let sequence = U64::new(cursor.u64()?);
            let object_digest = cursor.array()?;
            let total_bytes = U64::new(cursor.u64()?);
            let offset = U64::new(cursor.u64()?);
            let bytes = cursor.take(cursor.0.len())?.to_vec();
            let chunk = super::NativeTimerChunk {
                prepared_scope_hash,
                sequence,
                object_digest,
                total_bytes,
                offset,
                bytes,
            };
            chunk.validate()?;
            NativeFrame::TimerChunk(chunk)
        }
        7 => {
            let facts = NativeCpuParkFacts {
                coverage: cursor.u32()?,
                cpu_count: cursor.u32()?,
                current_ps: U64::new(cursor.u64()?),
                retired_count: U64::new(cursor.u64()?),
                next_service_deadline_ps: deadline(cursor.u64()?),
                pending_service_credit_ps: U64::new(cursor.u64()?),
                prepared_scope_hash: cursor.array()?,
                roster_sha256: cursor.array()?,
            };
            facts.validate()?;
            NativeFrame::CpuPark(facts)
        }
        8 => {
            let scope = cursor.array()?;
            if scope == [0; 32] {
                return Err(NativeCommandError::Invalid(
                    "native CPU park scope must be pinned",
                ));
            }
            NativeFrame::QueryCpuPark(scope)
        }
        1 | 2 => {
            return super::decode_command(encoded)
                .map(|command| NativeFrame::Command(Box::new(command)));
        }
        3 => {
            let sequence = U64::new(cursor.u64()?);
            let command_digest = cursor.array()?;
            let kind = match cursor.u16()? {
                1 => NativeStopKind::HorizonPark,
                2 => NativeStopKind::NativeBoundary,
                3 => NativeStopKind::Unsupported,
                4 => NativeStopKind::Invalid,
                _ => {
                    return Err(NativeCommandError::Invalid(
                        "unknown native stop disposition",
                    ));
                }
            };
            if cursor.u16()? != 0 {
                return Err(NativeCommandError::Invalid(
                    "native reserved field must be zero",
                ));
            }
            let pending_classes = cursor.u32()?;
            let reached = cursor.position()?;
            let retired_count = U64::new(cursor.u64()?);
            let next_native_deadline_ps = deadline(cursor.u64()?);
            let next_service_deadline_ps = deadline(cursor.u64()?);
            let pending_service_credit_ps = U64::new(cursor.u64()?);
            let facts = NativeStopFacts {
                sequence,
                command_digest,
                kind,
                pending_classes,
                reached,
                retired_count,
                next_native_deadline_ps,
                next_service_deadline_ps,
                pending_service_credit_ps,
            };
            facts.validate()?;
            NativeFrame::Stopped(facts)
        }
        4 | 6 => {
            let sequence = U64::new(cursor.u64()?);
            if sequence.get() == 0 {
                return Err(NativeCommandError::Invalid(
                    "native acknowledgement sequence must be positive",
                ));
            }
            let acknowledgement = ReceiptAcknowledgement {
                sequence,
                command_digest: cursor.array()?,
                authorization_digest: cursor.array()?,
            };
            if kind == 6 {
                NativeFrame::Acknowledged(acknowledgement)
            } else {
                NativeFrame::Acknowledge(acknowledgement)
            }
        }
        5 => {
            let plan = NativePreparation {
                scope: cursor.scope()?,
                boundary: cursor.position()?,
                maximum_commands: U64::new(cursor.u64()?),
            };
            plan.validate()?;
            NativeFrame::Prepare(Box::new(plan))
        }
        _ => return Err(NativeCommandError::Invalid("unknown native frame kind")),
    };
    if !cursor.0.is_empty() {
        return Err(NativeCommandError::Invalid("trailing native frame data"));
    }
    Ok(frame)
}

fn deadline(encoded: u64) -> Option<U64> {
    (encoded != u64::MAX).then_some(U64::new(encoded))
}
