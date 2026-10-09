//! Bounded schema-aware preflight runs before Protobuf allocates decoded fields.

use crate::ProtocolError;

const MAX_FIELDS: usize = 8192;
const MAX_DEPTH: usize = 32;

#[derive(Clone, Copy)]
enum MessageKind {
    WorkerEnvelope,
    Version,
    Hello,
    WireLimits,
    Capabilities,
    Prepare,
    Prepared,
    Solve,
    SolveOptions,
    Progress,
    ValidationBinding,
    Candidate,
    Finished,
    SearchEvidence,
    StageTiming,
    Release,
    Released,
    Cancel,
    ProtocolError,
}

struct Field {
    number: u32,
    wire: u8,
    nested: Option<MessageKind>,
    repeated: bool,
    packed: bool,
}

fn fields(kind: MessageKind) -> &'static [Field] {
    match kind {
        MessageKind::WorkerEnvelope => &[
            Field {
                number: 1,
                wire: 2,
                nested: Some(MessageKind::Version),
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 10,
                wire: 2,
                nested: Some(MessageKind::Hello),
                repeated: false,
                packed: false,
            },
            Field {
                number: 11,
                wire: 2,
                nested: Some(MessageKind::Capabilities),
                repeated: false,
                packed: false,
            },
            Field {
                number: 12,
                wire: 2,
                nested: Some(MessageKind::Prepare),
                repeated: false,
                packed: false,
            },
            Field {
                number: 13,
                wire: 2,
                nested: Some(MessageKind::Prepared),
                repeated: false,
                packed: false,
            },
            Field {
                number: 14,
                wire: 2,
                nested: Some(MessageKind::Solve),
                repeated: false,
                packed: false,
            },
            Field {
                number: 15,
                wire: 2,
                nested: Some(MessageKind::Progress),
                repeated: false,
                packed: false,
            },
            Field {
                number: 16,
                wire: 2,
                nested: Some(MessageKind::Candidate),
                repeated: false,
                packed: false,
            },
            Field {
                number: 17,
                wire: 2,
                nested: Some(MessageKind::Finished),
                repeated: false,
                packed: false,
            },
            Field {
                number: 18,
                wire: 2,
                nested: Some(MessageKind::Release),
                repeated: false,
                packed: false,
            },
            Field {
                number: 19,
                wire: 2,
                nested: Some(MessageKind::Released),
                repeated: false,
                packed: false,
            },
            Field {
                number: 20,
                wire: 2,
                nested: Some(MessageKind::ProtocolError),
                repeated: false,
                packed: false,
            },
            Field {
                number: 21,
                wire: 2,
                nested: Some(MessageKind::Cancel),
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Version => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Hello => &[
            Field {
                number: 1,
                wire: 2,
                nested: Some(MessageKind::Version),
                repeated: true,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: Some(MessageKind::Version),
                repeated: true,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: Some(MessageKind::WireLimits),
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: None,
                repeated: true,
                packed: false,
            },
        ],
        MessageKind::WireLimits => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 6,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 7,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 8,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 9,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 10,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 11,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 12,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 13,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 14,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 15,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 16,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Capabilities => &[
            Field {
                number: 1,
                wire: 2,
                nested: Some(MessageKind::Version),
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: Some(MessageKind::Version),
                repeated: true,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: Some(MessageKind::WireLimits),
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 6,
                wire: 2,
                nested: None,
                repeated: true,
                packed: false,
            },
            Field {
                number: 7,
                wire: 2,
                nested: None,
                repeated: true,
                packed: false,
            },
            Field {
                number: 8,
                wire: 2,
                nested: None,
                repeated: true,
                packed: false,
            },
            Field {
                number: 9,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 10,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 11,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 12,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 13,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 14,
                wire: 2,
                nested: None,
                repeated: true,
                packed: true,
            },
            Field {
                number: 15,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 16,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Prepare => &[
            Field {
                number: 1,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Prepared => &[
            Field {
                number: 1,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Solve => &[
            Field {
                number: 1,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 6,
                wire: 2,
                nested: Some(MessageKind::SolveOptions),
                repeated: false,
                packed: false,
            },
            Field {
                number: 7,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::SolveOptions => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 6,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 7,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Progress => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: Some(MessageKind::ValidationBinding),
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::ValidationBinding => &[
            Field {
                number: 1,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Candidate => &[
            Field {
                number: 1,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Finished => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: Some(MessageKind::SearchEvidence),
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 6,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 7,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 8,
                wire: 2,
                nested: Some(MessageKind::SolveOptions),
                repeated: false,
                packed: false,
            },
            Field {
                number: 9,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 10,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 11,
                wire: 2,
                nested: Some(MessageKind::StageTiming),
                repeated: true,
                packed: false,
            },
            Field {
                number: 12,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 13,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 14,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 15,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::SearchEvidence => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 4,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 5,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::StageTiming => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
        ],
        MessageKind::Release => &[Field {
            number: 1,
            wire: 2,
            nested: None,
            repeated: false,
            packed: false,
        }],
        MessageKind::Released => &[Field {
            number: 1,
            wire: 2,
            nested: None,
            repeated: false,
            packed: false,
        }],
        MessageKind::Cancel => &[Field {
            number: 1,
            wire: 0,
            nested: None,
            repeated: false,
            packed: false,
        }],
        MessageKind::ProtocolError => &[
            Field {
                number: 1,
                wire: 0,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 2,
                wire: 2,
                nested: None,
                repeated: false,
                packed: false,
            },
            Field {
                number: 3,
                wire: 2,
                nested: None,
                repeated: true,
                packed: false,
            },
        ],
    }
}

pub(crate) fn preflight(payload: &[u8]) -> Result<(), ProtocolError> {
    let mut count = 0;
    scan(payload, MessageKind::WorkerEnvelope, 0, &mut count)
}

fn scan(
    payload: &[u8],
    kind: MessageKind,
    depth: usize,
    count: &mut usize,
) -> Result<(), ProtocolError> {
    if depth > MAX_DEPTH {
        return invalid("Protobuf nesting bound exceeded");
    }
    let mut offset = 0;
    let mut seen = 0_u64;
    let mut has_body = false;
    while offset < payload.len() {
        bump(count)?;
        let key = varint(payload, &mut offset)?;
        let number = u32::try_from(key >> 3).map_err(|_| ProtocolError::NonCanonicalProtobuf)?;
        let wire = (key & 7) as u8;
        let field = fields(kind)
            .iter()
            .find(|field| field.number == number)
            .ok_or(ProtocolError::NonCanonicalProtobuf)?;
        if field.wire != wire || (!field.repeated && (seen & (1_u64 << number)) != 0) {
            return Err(ProtocolError::NonCanonicalProtobuf);
        }
        seen |= 1_u64 << number;
        if matches!(kind, MessageKind::WorkerEnvelope) && (10..=21).contains(&number) {
            if has_body {
                return Err(ProtocolError::NonCanonicalProtobuf);
            }
            has_body = true;
        }
        if wire == 0 {
            varint(payload, &mut offset)?;
            continue;
        }
        let size = usize::try_from(varint(payload, &mut offset)?)
            .map_err(|_| ProtocolError::NonCanonicalProtobuf)?;
        let end = offset
            .checked_add(size)
            .ok_or(ProtocolError::NonCanonicalProtobuf)?;
        let bytes = payload
            .get(offset..end)
            .ok_or(ProtocolError::NonCanonicalProtobuf)?;
        if let Some(nested) = field.nested {
            scan(bytes, nested, depth + 1, count)?;
        } else if field.packed {
            let mut position = 0;
            while position < bytes.len() {
                bump(count)?;
                varint(bytes, &mut position)?;
            }
        }
        offset = end;
    }
    Ok(())
}

fn bump(count: &mut usize) -> Result<(), ProtocolError> {
    *count += 1;
    if *count > MAX_FIELDS {
        return invalid("Protobuf field-count bound exceeded");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidMessage(message.into()))
}

fn varint(bytes: &[u8], offset: &mut usize) -> Result<u64, ProtocolError> {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = *bytes
            .get(*offset)
            .ok_or(ProtocolError::NonCanonicalProtobuf)?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return Err(ProtocolError::NonCanonicalProtobuf);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            if index > 0 && byte == 0 {
                return Err(ProtocolError::NonCanonicalProtobuf);
            }
            return Ok(value);
        }
    }
    Err(ProtocolError::NonCanonicalProtobuf)
}
