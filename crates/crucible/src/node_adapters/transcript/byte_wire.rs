//! Lossless byte strings for the explicitly selected boundary envelope edition 2.
//!
//! ```text
//! {"schema_version":2,"origin":{"context":[{"reference":{...},"bytes":"00ff"}],...},
//!  "limits":{...},"records":[{"request":{"bytes":"...",...},
//!  "response_bytes":"...","evidence":[{"reference":{...},"bytes":"..."}],...}]}
//! ```
//!
//! Only the envelope representation changes. Inner control bodies, immutable
//! content references and source context commitments retain their original bytes.
//! Every decoded body extent is charged before any decoded body allocation.

use std::{fmt, io};

use crucible_node_contract::{ContentRef, Id, Position, Repeatability, U64, Validate};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    node_contract::{NodeRoute, SavedRuntimeActivation},
    node_scheduling::InputPayload,
};

use super::{
    codec::{TranscriptError, encode, invalid},
    types::*,
};

struct Hex<'a>(&'a [u8]);

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            let pair = [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 15) as usize]];
            formatter.write_str(std::str::from_utf8(&pair).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ObjectView<'a> {
    reference: &'a ContentRef,
    bytes: Hex<'a>,
}

struct Objects<'a>(&'a [InputPayload]);

impl Serialize for Objects<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for object in self.0 {
            sequence.serialize_element(&ObjectView {
                reference: &object.reference,
                bytes: Hex(&object.bytes),
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct OriginView<'a> {
    attempt: &'a Id,
    activation: &'a SavedRuntimeActivation,
    route: &'a NodeRoute,
    source_binding: &'a ContentRef,
    context: Objects<'a>,
    repeatability: Repeatability,
}

impl<'a> From<&'a TranscriptOrigin> for OriginView<'a> {
    fn from(origin: &'a TranscriptOrigin) -> Self {
        Self {
            attempt: &origin.attempt,
            activation: &origin.activation,
            route: &origin.route,
            source_binding: &origin.source_binding,
            context: Objects(&origin.context),
            repeatability: origin.repeatability,
        }
    }
}

#[derive(Serialize)]
struct RequestView<'a> {
    action: TranscriptAction,
    identity: &'a Id,
    boundary: Position,
    content: &'a ContentRef,
    bytes: Hex<'a>,
    context: &'a ContentRef,
}

impl<'a> From<&'a TranscriptRequest> for RequestView<'a> {
    fn from(request: &'a TranscriptRequest) -> Self {
        Self {
            action: request.action,
            identity: &request.identity,
            boundary: request.boundary,
            content: &request.content,
            bytes: Hex(&request.bytes),
            context: &request.context,
        }
    }
}

#[derive(Serialize)]
struct RecordView<'a> {
    sequence: U64,
    request: RequestView<'a>,
    response: &'a ContentRef,
    response_bytes: Hex<'a>,
    evidence: Objects<'a>,
    assigned_positions: &'a [Position],
    physical_uncertainty: &'a PhysicalTimingUncertainty,
}

impl<'a> From<&'a TranscriptRecord> for RecordView<'a> {
    fn from(record: &'a TranscriptRecord) -> Self {
        Self {
            sequence: record.sequence,
            request: (&record.request).into(),
            response: &record.response,
            response_bytes: Hex(&record.response_bytes),
            evidence: Objects(&record.evidence),
            assigned_positions: &record.assigned_positions,
            physical_uncertainty: &record.physical_uncertainty,
        }
    }
}

struct Records<'a>(&'a [TranscriptRecord]);

impl Serialize for Records<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for record in self.0 {
            sequence.serialize_element(&RecordView::from(record))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct EnvelopeView<'a> {
    schema_version: u16,
    origin: OriginView<'a>,
    limits: &'a TranscriptLimits,
    records: Records<'a>,
}

struct Count {
    remaining: u64,
}

impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("transcript encoded credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_encode(value: &impl Serialize, maximum: u64) -> Result<Vec<u8>, TranscriptError> {
    // Counting borrows the complete view; no byte string/body copy precedes it.
    serde_json::to_writer(Count { remaining: maximum }, value)
        .map_err(|_| TranscriptError::CaptureLimit)?;
    encode(value)
}

pub(super) fn envelope(data: &BoundaryTranscript) -> Result<Vec<u8>, TranscriptError> {
    bounded_encode(
        &EnvelopeView {
            schema_version: 2,
            origin: (&data.origin).into(),
            limits: &data.limits,
            records: Records(&data.records),
        },
        data.limits.maximum_total_bytes.get(),
    )
}

pub(super) fn request(
    request: &TranscriptRequest,
    maximum: u64,
) -> Result<Vec<u8>, TranscriptError> {
    bounded_encode(&RequestView::from(request), maximum)
}

pub(super) fn record(record: &TranscriptRecord, maximum: u64) -> Result<Vec<u8>, TranscriptError> {
    bounded_encode(&RecordView::from(record), maximum)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObject {
    reference: ContentRef,
    bytes: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOrigin {
    attempt: Id,
    activation: SavedRuntimeActivation,
    route: NodeRoute,
    source_binding: ContentRef,
    context: Vec<RawObject>,
    repeatability: Repeatability,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    action: TranscriptAction,
    identity: Id,
    boundary: Position,
    content: ContentRef,
    bytes: String,
    context: ContentRef,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    sequence: U64,
    request: RawRequest,
    response: ContentRef,
    response_bytes: String,
    evidence: Vec<RawObject>,
    assigned_positions: Vec<Position>,
    physical_uncertainty: PhysicalTimingUncertainty,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    origin: RawOrigin,
    limits: TranscriptLimits,
    records: Vec<RawRecord>,
}

fn extent(reference: &ContentRef, text: &str, remaining: &mut u64) -> Result<(), TranscriptError> {
    reference.validate().map_err(invalid)?;
    if !text.len().is_multiple_of(2)
        || text.len() as u64 / 2 != reference.length.get()
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("noncanonical byte string or original extent"));
    }
    *remaining = remaining
        .checked_sub(reference.length.get())
        .ok_or(TranscriptError::CaptureLimit)?;
    Ok(())
}

fn body(reference: &ContentRef, text: String) -> Result<Vec<u8>, TranscriptError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(text.len() / 2)
        .map_err(|_| TranscriptError::CaptureLimit)?;
    fn digit(byte: u8) -> u8 {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    }
    for pair in text.as_bytes().as_chunks::<2>().0 {
        bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    reference.verify(&bytes).map_err(invalid)?;
    Ok(bytes)
}

fn objects(raw: Vec<RawObject>) -> Result<Vec<InputPayload>, TranscriptError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(raw.len())
        .map_err(|_| TranscriptError::CaptureLimit)?;
    for object in raw {
        let bytes = body(&object.reference, object.bytes)?;
        result.push(InputPayload {
            reference: object.reference,
            bytes,
        });
    }
    Ok(result)
}

pub(super) fn decode(value: serde_json::Value) -> Result<BoundaryTranscript, TranscriptError> {
    let raw: RawEnvelope = serde_json::from_value(value).map_err(invalid)?;
    raw.limits.validate()?;
    if raw.schema_version != 2
        || raw.records.len() as u64 > raw.limits.maximum_records.get()
        || raw.origin.context.len() > 4096
    {
        return Err(invalid("byte-string envelope edition or count"));
    }

    serde_json::to_writer(
        Count {
            remaining: raw.limits.maximum_total_bytes.get(),
        },
        &raw,
    )
    .map_err(|_| TranscriptError::CaptureLimit)?;
    let mut remaining = raw.limits.maximum_total_bytes.get();
    for object in &raw.origin.context {
        extent(&object.reference, &object.bytes, &mut remaining)?;
    }
    for record in &raw.records {
        // The complete encoded interaction (including metadata and hex expansion)
        // is bounded before any decoded bodies are materialized.
        serde_json::to_writer(
            Count {
                remaining: raw.limits.maximum_record_bytes.get(),
            },
            record,
        )
        .map_err(|_| TranscriptError::CaptureLimit)?;
        if record.evidence.len() > 4096 || record.assigned_positions.len() > 4096 {
            return Err(TranscriptError::CaptureLimit);
        }
        let before = remaining;
        extent(
            &record.request.content,
            &record.request.bytes,
            &mut remaining,
        )?;
        extent(&record.response, &record.response_bytes, &mut remaining)?;
        for object in &record.evidence {
            extent(&object.reference, &object.bytes, &mut remaining)?;
        }
        if before - remaining > raw.limits.maximum_record_bytes.get() {
            return Err(TranscriptError::CaptureLimit);
        }
    }

    // All extents and both total/interaction credits passed before the first
    // decoded body allocation. Encoded metadata remains independently bounded.
    let origin = TranscriptOrigin {
        attempt: raw.origin.attempt,
        activation: raw.origin.activation,
        route: raw.origin.route,
        source_binding: raw.origin.source_binding,
        context: objects(raw.origin.context)?,
        repeatability: raw.origin.repeatability,
    };
    let mut records = Vec::new();
    records
        .try_reserve_exact(raw.records.len())
        .map_err(|_| TranscriptError::CaptureLimit)?;
    for record in raw.records {
        let bytes = body(&record.request.content, record.request.bytes)?;
        let response_bytes = body(&record.response, record.response_bytes)?;
        records.push(TranscriptRecord {
            sequence: record.sequence,
            request: TranscriptRequest {
                action: record.request.action,
                identity: record.request.identity,
                boundary: record.request.boundary,
                content: record.request.content,
                bytes,
                context: record.request.context,
            },
            response: record.response,
            response_bytes,
            evidence: objects(record.evidence)?,
            assigned_positions: record.assigned_positions,
            physical_uncertainty: record.physical_uncertainty,
        });
    }
    Ok(BoundaryTranscript {
        schema_version: 2,
        origin,
        limits: raw.limits,
        records,
    })
}
