//! Deterministic importers for open trace interchange and packet captures.
//!
//! Importers consume caller-supplied raw bytes outside canonical execution and
//! emit [`SignalTraceChunk`] objects plus a [`SignalTraceManifest`]. No locale,
//! host clock, file metadata, floating-point number, or ambient parser setting
//! participates in normalization.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use serde_json::{Map, Value};

use crate::model::{DagStore, DagStoreError};

use super::*;

/// Stable importer semantic version shared by the initial open formats.
pub const TRACE_IMPORTER_VERSION: u16 = 1;
/// Hard maximum raw bytes accepted by one in-memory importer call.
pub const HARD_TRACE_IMPORT_BYTES: usize = 1_099_511_627_776;

/// Closed input format handled by the generic importer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceImportFormat {
    /// RFC-4180-style UTF-8 CSV with the canonical columns.
    Csv,
    /// One closed JSON object per UTF-8 line.
    JsonLines,
    /// Classic libpcap capture.
    Pcap,
    /// PCAP Next Generation capture.
    PcapNg,
}

impl TraceImportFormat {
    fn importer_id(self) -> &'static str {
        match self {
            Self::Csv => "trace-csv-v1",
            Self::JsonLines => "trace-jsonl-v1",
            Self::Pcap => "trace-pcap-v1",
            Self::PcapNg => "trace-pcapng-v1",
        }
    }
}

/// Explicit normalization choices for one imported channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceImportOptions {
    /// Output channel identity.
    pub channel: SignalId,
    /// Exact output shape.
    pub shape: SignalShape,
    /// Whether equal-coordinate sequenced events are accepted.
    pub event_channel: bool,
    /// Source coordinate basis retained in the manifest.
    pub time_basis: TraceTimeBasis,
    /// Exact source-to-virtual mapping.
    pub time_mapping: NormalizedTraceTimeMapping,
    /// Stable source-device alias.
    pub source_alias: FaultObjectId,
    /// Privacy-policy digest.
    pub privacy_policy: ContentHash,
    /// Optional local coordinate frame.
    pub coordinate_frame: Option<TraceCoordinateFrame>,
    /// Optional deterministic redaction transform.
    pub redaction: Option<SpatialRedaction>,
}

/// Complete normalized output and independently stored chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedSignalTrace {
    /// Canonical manifest.
    pub manifest: SignalTraceManifest,
    /// Canonical chunks in manifest order.
    pub chunks: Vec<SignalTraceChunk>,
}

/// Persists raw provenance, canonical chunks, and the manifest atomically by
/// content identity from the caller's perspective.
///
/// # Errors
///
/// Returns [`TraceArtifactStoreError`] when raw provenance differs, a canonical
/// object has stale identity, or the backing store rejects an object.
pub fn store_imported_signal_trace(
    store: &dyn DagStore,
    raw_bytes: &[u8],
    imported: &ImportedSignalTrace,
) -> Result<ContentHash, TraceArtifactStoreError> {
    let raw = ContentHash::from_bytes(raw_bytes);
    if imported.manifest.provenance.raw_content != Some(raw) {
        return Err(TraceArtifactStoreError::RawProvenanceMismatch);
    }
    let stored_raw = store
        .put(raw_bytes)
        .map_err(TraceArtifactStoreError::Store)?;
    if stored_raw != raw {
        return Err(TraceArtifactStoreError::ContentMismatch);
    }
    for chunk in &imported.chunks {
        let bytes = chunk.encode();
        if ContentHash::from_bytes(&bytes) != chunk.content
            || store.put(&bytes).map_err(TraceArtifactStoreError::Store)? != chunk.content
        {
            return Err(TraceArtifactStoreError::ContentMismatch);
        }
    }
    let bytes = imported.manifest.encode();
    if ContentHash::from_bytes(&bytes) != imported.manifest.content
        || store.put(&bytes).map_err(TraceArtifactStoreError::Store)? != imported.manifest.content
    {
        return Err(TraceArtifactStoreError::ContentMismatch);
    }
    Ok(imported.manifest.content)
}

/// Loads a complete canonical trace and verifies every dependency reference.
///
/// # Errors
///
/// Returns [`TraceArtifactStoreError`] when any object is absent, corrupt,
/// malformed, or inconsistent with the manifest.
pub fn load_stored_signal_trace(
    store: &dyn DagStore,
    manifest_content: ContentHash,
) -> Result<ImportedSignalTrace, TraceArtifactStoreError> {
    let manifest_bytes = store
        .get(&manifest_content)
        .map_err(TraceArtifactStoreError::Store)?;
    if ContentHash::from_bytes(&manifest_bytes) != manifest_content {
        return Err(TraceArtifactStoreError::ContentMismatch);
    }
    let manifest =
        SignalTraceManifest::decode(&manifest_bytes).map_err(TraceArtifactStoreError::Trace)?;
    let mut chunks = Vec::new();
    for channel in &manifest.channels {
        for reference in &channel.chunks {
            let bytes = store
                .get(&reference.content)
                .map_err(TraceArtifactStoreError::Store)?;
            if ContentHash::from_bytes(&bytes) != reference.content {
                return Err(TraceArtifactStoreError::ContentMismatch);
            }
            let chunk = SignalTraceChunk::decode(&bytes).map_err(TraceArtifactStoreError::Trace)?;
            if chunk.channel != channel.id
                || chunk.event_channel != channel.event_channel
                || chunk.reference() != *reference
            {
                return Err(TraceArtifactStoreError::ReferenceMismatch);
            }
            chunks.push(chunk);
        }
    }
    if let Some(raw) = manifest.provenance.raw_content {
        let bytes = store.get(&raw).map_err(TraceArtifactStoreError::Store)?;
        if ContentHash::from_bytes(&bytes) != raw {
            return Err(TraceArtifactStoreError::ContentMismatch);
        }
    }
    Ok(ImportedSignalTrace { manifest, chunks })
}

/// Imports one raw byte stream into a canonical one-channel artifact.
///
/// # Errors
///
/// Returns [`TraceImportError`] for oversized, malformed, ambiguous, unknown,
/// non-integer, out-of-order, shape-incompatible, or unmappable input.
pub fn import_signal_trace(
    format: TraceImportFormat,
    bytes: &[u8],
    options: TraceImportOptions,
) -> Result<ImportedSignalTrace, TraceImportError> {
    if bytes.len() > HARD_TRACE_IMPORT_BYTES {
        return Err(TraceImportError::InputLimit);
    }
    let raw_hash = ContentHash::from_bytes(bytes);
    let entries = match format {
        TraceImportFormat::Csv => import_csv_entries(bytes, &options)?,
        TraceImportFormat::JsonLines => import_jsonl_entries(bytes, &options)?,
        TraceImportFormat::Pcap => import_pcap_entries(bytes, &options)?,
        TraceImportFormat::PcapNg => import_pcapng_entries(bytes, &options)?,
    };
    build_import(format, raw_hash, entries, options)
}

fn build_import(
    format: TraceImportFormat,
    raw_hash: ContentHash,
    mut entries: Vec<TraceEntry>,
    options: TraceImportOptions,
) -> Result<ImportedSignalTrace, TraceImportError> {
    if entries.is_empty() {
        return Err(TraceImportError::NoEntries);
    }
    if matches!(format, TraceImportFormat::Pcap | TraceImportFormat::PcapNg)
        && options.time_basis != TraceTimeBasis::Nanoseconds
    {
        return Err(TraceImportError::PacketCaptureContract);
    }
    if let Some(redaction) = options.redaction {
        apply_spatial_redaction(&mut entries, &options.shape, redaction)?;
    }
    let mut chunks = Vec::new();
    for entries in entries.chunks(TRACE_ENTRIES_PER_CHUNK) {
        chunks.push(
            SignalTraceChunk::new(
                TRACE_CODEC_VERSION,
                options.channel.clone(),
                options.event_channel,
                entries.to_vec(),
            )
            .map_err(TraceImportError::Trace)?,
        );
    }
    let channel = TraceChannel {
        id: options.channel.clone(),
        shape: options.shape.clone(),
        event_channel: options.event_channel,
        chunks: chunks.iter().map(SignalTraceChunk::reference).collect(),
    };
    let importer =
        FaultObjectId::parse(format.importer_id()).map_err(TraceImportError::Contract)?;
    let options_hash = import_options_hash(format, &options, &channel);
    let manifest = SignalTraceManifest::new(
        TRACE_CODEC_VERSION,
        options.time_basis,
        options.time_mapping,
        options.coordinate_frame,
        options.redaction,
        vec![channel],
        TraceProvenance {
            raw_content: Some(raw_hash),
            raw_omission_reason: None,
            importer,
            importer_version: TRACE_IMPORTER_VERSION,
            options: options_hash,
            source_alias: options.source_alias,
            privacy_policy: options.privacy_policy,
        },
    )
    .map_err(TraceImportError::Trace)?;
    Ok(ImportedSignalTrace { manifest, chunks })
}

fn apply_spatial_redaction(
    entries: &mut [TraceEntry],
    shape: &SignalShape,
    redaction: SpatialRedaction,
) -> Result<(), TraceImportError> {
    if shape.unit != SignalUnit::Millimetres {
        return Err(TraceImportError::RedactionShape);
    }
    for entry in entries {
        entry.value = match &entry.value {
            SignalValue::Vector2(values) if values.len() == 2 => {
                let [x, y] = vector_i64_2(values)?;
                let [x, y, _] = redaction
                    .apply([x, y, 0])
                    .map_err(TraceImportError::Trace)?;
                SignalValue::Vector2(vec![SignalValue::I64(x), SignalValue::I64(y)])
            }
            SignalValue::Vector3(values) if values.len() == 3 => {
                let [x, y, z] = vector_i64_3(values)?;
                let [x, y, z] = redaction
                    .apply([x, y, z])
                    .map_err(TraceImportError::Trace)?;
                SignalValue::Vector3(vec![
                    SignalValue::I64(x),
                    SignalValue::I64(y),
                    SignalValue::I64(z),
                ])
            }
            _ => return Err(TraceImportError::RedactionShape),
        };
    }
    Ok(())
}

fn vector_i64_2(values: &[SignalValue]) -> Result<[i64; 2], TraceImportError> {
    match values {
        [SignalValue::I64(x), SignalValue::I64(y)] => Ok([*x, *y]),
        _ => Err(TraceImportError::RedactionShape),
    }
}

fn vector_i64_3(values: &[SignalValue]) -> Result<[i64; 3], TraceImportError> {
    match values {
        [
            SignalValue::I64(x),
            SignalValue::I64(y),
            SignalValue::I64(z),
        ] => Ok([*x, *y, *z]),
        _ => Err(TraceImportError::RedactionShape),
    }
}

fn import_options_hash(
    format: TraceImportFormat,
    options: &TraceImportOptions,
    channel: &TraceChannel,
) -> ContentHash {
    let material = format!(
        "format={format:?};channel={};type={:?};unit={:?};scale={};event={};basis={:?};mapping={:?};chunks={};frame={:?};redaction={:?};privacy={};",
        channel.id.as_str(),
        channel.shape.value_type,
        channel.shape.unit,
        channel.shape.scale_decimal_exponent,
        channel.event_channel,
        options.time_basis,
        options.time_mapping,
        channel.chunks.len(),
        options.coordinate_frame,
        options.redaction,
        options.privacy_policy.to_hex(),
    );
    ContentHash::from_canonical_material("crucible.trace-import-options.v1", &material)
}

fn import_csv_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TraceImportError::InvalidUtf8)?;
    let rows = parse_csv(text)?;
    let Some(header) = rows.first() else {
        return Err(TraceImportError::NoEntries);
    };
    let expected = ["coordinate", "event_sequence", "value", "validity"];
    if header.iter().map(String::as_str).ne(expected) {
        return Err(TraceImportError::InvalidColumns);
    }
    let mut entries = Vec::with_capacity(rows.len().saturating_sub(1));
    for row in rows.iter().skip(1) {
        if row.len() != expected.len() {
            return Err(TraceImportError::InvalidColumns);
        }
        let source = parse_u64(&row[0])?;
        let coordinate = options
            .time_mapping
            .map(source)
            .map_err(TraceImportError::Trace)?;
        let event_sequence = parse_optional_u64(&row[1])?;
        let value = parse_text_value(&row[2], &options.shape.value_type)?;
        let validity = parse_validity(&row[3])?;
        entries.push(TraceEntry {
            coordinate,
            event_sequence,
            value,
            validity,
        });
    }
    Ok(entries)
}

fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, TraceImportError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                characters.next();
                field.push('"');
            }
            '"' if field.is_empty() || quoted => quoted = !quoted,
            '"' => return Err(TraceImportError::MalformedCsv),
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\r' if !quoted && characters.peek() == Some(&'\n') => {}
            value => field.push(value),
        }
    }
    if quoted {
        return Err(TraceImportError::MalformedCsv);
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

fn import_jsonl_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TraceImportError::InvalidUtf8)?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(TraceImportError::MalformedJson);
        }
        let value: Value =
            serde_json::from_str(line).map_err(|_| TraceImportError::MalformedJson)?;
        let object = value.as_object().ok_or(TraceImportError::MalformedJson)?;
        reject_unknown_fields(
            object,
            &["coordinate", "event_sequence", "value", "validity"],
        )?;
        let source = json_u64(required(object, "coordinate")?)?;
        let coordinate = options
            .time_mapping
            .map(source)
            .map_err(TraceImportError::Trace)?;
        let event_sequence = match object.get("event_sequence") {
            Some(value) => Some(json_u64(value)?),
            None => None,
        };
        let raw_value = required(object, "value")?;
        let normalized = parse_json_value(raw_value, &options.shape.value_type)?;
        let validity = match object.get("validity") {
            Some(Value::String(value)) => parse_validity(value)?,
            None => TraceValidity::Valid,
            _ => return Err(TraceImportError::MalformedJson),
        };
        entries.push(TraceEntry {
            coordinate,
            event_sequence,
            value: normalized,
            validity,
        });
    }
    Ok(entries)
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, TraceImportError> {
    object.get(key).ok_or(TraceImportError::MissingField)
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), TraceImportError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(TraceImportError::UnknownField);
    }
    Ok(())
}

fn json_u64(value: &Value) -> Result<u64, TraceImportError> {
    value.as_u64().ok_or(TraceImportError::NonIntegerNumber)
}

fn json_i64(value: &Value) -> Result<i64, TraceImportError> {
    value.as_i64().ok_or(TraceImportError::NonIntegerNumber)
}

fn parse_json_value(
    value: &Value,
    value_type: &SignalValueType,
) -> Result<SignalValue, TraceImportError> {
    match value_type {
        SignalValueType::Bool => value
            .as_bool()
            .map(SignalValue::Bool)
            .ok_or(TraceImportError::ValueShape),
        SignalValueType::I64 => Ok(SignalValue::I64(json_i64(value)?)),
        SignalValueType::U64 => Ok(SignalValue::U64(json_u64(value)?)),
        SignalValueType::DurationNanos => Ok(SignalValue::DurationNanos(json_u64(value)?)),
        SignalValueType::RatePerSecond => Ok(SignalValue::RatePerSecond(json_u64(value)?)),
        SignalValueType::ProbabilityMillionths => {
            let probability =
                u32::try_from(json_u64(value)?).map_err(|_| TraceImportError::ValueShape)?;
            if probability > 1_000_000 {
                return Err(TraceImportError::ValueShape);
            }
            Ok(SignalValue::ProbabilityMillionths(probability))
        }
        SignalValueType::Ratio => {
            let object = value.as_object().ok_or(TraceImportError::ValueShape)?;
            reject_unknown_fields(object, &["numerator", "denominator"])?;
            let ratio = ExactRatio::new(
                json_i64(required(object, "numerator")?)?,
                json_u64(required(object, "denominator")?)?,
            )
            .map_err(TraceImportError::Signal)?;
            Ok(SignalValue::Ratio(ratio))
        }
        SignalValueType::Enum(schema) => {
            let variant = value.as_str().ok_or(TraceImportError::ValueShape)?;
            Ok(SignalValue::Enum {
                schema: schema.clone(),
                variant: SignalId::parse(variant).map_err(TraceImportError::Signal)?,
            })
        }
        SignalValueType::Event(schema) => {
            let payload = canonical_json_payload(value)?;
            Ok(SignalValue::Event {
                schema: schema.clone(),
                payload,
            })
        }
        SignalValueType::Vector2(element) => parse_json_vector(value, element, 2, true),
        SignalValueType::Vector3(element) => parse_json_vector(value, element, 3, false),
        SignalValueType::Bytes => {
            let text = value.as_str().ok_or(TraceImportError::ValueShape)?;
            Ok(SignalValue::Bytes(parse_hex(text)?))
        }
    }
}

fn parse_json_vector(
    value: &Value,
    element: &SignalValueType,
    length: usize,
    two: bool,
) -> Result<SignalValue, TraceImportError> {
    let values = value.as_array().ok_or(TraceImportError::ValueShape)?;
    if values.len() != length {
        return Err(TraceImportError::ValueShape);
    }
    let normalized = values
        .iter()
        .map(|value| parse_json_value(value, element))
        .collect::<Result<Vec<_>, _>>()?;
    if two {
        Ok(SignalValue::Vector2(normalized))
    } else {
        Ok(SignalValue::Vector3(normalized))
    }
}

fn canonical_json_payload(value: &Value) -> Result<Vec<u8>, TraceImportError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    if output.len() > HARD_TRACE_VALUE_BYTES {
        return Err(TraceImportError::ValueShape);
    }
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), TraceImportError> {
    match value {
        Value::Null => return Err(TraceImportError::ValueShape),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) if value.is_i64() || value.is_u64() => {
            output.extend_from_slice(value.to_string().as_bytes());
        }
        Value::Number(_) => return Err(TraceImportError::NonIntegerNumber),
        Value::String(value) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| TraceImportError::MalformedJson)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let ordered = values.iter().collect::<BTreeMap<_, _>>();
            for (index, (key, value)) in ordered.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let key =
                    serde_json::to_string(key).map_err(|_| TraceImportError::MalformedJson)?;
                output.extend_from_slice(key.as_bytes());
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn parse_text_value(
    text: &str,
    value_type: &SignalValueType,
) -> Result<SignalValue, TraceImportError> {
    match value_type {
        SignalValueType::Bool => match text {
            "true" => Ok(SignalValue::Bool(true)),
            "false" => Ok(SignalValue::Bool(false)),
            _ => Err(TraceImportError::ValueShape),
        },
        SignalValueType::I64 => text
            .parse::<i64>()
            .map(SignalValue::I64)
            .map_err(|_| TraceImportError::ValueShape),
        SignalValueType::U64 => Ok(SignalValue::U64(parse_u64(text)?)),
        SignalValueType::DurationNanos => Ok(SignalValue::DurationNanos(parse_u64(text)?)),
        SignalValueType::RatePerSecond => Ok(SignalValue::RatePerSecond(parse_u64(text)?)),
        SignalValueType::ProbabilityMillionths => {
            let value = text
                .parse::<u32>()
                .map_err(|_| TraceImportError::ValueShape)?;
            if value > 1_000_000 {
                return Err(TraceImportError::ValueShape);
            }
            Ok(SignalValue::ProbabilityMillionths(value))
        }
        SignalValueType::Ratio => {
            let (numerator, denominator) =
                text.split_once('/').ok_or(TraceImportError::ValueShape)?;
            Ok(SignalValue::Ratio(
                ExactRatio::new(
                    numerator
                        .parse::<i64>()
                        .map_err(|_| TraceImportError::ValueShape)?,
                    parse_u64(denominator)?,
                )
                .map_err(TraceImportError::Signal)?,
            ))
        }
        SignalValueType::Enum(schema) => Ok(SignalValue::Enum {
            schema: schema.clone(),
            variant: SignalId::parse(text).map_err(TraceImportError::Signal)?,
        }),
        SignalValueType::Event(schema) => Ok(SignalValue::Event {
            schema: schema.clone(),
            payload: text.as_bytes().to_vec(),
        }),
        SignalValueType::Bytes => Ok(SignalValue::Bytes(parse_hex(text)?)),
        SignalValueType::Vector2(_) | SignalValueType::Vector3(_) => {
            Err(TraceImportError::ValueShape)
        }
    }
}

fn parse_u64(text: &str) -> Result<u64, TraceImportError> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return Err(TraceImportError::NonCanonicalInteger);
    }
    text.parse::<u64>()
        .map_err(|_| TraceImportError::NonCanonicalInteger)
}

fn parse_optional_u64(text: &str) -> Result<Option<u64>, TraceImportError> {
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parse_u64(text)?))
    }
}

fn parse_validity(text: &str) -> Result<TraceValidity, TraceImportError> {
    match text {
        "valid" => Ok(TraceValidity::Valid),
        "invalid_quality" => Ok(TraceValidity::InvalidQuality),
        "missing" => Ok(TraceValidity::Missing),
        "discontinuity" => Ok(TraceValidity::Discontinuity),
        _ => Err(TraceImportError::UnknownValidity),
    }
}

fn parse_hex(text: &str) -> Result<Vec<u8>, TraceImportError> {
    if !text.len().is_multiple_of(2) || text.len() > HARD_TRACE_VALUE_BYTES.saturating_mul(2) {
        return Err(TraceImportError::ValueShape);
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, TraceImportError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(TraceImportError::ValueShape),
    }
}

fn import_pcap_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    if !options.event_channel
        || !matches!(options.shape.value_type, SignalValueType::Event(_))
        || bytes.len() < 24
    {
        return Err(TraceImportError::PacketCaptureContract);
    }
    let magic = bytes
        .get(0..4)
        .ok_or(TraceImportError::MalformedPacketCapture)?;
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(TraceImportError::MalformedPacketCapture),
    };
    let mut cursor = 24_usize;
    let mut sequence = 0_u64;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor.saturating_add(16))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let seconds = endian_u32(&header[0..4], little)?;
        let fraction = endian_u32(&header[4..8], little)?;
        let included = usize::try_from(endian_u32(&header[8..12], little)?)
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        let original = endian_u32(&header[12..16], little)?;
        cursor = cursor
            .checked_add(16)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let packet = bytes
            .get(cursor..cursor.saturating_add(included))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        cursor = cursor
            .checked_add(included)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let fraction_nanos = if nanos {
            u64::from(fraction)
        } else {
            u64::from(fraction)
                .checked_mul(1_000)
                .ok_or(TraceImportError::MalformedPacketCapture)?
        };
        if fraction_nanos >= 1_000_000_000 {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let source = u64::from(seconds)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(fraction_nanos))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        entries.push(packet_entry(source, sequence, original, packet, options)?);
        sequence = sequence
            .checked_add(1)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
    }
    Ok(entries)
}

fn endian_u32(bytes: &[u8], little: bool) -> Result<u32, TraceImportError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| TraceImportError::MalformedPacketCapture)?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn import_pcapng_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    if !options.event_channel || !matches!(options.shape.value_type, SignalValueType::Event(_)) {
        return Err(TraceImportError::PacketCaptureContract);
    }
    let mut cursor = 0_usize;
    let mut little = true;
    let mut have_section = false;
    let mut timestamp_resolutions = Vec::new();
    let mut sequence = 0_u64;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let prefix = bytes
            .get(cursor..cursor.saturating_add(12))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let raw_type: [u8; 4] = prefix[0..4]
            .try_into()
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        if raw_type == [0x0a, 0x0d, 0x0d, 0x0a] {
            little = match &prefix[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err(TraceImportError::MalformedPacketCapture),
            };
            have_section = true;
            timestamp_resolutions.clear();
        }
        if !have_section {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let block_type = endian_u32(&prefix[0..4], little)?;
        let length = usize::try_from(endian_u32(&prefix[4..8], little)?)
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        if length < 12 || length % 4 != 0 {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let block = bytes
            .get(cursor..cursor.saturating_add(length))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        if endian_u32(&block[length - 4..], little)?
            != u32::try_from(length).map_err(|_| TraceImportError::MalformedPacketCapture)?
        {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        if block_type == 1 {
            timestamp_resolutions.push(parse_pcapng_timestamp_resolution(block, little)?);
        } else if block_type == 6 {
            if length < 32 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let interface = usize::try_from(endian_u32(&block[8..12], little)?)
                .map_err(|_| TraceImportError::MalformedPacketCapture)?;
            let resolution = timestamp_resolutions
                .get(interface)
                .copied()
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            let high = endian_u32(&block[12..16], little)?;
            let low = endian_u32(&block[16..20], little)?;
            let timestamp = (u64::from(high) << 32) | u64::from(low);
            let source = resolution.to_nanoseconds(timestamp)?;
            let captured = usize::try_from(endian_u32(&block[20..24], little)?)
                .map_err(|_| TraceImportError::MalformedPacketCapture)?;
            let original = endian_u32(&block[24..28], little)?;
            let packet_end = 28_usize
                .checked_add(captured)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            let padded_end = packet_end
                .checked_add(3)
                .map(|end| end & !3)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            if padded_end > length.saturating_sub(4) {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let packet = block
                .get(28..packet_end)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            entries.push(packet_entry(source, sequence, original, packet, options)?);
            sequence = sequence
                .checked_add(1)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
        }
        cursor = cursor
            .checked_add(length)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
    }
    Ok(entries)
}

#[derive(Clone, Copy)]
enum PcapNgTimestampResolution {
    Decimal(u8),
    Binary(u8),
}

impl PcapNgTimestampResolution {
    fn to_nanoseconds(self, timestamp: u64) -> Result<u64, TraceImportError> {
        let denominator = match self {
            Self::Decimal(exponent) => 10_u128
                .checked_pow(u32::from(exponent))
                .ok_or(TraceImportError::MalformedPacketCapture)?,
            Self::Binary(exponent) => 1_u128
                .checked_shl(u32::from(exponent))
                .ok_or(TraceImportError::MalformedPacketCapture)?,
        };
        let nanos = u128::from(timestamp)
            .checked_mul(1_000_000_000)
            .ok_or(TraceImportError::MalformedPacketCapture)?
            / denominator;
        u64::try_from(nanos).map_err(|_| TraceImportError::MalformedPacketCapture)
    }
}

fn parse_pcapng_timestamp_resolution(
    block: &[u8],
    little: bool,
) -> Result<PcapNgTimestampResolution, TraceImportError> {
    if block.len() < 20 {
        return Err(TraceImportError::MalformedPacketCapture);
    }
    let options_end = block.len() - 4;
    let mut cursor = 16_usize;
    let mut resolution = PcapNgTimestampResolution::Decimal(6);
    while cursor < options_end {
        if cursor.saturating_add(4) > options_end {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let code = endian_u16(&block[cursor..cursor + 2], little)?;
        let length = usize::from(endian_u16(&block[cursor + 2..cursor + 4], little)?);
        cursor += 4;
        if code == 0 {
            if length != 0 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            break;
        }
        let value_end = cursor
            .checked_add(length)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let padded_end = value_end
            .checked_add(3)
            .map(|end| end & !3)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        if padded_end > options_end {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        if code == 9 {
            if length != 1 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let encoded = block[cursor];
            resolution = if encoded & 0x80 == 0 {
                PcapNgTimestampResolution::Decimal(encoded)
            } else {
                PcapNgTimestampResolution::Binary(encoded & 0x7f)
            };
        }
        cursor = padded_end;
    }
    Ok(resolution)
}

fn endian_u16(bytes: &[u8], little: bool) -> Result<u16, TraceImportError> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| TraceImportError::MalformedPacketCapture)?;
    Ok(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn packet_entry(
    source_nanos: u64,
    sequence: u64,
    original_length: u32,
    packet: &[u8],
    options: &TraceImportOptions,
) -> Result<TraceEntry, TraceImportError> {
    let coordinate = options
        .time_mapping
        .map(source_nanos)
        .map_err(TraceImportError::Trace)?;
    let digest = ContentHash::from_bytes(packet);
    let mut payload = Vec::with_capacity(44);
    payload.extend_from_slice(&original_length.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(packet.len())
            .map_err(|_| TraceImportError::MalformedPacketCapture)?
            .to_be_bytes(),
    );
    payload.extend_from_slice(&digest.bytes);
    let schema = match &options.shape.value_type {
        SignalValueType::Event(schema) => schema.clone(),
        _ => return Err(TraceImportError::PacketCaptureContract),
    };
    Ok(TraceEntry {
        coordinate,
        event_sequence: Some(sequence),
        value: SignalValue::Event { schema, payload },
        validity: TraceValidity::Valid,
    })
}

/// Deterministic importer failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceImportError {
    /// Input exceeded the hard byte limit.
    InputLimit,
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// CSV quoting or record termination was malformed.
    MalformedCsv,
    /// CSV columns differed from the exact canonical header.
    InvalidColumns,
    /// JSON line was malformed or not an object.
    MalformedJson,
    /// JSON object omitted a required field.
    MissingField,
    /// JSON object contained an unknown field.
    UnknownField,
    /// JSON number was negative for unsigned use or non-integer.
    NonIntegerNumber,
    /// Integer text contained leading zeroes or was out of range.
    NonCanonicalInteger,
    /// Value did not match the declared channel shape.
    ValueShape,
    /// Spatial redaction requires a two- or three-dimensional signed millimetre vector.
    RedactionShape,
    /// Validity spelling was unknown.
    UnknownValidity,
    /// Import produced no entries.
    NoEntries,
    /// Packet importer requires an event channel.
    PacketCaptureContract,
    /// PCAP or PCAPNG framing was malformed or unsupported.
    MalformedPacketCapture,
    /// Nested normalized-trace validation failed.
    Trace(TraceError),
    /// Nested signal validation failed.
    Signal(SignalProgramError),
    /// Nested fault contract failed.
    Contract(FaultContractError),
}

impl fmt::Display for TraceImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "trace import failed: {self:?}")
    }
}

impl Error for TraceImportError {}

/// Persistence or dependency-closure failure for a normalized trace artifact.
#[derive(Debug)]
pub enum TraceArtifactStoreError {
    /// Caller-supplied raw bytes differ from manifest provenance.
    RawProvenanceMismatch,
    /// Encoded bytes, declared content identity, and store identity differ.
    ContentMismatch,
    /// A chunk reference disagrees with decoded chunk metadata.
    ReferenceMismatch,
    /// Backing content-addressed store failed.
    Store(DagStoreError),
    /// Canonical trace codec failed.
    Trace(TraceError),
}

impl fmt::Display for TraceArtifactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "normalized trace persistence failed: {self:?}")
    }
}

impl Error for TraceArtifactStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Trace(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> FaultObjectId {
        match FaultObjectId::parse(value) {
            Ok(value) => value,
            Err(error) => panic!("test ID must be valid: {error}"),
        }
    }

    fn signal_id(value: &str) -> SignalId {
        match SignalId::parse(value) {
            Ok(value) => value,
            Err(error) => panic!("test signal ID must be valid: {error}"),
        }
    }

    fn options(value_type: SignalValueType, unit: SignalUnit, event: bool) -> TraceImportOptions {
        let one = match PositiveU64::new("one", 1) {
            Ok(value) => value,
            Err(error) => panic!("one must be valid: {error}"),
        };
        let mapping = match NormalizedTraceTimeMapping::new(vec![TraceTimeSegment {
            source_start: 0,
            source_end: None,
            source_epoch: 0,
            virtual_epoch_nanos: 0,
            numerator: one,
            denominator: one,
            rounding: SignalRounding::Floor,
        }]) {
            Ok(value) => value,
            Err(error) => panic!("test mapping must be valid: {error}"),
        };
        let shape = match SignalShape::new(value_type, unit, 0) {
            Ok(value) => value,
            Err(error) => panic!("test shape must be valid: {error}"),
        };
        TraceImportOptions {
            channel: signal_id("channel-a"),
            shape,
            event_channel: event,
            time_basis: TraceTimeBasis::Nanoseconds,
            time_mapping: mapping,
            source_alias: id("device-a"),
            privacy_policy: ContentHash::from_bytes(b"privacy"),
            coordinate_frame: None,
            redaction: None,
        }
    }

    #[test]
    fn csv_and_jsonl_normalize_identically() {
        let csv = b"coordinate,event_sequence,value,validity\n1,,7,valid\n2,,8,valid\n";
        let jsonl = b"{\"coordinate\":1,\"value\":7}\n{\"coordinate\":2,\"value\":8}\n";
        let csv_result = import_signal_trace(
            TraceImportFormat::Csv,
            csv,
            options(SignalValueType::U64, SignalUnit::Dimensionless, false),
        );
        let json_result = import_signal_trace(
            TraceImportFormat::JsonLines,
            jsonl,
            options(SignalValueType::U64, SignalUnit::Dimensionless, false),
        );
        let (Ok(csv_result), Ok(json_result)) = (csv_result, json_result) else {
            panic!("test imports must succeed");
        };
        assert_eq!(csv_result.chunks[0].entries, json_result.chunks[0].entries);
        assert_ne!(csv_result.manifest.content, json_result.manifest.content);
    }

    #[test]
    fn jsonl_rejects_floats_and_unknown_fields() {
        let float = b"{\"coordinate\":1,\"value\":1.5}\n";
        assert!(
            import_signal_trace(
                TraceImportFormat::JsonLines,
                float,
                options(SignalValueType::U64, SignalUnit::Dimensionless, false),
            )
            .is_err()
        );
        let unknown = b"{\"coordinate\":1,\"value\":1,\"extra\":false}\n";
        assert_eq!(
            import_signal_trace(
                TraceImportFormat::JsonLines,
                unknown,
                options(SignalValueType::U64, SignalUnit::Dimensionless, false),
            ),
            Err(TraceImportError::UnknownField)
        );
    }

    #[test]
    fn text_import_preserves_basis_and_applies_spatial_redaction() {
        let value_type = SignalValueType::Vector2(Box::new(SignalValueType::I64));
        let mut import_options = options(value_type, SignalUnit::Millimetres, false);
        import_options.time_basis = TraceTimeBasis::DeviceTicks;
        import_options.redaction = Some(SpatialRedaction {
            translation_mm: [5, -5, 0],
            quarter_turns: 1,
            quantization_mm: match PositiveU64::new("quantization", 10) {
                Ok(value) => value,
                Err(error) => panic!("test quantization must be valid: {error}"),
            },
        });
        let result = import_signal_trace(
            TraceImportFormat::JsonLines,
            b"{\"coordinate\":1,\"value\":[12,23]}\n",
            import_options,
        );
        let Ok(result) = result else {
            panic!("redacted import must succeed: {result:?}");
        };
        assert_eq!(result.manifest.time_basis, TraceTimeBasis::DeviceTicks);
        assert_eq!(
            result.chunks[0].entries[0].value,
            SignalValue::Vector2(vec![SignalValue::I64(-20), SignalValue::I64(0)])
        );
    }

    #[test]
    fn pcapng_honors_timestamp_resolution_and_packet_bounds() {
        let packet_type = SignalValueType::Event(signal_id("packet-digest"));
        let valid = pcapng_capture(1, 7, &[0xaa]);
        let result = import_signal_trace(
            TraceImportFormat::PcapNg,
            &valid,
            options(packet_type.clone(), SignalUnit::Dimensionless, true),
        );
        let Ok(result) = result else {
            panic!("pcapng import must succeed: {result:?}");
        };
        assert_eq!(result.chunks[0].entries[0].coordinate, 7);

        let malformed = pcapng_capture(9, 7, &[0xaa]);
        assert_eq!(
            import_signal_trace(
                TraceImportFormat::PcapNg,
                &malformed,
                options(packet_type, SignalUnit::Dimensionless, true),
            ),
            Err(TraceImportError::MalformedPacketCapture)
        );
    }

    fn pcapng_capture(declared_capture_length: u32, timestamp: u64, packet: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_le_block(
            &mut bytes,
            0x0a0d0d0a,
            &[
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        );
        let mut interface = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
        interface.extend_from_slice(&9_u16.to_le_bytes());
        interface.extend_from_slice(&1_u16.to_le_bytes());
        interface.extend_from_slice(&[9, 0, 0, 0]);
        interface.extend_from_slice(&[0, 0, 0, 0]);
        push_le_block(&mut bytes, 1, &interface);

        let mut enhanced = Vec::new();
        enhanced.extend_from_slice(&0_u32.to_le_bytes());
        enhanced.extend_from_slice(
            &u32::try_from(timestamp >> 32)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        enhanced.extend_from_slice(&(timestamp as u32).to_le_bytes());
        enhanced.extend_from_slice(&declared_capture_length.to_le_bytes());
        enhanced.extend_from_slice(&declared_capture_length.to_le_bytes());
        enhanced.extend_from_slice(packet);
        while enhanced.len() % 4 != 0 {
            enhanced.push(0);
        }
        push_le_block(&mut bytes, 6, &enhanced);
        bytes
    }

    fn push_le_block(output: &mut Vec<u8>, block_type: u32, body: &[u8]) {
        let length = u32::try_from(body.len() + 12).unwrap_or(u32::MAX);
        output.extend_from_slice(&block_type.to_le_bytes());
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(body);
        output.extend_from_slice(&length.to_le_bytes());
    }
}
