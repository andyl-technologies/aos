//! Legacy v1-v5 prepared-result codecs for explicit offline migration.
//!
//! Normal prepared-result decoding does not import this format. The stopped
//! daemon store-repair operation uses this module to authenticate old payloads
//! and produce current payloads before runtime startup is allowed.

use super::*;

const PREPARED_RESULT_MAGIC_V1: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v1\0";
const PREPARED_RESULT_MAGIC_V2: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v2\0";
const PREPARED_RESULT_MAGIC_V3: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v3\0";
const PREPARED_RESULT_MAGIC_V4: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v4\0";
const PREPARED_RESULT_MAGIC_V5: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v5\0";

const V2_FORMAT: PreparedResultFormat = PreparedResultFormat {
    terminal_fingerprints: TerminalFingerprintEncoding::Absent,
    replay_incompatibility: false,
    triage_replays: TriageReplayEncoding::Absent,
};
const V3_FORMAT: PreparedResultFormat = PreparedResultFormat {
    terminal_fingerprints: TerminalFingerprintEncoding::Required,
    ..V2_FORMAT
};
const V4_FORMAT: PreparedResultFormat = PreparedResultFormat {
    terminal_fingerprints: TerminalFingerprintEncoding::Optional,
    replay_incompatibility: true,
    ..V2_FORMAT
};
const V5_FORMAT: PreparedResultFormat = PreparedResultFormat {
    triage_replays: TriageReplayEncoding::Required,
    ..V4_FORMAT
};

pub(crate) struct DecodedMigrationResult {
    pub(crate) result: PreparedSemanticAttemptResult,
    pub(crate) current: bool,
}

pub(crate) fn decode(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<DecodedMigrationResult, PreparedSemanticResultCodecError> {
    if bytes.starts_with(PREPARED_RESULT_MAGIC_V1) {
        return decode_v1(bytes, maximum_bytes).map(|result| DecodedMigrationResult {
            result,
            current: false,
        });
    }
    let (format, magic, current) = if bytes.starts_with(PREPARED_RESULT_MAGIC_V2) {
        (V2_FORMAT, PREPARED_RESULT_MAGIC_V2, false)
    } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V3) {
        (V3_FORMAT, PREPARED_RESULT_MAGIC_V3, false)
    } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V4) {
        (V4_FORMAT, PREPARED_RESULT_MAGIC_V4, false)
    } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V5) {
        (V5_FORMAT, PREPARED_RESULT_MAGIC_V5, false)
    } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V6) {
        (CURRENT_FORMAT, PREPARED_RESULT_MAGIC_V6, true)
    } else {
        return Err(PreparedSemanticResultCodecError::NonCanonical);
    };
    PreparedSemanticAttemptResult::decode_version(bytes, maximum_bytes, format, magic)
        .map(|result| DecodedMigrationResult { result, current })
}

fn decode_v1(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<PreparedSemanticAttemptResult, PreparedSemanticResultCodecError> {
    let maximum_bytes = maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES);
    if bytes.len() > maximum_bytes {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }

    let mut decoder = Decoder::new(bytes);
    decoder.magic(PREPARED_RESULT_MAGIC_V1)?;
    let observation = decode_observation(&mut decoder)?;
    let finding = match decoder.byte()? {
        0 => None,
        1 => Some(decode_finding(&mut decoder, V2_FORMAT)?),
        _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
    };
    decoder.finish()?;

    let value = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        observation,
        Vec::new(),
        finding,
    )?;
    if encode(&value, maximum_bytes)? != bytes {
        return Err(PreparedSemanticResultCodecError::NonCanonical);
    }
    Ok(value)
}

pub(crate) fn encode(
    value: &PreparedSemanticAttemptResult,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
    encode_parts(
        &value.observation,
        value.finding.as_ref(),
        &value.measurement_replay_evidence,
        value.terminal_fingerprints.as_ref(),
        maximum_bytes,
    )
}

#[cfg(test)]
pub(crate) fn encode_version_for_test(
    value: &PreparedSemanticAttemptResult,
    version: u8,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
    let (format, magic) = match version {
        2 => (V2_FORMAT, PREPARED_RESULT_MAGIC_V2),
        3 => (V3_FORMAT, PREPARED_RESULT_MAGIC_V3),
        4 => (V4_FORMAT, PREPARED_RESULT_MAGIC_V4),
        5 => (V5_FORMAT, PREPARED_RESULT_MAGIC_V5),
        _ => return Err(PreparedSemanticResultCodecError::NonCanonical),
    };
    value.encode_version(maximum_bytes, format, magic)
}

fn encode_parts(
    observation: &ObservationCandidate,
    finding: Option<&PreparedCrucibleFindingCandidate>,
    measurement_replay_evidence: &[CrucibleMeasurementReplayEvidence],
    terminal_fingerprints: Option<&Vec<FingerprintSample>>,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
    if !measurement_replay_evidence.is_empty() {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "v1 measurement replay evidence",
        });
    }
    if terminal_fingerprints.is_some() {
        return Err(inconsistent("v1 terminal fingerprint evidence"));
    }
    validate_pair(observation, finding)?;

    let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
    encoder.raw(PREPARED_RESULT_MAGIC_V1)?;
    encode_observation(&mut encoder, observation)?;
    match finding {
        Some(finding) => {
            encoder.byte(1)?;
            encode_finding(&mut encoder, finding, V2_FORMAT)?;
        }
        None => encoder.byte(0)?,
    }
    let bytes = encoder.finish()?;
    validate_measurement_evidence(observation, &[], finding)?;
    Ok(bytes)
}
