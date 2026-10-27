//! Streaming parser for the `ResumeSession` request body.
//!
//! A resume request is newline-delimited text. Bracketed lines are the
//! optional replay closure, whose frame pair repeats once per frame:
//!
//! ```text
//! crucible.rpc/resume-session-request
//! scenario-id=<64 hex digits>
//! scenario-seed=<64 hex digits>
//! app-random-draw-cap=<u64>
//! scenario-payload=<hex compact scenario form>
//! seed=<64 hex digits>
//! schedule=<hex compact schedule>
//! checkpoint=<hex compact checkpoint>
//! [campaign-replay-closure-version=<u32>]
//! [campaign-replay-closure-identity=<64 hex digits>]
//! [campaign-replay-closure-frames=<count>]
//! [campaign-replay-closure-frame-size=<bytes>]
//! [campaign-replay-closure-frame=<hex>]
//! campaign-observation-source-version=<u32>
//! campaign-observation-source-identity=<64 hex digits>
//! campaign-observation-source-proof-size=<bytes>
//! campaign-observation-source-proof=<hex>
//! campaign-observation-source-evidence-size=<bytes>
//! campaign-observation-source-evidence=<hex>
//! ```
//!
//! The parser reads the body one transport chunk at a time and never
//! collects it (RFC-0020 CMEAS-36). Every field is checked against its bound
//! before its bytes are accepted:
//!
//! - text lines against [`RESUME_WIRE_TEXT_LINE_MAX_BYTES`];
//! - the scenario, schedule, and checkpoint hex against one shared
//!   model-envelope budget, [`RESUME_SESSION_RPC_MODEL_ENVELOPE_MAX_BYTES`];
//! - each closure frame and observation payload against its declared size,
//!   which is itself checked against the closure or observation bound before
//!   any hex is decoded.
//!
//! Hex is decoded straight into the field's binary buffer, so the largest
//! transient a request holds is its decoded fields.

use axum::http::StatusCode;
use axum::response::Response;
use bytes::{Buf, Bytes};
use crucible_engine::{Checkpoint, ScenarioDefForm, Schedule};
use futures_util::{Stream, StreamExt};

use super::{
    RpcStatusCode, http2_response, parse_content_hash_line, parse_seed_line, parse_u64_line,
    typed_rpc_status_response,
};
use crate::lifecycle::{
    RESUME_OBSERVATION_SOURCE_MAX_BYTES, RESUME_REPLAY_CLOSURE_FRAME_MAX_BYTES,
    RESUME_REPLAY_CLOSURE_MAX_BYTES, RESUME_REPLAY_CLOSURE_MAX_FRAMES, ResumeObservationSource,
    ResumeReplayClosure, ResumeSessionRequest,
};

/// Hex digits the scenario, schedule, and checkpoint fields may use together.
///
/// These are typed in-memory models that the lifecycle consumes whole, so
/// they keep a fixed allowance. Decoding them halves it.
pub(super) const RESUME_SESSION_RPC_MODEL_ENVELOPE_MAX_BYTES: usize = 512 * 1024 * 1024;

/// Longest accepted text line; every one is a short scalar or digest.
pub(super) const RESUME_WIRE_TEXT_LINE_MAX_BYTES: usize = 1024;

const REQUEST_HEADER: &str = "crucible.rpc/resume-session-request";
const CLOSURE_VERSION_PREFIX: &str = "campaign-replay-closure-version=";
const OBSERVATION_VERSION_PREFIX: &str = "campaign-observation-source-version=";

/// Bounds applied while a resume request streams in.
#[derive(Clone, Copy, Debug)]
pub(super) struct ResumeWireLimits {
    /// Hex digits shared by the scenario, schedule, and checkpoint fields.
    pub(super) model_envelope_hex_digits: usize,
}

impl Default for ResumeWireLimits {
    fn default() -> Self {
        Self {
            model_envelope_hex_digits: RESUME_SESSION_RPC_MODEL_ENVELOPE_MAX_BYTES,
        }
    }
}

/// A resume request the parser refused.
#[derive(Debug, thiserror::Error)]
pub(super) enum ResumeWireError {
    /// The model fields or a text line exceeded their wire allowance.
    #[error("{0}")]
    TooLarge(String),
    /// The body was unreadable, malformed, or failed a semantic check.
    #[error("{0}")]
    Malformed(String),
}

impl From<String> for ResumeWireError {
    fn from(message: String) -> Self {
        Self::Malformed(message)
    }
}

impl From<super::UnexpectedRpcRequestField> for ResumeWireError {
    fn from(error: super::UnexpectedRpcRequestField) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl ResumeWireError {
    /// Encodes the refusal as the RPC's HTTP/2 error response.
    ///
    /// A size refusal keeps the typed `resume-session-request-too-large`
    /// status. Any other refusal is a plain bad request, as for every
    /// other RPC.
    pub(super) fn into_response(self) -> Response {
        match self {
            Self::TooLarge(message) => typed_rpc_status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                RpcStatusCode::InvalidArgument,
                "resume-session-request-too-large",
                &message,
            ),
            Self::Malformed(message) => http2_response(StatusCode::BAD_REQUEST, message),
        }
    }
}

/// Reads and validates one resume request from a stream of body chunks.
///
/// The scenario payload must match its declared id, seed, and draw cap, and
/// the closure and observation source must derive their declared identities.
///
/// # Errors
///
/// Returns [`ResumeWireError::TooLarge`] when the model fields or a text line
/// exceed `limits`, and [`ResumeWireError::Malformed`] for an unreadable,
/// truncated, malformed, oversized, or mismatched field or trailing line.
pub(super) async fn read_resume_session_request<S, E>(
    chunks: S,
    limits: ResumeWireLimits,
) -> Result<ResumeSessionRequest, ResumeWireError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut body = ResumeBody::new(chunks);
    let mut model_budget = limits.model_envelope_hex_digits;

    let header = body.text_line().await?;
    super::expect_wire_header(header.as_deref(), REQUEST_HEADER)?;
    let scenario_id = parse_content_hash_line(body.text_line().await?.as_deref(), "scenario-id=")?;
    let scenario_seed = parse_seed_line(body.text_line().await?.as_deref(), "scenario-seed=")?;
    let app_random_draw_cap =
        parse_u64_line(body.text_line().await?.as_deref(), "app-random-draw-cap=")?;
    let scenario_bytes = body
        .budgeted_hex_line("scenario-payload=", &mut model_budget)
        .await?;
    let scenario = ScenarioDefForm::from_compact_binary(&scenario_bytes)
        .map_err(|error| format!("invalid scenario form: {error}"))?;
    drop(scenario_bytes);
    check_scenario_declaration(&scenario, scenario_id, scenario_seed, app_random_draw_cap)?;

    let seed = parse_seed_line(body.text_line().await?.as_deref(), "seed=")?;
    let schedule_bytes = body
        .budgeted_hex_line("schedule=", &mut model_budget)
        .await?;
    let schedule = Schedule::from_compact_binary(&schedule_bytes)
        .map_err(|error| format!("invalid schedule: {error}"))?;
    drop(schedule_bytes);
    let checkpoint_bytes = body
        .budgeted_hex_line("checkpoint=", &mut model_budget)
        .await?;
    let checkpoint = Checkpoint::from_compact_binary(&checkpoint_bytes)
        .map_err(|error| format!("invalid checkpoint: {error}"))?;
    drop(checkpoint_bytes);

    // The closure is optional; the observation source always follows it.
    let mut version_line = body.text_line().await?;
    let mut replay_closure = None;
    if version_line
        .as_deref()
        .is_some_and(|line| line.starts_with(CLOSURE_VERSION_PREFIX))
    {
        let closure =
            read_replay_closure(&mut body, &scenario, &schedule, &checkpoint, version_line).await?;
        replay_closure = Some(closure);
        version_line = body.text_line().await?;
    }
    let observation_source =
        read_observation_source(&mut body, &scenario, &schedule, &checkpoint, version_line).await?;
    super::reject_extra_line(body.text_line().await?.as_deref())?;

    let mut request =
        ResumeSessionRequest::new(scenario, schedule, checkpoint, seed, observation_source);
    if let Some(replay_closure) = replay_closure {
        request = request.with_replay_closure(replay_closure);
    }
    Ok(request)
}

/// Parses complete resume request bytes, as one already-received chunk.
///
/// # Errors
///
/// Returns the same refusals as [`read_resume_session_request`].
#[cfg(test)]
pub(super) fn parse_resume_session_request(
    body: &[u8],
) -> Result<ResumeSessionRequest, ResumeWireError> {
    use futures_util::FutureExt;

    let chunks = futures_util::stream::iter([Ok::<_, std::convert::Infallible>(
        Bytes::copy_from_slice(body),
    )]);
    read_resume_session_request(chunks, ResumeWireLimits::default())
        .now_or_never()
        .unwrap_or_else(|| {
            Err(ResumeWireError::Malformed(String::from(
                "in-memory resume body unexpectedly pended",
            )))
        })
}

fn check_scenario_declaration(
    scenario: &ScenarioDefForm,
    id: crucible_engine::ContentHash,
    seed: crucible_engine::Seed,
    app_random_draw_cap: u64,
) -> Result<(), ResumeWireError> {
    let scenario_def = scenario.scenario_def();
    if scenario_def.id() != id {
        return Err(ResumeWireError::Malformed(format!(
            "scenario payload id {} did not match request scenario id {}",
            scenario_def.id().to_hex(),
            id.to_hex()
        )));
    }
    if scenario.seed() != seed {
        return Err(ResumeWireError::Malformed(format!(
            "scenario payload seed {} did not match request scenario seed {}",
            scenario.seed().to_hex(),
            seed.to_hex()
        )));
    }
    if scenario.app_random_draw_cap() != app_random_draw_cap {
        return Err(ResumeWireError::Malformed(format!(
            "scenario payload app-random draw cap {} did not match request cap {}",
            scenario.app_random_draw_cap(),
            app_random_draw_cap
        )));
    }
    Ok(())
}

/// Reads the size-prefixed closure frames, checking every bound before
/// decoding each frame's hex.
async fn read_replay_closure<S, E>(
    body: &mut ResumeBody<S>,
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    version_line: Option<String>,
) -> Result<ResumeReplayClosure, ResumeWireError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let version = parse_u64_line(version_line.as_deref(), CLOSURE_VERSION_PREFIX)?;
    let version = u32::try_from(version)
        .map_err(|_| String::from("campaign replay closure version exceeds u32"))?;
    let expected_identity = parse_content_hash_line(
        body.text_line().await?.as_deref(),
        "campaign-replay-closure-identity=",
    )?;
    let count = parse_u64_line(
        body.text_line().await?.as_deref(),
        "campaign-replay-closure-frames=",
    )?;
    let count = usize::try_from(count)
        .ok()
        .filter(|count| (1..=RESUME_REPLAY_CLOSURE_MAX_FRAMES).contains(count))
        .ok_or_else(|| {
            format!(
                "campaign replay closure has {count} frames, expected 1 through {RESUME_REPLAY_CLOSURE_MAX_FRAMES}"
            )
        })?;

    let mut frames = Vec::with_capacity(count);
    let mut total = 0_usize;
    for _ in 0..count {
        let size = parse_u64_line(
            body.text_line().await?.as_deref(),
            "campaign-replay-closure-frame-size=",
        )?;
        let size = usize::try_from(size)
            .ok()
            .filter(|size| *size <= RESUME_REPLAY_CLOSURE_FRAME_MAX_BYTES)
            .ok_or_else(|| {
                format!(
                    "campaign replay closure frame has {size} bytes, maximum is {RESUME_REPLAY_CLOSURE_FRAME_MAX_BYTES}"
                )
            })?;
        total = total
            .checked_add(size)
            .filter(|total| *total <= RESUME_REPLAY_CLOSURE_MAX_BYTES)
            .ok_or_else(|| {
                format!("campaign replay closure exceeds {RESUME_REPLAY_CLOSURE_MAX_BYTES} bytes")
            })?;
        frames.push(
            body.sized_hex_line(
                "campaign-replay-closure-frame=",
                size,
                "campaign replay closure frame",
            )
            .await?,
        );
    }

    let closure = ResumeReplayClosure::new(scenario, schedule, checkpoint, version, frames)
        .map_err(|error| error.to_string())?;
    if closure.identity() != expected_identity {
        return Err(ResumeWireError::Malformed(format!(
            "campaign replay closure identity {} did not match bound identity {}",
            closure.identity().to_hex(),
            expected_identity.to_hex(),
        )));
    }
    Ok(closure)
}

/// Reads the observation proof and evidence, checking their combined
/// declared size before decoding either payload.
async fn read_observation_source<S, E>(
    body: &mut ResumeBody<S>,
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    version_line: Option<String>,
) -> Result<ResumeObservationSource, ResumeWireError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    if version_line.is_none() {
        return Err(ResumeWireError::Malformed(String::from(
            "resume request is missing an authenticated campaign observation source",
        )));
    }
    let version = parse_u64_line(version_line.as_deref(), OBSERVATION_VERSION_PREFIX)?;
    let version = u32::try_from(version)
        .map_err(|_| String::from("campaign observation source version exceeds u32"))?;
    let expected_identity = parse_content_hash_line(
        body.text_line().await?.as_deref(),
        "campaign-observation-source-identity=",
    )?;

    let proof_size = parse_u64_line(
        body.text_line().await?.as_deref(),
        "campaign-observation-source-proof-size=",
    )?;
    let proof_size = observation_payload_size(proof_size, 0)?;
    let proof = body
        .sized_hex_line(
            "campaign-observation-source-proof=",
            proof_size,
            "campaign observation source proof",
        )
        .await?;
    let evidence_size = parse_u64_line(
        body.text_line().await?.as_deref(),
        "campaign-observation-source-evidence-size=",
    )?;
    let evidence_size = observation_payload_size(evidence_size, proof_size)?;
    let evidence = body
        .sized_hex_line(
            "campaign-observation-source-evidence=",
            evidence_size,
            "campaign observation source evidence",
        )
        .await?;

    let source =
        ResumeObservationSource::new(scenario, schedule, checkpoint, version, proof, evidence)
            .map_err(|error| error.to_string())?;
    if source.identity() != expected_identity {
        return Err(ResumeWireError::Malformed(format!(
            "campaign observation source identity {} did not match bound identity {}",
            source.identity().to_hex(),
            expected_identity.to_hex(),
        )));
    }
    Ok(source)
}

/// Admits one declared observation payload size after `already` bytes.
fn observation_payload_size(declared: u64, already: usize) -> Result<usize, ResumeWireError> {
    let total = u64::try_from(already)
        .ok()
        .and_then(|already| already.checked_add(declared))
        .ok_or_else(|| String::from("campaign observation source size overflowed"))?;
    let maximum = u64::try_from(RESUME_OBSERVATION_SOURCE_MAX_BYTES)
        .map_err(|_| String::from("campaign observation source bound cannot be represented"))?;
    if total > maximum {
        return Err(ResumeWireError::Malformed(format!(
            "campaign observation source has {total} bytes, maximum is {RESUME_OBSERVATION_SOURCE_MAX_BYTES}"
        )));
    }
    usize::try_from(declared)
        .map_err(|_| ResumeWireError::Malformed(String::from("observation size overflowed")))
}

/// Line reader over a request body that arrives in transport chunks.
struct ResumeBody<S> {
    chunks: S,
    chunk: Bytes,
    finished: bool,
}

impl<S, E> ResumeBody<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    const fn new(chunks: S) -> Self {
        Self {
            chunks,
            chunk: Bytes::new(),
            finished: false,
        }
    }

    /// Makes the current chunk non-empty; returns `false` at end of body.
    async fn fill(&mut self) -> Result<bool, ResumeWireError> {
        while self.chunk.is_empty() {
            if self.finished {
                return Ok(false);
            }
            match self.chunks.next().await {
                Some(Ok(chunk)) => self.chunk = chunk,
                Some(Err(error)) => {
                    return Err(ResumeWireError::Malformed(format!(
                        "read resume-session request body: {error}"
                    )));
                }
                None => self.finished = true,
            }
        }
        Ok(true)
    }

    /// Reads one text line without its terminator, or `None` at end of body.
    ///
    /// A final line may omit its newline, and a carriage return before the
    /// newline is dropped, matching [`str::lines`].
    async fn text_line(&mut self) -> Result<Option<String>, ResumeWireError> {
        if !self.fill().await? {
            return Ok(None);
        }
        let mut line = Vec::new();
        while self.fill().await? {
            let newline = self.chunk.iter().position(|byte| *byte == b'\n');
            let length = newline.unwrap_or(self.chunk.len());
            if line.len().saturating_add(length) > RESUME_WIRE_TEXT_LINE_MAX_BYTES {
                return Err(ResumeWireError::TooLarge(format!(
                    "resume-session text line exceeds {RESUME_WIRE_TEXT_LINE_MAX_BYTES} bytes"
                )));
            }
            line.extend_from_slice(&self.chunk[..length]);
            if newline.is_some() {
                self.chunk.advance(length + 1);
                break;
            }
            self.chunk.advance(length);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line)
            .map(Some)
            .map_err(|error| ResumeWireError::Malformed(error.to_string()))
    }

    /// Reads a hex line of unknown length, charging its digits to `budget`.
    async fn budgeted_hex_line(
        &mut self,
        prefix: &'static str,
        budget: &mut usize,
    ) -> Result<Vec<u8>, ResumeWireError> {
        self.expect_prefix(prefix).await?;
        let mut decoded = Vec::new();
        let digits = self
            .decode_hex_to_line_end(prefix, *budget, &mut decoded)
            .await?
            .ok_or_else(|| {
                ResumeWireError::TooLarge(String::from(
                    "resume-session request exceeds its bounded wire envelope",
                ))
            })?;
        *budget -= digits;
        Ok(decoded)
    }

    /// Reads a hex line that must decode to exactly `size` bytes.
    async fn sized_hex_line(
        &mut self,
        prefix: &'static str,
        size: usize,
        name: &str,
    ) -> Result<Vec<u8>, ResumeWireError> {
        let expected_digits = size
            .checked_mul(2)
            .ok_or_else(|| format!("{name} hex size overflowed"))?;
        self.expect_prefix(prefix).await?;
        let mut decoded = Vec::with_capacity(size);
        let digits = self
            .decode_hex_to_line_end(prefix, expected_digits, &mut decoded)
            .await?
            .ok_or_else(|| format!("{name} has more than {expected_digits} hex bytes"))?;
        if digits != expected_digits {
            return Err(ResumeWireError::Malformed(format!(
                "{name} has {digits} hex bytes, expected {expected_digits}"
            )));
        }
        Ok(decoded)
    }

    /// Consumes `prefix` from the start of the next line.
    async fn expect_prefix(&mut self, prefix: &'static str) -> Result<(), ResumeWireError> {
        if !self.fill().await? {
            return Err(ResumeWireError::Malformed(format!(
                "missing `{prefix}` line"
            )));
        }
        let mut matched = 0;
        while matched < prefix.len() {
            if !self.fill().await? {
                break;
            }
            let wanted = &prefix.as_bytes()[matched..];
            let length = wanted.len().min(self.chunk.len());
            if self.chunk[..length] != wanted[..length] {
                break;
            }
            self.chunk.advance(length);
            matched += length;
        }
        if matched == prefix.len() {
            Ok(())
        } else {
            Err(ResumeWireError::Malformed(format!(
                "expected `{prefix}` line"
            )))
        }
    }

    /// Decodes hex digits into `out` until the line ends.
    ///
    /// Returns the digit count, or `None` once more than `max_digits` digits
    /// arrive; the excess is refused before it is decoded.
    async fn decode_hex_to_line_end(
        &mut self,
        prefix: &'static str,
        max_digits: usize,
        out: &mut Vec<u8>,
    ) -> Result<Option<usize>, ResumeWireError> {
        let mut digits = 0_usize;
        let mut high_nibble = None;
        while self.fill().await? {
            let newline = self.chunk.iter().position(|byte| *byte == b'\n');
            let length = newline.unwrap_or(self.chunk.len());
            if digits.saturating_add(length) > max_digits {
                return Ok(None);
            }
            for &byte in &self.chunk[..length] {
                let nibble = hex_nibble(byte)
                    .ok_or_else(|| format!("invalid hex digit 0x{byte:02x} in `{prefix}` line"))?;
                match high_nibble.take() {
                    None => high_nibble = Some(nibble),
                    Some(high) => out.push((high << 4) | nibble),
                }
            }
            digits += length;
            if newline.is_some() {
                self.chunk.advance(length + 1);
                break;
            }
            self.chunk.advance(length);
        }
        if high_nibble.is_some() {
            return Err(ResumeWireError::Malformed(format!(
                "hex string in `{prefix}` line has odd length {digits}"
            )));
        }
        Ok(Some(digits))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "resume_wire_tests.rs"]
mod tests;
