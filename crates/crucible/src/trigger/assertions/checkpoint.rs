//! Canonical assertion continuation capture, admitted CBOR, and atomic restore.
//!
//! The envelope remains `crucible.host-assertion-continuation.v2\0` followed by
//! canonical CBOR. Only mutable state crosses this boundary; immutable property
//! definitions and resolution tables remain shared by the evaluator.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeCustody};
use std::io::{self, Write};

const MAGIC: &[u8] = b"crucible.host-assertion-continuation.v2\0";
const MAX_BYTES: usize = 268_435_456;

/// Process-independent continuation of the streaming host assertion evaluator.
#[derive(Debug)]
pub struct HostAssertionEvaluatorCheckpoint {
    wire: HostAssertionEvaluatorWire,
    custody: DecodeCustody,
}

/// Canonical continuation bytes retained with their original allocation credit.
#[derive(Debug, PartialEq, Eq)]
pub struct HostAssertionCheckpointBytes {
    bytes: Vec<u8>,
    custody: DecodeCustody,
}

impl HostAssertionCheckpointBytes {
    /// Borrows the complete canonical envelope.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers bytes and their custody into a longer-lived continuation owner.
    ///
    /// The receiving owner must close its bytes before dropping the custody.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, DecodeCustody) {
        (self.bytes, self.custody)
    }
}

impl std::ops::Deref for HostAssertionCheckpointBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::ops::DerefMut for HostAssertionCheckpointBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAssertionEvaluatorWire {
    states: Vec<HostAssertionStateWire>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Vec<u8>>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    last_prefix: Option<EventLogOffset>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAssertionStateWire {
    assertion: AssertionId,
    lifecycle: PropertyLifecycleState,
    terminal: Option<HostAssertionTerminal>,
    evaluated: bool,
    eventually_triggered: bool,
    eventually_satisfied_at: Option<VirtualTime>,
    pending_eventually: Vec<EventuallyObligation>,
    proximity: Option<HostAssertionProximityMinimum>,
}

impl HostAssertionEvaluator {
    /// Captures mutable continuation state under the original resource authority.
    ///
    /// # Errors
    /// Returns the original metadata refusal before publishing a partial copy.
    pub fn checkpoint(
        &self,
    ) -> Result<HostAssertionEvaluatorCheckpoint, HostAssertionCheckpointError> {
        let _original = self._definition_custody.enter();
        let child = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = child.enter();
        let mut states = Vec::new();
        for state in &self.states {
            owned_storage::reserve_slot(&mut states).map_err(engine)?;
            states.push(HostAssertionStateWire {
                assertion: owned_storage::copy_assertion_id(&state.assertion.id).map_err(engine)?,
                lifecycle: state.lifecycle,
                terminal: owned_storage::copy_json(&state.terminal).map_err(engine)?,
                evaluated: state.evaluated,
                eventually_triggered: state.eventually_triggered,
                eventually_satisfied_at: state.eventually_satisfied_at,
                pending_eventually: owned_storage::copy_json(&state.pending_eventually)
                    .map_err(engine)?,
                proximity: state.proximity.clone(),
            });
        }
        let mut once_latches = Vec::new();
        for predicate in &self.once_latches {
            owned_storage::reserve_slot(&mut once_latches).map_err(engine)?;
            once_latches.push(predicate.to_compact_binary_admitted().map_err(engine)?);
        }
        let wire = HostAssertionEvaluatorWire {
            states,
            guest_marker_states: owned_storage::copy_json(&self.guest_marker_states)
                .map_err(engine)?,
            once_latches,
            terminal_quiescence: self
                .terminal_quiescence
                .as_deref()
                .map(owned_storage::copy_json)
                .transpose()
                .map_err(engine)?,
            last_prefix: self.last_position.map(|position| position.offset),
        };
        owned_storage::check().map_err(engine)?;
        Ok(HostAssertionEvaluatorCheckpoint {
            wire,
            custody: child.custody(),
        })
    }
}

impl HostAssertionEvaluatorCheckpoint {
    /// Compares every assertion continuation field without copying its custody.
    ///
    /// Each checkpoint retains its own original allocation authority. Those
    /// operational credits do not contribute to logical assertion equality.
    #[must_use]
    pub fn same_continuation(&self, other: &Self) -> bool {
        self.wire == other.wire
    }

    /// Encodes the complete assertion continuation canonically.
    ///
    /// The exact output is counted before allocating; the write pass cannot grow
    /// beyond that count. Returned bytes own a separate child account, including
    /// when they outlive this checkpoint or move into a continuation owner.
    ///
    /// # Errors
    /// Returns malformed/noncanonical state, size overflow or original admission.
    pub fn canonical_bytes(
        &self,
    ) -> Result<HostAssertionCheckpointBytes, HostAssertionCheckpointError> {
        let _original = self.custody.enter();
        let child = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = child.enter();
        validate(&self.wire)?;
        let bytes = encode(&self.wire)?;
        Ok(HostAssertionCheckpointBytes {
            bytes,
            custody: child.custody(),
        })
    }

    /// Decodes and validates one canonical assertion continuation.
    ///
    /// # Errors
    /// Returns unsupported, malformed, noncanonical or over-limit input, and
    /// preserves the original typed metadata refusal separately from CBOR errors.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HostAssertionCheckpointError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(HostAssertionCheckpointError::Version)?;
        if payload.len() > MAX_BYTES {
            return Err(HostAssertionCheckpointError::Limit);
        }
        let child = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = child.enter();
        let _parser_bank = child
            .reserve_scratch_bytes(parser_peak(payload.len()).map_err(admission)?)
            .map_err(admission)?;
        // Ciborium's default reader owns a fixed 4096-byte stack buffer. Its
        // scalar/error heap bank above precedes the parser and all its objects.
        let decoded: BudgetedWire =
            ciborium::de::from_reader(payload).map_err(|_| recorded_or_malformed())?;
        let checkpoint = Self {
            wire: decoded.0,
            custody: child.custody(),
        };
        validate(&checkpoint.wire)?;
        // Comparison is streamed into the original bytes, so canonicality does
        // not allocate another complete encoded image.
        let mut compare = Comparison {
            expected: &bytes[MAGIC.len()..],
            position: 0,
        };
        ciborium::ser::into_writer(&checkpoint.wire, &mut compare)
            .map_err(|_| HostAssertionCheckpointError::Noncanonical)?;
        if compare.position != compare.expected.len() {
            return Err(HostAssertionCheckpointError::Noncanonical);
        }
        owned_storage::check().map_err(engine)?;
        Ok(checkpoint)
    }

    /// Restores mutable state into an evaluator with the same assertion identities.
    ///
    /// # Errors
    /// Returns binding, malformed or original admission errors. Failure leaves
    /// every evaluator field unchanged; definitions and tables are never copied.
    pub fn restore_into(
        &self,
        evaluator: &mut HostAssertionEvaluator,
        current_prefix: &ConditionEventLogPrefix,
    ) -> Result<(), HostAssertionCheckpointError> {
        let _original = evaluator._definition_custody.enter();
        let child = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = child.enter();
        validate(&self.wire)?;
        if self.wire.states.len() != evaluator.states.len()
            || self
                .wire
                .states
                .iter()
                .zip(&evaluator.states)
                .any(|(wire, state)| wire.assertion != state.assertion.id)
            || self.wire.last_prefix.is_some()
                && self.wire.last_prefix != Some(current_prefix.event_log_offset())
        {
            return Err(HostAssertionCheckpointError::Binding);
        }
        let mut states = Vec::new();
        for (state, wire) in evaluator.states.iter().zip(&self.wire.states) {
            owned_storage::reserve_slot(&mut states).map_err(engine)?;
            states.push(HostAssertionState {
                assertion: std::sync::Arc::clone(&state.assertion),
                lifecycle: wire.lifecycle,
                terminal: owned_storage::copy_json(&wire.terminal).map_err(engine)?,
                evaluated: wire.evaluated,
                eventually_triggered: wire.eventually_triggered,
                eventually_satisfied_at: wire.eventually_satisfied_at,
                pending_eventually: owned_storage::copy_json(&wire.pending_eventually)
                    .map_err(engine)?,
                proximity: wire.proximity.clone(),
            });
        }
        let guest_marker_states =
            owned_storage::copy_json(&self.wire.guest_marker_states).map_err(engine)?;
        let mut once_latches = Vec::new();
        for bytes in &self.wire.once_latches {
            owned_storage::reserve_slot(&mut once_latches).map_err(engine)?;
            once_latches.push(Predicate::from_compact_binary(bytes).map_err(engine)?);
        }
        let terminal_quiescence = self
            .wire
            .terminal_quiescence
            .as_ref()
            .map(|value| {
                owned_storage::reserve_arc::<SchedulerQuiescence>()?;
                Ok::<_, EngineError>(std::sync::Arc::new(owned_storage::copy_json(value)?))
            })
            .transpose()
            .map_err(engine)?;
        owned_storage::check().map_err(engine)?;
        evaluator.states = states;
        evaluator.guest_marker_states = guest_marker_states;
        evaluator.once_latches = once_latches;
        evaluator.terminal_quiescence = terminal_quiescence;
        evaluator.last_position = self
            .wire
            .last_prefix
            .map(|_| HostAssertionPrefixPosition::from_prefix(current_prefix));
        evaluator.evaluation_failure = None;
        // Old fields close above before their credit is replaced.
        evaluator._mutable_custody = child.custody();
        Ok(())
    }
}

fn validate(wire: &HostAssertionEvaluatorWire) -> Result<(), HostAssertionCheckpointError> {
    if !wire
        .states
        .windows(2)
        .all(|pair| pair[0].assertion < pair[1].assertion)
        || !wire
            .guest_marker_states
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(HostAssertionCheckpointError::Noncanonical);
    }
    for predicate in &wire.once_latches {
        // Validation owns no retained predicate. Its temporary decoded fields
        // close before the independent validation account returns its credits.
        let validation = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = validation.enter();
        Predicate::from_compact_binary(predicate).map_err(engine)?;
    }
    Ok(())
}

struct BudgetedWire(HostAssertionEvaluatorWire);
impl<'de> serde::Deserialize<'de> for BudgetedWire {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let budget = crate::owned_decode::current_budget().ok_or_else(|| {
            serde::de::Error::custom("original decoded metadata authority is required")
        })?;
        let wire = crate::owned_decode::deserialize_with_budget(decoder, &budget)?;
        Ok(Self(wire))
    }
}

fn parser_peak(input_bytes: usize) -> Result<u64, DecodeAdmissionError> {
    let bytes = u64::try_from(input_bytes).map_err(DecodeAdmissionError::new)?;
    // Pinned ciborium 0.2.2 de/mod.rs scalar accumulation (341,384,415) appends
    // consumed bytes. One active scalar's capacity C <= max(2*input,8); old/new
    // growth overlap <= 2*C. Tags, maps, segments and recursion own inline state.
    let scalar = bytes
        .checked_mul(2)
        .map(|n| n.max(8))
        .and_then(|n| n.checked_mul(2));
    // This closed wire contains only derived visitors, primitive numbers and
    // strings/bytes. Its largest field list is GuestMarkerAssertionState (12);
    // its largest variant list is SchedulerQuiescenceBlocker (11). Every field,
    // variant and derived type name is below 64 ASCII bytes. Serde 1.0.228
    // de::OneOf adds at most four punctuation bytes/name plus a fixed phrase.
    // A refusal formats one expectation, rather than concatenating recursive
    // contexts. The 32-name bank covers both lists independently of payload.
    // The remaining fixed bank covers Serde/Ciborium phrases, a complete f64
    // decimal display (including subnormals), and integer/length diagnostics.
    const FIXED_DIAGNOSTIC_BYTES: u64 = 32 * (64 + 4) + 256 + 1024 + 128;
    // Unexpected scalar text can escape each consumed byte to at most six ASCII
    // bytes. Identifier parsing is also capped by Ciborium's 4096-byte buffer.
    // Ciborium Error::custom owns one String; old/new growth overlap is bounded
    // by four times the complete rendered-length bound. The admission adapter
    // emits a fixed marker and never formats an arbitrary provider cause here.
    let diagnostic = bytes
        .checked_mul(6)
        .and_then(|n| n.checked_add(FIXED_DIAGNOSTIC_BYTES))
        .and_then(|n| n.checked_mul(4));
    scalar
        .and_then(|n| n.checked_add(diagnostic?))
        .ok_or_else(|| DecodeAdmissionError::new(io::Error::other("CBOR parser bank overflow")))
}

fn encode(wire: &HostAssertionEvaluatorWire) -> Result<Vec<u8>, HostAssertionCheckpointError> {
    let mut count = Counter(0);
    ciborium::ser::into_writer(wire, &mut count)
        .map_err(|_| HostAssertionCheckpointError::Limit)?;
    let length = MAGIC
        .len()
        .checked_add(count.0)
        .ok_or(HostAssertionCheckpointError::Limit)?;
    let mut bytes = Vec::new();
    crate::owned_decode::reserve_vec(&mut bytes, length).map_err(admission)?;
    bytes.extend_from_slice(MAGIC);
    let mut output = Output { bytes, length };
    ciborium::ser::into_writer(wire, &mut output)
        .map_err(|_| HostAssertionCheckpointError::Malformed)?;
    if output.bytes.len() != length {
        return Err(HostAssertionCheckpointError::Malformed);
    }
    Ok(output.bytes)
}

struct Counter(usize);
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| io::Error::other("assertion checkpoint size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Output {
    bytes: Vec<u8>,
    length: usize,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.length.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "assertion checkpoint changed between passes",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Comparison<'a> {
    expected: &'a [u8],
    position: usize,
}
impl Write for Comparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("CBOR comparison overflow"))?;
        if self.expected.get(self.position..end) != Some(bytes) {
            return Err(io::Error::other("noncanonical assertion CBOR"));
        }
        self.position = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Error returned by assertion continuation encoding and restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAssertionCheckpointError {
    /// The envelope version is unsupported.
    Version,
    /// The payload is malformed.
    Malformed,
    /// The payload is valid but not canonical.
    Noncanonical,
    /// The payload exceeds its hard bound.
    Limit,
    /// The continuation does not bind to the properties or prefix.
    Binding,
    /// Original metadata admission refused; custody outlives its typed cause.
    Admission {
        /// Original typed resource refusal.
        source: DecodeAdmissionError,
        /// Retained account for already allocated error/continuation fields.
        custody: DecodeCustody,
    },
}
impl fmt::Display for HostAssertionCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => f.write_str("unsupported host-assertion checkpoint version"),
            Self::Malformed => f.write_str("malformed host-assertion checkpoint"),
            Self::Noncanonical => f.write_str("noncanonical host-assertion checkpoint"),
            Self::Limit => f.write_str("host-assertion checkpoint exceeds its size limit"),
            Self::Binding => f.write_str("host-assertion checkpoint binding mismatch"),
            Self::Admission { source, .. } => {
                write!(f, "host-assertion checkpoint admission: {source}")
            }
        }
    }
}
impl Error for HostAssertionCheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission { source, .. } => Some(source),
            _ => None,
        }
    }
}
fn admission(source: DecodeAdmissionError) -> HostAssertionCheckpointError {
    HostAssertionCheckpointError::Admission {
        source,
        custody: crate::owned_decode::current_custody().unwrap_or_default(),
    }
}
fn engine(source: EngineError) -> HostAssertionCheckpointError {
    match source {
        EngineError::ArtifactDecodeAdmission { source } => admission(source),
        _ => recorded_or_malformed(),
    }
}
fn recorded_or_malformed() -> HostAssertionCheckpointError {
    match crate::owned_decode::current_budget().map(|budget| budget.failure()) {
        Some(Ok(Some(source))) | Some(Err(source)) => admission(source),
        _ => HostAssertionCheckpointError::Malformed,
    }
}

#[cfg(test)]
mod tests;
