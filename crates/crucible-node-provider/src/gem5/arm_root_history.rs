//! Retains actual ARM control requests, native replies and preparation transcripts.
//!
//! These bounded data records are archive evidence, never current peer authority.
//! Requests are recorded before the first wire byte; replies are preserved before
//! interpretation. A vanished source route is lineage, not a filesystem input.
//!
//! The closed archive envelope retains transport order; packet byte arrays and
//! preparation records are abbreviated in this schematic example:
//!
//! ```text
//! {"schema":"crucible.gem5.arm-root-control-history.v1",
//!  "packets":[{"kind":"request","bytes":[...]}],"sessions":[...]}
//! ```

use crucible_node_contract::{ContentRef, HashRef, Id, U64, Validate, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ArmRootPreparedSession, GEM5_NATIVE_FRAME_BYTES};
use crate::ProviderError;

const MAX_PACKETS: usize = 4096;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SESSIONS: usize = 256;

/// Identifies the direction and meaning of an original control packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmRootControlKind {
    /// Retains a complete original request before any transport effect.
    Request,
    /// Retains a native response before caller interpretation.
    Response,
    /// Retains genuine original, captured or reconstructed native readiness.
    Ready,
}

/// Retains one exact original JSON body without rewriting its formatting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRootControlPacket {
    /// Distinguishes original requests, ordinary replies and readiness.
    pub kind: ArmRootControlKind,
    /// Retains every original wire byte, excluding the derivable framing header.
    pub bytes: Vec<u8>,
}

/// Retains preparation provenance as inert data beneath signed archive ancestry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRootPreparationRecord {
    /// Retains the original authenticated session token.
    pub token: Id,
    /// Pins its actual native Ready body in the control packet ledger.
    pub packet: ContentRef,
    /// Pins the exact original owning-session transcript.
    pub transcript: ContentRef,
    /// Retains the transcript bytes without manufacturing new kernel identities.
    pub transcript_bytes: Vec<u8>,
}

/// Retains bounded complete known control history across native reconstructions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRootControlHistory {
    /// Selects the distinct model-aware host continuation edition.
    pub schema: String,
    /// Retains packets in their actual original transport order.
    pub packets: Vec<ArmRootControlPacket>,
    /// Retains each genuine original or reconstructed session transcript.
    pub sessions: Vec<ArmRootPreparationRecord>,
}

/// Parses an inert transcript without exposing a kernel authority constructor.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivedSessionTranscript {
    format: String,
    version: u64,
    origin: String,
    #[serde(default)]
    source_capture: Option<Id>,
    pid: u32,
    start_ticks: String,
    source_scope: HashRef,
    profile: ContentRef,
    ready_packet: ContentRef,
    owner: Id,
    incarnation: Id,
    generation: U64,
}

impl ArmRootControlHistory {
    pub(crate) fn empty() -> Self {
        Self {
            schema: "crucible.gem5.arm-root-control-history.v1".to_owned(),
            packets: Vec::new(),
            sessions: Vec::new(),
        }
    }

    pub(crate) fn reserve(&mut self, count: usize) -> Result<(), ProviderError> {
        let worst_bytes = count
            .checked_mul(GEM5_NATIVE_FRAME_BYTES)
            .and_then(|extra| self.bytes().ok()?.checked_add(extra));
        if self
            .packets
            .len()
            .checked_add(count)
            .is_none_or(|length| length > MAX_PACKETS)
            || worst_bytes.is_none_or(|length| length > MAX_BYTES)
        {
            return Err(ProviderError::ResourceExhausted(
                "ARM original control-history credit",
            ));
        }
        self.packets
            .try_reserve(count)
            .map_err(|_| ProviderError::ResourceExhausted("ARM reserved control-history packets"))
    }

    pub(crate) fn reserve_session(&mut self) -> Result<(), ProviderError> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(ProviderError::ResourceExhausted(
                "ARM original preparation-history credit",
            ));
        }
        self.sessions.try_reserve(1).map_err(|_| {
            ProviderError::ResourceExhausted("ARM reserved preparation-history storage")
        })
    }

    pub(crate) fn request(&mut self, request: &Value) -> Result<(), ProviderError> {
        self.push(
            ArmRootControlKind::Request,
            canonical::canonical_json(request)?,
        )
    }

    pub(crate) fn push(
        &mut self,
        kind: ArmRootControlKind,
        bytes: Vec<u8>,
    ) -> Result<(), ProviderError> {
        if self.packets.len() >= MAX_PACKETS
            || bytes.is_empty()
            || bytes.len() > GEM5_NATIVE_FRAME_BYTES
            || self
                .bytes()?
                .checked_add(bytes.len())
                .is_none_or(|total| total > MAX_BYTES)
        {
            return Err(ProviderError::ResourceExhausted(
                "ARM retained control-history extent",
            ));
        }
        self.packets.push(ArmRootControlPacket { kind, bytes });
        Ok(())
    }

    pub(crate) fn prepared(
        &mut self,
        session: &ArmRootPreparedSession,
    ) -> Result<(), ProviderError> {
        let record = ArmRootPreparationRecord {
            token: session.token().clone(),
            packet: session.packet().0.clone(),
            transcript: session.transcript().0.clone(),
            transcript_bytes: session.transcript().1.to_owned(),
        };
        if self.sessions.len() >= MAX_SESSIONS
            || self
                .bytes()?
                .checked_add(record.transcript_bytes.len())
                .is_none_or(|total| total > MAX_BYTES)
        {
            return Err(ProviderError::ResourceExhausted(
                "ARM retained preparation-history extent",
            ));
        }
        self.sessions.push(record);
        Ok(())
    }

    fn bytes(&self) -> Result<usize, ProviderError> {
        self.packets
            .iter()
            .map(|packet| packet.bytes.len())
            .chain(
                self.sessions
                    .iter()
                    .map(|session| session.transcript_bytes.len()),
            )
            .try_fold(0usize, |total, length| {
                total
                    .checked_add(length)
                    .ok_or(ProviderError::ResourceExhausted(
                        "ARM control-history byte extent",
                    ))
            })
    }

    /// Validates closed original packet ordering and transcript commitments.
    ///
    /// This verifies inert consistency only. An installed signed-source verifier,
    /// fresh kernel peer and current native audit remain mandatory for restoration.
    ///
    /// # Errors
    /// Refuses truncated/altered packets, unresolved requests, foreign dialects,
    /// substituted transcript bodies and count or byte-credit exhaustion.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema != "crucible.gem5.arm-root-control-history.v1"
            || self.packets.is_empty()
            || self.packets.len() > MAX_PACKETS
            || self.sessions.is_empty()
            || self.sessions.len() > MAX_SESSIONS
            || self.bytes()? > MAX_BYTES
        {
            return Err(ProviderError::Frame("ARM archived control-history scope"));
        }
        let mut pending = None;
        let mut capture_ready = false;
        let mut readiness = Vec::new();
        for packet in &self.packets {
            let value = canonical::parse_json(&packet.bytes, GEM5_NATIVE_FRAME_BYTES)?;
            match packet.kind {
                ArmRootControlKind::Request => {
                    if pending.is_some()
                        || capture_ready
                        || canonical::canonical_json(&value)? != packet.bytes
                    {
                        return Err(ProviderError::Correlation(
                            "ARM original request ordering or bytes differ",
                        ));
                    }
                    pending = Some(value);
                }
                ArmRootControlKind::Response => {
                    let original = pending
                        .take()
                        .ok_or(ProviderError::Correlation("ARM orphan original response"))?;
                    if original.get("kind").is_none()
                        || original.get("kind") == Some(&serde_json::json!("restore_bind"))
                    {
                        return Err(ProviderError::Correlation(
                            "ARM response substituted for Ready",
                        ));
                    }
                    capture_ready = value.get("kind") == Some(&serde_json::json!("capture_ready"));
                    if capture_ready && original.get("kind") != Some(&serde_json::json!("capture"))
                    {
                        return Err(ProviderError::Correlation(
                            "ARM capture reply original differs",
                        ));
                    }
                }
                ArmRootControlKind::Ready => {
                    if let Some(original) = pending.take() {
                        if original.get("schema")
                            != Some(&serde_json::json!("crucible.gem5.arm-linux-native/1"))
                            && original.get("kind") != Some(&serde_json::json!("restore_bind"))
                        {
                            return Err(ProviderError::Correlation("ARM Ready original differs"));
                        }
                    } else if !capture_ready {
                        return Err(ProviderError::Correlation(
                            "ARM unsolicited Ready omitted original capture",
                        ));
                    }
                    if value.get("schema")
                        != Some(&serde_json::json!("crucible.gem5.arm-linux-native/1"))
                    {
                        return Err(ProviderError::Correlation(
                            "ARM historical Ready dialect differs",
                        ));
                    }
                    readiness.push((
                        canonical::content_ref(&packet.bytes, "application/json")?,
                        value,
                    ));
                    capture_ready = false;
                }
            }
        }
        if pending.is_some() || capture_ready {
            return Err(ProviderError::Conflict(
                "ARM archived original control remains uncertain",
            ));
        }
        let mut previous_ready = None;
        for (number, session) in self.sessions.iter().enumerate() {
            session.token.validate()?;
            session.transcript.verify(&session.transcript_bytes)?;
            let index = readiness
                .iter()
                .position(|(reference, _)| reference == &session.packet)
                .ok_or(ProviderError::Correlation(
                    "ARM archived original Ready body omitted",
                ))?;
            if previous_ready.is_some_and(|previous| index <= previous) {
                return Err(ProviderError::Correlation(
                    "ARM preparation session ordering differs",
                ));
            }
            previous_ready = Some(index);
            let ready = &readiness[index].1;
            let body: ArchivedSessionTranscript = serde_json::from_value(canonical::parse_json(
                &session.transcript_bytes,
                GEM5_NATIVE_FRAME_BYTES,
            )?)
            .map_err(|_| ProviderError::Frame("ARM archived session transcript shape"))?;
            body.owner.validate()?;
            body.incarnation.validate()?;
            body.source_scope.validate()?;
            body.profile.validate()?;
            let expected_origin = if number == 0 { "original" } else { "restored" };
            if body.format != "crucible.gem5.arm-root-prepared-session"
                || body.version != 1
                || body.origin != expected_origin
                || body.source_capture.is_some() != (number > 0)
                || body.pid == 0
                || body.generation.get() == 0
                || body.start_ticks.is_empty()
                || body.start_ticks.len() > 20
                || !body.start_ticks.bytes().all(|byte| byte.is_ascii_digit())
                || body.ready_packet != session.packet
                || ready.get("kind").and_then(Value::as_str) != Some("ready")
                || ready.get("continuation").and_then(Value::as_str) != Some(expected_origin)
                || ready.get("owner")
                    != Some(
                        &serde_json::to_value(&body.owner)
                            .map_err(|_| ProviderError::Frame("ARM archived owner encoding"))?,
                    )
                || ready.get("incarnation")
                    != Some(
                        &serde_json::to_value(&body.incarnation).map_err(|_| {
                            ProviderError::Frame("ARM archived incarnation encoding")
                        })?,
                    )
                || ready.get("generation")
                    != Some(
                        &serde_json::to_value(body.generation).map_err(|_| {
                            ProviderError::Frame("ARM archived generation encoding")
                        })?,
                    )
                || session.token
                    != Id::new(format!(
                        "gem5/arm-root/prepared/{}",
                        session.transcript.hash.digest
                    ))?
            {
                return Err(ProviderError::Correlation(
                    "ARM historical session transcript differs",
                ));
            }
            if let Some(capture) = body.source_capture {
                capture.validate()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fixture_for_archive_test() -> ArmRootControlHistory {
    tests::fixture()
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Invalid archive fixtures must fail assertions.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn fixture() -> ArmRootControlHistory {
        let bootstrap = json!({"schema":"crucible.gem5.arm-linux-native/1","owner":"original"});
        let ready_bytes = canonical::canonical_json(
            &json!({"kind":"ready","schema":"crucible.gem5.arm-linux-native/1","continuation":"original","owner":"owner","incarnation":"incarnation","generation":"1"}),
        )
        .unwrap();
        let packet = canonical::content_ref(&ready_bytes, "application/json").unwrap();
        let transcript_bytes = canonical::canonical_json(&json!({
            "format":"crucible.gem5.arm-root-prepared-session","version":1,"origin":"original",
            "ready_packet":packet,"owner":"owner","incarnation":"incarnation","generation":"1",
            "pid":42,"start_ticks":"1234","source_scope":canonical::content_ref(b"scope","application/json").unwrap().hash,
            "profile":canonical::content_ref(b"profile","application/json").unwrap(),
        }))
        .unwrap();
        let transcript = canonical::content_ref(&transcript_bytes, "application/json").unwrap();
        ArmRootControlHistory {
            schema: "crucible.gem5.arm-root-control-history.v1".to_owned(),
            packets: vec![
                ArmRootControlPacket {
                    kind: ArmRootControlKind::Request,
                    bytes: canonical::canonical_json(&bootstrap).unwrap(),
                },
                ArmRootControlPacket {
                    kind: ArmRootControlKind::Ready,
                    bytes: ready_bytes,
                },
            ],
            sessions: vec![ArmRootPreparationRecord {
                token: Id::new(format!("gem5/arm-root/prepared/{}", transcript.hash.digest))
                    .unwrap(),
                packet,
                transcript,
                transcript_bytes,
            }],
        }
    }

    #[test]
    fn original_ready_and_session_bodies_survive_without_live_authority() {
        let source = fixture();
        source.validate().unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(&source).unwrap()).unwrap();
        let restored: ArmRootControlHistory = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, source);
    }

    #[test]
    fn truncated_original_request_and_substituted_ready_are_refused() {
        for change in 0..5 {
            let mut source = fixture();
            match change {
                0 => {
                    source.packets.pop();
                }
                1 => source.packets[1].kind = ArmRootControlKind::Response,
                2 => source.packets[1].bytes = b"{}".to_vec(),
                3 => source.sessions[0].transcript_bytes = b"{}".to_vec(),
                _ => {
                    source.sessions[0].packet =
                        canonical::content_ref(b"other", "application/json").unwrap()
                }
            }
            assert!(source.validate().is_err(), "change {change}");
        }
    }

    #[test]
    fn self_committed_session_metadata_cannot_change_original_provenance() {
        for change in 0..8 {
            let mut history = fixture();
            let session = &mut history.sessions[0];
            let mut body: Value = serde_json::from_slice(&session.transcript_bytes).unwrap();
            match change {
                0 => body["owner"] = json!("different"),
                1 => body["incarnation"] = json!("different"),
                2 => body["generation"] = json!("2"),
                3 => body["origin"] = json!("restored"),
                4 => body["source_capture"] = json!("foreign"),
                5 => body["pid"] = json!(0),
                6 => body["start_ticks"] = json!("not-kernel-ticks"),
                _ => body["unexpected"] = json!(true),
            }
            session.transcript_bytes = canonical::canonical_json(&body).unwrap();
            session.transcript =
                canonical::content_ref(&session.transcript_bytes, "application/json").unwrap();
            session.token = Id::new(format!(
                "gem5/arm-root/prepared/{}",
                session.transcript.hash.digest
            ))
            .unwrap();
            assert!(history.validate().is_err(), "change {change}");
        }
    }

    #[test]
    fn packet_and_session_credit_is_reserved_before_any_append() {
        let mut source = fixture();
        let previous = source.clone();
        assert!(source.reserve(MAX_PACKETS).is_err());
        assert_eq!(source, previous);
        source.sessions = vec![source.sessions[0].clone(); MAX_SESSIONS];
        assert!(source.reserve_session().is_err());
    }
}
