//! Historical signed-packet replay without live or protected-owner authority.
//!
//! This is the canonical cryptographic replay routine shared by protected
//! owners. Its returned traffic state is historical DATA: this function does
//! not observe a live socket, current policy, journal lock, required floor or
//! current peer, and cannot mint Session, resend or currentness authority.

use crate::projection::{
    CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerResponseDecodeCaptureV1,
    decode_canonical_request_retaining_v1, decode_canonical_response_retaining_v1,
};
use crate::traffic::{BrokerRequestAdmissionCaptureV1, BrokerOutcomeAdmissionCaptureV1};

use crate::{
    BrokerOutcomeAdmissionV1, BrokerRequestAdmissionV1, BrokerSessionDurablePhaseV1,
    BrokerSessionDurableRecordV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};

/// Reports canonical packet, signature, linkage or replay-admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoricalTrafficReplayErrorV1 {
    /// The exact retained packet stream could not advance the traffic machine.
    #[error("invalid historical Broker Session Authentication packet stream")]
    Invalid,
}

/// Replays exact retained signed packets into a historical traffic machine.
///
/// Record order and exact-replay refusal match the original protected recovery
/// routine. The result grants no live session, floor, resend or currentness;
/// a concrete owner must independently retain and recheck that custody.
///
/// # Errors
///
/// Rejects malformed canonical packets, invalid signatures, incompatible
/// transcript/context, discontinuous admission or an unexpected exact replay.
pub fn verify_historical_traffic_records_v1(
    records: &[BrokerSessionDurableRecordV1],
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<BrokerSessionTrafficStateV1, HistoricalTrafficReplayErrorV1> {
    let mut work = HistoricalTrafficReplayCaptureV1::new();
    replay_records(records, transcript, context, &mut work, false)?;
    work.traffic.take().ok_or(HistoricalTrafficReplayErrorV1::Invalid)
}

/// Retains reached historical state, projections, and admissions on refusal.
#[derive(Default)]
pub struct HistoricalTrafficReplayCaptureV1 {
    request: Option<CanonicalBrokerRequestDecodeCaptureV1>,
    outcome: Option<CanonicalBrokerResponseDecodeCaptureV1>,
    request_admission: Option<BrokerRequestAdmissionCaptureV1>,
    outcome_admission: Option<BrokerOutcomeAdmissionCaptureV1>,
    traffic: Option<BrokerSessionTrafficStateV1>,
    initial_transcript: Option<VerifiedBrokerSessionTranscriptV1>,
    initial_failure: Option<crate::BrokerSessionSequenceError>,
    result: Option<Result<(), HistoricalTrafficReplayErrorV1>>,
    attempted: bool,
    closed: Option<HistoricalTrafficReplayErrorV1>,
}

impl HistoricalTrafficReplayCaptureV1 {
    /// Constructs an inert once-only historical DATA owner.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Bounds fixed progress cells and the actually coexisting active row.
    ///
    /// Traffic/transcript destinations, initial refusal, final result and two
    /// once/refusal controls coexist. Each complete positive row physically
    /// drops its projection and admission before the next row can enter.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        let request = CanonicalBrokerRequestDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(BrokerRequestAdmissionCaptureV1::receiving_metadata_cells_v1()?)?;
        let outcome = CanonicalBrokerResponseDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(BrokerOutcomeAdmissionCaptureV1::receiving_metadata_cells_v1()?)?;
        6_usize.checked_add(request.max(outcome))
    }

    /// Borrows the replay refusal while reached lower owners remain resident.
    #[must_use]
    pub fn failure(&self) -> Option<&HistoricalTrafficReplayErrorV1> {
        self.result.as_ref().and_then(|value| value.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the concrete earliest failed projection or sequencing cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.initial_failure.as_ref().map(|cause| cause as _)
            .or_else(|| self.request.as_ref().and_then(|v| v.failure()).map(|e| e as _))
            .or_else(|| self.request_admission.as_ref().and_then(|v| v.cause()))
            .or_else(|| self.outcome.as_ref().and_then(|v| v.failure()).map(|e| e as _))
            .or_else(|| self.outcome_admission.as_ref().and_then(|v| v.cause()))
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Borrows only the complete historical traffic state.
    #[must_use]
    pub fn traffic(&self) -> Option<&BrokerSessionTrafficStateV1> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) { return None; }
        self.traffic.as_ref()
    }

    /// Moves the complete historical state out once without authority.
    ///
    /// # Errors
    /// Refuses an incomplete, failed, or already consumed replay.
    pub fn take_traffic_once(&mut self) -> Result<BrokerSessionTrafficStateV1, HistoricalTrafficReplayErrorV1> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) { return Err(HistoricalTrafficReplayErrorV1::Invalid); }
        self.traffic.take().ok_or(HistoricalTrafficReplayErrorV1::Invalid)
    }
}

/// Replays through the same sequencing engine into a caller-owned DATA capture.
///
/// # Errors
/// Returns the ordinary historical replay refusal, or refuses repeated entry.
pub fn verify_historical_traffic_records_retaining_v1(
    records: &[BrokerSessionDurableRecordV1],
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    capture: &mut HistoricalTrafficReplayCaptureV1,
) -> Result<(), HistoricalTrafficReplayErrorV1> {
    if capture.attempted {
        capture.closed.get_or_insert(HistoricalTrafficReplayErrorV1::Invalid);
        return Err(HistoricalTrafficReplayErrorV1::Invalid);
    }
    capture.attempted = true;
    let result = replay_records(records, transcript, context, capture, true);
    capture.result = Some(result);
    result
}

fn replay_records(
    records: &[BrokerSessionDurableRecordV1],
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    work: &mut HistoricalTrafficReplayCaptureV1,
    retaining: bool,
) -> Result<(), HistoricalTrafficReplayErrorV1> {
    work.initial_transcript = Some(transcript.clone());
    work.traffic = Some(match BrokerSessionTrafficStateV1::from_provisional_owner(
        &mut work.initial_transcript,
    ) {
        Ok(traffic) => traffic,
        Err(cause) => {
            if retaining { work.initial_failure = Some(cause); }
            return Err(HistoricalTrafficReplayErrorV1::Invalid);
        }
    });
    for record in records {
        match record.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => {
                let mut ordinary_request = None;
                let request = if retaining {
                    work.request = Some(CanonicalBrokerRequestDecodeCaptureV1::new());
                    let capture = work.request.as_mut().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                    decode_canonical_request_retaining_v1(record.request_packet(), capture)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                    capture.model().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?
                } else {
                    ordinary_request = Some(decode_canonical_request_v1(record.request_packet())
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?);
                    ordinary_request.as_ref().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?
                };
                let traffic = work.traffic.as_ref().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                if retaining {
                    work.request_admission = Some(BrokerRequestAdmissionCaptureV1::new());
                    let admission = work.request_admission.as_mut().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                    traffic.admit_request_retaining(request, record.request_id(), record.maximum_response_bytes(), context, admission)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                    if !matches!(admission.admission(), Some(BrokerRequestAdmissionV1::New { .. })) {
                        return Err(HistoricalTrafficReplayErrorV1::Invalid);
                    }
                    if let BrokerRequestAdmissionV1::New { next_state, .. } = admission.take_admission_once()
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)? {
                        work.traffic = Some(*next_state);
                    }
                } else {
                    work.traffic = Some(match traffic.admit_request(request, record.request_id(), record.maximum_response_bytes(), context)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)? {
                        BrokerRequestAdmissionV1::New { next_state, .. } => *next_state,
                        BrokerRequestAdmissionV1::ExactReplay(_) => return Err(HistoricalTrafficReplayErrorV1::Invalid),
                    });
                }
                // The actual next state is parked before successful row scratch disposal.
                drop(work.request_admission.take());
                drop(work.request.take());
                drop(ordinary_request);
            }
            BrokerSessionDurablePhaseV1::Terminal => {
                let packet = record.outcome_packet().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                let mut ordinary_outcome = None;
                let outcome = if retaining {
                    work.outcome = Some(CanonicalBrokerResponseDecodeCaptureV1::new());
                    let capture = work.outcome.as_mut().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                    decode_canonical_response_retaining_v1(packet, capture)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                    capture.model().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?
                } else {
                    ordinary_outcome = Some(decode_canonical_response_v1(packet)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?);
                    ordinary_outcome.as_ref().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?
                };
                let traffic = work.traffic.as_ref().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                if retaining {
                    work.outcome_admission = Some(BrokerOutcomeAdmissionCaptureV1::new());
                    let admission = work.outcome_admission.as_mut().ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                    traffic.admit_outcome_retaining(outcome, context, admission)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                    if !matches!(admission.admission(), Some(BrokerOutcomeAdmissionV1::New { .. })) {
                        return Err(HistoricalTrafficReplayErrorV1::Invalid);
                    }
                    if let BrokerOutcomeAdmissionV1::New { next_state, .. } = admission.take_admission_once()
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)? {
                        work.traffic = Some(*next_state);
                    }
                } else {
                    work.traffic = Some(match traffic.admit_outcome(outcome, context)
                        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)? {
                        BrokerOutcomeAdmissionV1::New { next_state, .. } => *next_state,
                        BrokerOutcomeAdmissionV1::ExactReplay(_) => return Err(HistoricalTrafficReplayErrorV1::Invalid),
                    });
                }
                drop(work.outcome_admission.take());
                drop(work.outcome.take());
                drop(ordinary_outcome);
            }
        }
    }
    Ok(())
}
