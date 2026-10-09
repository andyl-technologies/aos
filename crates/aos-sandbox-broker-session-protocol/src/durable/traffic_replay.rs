//! Historical signed-packet replay without live or protected-owner authority.
//!
//! This is the canonical cryptographic replay routine shared by protected
//! owners. Its returned traffic state is historical DATA: this function does
//! not observe a live socket, current policy, journal lock, required floor or
//! current peer, and cannot mint Session, resend or currentness authority.

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
    let mut traffic = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())
        .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
    for record in records {
        match record.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => {
                let request = decode_canonical_request_v1(record.request_packet())
                    .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                traffic = match traffic
                    .admit_request(
                        &request,
                        record.request_id(),
                        record.maximum_response_bytes(),
                        context,
                    )
                    .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?
                {
                    BrokerRequestAdmissionV1::New { next_state, .. } => *next_state,
                    BrokerRequestAdmissionV1::ExactReplay(_) => {
                        return Err(HistoricalTrafficReplayErrorV1::Invalid);
                    }
                };
            }
            BrokerSessionDurablePhaseV1::Terminal => {
                let packet = record
                    .outcome_packet()
                    .ok_or(HistoricalTrafficReplayErrorV1::Invalid)?;
                let outcome = decode_canonical_response_v1(packet)
                    .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?;
                traffic = match traffic
                    .admit_outcome(&outcome, context)
                    .map_err(|_| HistoricalTrafficReplayErrorV1::Invalid)?
                {
                    BrokerOutcomeAdmissionV1::New { next_state, .. } => *next_state,
                    BrokerOutcomeAdmissionV1::ExactReplay(_) => {
                        return Err(HistoricalTrafficReplayErrorV1::Invalid);
                    }
                };
            }
        }
    }
    Ok(traffic)
}
