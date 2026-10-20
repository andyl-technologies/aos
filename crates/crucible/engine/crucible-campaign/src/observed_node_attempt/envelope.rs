//! Explicit schema classification without widening legacy campaign record formats.

use super::*;

pub(crate) enum ObservedEnvelopeRecord {
    Request(ObservedAttemptRequest),
    Result(ObservedAttemptResult),
    State(ObservedAttemptState),
    Ledger(ObservedLedger),
    Reservation(ObservedDispatchReservation),
}

impl ObservedEnvelopeRecord {
    pub(crate) fn decode(
        id: ContentId,
        envelope: &ContentEnvelope,
    ) -> Result<Option<Self>, CampaignCodecError> {
        let record = match envelope.schema_name() {
            "crucible.observed-node-request" => Self::Request(
                ObservedAttemptRequest::from_canonical_bytes(envelope.body())?,
            ),
            "crucible.observed-node-result" => Self::Result(
                ObservedAttemptResult::from_canonical_bytes(envelope.body())?,
            ),
            "crucible.observed-node-state" => Self::State(codec::decode_bounded(
                envelope.body(),
                MAX_OBSERVED_RECORD_BYTES,
                "observed state bytes",
            )?),
            "crucible.observed-node-ledger" => Self::Ledger(codec::decode_bounded(
                envelope.body(),
                MAX_OBSERVED_RECORD_BYTES,
                "observed ledger bytes",
            )?),
            "crucible.observed-node-dispatch-reservation" => {
                Self::Reservation(codec::decode_bounded(
                    envelope.body(),
                    MAX_OBSERVED_RECORD_BYTES,
                    "observed dispatch reservation bytes",
                )?)
            }
            _ => return Ok(None),
        };
        let (expected, kind) = match &record {
            Self::Request(request) => (request.envelope()?, ObjectKind::CampaignFact),
            Self::Result(result) => (result.envelope()?, ObjectKind::Observation),
            Self::State(state) => (state.envelope()?, ObjectKind::CampaignFact),
            Self::Ledger(ledger) => (ledger.envelope()?, ObjectKind::CampaignSnapshot),
            Self::Reservation(reservation) => (reservation.envelope()?, ObjectKind::CampaignFact),
        };
        if envelope.canonical_bytes() != expected.canonical_bytes()
            || expected.content_id(kind) != id
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed envelope kind, schema, body or child table differs",
            });
        }
        Ok(Some(record))
    }

    pub(crate) fn is_evidence(&self) -> bool {
        matches!(
            self,
            Self::Result(_)
                | Self::State(
                    ObservedAttemptState::Completed(_) | ObservedAttemptState::Quarantined { .. }
                )
        )
    }
}
