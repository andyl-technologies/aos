//! Pure authenticated traffic sequencing and exact replay classification.
//!
//! Direction-local sequences start at one and advance only after a signed
//! BrokerOutcome completes the sole outstanding request. The model rejects
//! gaps, rollback, wrap, cross-session/direction/method transplants, changed
//! equal-sequence or equal-request-ID records, and a second outstanding request.
//! Exact replay returns explicit no-write evidence only for the current
//! outstanding request or latest completed request/outcome retained by this
//! snapshot; this is not an unbounded replay history. Sequence `u64::MAX` is
//! reserved for exhaustion, so `u64::MAX - 1` is the final admissible value.
//!
//! These checks do not persist or advance authority. At P0 activation, request
//! sequence reservation must be atomically companion to the owning effect
//! intent, and signed-outcome CAS must be atomically companion to the effect
//! result. Controller-side producers and consumers require the same rule. A
//! future helper may return records for a caller-owned transaction; it must not
//! own a journal. Per-method atomic companion-proof gates, not a universal
//! durable-request limit, decide which effects may activate.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;

use crate::artifact::{
    BrokerSessionArtifactError, SignedBrokerOutcomeV1, SignedBrokerRequestV1,
    complete_signed_outcome_bytes_digest_v1, complete_signed_request_digest_v1,
};
use crate::context::ProtectedBrokerSessionVerificationContextV1;
use crate::model::{BrokerSessionKeyUsageV1, BrokerSessionValidationError};
use crate::profile::method_has_required_traffic_features;
use crate::projection::{
    BrokerSessionProjectionError, CanonicalBrokerRequestEnvelopeV1,
    CanonicalBrokerResponseEnvelopeV1, validate_authenticated_response_budget_v1,
};
use crate::transcript::{BrokerSessionTranscriptPhaseV1, VerifiedBrokerSessionTranscriptV1};

/// Carries a cryptographically verified request without conferring authority.
///
/// This value proves only canonical bytes, the caller-selected verification
/// context, transcript continuity, and pure sequence shape. It is not a
/// descriptor-use permit, durable-CAS proof, kernel-provenance brand, or effect
/// authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptographicallyVerifiedBrokerRequestV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    sequence: u64,
    signed_request_digest: [u8; 32],
    first_traffic_key_proof: bool,
}

impl CryptographicallyVerifiedBrokerRequestV1 {
    /// Returns the exact broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    /// Returns the client-to-broker sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Returns the complete signed-request digest used by its outcome.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }
    /// Reports whether this was the mandatory sequence-1 traffic-key proof.
    #[must_use]
    pub const fn is_first_traffic_key_proof(&self) -> bool {
        self.first_traffic_key_proof
    }
}

/// Carries a cryptographically verified signed outcome without effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptographicallyVerifiedBrokerOutcomeV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    sequence: u64,
}

impl CryptographicallyVerifiedBrokerOutcomeV1 {
    /// Returns the exact broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
    /// Returns the completed request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    /// Returns the broker-to-client sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Proves that an exact previously admitted signed record requires no new write.
///
/// Evidence covers only the latest outstanding or completed record represented
/// by the state snapshot. It does not prove a durable historical lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionReplayEvidenceV1 {
    request_id: [u8; 16],
    sequence: u64,
    signed_artifact_digest: [u8; 32],
}

impl BrokerSessionReplayEvidenceV1 {
    /// Returns the replayed request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    /// Returns the replayed direction-local sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Returns the digest of the byte-identical signed artifact.
    #[must_use]
    pub const fn signed_artifact_digest(&self) -> [u8; 32] {
        self.signed_artifact_digest
    }
}

/// Classifies a newly admitted request versus an exact no-write replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerRequestAdmissionV1 {
    /// A new request and the next pure state snapshot.
    New {
        /// Cryptographic verification result without authority.
        request: CryptographicallyVerifiedBrokerRequestV1,
        /// Caller-owned next state snapshot; it is not persisted by this crate.
        next_state: Box<BrokerSessionTrafficStateV1>,
    },
    /// The exact outstanding record was replayed and must cause no new write.
    ExactReplay(BrokerSessionReplayEvidenceV1),
}

/// Classifies a newly admitted outcome versus an exact no-write replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerOutcomeAdmissionV1 {
    /// A new signed terminal outcome and the next pure state snapshot.
    New {
        /// Cryptographic verification result without authority.
        outcome: CryptographicallyVerifiedBrokerOutcomeV1,
        /// Caller-owned next state snapshot; it is not persisted by this crate.
        next_state: Box<BrokerSessionTrafficStateV1>,
    },
    /// The exact completed outcome was replayed and must cause no new write.
    ExactReplay(BrokerSessionReplayEvidenceV1),
}

/// Reports failed crypto, continuity, or direction-local sequence invariants.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionSequenceError {
    /// Canonical protobuf validation failed.
    #[error("invalid canonical authenticated broker packet: {0}")]
    Projection(#[from] BrokerSessionProjectionError),
    /// Fixed context/signer shape failed.
    #[error("authenticated broker packet signer differs from local context: {0}")]
    Context(#[from] BrokerSessionValidationError),
    /// Strict Ed25519 verification failed.
    #[error("authenticated broker packet signature failed: {0}")]
    Signature(#[from] BrokerSessionArtifactError),
    /// Session binding, process, request ID, method, digest, or direction differs.
    #[error("authenticated broker packet is not continuous with this session")]
    Continuity,
    /// A request arrived while another exact request remains outstanding.
    #[error("authenticated broker session permits only one outstanding request")]
    Outstanding,
    /// A sequence skipped the next expected value.
    #[error("authenticated broker sequence gap")]
    Gap,
    /// A sequence is below the next expected value without being an exact replay.
    #[error("authenticated broker sequence rollback")]
    Rollback,
    /// Equal sequence or request ID was reused with changed signed bytes.
    #[error("authenticated broker equal-sequence or request-ID equivocation")]
    Equivocation,
    /// The direction-local sequence cannot advance without wrapping.
    #[error("authenticated broker sequence exhausted")]
    SequenceExhausted,
    /// The transcript was not in the required provisional/traffic-proved phase.
    #[error("authenticated broker transcript phase does not permit this operation")]
    TranscriptPhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OutstandingRequestV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    client_sequence: u64,
    signed_bytes: Vec<u8>,
    signed_request_digest: [u8; 32],
    maximum_response_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedOutcomeV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    broker_sequence: u64,
    response_bytes: Vec<u8>,
    signed_digest: [u8; 32],
    client_sequence: u64,
    request_signed_bytes: Vec<u8>,
    signed_request_digest: [u8; 32],
    maximum_response_bytes: u32,
}

/// Stores a pure stop-and-wait state snapshot derived from a verified transcript.
///
/// The state is intentionally constructed only from a verified provisional
/// transcript. Returning a new value does not persist it or reserve authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionTrafficStateV1 {
    transcript: VerifiedBrokerSessionTranscriptV1,
    next_client_sequence: u64,
    next_broker_sequence: u64,
    outstanding: Option<OutstandingRequestV1>,
    completed_outcome: Option<CompletedOutcomeV1>,
    negotiated_maximum_response_bytes: u32,
}

impl BrokerSessionTrafficStateV1 {
    /// Derives initial sequence state from a provisional verified transcript.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError::TranscriptPhase`] for a transcript
    /// that has already proved its first traffic record.
    pub fn from_provisional_transcript(
        transcript: VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Self, BrokerSessionSequenceError> {
        if transcript.phase() != BrokerSessionTranscriptPhaseV1::Provisional {
            return Err(BrokerSessionSequenceError::TranscriptPhase);
        }
        let negotiated_maximum_response_bytes = transcript.negotiated_maximum_response_bytes();
        validate_authenticated_response_budget_v1(
            negotiated_maximum_response_bytes,
            negotiated_maximum_response_bytes,
        )?;
        Ok(Self {
            transcript,
            next_client_sequence: 1,
            next_broker_sequence: 1,
            outstanding: None,
            completed_outcome: None,
            negotiated_maximum_response_bytes,
        })
    }

    /// Returns the verified transcript and its current traffic-key-proof phase.
    #[must_use]
    pub const fn transcript(&self) -> &VerifiedBrokerSessionTranscriptV1 {
        &self.transcript
    }
    /// Returns the next new client-to-broker sequence.
    #[must_use]
    pub const fn next_client_sequence(&self) -> u64 {
        self.next_client_sequence
    }
    /// Returns the next new broker-to-client sequence.
    #[must_use]
    pub const fn next_broker_sequence(&self) -> u64 {
        self.next_broker_sequence
    }
    /// Reports whether one request is awaiting its signed outcome.
    #[must_use]
    pub const fn has_outstanding_request(&self) -> bool {
        self.outstanding.is_some()
    }

    /// Verifies that the supplied protected context is still the retained one.
    ///
    /// This pure check is intended for pre-I/O currentness sandwiches. Normal
    /// request and outcome admission repeats it before cryptographic use.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError`] after any protected-context or
    /// key-currentness change.
    pub fn require_current_context(
        &self,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), BrokerSessionSequenceError> {
        verify_current_context(&self.transcript, context)
    }

    /// Verifies one canonical signed ClientRecord against local context and state.
    ///
    /// `request_id` and `request_maximum_response_bytes` must come from the
    /// already validated method body header. Verification is pure and does not
    /// reserve a sequence or persist/advance authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError`] for failed cryptography,
    /// continuity, bounds, gaps, rollback, equivocation, or stop-and-wait violations.
    pub fn admit_request(
        &self,
        request: &CanonicalBrokerRequestEnvelopeV1,
        request_id: [u8; 16],
        request_maximum_response_bytes: u32,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerRequestAdmissionV1, BrokerSessionSequenceError> {
        verify_current_context(&self.transcript, context)?;
        if request.encoded_len() > self.transcript.negotiated_maximum_request_bytes()
            || !self
                .transcript
                .negotiated_methods()
                .contains(&request.signed_artifact().method())
            || !method_has_required_traffic_features(
                request.signed_artifact().method(),
                self.transcript.required_features(),
            )
        {
            return Err(BrokerSessionSequenceError::Continuity);
        }
        validate_authenticated_response_budget_v1(
            self.negotiated_maximum_response_bytes,
            request_maximum_response_bytes,
        )?;
        let signed = request.signed_artifact();
        verify_request_continuity(request, signed, request_id, &self.transcript)?;
        let key = context.key(BrokerSessionKeyUsageV1::ClientRecord);
        key.matches_active(signed.signer())?;
        signed.verify_with_public_key(key.public_key())?;

        let signed_bytes = signed.to_canonical_bytes();
        let signed_digest = complete_signed_request_digest_v1(signed);
        if let Some(completed) = &self.completed_outcome
            && (signed.subject().sequence() == completed.client_sequence
                || request_id == completed.request_id)
        {
            if signed.subject().sequence() == completed.client_sequence
                && request_id == completed.request_id
                && signed.method() == completed.method
                && signed_bytes == completed.request_signed_bytes
                && request_maximum_response_bytes == completed.maximum_response_bytes
            {
                return Ok(BrokerRequestAdmissionV1::ExactReplay(
                    BrokerSessionReplayEvidenceV1 {
                        request_id,
                        sequence: completed.client_sequence,
                        signed_artifact_digest: completed.signed_request_digest,
                    },
                ));
            }
            return Err(BrokerSessionSequenceError::Equivocation);
        }
        if let Some(outstanding) = &self.outstanding {
            if signed.subject().sequence() == outstanding.client_sequence
                || request_id == outstanding.request_id
            {
                if signed.subject().sequence() == outstanding.client_sequence
                    && request_id == outstanding.request_id
                    && signed.method() == outstanding.method
                    && signed_bytes == outstanding.signed_bytes
                    && request_maximum_response_bytes == outstanding.maximum_response_bytes
                {
                    return Ok(BrokerRequestAdmissionV1::ExactReplay(
                        BrokerSessionReplayEvidenceV1 {
                            request_id,
                            sequence: outstanding.client_sequence,
                            signed_artifact_digest: outstanding.signed_request_digest,
                        },
                    ));
                }
                return Err(BrokerSessionSequenceError::Equivocation);
            }
            return Err(BrokerSessionSequenceError::Outstanding);
        }
        classify_sequence(signed.subject().sequence(), self.next_client_sequence)?;
        require_advanceable_sequence(self.next_client_sequence)?;
        let first = self.next_client_sequence == 1;
        let mut next = self.clone();
        if first {
            next.transcript = self.transcript.with_traffic_key_proved();
        }
        next.outstanding = Some(OutstandingRequestV1 {
            method: signed.method(),
            request_id,
            client_sequence: signed.subject().sequence(),
            signed_bytes,
            signed_request_digest: signed_digest,
            maximum_response_bytes: request_maximum_response_bytes,
        });
        Ok(BrokerRequestAdmissionV1::New {
            request: CryptographicallyVerifiedBrokerRequestV1 {
                method: signed.method(),
                request_id,
                sequence: signed.subject().sequence(),
                signed_request_digest: signed_digest,
                first_traffic_key_proof: first,
            },
            next_state: Box::new(next),
        })
    }

    /// Bounds, decodes, and verifies one raw authenticated request packet.
    ///
    /// This entry point checks the signed negotiated request ceiling before
    /// protobuf allocation. Full method-body/header and ancillary descriptor
    /// validation remains a future production composite gate.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError`] for changed context, an oversized
    /// packet, malformed canonical protobuf, or any [`Self::admit_request`] error.
    pub fn decode_and_admit_request(
        &self,
        bytes: &[u8],
        request_id: [u8; 16],
        request_maximum_response_bytes: u32,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerRequestAdmissionV1, BrokerSessionSequenceError> {
        verify_current_context(&self.transcript, context)?;
        if bytes.len() > self.transcript.negotiated_maximum_request_bytes() {
            return Err(BrokerSessionSequenceError::Projection(
                BrokerSessionProjectionError::TooLarge,
            ));
        }
        let request = crate::projection::decode_canonical_request_v1(bytes)?;
        self.admit_request(
            &request,
            request_id,
            request_maximum_response_bytes,
            context,
        )
    }

    /// Verifies the signed terminal outcome for the sole outstanding request.
    ///
    /// Both successful and error responses must enter through this function.
    /// Pre-authentication malformed input may instead close silently; a bare
    /// transport close is never represented as signed `Unavailable`.
    /// Verification returns a new state but does not persist or advance authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError`] for failed cryptography,
    /// continuity, replay equivocation, missing request, gaps, rollback, or wrap.
    pub fn admit_outcome(
        &self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerOutcomeAdmissionV1, BrokerSessionSequenceError> {
        verify_current_context(&self.transcript, context)?;
        let signed = outcome.signed_artifact();
        let effective_bound = self.response_bound_for(signed)?;
        if outcome.encoded_len() > effective_bound {
            return Err(BrokerSessionSequenceError::Projection(
                BrokerSessionProjectionError::TooLarge,
            ));
        }
        let signed_bytes = signed.to_canonical_bytes();
        let signed_digest = digest_signed_outcome(&signed_bytes);
        if let Some(completed) = &self.completed_outcome
            && (signed.subject().sequence() == completed.broker_sequence
                || signed.subject().request_id() == completed.request_id)
        {
            if outcome.encoded_bytes() != completed.response_bytes {
                return Err(BrokerSessionSequenceError::Equivocation);
            }
            verify_completed_outcome_continuity(outcome, signed, completed, &self.transcript)?;
            return Ok(BrokerOutcomeAdmissionV1::ExactReplay(
                BrokerSessionReplayEvidenceV1 {
                    request_id: completed.request_id,
                    sequence: completed.broker_sequence,
                    signed_artifact_digest: completed.signed_digest,
                },
            ));
        }
        let outstanding = self
            .outstanding
            .as_ref()
            .ok_or(BrokerSessionSequenceError::Outstanding)?;
        verify_outcome_continuity(outcome, signed, outstanding, &self.transcript)?;
        classify_sequence(signed.subject().sequence(), self.next_broker_sequence)?;
        require_advanceable_sequence(self.next_client_sequence)?;
        require_advanceable_sequence(self.next_broker_sequence)?;
        let key = context.key(BrokerSessionKeyUsageV1::BrokerOutcome);
        key.matches_active(signed.signer())?;
        signed.verify_with_public_key(key.public_key())?;

        let verified = CryptographicallyVerifiedBrokerOutcomeV1 {
            method: signed.method(),
            request_id: outstanding.request_id,
            sequence: signed.subject().sequence(),
        };
        let mut next = self.clone();
        next.next_client_sequence += 1;
        next.next_broker_sequence += 1;
        next.outstanding = None;
        next.completed_outcome = Some(CompletedOutcomeV1 {
            method: signed.method(),
            request_id: outstanding.request_id,
            broker_sequence: signed.subject().sequence(),
            response_bytes: outcome.encoded_bytes().to_vec(),
            signed_digest,
            client_sequence: outstanding.client_sequence,
            request_signed_bytes: outstanding.signed_bytes.clone(),
            signed_request_digest: outstanding.signed_request_digest,
            maximum_response_bytes: outstanding.maximum_response_bytes,
        });
        Ok(BrokerOutcomeAdmissionV1::New {
            outcome: verified,
            next_state: Box::new(next),
        })
    }

    /// Bounds, decodes, and verifies one raw authenticated outcome packet.
    ///
    /// Before protobuf allocation, the packet is bounded by the largest
    /// applicable retained outstanding/latest-completed response ceiling.
    /// After decode, the authenticated target's own retained ceiling applies.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSequenceError`] for changed context, no retained
    /// request/replay bound, oversize, malformed protobuf, or any outcome error.
    pub fn decode_and_admit_outcome(
        &self,
        bytes: &[u8],
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerOutcomeAdmissionV1, BrokerSessionSequenceError> {
        verify_current_context(&self.transcript, context)?;
        if bytes.len() > self.maximum_candidate_response_bound()? {
            return Err(BrokerSessionSequenceError::Projection(
                BrokerSessionProjectionError::TooLarge,
            ));
        }
        let outcome = crate::projection::decode_canonical_response_v1(bytes)?;
        self.admit_outcome(&outcome, context)
    }

    fn maximum_candidate_response_bound(&self) -> Result<usize, BrokerSessionSequenceError> {
        let outstanding_bound = self
            .outstanding
            .as_ref()
            .map(|request| request.maximum_response_bytes);
        let completed_bound = self
            .completed_outcome
            .as_ref()
            .map(|outcome| outcome.maximum_response_bytes);
        let request_bound = match (outstanding_bound, completed_bound) {
            (Some(outstanding), Some(completed)) => outstanding.max(completed),
            (Some(bound), None) | (None, Some(bound)) => bound,
            (None, None) => return Err(BrokerSessionSequenceError::Outstanding),
        };
        self.response_bound(request_bound)
    }

    fn response_bound_for(
        &self,
        signed: &SignedBrokerOutcomeV1,
    ) -> Result<usize, BrokerSessionSequenceError> {
        let request_bound = self
            .completed_outcome
            .as_ref()
            .filter(|completed| {
                signed.subject().sequence() == completed.broker_sequence
                    || signed.subject().request_id() == completed.request_id
            })
            .map(|completed| completed.maximum_response_bytes)
            .or_else(|| {
                self.outstanding
                    .as_ref()
                    .map(|request| request.maximum_response_bytes)
            })
            .or_else(|| {
                self.completed_outcome
                    .as_ref()
                    .map(|outcome| outcome.maximum_response_bytes)
            })
            .ok_or(BrokerSessionSequenceError::Outstanding)?;
        self.response_bound(request_bound)
    }

    fn response_bound(&self, request_bound: u32) -> Result<usize, BrokerSessionSequenceError> {
        let bound = request_bound.min(self.negotiated_maximum_response_bytes);
        usize::try_from(bound).map_err(|_| {
            BrokerSessionSequenceError::Projection(BrokerSessionProjectionError::TooLarge)
        })
    }
}

fn verify_current_context(
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<(), BrokerSessionSequenceError> {
    context.require_all_active()?;
    if context.protected_context_digest() != transcript.protected_context_digest() {
        return Err(BrokerSessionSequenceError::Continuity);
    }
    Ok(())
}

fn verify_request_continuity(
    request: &CanonicalBrokerRequestEnvelopeV1,
    signed: &SignedBrokerRequestV1,
    request_id: [u8; 16],
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<(), BrokerSessionSequenceError> {
    if request_id.iter().all(|byte| *byte == 0)
        || signed.subject().session_binding() != transcript.session_binding()
        || signed.subject().client_process() != transcript.client_process()
        || signed.subject().request_id() != request_id
        || signed.subject().cleared_fields_digest() != request.cleared_fields_digest()
    {
        Err(BrokerSessionSequenceError::Continuity)
    } else {
        Ok(())
    }
}

fn verify_outcome_continuity(
    outcome: &CanonicalBrokerResponseEnvelopeV1,
    signed: &SignedBrokerOutcomeV1,
    outstanding: &OutstandingRequestV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<(), BrokerSessionSequenceError> {
    if signed.subject().session_binding() != transcript.session_binding()
        || signed.subject().broker_process() != transcript.broker_process()
        || signed.method() != outstanding.method
        || signed.subject().request_id() != outstanding.request_id
        || outcome.message().request_id.as_slice() != outstanding.request_id
        || signed.subject().signed_request_digest() != outstanding.signed_request_digest
        || signed.subject().cleared_fields_digest() != outcome.cleared_fields_digest()
    {
        Err(BrokerSessionSequenceError::Continuity)
    } else {
        Ok(())
    }
}

fn verify_completed_outcome_continuity(
    outcome: &CanonicalBrokerResponseEnvelopeV1,
    signed: &SignedBrokerOutcomeV1,
    completed: &CompletedOutcomeV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<(), BrokerSessionSequenceError> {
    if signed.subject().session_binding() != transcript.session_binding()
        || signed.subject().broker_process() != transcript.broker_process()
        || signed.method() != completed.method
        || signed.subject().request_id() != completed.request_id
        || outcome.message().request_id.as_slice() != completed.request_id
        || signed.subject().signed_request_digest() != completed.signed_request_digest
        || signed.subject().cleared_fields_digest() != outcome.cleared_fields_digest()
    {
        Err(BrokerSessionSequenceError::Continuity)
    } else {
        Ok(())
    }
}

fn classify_sequence(received: u64, expected: u64) -> Result<(), BrokerSessionSequenceError> {
    if received == expected {
        Ok(())
    } else if received > expected {
        Err(BrokerSessionSequenceError::Gap)
    } else {
        Err(BrokerSessionSequenceError::Rollback)
    }
}

fn require_advanceable_sequence(sequence: u64) -> Result<(), BrokerSessionSequenceError> {
    if sequence == u64::MAX {
        Err(BrokerSessionSequenceError::SequenceExhausted)
    } else {
        Ok(())
    }
}

fn digest_signed_outcome(bytes: &[u8]) -> [u8; 32] {
    complete_signed_outcome_bytes_digest_v1(bytes)
}

#[cfg(test)]
mod tests {
    use super::{BrokerSessionSequenceError, classify_sequence, require_advanceable_sequence};

    #[test]
    fn rollback_gap_and_reserved_maximum_are_closed() {
        assert_eq!(
            classify_sequence(1, 2),
            Err(BrokerSessionSequenceError::Rollback)
        );
        assert_eq!(
            classify_sequence(3, 2),
            Err(BrokerSessionSequenceError::Gap)
        );
        assert_eq!(classify_sequence(2, 2), Ok(()));
        assert_eq!(require_advanceable_sequence(u64::MAX - 1), Ok(()));
        assert_eq!(
            require_advanceable_sequence(u64::MAX),
            Err(BrokerSessionSequenceError::SequenceExhausted)
        );
    }
}
