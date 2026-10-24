//! Correlates the Root-first Cache signer invitation with the original Hello.
//!
//! ```text
//! body[136] = AOSXCC01 | lane[16] | RootOpen-checksum[32] |
//!             RootNonce[16] | Ready[32] | Cache-challenge-digest[32]
//! frame[248] = CurrentProofsChallenge-header[112] | body[136]
//! sequence = 3 + actual Ready transfer index count
//! ```
//!
//! Root sends this only after its real independent signer half begins. The
//! Controller's live borrower authenticates the same Root stream and posts
//! before contacting its signer half. These codecs expose comparison DATA;
//! they cannot prove either contacted half or lend a signing permission.

use super::super::{nonzero, reader, HistoryErrorV1};
use super::super::cache_held::{CACHE_HELD_RECEIPT_BYTES_V1, current_proof::current_cache_challenge_digest_v1};
use super::super::root_open::{ROOT_HELLO_FRAME_BYTES_V1, RootHelloDataV1};
use super::super::transport::{
    FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1,
};

/// Holds the exact Cache signer invitation body width.
pub const CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1: usize = 136;
/// Holds the exact Cache signer invitation frame width.
pub const CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1: usize =
    FRAME_HEADER_BYTES + CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1;

/// Carries the exact original Cache challenge as nonauthorizing correlation DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentProofsChallengeDataV1 {
    /// The original complete-B lane, unchanged across both signer halves.
    pub lane: [u8; 16],
    /// The actual first Hello's RootOpen envelope checksum.
    pub root_open: [u8; 32],
    /// The original Root nonce, never renewed by this invitation.
    pub root_nonce: [u8; 16],
    /// The exact original complete-B commitment.
    pub ready: [u8; 32],
    /// The shared digest over the exact Hello612 and CacheHeld1052 originals.
    pub challenge: [u8; 32],
}

#[derive(Clone, Copy)]
enum InvitationTurnV1 { Initial, ReservedUse }

impl CurrentProofsChallengeDataV1 {
    /// Decodes the exact fixed invitation without allocating or contacting a peer.
    ///
    /// # Errors
    /// Rejects wrong magic, nonexact extent or zero correlation fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCC01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            lane: input.array()?,
            root_open: input.array()?,
            root_nonce: input.array()?,
            ready: input.array()?,
            challenge: input.array()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes one exact fixed invitation into an allocation-free array.
    ///
    /// # Errors
    /// Rejects zero correlation fields before writing bytes.
    pub fn encode(self) -> Result<[u8; CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXCC01");
        bytes[8..24].copy_from_slice(&self.lane);
        bytes[24..56].copy_from_slice(&self.root_open);
        bytes[56..72].copy_from_slice(&self.root_nonce);
        bytes[72..104].copy_from_slice(&self.ready);
        bytes[104..136].copy_from_slice(&self.challenge);
        Ok(bytes)
    }

    /// Requires the same original checked Root Hello correlation.
    ///
    /// # Errors
    /// Rejects a changed lane, nonce, RootOpen checksum or complete-B commitment.
    pub fn require_hello(self, hello: &RootHelloDataV1<'_>) -> Result<(), HistoryErrorV1> {
        self.validate()?;
        if self.lane != hello.body.open.lane || self.root_open != hello.checksum
            || self.root_nonce != hello.body.root_nonce || self.ready != hello.body.open.ready
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Requires the shared digest of the exact two actual original packets.
    ///
    /// The caller independently validates and retains both packets under its
    /// live original. This does not authenticate a Hello or Cache receipt.
    ///
    /// # Errors
    /// Rejects a different complete challenge; no packet is regenerated here.
    pub fn require_challenge_bytes(
        self,
        hello: &[u8; ROOT_HELLO_FRAME_BYTES_V1],
        held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1],
    ) -> Result<(), HistoryErrorV1> {
        self.validate()?;
        if self.challenge != current_cache_challenge_digest_v1(hello, held) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Checks the exact next global frame after the actual complete-B chunks.
    ///
    /// # Errors
    /// Rejects changed Hello correlation, wrong kind, nonces, sequence, checksum,
    /// body or extent. The expected sequence derives from the retained index,
    /// never the untrusted incoming header.
    pub fn decode_frame(
        bytes: &[u8],
        hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1,
    ) -> Result<Self, HistoryErrorV1> {
        Self::decode_for_turn(bytes, hello, index, InvitationTurnV1::Initial)
    }

    /// Decodes the distinct use-stage invitation after the actual reserved turn.
    ///
    /// # Errors
    /// Rejects another kind/sequence, changed Hello or malformed fixed challenge.
    /// This codec supplies comparison DATA, never a fresh Cache or U grant.
    pub fn decode_use_frame(bytes: &[u8], hello: &RootHelloDataV1<'_>, index: TransferIndexV1)
        -> Result<Self, HistoryErrorV1>
    {
        Self::decode_for_turn(bytes, hello, index, InvitationTurnV1::ReservedUse)
    }

    fn decode_for_turn(bytes: &[u8], hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1, turn: InvitationTurnV1) -> Result<Self, HistoryErrorV1>
    {
        if bytes.len() != CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1 {
            return Err(HistoryErrorV1::Extent);
        }
        let coordinates = match turn {
            InvitationTurnV1::Initial => Self::coordinates(hello, index)?,
            InvitationTurnV1::ReservedUse => Self::use_coordinates(hello, index)?,
        };
        let frame = FrameEnvelopeV1::decode(bytes, coordinates)?;
        let value = Self::decode(frame.payload())?;
        value.require_hello(hello)?;
        Ok(value)
    }

    /// Encodes the exact next global invitation frame without variable storage.
    ///
    /// # Errors
    /// Rejects invalid or different original Hello correlation or wire overflow.
    pub fn encode_frame(
        self,
        hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1,
    ) -> Result<[u8; CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1], HistoryErrorV1> {
        self.encode_for_turn(hello, index, InvitationTurnV1::Initial)
    }

    /// Encodes the fixed use-stage invitation with its distinct kind and turn.
    ///
    /// # Errors
    /// Rejects changed Hello/index identity or noncanonical challenge fields.
    pub fn encode_use_frame(self, hello: &RootHelloDataV1<'_>, index: TransferIndexV1)
        -> Result<[u8; CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1], HistoryErrorV1>
    {
        self.encode_for_turn(hello, index, InvitationTurnV1::ReservedUse)
    }

    fn encode_for_turn(self, hello: &RootHelloDataV1<'_>, index: TransferIndexV1, turn: InvitationTurnV1)
        -> Result<[u8; CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1], HistoryErrorV1>
    {
        self.require_hello(hello)?;
        let body = self.encode()?;
        let coordinates = match turn {
            InvitationTurnV1::Initial => Self::coordinates(hello, index)?,
            InvitationTurnV1::ReservedUse => Self::use_coordinates(hello, index)?,
        };
        let header = coordinates.encode_header(&body)?;
        let mut frame = [0; CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1];
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        frame[FRAME_HEADER_BYTES..].copy_from_slice(&body);
        Ok(frame)
    }

    fn coordinates(
        hello: &RootHelloDataV1<'_>,
        index: TransferIndexV1,
    ) -> Result<FrameCoordinatesV1, HistoryErrorV1> {
        if index.digest() != hello.body.open.ready {
            return Err(HistoryErrorV1::Correlation);
        }
        let sequence = 3_u64.checked_add(u64::from(index.count()))
            .ok_or(HistoryErrorV1::Extent)?;
        Ok(FrameCoordinatesV1 {
            kind: FrameKindV1::CurrentProofsChallenge,
            lane: hello.body.open.lane,
            sequence,
            root_nonce: hello.body.root_nonce,
            controller_nonce: hello.body.open.controller_nonce,
        })
    }

    fn use_coordinates(hello: &RootHelloDataV1<'_>, index: TransferIndexV1)
        -> Result<FrameCoordinatesV1, HistoryErrorV1>
    {
        let mut coordinates = Self::coordinates(hello, index)?;
        coordinates.kind = FrameKindV1::UseCurrentProofsChallenge;
        coordinates.sequence = 7_u64.checked_add(u64::from(index.count()))
            .ok_or(HistoryErrorV1::Extent)?;
        Ok(coordinates)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        nonzero(&self.lane)?;
        nonzero(&self.root_open)?;
        nonzero(&self.root_nonce)?;
        nonzero(&self.ready)?;
        nonzero(&self.challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{
        KeyV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    };

    fn original_hello() -> ([u8; ROOT_HELLO_FRAME_BYTES_V1], super::super::super::transport::OpenQueryV1) {
        use super::super::super::root_open::RootOpenBodyDataV1;
        use super::super::super::transport::OpenQueryV1;
        use super::super::super::super::protected_names::ProtectedJournalNamesV1;

        let body = RootOpenBodyDataV1 {
            open: OpenQueryV1 {
                controller_nonce: [1; 16], lane: [2; 16], seed: [3; 32], ready: [4; 32],
            },
            root_nonce: [5; 16], boot: [6; 16], started: 100, cutoff: 200,
            authority_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 11, policy_next: 1, root_profile: [12; 32],
            root_recipient: [13; 16], root_producer: [14; 16], root_pid: 15,
            controller_pid: 16, controller_uid: 17, controller_gid: 18,
        };
        let mut record = [0; 500];
        RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(body.open.lane, OwnerV1::Root, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(),
            predecessor: [0; 32],
            correlation: body.open.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let header = FrameCoordinatesV1 {
            kind: FrameKindV1::Hello,
            lane: body.open.lane,
            sequence: 1,
            root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce,
        }.encode_header(&record).unwrap();
        let mut frame = [0; ROOT_HELLO_FRAME_BYTES_V1];
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        frame[FRAME_HEADER_BYTES..].copy_from_slice(&record);
        (frame, body.open)
    }

    #[test]
    fn invitation_requires_original_hello_and_the_next_global_sequence() {
        let (bytes, open) = original_hello();
        let hello = RootHelloDataV1::decode(&bytes, open).unwrap();
        let index = TransferIndexV1::new(1, open.ready).unwrap();
        // This is only digest/framing DATA; no synthetic Held authority is used.
        let held = [1; CACHE_HELD_RECEIPT_BYTES_V1];
        let value = CurrentProofsChallengeDataV1 {
            lane: open.lane,
            root_open: hello.checksum,
            root_nonce: hello.body.root_nonce,
            ready: open.ready,
            challenge: current_cache_challenge_digest_v1(&bytes, &held),
        };
        let frame = value.encode_frame(&hello, index).unwrap();

        assert_eq!(CurrentProofsChallengeDataV1::decode_frame(&frame, &hello, index).unwrap(), value);
        assert!(value.require_challenge_bytes(&bytes, &held).is_ok());
        let mut changed = value;
        changed.root_open[0] ^= 1;
        assert!(changed.encode_frame(&hello, index).is_err());
        assert!(CurrentProofsChallengeDataV1::decode_frame(&frame[..frame.len() - 1], &hello, index).is_err());

        let mut coordinates = CurrentProofsChallengeDataV1::coordinates(&hello, index).unwrap();
        assert_eq!(coordinates.sequence, 4);
        coordinates.sequence += 1;
        let mut changed = frame;
        changed[..FRAME_HEADER_BYTES].copy_from_slice(&coordinates.encode_header(&value.encode().unwrap()).unwrap());
        assert!(CurrentProofsChallengeDataV1::decode_frame(&changed, &hello, index).is_err());
    }

    #[test]
    fn invitation_rejects_different_complete_challenge_and_transfer_commitment() {
        let (bytes, open) = original_hello();
        let hello = RootHelloDataV1::decode(&bytes, open).unwrap();
        let held = [1; CACHE_HELD_RECEIPT_BYTES_V1];
        let value = CurrentProofsChallengeDataV1 {
            lane: open.lane,
            root_open: hello.checksum,
            root_nonce: hello.body.root_nonce,
            ready: open.ready,
            challenge: current_cache_challenge_digest_v1(&bytes, &held),
        };
        let mut changed = held;
        changed[0] ^= 1;

        assert!(value.require_challenge_bytes(&bytes, &changed).is_err());
        assert!(value.encode_frame(&hello, TransferIndexV1::new(1, [42; 32]).unwrap()).is_err());
        assert!(CurrentProofsChallengeDataV1::decode(&[0; CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1]).is_err());
    }

    #[test]
    fn first_and_reserved_invitations_cannot_cross_their_actual_turns() {
        let (bytes, open) = original_hello();
        let hello = RootHelloDataV1::decode(&bytes, open).unwrap();
        let index = TransferIndexV1::new(2, open.ready).unwrap();
        let value = CurrentProofsChallengeDataV1 {
            lane: open.lane, root_open: hello.checksum,
            root_nonce: hello.body.root_nonce, ready: open.ready,
            challenge: current_cache_challenge_digest_v1(&bytes, &[1; CACHE_HELD_RECEIPT_BYTES_V1]),
        };

        let first = value.encode_frame(&hello, index).unwrap();
        let reserved = value.encode_use_frame(&hello, index).unwrap();

        assert_eq!(CurrentProofsChallengeDataV1::decode_use_frame(&reserved, &hello, index).unwrap(), value);
        assert!(CurrentProofsChallengeDataV1::decode_frame(&reserved, &hello, index).is_err());
        assert!(CurrentProofsChallengeDataV1::decode_use_frame(&first, &hello, index).is_err());
        assert_eq!(&first[FRAME_HEADER_BYTES..], &reserved[FRAME_HEADER_BYTES..]);
        // The kind code is not a sequence. C UseReserved occupies6+count,
        // this Root invitation7+count, then C's proof container8+count.
        let actual = CurrentProofsChallengeDataV1::use_coordinates(&hello, index).unwrap();
        let controller_reserved_sequence = 6 + u64::from(index.count());
        let controller_proofs_sequence = 8 + u64::from(index.count());
        assert_eq!(actual.sequence, controller_reserved_sequence + 1);
        assert_eq!(actual.sequence + 1, controller_proofs_sequence);
        assert_eq!(actual.kind, FrameKindV1::UseCurrentProofsChallenge);
        assert_eq!(CurrentProofsChallengeDataV1::coordinates(&hello, index).unwrap().sequence,
            3 + u64::from(index.count()));
        let mut wrong_sequence = CurrentProofsChallengeDataV1::use_coordinates(&hello, index).unwrap();
        wrong_sequence.sequence -= 1;
        let mut replaced = reserved;
        replaced[..FRAME_HEADER_BYTES].copy_from_slice(&wrong_sequence.encode_header(&value.encode().unwrap()).unwrap());
        assert!(CurrentProofsChallengeDataV1::decode_use_frame(&replaced, &hello, index).is_err());
        let different = TransferIndexV1::new(2, [42; 32]).unwrap();
        assert!(matches!(CurrentProofsChallengeDataV1::decode_frame(&[], &hello, different),
            Err(HistoryErrorV1::Extent)));
        let malformed = CurrentProofsChallengeDataV1 { challenge: [0; 32], ..value };
        assert!(matches!(malformed.encode_frame(&hello, different), Err(HistoryErrorV1::Malformed)));
    }
}
