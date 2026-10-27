//! Earns Cache continuations from complete frames on the same Root stream.
//!
//! Actual successful sends and original qualified receives advance byte zero
//! framing. Payload bytes cannot be rescanned as headers, and no public method
//! accepts a decoded phase, nonce adoption, stream or caller asserted stage.

use aos_sandbox_model::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_SOURCE_REFRESH_COUNT_V1 as SOURCE_REFRESHES;
use aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::{
    CLAIM_CHUNK_PREFIX_BYTES, PREVIEW_INDEX_BYTES, Q04ChunkPurposeV1, Q04PreviewChunkV1,
    preview_index_shape,
};
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    DECISION_BYTES, PHASE_BYTES, PREHOLD_RESPONSE_BYTES, Q04CutIdentityV1, Q04PhaseOwnerV1,
    Q04PhaseRecordV1, Q04PreholdPublicationDataV1, Q04RootDecisionV1,
};
use aos_sandbox_protocol::source_genesis_wire::{
    self as wire, RootCreateQ04TransferKindV1 as Kind, RootSourceGenesisFrameKindV1 as Genesis,
};
use sha2::{Digest as _, Sha256};

use super::{ControllerRootFlightErrorV1 as Error, ControllerRootFlightOriginalV1};

#[cfg(test)]
mod tests;

const FRAME_CAPACITY: usize = wire::ROOT_SOURCE_GENESIS_MAXIMUM_FRAME_BYTES_V1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Purpose {
    Undecided,
    Ordinary,
    Q04,
}

struct Frame {
    bytes: [u8; FRAME_CAPACITY],
    used: usize,
    shape: Option<(usize, Option<Kind>)>,
}

impl Frame {
    fn new() -> Self {
        Self {
            bytes: [0; FRAME_CAPACITY],
            used: 0,
            shape: None,
        }
    }

    fn push(&mut self, byte: u8) -> Result<(), Error> {
        let slot = self.bytes.get_mut(self.used).ok_or(Error::Stale)?;
        *slot = byte;
        self.used = self.used.checked_add(1).ok_or(Error::Stale)?;
        Ok(())
    }

    fn current(&self) -> &[u8] {
        &self.bytes[..self.used]
    }

    fn clear(&mut self) {
        self.used = 0;
        self.shape = None;
    }

    fn observe_shape(&mut self, nonce: [u8; 16], incoming: bool) -> Result<(), Error> {
        // Fixed headers are classified once. Only an actual variable chunk
        // waits for its complete fixed prefix; payload bytes are never parsed
        // again as headers or repeatedly hashed during byte accumulation.
        if self.shape.is_none() && (self.used == 32 || self.used == 32 + CLAIM_CHUNK_PREFIX_BYTES) {
            self.shape = frame_shape(self.current(), nonce, incoming)?;
        }
        Ok(())
    }
}

pub(super) struct Original {
    purpose: Purpose,
    refused: bool,
    outgoing: Frame,
    incoming: Frame,
    facts: Facts,
}

struct Facts {
    nonce: Option<[u8; 16]>,
    preview_metadata: Option<[u8; 32]>,
    preview_index: Option<[u8; PREVIEW_INDEX_BYTES]>,
    prehold: Option<[u8; PREHOLD_RESPONSE_BYTES]>,
    decision: Option<[u8; DECISION_BYTES]>,
    acknowledgements: [Option<ObjectDigest>; 4],
    phases: [[u8; PHASE_BYTES]; 4],
    sent: usize,
    claim_started: bool,
    source_refreshes: usize,
    source_observations: usize,
    last_source_phase_count: usize,
    received: usize,
}

impl Original {
    pub(super) fn additional_control_bytes_v1() -> Option<usize> {
        // The enclosing original already contains the resident Wire. These
        // are the nested constructor/return planes and the actual finite
        // parser/phase projection objects introduced by this receiver.
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<(&Q04CutIdentityV1, RawPairedClockSample, [u8;16], &[u8;32], &Q04PreholdPublicationDataV1)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(&Q04PhaseRecordV1, u8, &Q04CutIdentityV1, &Q04RootDecisionV1, &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1, ObjectDigest, Option<&Q04PhaseRecordV1>)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<[u8;16], aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ControllerRootQ04FinalObservationLoanV1<'_, '_, '_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&ControllerRootQ04FinalObservationLoanV1<'_, '_, '_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<bool>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<ObjectDigest, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<std::cell::Ref<'_, Self>, std::cell::BorrowError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<std::cell::RefMut<'_, Self>, std::cell::BorrowMutError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<std::cell::Ref<'_, [u8; DECISION_BYTES]>, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<std::cell::Ref<'_, [u8; DECISION_BYTES]>, std::cell::Ref<'_, Self>>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<usize, aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(usize,u16), aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<Q04PreviewChunkV1<'_>, aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<Option<[u8;32]>, aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<bool, aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<[u8; PREVIEW_INDEX_BYTES], std::array::TryFromSliceError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<[u8; PREHOLD_RESPONSE_BYTES], std::array::TryFromSliceError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<[u8; DECISION_BYTES], std::array::TryFromSliceError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<RawPairedClockSample>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Frame>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<Facts>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<Option<(usize, Option<Kind>)>, Error>>().checked_mul(3)?)?
            // These are the new observer's own call and loop controls. The
            // canonical codec invoice pays its separate argument/return lanes.
            .checked_add(std::mem::size_of::<(&[u8], [u8; 16], bool)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(&mut Frame, [u8; 16], bool)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&[u8]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&[Genesis]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<[Genesis; 2]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<[Genesis; 3]>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<std::iter::Copied<std::slice::Iter<'_, Genesis>>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<Genesis>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Genesis>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<bool>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Q04PreholdPublicationDataV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Q04RootDecisionV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1>().checked_mul(3)?)?
            // Current+previous loop phases coexist with a borrowed caller's
            // release result and the next public return/projection plane.
            .checked_add(std::mem::size_of::<Q04PhaseRecordV1>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Result<Q04PhaseRecordV1, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ControllerRootQ04CacheLoanV1<'_, '_, '_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<ControllerRootQ04CacheLoanV1<'_, '_, '_>, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<std::cell::Ref<'_, [u8; PHASE_BYTES]>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<std::cell::Ref<'_, [u8; PHASE_BYTES]>, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Sha256>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Error>>().checked_mul(6)?)
    }

    pub(super) fn new() -> Self {
        Self {
            purpose: Purpose::Undecided,
            refused: false,
            outgoing: Frame::new(),
            incoming: Frame::new(),
            facts: Facts {
                nonce: None,
                preview_metadata: None,
                preview_index: None,
                prehold: None,
                decision: None,
                acknowledgements: [None; 4],
                phases: [[0; PHASE_BYTES]; 4],
                sent: 0,
                claim_started: false,
                source_refreshes: 0,
                source_observations: 0,
                last_source_phase_count: 0,
                received: 0,
            },
        }
    }

    pub(super) fn observe_sent(&mut self, bytes: &[u8], client_nonce: [u8; 16]) {
        if !self.refused && self.sent(bytes, client_nonce).is_err() {
            self.refused = true;
        }
    }

    pub(super) fn observe_received(
        &mut self,
        bytes: &[u8],
        client_nonce: [u8; 16],
        source_uid: u32,
    ) {
        if !self.refused && self.received(bytes, client_nonce, source_uid).is_err() {
            self.refused = true;
        }
    }

    fn sent(&mut self, bytes: &[u8], client_nonce: [u8; 16]) -> Result<(), Error> {
        if self.purpose == Purpose::Ordinary {
            return Ok(());
        }
        for byte in bytes {
            self.outgoing.push(*byte)?;
            if self.purpose == Purpose::Undecided {
                if self.outgoing.used != 32 {
                    continue;
                }
                let query = self.outgoing.current();
                if query[..8] != *aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_QUERY_MAGIC_V1 {
                    self.purpose = Purpose::Ordinary;
                    self.outgoing.clear();
                    return Ok(());
                }
                if query[8..24] != client_nonce || query[24..32] != [0; 8] {
                    return Err(Error::Stale);
                }
                self.purpose = Purpose::Q04;
                self.outgoing.clear();
                continue;
            }
            let nonce = self.facts.nonce.ok_or(Error::Stale)?;
            self.outgoing.observe_shape(nonce, false)?;
            if let Some((length, kind)) = self.outgoing.shape {
                if self.outgoing.used == length {
                    accept_sent(&mut self.facts, self.outgoing.current(), kind)?;
                    self.outgoing.clear();
                }
            }
        }
        Ok(())
    }

    fn received(
        &mut self,
        bytes: &[u8],
        client_nonce: [u8; 16],
        source_uid: u32,
    ) -> Result<(), Error> {
        if self.purpose != Purpose::Q04 {
            return Ok(());
        }
        for byte in bytes {
            self.incoming.push(*byte)?;
            if self.facts.nonce.is_none() {
                if self.incoming.used != 56 {
                    continue;
                }
                let hello = self.incoming.current();
                if hello[..8] != *wire::ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1
                    || hello[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
                    || hello[16..32] != client_nonce
                    || fixed::<16>(hello, 32)? == [0; 16]
                    || fixed::<4>(hello, 48)? != source_uid.to_be_bytes()
                    || fixed::<4>(hello, 52)? != source_uid.to_be_bytes()
                {
                    return Err(Error::Stale);
                }
                self.facts.nonce = Some(fixed(hello, 32)?);
                self.incoming.clear();
                continue;
            }
            let nonce = self.facts.nonce.ok_or(Error::Stale)?;
            self.incoming.observe_shape(nonce, true)?;
            if let Some((length, kind)) = self.incoming.shape {
                if self.incoming.used == length {
                    accept_received(&mut self.facts, self.incoming.current(), kind)?;
                    self.incoming.clear();
                }
            }
        }
        Ok(())
    }

    fn require_identity(
        &self,
        identity: &Q04CutIdentityV1,
        original: RawPairedClockSample,
    ) -> Result<(), Error> {
        if self.refused || self.incoming.used != 0 || self.outgoing.used != 0 {
            return Err(Error::Stale);
        }
        let nonce = self.facts.nonce.ok_or(Error::Stale)?;
        let prehold = self.facts.prehold.as_ref().ok_or(Error::Stale)?;
        let metadata = self.facts.preview_metadata.ok_or(Error::Stale)?;
        let response =
            Q04PreholdPublicationDataV1::decode(prehold, nonce).map_err(|_| Error::Stale)?;
        if !aos_sandbox_protocol::domain_ledger::create_q04_history::matches_original_q04_cut_context_data_v1(
            identity, original, nonce, &metadata, &response,
        ) { return Err(Error::Stale); }
        Ok(())
    }

    fn phase(&self, identity: &Q04CutIdentityV1, index: usize) -> Result<Q04PhaseRecordV1, Error> {
        if index >= self.facts.received {
            return Err(Error::Stale);
        }
        let decision =
            Q04RootDecisionV1::decode(self.facts.decision.as_ref().ok_or(Error::Stale)?, identity)
                .map_err(|_| Error::Stale)?;
        let gate =
            aos_sandbox_protocol::domain_ledger::create_q04_history::root_consumed_gate_record_v1(
                identity, &decision,
            )
            .map_err(|_| Error::Stale)?;
        let mut previous = None;
        for position in 0..=index {
            let phase = Q04PhaseRecordV1::decode(
                Q04PhaseOwnerV1::Root,
                &self.facts.phases[position],
                identity,
            )
            .map_err(|_| Error::Stale)?;
            let acknowledgement = self.facts.acknowledgements[position].ok_or(Error::Stale)?;
            if !aos_sandbox_protocol::domain_ledger::create_q04_history::matches_original_q04_root_phase_data_v1(
                &phase, u8::try_from(position + 4).map_err(|_| Error::Stale)?, identity,
                &decision, &gate, acknowledgement, previous.as_ref(),
            ).map_err(|_| Error::Stale)? { return Err(Error::Stale); }
            previous = Some(phase);
        }
        previous.ok_or(Error::Stale)
    }
}

fn frame_shape(
    frame: &[u8],
    nonce: [u8; 16],
    incoming: bool,
) -> Result<Option<(usize, Option<Kind>)>, Error> {
    if frame.len() < wire::ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Ok(None);
    }
    let header = &frame[..wire::ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1];
    if let Ok(kind) = wire::q04_transfer_kind_from_header_v1(header, nonce) {
        let payload = if let Some(fixed) = kind.fixed_payload_bytes() {
            let resource_header = match kind.resource_magic() {
                Some(magic) => header[..8] == *magic,
                None => false,
            };
            if resource_header {
                kind.resource_payload_bytes().ok_or(Error::Stale)?
            } else {
                fixed
            }
        } else {
            if frame.len() < 32 + CLAIM_CHUNK_PREFIX_BYTES {
                return Ok(None);
            }
            let purpose = match kind {
                Kind::PreviewChunk => Q04ChunkPurposeV1::Preview,
                Kind::ClaimChunk => Q04ChunkPurposeV1::Claim,
                Kind::PreholdChunk => Q04ChunkPurposeV1::Prehold,
                _ => return Err(Error::Stale),
            };
            purpose
                .frame_bytes_from_prefix_v1(&frame[32..32 + CLAIM_CHUNK_PREFIX_BYTES])
                .map_err(|_| Error::Stale)?
        };
        wire::q04_transfer_payload_bytes_from_header_v1(header, kind, nonce, payload)
            .map_err(|_| Error::Stale)?;
        let length = 32_usize.checked_add(payload).ok_or(Error::Stale)?;
        if length > FRAME_CAPACITY || frame.len() > length {
            return Err(Error::Stale);
        }
        return Ok(Some((length, Some(kind))));
    }
    let allowed: &[Genesis] = if incoming {
        &[Genesis::Anchored, Genesis::Completed]
    } else {
        &[Genesis::Prepare, Genesis::Complete, Genesis::Finish]
    };
    for phase in allowed.iter().copied() {
        if let Ok(payload) = wire::strict_genesis_payload_bytes_from_header(header, phase, nonce) {
            let length = 32_usize.checked_add(payload).ok_or(Error::Stale)?;
            if length > FRAME_CAPACITY || frame.len() > length {
                return Err(Error::Stale);
            }
            return Ok(Some((length, None)));
        }
    }
    Err(Error::Stale)
}

fn accept_sent(facts: &mut Facts, frame: &[u8], kind: Option<Kind>) -> Result<(), Error> {
    let Some(kind) = kind else {
        return Ok(());
    };
    let payload =
        wire::decode_root_create_q04_transfer_v1(frame, kind, facts.nonce.ok_or(Error::Stale)?)
            .map_err(|_| Error::Stale)?;
    if matches!(kind, Kind::ClaimIndex) {
        if facts.claim_started || facts.prehold.is_none() {
            return Err(Error::Stale);
        }
        facts.claim_started = true;
    }
    if matches!(kind, Kind::SourceRefresh) {
        if facts.source_refreshes >= SOURCE_REFRESHES
            || facts.source_observations != facts.source_refreshes + 1
        {
            return Err(Error::Stale);
        }
        facts.source_refreshes = facts.source_refreshes.checked_add(1).ok_or(Error::Stale)?;
    }
    let index = match kind {
        Kind::PolicyAcknowledgement => Some(0),
        Kind::ReleaseAcknowledgement => Some(1),
        Kind::SettlementAcknowledgement => Some(2),
        Kind::ClearanceAcknowledgement => Some(3),
        _ => None,
    };
    if let Some(index) = index {
        if facts.sent != index || facts.received != index || facts.decision.is_none() {
            return Err(Error::Stale);
        }
        facts.acknowledgements[index] =
            Some(ObjectDigest::from_bytes(Sha256::digest(payload).into()));
        facts.sent += 1;
    }
    Ok(())
}

fn accept_received(facts: &mut Facts, frame: &[u8], kind: Option<Kind>) -> Result<(), Error> {
    let Some(kind) = kind else {
        return Ok(());
    };
    let payload =
        wire::decode_root_create_q04_transfer_v1(frame, kind, facts.nonce.ok_or(Error::Stale)?)
            .map_err(|_| Error::Stale)?;
    match kind {
        Kind::SourceObservation => {
            if facts.source_observations != facts.source_refreshes {
                return Err(Error::Stale);
            }
            facts.source_observations = facts
                .source_observations
                .checked_add(1)
                .ok_or(Error::Stale)?;
            facts.last_source_phase_count = facts.received;
        }
        Kind::PreviewIndex => {
            if facts.preview_index.is_some() {
                return Err(Error::Stale);
            }
            preview_index_shape(payload).map_err(|_| Error::Stale)?;
            facts.preview_index = Some(payload.try_into().map_err(|_| Error::Stale)?);
        }
        Kind::PreviewChunk => {
            let original_index = facts.preview_index.as_ref().ok_or(Error::Stale)?;
            let chunk =
                Q04PreviewChunkV1::decode(payload, original_index).map_err(|_| Error::Stale)?;
            if let Some(metadata) = chunk.first_metadata_data_v1().map_err(|_| Error::Stale)? {
                if facts.preview_metadata.is_some() {
                    return Err(Error::Stale);
                }
                facts.preview_metadata = Some(metadata);
            }
        }
        Kind::PreholdRecipe => {
            if facts.prehold.is_some() || facts.decision.is_some() {
                return Err(Error::Stale);
            }
            Q04PreholdPublicationDataV1::decode(payload, facts.nonce.ok_or(Error::Stale)?)
                .map_err(|_| Error::Stale)?;
            facts.prehold = Some(payload.try_into().map_err(|_| Error::Stale)?);
        }
        Kind::Decision => {
            if facts.prehold.is_none() || facts.decision.is_some() {
                return Err(Error::Stale);
            }
            facts.decision = Some(payload.try_into().map_err(|_| Error::Stale)?);
        }
        Kind::PolicyAccepted | Kind::ReleaseAuthorized | Kind::Settled | Kind::FinalClearance => {
            let index = match kind {
                Kind::PolicyAccepted => 0,
                Kind::ReleaseAuthorized => 1,
                Kind::Settled => 2,
                Kind::FinalClearance => 3,
                _ => return Err(Error::Stale),
            };
            if facts.received != index || facts.sent != index + 1 {
                return Err(Error::Stale);
            }
            facts.phases[index].copy_from_slice(payload);
            facts.received += 1;
        }
        _ => {}
    }
    Ok(())
}

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Stale)?)
        .ok_or(Error::Stale)?
        .try_into()
        .map_err(|_| Error::Stale)
}

/// Borrows actual Root wire phases earned by the same Controller connection.
///
/// There is no public constructor. DATA decoding, cached phases or a server
/// Origin cannot replace this client's original stream, clock and nonce.
pub struct ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut> {
    flight: &'flight ControllerRootFlightOriginalV1<'profile>,
    identity: &'cut Q04CutIdentityV1,
}

impl ControllerRootQ04CacheLoanV1<'_, '_, '_> {
    /// Borrows the cut joined to the actual prehold and Root phase wire.
    #[must_use]
    pub fn identity(&self) -> &Q04CutIdentityV1 {
        self.identity
    }

    /// Rechecks the same original and its earned complete-frame association.
    ///
    /// # Errors
    /// Refuses changed custody, expiry or inconsistent original wire DATA.
    pub fn recheck(&self) -> Result<(), Error> {
        self.flight.recheck()?;
        let original = self.flight.original_data()?.1;
        self.flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?
            .require_identity(self.identity, original)
    }

    /// Checks the actual lower mutation's same-wire phase immediately before effect.
    ///
    /// # Errors
    /// Refuses a different original, stage or release authorization.
    pub fn require_lower_transition(
        &self,
        index: usize,
        release_authorization: Option<ObjectDigest>,
    ) -> Result<(), Error> {
        self.recheck()?;
        let wire = self
            .flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?;
        match index {
            0 if wire.facts.prehold.is_some()
                && !wire.facts.claim_started
                && wire.facts.decision.is_none() =>
            {
                if release_authorization.is_some() {
                    return Err(Error::Stale);
                }
            }
            1 if wire.facts.received == 2 => {
                if release_authorization != Some(wire.phase(self.identity, 1)?.digest()) {
                    return Err(Error::Stale);
                }
            }
            2 if wire.facts.received == 3 => {
                if release_authorization != Some(wire.phase(self.identity, 1)?.digest()) {
                    return Err(Error::Stale);
                }
                wire.phase(self.identity, 2)?;
            }
            _ => return Err(Error::Stale),
        }
        drop(wire);
        self.recheck()
    }

    /// Copies the authenticated original Root phase-five release DATA.
    ///
    /// # Errors
    /// Refuses an unearned or inconsistent same-wire release.
    pub fn release_phase(&self) -> Result<Q04PhaseRecordV1, Error> {
        self.recheck()?;
        let phase = self
            .flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?
            .phase(self.identity, 1)?;
        self.recheck()?;
        Ok(phase)
    }

    /// Copies the authenticated original Root phase-six settlement DATA.
    ///
    /// # Errors
    /// Refuses an unearned or inconsistent same-wire settlement.
    pub fn settlement_phase(&self) -> Result<Q04PhaseRecordV1, Error> {
        self.recheck()?;
        let wire = self
            .flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?;
        let release = wire.phase(self.identity, 1)?;
        let settlement = wire.phase(self.identity, 2)?;
        if settlement.bytes()[160..192] != *release.digest().as_bytes() {
            return Err(Error::Stale);
        }
        drop(wire);
        self.recheck()?;
        Ok(settlement)
    }

    /// Observes the original signing boundary after same-wire currentness.
    ///
    /// # Errors
    /// Refuses changed custody or the original clock bound.
    pub fn require_signing_boundary(&self) -> Result<(), Error> {
        self.recheck()?;
        self.flight.signing_boundary_clock().map(|_| ())
    }
}

impl<'profile> ControllerRootFlightOriginalV1<'profile> {
    /// Borrows the exact decision body received from the same original Root.
    ///
    /// # Errors
    /// Refuses an absent same-wire decision or unavailable original borrow.
    pub fn q04_received_decision_body_data_v1(
        &self,
    ) -> Result<std::cell::Ref<'_, [u8; DECISION_BYTES]>, Error> {
        let wire = self.q04_wire.try_borrow().map_err(|_| Error::Stale)?;
        if wire.refused || wire.facts.decision.is_none() {
            return Err(Error::Stale);
        }
        std::cell::Ref::filter_map(wire, |wire| wire.facts.decision.as_ref())
            .map_err(|_| Error::Stale)
    }

    /// Copies an acknowledgement digest from actual bytes sent on this original.
    ///
    /// # Errors
    /// Refuses a missing complete acknowledgement or unavailable original borrow.
    pub fn q04_sent_acknowledgement_digest_data_v1(
        &self,
        index: usize,
    ) -> Result<ObjectDigest, Error> {
        let wire = self.q04_wire.try_borrow().map_err(|_| Error::Stale)?;
        if wire.refused {
            return Err(Error::Stale);
        }
        wire.facts
            .acknowledgements
            .get(index)
            .copied()
            .flatten()
            .ok_or(Error::Stale)
    }

    /// Borrows the body actually received at one original Root phase boundary.
    ///
    /// This is historical DATA only. Upper semantic decoding retains its own
    /// original error lane; no supplied body can populate this native slot.
    ///
    /// # Errors
    /// Refuses an absent same-wire frame or unavailable original borrow.
    pub fn q04_received_phase_body_data_v1(
        &self,
        index: usize,
    ) -> Result<std::cell::Ref<'_, [u8; PHASE_BYTES]>, Error> {
        let wire = self.q04_wire.try_borrow().map_err(|_| Error::Stale)?;
        if wire.refused || index >= wire.facts.received {
            return Err(Error::Stale);
        }
        Ok(std::cell::Ref::map(wire, |wire| &wire.facts.phases[index]))
    }

    /// Borrows a Cache continuation earned by this actual original wire.
    ///
    /// # Errors
    /// Refuses missing actual prehold/preview or a changed cut association.
    pub fn q04_cache_loan<'flight, 'cut>(
        &'flight self,
        identity: &'cut Q04CutIdentityV1,
    ) -> Result<ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>, Error> {
        let original = self.original_data()?.1;
        self.q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?
            .require_identity(identity, original)?;
        Ok(ControllerRootQ04CacheLoanV1 {
            flight: self,
            identity,
        })
    }
}

/// Borrows the actual completed Root phase-seven and final original shutdown.
///
/// Only this same client's complete wire history and actual native EOF can
/// construct the loan. Historical Root7 DATA or a supplied EOF is insufficient.
pub struct ControllerRootQ04FinalObservationLoanV1<'flight, 'profile, 'cut> {
    flight: &'flight ControllerRootFlightOriginalV1<'profile>,
    identity: &'cut Q04CutIdentityV1,
}

impl ControllerRootQ04FinalObservationLoanV1<'_, '_, '_> {
    /// Borrows the cut joined to the same completed original stream.
    #[must_use]
    pub fn identity(&self) -> &Q04CutIdentityV1 {
        self.identity
    }

    /// Compares the same original's completed wire, Source refreshes and EOF.
    ///
    /// This reads only retained native facts and the original cut association.
    /// It observes no peer, clock or socket and cannot complete another phase,
    /// restore a refused flight or substitute a supplied completion flag.
    ///
    /// # Errors
    /// Refuses a poisoned original, missing actual EOF, unavailable original
    /// borrow, changed cut, incomplete Source programme or absent Root phase7.
    pub fn require_completed_affinity_data_v1(&self) -> Result<(), Error> {
        if self.flight.poisoned.get() || !self.flight.shutdown_observed.get() {
            return Err(Error::Stale);
        }
        let wire = self
            .flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?;
        wire.require_identity(self.identity, self.flight.original_data()?.1)?;
        if wire.facts.received != 4
            || wire.facts.source_refreshes != SOURCE_REFRESHES
            || wire.facts.source_observations != SOURCE_REFRESHES + 1
            || wire.facts.last_source_phase_count != 4
        {
            return Err(Error::Stale);
        }
        if wire.phase(self.identity, 3)?.phase() != 7 {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Observes the same terminal peer and original clock around retained DATA.
    ///
    /// # Errors
    /// Refuses changed original custody, incomplete final wire history or expiry.
    pub fn recheck(&self) -> Result<(), Error> {
        self.flight.terminal_clock()?;
        self.flight.terminal_clock()?;
        self.require_completed_affinity_data_v1()?;
        self.flight.terminal_clock().map(|_| ())
    }

    /// Copies the actual original Root phase-seven digest as terminal DATA.
    ///
    /// # Errors
    /// Refuses changed original or an incomplete actual phase-seven observation.
    pub fn terminal_digest(&self) -> Result<ObjectDigest, Error> {
        self.recheck()?;
        self.flight
            .q04_wire
            .try_borrow()
            .map_err(|_| Error::Stale)?
            .phase(self.identity, 3)
            .map(|phase| phase.digest())
    }
}

impl<'profile> ControllerRootFlightOriginalV1<'profile> {
    /// Borrows this same actual original for its final observation checks.
    ///
    /// Construction is inert. The loan's terminal operations require actual
    /// phase-seven, every original Source refresh and this same native EOF.
    #[must_use]
    pub fn q04_final_observation_loan<'flight, 'cut>(
        &'flight self,
        identity: &'cut Q04CutIdentityV1,
    ) -> ControllerRootQ04FinalObservationLoanV1<'flight, 'profile, 'cut> {
        ControllerRootQ04FinalObservationLoanV1 {
            flight: self,
            identity,
        }
    }
}
