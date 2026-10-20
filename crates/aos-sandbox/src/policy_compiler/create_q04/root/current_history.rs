//! Checks immutable prior Root Q04 history for one genuine inert RootOpen.
//!
//! This is a nonissuing predecessor check, not a Q04 loan or C8 completion
//! proof. RootOpen precedes Hello/B, so this stage cannot know new A. The full
//! typed-B consumer must separately join its exact original Controller parent.
//! Ordinary Root writes retain their old unconditional Q04-history boundary.

use std::collections::BTreeMap;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use sha2::{Digest as _, Sha256};

use crate::journal::{JournalError, RecordNamespace};

use super::{CreateQ04ErrorV1, Q04CutIdentityV1, RootQ04RecordKeyV1};
use super::super::{
    Q04PhaseOwnerV1, Q04PhaseRecordV1, Q04RootDecisionV1,
    Q04AcknowledgementKindV1, Q04ClaimChunkV1, claim_index_shape,
    require_acknowledgement_body, CLAIM_INDEX_DOMAIN,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(crate) struct RootInertHistoryScanV1 {
    entered: bool,
    active: RootCutScanV1,
    completed_cuts: usize,
    result: Option<Result<(), CreateQ04ErrorV1>>,
    closed: Option<CreateQ04ErrorV1>,
}

struct RootCutScanV1 {
    shape: Option<Result<(RootQ04RecordKeyV1, [u8; 16]), CreateQ04ErrorV1>>,
    lookup: Option<Result<(RecordNamespace, Vec<u8>), CreateQ04ErrorV1>>,
    cut: Option<Result<Q04CutIdentityV1, CreateQ04ErrorV1>>,
    phases: [Option<Result<Q04PhaseRecordV1, CreateQ04ErrorV1>>; 7],
    decision: Option<Result<Q04RootDecisionV1, CreateQ04ErrorV1>>,
    index: Option<Result<(usize, u16), CreateQ04ErrorV1>>,
    chunk: Option<Result<(), CreateQ04ErrorV1>>,
    packets: [Option<Result<(), CreateQ04ErrorV1>>; 4],
    comparison: Option<Result<(), CreateQ04ErrorV1>>,
}

impl Default for RootInertHistoryScanV1 {
    fn default() -> Self {
        Self {
            entered: false,
            active: RootCutScanV1::default(),
            completed_cuts: 0,
            result: None,
            closed: None,
        }
    }
}

impl Default for RootCutScanV1 {
    fn default() -> Self {
        Self {
            shape: None,
            lookup: None,
            cut: None,
            phases: std::array::from_fn(|_| None),
            decision: None,
            index: None,
            chunk: None,
            packets: std::array::from_fn(|_| None),
            comparison: None,
        }
    }
}

impl RootInertHistoryScanV1 {
    pub(crate) fn observe_once(&mut self, state: &State) -> Result<(), CreateQ04ErrorV1> {
        if self.entered {
            self.closed.get_or_insert(CreateQ04ErrorV1::ChangedCut);
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.entered = true;
        self.result = Some(self.observe_inner(state));

        if self.failure().is_none() && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CreateQ04ErrorV1::ChangedCut)
        }
    }

    /// Compares one accepted parent against this SAME held Root history.
    pub(crate) fn observe_original_parent_once(
        &mut self, state: &State, identity: &Q04CutIdentityV1,
        root_final: [u8; 32],
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.entered {
            self.closed.get_or_insert(CreateQ04ErrorV1::ChangedCut);
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.entered = true;
        self.result = Some((|| {
            let bytes = self.active.lookup(state, RootQ04RecordKeyV1::Cut, identity.nonce())?;
            self.active.cut = Some(Q04CutIdentityV1::decode(bytes).map_err(CreateQ04ErrorV1::from));
            if value(&self.active.cut)?.bytes() != identity.bytes() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.active.require_complete_cut(state, identity)?;
            if value(&self.active.phases[6])?.digest().as_bytes() != &root_final {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })());
        if self.failure().is_none() && matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(CreateQ04ErrorV1::ChangedCut) }
    }

    fn observe_inner(&mut self, state: &State) -> Result<(), CreateQ04ErrorV1> {
        for ((namespace, key), record_bytes) in state.iter()
            .filter(|((_, key), _)| key.starts_with(b"\0aos-q04-root-"))
        {
            if *namespace != RecordNamespace::DesiredState {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }

            self.active.shape = Some(RootQ04RecordKeyV1::decode_key_v1(key));
            let (kind, nonce) = *value(&self.active.shape)?;
            let bytes = self.active.lookup(state, RootQ04RecordKeyV1::Cut, nonce)?;
            self.active.cut = Some(Q04CutIdentityV1::decode(bytes).map_err(CreateQ04ErrorV1::from));
            let identity = value(&self.active.cut)?.clone();
            if identity.nonce() != nonce {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }

            if let RootQ04RecordKeyV1::ClaimChunk(ordinal) = kind {
                let index = self.active.lookup(state, RootQ04RecordKeyV1::ClaimIndex, nonce)?;
                self.active.index = Some(claim_index_shape(index, &identity));
                value(&self.active.index)?;
                self.active.chunk = Some(Q04ClaimChunkV1::decode(record_bytes, index, &identity)
                    .and_then(|chunk| if chunk.chunk.index() == ordinal { Ok(()) }
                        else { Err(CreateQ04ErrorV1::ChangedCut) }));
                value(&self.active.chunk)?;
            }

            if matches!(kind, RootQ04RecordKeyV1::Cut) {
                self.active.require_complete_cut(state, &identity)?;
                self.completed_cuts = self.completed_cuts.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
            }

            // Every positive row/cut comparison is complete and nonauthorizing.
            // Physically dispose its exact key backing and fixed scratch before
            // reusing this one paid carrier. Failed progress is never reset.
            self.active = RootCutScanV1::default();
        }
        Ok(())
    }

    pub(crate) fn require_complete(&self) -> Result<(), JournalError> {
        if self.entered && self.failure().is_none() && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.active.failure().or_else(|| cause(&self.result))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl RootCutScanV1 {
    fn lookup<'state>(
        &mut self,
        state: &'state State,
        kind: RootQ04RecordKeyV1,
        nonce: [u8; 16],
    ) -> Result<&'state [u8], CreateQ04ErrorV1> {
        self.lookup = Some(kind.encode(nonce).map(|key| (RecordNamespace::DesiredState, key)));
        let key = value(&self.lookup)?;
        state.get(key).map(Vec::as_slice).ok_or(CreateQ04ErrorV1::ChangedCut)
    }

    fn require_complete_cut(
        &mut self,
        state: &State,
        identity: &Q04CutIdentityV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        for index in 0..7 {
            let bytes = self.lookup(state, RootQ04RecordKeyV1::Phase(index as u8 + 1), identity.nonce())?;
            self.phases[index] = Some(Q04PhaseRecordV1::decode(Q04PhaseOwnerV1::Root, bytes, identity)
                .map_err(CreateQ04ErrorV1::from));
            let phase = value(&self.phases[index])?;
            if phase.phase() != index as u8 + 1 {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            if index > 0 {
                phase.require_successor(value(&self.phases[index - 1])?)?;
            }
        }

        let bytes = self.lookup(state, RootQ04RecordKeyV1::Decision, identity.nonce())?;
        self.decision = Some(Q04RootDecisionV1::decode(bytes, identity).map_err(CreateQ04ErrorV1::from));
        self.comparison = Some(if value(&self.phases[2])?.bytes()[96..128]
            == *value(&self.decision)?.digest().as_bytes() { Ok(()) }
            else { Err(CreateQ04ErrorV1::ChangedCut) });
        value(&self.comparison)?;

        for (index, kind) in [
            Q04AcknowledgementKindV1::Policy,
            Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement,
            Q04AcknowledgementKindV1::Clearance,
        ].into_iter().enumerate() {
            let packet = self.lookup(state, RootQ04RecordKeyV1::Packet(kind.phase()), identity.nonce())?;
            self.packets[index] = Some((|| {
                if packet.len() != kind.body_bytes() + 64 { return Err(CreateQ04ErrorV1::Bounds); }
                require_acknowledgement_body(kind, &packet[..kind.body_bytes()], identity)?;
                if packet[kind.body_bytes()..] == [0; 64]
                    || *value(&self.phases[index + 3])?.acknowledgement().as_bytes()
                        != <[u8; 32]>::from(Sha256::digest(packet)) {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                Ok(())
            })());
            value(&self.packets[index])?;
        }

        // Hash the existing checked chunk payloads directly; no second Claim
        // model, aggregate reconstruction or typed-policy parser is entered.
        let index = self.lookup(state, RootQ04RecordKeyV1::ClaimIndex, identity.nonce())?;
        self.index = Some(claim_index_shape(index, identity));
        let (total, count) = *value(&self.index)?;
        let mut digest = Sha256::new().chain_update(CLAIM_INDEX_DOMAIN).chain_update(&index[..64]);
        let mut reached = 0_usize;
        for ordinal in 0..count {
            let bytes = self.lookup(state, RootQ04RecordKeyV1::ClaimChunk(ordinal), identity.nonce())?;
            self.chunk = Some((|| {
                let chunk = Q04ClaimChunkV1::decode(bytes, index, identity)?;
                if chunk.chunk.index() != ordinal { return Err(CreateQ04ErrorV1::ChangedCut); }
                reached = reached.checked_add(chunk.chunk.payload().len()).ok_or(CreateQ04ErrorV1::Bounds)?;
                digest.update(chunk.chunk.payload());
                Ok(())
            })());
            value(&self.chunk)?;
        }
        self.comparison = Some(if reached == total && index[64..96] == <[u8; 32]>::from(digest.finalize()) {
            Ok(())
        } else { Err(CreateQ04ErrorV1::ChangedCut) });
        value(&self.comparison).map(|_| ())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.shape).or_else(|| cause(&self.lookup)).or_else(|| cause(&self.cut))
            .or_else(|| self.phases.iter().find_map(cause)).or_else(|| cause(&self.decision))
            .or_else(|| self.packets.iter().find_map(cause)).or_else(|| cause(&self.index))
            .or_else(|| cause(&self.chunk)).or_else(|| cause(&self.comparison))
    }
}

pub(crate) fn require_inert_root_open_history_v1(
    state: &State,
    originals: &mut RootInertHistoryScanV1,
) -> Result<(), CreateQ04ErrorV1> {
    originals.observe_once(state)
}

pub(crate) fn inert_root_open_history_scan_demand_v1()
    -> Result<ResourceVector, JournalError>
{
    // One active cut, its complete phase/decision scratch and one maximum
    // existing key allocation. The23 metadata destinations are18 active slots,
    // four scan controls/results and the caller's whole returned scan Result.
    // Positive comparisons physically dispose before
    // reuse; no failed result or future native cleanup is credited.
    let bytes = size_of::<RootInertHistoryScanV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2 * 47))
        .and_then(|bytes| bytes.checked_add(root_history_chunk_getter_control_bytes_v1()?))
        .ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?)
        .with(D::MetadataEntries, 23))
}

// Both actual Root history suppliers pay these new DATA method boundaries.
// Receiver and return planes are independent of the existing decoded chunk.
pub(crate) fn root_history_chunk_getter_control_bytes_v1() -> Option<usize> {
    size_of::<&aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04OrderedChunkV1<'_>>()
        .checked_mul(6)?
        .checked_add(size_of::<u16>().checked_mul(3)?)?
        .checked_add(size_of::<&[u8]>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
        // The readonly supplier keeps its original output before constructing
        // the separate Memory-only return and checked conversion planes.
        .checked_add(size_of::<(ResourceVector, D, u64)>().checked_mul(3)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>().checked_mul(3)?)
}

fn value<T>(slot: &Option<Result<T, CreateQ04ErrorV1>>) -> Result<&T, CreateQ04ErrorV1> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CreateQ04ErrorV1::ChangedCut)
}

fn cause<T>(slot: &Option<Result<T, CreateQ04ErrorV1>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalRecord, JournalTransaction};

    fn cut_state() -> State {
        let cut = super::super::tests::cut();
        BTreeMap::from([((RecordNamespace::DesiredState,
            RootQ04RecordKeyV1::Cut.encode(cut.nonce()).unwrap()), cut.bytes().to_vec())])
    }

    #[test]
    fn incomplete_actual_cut_keeps_failure_and_cannot_be_reentered() {
        let state = cut_state();
        let mut original = RootInertHistoryScanV1::default();

        assert!(original.observe_once(&state).is_err());
        let first = original.failure().unwrap() as *const dyn Error as *const ();
        assert!(original.observe_once(&BTreeMap::new()).is_err());

        assert_eq!(first, original.failure().unwrap() as *const dyn Error as *const ());
        assert!(original.active.cut.as_ref().unwrap().is_ok());
        assert!(original.active.lookup.as_ref().unwrap().is_ok());
        assert!(original.require_complete().is_err());
    }

    #[test]
    fn malformed_phase_namespace_and_orphan_chunk_remain_closed() {
        let cut = super::super::tests::cut();
        let mut malformed = RootQ04RecordKeyV1::Phase(7).encode(cut.nonce()).unwrap();
        *malformed.last_mut().unwrap() = 8;
        let cases = [
            BTreeMap::from([((RecordNamespace::DesiredState, malformed), vec![1])]),
            BTreeMap::from([((RecordNamespace::CreateStorageHistory,
                RootQ04RecordKeyV1::Cut.encode(cut.nonce()).unwrap()), cut.bytes().to_vec())]),
            BTreeMap::from([((RecordNamespace::DesiredState,
                RootQ04RecordKeyV1::ClaimChunk(0).encode(cut.nonce()).unwrap()), vec![1])]),
        ];

        for state in cases {
            let mut original = RootInertHistoryScanV1::default();
            assert!(original.observe_once(&state).is_err());
            assert!(original.failure().is_some());
            assert!(original.require_complete().is_err());
        }
    }

    #[test]
    fn ordinary_root_write_stays_denied_by_retained_q04_history() {
        let state = cut_state();
        let transaction = JournalTransaction::new([7; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]),
        ]).unwrap();

        assert!(super::super::require_root_q04_ordinary_boundary(&state, &transaction).is_err());
        assert!(super::super::require_root_q04_ordinary_boundary(&BTreeMap::new(), &transaction).is_ok());
    }
}
