//! Builds the single passive Root Q04 suffix used for preflight and history.
//!
//! Future ACKs and heads are exact-width capacity representatives only. The
//! actual native History separately owns eligibility and every returned append
//! Result; constructing or editing these DATA never grants a commit permission.

use super::root_records::*;
use super::{
    PolicyQ04DataErrorV1, Q04AcknowledgementKindV1, Q04ClaimStorageRecipeV1, Q04ClaimV1,
    Q04PreholdInputDataV1, Q04PreviewV1, Q04RootStageRecipeV1, encode_q04_claim_body_v1, fixed,
};
use aos_sandbox_model::ObjectDigest;
use sha2::Digest as _;
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    Q04CutIdentityV1, Q04PhaseRecordV1, Q04TransactionOwnerV1,
    root_consumed_gate_record_v1 as root_consumed_gate_record,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

/// Owns canonical future-shape buffers without native eligibility.
#[derive(Default)]
pub struct RootQ04SuffixDataV1 {
    /// Retains the complete Claim DATA bytes.
    pub claim: Vec<u8>,
    /// Retains four future or authentic ACK DATA packets.
    pub packets: Vec<Vec<u8>>,
    /// Retains seven ordered Root phase DATA records.
    pub phases: Vec<Q04PhaseRecordV1>,
    /// Retains the original canonical Claim chunk encodings.
    pub chunks: Vec<Vec<u8>>,
    /// Retains the complete ordered canonical transaction recipes.
    pub transactions: Vec<JournalTransaction>,
    /// Marks only completed shape construction, never native admission.
    pub complete: bool,
}

/// Borrows the unchanged passive inputs used to form one capacity suffix.
pub struct RootQ04SuffixInputDataV1<'plan> {
    /// Borrows the original comparison identity.
    pub identity: &'plan Q04CutIdentityV1,
    /// Borrows canonical proposed binding bytes.
    pub binding: &'plan [u8],
    /// Copies the original Root all-row digest.
    pub root_before: ObjectDigest,
    /// Copies original Root NEXT as comparison DATA.
    pub root_sequence: u64,
    /// Copies original compiler-state NEXT as comparison DATA.
    pub state_sequence: u64,
    /// Bounds the exact canonical complete Claim width.
    pub claim_length: usize,
    /// Retains the complete Claim DATA bytes.
    pub claim: Option<&'plan super::Q04ClaimV1<'plan>>,
    /// Optionally supplies already authenticated held comparison fields.
    pub held_pairs: Option<[ObjectDigest; 6]>,
}

impl RootQ04SuffixDataV1 {
    /// Bounds one fresh suffix construction before any buffer growth.
    ///
    /// This counts the actual Claim/chunk/group dimensions, fixed canonical
    /// keys and record widths, and the genuine Stage's retained transaction.
    /// The resident suffix header belongs to its enclosing native History.
    /// Every later ACK-driven rebuild must fund its own fresh construction;
    /// this measurement neither releases the previous suffix nor pays native
    /// replay, prospective maps or append encoding.
    ///
    /// Returns `None` for invalid Claim dimensions or representation overflow.
    #[must_use]
    pub fn receiving_bytes_v1(claim_length: usize, stage: &Q04RootStageRecipeV1) -> Option<usize> {
        use aos_sandbox_protocol::domain_ledger::create_q04_history::{
            CLAIM_CHUNK_PREFIX_BYTES, CLAIM_INDEX_BYTES, DECISION_BYTES, IDENTITY_BYTES,
            PHASE_BYTES, chunk_count,
        };
        use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
        use aos_sandbox_protocol::policy_data::binding_v2::{
            BINDING_V2_KEY_PREFIX, CLOSED_POLICY_BINDING_BYTES_V2, HOLD_KEY, ROOT_BINDING_HEAD_KEY,
            RootBindingHoldV1,
        };
        use std::mem::size_of;

        let count = usize::from(chunk_count(claim_length, super::MAXIMUM_CLAIM_BYTES).ok()?);
        let groups = count.checked_add(127)?.checked_div(128)?;
        let transactions = 8_usize.checked_add(groups)?;
        let chunk_bytes = claim_length.checked_add(count.checked_mul(CLAIM_CHUNK_PREFIX_BYTES)?)?;
        let ack_bytes = [
            Q04AcknowledgementKindV1::Policy,
            Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement,
            Q04AcknowledgementKindV1::Clearance,
        ]
        .into_iter()
        .try_fold(0_usize, |sum, kind| {
            sum.checked_add(kind.body_bytes().checked_add(64)?)
        })?;

        // root_record reserves prefix + nonce + the maximum two-byte suffix.
        let root_keys = [
            (RootQ04RecordKeyV1::Cut, 1_usize),
            (RootQ04RecordKeyV1::Phase(1), 7),
            (RootQ04RecordKeyV1::Decision, 1),
            (RootQ04RecordKeyV1::Packet(1), 4),
            (RootQ04RecordKeyV1::ClaimIndex, 1),
            (RootQ04RecordKeyV1::ClaimChunk(0), count),
        ]
        .into_iter()
        .try_fold(0_usize, |sum, (key, number)| {
            sum.checked_add(key.prefix().len().checked_add(18)?.checked_mul(number)?)
        })?;
        let binding_keys = BINDING_V2_KEY_PREFIX
            .len()
            .checked_add(32)?
            .checked_add(ROOT_BINDING_HEAD_KEY.len())?
            .checked_add(HOLD_KEY.len().checked_mul(3)?)?;
        let root_values = IDENTITY_BYTES
            .checked_add(PHASE_BYTES.checked_mul(7)?)?
            .checked_add(CLAIM_INDEX_BYTES)?
            .checked_add(chunk_bytes)?
            .checked_add(DECISION_BYTES)?
            .checked_add(ack_bytes)?;
        let binding_values = CLOSED_POLICY_BINDING_BYTES_V2
            .checked_add(32)?
            .checked_add(RootBindingHoldV1::encoded_bytes_v1().checked_mul(3)?)?;
        // The local released record remains owned while its clone is inserted.
        let payloads = claim_length.checked_mul(3)?
            .checked_add(chunk_bytes)?
            .checked_add(ack_bytes.checked_mul(3)?)?
            .checked_add(root_keys)?.checked_add(binding_keys)?
            .checked_add(root_values)?.checked_add(binding_values)?
            .checked_add(CLOSED_POLICY_BINDING_BYTES_V2)?;

        // The three-record qualified Vec grows to at least four slots while
        // its previous allocation may still be live. Nine slots bound its
        // old three plus new six; all other record Vecs reserve exact counts.
        let stage_records = stage.transaction().records().len();
        let records = 19_usize.checked_add(count)?.checked_sub(stage_records)?
            .checked_add(5)?.checked_add(1)?;
        let backing = count.checked_add(4)?.checked_mul(size_of::<Vec<u8>>())?
            .checked_add(transactions.checked_mul(size_of::<JournalTransaction>())?)?
            .checked_add(records.checked_mul(size_of::<JournalRecord>())?)?
            .checked_add(7_usize.checked_mul(size_of::<Q04PhaseRecordV1>())?)?;
        // The transaction Vec above already contains the Stage's inline
        // header. Only its genuine cloned record/key/value backing is extra.
        let stage_backing = stage.transaction().retained_receiving_bytes_v2()?
            .checked_sub(size_of::<JournalTransaction>())?;
        let bytes = payloads.checked_add(stage_backing)?.checked_add(backing)?;
        let controls = [
            size_of::<RootQ04SuffixInputDataV1<'_>>(),
            size_of::<sha2::Sha256>(),
            size_of::<super::ClosedPolicyRootBindingV2>(),
            size_of::<RootBindingHoldV1>(),
            size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1>(),
            size_of::<[u8; CLAIM_CHUNK_PREFIX_BYTES]>(),
            size_of::<[u8; 64]>(),
            size_of::<Result<(), PolicyQ04DataErrorV1>>(),
            size_of::<Result<JournalTransaction, aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>(),
            size_of::<Result<JournalRecord, PolicyQ04DataErrorV1>>(),
            size_of::<Result<Q04PhaseRecordV1, PolicyQ04DataErrorV1>>(),
            size_of::<Result<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04RootDecisionV1, PolicyQ04DataErrorV1>>(),
            size_of::<Result<(Vec<JournalRecord>, JournalRecord), PolicyQ04DataErrorV1>>(),
            size_of::<Q04ClaimV1<'_>>(),
            size_of::<Q04ClaimStorageRecipeV1<'_>>(),
            size_of::<[ObjectDigest; 6]>(),
            size_of::<[ObjectDigest; 5]>(),
            size_of::<[u8; crate::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]>(),
            size_of::<[u8; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2]>(),
        ].into_iter().try_fold(0_usize, |sum, size| sum.checked_add(size))?
            .checked_mul(3)?;
        bytes.checked_add(controls)
    }

    // There is no authentic future signature at prehold. These exact codec
    // shapes traverse the sole Claim/chunk/native encoders to bound every
    // eligible fixed-width variation. They may never be offered to commit.
    /// Builds the unchanged canonical suffix as nonissuing capacity DATA.
    ///
    /// # Errors
    /// Refuses reentry, inconsistent canonical widths, invalid phase fields,
    /// exhausted bounds or actual bounded allocation failure.
    pub fn form(
        &mut self,
        plan: RootQ04SuffixInputDataV1<'_>,
        stage: &Q04RootStageRecipeV1,
        request: &Q04PreholdInputDataV1<'_>,
        preview: &Q04PreviewV1<'_>,
        source_packet: &[u8],
    ) -> Result<(), PolicyQ04DataErrorV1> {
        let identity = plan.identity;
        if self.complete
            || !self.claim.is_empty()
            || !self.transactions.is_empty()
            || !self.chunks.is_empty()
            || !self.phases.is_empty()
            || !self.packets.is_empty()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let original = request.fields();
        let inputs = preview.fields();
        let held_controller_shape =
            [0; crate::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let held_cache_shape =
            [0; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        if let Some(claim) = plan.claim {
            self.claim.try_reserve_exact(claim.bytes().len())?;
            self.claim.extend_from_slice(claim.bytes());
        } else {
            encode_q04_claim_body_v1(
                &mut self.claim,
                [
                    original[1],
                    original[2],
                    original[3],
                    inputs[3],
                    inputs[4],
                    inputs[5],
                    inputs[6],
                    inputs[8],
                    plan.binding,
                    original[5],
                    &held_controller_shape,
                    source_packet,
                    &held_cache_shape,
                    identity.bytes(),
                ],
                identity,
            )?;
            self.claim.try_reserve_exact(64)?;
            self.claim.extend_from_slice(&[0; 64]);
        }
        if self.claim.len() != plan.claim_length {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let claim = Q04ClaimV1::decode(&self.claim, identity)?;
        let storage = Q04ClaimStorageRecipeV1::new(&claim, identity)?;
        let count = storage.chunk_count();
        let groups = count.checked_add(127).ok_or(PolicyQ04DataErrorV1::Bounds)? / 128;
        self.transactions
            .try_reserve_exact(8 + usize::from(groups))?;
        self.chunks.try_reserve_exact(usize::from(count))?;
        self.phases.try_reserve_exact(7)?;
        self.packets.try_reserve_exact(4)?;

        let mut pairs = [ObjectDigest::from_bytes([0; 32]); 6];
        for (index, pair) in pairs.iter_mut().enumerate() {
            *pair = capacity_shape_digest(
                identity,
                u8::try_from(index + 1).map_err(|_| PolicyQ04DataErrorV1::Bounds)?,
            )?;
        }
        if let Some(actual) = plan.held_pairs {
            // Only held fields have been observed at this boundary. Future
            // released representatives remain noncommitting capacity DATA.
            for index in [0, 2, 4] {
                pairs[index] = actual[index];
            }
        }
        let r1_id = Q04TransactionOwnerV1::Root.transaction_id(identity, 1, plan.root_before)?;
        let r1 = root_phase_record(
            identity,
            1,
            r1_id,
            plan.root_before,
            None,
            [ObjectDigest::from_bytes([0; 32]); 5],
            pairs,
            None,
        )?;
        self.transactions.push(JournalTransaction::new(
            r1_id,
            vec![
                root_record(RootQ04RecordKeyV1::Cut, identity, identity.bytes())?,
                root_record(RootQ04RecordKeyV1::Phase(1), identity, r1.bytes())?,
                root_record(
                    RootQ04RecordKeyV1::ClaimIndex,
                    identity,
                    storage.index_bytes(),
                )?,
            ],
        )?);
        self.phases.push(r1);

        for chunk in 0..count {
            // The same parent owns the empty chunk before its first growth.
            self.chunks.push(Vec::new());
            storage.encode_chunk(
                chunk,
                self.chunks
                    .last_mut()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?,
            )?;
        }
        for group in 0..groups {
            let first = usize::from(group) * 128;
            let last = self.chunks.len().min(first + 128);
            let mut records = Vec::new();
            records.try_reserve_exact(last - first)?;
            for chunk in first..last {
                records.push(root_record(
                    RootQ04RecordKeyV1::ClaimChunk(
                        u16::try_from(chunk).map_err(|_| PolicyQ04DataErrorV1::Bounds)?,
                    ),
                    identity,
                    &self.chunks[chunk],
                )?);
            }
            let id = root_claim_group_id(
                identity,
                group,
                self.phases
                    .first()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?
                    .digest(),
            )?;
            self.transactions
                .push(JournalTransaction::new(id, records)?);
        }
        self.transactions.push(stage.transaction().clone());

        let (mut qualified, released) = stage.q04_binding_capacity_records(plan.binding)?;
        let r2 = self.next_phase(
            identity,
            2,
            plan.root_before,
            [ObjectDigest::from_bytes([0; 32]); 5],
            pairs,
            None,
        )?;
        qualified.push(root_record(
            RootQ04RecordKeyV1::Phase(2),
            identity,
            r2.bytes(),
        )?);
        self.transactions.push(JournalTransaction::new(
            r2.native_transaction_id(),
            qualified,
        )?);
        self.phases.push(r2);

        // The capacity decision points to the earlier R2 recipe, never its
        // own R3 transaction. The live decision must instead consume actual
        // qualified-CAS and policy-state committed native readbacks.
        let decision = root_decision_record(
            identity,
            self.phases
                .last()
                .ok_or(PolicyQ04DataErrorV1::ChangedCut)?
                .native_transaction_id(),
            plan.state_sequence
                .checked_add(5)
                .ok_or(PolicyQ04DataErrorV1::Bounds)?,
            plan.root_sequence,
            pairs[2],
            pairs[4],
        )?;
        let gate = root_consumed_gate_record(identity, &decision)?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        let mut events = [decision.digest(), zero, zero, zero, zero];
        let r3 = self.next_phase(identity, 3, plan.root_before, events, pairs, None)?;
        self.transactions.push(JournalTransaction::new(
            r3.native_transaction_id(),
            vec![
                root_record(RootQ04RecordKeyV1::Decision, identity, decision.bytes())?,
                root_record(RootQ04RecordKeyV1::Phase(3), identity, r3.bytes())?,
            ],
        )?);
        self.phases.push(r3);

        let controller_next = u64::from_be_bytes(fixed(original[0], 464));
        for (index, kind) in [
            Q04AcknowledgementKindV1::Policy,
            Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement,
            Q04AcknowledgementKindV1::Clearance,
        ]
        .into_iter()
        .enumerate()
        {
            self.packets.push(Vec::new());
            root_capacity_acknowledgement(
                self.packets
                    .last_mut()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?,
                kind,
                identity,
                controller_next,
                gate.digest(),
                pairs,
            )?;
            events[1] = gate.digest();
            if index == 1 {
                events[2] = capacity_shape_digest(identity, 7)?;
            } else if index == 2 {
                events[2] = self
                    .phases
                    .last()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?
                    .digest();
            } else if index == 3 {
                events[3] = self
                    .phases
                    .last()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?
                    .digest();
                events[4] = capacity_shape_digest(identity, 8)?;
            }
            let acknowledgement = ObjectDigest::from_bytes(
                sha2::Sha256::digest(
                    self.packets
                        .last()
                        .ok_or(PolicyQ04DataErrorV1::ChangedCut)?
                        .as_slice(),
                )
                .into(),
            );
            let phase = u8::try_from(index + 4).map_err(|_| PolicyQ04DataErrorV1::Bounds)?;
            let record = self.next_phase(
                identity,
                phase,
                plan.root_before,
                events,
                pairs,
                Some(acknowledgement),
            )?;
            let mut records = Vec::new();
            records.try_reserve_exact(if phase == 5 { 3 } else { 2 })?;
            if phase == 5 {
                records.push(released.clone());
            }
            records.push(root_record(
                RootQ04RecordKeyV1::Packet(kind.phase()),
                identity,
                self.packets
                    .last()
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?,
            )?);
            records.push(root_record(
                RootQ04RecordKeyV1::Phase(phase),
                identity,
                record.bytes(),
            )?);
            self.transactions.push(JournalTransaction::new(
                record.native_transaction_id(),
                records,
            )?);
            self.phases.push(record);
        }

        let records = self
            .transactions
            .iter()
            .try_fold(0_usize, |sum, transaction| {
                sum.checked_add(transaction.records().len())
                    .ok_or(PolicyQ04DataErrorV1::Bounds)
            })?;
        if self.transactions.len() != 8 + usize::from(groups)
            || records != 19 + usize::from(count)
            || self.phases.len() != 7
            || self.packets.len() != 4
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        self.complete = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn next_phase(
        &self,
        identity: &Q04CutIdentityV1,
        phase: u8,
        before: ObjectDigest,
        events: [ObjectDigest; 5],
        pairs: [ObjectDigest; 6],
        acknowledgement: Option<ObjectDigest>,
    ) -> Result<Q04PhaseRecordV1, PolicyQ04DataErrorV1> {
        let prior = self.phases.last().ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
        let transaction =
            Q04TransactionOwnerV1::Root.transaction_id(identity, phase, prior.digest())?;
        let record = root_phase_record(
            identity,
            phase,
            transaction,
            before,
            Some(prior.digest()),
            events,
            pairs,
            acknowledgement,
        )?;
        record.require_successor(prior)?;
        Ok(record)
    }
}
