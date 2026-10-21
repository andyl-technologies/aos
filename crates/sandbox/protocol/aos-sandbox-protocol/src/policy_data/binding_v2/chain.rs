//! Validates complete borrowed Root binding rows in the original check order.
//!
//! Staged DATA methods let native owners keep their original gate calls between
//! scans and comparisons. The composed method uses the same stages; it neither
//! clones a row map nor accepts a parser, native callback or authority witness.

use super::{
    BINDING_V2_KEY_PREFIX, BindingDataErrorV1, ClosedPolicyRootBindingV2, HOLD_KEY,
    MAXIMUM_POLICY_BINDINGS, POLICY_BINDING_KEY_PREFIX, PROOF_KEY_PREFIX, RETIRED_EFFECT_ACK_KEY,
    RETIRED_EFFECT_CHALLENGE_KEY, ROOT_BINDING_HEAD_KEY, RootBindingHoldV1, RootQualifiedProofV1,
    decode_closed_policy_binding_v2, proof_key,
};
use aos_sandbox_model::ObjectDigest;
use std::collections::BTreeSet;

/// Retains the original full-chain comparison scratch as unbranded DATA.
///
/// The real native caller supplies every row from the same held DesiredState
/// map and independently performs its original authority/currentness gates.
/// A successful stage or scalar head cannot grant any role operation.
pub struct RootBindingChainDataV2 {
    bindings: Vec<(ClosedPolicyRootBindingV2, ObjectDigest)>,
    binding_epochs: BTreeSet<(ObjectDigest, u64)>,
    operations: BTreeSet<[u8; 16]>,
    effect_transactions: BTreeSet<[u8; 16]>,
    predecessor: ObjectDigest,
    proofs_checked: bool,
    ordered: bool,
    next_generation: Option<u64>,
}

impl RootBindingChainDataV2 {
    /// Scans the complete actual row set using the existing key/value decoder.
    ///
    /// # Errors
    /// Rejects retired ACK/challenge/legacy binding keys, malformed closed
    /// records and the original binding-count limit.
    pub fn from_records_v2<'rows>(
        records: impl Iterator<Item = (&'rows [u8], &'rows [u8])>,
    ) -> Result<Self, BindingDataErrorV1> {
        let mut bindings = Vec::new();
        for (key, value) in records {
            if key == RETIRED_EFFECT_ACK_KEY || key == RETIRED_EFFECT_CHALLENGE_KEY {
                return Err(BindingDataErrorV1::UnauthenticatedCandidate);
            }
            if key.starts_with(POLICY_BINDING_KEY_PREFIX) {
                return Err(BindingDataErrorV1::UnauthenticatedCandidate);
            }
            if key.starts_with(BINDING_V2_KEY_PREFIX) {
                let binding = decode_closed_policy_binding_v2(key, value)?;
                let head: [u8; 32] = key[BINDING_V2_KEY_PREFIX.len()..]
                    .try_into()
                    .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?;
                bindings.push((binding, ObjectDigest::from_bytes(head)));
            }
        }
        if bindings.len() > MAXIMUM_POLICY_BINDINGS {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let binding_epochs = bindings
            .iter()
            .map(|(binding, head)| (*head, binding.root_generation))
            .collect();
        Ok(Self {
            bindings,
            binding_epochs,
            operations: BTreeSet::new(),
            effect_transactions: BTreeSet::new(),
            predecessor: ObjectDigest::from_bytes([0; 32]),
            proofs_checked: false,
            ordered: false,
            next_generation: None,
        })
    }

    /// Checks every canonical proof against the same complete binding set.
    ///
    /// # Errors
    /// Rejects wrong proof framing/key/binding epoch or repeated/out-of-order stages.
    pub fn require_proof_records_v2<'rows>(
        &mut self,
        records: impl Iterator<Item = (&'rows [u8], &'rows [u8])>,
    ) -> Result<(), BindingDataErrorV1> {
        if self.proofs_checked || self.ordered {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        for (key, value) in records {
            if !key.starts_with(PROOF_KEY_PREFIX) {
                continue;
            }
            let proof = RootQualifiedProofV1::decode(value)?;
            if key != proof_key(proof.binding).as_slice()
                || !self.binding_epochs.contains(&(proof.binding, proof.epoch))
            {
                return Err(BindingDataErrorV1::UnauthenticatedCandidate);
            }
        }
        self.proofs_checked = true;
        Ok(())
    }

    /// Checks original contiguous generations, predecessors and unique operations.
    ///
    /// # Errors
    /// Rejects missing proof scan, repeated stage, a generation/epoch break,
    /// wrong predecessor, repeated operation or repeated effect transaction.
    pub fn require_ordered_v2(&mut self) -> Result<(), BindingDataErrorV1> {
        if !self.proofs_checked || self.ordered {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        self.bindings
            .sort_by_key(|(binding, _)| binding.root_generation);
        for (index, (binding, head)) in self.bindings.iter().enumerate() {
            let generation = u64::try_from(index + 1)
                .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?;
            if binding.root_generation != generation
                || binding.root_predecessor != self.predecessor
                || binding.barrier_epoch != generation
                || binding.handoff_epoch != generation
                || !self.operations.insert(*binding.operation.as_bytes())
                || !self.effect_transactions.insert(binding.effect_transaction)
            {
                return Err(BindingDataErrorV1::UnauthenticatedCandidate);
            }
            self.predecessor = *head;
        }
        self.ordered = true;
        Ok(())
    }

    /// Checks the original head pointer before deriving the next generation.
    ///
    /// # Errors
    /// Rejects a missing/mismatched head, an unexpected empty-chain pointer,
    /// a repeated stage or arithmetic overflow.
    pub fn require_head_v2(
        &mut self,
        pointer: Option<&[u8]>,
    ) -> Result<(ObjectDigest, u64, usize), BindingDataErrorV1> {
        if !self.ordered
            || self.next_generation.is_some()
            || (self.bindings.is_empty() && pointer.is_some())
            || (!self.bindings.is_empty() && pointer != Some(self.predecessor.as_bytes()))
        {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let next_generation = u64::try_from(self.bindings.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(BindingDataErrorV1::UnauthenticatedCandidate)?;
        self.next_generation = Some(next_generation);
        Ok((self.predecessor, next_generation, self.bindings.len()))
    }

    /// Checks the existing hold issuer against the actual last binding record.
    ///
    /// # Errors
    /// Rejects an incomplete stage or a different hold issuer/absence.
    pub fn require_hold_issuer_v2(
        &self,
        held: Option<RootBindingHoldV1>,
    ) -> Result<(), BindingDataErrorV1> {
        if self.next_generation.is_none()
            || held.map(|record| record.issuer_owner)
                != self
                    .bindings
                    .last()
                    .map(|(binding, _)| binding.issuer_owner)
        {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        Ok(())
    }
}

/// Checks the canonical hold row against the supplied complete-chain coordinates.
///
/// These coordinates are comparison DATA, not native custody or a current grant.
/// # Errors
/// Rejects malformed hold bytes, inconsistent presence, head or epoch.
pub fn current_hold_v1(
    raw: Option<&[u8]>,
    head: ObjectDigest,
    next_epoch: u64,
    count: usize,
) -> Result<Option<RootBindingHoldV1>, BindingDataErrorV1> {
    let record = raw.map(RootBindingHoldV1::decode).transpose()?;
    if (count == 0) != record.is_none() {
        return Err(BindingDataErrorV1::UnauthenticatedCandidate);
    }
    if let Some(held) = record {
        if held.binding != head || held.epoch.checked_add(1) != Some(next_epoch) {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
    }
    Ok(record)
}

/// Validates every binding, proof, pointer and hold in complete borrowed rows.
///
/// The iterator must be the actual complete immutable map view. It is cloned
/// only as a borrowed cursor; no row map, native owner or authority is adopted.
/// # Errors
/// Preserves the original full-chain framing, order, uniqueness and hold gates.
pub fn current_root_binding_chain_v2<'rows, I>(
    mut records: I,
) -> Result<(ObjectDigest, u64, usize), BindingDataErrorV1>
where
    I: Iterator<Item = (&'rows [u8], &'rows [u8])> + Clone,
{
    let mut chain = RootBindingChainDataV2::from_records_v2(records.clone())?;
    chain.require_proof_records_v2(records.clone())?;
    chain.require_ordered_v2()?;
    let pointer = records
        .clone()
        .find_map(|(key, value)| (key == ROOT_BINDING_HEAD_KEY).then_some(value));
    let coordinates = chain.require_head_v2(pointer)?;
    let raw = records.find_map(|(key, value)| (key == HOLD_KEY).then_some(value));
    let held = current_hold_v1(raw, coordinates.0, coordinates.1, coordinates.2)?;
    chain.require_hold_issuer_v2(held)?;
    Ok(coordinates)
}

/// Prices the actual complete-chain comparison representation before decoding.
///
/// The count comes from the actual complete held row scan and is deliberately
/// not clamped to the semantic maximum: the original decoder visits all rows
/// before its count check. This DATA quote grants no admission or authority.
/// Native owners separately retain and price their complete held source and
/// native bookends. This function prices Memory only, not namespace permission.
///
/// # Errors
/// Returns `None` when checked representation geometry cannot fit `usize`.
#[must_use]
pub fn root_binding_chain_receiving_bytes_v2(raw_binding_count: usize) -> Option<usize> {
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1;
    use std::mem::{align_of, size_of};

    type BindingRow = (ClosedPolicyRootBindingV2, ObjectDigest);
    type Epoch = (ObjectDigest, u64);

    // Rust 1.98.1 RawVec starts at four slots for these nonzero elements and
    // doubles. Include old and new backing during a moving reallocation.
    let slots = if raw_binding_count == 0 {
        0
    } else {
        raw_binding_count.max(4).checked_next_power_of_two()?
    };
    let binding_rows = slots.checked_mul(size_of::<BindingRow>())?.checked_mul(3)?;
    // BTreeSet::from_iter first collects and stable-sorts its own input Vec;
    // its backing remains live during the bulk construction of epoch nodes.
    let epoch_rows = slots.checked_mul(size_of::<Epoch>())?.checked_mul(3)?;
    let indices = conservative_btree_node_bytes_v1::<Epoch, ()>(raw_binding_count)?
        .checked_add(conservative_btree_node_bytes_v1::<[u8; 16], ()>(
            raw_binding_count,
        )?)?
        .checked_add(conservative_btree_node_bytes_v1::<[u8; 16], ()>(
            raw_binding_count,
        )?)?;

    // The pinned stable sorter uses at most max(len,48) elements of heap
    // scratch, an aligned 4096-byte local buffer, and 66 run/depth slots.
    // Conservatively sum both sort invocations rather than credit reuse.
    let sort_elements = raw_binding_count.max(48);
    let sort_heap = sort_elements
        .checked_mul(size_of::<BindingRow>())?
        .checked_add(sort_elements.checked_mul(size_of::<Epoch>())?)?;
    let sort_fixed = 4096usize
        .checked_add(align_of::<BindingRow>())?
        .checked_add(66usize.checked_mul(size_of::<usize>())?)?
        .checked_add(66)?
        .checked_mul(2)?;

    // Sole codec fixed wire widths are AOSPCB02=664, AOSPCP01=280 and
    // AOSPCH01=104. Keep decode/re-encode/hash/key construction and returned
    // controls beside the resident chain, without optimizer/layout credit.
    type Decode = (
        sha2::Sha256,
        ClosedPolicyRootBindingV2,
        RootQualifiedProofV1,
        RootBindingHoldV1,
        [u8; 664],
        [u8; 280],
        [u8; 104],
        [u8; 32],
        Result<ClosedPolicyRootBindingV2, BindingDataErrorV1>,
        Result<RootQualifiedProofV1, BindingDataErrorV1>,
        Result<RootBindingHoldV1, BindingDataErrorV1>,
    );
    let keys = BINDING_V2_KEY_PREFIX
        .len()
        .checked_add(32)?
        .checked_add(PROOF_KEY_PREFIX.len().checked_add(32)?)?;
    size_of::<RootBindingChainDataV2>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<RootBindingChainDataV2, BindingDataErrorV1>>())?
        .checked_add(size_of::<Decode>().checked_mul(3)?)?
        .checked_add(keys.checked_mul(2)?)?
        .checked_add(binding_rows)?
        .checked_add(epoch_rows)?
        .checked_add(indices)?
        .checked_add(sort_heap)?
        .checked_add(sort_fixed)
}
