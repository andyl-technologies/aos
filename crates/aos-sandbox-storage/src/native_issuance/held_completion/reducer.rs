//! Exact one-row data reductions; no method acquires an owner or authorizes IO.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3;
use aos_sandbox_source_provider_protocol::native_held_completion::assertion::{
    NativeHeldDispositionV1, NativeHeldSettlementV1,
};
use aos_sandbox_source_provider_protocol::native_held_completion::recovery::{
    NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1, StorageNativeRecoveryStateV1,
};
use aos_sandbox_source_provider_protocol::native_held_completion::witness::{
    NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1, NativeHeldRecordFamilyV1,
    native_held_record_byte_digest_v1,
};

use super::*;

/// Names one closed data transition, not a signing or dispatch permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageHeldStepV1 {
    /// Inserts the original interest with signed RootPrepared only.
    InterestRecorded,
    /// Retains unsigned2 before any positive packet can escape.
    HeldPrepared,
    /// Stores the exact signed successor of unsigned2.
    HeldStored,
    /// Retains the first immutable Root disposition proof.
    RootDispositionRecorded,
    /// Prepares the exact unsigned6 or first cold12.
    SettlementPrepared,
    /// Selects cold unsigned12, replacing only an optional unescaped unsigned6.
    ///
    /// The future IO owner must prove old hot authority unavailable. This data
    /// variant does not establish that fact or permit an effect retry.
    ColdCarrierPrepared,
    /// Stores the exact previously prepared terminal and clears that slot.
    SettlementStored,
    /// Adds only first11 then12 to an already settled normal6 row (R4).
    AlreadySettledRecoveryProofRecorded,
    /// Records only the existing separate nonzero retirement pair.
    RetirementRecorded,
    /// Requires byte-identical complete before/after state and appends nothing.
    ExactReplay,
}

/// Returns checked canonical mutation data without committing it.
#[derive(Debug)]
pub(crate) struct StorageHeldReductionV1 {
    /// The sole exact replacement transaction, absent on exact replay.
    pub(crate) transaction: Option<JournalTransaction>,
}

/// Validates complete issuance states and one exact named before/after mutation.
///
/// The sequence is only a diagnostic supplied by the real future owner. This
/// function does not prove the snapshots came from a retained physical gate.
///
/// # Errors
///
/// Rejects wrong keys, recycled identity, legacy upgrade, unrelated changes,
/// assertion/witness mismatches, replacement archives and all unnamed steps.
pub(crate) fn reduce(
    before: &BTreeMap<[u8; 48], Vec<u8>>,
    after: &BTreeMap<[u8; 48], Vec<u8>>,
    before_sequence: u64,
    step: StorageHeldStepV1,
) -> Result<StorageHeldReductionV1> {
    let old = decode_state(before)?;
    let new = decode_state(after)?;
    if step == StorageHeldStepV1::ExactReplay {
        if before != after {
            return Err(invalid("conflicting exact replay"));
        }
        return Ok(StorageHeldReductionV1 { transaction: None });
    }
    if before.keys().any(|key| !after.contains_key(key)) {
        return Err(invalid("removed issuance identity"));
    }
    let changed = after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .map(|(key, _)| *key)
        .collect::<Vec<_>>();
    let [key] = changed.as_slice() else {
        return Err(invalid("exactly one issuance mutation"));
    };
    let Some(StorageIssuanceValueV1::Held(next)) = new.get(key) else {
        return Err(invalid("held transition target"));
    };
    match old.get(key) {
        None if step == StorageHeldStepV1::InterestRecorded && next.suffix.phase() == 0 => {}
        Some(StorageIssuanceValueV1::Held(previous)) => {
            validate_step(previous, next, before_sequence, step)?
        }
        _ => return Err(invalid("legacy value is not a held admission")),
    }
    Ok(StorageHeldReductionV1 {
        transaction: Some(next.transaction()?),
    })
}

// The same non-recycling index covers active, retired, legacy and held rows.
pub(super) fn decode_state(
    values: &BTreeMap<[u8; 48], Vec<u8>>,
) -> Result<BTreeMap<[u8; 48], StorageIssuanceValueV1>> {
    if values.len() > super::super::MAXIMUM_ISSUANCES {
        return Err(invalid("issuance row count"));
    }
    let mut identities = super::super::NativeIssuanceIdentityIndexV1::default();
    values
        .iter()
        .map(|(key, bytes)| {
            let value = StorageIssuanceValueV1::from_canonical_bytes(bytes)?;
            if value.original().key() != *key {
                return Err(invalid("actual issuance key"));
            }
            identities.insert(value.original())?;
            Ok((*key, value))
        })
        .collect()
}

pub(super) fn validate_prefix(row: &StorageHeldIssuanceRowV2) -> Result<()> {
    let suffix = &row.suffix;
    let mut kinds = suffix
        .controls()
        .iter()
        .map(SignedNativeHeldControlV1::kind)
        .collect::<Vec<_>>();
    if kinds.first() != Some(&Kind::RootPrepared) {
        return Err(invalid("original first archive"));
    }
    kinds.remove(0);
    if kinds.first() == Some(&Kind::StorageHeld) {
        kinds.remove(0);
    }
    let remaining = kinds.as_slice();
    let phase = suffix.phase();
    let prepared = suffix.prepared().map(|value| value.kind());
    let legal = match phase {
        0 => suffix.controls().len() == 1 && prepared.is_none(),
        1 => suffix.controls().len() == 1 && prepared == Some(Kind::StorageHeld),
        2 => suffix.controls().len() == 2 && remaining.is_empty() && prepared.is_none(),
        3 => {
            matches!(
                remaining,
                [Kind::ProviderRelay]
                    | [Kind::ProviderStorageRecoveryQuery]
                    | [Kind::ProviderRelay, Kind::ProviderStorageRecoveryQuery]
            ) && match prepared {
                None => true,
                Some(Kind::StorageSettled) => remaining == [Kind::ProviderRelay],
                Some(Kind::StorageRecoveryState) => {
                    remaining.last() == Some(&Kind::ProviderStorageRecoveryQuery)
                }
                _ => false,
            }
        }
        4 | 5 => {
            prepared.is_none()
                && matches!(
                    remaining,
                    [Kind::ProviderRelay, Kind::StorageSettled]
                        | [
                            Kind::ProviderStorageRecoveryQuery,
                            Kind::StorageRecoveryState
                        ]
                        | [
                            Kind::ProviderRelay,
                            Kind::ProviderStorageRecoveryQuery,
                            Kind::StorageRecoveryState
                        ]
                        | [
                            Kind::ProviderRelay,
                            Kind::StorageSettled,
                            Kind::ProviderStorageRecoveryQuery,
                            Kind::StorageRecoveryState
                        ]
                )
        }
        _ => false,
    };
    if !legal {
        return Err(invalid("closed Storage chronology/preparation"));
    }
    let scope = row.scope()?;
    for control in suffix.controls().iter().skip(1) {
        if control.scope() != &scope {
            return Err(invalid("complete original control scope"));
        }
        if control.kind() == Kind::ProviderStorageRecoveryQuery {
            let query = NativeHeldRecoveryQueryV1::from_canonical_bytes(required(
                control,
                Tag::RecoveryQuery,
            )?)?;
            if query.mode != NativeHeldRecoveryModeV1::SettleRecordedDisposition
                || query.original_prepared != suffix.controls()[0].digest()
            {
                return Err(invalid("original preparation/current Settle query"));
            }
        }
    }
    if suffix
        .prepared()
        .is_some_and(|control| control.scope() != &scope)
    {
        return Err(invalid("complete original prepared scope"));
    }
    if row.root_disposition()?.is_some() != (phase >= 3) {
        return Err(invalid("immutable Root phase"));
    }

    if let Some(held) = suffix.control(Kind::StorageHeld) {
        validate_held(row, held.prepared())?;
    }
    if let Some(prepared) = suffix.prepared() {
        if prepared.kind() == Kind::StorageHeld {
            validate_held(row, prepared)?
        } else {
            validate_terminal(row, prepared)?
        }
    }
    if let Some(terminal) = suffix.control(Kind::StorageSettled) {
        validate_terminal(row, terminal.prepared())?;
    }
    if let Some(terminal) = suffix.control(Kind::StorageRecoveryState) {
        validate_terminal(row, terminal.prepared())?;
    }
    Ok(())
}

fn prefix(
    row: &StorageHeldIssuanceRowV2,
    phase: u8,
    controls: Vec<SignedNativeHeldControlV1>,
) -> Result<StorageHeldIssuanceRowV2> {
    let mut original = row.original.clone();
    original.retirement = None;
    Ok(StorageHeldIssuanceRowV2 {
        original,
        suffix: NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            phase,
            row.suffix.flight(),
            None,
            controls,
        )?,
    })
}

fn matches_witness(
    row: &StorageHeldIssuanceRowV2,
    witness: &NativeHeldByteWitnessV1,
) -> Result<()> {
    if witness.family() != NativeHeldRecordFamilyV1::StorageIssuance
        || witness.key() != row.key()
        || witness.digest()
            != native_held_record_byte_digest_v1(
                NativeHeldRecordFamilyV1::StorageIssuance,
                &row.key(),
                &row.encode_fields()?,
            )?
    {
        return Err(invalid("exact canonical before issuance witness"));
    }
    Ok(())
}

fn validate_held(
    row: &StorageHeldIssuanceRowV2,
    control: &PreparedNativeHeldControlV1,
) -> Result<()> {
    let original = row
        .suffix
        .control(Kind::RootPrepared)
        .ok_or_else(|| invalid("original RootPrepared"))?;
    if control.section(Tag::RootPrepared) != Some(original.to_canonical_bytes().as_slice()) {
        return Err(invalid("unchanged original signed RootPrepared"));
    }
    let reply = StorageNativeAcquireReplyV3::from_canonical_bytes(
        control
            .section(Tag::NativeReply)
            .ok_or_else(|| invalid("original reply"))?,
    )
    .map_err(|_| invalid("original canonical native reply"))?;
    if reply.acceptance().acceptance() != &row.original.acceptance {
        return Err(invalid("complete original unsigned acceptance"));
    }
    let claims = row.original.request.request().claims();
    let catalog = claims.catalog();
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            claims.selection().0,
        )
        .map_err(|_| invalid("original native selection"))?;
    if reply.receipt().receipt().attempt() != claims.attempt()
        || reply.receipt().receipt().binding_digest() != claims.selection().0
        || reply.receipt().receipt().resource() != &resource
        || reply.receipt().receipt().snapshot() != &snapshot
    {
        return Err(invalid("complete original native receipt"));
    }
    let before = prefix(row, 0, vec![original.clone()])?;
    let NativeHeldOwnerWitnessV1::Storage(witness) =
        NativeHeldOwnerWitnessV1::from_canonical_bytes(
            Owner::Storage,
            control
                .section(Tag::Witness)
                .ok_or_else(|| invalid("Storage witness"))?,
        )?
    else {
        return Err(invalid("Storage witness role"));
    };
    matches_witness(&before, &witness.issuance)
}

fn validate_terminal(
    row: &StorageHeldIssuanceRowV2,
    control: &PreparedNativeHeldControlV1,
) -> Result<()> {
    let own = row
        .settlement()?
        .ok_or_else(|| invalid("original settlement assertion"))?;
    if control.kind() == Kind::StorageSettled {
        let relay = row
            .suffix
            .control(Kind::ProviderRelay)
            .ok_or_else(|| invalid("normal relay predecessor"))?;
        let settlement = NativeHeldSettlementV1::from_canonical_bytes(
            control
                .section(Tag::Settlement)
                .ok_or_else(|| invalid("settlement tuple"))?,
        )?;
        if control.predecessor() != relay.digest()
            || settlement.disposition != own.disposition
            || settlement.root_disposition != own.root_disposition
            || settlement.storage_settlement != own.digest()?
        {
            return Err(invalid("normal complete settlement identity"));
        }
        let before = prefix(
            row,
            3,
            row.suffix
                .controls()
                .iter()
                .take_while(|control| control.kind() != Kind::StorageSettled)
                .cloned()
                .collect(),
        )?;
        let NativeHeldOwnerWitnessV1::Storage(witness) =
            NativeHeldOwnerWitnessV1::from_canonical_bytes(
                Owner::Storage,
                control
                    .section(Tag::Witness)
                    .ok_or_else(|| invalid("settlement witness"))?,
            )?
        else {
            return Err(invalid("settlement witness role"));
        };
        matches_witness(&before, &witness.issuance)?;
    } else {
        let query = row
            .suffix
            .control(Kind::ProviderStorageRecoveryQuery)
            .ok_or_else(|| invalid("first query11"))?;
        if control.predecessor() != query.digest()
            || control.section(Tag::RecoveryQuery) != query.section(Tag::RecoveryQuery)
        {
            return Err(invalid("exact current 11->12 correlation"));
        }
        let state = StorageNativeRecoveryStateV1::from_canonical_bytes(
            control
                .section(Tag::StorageRecoveryState)
                .ok_or_else(|| invalid("Storage recovery state"))?,
        )?;
        let fields = &state.fields;
        let normal = row.suffix.control(Kind::StorageSettled);
        let before_controls = row
            .suffix
            .controls()
            .iter()
            .filter(|value| {
                value.kind() != Kind::StorageRecoveryState
                    && (normal.is_none() || value.kind() != Kind::ProviderStorageRecoveryQuery)
            })
            .cloned()
            .collect();
        let before = prefix(row, if normal.is_some() { 4 } else { 3 }, before_controls)?;
        if fields.phase != before.suffix.phase()
            || fields.native_request != row.original.request.digest()
            || fields.acceptance != row.original.acceptance.digest()
            || fields.disposition.as_ref() != row.root_disposition()?.as_ref()
            || fields.root_disposition != own.root_disposition
            || fields.storage_settlement != own.digest()?
            || fields.own_assertion != own.to_canonical_bytes()?
            || fields.hot_terminal.as_deref().is_some_and(|archive| {
                normal
                    .map(SignedNativeHeldControlV1::to_canonical_bytes)
                    .as_deref()
                    != Some(archive)
            })
        {
            return Err(invalid("complete historical Storage12 before state"));
        }
        let witness = fields
            .witness
            .as_ref()
            .ok_or_else(|| invalid("actual before witness"))?;
        if normal.is_some() {
            // R4 removes ONLY the two added archives and recovers exact old bytes.
            matches_witness(&before, witness)?;
        } else if witness.family() != NativeHeldRecordFamilyV1::StorageIssuance
            || witness.key() != row.key()
        {
            return Err(invalid("cold historical issuance subject"));
        }
        // Cold substitution deliberately discards an unescaped unsigned6. Its
        // historical value cannot be recovered from the after-row alone. Only
        // the exact before/after reducer below checks that byte commitment;
        // replay/current trust must establish its provenance before owner IO.
    }
    Ok(())
}

fn validate_step(
    old: &StorageHeldIssuanceRowV2,
    new: &StorageHeldIssuanceRowV2,
    sequence: u64,
    step: StorageHeldStepV1,
) -> Result<()> {
    let old_root = old.root_disposition()?;
    let new_root = new.root_disposition()?;
    if old.original.request != new.original.request
        || old.original.acceptance != new.original.acceptance
        || old.suffix.flight() != new.suffix.flight()
        || old_root
            .as_ref()
            .is_some_and(|root| new_root.as_ref() != Some(root))
        || !new.suffix.controls().starts_with(old.suffix.controls())
    {
        return Err(invalid("immutable originals and append-once archives"));
    }
    let added = &new.suffix.controls()[old.suffix.controls().len()..];
    let kinds = added
        .iter()
        .map(SignedNativeHeldControlV1::kind)
        .collect::<Vec<_>>();
    let phases = (old.suffix.phase(), new.suffix.phase());
    let old_prepared = old.suffix.prepared();
    let new_prepared = new.suffix.prepared();
    let mut expected_retirement = old.original.retirement;
    let legal = match step {
        StorageHeldStepV1::HeldPrepared => {
            phases == (0, 1) && added.is_empty() && new_prepared.is_some()
        }
        StorageHeldStepV1::HeldStored => {
            phases == (1, 2)
                && kinds == [Kind::StorageHeld]
                && signed_successor(old_prepared, added.first())
                && new_prepared.is_none()
        }
        StorageHeldStepV1::RootDispositionRecorded => {
            phases.0 <= 2
                && phases.1 == 3
                && matches!(
                    kinds.as_slice(),
                    [Kind::ProviderRelay] | [Kind::ProviderStorageRecoveryQuery]
                )
                && new_prepared.is_none()
        }
        StorageHeldStepV1::SettlementPrepared => {
            phases == (3, 3) && old_prepared.is_none() && new_prepared.is_some() && added.is_empty()
        }
        StorageHeldStepV1::ColdCarrierPrepared => {
            phases == (3, 3)
                && old_prepared.is_none_or(|value| value.kind() == Kind::StorageSettled)
                && new_prepared.is_some_and(|value| value.kind() == Kind::StorageRecoveryState)
                && kinds == [Kind::ProviderStorageRecoveryQuery]
        }
        StorageHeldStepV1::SettlementStored => {
            phases == (3, 4)
                && added.len() == 1
                && signed_successor(old_prepared, added.first())
                && new_prepared.is_none()
        }
        StorageHeldStepV1::AlreadySettledRecoveryProofRecorded => {
            phases == (4, 4)
                && old_prepared.is_none()
                && new_prepared.is_none()
                && old.suffix.control(Kind::StorageSettled).is_some()
                && old
                    .suffix
                    .control(Kind::ProviderStorageRecoveryQuery)
                    .is_none()
                && old.suffix.control(Kind::StorageRecoveryState).is_none()
                && kinds
                    == [
                        Kind::ProviderStorageRecoveryQuery,
                        Kind::StorageRecoveryState,
                    ]
        }
        StorageHeldStepV1::RetirementRecorded => {
            expected_retirement = new.original.retirement;
            phases == (4, 5)
                && added.is_empty()
                && old_prepared.is_none()
                && new_prepared.is_none()
                && old.original.retirement.is_none()
                && new.original.retirement.is_some()
        }
        _ => false,
    };
    if !legal || new.original.retirement != expected_retirement {
        return Err(invalid("closed named Storage transition"));
    }
    if step == StorageHeldStepV1::RootDispositionRecorded
        && old_prepared.is_some()
        && (new
            .root_disposition()?
            .is_none_or(|root| root.disposition != NativeHeldDispositionV1::Closed)
            || old_prepared.is_none_or(|value| value.kind() != Kind::StorageHeld))
    {
        return Err(invalid(
            "only irreversible Closed clears unsigned held offer",
        ));
    }
    if step == StorageHeldStepV1::RootDispositionRecorded
        && kinds == [Kind::ProviderRelay]
        && phases.0 != 2
        && new
            .root_disposition()?
            .is_some_and(|root| root.disposition == NativeHeldDispositionV1::Accepted)
    {
        return Err(invalid("hot Accepted requires original stored held offer"));
    }
    if matches!(
        step,
        StorageHeldStepV1::HeldPrepared
            | StorageHeldStepV1::SettlementPrepared
            | StorageHeldStepV1::ColdCarrierPrepared
    ) {
        let prepared = new_prepared.ok_or_else(|| invalid("prepared successor"))?;
        if prepared.kind() == Kind::StorageRecoveryState {
            let state = StorageNativeRecoveryStateV1::from_canonical_bytes(
                prepared
                    .section(Tag::StorageRecoveryState)
                    .ok_or_else(|| invalid("prepared state"))?,
            )?;
            if state.fields.diagnostic_sequence != sequence {
                return Err(invalid("prepared diagnostic before sequence"));
            }
            matches_witness(
                old,
                state
                    .fields
                    .witness
                    .as_ref()
                    .ok_or_else(|| invalid("prepared exact before witness"))?,
            )?;
        } else {
            let NativeHeldOwnerWitnessV1::Storage(witness) =
                NativeHeldOwnerWitnessV1::from_canonical_bytes(
                    Owner::Storage,
                    prepared
                        .section(Tag::Witness)
                        .ok_or_else(|| invalid("prepared witness"))?,
                )?
            else {
                return Err(invalid("prepared owner"));
            };
            if witness.issuance_sequence != sequence {
                return Err(invalid("prepared diagnostic before sequence"));
            }
        }
    }
    if step == StorageHeldStepV1::AlreadySettledRecoveryProofRecorded {
        let state = StorageNativeRecoveryStateV1::from_canonical_bytes(required(
            &added[1],
            Tag::StorageRecoveryState,
        )?)?;
        if state.fields.diagnostic_sequence != sequence {
            return Err(invalid("R4 exact pre-append sequence"));
        }
        matches_witness(
            old,
            state
                .fields
                .witness
                .as_ref()
                .ok_or_else(|| invalid("R4 witness"))?,
        )?;
    }
    for query in added
        .iter()
        .filter(|control| control.kind() == Kind::ProviderStorageRecoveryQuery)
    {
        if NativeHeldRecoveryQueryV1::from_canonical_bytes(required(query, Tag::RecoveryQuery)?)?
            .mode
            != NativeHeldRecoveryModeV1::SettleRecordedDisposition
        {
            return Err(invalid("Observe cannot append"));
        }
    }
    Ok(())
}

fn signed_successor(
    prepared: Option<&PreparedNativeHeldControlV1>,
    signed: Option<&SignedNativeHeldControlV1>,
) -> bool {
    prepared
        .zip(signed)
        .is_some_and(|(prepared, signed)| prepared == signed.prepared())
}
