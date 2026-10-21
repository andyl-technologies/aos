//! Shares Q04 lower-clear framing and hashing as comparison DATA.
//!
//! Native membership, original-purpose loans and release observations remain
//! with the actual writer. These helpers never append or construct a grant.

/// Shares complete nonauthorizing Source Q04 transaction recipes.
pub mod source;

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{
    PHASE_BYTES, Q04CutIdentityV1, Q04HistoryDataErrorV1, Q04PhaseOwnerV1,
    Q04PhaseRecordV1, Q04TransactionOwnerV1,
};
use crate::cache_state::hold_state::CACHE_PENDING_KEY;
use crate::domain_ledger::{
    JournalTransactionDataError, ProtectedHistoryDataErrorV1,
    protected_names::ProtectedJournalNamesV1,
    transaction::{JournalTransaction, encode_transaction},
};

/// Identifies the existing saved Source Q04 pending row.
pub const SOURCE_PENDING_KEY: &[u8] = b"\0aos-source-domain-q04-pending-v1\0";

/// Preserves the original recipe comparison and canonical codec refusal.
#[derive(Debug, thiserror::Error)]
pub enum Q04RecipeDataErrorV1 {
    /// The original comparison fields or recipe shape changed.
    #[error("Q04 recipe comparison fields changed")]
    ChangedCut,
    /// A canonical length or aggregate extent cannot be represented.
    #[error("Q04 recipe exceeds its representation bound")]
    Bounds,
    /// The existing clear transaction sequence cannot be represented.
    #[error("Q04 recipe sequence is exhausted")]
    SequenceExhausted,
    /// The original fixed-history codec retained its refusal.
    #[error(transparent)]
    History(#[from] ProtectedHistoryDataErrorV1),
    /// The original transaction encoder retained its refusal.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
}

/// Hashes the same canonical clear frames at the supplied historical coordinates.
///
/// # Errors
/// Rejects unsupported owners, changed clear records, or framing overflow and
/// retains the actual canonical transaction error. Success supplies no grant.
pub fn lower_clear_recipe_digest_data_v1(
    identity: &Q04CutIdentityV1,
    owner: Q04TransactionOwnerV1,
    names: ProtectedJournalNamesV1,
    first_sequence: u64,
    transaction: &JournalTransaction,
) -> Result<ObjectDigest, Q04RecipeDataErrorV1> {
    let (tag, namespace, key) = match owner {
        Q04TransactionOwnerV1::Source => (
            1,
            RecordNamespace::SourceDomainPolicyHold,
            SOURCE_PENDING_KEY,
        ),
        Q04TransactionOwnerV1::Cache => (2, RecordNamespace::DesiredState, CACHE_PENDING_KEY),
        _ => return Err(Q04RecipeDataErrorV1::ChangedCut),
    };
    if first_sequence == 0
        || transaction.records().len() != 1
        || transaction.records()[0].namespace() != namespace
        || transaction.records()[0].key() != key
        || transaction.records()[0].value().is_some()
    {
        return Err(Q04RecipeDataErrorV1::ChangedCut);
    }
    let frames = encode_transaction(transaction, first_sequence)?;
    let native_bytes = frames.iter().try_fold(0_usize, |total, frame| {
        total
            .checked_add(frame.len())
            .ok_or(Q04RecipeDataErrorV1::Bounds)
    })?;
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.lower-clear-native-recipe.v1\0");
    digest.update([tag]);
    for value in [
        identity.bytes().as_slice(),
        names.to_bytes().as_slice(),
        first_sequence.to_be_bytes().as_slice(),
    ] {
        digest.update(
            u32::try_from(value.len())
                .map_err(|_| Q04RecipeDataErrorV1::Bounds)?
                .to_be_bytes(),
        );
        digest.update(value);
    }
    digest.update(
        u32::try_from(native_bytes)
            .map_err(|_| Q04RecipeDataErrorV1::Bounds)?
            .to_be_bytes(),
    );
    for frame in frames {
        digest.update(frame);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

/// Supplies unbranded event comparison DATA for a Controller phase recipe.
///
/// Shaped future DATA grants no commit, custody or currentness.
pub struct Q04ControllerPhaseEventsV1 {
    /// The canonical observed Root decision digest.
    pub decision: ObjectDigest,
    /// The canonical observed consumed-gate digest.
    pub consumed_gate: ObjectDigest,
    /// The canonical observed Root release digest.
    pub release: ObjectDigest,
    /// The canonical observed Root settlement digest.
    pub settlement: ObjectDigest,
    /// The canonical observed Root clearance digest.
    pub clearance: ObjectDigest,
    /// The canonical observed final Root phase digest.
    pub final_root: ObjectDigest,
    /// The three ordered held and released lower-record digest pairs.
    pub pairs: [ObjectDigest; 6],
    /// The canonical policy acknowledgement digest.
    pub policy_ack: ObjectDigest,
    /// The canonical release acknowledgement digest.
    pub release_ack: ObjectDigest,
    /// The canonical settlement acknowledgement digest.
    pub settlement_ack: ObjectDigest,
    /// The canonical clearance acknowledgement digest.
    pub clearance_ack: ObjectDigest,
}

/// Hashes complete retained lower-clearance fields as comparison DATA.
///
/// # Errors
/// Rejects non-settlement phases, zero clear digests, an empty Effect, or a
/// field length that cannot be represented by the established framing.
pub fn lower_clearance_recipe_digest_v1(
    identity: &Q04CutIdentityV1,
    root_settlement: &Q04PhaseRecordV1,
    cache_clear: ObjectDigest,
    source_clear: ObjectDigest,
    controller_settlement: &Q04PhaseRecordV1,
    status_three_effect: &[u8],
) -> Result<ObjectDigest, Q04HistoryDataErrorV1> {
    if root_settlement.owner() != Q04PhaseOwnerV1::Root || root_settlement.phase() != 6
        || controller_settlement.owner() != Q04PhaseOwnerV1::Controller
        || controller_settlement.phase() != 6
        || cache_clear.as_bytes() == &[0; 32] || source_clear.as_bytes() == &[0; 32]
        || status_three_effect.is_empty()
    {
        return Err(Q04HistoryDataErrorV1::ChangedCut);
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.lower-clearance-recipe.v1\0");
    for value in [
        identity.bytes().as_slice(), root_settlement.bytes().as_slice(),
        cache_clear.as_bytes().as_slice(), source_clear.as_bytes().as_slice(),
        controller_settlement.bytes().as_slice(), status_three_effect,
    ] {
        let length = u32::try_from(value.len()).map_err(|_| Q04HistoryDataErrorV1::Bounds)?;
        digest.update(length.to_be_bytes());
        digest.update(value);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

/// Reconstructs the canonical Controller phase from historical event DATA.
///
/// # Errors
/// Rejects an unsupported phase, a changed predecessor, or fields refused by
/// the existing transaction-identity and phase-record codecs.
pub fn controller_phase_recipe_v1(
    identity: &Q04CutIdentityV1,
    phase: u8,
    prior: Option<&Q04PhaseRecordV1>,
    events: &Q04ControllerPhaseEventsV1,
) -> Result<Q04PhaseRecordV1, Q04HistoryDataErrorV1> {
    if phase == 0 || phase > 8 || (phase == 1) != prior.is_none()
        || prior.is_some_and(|prior| prior.owner() != Q04PhaseOwnerV1::Controller
            || prior.phase().checked_add(1) != Some(phase))
    {
        return Err(Q04HistoryDataErrorV1::ChangedCut);
    }
    let predecessor = prior.map(Q04PhaseRecordV1::digest);
    let transaction = Q04TransactionOwnerV1::Controller.transaction_id(
        identity, phase, predecessor.unwrap_or(identity.before_controller_rows()),
    )?;
    let mut body = [0; PHASE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.stage_id());
    if let Some(predecessor) = predecessor {
        body[64..96].copy_from_slice(predecessor.as_bytes());
    }
    let introduced = [2, 2, 5, 6, 7, 8];
    for (index, event) in [events.decision, events.consumed_gate, events.release,
        events.settlement, events.clearance, events.final_root].into_iter().enumerate()
    {
        if phase >= introduced[index] {
            body[96 + index * 32..128 + index * 32].copy_from_slice(event.as_bytes());
        }
    }
    for (index, pair) in events.pairs.iter().enumerate() {
        if (index == 0 || phase >= 2) && (index % 2 == 0 || phase >= 5) {
            body[288 + index * 32..320 + index * 32].copy_from_slice(pair.as_bytes());
        }
    }
    let acknowledgement = match phase {
        3 | 4 => Some(events.policy_ack),
        5 => Some(events.release_ack),
        6 | 7 => Some(events.settlement_ack),
        8 => Some(events.clearance_ack),
        _ => None,
    };
    if let Some(acknowledgement) = acknowledgement {
        body[480..512].copy_from_slice(acknowledgement.as_bytes());
    }
    body[512..544].copy_from_slice(identity.before_controller_rows().as_bytes());
    body[544..560].copy_from_slice(&transaction);
    let record = Q04PhaseRecordV1::from_body(Q04PhaseOwnerV1::Controller, phase, body, identity)?;
    if let Some(prior) = prior {
        record.require_successor(prior)?;
    }
    Ok(record)
}

/// Derives the existing nonissuing lower-release capacity comparison shape.
///
/// The same fixed-width lower suffix can be forecast before Root5 exists.
/// This digest cannot replace the actual original-flight loan or authorize a
/// lower release; the committing owner must still bind the observed Root5.
pub fn lower_release_capacity_shape_data_v1(identity: &Q04CutIdentityV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.create-q04.lower-release-capacity-shape.v1\0")
            .chain_update(identity.bytes())
            .finalize()
            .into(),
    )
}
