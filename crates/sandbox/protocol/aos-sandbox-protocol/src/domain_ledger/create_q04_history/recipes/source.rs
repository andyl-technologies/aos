//! Owns complete Source Q04 hold transaction recipes as comparison DATA.
//!
//! The same canonical hold codec and pending-record codec produce all three
//! transactions. No native Source owner, Root release proof or live phase is
//! created here; the caller retains its independent original writer gates.

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{Q04RecipeDataErrorV1, SOURCE_PENDING_KEY, lower_clear_recipe_digest_data_v1};
use super::super::{
    PENDING_BYTES, Q04CutIdentityV1, Q04PendingOwnerV1, Q04PendingRecordV1,
    Q04TransactionOwnerV1,
};
use crate::domain_ledger::{
    protected_names::ProtectedJournalNamesV1,
    source_policy_hold::{KEY, SourceDomainPolicyHoldV1},
    transaction::{JournalRecord, JournalTransaction},
};

/// Retains complete nonauthorizing held, released and clear transaction DATA.
pub struct Q04SourceHoldRecipeBodiesV1 {
    /// The canonical historical held pending record.
    pub held_marker: Q04PendingRecordV1,
    /// The canonical historical released pending record.
    pub released_marker: Q04PendingRecordV1,
    /// The ordered acquire, release and clear transaction recipes.
    pub transactions: [JournalTransaction; 3],
}

/// Constructs the exact Source Q04 records and three canonical transactions.
///
/// # Errors
/// Rejects changed original fields, a zero release digest, or a record or
/// transaction refused by the original canonical codecs.
pub fn q04_hold_recipe_bodies(
    identity: &Q04CutIdentityV1,
    names: ProtectedJournalNamesV1,
    held: SourceDomainPolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<Q04SourceHoldRecipeBodiesV1, Q04RecipeDataErrorV1> {
    if !held.is_held() || held.operation() != identity.operation()
        || held.sandbox() != identity.sandbox() || held.binding() != identity.binding()
        || held.epoch() != identity.epoch() || held.ancestry() != identity.ancestry()
        || release_authorization.as_bytes() == &[0; 32]
    {
        return Err(Q04RecipeDataErrorV1::ChangedCut);
    }
    let released = (held).released_data();
    let owner_recipe = ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.source-before-owner-recipe.v1\0")
        .chain_update(names.to_bytes())
        .chain_update(held.encode()?)
        .chain_update(released.encode()?)
        .finalize().into());
    let mut body = [0; PENDING_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.nonce());
    body[64..96].copy_from_slice(identity.binding().as_bytes());
    body[96..104].copy_from_slice(&identity.epoch().to_be_bytes());
    body[104..136].copy_from_slice(held.record_digest()?.as_bytes());
    body[136..168].copy_from_slice(released.record_digest()?.as_bytes());
    body[200..232].copy_from_slice(owner_recipe.as_bytes());
    let held_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Source, 1, body)?;
    body[168..200].copy_from_slice(release_authorization.as_bytes());
    let released_marker = Q04PendingRecordV1::from_body(Q04PendingOwnerV1::Source, 2, body)?;
    released_marker.require_release_of(&held_marker)?;

    let acquire = q04_transaction(identity, 1, owner_recipe, vec![
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, KEY.to_vec(), held.encode()?.to_vec()),
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec(), held_marker.bytes().to_vec()),
    ])?;
    let release = q04_transaction(identity, 2, held_marker.digest(), vec![
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, KEY.to_vec(), released.encode()?.to_vec()),
        JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec(), released_marker.bytes().to_vec()),
    ])?;
    let clear = q04_transaction(identity, 3, released_marker.digest(), vec![
        JournalRecord::delete(RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY.to_vec()),
    ])?;
    Ok(Q04SourceHoldRecipeBodiesV1 {
        held_marker, released_marker, transactions: [acquire, release, clear],
    })
}

/// Hashes the complete Source clear native recipe at its original coordinate.
///
/// # Errors
/// Retains the original hold recipe refusal, exhausted clear sequence, or
/// canonical clear-frame encoding error.
pub fn q04_clear_recipe_digest_data(
    identity: &Q04CutIdentityV1,
    names: ProtectedJournalNamesV1,
    original_next: u64,
    held: SourceDomainPolicyHoldV1,
    release_authorization: ObjectDigest,
) -> Result<ObjectDigest, Q04RecipeDataErrorV1> {
    let bodies = q04_hold_recipe_bodies(identity, names, held, release_authorization)?;
    lower_clear_recipe_digest_data_v1(
        identity, Q04TransactionOwnerV1::Source, names,
        original_next.checked_add(8).ok_or(Q04RecipeDataErrorV1::SequenceExhausted)?,
        &bodies.transactions[2],
    )
}

fn q04_transaction(
    identity: &Q04CutIdentityV1,
    phase: u8,
    predecessor: ObjectDigest,
    records: Vec<JournalRecord>,
) -> Result<JournalTransaction, Q04RecipeDataErrorV1> {
    JournalTransaction::new(
        Q04TransactionOwnerV1::Source.transaction_id(identity, phase, predecessor)?,
        records,
    ).map_err(Q04RecipeDataErrorV1::from)
}
