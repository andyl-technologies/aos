//! Shares Q04 lower-clear framing and hashing as comparison DATA.
//!
//! Native membership, original-purpose loans and release observations remain
//! with the actual writer. These helpers never append or construct a grant.

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{Q04CutIdentityV1, Q04TransactionOwnerV1};
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
