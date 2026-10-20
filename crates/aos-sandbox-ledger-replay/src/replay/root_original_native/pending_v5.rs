//! Checks saved Pending sequence and witness DATA.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{NativeHeldSectionTagV1 as Tag, assertion::RootNativeDispositionAssertionV1, witness::NativeHeldOwnerWitnessV1};

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_pending_sequence(
    state: &State,
    transaction: &JournalTransaction,
    attempt: [u8; 32],
    successor_sequence: u64,
) -> Result<(), JournalError> {
    let before = graph(state)?;
    // Capacity DEL/PUT rows are independently checked by the exact funded
    // owner edge. This graph projection accepts only its namespace40 PUTs.
    let owners: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        .cloned()
        .collect();
    let after = graph(&apply(state, &owners)?)?;
    let Some(old) = before.sidecars().get(&attempt) else {
        return Ok(());
    };
    let next = after.sidecars().get(&attempt).ok_or_else(invalid)?;
    if old.suffix().phase() == 1
        && next
            .disposition_cut()
            .is_some_and(RootNativeCutV1::is_pending_disposition)
    {
        if transaction.records().len() != 6 {
            return Err(invalid());
        }
        validate_witness(
            old,
            next.suffix().prepared().ok_or_else(invalid)?,
            next.disposition().ok_or_else(invalid)?,
            successor_sequence,
        )?;
    }
    Ok(())
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_witness(
    old: &RootNativeHeldSidecarV2,
    unsigned8: &PreparedNativeHeldControlV1,
    r: &RootNativeDispositionAssertionV1,
    sequence: u64,
) -> Result<(), JournalError> {
    let root1 = old
        .suffix()
        .control(NativeHeldControlKindV1::RootPrepared)
        .ok_or_else(invalid)?;
    let NativeHeldOwnerWitnessV1::Root(mut expected) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        root1.section(Tag::Witness).ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?
    else {
        return Err(invalid());
    };

    expected.journal_sequence = sequence;
    expected.records = r.records.clone();
    if unsigned8.signer() != root1.prepared().signer()
        || unsigned8.predecessor() != root1.digest()
        || unsigned8.section(Tag::Witness)
            != Some(
                NativeHeldOwnerWitnessV1::Root(expected)
                    .to_canonical_bytes()
                    .map_err(|_| invalid())?
                    .as_slice(),
            )
    {
        return Err(invalid());
    }
    Ok(())
}

