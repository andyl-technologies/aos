//! Root-local custody for one closed policy binding handoff.
//!
//! ```text
//! AOSPCH01 | version=1 | phase=held|released | reserved=0 |
//! issuer-owner[16] | binding-head[32] | handoff-epoch[8] | SHA-256[32]
//! ```
//!
//! The record is committed in the same transaction as AOSPCB02. It preserves
//! ambiguity after a lost response or process crash. It does not freeze the
//! Controller, source-domain, or Cache owners and grants no effect authority.

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
};

use super::{PolicyCompilerJournalErrorV1, ROOT_TRANSACTION_DOMAIN};

pub(super) const HOLD_KEY: &[u8] = b"\0aos-policy-compiler-binding-hold-v1\0";
const MAGIC: &[u8; 8] = b"AOSPCH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-hold.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-hold-release.v1\0";
const RECORD_BYTES: usize = 104;

pub(super) use aos_sandbox_policy::q04_data::RootBindingHoldV1;

pub(super) fn current_hold(
    authority: &ProtectedJournalAuthority<'_>,
    head: ObjectDigest,
    next_epoch: u64,
    count: usize,
) -> Result<Option<RootBindingHoldV1>, PolicyCompilerJournalErrorV1> {
    let record = authority
        .get(HOLD_KEY)?
        .map(RootBindingHoldV1::decode)
        .transpose()?;
    if (count == 0) != record.is_none() {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    if let Some(held) = record {
        if held.binding != head || held.epoch.checked_add(1) != Some(next_epoch) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
    }
    Ok(record)
}

pub(super) fn release_hold(
    authority: &mut ProtectedJournalAuthority<'_>,
    expected: RootBindingHoldV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let expected_bytes = expected.encode()?;
    if !expected.held || authority.get(HOLD_KEY)? != Some(expected_bytes.as_slice()) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let released = RootBindingHoldV1 {
        held: false,
        ..expected
    }
    .encode()?;
    let digest = Sha256::new()
        .chain_update(RELEASE_DOMAIN)
        .chain_update(ROOT_TRANSACTION_DOMAIN)
        .chain_update(released)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            HOLD_KEY.to_vec(),
            released.to_vec(),
        )],
    )
    .map_err(crate::journal::JournalError::from)?;
    authority.commit(&transaction)?;
    if authority.get(HOLD_KEY)? != Some(released.as_slice()) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}
