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

use aos_sandbox_core::ObjectDigest;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootBindingHoldV1 {
    pub(super) issuer_owner: [u8; 16],
    pub(super) binding: ObjectDigest,
    pub(super) epoch: u64,
    pub(super) held: bool,
}

impl RootBindingHoldV1 {
    pub(super) fn encode(self) -> Result<[u8; RECORD_BYTES], PolicyCompilerJournalErrorV1> {
        if self.issuer_owner == [0; 16] || self.binding.as_bytes() == &[0; 32] || self.epoch == 0 {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(&self.issuer_owner);
        bytes[32..64].copy_from_slice(self.binding.as_bytes());
        bytes[64..72].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..72])
            .finalize();
        bytes[72..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let record = Self {
            issuer_owner: bytes[16..32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            binding: ObjectDigest::from_bytes(
                bytes[32..64]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[64..72]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            ),
            held: bytes[10] == 1,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(record)
    }
}

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
    )?;
    authority.commit(&transaction)?;
    if authority.get(HOLD_KEY)? != Some(released.as_slice()) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}
