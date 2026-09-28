//! Atomic Root release marker for a verified V8 terminal.
//!
//! ```text
//! AOSPC88L | version=1 | reserved[6]=0 | binding[32] | epoch:u64 |
//! AOSPC88T-digest[32] | released-AOSPCH01-digest[32] | SHA-256[32]
//! ```
//!
//! The distinct held V8 release socket calls this primitive only after it
//! verifies Controller's signed final command. Public Create remains closed
//! until the caller retains and postchecks every earlier owner.

use aos_sandbox_core::ObjectDigest;
use sha2::Sha256;

use crate::journal::{
    JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
};
use crate::policy_compiler::PolicyCompilerJournalErrorV1;
use crate::policy_compiler::binding_v2::hold::{HOLD_KEY, RootBindingHoldV1, current_hold};

use super::*;

pub(in crate::policy_compiler::binding_v2) const RELEASE_KEY: &[u8] =
    b"\0aos-policy-compiler-root-v8-terminal-release-v1\0";
const MAGIC: &[u8; 8] = b"AOSPC88L";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-terminal-release.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-v8-terminal-release-transaction.v1\0";
const RECORD_BYTES: usize = 152;

pub(super) fn replayed_release_marker_digest(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<ObjectDigest, RootV8EffectAckErrorV1> {
    let marker = authority
        .get(RELEASE_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    Ok(ObjectDigest::from_bytes(Sha256::digest(marker).into()))
}

fn release_record(
    binding: ObjectDigest,
    epoch: u64,
    terminal: &[u8],
    released_hold: &[u8],
) -> [u8; RECORD_BYTES] {
    let mut record = [0; RECORD_BYTES];
    record[..8].copy_from_slice(MAGIC);
    record[8..10].copy_from_slice(&1_u16.to_be_bytes());
    record[16..48].copy_from_slice(binding.as_bytes());
    record[48..56].copy_from_slice(&epoch.to_be_bytes());
    record[56..88].copy_from_slice(&Sha256::digest(terminal));
    record[88..120].copy_from_slice(&Sha256::digest(released_hold));
    let checksum = Sha256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(&record[..120])
        .finalize();
    record[120..].copy_from_slice(&checksum);
    record
}

fn release_transaction(
    held: RootBindingHoldV1,
    terminal: &[u8],
) -> Result<JournalTransaction, RootV8EffectAckErrorV1> {
    let released = RootBindingHoldV1 {
        held: false,
        ..held
    }
    .encode()?;
    let marker = release_record(held.binding, held.epoch, terminal, &released);
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(marker)
        .chain_update(released)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    Ok(JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                released.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                RELEASE_KEY.to_vec(),
                marker.to_vec(),
            ),
        ],
    )?)
}

pub(in crate::policy_compiler::binding_v2) fn release_capacity_transaction()
-> Result<JournalTransaction, RootV8EffectAckErrorV1> {
    release_transaction(
        RootBindingHoldV1 {
            issuer_owner: [1; 16],
            binding: ObjectDigest::from_bytes([1; 32]),
            epoch: 1,
            held: true,
        },
        &[1; RECORD_BYTES],
    )
}

pub(in crate::policy_compiler::binding_v2) fn release_marker_matches(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    hold: RootBindingHoldV1,
) -> Result<bool, PolicyCompilerJournalErrorV1> {
    let Some(marker) = authority.get(RELEASE_KEY)? else {
        return Ok(false);
    };
    if hold.held || hold.binding != binding || hold.epoch != epoch {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let terminal = authority
        .get(TERMINAL_KEY)?
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let released = hold.encode()?;
    if marker != release_record(binding, epoch, terminal, &released) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(true)
}

/// Releases only the verified Root hold under a caller-retained writer.
///
/// The held release socket reaches this after verifying the exact signed
/// Controller final command. Its caller must retain Controller, Source, and
/// Cache writers through their final postflight while this Root writer holds.
///
/// # Errors
///
/// Rejects an absent or changed terminal, binding hold, signed receipt,
/// journal capacity, or failed durable readback.
#[allow(dead_code)]
pub(in crate::policy_compiler::binding_v2) fn release_verified_terminal_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    expected: RootV8VerifiedTerminalV1,
) -> Result<RootV8TerminalCustodyV1, RootV8EffectAckErrorV1> {
    if current_terminal(authority, binding, epoch)? != Some(expected) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let held =
        current_hold(authority, head, next_epoch, count)?.ok_or(RootV8EffectAckErrorV1::Stale)?;
    if head != binding || !held.held || held.binding != binding || held.epoch != epoch {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let terminal = authority
        .get(TERMINAL_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let transaction = release_transaction(held, terminal)?;
    let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
    authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
    authority.commit(&transaction)?;
    let released = current_released_terminal_without_public_decision(authority, binding, epoch)?;
    if released != expected {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let marker = replayed_release_marker_digest(authority)?;
    Ok(RootV8TerminalCustodyV1::Released(released, marker))
}
