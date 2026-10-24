//! Root's durable V8 settlement of a released predecessor.
//!
//! ```text
//! AOSPC88S | version=1 | reserved[6]=0 | predecessor[32] | epoch:u64 |
//! next-epoch:u64 | SHA-256(AOSQ8S01)[32] | SHA-256(AOSPC88L)[32] |
//! SHA-256(released AOSCPH01)[32] | SHA-256(released AOSSDH01)[32] |
//! SHA-256(signed AOSCTS08)[32] | SHA-256(settlement-domain || first 224 bytes)[32]
//! ```
//!
//! Root records this after Controller S and before any later Create. The
//! transaction also retires the fixed V8 flight slots. The immutable marker
//! lets owners clear their pending-release fences before new hold acquisition.

use aos_sandbox_policy::journal_keys::CONTROLLER_HOLD_PIN_KEY;

use std::{io, path::Path};

use aos_sandbox_model::ObjectDigest;
pub use aos_sandbox_protocol::root_settlement::RootV8SuccessorSettlementV1;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
    controller_v8_root_receipt_record_digest_v1,
};
use crate::policy_compiler::PolicyCompilerJournalErrorV1;
use crate::policy_compiler::binding_v2::held_cas_proof_key;
use crate::policy_compiler::controller_effect_ack_readback::ControllerEffectAckChallengeV1;
use crate::policy_compiler::controller_v8_settlement_readback::verify_controller_v8_settlement_readback_v1;

use super::*;

const KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-root-v8-successor-settlement-v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-v8-successor-settlement-transaction.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-successor-settlement-cut.v1\0";

fn key(predecessor: ObjectDigest) -> Vec<u8> {
    [KEY_PREFIX, predecessor.as_bytes()].concat()
}

fn settlement_transaction(
    settlement: RootV8SuccessorSettlementV1,
) -> Result<JournalTransaction, PolicyCompilerJournalErrorV1> {
    let bytes = settlement.record_bytes()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let mut records = vec![JournalRecord::put(
        RecordNamespace::DesiredState,
        key(settlement.predecessor),
        bytes.to_vec(),
    )];
    records.extend(
        [
            terminal::release::RELEASE_KEY,
            ACK_KEY,
            terminal::TERMINAL_KEY,
        ]
        .into_iter()
        .map(|key| JournalRecord::delete(RecordNamespace::DesiredState, key.to_vec())),
    );
    Ok(JournalTransaction::new(id, records).map_err(crate::journal::JournalError::from)?)
}

/// Reads and validates the immutable marker for one predecessor.
pub(in crate::policy_compiler::binding_v2) fn settlement_for_predecessor(
    authority: &ProtectedJournalAuthority<'_>,
    predecessor: ObjectDigest,
) -> Result<Option<RootV8SuccessorSettlementV1>, PolicyCompilerJournalErrorV1> {
    let Some(bytes) = authority.get(&key(predecessor))? else {
        return Ok(None);
    };
    let settlement = RootV8SuccessorSettlementV1::from_record_bytes(bytes)
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    if settlement.predecessor != predecessor {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(Some(settlement))
}

/// Requires an old V8 binding to be settled before a successor CAS.
pub(in crate::policy_compiler::binding_v2) fn require_settled_predecessor(
    authority: &ProtectedJournalAuthority<'_>,
    predecessor: ObjectDigest,
    next_epoch: u64,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    if !current_flight_slots_empty(authority)? {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let settlement = settlement_for_predecessor(authority, predecessor)?;
    let held_proof = authority.get(&held_cas_proof_key(predecessor))?;
    match (held_proof, settlement) {
        (None, None) => Ok(()),
        (Some(_), Some(settlement)) if settlement.next_epoch == next_epoch => Ok(()),
        _ => Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate),
    }
}

pub(super) fn settlement_capacity_transaction()
-> Result<JournalTransaction, PolicyCompilerJournalErrorV1> {
    settlement_transaction(RootV8SuccessorSettlementV1 {
        predecessor: ObjectDigest::from_bytes([1; 32]),
        epoch: 1,
        next_epoch: 2,
        settlement: ObjectDigest::from_bytes([1; 32]),
        release_marker: ObjectDigest::from_bytes([1; 32]),
        cache_released: ObjectDigest::from_bytes([1; 32]),
        source_released: ObjectDigest::from_bytes([1; 32]),
        signed_receipt: ObjectDigest::from_bytes([1; 32]),
    })
}

/// Settles a released V8 predecessor under Controller, then Root custody.
///
/// The caller retains Controller's protected writer while Root opens its own
/// writer last. Its exchange must sign the exact Controller AOSQ8S01 row while
/// that Controller writer remains held. This transition grants no Create or
/// Apply; it only permits owner-local pending-release fences to clear after a
/// separate peer-checked Root readback.
///
/// # Errors
///
/// Rejects missing release evidence, a stale Controller signer, an absent or
/// mismatched signed settlement, ambiguous Root commit, or failed readback.
pub fn settle_fixed_closed_root_v8_predecessor_v1(
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8SuccessorSettlementV1, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    settle_in_authority(
        &mut authority,
        binding,
        epoch,
        uid,
        credential,
        aos_sandbox_broker::root_nonce::fresh_root_nonce,
        exchange,
    )
}

/// Replays one settled predecessor from the protected Root journal.
///
/// This local read does not provide a peer-checked grant to Cache or Source.
/// Their signer transport must compare the typed marker under fixed Root
/// custody before clearing owner-local pending-release fences.
///
/// # Errors
///
/// Rejects a malformed marker, missing historical binding, inconsistent slots
/// while that predecessor is still current, or failed Root journal custody.
pub fn recover_fixed_closed_root_v8_predecessor_settlement_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8SuccessorSettlementV1>, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    recover_from_authority(&authority, binding, epoch)
}

pub(super) fn recover_from_authority(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8SuccessorSettlementV1>, RootV8EffectAckErrorV1> {
    let marker = settlement_for_predecessor(&authority, binding)?;
    if let Some(marker) = marker {
        let mut binding_key = BINDING_V2_KEY_PREFIX.to_vec();
        binding_key.extend_from_slice(binding.as_bytes());
        let row = authority
            .get(&binding_key)?
            .ok_or(RootV8EffectAckErrorV1::Stale)?;
        let historical = ClosedPolicyRootBindingV2::decode(row)?;
        let (head, next_epoch, _) = current_root_binding_chain(&authority)?;
        if marker.epoch != epoch
            || historical.root_generation != epoch
            || historical.handoff_epoch != epoch
            || head == binding
                && (next_epoch != marker.next_epoch || !current_flight_slots_empty(&authority)?)
        {
            return Err(RootV8EffectAckErrorV1::Stale);
        }
    }
    Ok(marker)
}

pub(super) fn settle_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8SuccessorSettlementV1, RootV8EffectAckErrorV1> {
    if uid == 0 || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(credential) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    if let Some(prior) = settlement_for_predecessor(authority, binding)? {
        if prior.epoch == epoch && current_flight_slots_empty(authority)? {
            return Ok(prior);
        }
        return Err(RootV8EffectAckErrorV1::Stale);
    }

    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let hold =
        current_hold(authority, head, next_epoch, count)?.ok_or(RootV8EffectAckErrorV1::Stale)?;
    if head != binding
        || next_epoch != epoch.checked_add(1).ok_or(RootV8EffectAckErrorV1::Stale)?
        || hold.held
        || hold.binding != binding
        || hold.epoch != epoch
        || !matches!(
            terminal::current_terminal_custody(authority, binding, epoch),
            Ok(Some(RootV8TerminalCustodyV1::Released(..)))
        )
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let cut = custody_cut(authority, binding, epoch, true)?;
    let ack = current_ack_for_cut(authority, binding, epoch, &cut)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    if ack.controller_uid() != uid || cut.pin.as_slice() != credential {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let ack_row = authority
        .get(ACK_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let terminal_row = authority
        .get(terminal::TERMINAL_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let release_row = authority
        .get(terminal::release::RELEASE_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let release_marker = ObjectDigest::from_bytes(Sha256::digest(release_row).into());
    let nonce = fresh_nonce()?;
    let challenge_cut = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(binding.as_bytes())
            .chain_update(epoch.to_be_bytes())
            .chain_update(Sha256::digest(ack_row))
            .chain_update(Sha256::digest(terminal_row))
            .chain_update(release_marker.as_bytes())
            .chain_update(Sha256::digest(credential))
            .chain_update(uid.to_be_bytes())
            .chain_update(nonce)
            .finalize()
            .into(),
    );
    let challenge = ControllerEffectAckChallengeV1::new(nonce, challenge_cut)?;
    let snapshot = authority.snapshot()?;
    let packet = exchange(challenge)?;
    let settlement =
        verify_controller_v8_settlement_readback_v1(&packet, &cut.signer, challenge, uid)?;
    if settlement.binding() != binding
        || settlement.epoch() != epoch
        || settlement.ack_digest() != ack.controller_ack()
        || settlement.root_receipt_digest() != controller_v8_root_receipt_record_digest_v1(ack)?
        || settlement.root_release_marker_digest() != release_marker
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    authority.validate_snapshot_for_effect(&snapshot)?;

    let marker = RootV8SuccessorSettlementV1 {
        predecessor: binding,
        epoch,
        next_epoch,
        settlement: settlement.record_digest()?,
        release_marker,
        cache_released: settlement.cache_released_digest(),
        source_released: settlement.source_released_digest(),
        signed_receipt: ObjectDigest::from_bytes(Sha256::digest(&packet).into()),
    };
    let transaction = settlement_transaction(marker)?;
    let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
    authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
    authority.commit(&transaction)?;
    if !current_flight_slots_empty(authority)?
        || settlement_for_predecessor(authority, binding)? != Some(marker)
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    Ok(marker)
}
