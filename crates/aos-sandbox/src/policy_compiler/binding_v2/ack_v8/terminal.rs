//! Root-held verification of Controller's later V8 Root receipt.
//!
//! ```text
//! AOSPC88T | version=1 | reserved[6]=0 | signed AOSCTR08[480] | SHA-256[32]
//! ```
//!
//! The historical AOSPC88A remains separate. Only this row records that Root
//! verified Controller's durable receipt under a fresh Root challenge and its
//! own protected writer. Neither row grants owner release on its own.

use std::{io, path::Path};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
};
use crate::policy_compiler::controller_effect_ack_readback::ControllerEffectAckChallengeV1;
use crate::policy_compiler::controller_root_receipt_readback_v8::{
    CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1, verify_controller_v8_root_receipt_readback_v1,
};
use crate::policy_compiler::root_challenge_record::RootChallengeRecordCodec;

use super::*;

pub(super) mod release;

pub(in crate::policy_compiler::binding_v2) use release::{
    release_capacity_transaction, release_marker_matches,
};

pub(in crate::policy_compiler::binding_v2) fn verify_released_terminal_without_decision(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    // The binding decision calls this verifier. Read its prior chain without
    // calling the decision again, then verify the pinned Controller signature.
    current_released_terminal_without_public_decision(authority, binding, epoch)
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    Ok(())
}

pub(in crate::policy_compiler::binding_v2) const TERMINAL_KEY: &[u8] =
    b"\0aos-policy-compiler-root-v8-verified-terminal-v1\0";
const CHALLENGE_KEY: &[u8] = b"\0aos-policy-compiler-root-v8-verified-terminal-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSPC88T";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-verified-terminal.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-v8-verified-terminal-transaction.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-verified-terminal-cut.v1\0";
const CHALLENGE_CODEC: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    b"AOSPC88D",
    b"aos.sandbox.policy-compiler.root-v8-verified-terminal-challenge.v1\0",
    b"aos.sandbox.policy-compiler.root-v8-verified-terminal-challenge-transaction.v1\0",
    CHALLENGE_KEY,
);
const RECORD_BYTES: usize = 16 + CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1 + 32;

/// Retains an exact Controller receipt verified under Root's held writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8VerifiedTerminalV1 {
    ack: RootV8EffectAckV1,
    controller_uid: u32,
    signed_receipt: [u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1],
}

/// Reports whether Root still holds the verified V8 terminal's custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootV8TerminalCustodyV1 {
    /// Root retains its exact protected binding hold.
    Held(RootV8VerifiedTerminalV1),
    /// Root durably released its exact protected binding hold.
    Released(RootV8VerifiedTerminalV1, ObjectDigest),
}

impl RootV8VerifiedTerminalV1 {
    /// Returns the exact historical Root V8 ACK.
    #[must_use]
    pub const fn ack(self) -> RootV8EffectAckV1 {
        self.ack
    }

    /// Returns the authenticated Controller UID.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the digest of the exact canonical AOSPC88T journal row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(terminal_record(self.signed_receipt)).into())
    }
}

fn terminal_cut(
    ack: RootV8EffectAckV1,
    credential: &[u8],
    uid: u32,
    issue: u64,
) -> Result<ObjectDigest, RootV8EffectAckErrorV1> {
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(ack.record_bytes()?)
            .chain_update(Sha256::digest(credential))
            .chain_update(uid.to_be_bytes())
            .chain_update(issue.to_be_bytes())
            .finalize()
            .into(),
    ))
}

fn terminal_transaction(
    signed_receipt: [u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1],
) -> Result<JournalTransaction, RootV8EffectAckErrorV1> {
    let row = terminal_record(signed_receipt);
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(row)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    Ok(JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            TERMINAL_KEY.to_vec(),
            row.to_vec(),
        )],
    )?)
}

fn terminal_record(
    signed_receipt: [u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1],
) -> [u8; RECORD_BYTES] {
    let mut row = [0; RECORD_BYTES];
    row[..8].copy_from_slice(MAGIC);
    row[8..10].copy_from_slice(&1_u16.to_be_bytes());
    row[16..16 + CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1].copy_from_slice(&signed_receipt);
    let checksum = Sha256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(&row[..RECORD_BYTES - 32])
        .finalize();
    row[RECORD_BYTES - 32..].copy_from_slice(&checksum);
    row
}

fn decode_terminal(
    row: &[u8],
) -> Result<[u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1], RootV8EffectAckErrorV1> {
    if row.len() != RECORD_BYTES
        || row[..8] != MAGIC[..]
        || row[8..10] != 1_u16.to_be_bytes()
        || row[10..16] != [0; 6]
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let checksum = Sha256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(&row[..RECORD_BYTES - 32])
        .finalize();
    if row[RECORD_BYTES - 32..] != checksum[..] {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    row[16..16 + CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1]
        .try_into()
        .map_err(|_| RootV8EffectAckErrorV1::Stale)
}

pub(super) fn current_terminal(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8VerifiedTerminalV1>, RootV8EffectAckErrorV1> {
    let held = held_cut(authority, binding, epoch)?;
    let ack = current_ack_for_cut(authority, binding, epoch, &held)?;
    current_terminal_for_cut(authority, ack, &held)
}

fn current_released_terminal_without_public_decision(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<RootV8VerifiedTerminalV1, RootV8EffectAckErrorV1> {
    let released = custody_cut(authority, binding, epoch, true)?;
    let ack = current_ack_for_cut(authority, binding, epoch, &released)?;
    current_terminal_for_cut(authority, ack, &released)?.ok_or(RootV8EffectAckErrorV1::Stale)
}

fn current_terminal_for_cut(
    authority: &ProtectedJournalAuthority<'_>,
    ack: Option<RootV8EffectAckV1>,
    held: &HeldCut,
) -> Result<Option<RootV8VerifiedTerminalV1>, RootV8EffectAckErrorV1> {
    let Some(row) = authority.get(TERMINAL_KEY)? else {
        return Ok(None);
    };
    let ack = ack.ok_or(RootV8EffectAckErrorV1::Stale)?;
    let challenge_row = authority
        .get(CHALLENGE_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let (issue, nonce) = CHALLENGE_CODEC
        .read_prior(Some(challenge_row))
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let signed_receipt = decode_terminal(row)?;
    let uid = ack.controller_uid();
    let cut = terminal_cut(ack, &held.pin, uid, issue)?;
    if challenge_row != CHALLENGE_CODEC.encode(issue, nonce, cut) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let challenge = ControllerEffectAckChallengeV1::new(nonce, cut)?;
    let receipt = verify_controller_v8_root_receipt_readback_v1(
        &signed_receipt,
        &held.signer,
        challenge,
        uid,
    )?;
    if receipt != ack {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    Ok(Some(RootV8VerifiedTerminalV1 {
        ack,
        controller_uid: uid,
        signed_receipt,
    }))
}

pub(super) fn terminal_capacity_transactions()
-> Result<[JournalTransaction; 2], RootV8EffectAckErrorV1> {
    let challenge = CHALLENGE_CODEC.encode(1, [1; 16], ObjectDigest::from_bytes([1; 32]));
    Ok([
        CHALLENGE_CODEC.transaction(challenge)?,
        terminal_transaction([1; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1])?,
    ])
}

/// Replays an exact verified V8 terminal and its Root custody phase.
///
/// A historical ACK without a terminal returns `None`. A release marker alone
/// cannot establish a released terminal without its signed Controller receipt.
///
/// # Errors
///
/// Rejects a changed Root chain, malformed release, forged receipt, or failed
/// protected journal custody.
pub fn recover_fixed_closed_root_v8_terminal_custody_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8TerminalCustodyV1>, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    current_terminal_custody(&authority, binding, epoch)
}

pub(super) fn current_terminal_custody(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8TerminalCustodyV1>, RootV8EffectAckErrorV1> {
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let hold =
        current_hold(authority, head, next_epoch, count)?.ok_or(RootV8EffectAckErrorV1::Stale)?;
    if head != binding || hold.binding != binding || hold.epoch != epoch {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    if hold.held {
        Ok(current_terminal(authority, binding, epoch)?.map(RootV8TerminalCustodyV1::Held))
    } else {
        let terminal =
            current_released_terminal_without_public_decision(authority, binding, epoch)?;
        let marker = release::replayed_release_marker_digest(authority)?;
        Ok(Some(RootV8TerminalCustodyV1::Released(terminal, marker)))
    }
}

/// Replays Root's verified V8 terminal only while its binding remains held.
///
/// A historical AOSPC88A without this terminal returns `None`. After a
/// legitimate release this held-only entry point returns stale; use
/// [`recover_fixed_closed_root_v8_terminal_custody_v1`] to inspect either
/// terminal custody state.
///
/// # Errors
///
/// Rejects changed Root custody, a forged Controller receipt, or corrupt replay.
pub fn recover_fixed_closed_root_v8_verified_terminal_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8VerifiedTerminalV1>, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    current_terminal(&authority, binding, epoch)
}

/// Verifies Controller's signed Root receipt while Root holds its journal writer.
///
/// The caller must keep Controller, Source, and both Cache writers held. An
/// exact prior terminal replays without signing or spending another challenge.
/// This function does not release any owner.
///
/// # Errors
///
/// Rejects a changed Root ACK, rotated Controller credential, stale signed
/// receipt, conflicting replay, transport loss, or failed durable write.
pub fn verify_fixed_closed_root_v8_terminal_v1(
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8VerifiedTerminalV1, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    verify_in_authority(
        &mut authority,
        binding,
        epoch,
        uid,
        credential,
        super::super::super::controller_readback_session::fresh_root_nonce,
        exchange,
    )
}

pub(super) fn verify_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8VerifiedTerminalV1, RootV8EffectAckErrorV1> {
    if uid == 0 || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(credential) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    if let Some(prior) = current_terminal(authority, binding, epoch)? {
        return if prior.controller_uid == uid {
            Ok(prior)
        } else {
            Err(RootV8EffectAckErrorV1::Stale)
        };
    }
    let ack = current_ack(authority, binding, epoch)?.ok_or(RootV8EffectAckErrorV1::Stale)?;
    if ack.controller_uid() != uid {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let held = held_cut(authority, binding, epoch)?;
    let (prior_issue, prior_nonce) = CHALLENGE_CODEC
        .read_prior(authority.get(CHALLENGE_KEY)?)
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let issue = prior_issue
        .checked_add(1)
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let nonce = fresh_nonce()?;
    if nonce == [0; 16] || nonce == prior_nonce {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let cut = terminal_cut(ack, &held.pin, uid, issue)?;
    let challenge = ControllerEffectAckChallengeV1::new(nonce, cut)?;
    let challenge_row = CHALLENGE_CODEC.encode(issue, nonce, cut);
    let terminal_capacity = terminal_capacity_transactions()?;
    let planned = [
        CHALLENGE_CODEC.transaction(challenge_row)?,
        terminal_capacity[1].clone(),
        release_capacity_transaction()?,
    ];
    let preflight = authority.preflight_transactions(&planned)?;
    authority.validate_preflight_for_effect(&preflight, &planned)?;
    authority.commit(&CHALLENGE_CODEC.transaction(challenge_row)?)?;
    let snapshot = authority.snapshot()?;

    let packet = exchange(challenge)?;
    let receipt =
        verify_controller_v8_root_receipt_readback_v1(&packet, &held.signer, challenge, uid)?;
    if receipt != ack
        || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(held.pin.as_slice())
        || authority.get(CHALLENGE_KEY)? != Some(challenge_row.as_slice())
        || current_ack(authority, binding, epoch)? != Some(ack)
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    authority.validate_snapshot_for_effect(&snapshot)?;
    let signed_receipt = packet
        .try_into()
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    authority.commit(&terminal_transaction(signed_receipt)?)?;
    current_terminal(authority, binding, epoch)?.ok_or(RootV8EffectAckErrorV1::Stale)
}
