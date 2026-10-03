//! Controller's versioned final command for a held Root V8 terminal.
//!
//! ```text
//! AOSCTF08 envelope | AOSPC88A[332] | AOSPC88T-digest[32] |
//! Cache-project[16] | Cache-partition[32] | Cache-head[32] |
//! Cache-quota-postflight[32] | Ed25519[64]
//! ```
//!
//! A successful signed packet asserts that Controller completed its final
//! owner postflight while the caller retained Controller, Source, and Cache
//! custody. Root independently compares every named claim to its held proof.

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::CacheResidencyWriterReadbackV2;
use crate::controller_service::journal::production_journal_limits;
use crate::journal::{Journal, ProtectedJournalAuthority, RecordNamespace};
use crate::policy_compiler::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use crate::policy_compiler::controller_v8_readback_envelope::{
    ControllerV8ReadbackProtocol, HEADER_BYTES, SIGNATURE_BYTES, sign_packet, verify_packet,
};

use super::*;

const CUT_DOMAIN: &[u8] = b"aos.sandbox.root-v8-final-release-cut.v1\0";
const RECORD_BYTES: usize = ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1 + 32 + 16 + 32 + 32 + 32;

/// Bounds Controller's distinct signed V8 final release command.
pub const CONTROLLER_V8_FINAL_RELEASE_BYTES_V1: usize =
    HEADER_BYTES + RECORD_BYTES + SIGNATURE_BYTES;

fn terminal_digest(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<ObjectDigest, RootV8EffectAckErrorV1> {
    let row = authority
        .get(terminal::TERMINAL_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    Ok(ObjectDigest::from_bytes(Sha256::digest(row).into()))
}

pub(super) fn challenge_for_terminal(
    authority: &ProtectedJournalAuthority<'_>,
    terminal: RootV8VerifiedTerminalV1,
    uid: u32,
    nonce: [u8; 16],
) -> Result<(ControllerEffectAckChallengeV1, ObjectDigest), RootV8EffectAckErrorV1> {
    if uid == 0 || nonce == [0; 16] || terminal.controller_uid() != uid {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let ack = terminal.ack();
    let held = held_cut(authority, ack.binding(), ack.epoch())?;
    if terminal::current_terminal(authority, ack.binding(), ack.epoch())? != Some(terminal) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let digest = terminal_digest(authority)?;
    if digest != terminal.record_digest() {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let cut = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(Sha256::digest(ack.record_bytes()?))
            .chain_update(digest.as_bytes())
            .chain_update(held.quota.as_bytes())
            .chain_update(Sha256::digest(&held.pin))
            .chain_update(uid.to_be_bytes())
            .chain_update(nonce)
            .finalize()
            .into(),
    );
    Ok((ControllerEffectAckChallengeV1::new(nonce, cut)?, digest))
}

/// Signs an exact final command from a typed, held Cache postflight readback.
///
/// The caller must invoke this only after its final Controller, Source, and
/// Cache postflight succeeds, while their writers and physical Cache lock
/// remain held. Signing does not itself release Root or Cache.
///
/// # Errors
///
/// Rejects changed Controller custody, a mismatched Cache readback or Root
/// terminal, a stale signer, or a changed protected journal name.
pub fn sign_fixed_controller_v8_final_release_v1(
    journal: &mut Journal,
    challenge: ControllerEffectAckChallengeV1,
    root_terminal_digest: ObjectDigest,
    cache: &CacheResidencyWriterReadbackV2,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_FINAL_RELEASE_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || signer_generation == 0 || root_terminal_digest.as_bytes() == &[0; 32] {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let directory = Path::new("/var/lib/aos/sandboxd");
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    let ack = journal
        .controller_policy_v8_effect_ack_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    let receipt = journal
        .controller_policy_v8_root_receipt_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    let hold = ack.attempt().hold();
    let cache_hold = cache.hold();
    if journal.controller_policy_v8_attempt_v1()? != Some(ack.attempt())
        || journal.controller_policy_hold_v1()? != Some(hold)
        || !hold.is_held()
        || receipt.controller_ack()
            != ack
                .record_digest()
                .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?
        || cache_hold.binding() != hold.binding()
        || cache_hold.epoch() != hold.epoch()
        || cache.quota_digest() != ack.cache_quota()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let record = encode_record(
        receipt,
        root_terminal_digest,
        cache_hold.project(),
        cache_hold.partition(),
        cache_hold.cache_head(),
        cache.quota_digest(),
    )
    .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?;
    let packet = sign_packet(
        ControllerV8ReadbackProtocol::FinalRelease,
        &record,
        uid,
        snapshot.sequence(),
        challenge,
        signer_generation,
        signing_key,
    )?;
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    if journal.controller_policy_v8_root_receipt_v1()? != Some(receipt)
        || journal.controller_policy_hold_v1()? != Some(hold)
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(packet)
}

fn encode_record(
    ack: RootV8EffectAckV1,
    terminal_digest: ObjectDigest,
    project: ProjectId,
    partition: ObjectDigest,
    cache_head: ObjectDigest,
    quota: ObjectDigest,
) -> Result<[u8; RECORD_BYTES], RootV8EffectAckErrorV1> {
    if terminal_digest.as_bytes() == &[0; 32] || quota.as_bytes() == &[0; 32] {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let mut record = [0; RECORD_BYTES];
    record[..332].copy_from_slice(&ack.record_bytes()?);
    record[332..364].copy_from_slice(terminal_digest.as_bytes());
    record[364..380].copy_from_slice(project.as_bytes());
    record[380..412].copy_from_slice(partition.as_bytes());
    record[412..444].copy_from_slice(cache_head.as_bytes());
    record[444..476].copy_from_slice(quota.as_bytes());
    Ok(record)
}

pub(super) fn verify_final_command(
    authority: &ProtectedJournalAuthority<'_>,
    terminal: RootV8VerifiedTerminalV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
    bytes: &[u8],
) -> Result<(), RootV8EffectAckErrorV1> {
    let ack = terminal.ack();
    let held = held_cut(authority, ack.binding(), ack.epoch())?;
    let record = verify_packet(
        ControllerV8ReadbackProtocol::FinalRelease,
        bytes,
        &held.signer,
        challenge,
        expected_uid,
    )?;
    let expected = encode_record(
        ack,
        terminal_digest(authority)?,
        held.proposal.project,
        held.proposal.physical_partition,
        held.proposal.physical_cache_head,
        held.quota,
    )?;
    if record != expected {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn sign_test_final_command(
    ack: RootV8EffectAckV1,
    digest: ObjectDigest,
    project: ProjectId,
    partition: ObjectDigest,
    head: ObjectDigest,
    quota: ObjectDigest,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> [u8; CONTROLLER_V8_FINAL_RELEASE_BYTES_V1] {
    let record = encode_record(ack, digest, project, partition, head, quota).unwrap();
    sign_packet(
        ControllerV8ReadbackProtocol::FinalRelease,
        &record,
        uid,
        7,
        challenge,
        generation,
        key,
    )
    .unwrap()
}
