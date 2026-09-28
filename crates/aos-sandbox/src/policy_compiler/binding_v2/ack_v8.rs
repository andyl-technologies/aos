//! Root-owned, nonauthorizing V8 acknowledgment of consumed AOSPCP02 custody.
//!
//! ```text
//! AOSPC88A | version=1 | reserved[6]=0 | binding[32] | epoch:u64 |
//! operation[16] | sandbox[16] | Create-generation:u64 |
//! effect-transaction[16] | terminal[32] | AOSPCP02-digest[32] |
//! quota[32] | AOSQ8K01-digest[32] | signed-receipt-digest[32] |
//! Controller-signer-generation:u64 | Controller-UID:u32 |
//! Root-nonce[16] | SHA-256[32]
//! ```
//!
//! The row is a historical receipt under the still-held Root decision. It
//! never permits Root or another owner to release, publish, or Apply.

use std::{io, path::Path};

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use crate::journal::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};
use crate::policy_compiler::cache_readback_pin::CACHE_PIN_KEY;
use crate::policy_compiler::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use crate::policy_compiler::controller_effect_ack_readback_v8::verify_controller_v8_effect_ack_readback_v1;
use crate::policy_compiler::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use crate::policy_compiler::controller_hold_readback::PinnedControllerHoldSignerV1;
use crate::policy_compiler::root_challenge_record::RootChallengeRecordCodec;
use crate::policy_compiler::source_hold_pin::SOURCE_HOLD_PIN_KEY;
use crate::policy_compiler::source_hold_readback::PinnedSourceHoldReadbackSignerV1;

use super::*;

mod final_release;
mod successor_settlement;
mod terminal;

pub use final_release::{
    CONTROLLER_V8_FINAL_RELEASE_BYTES_V1, sign_fixed_controller_v8_final_release_v1,
};

pub use successor_settlement::{
    RootV8SuccessorSettlementV1, recover_fixed_closed_root_v8_predecessor_settlement_v1,
    settle_fixed_closed_root_v8_predecessor_v1,
};
pub(super) use successor_settlement::{require_settled_predecessor, settlement_for_predecessor};
pub use terminal::{
    RootV8TerminalCustodyV1, RootV8VerifiedTerminalV1,
    recover_fixed_closed_root_v8_terminal_custody_v1,
    recover_fixed_closed_root_v8_verified_terminal_v1, verify_fixed_closed_root_v8_terminal_v1,
};
pub(super) use terminal::{release_marker_matches, verify_released_terminal_without_decision};

pub(super) fn current_flight_slots_empty(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<bool, PolicyCompilerJournalErrorV1> {
    Ok(authority.get(terminal::release::RELEASE_KEY)?.is_none()
        && authority.get(ACK_KEY)?.is_none()
        && authority.get(terminal::TERMINAL_KEY)?.is_none())
}

/// Identifies one step of the Root-held V8 terminal socket exchange.
pub enum RootV8HeldTerminalStepV1 {
    /// Requests Controller's signed no-Apply effect ACK.
    EffectAck(ControllerEffectAckChallengeV1),
    /// Sends the durable Root ACK so Controller can retain its exact receipt.
    Acknowledged(RootV8EffectAckV1),
    /// Requests Controller's signed readback of that retained Root receipt.
    RootReceipt(ControllerEffectAckChallengeV1),
    /// Sends the verified terminal and requests a final signed release command.
    FinalRelease {
        /// Names Root's fresh challenge for the final Controller command.
        challenge: ControllerEffectAckChallengeV1,
        /// Commits the exact durable AOSPC88T row under Root's writer.
        terminal_digest: ObjectDigest,
        /// Retains the exact terminal whose hold may be released.
        terminal: RootV8VerifiedTerminalV1,
    },
}

const ACK_KEY: &[u8] = b"\0aos-policy-compiler-root-v8-effect-ack-v1\0";
const CHALLENGE_KEY: &[u8] = b"\0aos-policy-compiler-root-v8-effect-ack-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSPC88A";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-v8-effect-ack-transaction.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-effect-ack-cut.v1\0";
const CHALLENGE_CODEC: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    b"AOSPC88C",
    b"aos.sandbox.policy-compiler.root-v8-effect-ack-challenge-record.v1\0",
    b"aos.sandbox.policy-compiler.root-v8-effect-ack-challenge-transaction.v1\0",
    CHALLENGE_KEY,
);
/// Bounds a canonical protected V8 Root ACK record.
pub const ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1: usize = 332;

/// Reports a rejected V8 Root/Controller ACK session.
#[derive(Debug, thiserror::Error)]
pub enum RootV8EffectAckErrorV1 {
    /// The Root held cut, signer, receipt, or replay is stale.
    #[error("stale Root V8 effect acknowledgment")]
    Stale,
    /// The protected Root journal failed.
    #[error(transparent)]
    Root(#[from] PolicyCompilerJournalErrorV1),
    /// The Controller-only packet failed verification.
    #[error(transparent)]
    Controller(#[from] ControllerEffectAckReadbackErrorV1),
    /// The live Controller exchange failed.
    #[error(transparent)]
    Transport(#[from] io::Error),
}

impl From<JournalError> for RootV8EffectAckErrorV1 {
    fn from(error: JournalError) -> Self {
        Self::Root(PolicyCompilerJournalErrorV1::from(error))
    }
}

/// Retains one exact no-Apply Root receipt before Root releases its writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8EffectAckV1 {
    binding: ObjectDigest,
    epoch: u64,
    operation: OperationId,
    sandbox: SandboxId,
    accepted_generation: u64,
    effect_transaction: [u8; 16],
    terminal: ObjectDigest,
    proof: ObjectDigest,
    quota: ObjectDigest,
    controller_ack: ObjectDigest,
    receipt: ObjectDigest,
    signer_generation: u64,
    controller_uid: u32,
    nonce: [u8; 16],
}

impl RootV8EffectAckV1 {
    /// Returns the held binding.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the Root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the accepted Create generation.
    #[must_use]
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Returns the reserved no-Apply effect transaction.
    #[must_use]
    pub const fn effect_transaction(self) -> [u8; 16] {
        self.effect_transaction
    }

    /// Returns the exact signed terminal digest.
    #[must_use]
    pub const fn terminal(self) -> ObjectDigest {
        self.terminal
    }

    /// Returns the consumed AOSPCP02 digest.
    #[must_use]
    pub const fn proof(self) -> ObjectDigest {
        self.proof
    }

    /// Returns the complete Cache quota digest.
    #[must_use]
    pub const fn quota(self) -> ObjectDigest {
        self.quota
    }

    /// Returns the protected AOSQ8K01 digest.
    #[must_use]
    pub const fn controller_ack(self) -> ObjectDigest {
        self.controller_ack
    }

    /// Returns the signed packet digest.
    #[must_use]
    pub const fn receipt(self) -> ObjectDigest {
        self.receipt
    }

    /// Returns the pinned Controller signer generation.
    #[must_use]
    pub const fn signer_generation(self) -> u64 {
        self.signer_generation
    }

    /// Returns the authenticated Controller UID.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the spent Root nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Encodes canonical bytes for authenticated transport.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields.
    pub fn record_bytes(
        self,
    ) -> Result<[u8; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1], RootV8EffectAckErrorV1> {
        self.encode()
    }

    /// Decodes canonical historical bytes without asserting current custody.
    ///
    /// # Errors
    ///
    /// Rejects changed or noncanonical bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootV8EffectAckErrorV1> {
        Self::decode(bytes)
    }

    fn encode(self) -> Result<[u8; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1], RootV8EffectAckErrorV1> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.terminal.as_bytes() == &[0; 32]
            || self.proof.as_bytes() == &[0; 32]
            || self.quota.as_bytes() == &[0; 32]
            || self.controller_ack.as_bytes() == &[0; 32]
            || self.receipt.as_bytes() == &[0; 32]
            || self.signer_generation == 0
            || self.controller_uid == 0
            || self.nonce == [0; 16]
        {
            return Err(RootV8EffectAckErrorV1::Stale);
        }
        let mut bytes = [0; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..72].copy_from_slice(self.operation.as_bytes());
        bytes[72..88].copy_from_slice(self.sandbox.as_bytes());
        bytes[88..96].copy_from_slice(&self.accepted_generation.to_be_bytes());
        bytes[96..112].copy_from_slice(&self.effect_transaction);
        bytes[112..144].copy_from_slice(self.terminal.as_bytes());
        bytes[144..176].copy_from_slice(self.proof.as_bytes());
        bytes[176..208].copy_from_slice(self.quota.as_bytes());
        bytes[208..240].copy_from_slice(self.controller_ack.as_bytes());
        bytes[240..272].copy_from_slice(self.receipt.as_bytes());
        bytes[272..280].copy_from_slice(&self.signer_generation.to_be_bytes());
        bytes[280..284].copy_from_slice(&self.controller_uid.to_be_bytes());
        bytes[284..300].copy_from_slice(&self.nonce);
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..300])
            .finalize();
        bytes[300..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RootV8EffectAckErrorV1> {
        if bytes.len() != ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1
            || bytes[..8] != MAGIC[..]
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(RootV8EffectAckErrorV1::Stale);
        }
        let record = Self {
            binding: ObjectDigest::from_bytes(take::<32>(bytes, 16)?),
            epoch: u64::from_be_bytes(take::<8>(bytes, 48)?),
            operation: OperationId::from_bytes(take::<16>(bytes, 56)?),
            sandbox: SandboxId::from_bytes(take::<16>(bytes, 72)?),
            accepted_generation: u64::from_be_bytes(take::<8>(bytes, 88)?),
            effect_transaction: take::<16>(bytes, 96)?,
            terminal: ObjectDigest::from_bytes(take::<32>(bytes, 112)?),
            proof: ObjectDigest::from_bytes(take::<32>(bytes, 144)?),
            quota: ObjectDigest::from_bytes(take::<32>(bytes, 176)?),
            controller_ack: ObjectDigest::from_bytes(take::<32>(bytes, 208)?),
            receipt: ObjectDigest::from_bytes(take::<32>(bytes, 240)?),
            signer_generation: u64::from_be_bytes(take::<8>(bytes, 272)?),
            controller_uid: u32::from_be_bytes(take::<4>(bytes, 280)?),
            nonce: take::<16>(bytes, 284)?,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(RootV8EffectAckErrorV1::Stale);
        }
        Ok(record)
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], RootV8EffectAckErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(RootV8EffectAckErrorV1::Stale)
}

struct HeldCut {
    proposal: ClosedPolicyRootBindingV2,
    terminal: ObjectDigest,
    proof: ObjectDigest,
    quota: ObjectDigest,
    pin: Vec<u8>,
    signer: PinnedControllerHoldSignerV1,
}

fn held_cut(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<HeldCut, RootV8EffectAckErrorV1> {
    custody_cut(authority, binding, epoch, false)
}

fn custody_cut(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    released: bool,
) -> Result<HeldCut, RootV8EffectAckErrorV1> {
    let (decision, proposed, qualified) = if released {
        // The released terminal verifier checks the signed receipt after
        // this cut; calling the public decision here would recurse.
        recover_closed_binding_decision_with_proof_from_authority_inner(
            authority, binding, epoch, false,
        )?
    } else {
        recover_closed_binding_decision_with_proof_from_authority(authority, binding, epoch)?
    };
    let expected_decision = if released {
        matches!(
            decision,
            ClosedPolicyBindingDecisionV2::CommittedReleased(_)
        )
    } else {
        matches!(decision, ClosedPolicyBindingDecisionV2::CommittedHeld(_))
    };
    if !expected_decision || qualified.is_some() || authority.get(ack::ACK_KEY)?.is_some() {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let proposal =
        ClosedPolicyRootBindingV2::decode(&proposed.ok_or(RootV8EffectAckErrorV1::Stale)?)?;
    let bytes = authority
        .get(&held_cas_proof_key(binding))?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    // The fixed slot is successor staging state. A released predecessor stays
    // current until successor CAS, even after that successor writes its proof.
    // Its immutable per-binding proof and signer pins still authenticate replay.
    if !released && authority.get(HELD_PROOF_KEY)? != Some(bytes) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let proof = RootHeldProofV2::decode(bytes)?;
    let pin = authority
        .get(CONTROLLER_HOLD_PIN_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?
        .to_vec();
    let signer =
        PinnedControllerHoldSignerV1::decode(&pin).map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    let source_pin = authority
        .get(SOURCE_HOLD_PIN_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let cache_pin = authority
        .get(CACHE_PIN_KEY)?
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    let cache_signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    if proof.binding != binding
        || proof.epoch != epoch
        || proof.controller_generation != signer.generation()
        || proof.source_generation != source_signer.generation()
        || proof.cache_generation != cache_signer.generation()
        || proof.controller_pin.as_bytes() != Sha256::digest(&pin).as_slice()
        || proof.source_pin.as_bytes() != Sha256::digest(source_pin).as_slice()
        || proof.cache_pin.as_bytes() != Sha256::digest(cache_pin).as_slice()
        || proof.project != proposal.project
        || proof.partition != proposal.physical_partition
        || proof.cache_head != proposal.physical_cache_head
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    Ok(HeldCut {
        proposal,
        terminal: proof.terminal,
        proof: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
        quota: proof.quota,
        pin,
        signer,
    })
}

fn effect_cut(
    binding: ObjectDigest,
    epoch: u64,
    held: &HeldCut,
    uid: u32,
    issue: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(binding.as_bytes())
            .chain_update(epoch.to_be_bytes())
            .chain_update(held.proposal.operation.as_bytes())
            .chain_update(held.proposal.sandbox.as_bytes())
            .chain_update(held.proposal.accepted_generation.to_be_bytes())
            .chain_update(held.proposal.effect_transaction)
            .chain_update(held.terminal.as_bytes())
            .chain_update(held.proof.as_bytes())
            .chain_update(held.quota.as_bytes())
            .chain_update(Sha256::digest(&held.pin))
            .chain_update(uid.to_be_bytes())
            .chain_update(issue.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn current_ack(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8EffectAckV1>, RootV8EffectAckErrorV1> {
    let held = held_cut(authority, binding, epoch)?;
    current_ack_for_cut(authority, binding, epoch, &held)
}

fn current_ack_for_cut(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    held: &HeldCut,
) -> Result<Option<RootV8EffectAckV1>, RootV8EffectAckErrorV1> {
    let record = authority
        .get(ACK_KEY)?
        .map(RootV8EffectAckV1::decode)
        .transpose()?;
    if let Some(record) = record {
        let challenge = authority
            .get(CHALLENGE_KEY)?
            .ok_or(RootV8EffectAckErrorV1::Stale)?;
        let (issue, nonce) = CHALLENGE_CODEC
            .read_prior(Some(challenge))
            .ok_or(RootV8EffectAckErrorV1::Stale)?;
        if record.binding != binding
            || record.epoch != epoch
            || record.operation != held.proposal.operation
            || record.sandbox != held.proposal.sandbox
            || record.accepted_generation != held.proposal.accepted_generation
            || record.effect_transaction != held.proposal.effect_transaction
            || record.terminal != held.terminal
            || record.proof != held.proof
            || record.quota != held.quota
            || record.signer_generation != held.signer.generation()
            || nonce != record.nonce
            || challenge
                != CHALLENGE_CODEC.encode(
                    issue,
                    nonce,
                    effect_cut(binding, epoch, &held, record.controller_uid, issue),
                )
        {
            return Err(RootV8EffectAckErrorV1::Stale);
        }
    }
    Ok(record)
}

/// Replays an exact historical V8 Root ACK under its held writer.
///
/// This read does not reacquire Cache or attest a current Controller writer.
/// The caller must retain and compare those earlier owners independently.
///
/// # Errors
///
/// Rejects a changed Root decision, proof, pin, challenge, or journal tail.
pub fn recover_fixed_closed_root_v8_effect_ack_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootV8EffectAckV1>, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    current_ack(&authority, binding, epoch)
}

/// Commits a Controller-signed V8 ACK without releasing Root custody.
///
/// Controller, Source, protected Cache, and physical Cache writers must be
/// retained by the caller while this function acquires Root last. The current
/// fixed Controller credential must match Root's protected signer pin before
/// any new challenge or ACK can be written.
///
/// # Errors
///
/// Rejects a stale held CAS, rotated credential, changed owner proof, forged
/// packet, ambiguous or conflicting replay, or failed durability.
pub fn acknowledge_fixed_closed_root_v8_effect_v1(
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8EffectAckV1, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    acknowledge_in_authority(
        &mut authority,
        binding,
        epoch,
        uid,
        credential,
        super::super::controller_readback_session::fresh_root_nonce,
        exchange,
    )
}

/// Completes both V8 receipt flights beneath one held Root journal writer.
///
/// The callback sends the intermediate ACK before responding to the fresh
/// receipt challenge. Controller must retain its earlier owner writers and
/// durably store that ACK before it signs the second packet. This function
/// returns no release authority.
///
/// # Errors
///
/// Rejects changed Root custody, a mismatched Controller signer or receipt,
/// ambiguous transport, or failed protected journal durability.
pub fn acknowledge_and_verify_fixed_closed_root_v8_terminal_v1(
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    exchange: impl FnMut(RootV8HeldTerminalStepV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8VerifiedTerminalV1, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;

    acknowledge_and_verify_in_authority(
        &mut authority,
        binding,
        epoch,
        uid,
        credential,
        super::super::controller_readback_session::fresh_root_nonce,
        super::super::controller_readback_session::fresh_root_nonce,
        exchange,
    )
}

/// Completes the V8 terminal and releases its exact Root hold under one writer.
///
/// The caller's final exchange must return a distinct Controller-signed
/// AOSCTF08 command produced only after the earlier owners' final postflight.
/// Root verifies its pinned signer, fresh challenge, exact terminal, Cache
/// quota, and held proof before atomically writing AOSPC88L and the released
/// AOSPCH01 row. This grants no Cache, Source, Controller, or public Apply.
///
/// # Errors
///
/// Rejects stale or changed custody, malformed signed commands, transport
/// loss, or failed durable Root release and readback.
pub fn acknowledge_verify_and_release_fixed_closed_root_v8_terminal_v1(
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    mut exchange: impl FnMut(RootV8HeldTerminalStepV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8TerminalCustodyV1, RootV8EffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let terminal = acknowledge_and_verify_in_authority(
        &mut authority,
        binding,
        epoch,
        uid,
        credential,
        super::super::controller_readback_session::fresh_root_nonce,
        super::super::controller_readback_session::fresh_root_nonce,
        &mut exchange,
    )?;
    release_verified_terminal_after_command_in_authority(
        &mut authority,
        terminal,
        uid,
        super::super::controller_readback_session::fresh_root_nonce,
        |challenge, terminal_digest| {
            exchange(RootV8HeldTerminalStepV1::FinalRelease {
                challenge,
                terminal_digest,
                terminal,
            })
        },
    )
}

fn release_verified_terminal_after_command_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    terminal: RootV8VerifiedTerminalV1,
    uid: u32,
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1, ObjectDigest) -> io::Result<Vec<u8>>,
) -> Result<RootV8TerminalCustodyV1, RootV8EffectAckErrorV1> {
    let ack = terminal.ack();
    let binding = ack.binding();
    let epoch = ack.epoch();
    let nonce = fresh_nonce()?;
    let (challenge, terminal_digest) =
        final_release::challenge_for_terminal(authority, terminal, uid, nonce)?;
    let snapshot = authority.snapshot()?;
    let packet = exchange(challenge, terminal_digest)?;
    final_release::verify_final_command(authority, terminal, challenge, uid, &packet)?;
    authority.validate_snapshot_for_effect(&snapshot)?;
    terminal::release::release_verified_terminal_in_authority(authority, binding, epoch, terminal)
}

fn acknowledge_and_verify_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    fresh_ack_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    fresh_terminal_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    mut exchange: impl FnMut(RootV8HeldTerminalStepV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8VerifiedTerminalV1, RootV8EffectAckErrorV1> {
    let ack = acknowledge_in_authority(
        authority,
        binding,
        epoch,
        uid,
        credential,
        fresh_ack_nonce,
        |challenge| exchange(RootV8HeldTerminalStepV1::EffectAck(challenge)),
    )?;
    if !exchange(RootV8HeldTerminalStepV1::Acknowledged(ack))?.is_empty() {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    terminal::verify_in_authority(
        authority,
        binding,
        epoch,
        uid,
        credential,
        fresh_terminal_nonce,
        |challenge| exchange(RootV8HeldTerminalStepV1::RootReceipt(challenge)),
    )
}

fn acknowledge_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    uid: u32,
    credential: &[u8],
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootV8EffectAckV1, RootV8EffectAckErrorV1> {
    if uid == 0 || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(credential) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    if let Some(prior) = current_ack(authority, binding, epoch)? {
        return if prior.controller_uid == uid {
            Ok(prior)
        } else {
            Err(RootV8EffectAckErrorV1::Stale)
        };
    }
    let held = held_cut(authority, binding, epoch)?;
    let (prior_issue, prior_nonce) = match authority.get(CHALLENGE_KEY)? {
        Some(bytes) => CHALLENGE_CODEC
            .read_prior(Some(bytes))
            .ok_or(RootV8EffectAckErrorV1::Stale)?,
        None => (0, [0; 16]),
    };
    let issue = prior_issue
        .checked_add(1)
        .ok_or(RootV8EffectAckErrorV1::Stale)?;
    let nonce = fresh_nonce()?;
    if nonce == [0; 16] || nonce == prior_nonce {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let cut = effect_cut(binding, epoch, &held, uid, issue);
    let challenge = ControllerEffectAckChallengeV1::new(nonce, cut)?;
    let row = CHALLENGE_CODEC.encode(issue, nonce, cut);
    let future = terminal::terminal_capacity_transactions()?;
    let ack_capacity = JournalTransaction::new(
        [0x88; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            ACK_KEY.to_vec(),
            vec![0; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1],
        )],
    )?;
    let planned = [
        CHALLENGE_CODEC.transaction(row)?,
        ack_capacity,
        future[0].clone(),
        future[1].clone(),
        terminal::release_capacity_transaction()?,
        successor_settlement::settlement_capacity_transaction()?,
    ];
    let preflight = authority.preflight_transactions(&planned)?;
    authority.validate_preflight_for_effect(&preflight, &planned)?;
    authority.commit(&CHALLENGE_CODEC.transaction(row)?)?;
    if authority.get(CHALLENGE_KEY)? != Some(row.as_slice()) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    let snapshot = authority.snapshot()?;
    let packet = exchange(challenge)?;
    let ack = verify_controller_v8_effect_ack_readback_v1(&packet, &held.signer, challenge, uid)?;
    let attempt = ack.attempt();
    let hold = attempt.hold();
    if hold.binding() != binding
        || hold.epoch() != epoch
        || hold.operation() != held.proposal.operation
        || hold.sandbox() != held.proposal.sandbox
        || ack.accepted_generation() != held.proposal.accepted_generation
        || ack.effect_transaction() != held.proposal.effect_transaction
        || attempt.terminal() != held.terminal
        || ack.root_proof() != held.proof
        || ack.cache_quota() != held.quota
        || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(held.pin.as_slice())
        || authority.get(CHALLENGE_KEY)? != Some(row.as_slice())
    {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    authority.validate_snapshot_for_effect(&snapshot)?;
    let record = RootV8EffectAckV1 {
        binding,
        epoch,
        operation: held.proposal.operation,
        sandbox: held.proposal.sandbox,
        accepted_generation: held.proposal.accepted_generation,
        effect_transaction: held.proposal.effect_transaction,
        terminal: held.terminal,
        proof: held.proof,
        quota: held.quota,
        controller_ack: ack
            .record_digest()
            .map_err(ControllerEffectAckReadbackErrorV1::from)?,
        receipt: ObjectDigest::from_bytes(Sha256::digest(&packet).into()),
        signer_generation: held.signer.generation(),
        controller_uid: uid,
        nonce,
    };
    let bytes = record.encode()?;
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| RootV8EffectAckErrorV1::Stale)?;
    authority.commit(&JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            ACK_KEY.to_vec(),
            bytes.to_vec(),
        )],
    )?)?;
    if current_ack(authority, binding, epoch)? != Some(record) {
        return Err(RootV8EffectAckErrorV1::Stale);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::{
        ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1, ControllerPolicyV8EffectAckV1,
    };
    use crate::policy_compiler::controller_effect_ack_readback_v8::sign_test_controller_v8_effect_ack_readback_v1;
    use crate::policy_compiler::controller_hold_readback::encode_controller_hold_signer_credential_v1;
    use crate::policy_compiler::controller_root_receipt_readback_v8::sign_test_controller_v8_root_receipt_readback_v1;
    use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    struct V8RootFixture {
        binding: ClosedPolicyRootBindingV2,
        binding_head: ObjectDigest,
        controller_key: SigningKey,
        controller_pin: Vec<u8>,
        proof_bytes: Vec<u8>,
        ack: ControllerPolicyV8EffectAckV1,
    }

    fn prepare_v8_root_fixture(directory: &Path) -> V8RootFixture {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let binding = super::super::tests::cas_fixture();
        let proposed = binding.encode().unwrap();
        let binding_head = closed_policy_binding_digest_v2(&proposed).unwrap();
        let controller_key = SigningKey::from_bytes(&[1; 32]);
        let source_key = SigningKey::from_bytes(&[2; 32]);
        let cache_key = SigningKey::from_bytes(&[3; 32]);
        let controller_pin =
            encode_controller_hold_signer_credential_v1(4, &controller_key.verifying_key())
                .unwrap();
        let source_pin =
            encode_source_hold_readback_signer_credential_v1(5, &source_key.verifying_key())
                .unwrap();
        let cache_pin =
            encode_cache_owner_readback_signer_credential_v1(6, &cache_key.verifying_key())
                .unwrap();
        let proof = RootHeldProofV2 {
            terminal: ObjectDigest::from_bytes([7; 32]),
            binding: binding_head,
            epoch: binding.handoff_epoch,
            stage_nonce: [8; 16],
            stage_issue: 1,
            source_nonce: [9; 16],
            source_issue: 1,
            names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
            source_packet: ObjectDigest::from_bytes([10; 32]),
            cache_packet: ObjectDigest::from_bytes([11; 32]),
            source_pin: ObjectDigest::from_bytes(Sha256::digest(&source_pin).into()),
            cache_pin: ObjectDigest::from_bytes(Sha256::digest(&cache_pin).into()),
            controller_pin: ObjectDigest::from_bytes(Sha256::digest(&controller_pin).into()),
            source_generation: 5,
            cache_generation: 6,
            controller_generation: 4,
            project: binding.project,
            partition: binding.physical_partition,
            cache_head: binding.physical_cache_head,
            quota: ObjectDigest::from_bytes([12; 32]),
        };
        let proof_bytes = proof.encode().unwrap();

        let mut root = super::super::tests::open_test_root(directory);
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        authority
            .commit(
                &JournalTransaction::new(
                    [13; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            CONTROLLER_HOLD_PIN_KEY.to_vec(),
                            controller_pin.to_vec(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            SOURCE_HOLD_PIN_KEY.to_vec(),
                            source_pin.to_vec(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            CACHE_PIN_KEY.to_vec(),
                            cache_pin.to_vec(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            HELD_PROOF_KEY.to_vec(),
                            proof_bytes.to_vec(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: super::super::tests::identity(&binding),
            postcommit: None,
        };
        session
            .commit_closed_binding_with_proof(&proposed, None, Some(proof))
            .unwrap();
        drop(session);
        drop(root);

        let hold = ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            ObjectDigest::from_bytes([14; 32]),
            binding_head,
            binding.handoff_epoch,
        )
        .unwrap();
        let attempt = ControllerPolicyV8AttemptV1::new(hold, proof.terminal).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            binding.accepted_generation,
            binding.effect_transaction,
            ObjectDigest::from_bytes(Sha256::digest(proof_bytes).into()),
            proof.quota,
        )
        .unwrap();

        V8RootFixture {
            binding,
            binding_head,
            controller_key,
            controller_pin: controller_pin.to_vec(),
            proof_bytes: proof_bytes.to_vec(),
            ack,
        }
    }

    fn complete_test_terminal(
        authority: &mut ProtectedJournalAuthority<'_>,
        fixture: &V8RootFixture,
        ack_nonce: [u8; 16],
        terminal_nonce: [u8; 16],
    ) -> RootV8VerifiedTerminalV1 {
        let mut stage = 0;
        let mut committed = None;
        let terminal = acknowledge_and_verify_in_authority(
            authority,
            fixture.binding_head,
            fixture.binding.handoff_epoch,
            1234,
            &fixture.controller_pin,
            || Ok(ack_nonce),
            || Ok(terminal_nonce),
            |step| match step {
                RootV8HeldTerminalStepV1::EffectAck(challenge) => {
                    assert_eq!(stage, 0);
                    stage = 1;
                    Ok(sign_test_controller_v8_effect_ack_readback_v1(
                        fixture.ack,
                        1234,
                        challenge,
                        4,
                        &fixture.controller_key,
                    )
                    .unwrap()
                    .to_vec())
                }
                RootV8HeldTerminalStepV1::Acknowledged(row) => {
                    assert_eq!(stage, 1);
                    assert_eq!(row.controller_ack(), fixture.ack.record_digest().unwrap());
                    stage = 2;
                    committed = Some(row);
                    Ok(Vec::new())
                }
                RootV8HeldTerminalStepV1::RootReceipt(challenge) => {
                    assert_eq!(stage, 2);
                    stage = 3;
                    Ok(sign_test_controller_v8_root_receipt_readback_v1(
                        committed.unwrap(),
                        1234,
                        challenge,
                        4,
                        &fixture.controller_key,
                    )
                    .unwrap()
                    .to_vec())
                }
                RootV8HeldTerminalStepV1::FinalRelease { .. } => {
                    panic!("held-only terminal must not request release")
                }
            },
        )
        .unwrap();
        assert_eq!(stage, 3);
        assert_eq!(Some(terminal.ack()), committed);
        terminal
    }

    fn test_settlement_record(
        authority: &ProtectedJournalAuthority<'_>,
        fixture: &V8RootFixture,
    ) -> [u8; 312] {
        let cut = custody_cut(authority, fixture.binding_head, 1, true).unwrap();
        let ack = current_ack_for_cut(authority, fixture.binding_head, 1, &cut)
            .unwrap()
            .unwrap();
        let release = authority
            .get(terminal::release::RELEASE_KEY)
            .unwrap()
            .unwrap();
        let mut record = [0; 312];
        record[..8].copy_from_slice(b"AOSQ8S01");
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[10] = 1;
        record[16..48].copy_from_slice(fixture.binding_head.as_bytes());
        record[48..56].copy_from_slice(&1_u64.to_be_bytes());
        record[56..88].fill(1);
        record[88..120].copy_from_slice(fixture.ack.record_digest().unwrap().as_bytes());
        record[120..152].copy_from_slice(
            crate::journal::controller_v8_root_receipt_record_digest_v1(ack)
                .unwrap()
                .as_bytes(),
        );
        record[152..184].copy_from_slice(&Sha256::digest(release));
        record[184..216].fill(2);
        record[216..248].fill(3);
        record[248..280].fill(4);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-policy-v8-settlement.v1\0")
            .chain_update(&record[..280])
            .finalize();
        record[280..].copy_from_slice(&checksum);
        record
    }

    #[test]
    fn v8_root_ack_codec_rejects_cross_version_and_corruption() {
        let record = RootV8EffectAckV1 {
            binding: ObjectDigest::from_bytes([1; 32]),
            epoch: 2,
            operation: OperationId::from_bytes([3; 16]),
            sandbox: SandboxId::from_bytes([4; 16]),
            accepted_generation: 5,
            effect_transaction: [6; 16],
            terminal: ObjectDigest::from_bytes([7; 32]),
            proof: ObjectDigest::from_bytes([8; 32]),
            quota: ObjectDigest::from_bytes([9; 32]),
            controller_ack: ObjectDigest::from_bytes([10; 32]),
            receipt: ObjectDigest::from_bytes([11; 32]),
            signer_generation: 12,
            controller_uid: 13,
            nonce: [14; 16],
        };
        let bytes = record.encode().unwrap();
        assert_eq!(RootV8EffectAckV1::decode(&bytes).unwrap(), record);
        for offset in [
            0, 8, 16, 48, 56, 72, 88, 96, 112, 144, 176, 208, 240, 272, 280, 284, 300,
        ] {
            let mut altered = bytes;
            altered[offset] ^= 1;
            assert!(RootV8EffectAckV1::decode(&altered).is_err());
        }
    }

    #[test]
    fn fresh_v8_ack_and_terminal_complete_under_one_root_writer() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = prepare_v8_root_fixture(directory.path());
        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let terminal = complete_test_terminal(&mut authority, &fixture, [21; 16], [22; 16]);
        assert_eq!(
            terminal::current_terminal(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(terminal)
        );
        drop(authority);
        drop(root);

        let mut reopened = super::super::tests::open_test_root(directory.path());
        let mut authority = reopened
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(terminal)
        );

        let released = terminal::release::release_verified_terminal_in_authority(
            &mut authority,
            fixture.binding_head,
            fixture.binding.handoff_epoch,
            terminal,
        )
        .unwrap();
        assert!(matches!(
            released,
            RootV8TerminalCustodyV1::Released(row, marker)
                if row == terminal && marker.as_bytes() != &[0; 32]
        ));
        assert!(matches!(
            recover_closed_binding_decision_with_proof_from_authority(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            ),
            Ok((ClosedPolicyBindingDecisionV2::CommittedReleased(_), _, _))
        ));
        assert!(
            current_ack(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch
            )
            .is_err()
        );
        assert_eq!(
            terminal::current_terminal_custody(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(released)
        );
        drop(authority);
        drop(reopened);

        let mut reopened = super::super::tests::open_test_root(directory.path());
        let mut authority = reopened
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal_custody(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(released)
        );

        let mut marker = authority
            .get(terminal::release::RELEASE_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        marker[56] ^= 1;
        authority
            .commit(
                &JournalTransaction::new(
                    [29; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        terminal::release::RELEASE_KEY.to_vec(),
                        marker,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(
            recover_closed_binding_decision_with_proof_from_authority(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .is_err()
        );

        authority
            .commit(
                &JournalTransaction::new(
                    [30; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::DesiredState,
                        terminal::release::RELEASE_KEY.to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(
            require_settled_predecessor(&authority, fixture.binding_head, 2).is_err(),
            "a lost release marker cannot turn a V8 predecessor into an inert one"
        );
    }

    #[test]
    fn signed_final_command_releases_root_under_writer_and_cold_replays() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = prepare_v8_root_fixture(directory.path());
        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let terminal = complete_test_terminal(&mut authority, &fixture, [31; 16], [32; 16]);
        let digest = terminal.record_digest();
        assert_eq!(
            digest,
            ObjectDigest::from_bytes(
                Sha256::digest(authority.get(terminal::TERMINAL_KEY).unwrap().unwrap()).into()
            )
        );

        let released = release_verified_terminal_after_command_in_authority(
            &mut authority,
            terminal,
            1234,
            || Ok([33; 16]),
            |challenge, challenged_digest| {
                assert_eq!(challenged_digest, digest);
                assert!(matches!(
                    Journal::open_protected_at_uid(
                        directory.path(),
                        "closed-binding.journal",
                        policy_authority_journal_limits(),
                        fs::metadata(directory.path()).unwrap().uid(),
                    ),
                    Err(JournalError::AlreadyLocked)
                ));
                Ok(final_release::sign_test_final_command(
                    terminal.ack(),
                    digest,
                    fixture.binding.project,
                    fixture.binding.physical_partition,
                    fixture.binding.physical_cache_head,
                    fixture.ack.cache_quota(),
                    1234,
                    challenge,
                    4,
                    &fixture.controller_key,
                )
                .to_vec())
            },
        )
        .unwrap();
        assert!(matches!(
            released,
            RootV8TerminalCustodyV1::Released(row, marker)
                if row == terminal && marker.as_bytes() != &[0; 32]
        ));
        drop(authority);
        drop(root);

        let mut reopened = super::super::tests::open_test_root(directory.path());
        let authority = reopened
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal_custody(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(released),
        );
    }

    #[test]
    fn failed_or_foreign_final_command_cannot_release_root() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = prepare_v8_root_fixture(directory.path());
        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let terminal = complete_test_terminal(&mut authority, &fixture, [41; 16], [42; 16]);

        assert!(
            release_verified_terminal_after_command_in_authority(
                &mut authority,
                terminal,
                1234,
                || Ok([43; 16]),
                |_, _| Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "final command timed out before submission"
                )),
            )
            .is_err()
        );
        assert_eq!(
            terminal::current_terminal_custody(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(RootV8TerminalCustodyV1::Held(terminal)),
        );

        assert!(
            release_verified_terminal_after_command_in_authority(
                &mut authority,
                terminal,
                1234,
                || Ok([44; 16]),
                |challenge, digest| {
                    let mut packet = final_release::sign_test_final_command(
                        terminal.ack(),
                        digest,
                        fixture.binding.project,
                        fixture.binding.physical_partition,
                        fixture.binding.physical_cache_head,
                        fixture.ack.cache_quota(),
                        1234,
                        challenge,
                        4,
                        &fixture.controller_key,
                    );
                    packet[420] ^= 1;
                    Ok(packet.to_vec())
                },
            )
            .is_err()
        );
        assert_eq!(
            terminal::current_terminal_custody(
                &authority,
                fixture.binding_head,
                fixture.binding.handoff_epoch,
            )
            .unwrap(),
            Some(RootV8TerminalCustodyV1::Held(terminal)),
        );
    }

    #[test]
    fn released_v8_terminal_requires_signed_settlement_before_successor_cas() {
        let directory = tempfile::tempdir().unwrap();
        let first = prepare_v8_root_fixture(directory.path());
        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let first_terminal = complete_test_terminal(&mut authority, &first, [21; 16], [22; 16]);
        let first_released = terminal::release::release_verified_terminal_in_authority(
            &mut authority,
            first.binding_head,
            first.binding.handoff_epoch,
            first_terminal,
        )
        .unwrap();
        drop(authority);
        drop(root);

        let mut next = first.binding.clone();
        next.operation = OperationId::from_bytes([41; 16]);
        next.effect_transaction = [42; 16];
        next.root_predecessor = first.binding_head;
        next.root_generation = 2;
        next.barrier_epoch = 2;
        next.handoff_epoch = 2;
        let proposed = next.encode().unwrap();
        let next_head = closed_policy_binding_digest_v2(&proposed).unwrap();
        let mut next_proof = RootHeldProofV2::decode(&first.proof_bytes).unwrap();
        next_proof.binding = next_head;
        next_proof.epoch = 2;
        next_proof.terminal = ObjectDigest::from_bytes([43; 32]);
        next_proof.stage_nonce = [31; 16];
        next_proof.stage_issue = 1;
        next_proof.source_nonce = [44; 16];
        next_proof.source_issue = 1;
        let next_proof_bytes = next_proof.encode().unwrap();

        // A stage or failed signer leaves the old released head current.
        let mut root = super::super::tests::open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: super::super::tests::identity(&next),
            postcommit: None,
        };
        session.stage_closed_binding_base(|| Ok([31; 16])).unwrap();
        drop(session);
        drop(root);

        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal_custody(&authority, first.binding_head, 1).unwrap(),
            Some(first_released)
        );

        // A successor AOSPCP02 may replace the fixed staging slot before CAS.
        authority
            .commit(
                &JournalTransaction::new(
                    [45; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        HELD_PROOF_KEY.to_vec(),
                        next_proof_bytes.to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(authority);
        drop(root);

        let mut root = super::super::tests::open_test_root(directory.path());
        root.compact().unwrap();
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal_custody(&authority, first.binding_head, 1).unwrap(),
            Some(first_released)
        );
        assert!(
            recover_closed_binding_decision_with_proof_from_authority(
                &authority,
                first.binding_head,
                1,
            )
            .is_ok()
        );

        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: super::super::tests::identity(&next),
            postcommit: None,
        };
        assert!(
            session
                .commit_closed_binding_with_proof(&proposed, None, Some(next_proof))
                .is_err()
        );
        drop(session);
        drop(root);

        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let record = test_settlement_record(&authority, &first);
        let settled = successor_settlement::settle_in_authority(
            &mut authority,
            first.binding_head,
            1,
            1234,
            &first.controller_pin,
            || Ok([46; 16]),
            |challenge| {
                use crate::policy_compiler::controller_v8_readback_envelope::{
                    ControllerV8ReadbackProtocol, sign_packet,
                };

                Ok(sign_packet::<460>(
                    ControllerV8ReadbackProtocol::Settlement,
                    &record,
                    1234,
                    7,
                    challenge,
                    4,
                    &first.controller_key,
                )
                .unwrap()
                .to_vec())
            },
        )
        .unwrap();
        assert_eq!(settled.predecessor(), first.binding_head);
        assert!(current_flight_slots_empty(&authority).unwrap());
        assert_eq!(
            successor_settlement::settle_in_authority(
                &mut authority,
                first.binding_head,
                1,
                1234,
                &first.controller_pin,
                || panic!("settled replay must not mint a new challenge"),
                |_| panic!("settled replay must not request another receipt"),
            )
            .unwrap(),
            settled,
        );
        drop(authority);
        drop(root);

        let mut root = super::super::tests::open_test_root(directory.path());
        root.compact().unwrap();
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            successor_settlement::settlement_for_predecessor(&authority, first.binding_head)
                .unwrap(),
            Some(settled),
        );
        assert!(matches!(
            recover_closed_binding_decision_with_proof_from_authority(
                &authority,
                first.binding_head,
                1,
            )
            .unwrap()
            .0,
            ClosedPolicyBindingDecisionV2::CommittedReleased(_)
        ));
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: super::super::tests::identity(&next),
            postcommit: None,
        };
        session
            .commit_closed_binding_with_proof(&proposed, None, Some(next_proof))
            .unwrap();
        drop(session);
        drop(root);

        let mut root = super::super::tests::open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert!(current_flight_slots_empty(&authority).unwrap());
        assert_eq!(
            authority.get(HELD_PROOF_KEY).unwrap(),
            Some(next_proof_bytes.as_slice())
        );
        assert!(matches!(
            recover_closed_binding_decision_with_proof_from_authority(&authority, next_head, 2)
                .unwrap()
                .0,
            ClosedPolicyBindingDecisionV2::CommittedHeld(_)
        ));
        assert_eq!(current_ack(&authority, next_head, 2).unwrap(), None);

        let hold = ControllerPolicyHoldV1::new(
            next.operation,
            next.sandbox,
            ObjectDigest::from_bytes([14; 32]),
            next_head,
            2,
        )
        .unwrap();
        let attempt = ControllerPolicyV8AttemptV1::new(hold, next_proof.terminal).unwrap();
        let next_ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            next.accepted_generation,
            next.effect_transaction,
            ObjectDigest::from_bytes(Sha256::digest(&next_proof_bytes).into()),
            next_proof.quota,
        )
        .unwrap();
        let second = V8RootFixture {
            binding: next,
            binding_head: next_head,
            controller_key: first.controller_key,
            controller_pin: first.controller_pin,
            proof_bytes: next_proof_bytes.to_vec(),
            ack: next_ack,
        };
        let second_terminal = complete_test_terminal(&mut authority, &second, [51; 16], [52; 16]);
        assert_eq!(
            terminal::current_terminal(&authority, next_head, 2).unwrap(),
            Some(second_terminal)
        );
        assert_eq!(
            successor_settlement::recover_from_authority(&authority, first.binding_head, 1)
                .unwrap(),
            Some(settled),
        );
    }

    #[test]
    fn v8_root_ack_cold_replay_rejects_rotated_credential_and_forged_proof() {
        let directory = tempfile::tempdir().unwrap();
        let V8RootFixture {
            binding,
            binding_head,
            controller_key,
            controller_pin,
            proof_bytes,
            ack,
        } = prepare_v8_root_fixture(directory.path());
        let attempt = ack.attempt();
        let mut cold = super::super::tests::open_test_root(directory.path());
        let mut authority = cold
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            current_ack(&authority, binding_head, binding.handoff_epoch).unwrap(),
            None
        );
        assert!(
            acknowledge_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &[0; 88],
                || Ok([15; 16]),
                |_| panic!("rotated signer must not be queried"),
            )
            .is_err()
        );
        assert_eq!(
            current_ack(&authority, binding_head, binding.handoff_epoch).unwrap(),
            None
        );

        let wrong_quota = ControllerPolicyV8EffectAckV1::new(
            attempt,
            binding.accepted_generation,
            binding.effect_transaction,
            ack.root_proof(),
            ObjectDigest::from_bytes([99; 32]),
        )
        .unwrap();
        assert!(
            acknowledge_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &controller_pin,
                || Ok([15; 16]),
                |challenge| {
                    Ok(sign_test_controller_v8_effect_ack_readback_v1(
                        wrong_quota,
                        1234,
                        challenge,
                        4,
                        &controller_key,
                    )
                    .unwrap()
                    .to_vec())
                },
            )
            .is_err()
        );
        assert_eq!(
            current_ack(&authority, binding_head, binding.handoff_epoch).unwrap(),
            None
        );

        let committed = acknowledge_in_authority(
            &mut authority,
            binding_head,
            binding.handoff_epoch,
            1234,
            &controller_pin,
            || Ok([16; 16]),
            |challenge| {
                Ok(sign_test_controller_v8_effect_ack_readback_v1(
                    ack,
                    1234,
                    challenge,
                    4,
                    &controller_key,
                )
                .unwrap()
                .to_vec())
            },
        )
        .unwrap();
        assert_eq!(committed.controller_ack(), ack.record_digest().unwrap());
        drop(authority);
        drop(cold);

        let mut reopened = super::super::tests::open_test_root(directory.path());
        let mut authority = reopened
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            current_ack(&authority, binding_head, binding.handoff_epoch).unwrap(),
            Some(committed)
        );
        assert_eq!(
            terminal::current_terminal(&authority, binding_head, binding.handoff_epoch).unwrap(),
            None
        );
        assert_eq!(
            acknowledge_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &controller_pin,
                || panic!("exact replay must not spend a nonce"),
                |_| panic!("exact replay must not sign"),
            )
            .unwrap(),
            committed
        );

        assert!(
            terminal::verify_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &controller_pin,
                || Ok([17; 16]),
                |challenge| {
                    let mut packet = sign_test_controller_v8_root_receipt_readback_v1(
                        committed,
                        1234,
                        challenge,
                        4,
                        &controller_key,
                    )
                    .unwrap();
                    packet[84] ^= 1;
                    Ok(packet.to_vec())
                },
            )
            .is_err()
        );
        assert_eq!(
            terminal::current_terminal(&authority, binding_head, binding.handoff_epoch).unwrap(),
            None
        );
        let substituted = RootV8EffectAckV1 {
            quota: ObjectDigest::from_bytes([99; 32]),
            ..committed
        };
        assert!(
            terminal::verify_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &controller_pin,
                || Ok([18; 16]),
                |challenge| {
                    Ok(sign_test_controller_v8_root_receipt_readback_v1(
                        substituted,
                        1234,
                        challenge,
                        4,
                        &controller_key,
                    )
                    .unwrap()
                    .to_vec())
                },
            )
            .is_err()
        );
        let mut acknowledged = false;
        let terminal = acknowledge_and_verify_in_authority(
            &mut authority,
            binding_head,
            binding.handoff_epoch,
            1234,
            &controller_pin,
            || panic!("historical ACK must not spend another nonce"),
            || Ok([19; 16]),
            |step| match step {
                RootV8HeldTerminalStepV1::EffectAck(_) => {
                    panic!("historical ACK must not request another packet")
                }
                RootV8HeldTerminalStepV1::Acknowledged(row) => {
                    assert_eq!(row, committed);
                    acknowledged = true;
                    Ok(Vec::new())
                }
                RootV8HeldTerminalStepV1::RootReceipt(challenge) => {
                    assert!(acknowledged);
                    Ok(sign_test_controller_v8_root_receipt_readback_v1(
                        committed,
                        1234,
                        challenge,
                        4,
                        &controller_key,
                    )
                    .unwrap()
                    .to_vec())
                }
                RootV8HeldTerminalStepV1::FinalRelease { .. } => {
                    panic!("held-only terminal must not request release")
                }
            },
        )
        .unwrap();
        assert_eq!(terminal.ack(), committed);
        assert_eq!(
            terminal::verify_in_authority(
                &mut authority,
                binding_head,
                binding.handoff_epoch,
                1234,
                &controller_pin,
                || panic!("exact terminal replay must not spend a nonce"),
                |_| panic!("exact terminal replay must not sign"),
            )
            .unwrap(),
            terminal
        );
        drop(authority);
        drop(reopened);

        let mut reopened = super::super::tests::open_test_root(directory.path());
        let mut authority = reopened
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert_eq!(
            terminal::current_terminal(&authority, binding_head, binding.handoff_epoch).unwrap(),
            Some(terminal)
        );

        let mut altered = proof_bytes;
        altered[16] ^= 1;
        authority
            .commit(
                &JournalTransaction::new(
                    [17; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        held_cas_proof_key(binding_head),
                        altered.to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(current_ack(&authority, binding_head, binding.handoff_epoch).is_err());
    }
}
