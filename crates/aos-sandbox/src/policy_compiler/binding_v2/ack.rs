//! Root-owned, nonauthorizing acknowledgment of a signed Controller no-Apply ACK.
//!
//! ```text
//! AOSPCA01 | version=1 | reserved[6]=0 | binding[32] | epoch:u64 |
//! operation[16] | sandbox[16] | Create-generation:u64 |
//! effect-transaction[16] | Root-proof-digest[32] |
//! Controller-ACK-record-digest[32] | signed-receipt-digest[32] |
//! Controller-signer-generation:u64 | Controller-UID:u32 |
//! Root-nonce[16] | SHA-256[32]
//! AOSPCE01 | challenge-issue-epoch:u64 | Root-nonce[16] |
//! Root-effect-cut[32] | SHA-256[32]
//! ```
//!
//! This is only a durable receipt under a held Root writer. It cannot release
//! any owner or enable public Create/Apply.

use std::{io, path::Path};

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
};

use super::*;
use crate::policy_compiler::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
    verify_controller_effect_ack_readback_v1,
};
use crate::policy_compiler::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use crate::policy_compiler::controller_hold_readback::PinnedControllerHoldSignerV1;
use crate::policy_compiler::root_challenge_record::RootChallengeRecordCodec;

pub(super) const ACK_KEY: &[u8] = b"\0aos-policy-compiler-root-effect-ack-v1\0";
const CHALLENGE_KEY: &[u8] = b"\0aos-policy-compiler-root-effect-ack-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSPCA01";
const CHALLENGE_MAGIC: &[u8; 8] = b"AOSPCE01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-effect-ack.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-effect-ack-transaction.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-effect-ack-cut.v1\0";
const CHALLENGE_RECORD_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-effect-ack-challenge-record.v1\0";
const CHALLENGE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-effect-ack-challenge-transaction.v1\0";
const RECORD_BYTES: usize = 268;
const CHALLENGE_CODEC: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    CHALLENGE_MAGIC,
    CHALLENGE_RECORD_DOMAIN,
    CHALLENGE_TRANSACTION_DOMAIN,
    CHALLENGE_KEY,
);

/// Reports a rejected Root/Controller effect-ACK session.
#[derive(Debug, thiserror::Error)]
pub enum RootEffectAckErrorV1 {
    /// The Root cut, pin, receipt, or existing ACK is stale or substituted.
    #[error("stale Root effect acknowledgment cut")]
    Stale,
    /// The protected Root journal failed to open, commit, or replay.
    #[error(transparent)]
    Root(#[from] PolicyCompilerJournalErrorV1),
    /// The Controller-only signed packet failed verification.
    #[error(transparent)]
    Controller(#[from] ControllerEffectAckReadbackErrorV1),
    /// The Controller receipt exchange failed; cold Root replay is required.
    #[error(transparent)]
    Transport(#[from] io::Error),
}

/// Retains the exact, nonauthorizing Root ACK after durable readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEffectAckV1 {
    binding: ObjectDigest,
    epoch: u64,
    operation: OperationId,
    sandbox: SandboxId,
    accepted_generation: u64,
    effect_transaction: [u8; 16],
    root_proof: ObjectDigest,
    controller_ack: ObjectDigest,
    receipt: ObjectDigest,
    signer_generation: u64,
    controller_uid: u32,
    nonce: [u8; 16],
}

impl RootEffectAckV1 {
    /// Returns the exact Root binding head.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the held Root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the exact Controller ACK record digest.
    #[must_use]
    pub const fn controller_ack(self) -> ObjectDigest {
        self.controller_ack
    }

    /// Returns the exact Root signer-proof digest.
    #[must_use]
    pub const fn root_proof(self) -> ObjectDigest {
        self.root_proof
    }

    /// Returns the accepted Create generation.
    #[must_use]
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Returns the no-Apply effect transaction identity.
    #[must_use]
    pub const fn effect_transaction(self) -> [u8; 16] {
        self.effect_transaction
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], RootEffectAckErrorV1> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.root_proof.as_bytes() == &[0; 32]
            || self.controller_ack.as_bytes() == &[0; 32]
            || self.receipt.as_bytes() == &[0; 32]
            || self.signer_generation == 0
            || self.controller_uid == 0
            || self.nonce == [0; 16]
        {
            return Err(RootEffectAckErrorV1::Stale);
        }
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..72].copy_from_slice(self.operation.as_bytes());
        bytes[72..88].copy_from_slice(self.sandbox.as_bytes());
        bytes[88..96].copy_from_slice(&self.accepted_generation.to_be_bytes());
        bytes[96..112].copy_from_slice(&self.effect_transaction);
        bytes[112..144].copy_from_slice(self.root_proof.as_bytes());
        bytes[144..176].copy_from_slice(self.controller_ack.as_bytes());
        bytes[176..208].copy_from_slice(self.receipt.as_bytes());
        bytes[208..216].copy_from_slice(&self.signer_generation.to_be_bytes());
        bytes[216..220].copy_from_slice(&self.controller_uid.to_be_bytes());
        bytes[220..236].copy_from_slice(&self.nonce);
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..236])
            .finalize();
        bytes[236..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RootEffectAckErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(RootEffectAckErrorV1::Stale);
        }
        let take = |start, end| bytes.get(start..end).ok_or(RootEffectAckErrorV1::Stale);
        let record = Self {
            binding: ObjectDigest::from_bytes(
                take(16, 48)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            epoch: u64::from_be_bytes(
                take(48, 56)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            operation: OperationId::from_bytes(
                take(56, 72)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            sandbox: SandboxId::from_bytes(
                take(72, 88)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            accepted_generation: u64::from_be_bytes(
                take(88, 96)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            effect_transaction: take(96, 112)?
                .try_into()
                .map_err(|_| RootEffectAckErrorV1::Stale)?,
            root_proof: ObjectDigest::from_bytes(
                take(112, 144)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            controller_ack: ObjectDigest::from_bytes(
                take(144, 176)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            receipt: ObjectDigest::from_bytes(
                take(176, 208)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            signer_generation: u64::from_be_bytes(
                take(208, 216)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            controller_uid: u32::from_be_bytes(
                take(216, 220)?
                    .try_into()
                    .map_err(|_| RootEffectAckErrorV1::Stale)?,
            ),
            nonce: take(220, 236)?
                .try_into()
                .map_err(|_| RootEffectAckErrorV1::Stale)?,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(RootEffectAckErrorV1::Stale);
        }
        Ok(record)
    }
}

/// Replays Root's exact no-Apply ACK without releasing its hold.
///
/// The caller must retain Controller, Source, protected Cache, and physical
/// Cache custody before opening Root last. Absence is not an authorization.
///
/// # Errors
///
/// Rejects changed Root heads, malformed or released custody, changed signer
/// pin, mismatched proposal/proof, or unsafe protected journal replay.
pub fn recover_fixed_closed_root_effect_ack_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootEffectAckV1>, RootEffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )
    .map_err(PolicyCompilerJournalErrorV1::from)?;
    let authority = journal
        .claim_protected_authority(RecordNamespace::DesiredState)
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    current_ack(&authority, binding, epoch)
}

/// Records a pinned Controller-signed no-Apply ACK under Root-last custody.
///
/// The caller must retain Controller, Source, protected Cache, and physical
/// Cache writers through this call. A transport failure leaves every hold
/// intact; retry first replays the exact durable Root ACK. This library API
/// has no live Controller signer transport yet and grants no release or Apply.
///
/// # Errors
///
/// Rejects stale Root or Controller claims, changed signer pin, forged or
/// replayed receipt, conflicting prior ACK, or failed Root durability.
pub fn acknowledge_fixed_closed_root_effect_v1(
    binding: ObjectDigest,
    epoch: u64,
    controller_uid: u32,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootEffectAckV1, RootEffectAckErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )
    .map_err(PolicyCompilerJournalErrorV1::from)?;
    let mut authority = journal
        .claim_protected_authority(RecordNamespace::DesiredState)
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    acknowledge_in_authority(
        &mut authority,
        binding,
        epoch,
        controller_uid,
        super::super::controller_readback_session::fresh_root_nonce,
        exchange,
    )
}

pub(super) fn current_ack(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<Option<RootEffectAckV1>, RootEffectAckErrorV1> {
    let (decision, proposal, proof) =
        recover_closed_binding_decision_with_proof_from_authority(authority, binding, epoch)?;
    if !matches!(
        decision,
        ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(_)
    ) {
        return Err(RootEffectAckErrorV1::Stale);
    }
    let proposal =
        ClosedPolicyRootBindingV2::decode(&proposal.ok_or(RootEffectAckErrorV1::Stale)?)?;
    let proof = proof.ok_or(RootEffectAckErrorV1::Stale)?;
    let pin = authority
        .get(CONTROLLER_HOLD_PIN_KEY)
        .map_err(PolicyCompilerJournalErrorV1::from)?
        .ok_or(RootEffectAckErrorV1::Stale)?;
    let signer =
        PinnedControllerHoldSignerV1::decode(pin).map_err(|_| RootEffectAckErrorV1::Stale)?;
    let record = authority
        .get(ACK_KEY)
        .map_err(PolicyCompilerJournalErrorV1::from)?
        .map(RootEffectAckV1::decode)
        .transpose()?;
    if CHALLENGE_CODEC
        .read_prior(
            authority
                .get(CHALLENGE_KEY)
                .map_err(PolicyCompilerJournalErrorV1::from)?,
        )
        .is_none()
    {
        return Err(RootEffectAckErrorV1::Stale);
    }
    if let Some(record) = record {
        if record.binding != binding
            || record.epoch != epoch
            || record.operation != proposal.operation
            || record.sandbox != proposal.sandbox
            || record.accepted_generation != proposal.accepted_generation
            || record.effect_transaction != proposal.effect_transaction
            || record.root_proof != proof
            || record.signer_generation != signer.generation()
        {
            return Err(RootEffectAckErrorV1::Stale);
        }
        let challenge_bytes = authority
            .get(CHALLENGE_KEY)
            .map_err(PolicyCompilerJournalErrorV1::from)?
            .ok_or(RootEffectAckErrorV1::Stale)?;
        let (issue_epoch, nonce) = CHALLENGE_CODEC
            .read_prior(Some(challenge_bytes))
            .ok_or(RootEffectAckErrorV1::Stale)?;
        let cut = effect_cut(
            binding,
            epoch,
            &proposal,
            proof,
            pin,
            record.controller_uid,
            issue_epoch,
        );
        if nonce != record.nonce
            || challenge_bytes != CHALLENGE_CODEC.encode(issue_epoch, nonce, cut)
        {
            return Err(RootEffectAckErrorV1::Stale);
        }
    }
    Ok(record)
}

pub(super) fn acknowledge_in_authority(
    authority: &mut ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
    controller_uid: u32,
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ControllerEffectAckChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<RootEffectAckV1, RootEffectAckErrorV1> {
    if controller_uid == 0 {
        return Err(RootEffectAckErrorV1::Stale);
    }
    if let Some(prior) = current_ack(authority, binding, epoch)? {
        return if prior.controller_uid == controller_uid {
            Ok(prior)
        } else {
            Err(RootEffectAckErrorV1::Stale)
        };
    }
    let (_, proposed, proof) =
        recover_closed_binding_decision_with_proof_from_authority(authority, binding, epoch)?;
    let proposed =
        ClosedPolicyRootBindingV2::decode(&proposed.ok_or(RootEffectAckErrorV1::Stale)?)?;
    let proof = proof.ok_or(RootEffectAckErrorV1::Stale)?;
    let pin = authority
        .get(CONTROLLER_HOLD_PIN_KEY)
        .map_err(PolicyCompilerJournalErrorV1::from)?
        .ok_or(RootEffectAckErrorV1::Stale)?
        .to_vec();
    let signer =
        PinnedControllerHoldSignerV1::decode(&pin).map_err(|_| RootEffectAckErrorV1::Stale)?;
    let (prior_epoch, prior_nonce) = CHALLENGE_CODEC
        .read_prior(
            authority
                .get(CHALLENGE_KEY)
                .map_err(PolicyCompilerJournalErrorV1::from)?,
        )
        .ok_or(RootEffectAckErrorV1::Stale)?;
    let issue_epoch = prior_epoch
        .checked_add(1)
        .ok_or(RootEffectAckErrorV1::Stale)?;
    let nonce = fresh_nonce()?;
    if nonce == [0; 16] || nonce == prior_nonce {
        return Err(RootEffectAckErrorV1::Stale);
    }
    let cut = effect_cut(
        binding,
        epoch,
        &proposed,
        proof,
        &pin,
        controller_uid,
        issue_epoch,
    );
    let challenge = ControllerEffectAckChallengeV1::new(nonce, cut)?;
    let challenge_record = CHALLENGE_CODEC.encode(issue_epoch, nonce, cut);
    authority
        .commit(
            &CHALLENGE_CODEC
                .transaction(challenge_record)
                .map_err(PolicyCompilerJournalErrorV1::from)?,
        )
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    if authority
        .get(CHALLENGE_KEY)
        .map_err(PolicyCompilerJournalErrorV1::from)?
        != Some(challenge_record.as_slice())
    {
        return Err(RootEffectAckErrorV1::Stale);
    }
    let snapshot = authority
        .snapshot()
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    let packet = exchange(challenge)?;
    let receipt =
        verify_controller_effect_ack_readback_v1(&packet, &signer, challenge, controller_uid)?;
    let ack = receipt.ack();
    if ack.hold().binding() != binding
        || ack.hold().epoch() != epoch
        || ack.hold().operation() != proposed.operation
        || ack.hold().sandbox() != proposed.sandbox
        || ack.accepted_generation() != proposed.accepted_generation
        || ack.effect_transaction() != proposed.effect_transaction
        || ack.root_proof() != proof
        || authority
            .get(CONTROLLER_HOLD_PIN_KEY)
            .map_err(PolicyCompilerJournalErrorV1::from)?
            != Some(pin.as_slice())
        || authority
            .get(CHALLENGE_KEY)
            .map_err(PolicyCompilerJournalErrorV1::from)?
            != Some(challenge_record.as_slice())
    {
        return Err(RootEffectAckErrorV1::Stale);
    }
    authority
        .validate_snapshot_for_effect(&snapshot)
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    let record = RootEffectAckV1 {
        binding,
        epoch,
        operation: proposed.operation,
        sandbox: proposed.sandbox,
        accepted_generation: proposed.accepted_generation,
        effect_transaction: proposed.effect_transaction,
        root_proof: proof,
        controller_ack: ack
            .record_digest()
            .map_err(PolicyCompilerJournalErrorV1::from)?,
        receipt: ObjectDigest::from_bytes(Sha256::digest(&packet).into()),
        signer_generation: signer.generation(),
        controller_uid,
        nonce,
    };
    let encoded = record.encode()?;
    let transaction_digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(encoded)
        .finalize();
    let transaction_id: [u8; 16] = transaction_digest[..16]
        .try_into()
        .map_err(|_| RootEffectAckErrorV1::Stale)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            ACK_KEY.to_vec(),
            encoded.to_vec(),
        )],
    )
    .map_err(PolicyCompilerJournalErrorV1::from)?;
    authority
        .commit(&transaction)
        .map_err(PolicyCompilerJournalErrorV1::from)?;
    if current_ack(authority, binding, epoch)? != Some(record) {
        return Err(RootEffectAckErrorV1::Stale);
    }
    Ok(record)
}

fn effect_cut(
    binding: ObjectDigest,
    epoch: u64,
    proposed: &ClosedPolicyRootBindingV2,
    proof: ObjectDigest,
    pin: &[u8],
    controller_uid: u32,
    issue_epoch: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(binding.as_bytes())
            .chain_update(epoch.to_be_bytes())
            .chain_update(proposed.operation.as_bytes())
            .chain_update(proposed.sandbox.as_bytes())
            .chain_update(proposed.accepted_generation.to_be_bytes())
            .chain_update(proposed.effect_transaction)
            .chain_update(proof.as_bytes())
            .chain_update(Sha256::digest(pin))
            .chain_update(controller_uid.to_be_bytes())
            .chain_update(issue_epoch.to_be_bytes())
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_ack_record_rejects_changed_claims_and_checksum() {
        let record = RootEffectAckV1 {
            binding: ObjectDigest::from_bytes([1; 32]),
            epoch: 2,
            operation: OperationId::from_bytes([3; 16]),
            sandbox: SandboxId::from_bytes([4; 16]),
            accepted_generation: 5,
            effect_transaction: [6; 16],
            root_proof: ObjectDigest::from_bytes([7; 32]),
            controller_ack: ObjectDigest::from_bytes([8; 32]),
            receipt: ObjectDigest::from_bytes([9; 32]),
            signer_generation: 10,
            controller_uid: 11,
            nonce: [12; 16],
        };
        let encoded = record.encode().unwrap();
        assert_eq!(RootEffectAckV1::decode(&encoded).unwrap(), record);
        for offset in [8, 16, 48, 56, 72, 88, 96, 112, 144, 176, 208, 216, 220, 236] {
            let mut altered = encoded;
            altered[offset] ^= 1;
            assert!(RootEffectAckV1::decode(&altered).is_err());
        }
    }
}
