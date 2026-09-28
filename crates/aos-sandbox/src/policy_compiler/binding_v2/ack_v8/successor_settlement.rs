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

use std::{io, path::Path};

use aos_sandbox_core::ObjectDigest;
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
const MAGIC: &[u8; 8] = b"AOSPC88S";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-successor-settlement.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.root-v8-successor-settlement-transaction.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-successor-settlement-cut.v1\0";
const RECORD_BYTES: usize = 256;

/// Authenticated, immutable Root settlement of one V8 predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8SuccessorSettlementV1 {
    predecessor: ObjectDigest,
    epoch: u64,
    next_epoch: u64,
    settlement: ObjectDigest,
    release_marker: ObjectDigest,
    cache_released: ObjectDigest,
    source_released: ObjectDigest,
    signed_receipt: ObjectDigest,
}

impl RootV8SuccessorSettlementV1 {
    /// Returns the released predecessor binding.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the predecessor handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the next permitted Root epoch.
    #[must_use]
    pub const fn next_epoch(self) -> u64 {
        self.next_epoch
    }

    /// Returns the canonical Controller AOSQ8S01 digest.
    #[must_use]
    pub const fn settlement(self) -> ObjectDigest {
        self.settlement
    }

    /// Returns the canonical Root AOSPC88L digest.
    #[must_use]
    pub const fn release_marker(self) -> ObjectDigest {
        self.release_marker
    }

    /// Returns the exact released Cache hold digest.
    #[must_use]
    pub const fn cache_released(self) -> ObjectDigest {
        self.cache_released
    }

    /// Returns the exact released Source hold digest.
    #[must_use]
    pub const fn source_released(self) -> ObjectDigest {
        self.source_released
    }

    /// Returns the digest of the signed Controller settlement receipt.
    #[must_use]
    pub const fn signed_receipt(self) -> ObjectDigest {
        self.signed_receipt
    }

    /// Encodes the canonical Root settlement for a future fixed Root signer.
    ///
    /// # Errors
    ///
    /// Rejects invalid predecessor epochs or zero evidence digests.
    pub(crate) fn record_bytes(self) -> Result<[u8; RECORD_BYTES], PolicyCompilerJournalErrorV1> {
        self.encode()
    }

    /// Decodes the exact canonical Root settlement record.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields or a changed checksum.
    pub(crate) fn from_record_bytes(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        Self::decode(bytes)
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], PolicyCompilerJournalErrorV1> {
        if self.predecessor.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.next_epoch
                != self
                    .epoch
                    .checked_add(1)
                    .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
            || [
                self.settlement,
                self.release_marker,
                self.cache_released,
                self.source_released,
                self.signed_receipt,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.predecessor.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.next_epoch.to_be_bytes());
        for (index, digest) in [
            self.settlement,
            self.release_marker,
            self.cache_released,
            self.source_released,
            self.signed_receipt,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 64 + index * 32;
            bytes[offset..offset + 32].copy_from_slice(digest.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..224])
            .finalize();
        bytes[224..256].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let digest = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
            Ok(ObjectDigest::from_bytes(
                bytes[offset..offset + 32]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            ))
        };
        let settlement = Self {
            predecessor: digest(16)?,
            epoch: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            ),
            next_epoch: u64::from_be_bytes(
                bytes[56..64]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            ),
            settlement: digest(64)?,
            release_marker: digest(96)?,
            cache_released: digest(128)?,
            source_released: digest(160)?,
            signed_receipt: digest(192)?,
        };
        if settlement.encode()?.as_slice() != bytes {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(settlement)
    }
}

fn key(predecessor: ObjectDigest) -> Vec<u8> {
    [KEY_PREFIX, predecessor.as_bytes()].concat()
}

fn settlement_transaction(
    settlement: RootV8SuccessorSettlementV1,
) -> Result<JournalTransaction, PolicyCompilerJournalErrorV1> {
    let bytes = settlement.encode()?;
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
    Ok(JournalTransaction::new(id, records)?)
}

/// Reads and validates the immutable marker for one predecessor.
pub(in crate::policy_compiler::binding_v2) fn settlement_for_predecessor(
    authority: &ProtectedJournalAuthority<'_>,
    predecessor: ObjectDigest,
) -> Result<Option<RootV8SuccessorSettlementV1>, PolicyCompilerJournalErrorV1> {
    let Some(bytes) = authority.get(&key(predecessor))? else {
        return Ok(None);
    };
    let settlement = RootV8SuccessorSettlementV1::decode(bytes)?;
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
        super::super::super::controller_readback_session::fresh_root_nonce,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_settlement_record_rejects_changed_owner_or_release_digests() {
        let marker = RootV8SuccessorSettlementV1 {
            predecessor: ObjectDigest::from_bytes([1; 32]),
            epoch: 2,
            next_epoch: 3,
            settlement: ObjectDigest::from_bytes([4; 32]),
            release_marker: ObjectDigest::from_bytes([5; 32]),
            cache_released: ObjectDigest::from_bytes([6; 32]),
            source_released: ObjectDigest::from_bytes([7; 32]),
            signed_receipt: ObjectDigest::from_bytes([8; 32]),
        };
        let encoded = marker.record_bytes().unwrap();
        assert_eq!(
            RootV8SuccessorSettlementV1::from_record_bytes(&encoded).unwrap(),
            marker,
        );
        for offset in [0, 8, 16, 48, 56, 64, 96, 128, 160, 192, 224] {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert!(RootV8SuccessorSettlementV1::from_record_bytes(&changed).is_err());
        }
    }
}
